pub mod zkp_auth {
    include!(concat!(env!("OUT_DIR"), "/zkp_auth.rs"));
}

use std::{io, time::Duration};

use argon2::Argon2;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use crypto_bigint::Uint;
use crypto_bigint::{
    Odd,
    modular::{FixedMontyForm, MontyParams},
};
use hkdf::Hkdf;
use ratatui::{
    Terminal,
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Padding, Paragraph},
};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tui_input::Input;
use tui_input::backend::crossterm::EventHandler;

use zkp_auth::auth_service_client::AuthServiceClient;
use zkp_auth::{
    CreateAuthenticationChallengeRequest, RegisterRequest, VerifyAuthenticationRequest,
    VerifyNonInteractiveRequest,
};
use zkp_chaum_pedersen::{ChaumPedersenParameters, generate_random_nonce};

const SPINNER_FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

enum UiMessage {
    StartStep(String),
    CompleteStep(String, Color),
    ErrorStep(String),
    SystemChat(String, Color),
    LoginSuccess(String, String),
    Done,
}

#[derive(PartialEq)]
enum Focus {
    Username,
    Password,
    CommandMode,
    Processing,
}

#[derive(Clone)]
enum ZkpAction {
    Register,
    InteractiveLogin,
    FiatShamirLogin,
}

struct LogStep {
    description: String,
    result_msg: Option<String>,
    color: Color,
    is_active: bool,
    is_error: bool,
}

struct App {
    steps: Vec<LogStep>,
    focus: Focus,
    username_input: Input,
    password_input: Input,
    spinner_index: usize,
    session_id: Option<String>,
}

impl App {
    fn new() -> Self {
        Self {
            steps: vec![],
            focus: Focus::Username,
            username_input: Input::default(),
            password_input: Input::default(),
            spinner_index: 0,
            session_id: None,
        }
    }

    fn add_chat(&mut self, msg: String, color: Color) {
        self.steps.push(LogStep {
            description: msg,
            result_msg: None,
            color,
            is_active: false,
            is_error: false,
        });
    }

    fn start_step(&mut self, desc: String) {
        self.steps.push(LogStep {
            description: desc,
            result_msg: None,
            color: Color::White,
            is_active: true,
            is_error: false,
        });
    }

    fn complete_step(&mut self, msg: String, color: Color) {
        if let Some(step) = self.steps.last_mut() {
            step.is_active = false;
            step.result_msg = Some(msg);
            step.color = color;
        }
    }

    fn error_step(&mut self, msg: String) {
        if let Some(step) = self.steps.last_mut() {
            step.is_active = false;
            step.is_error = true;
            step.result_msg = Some(msg);
            step.color = Color::LightRed;
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();
    app.add_chat(
        "▶ [SYSTEM]: Welcome to ZKP Auth CLI!".to_string(),
        Color::Cyan,
    );
    app.add_chat(
        "▶ [SYSTEM]: Please fill in your Username and Password above.".to_string(),
        Color::Gray,
    );

    let (tx, mut rx) = mpsc::channel::<UiMessage>(32);

    let res = run_app(&mut terminal, &mut app, tx.clone(), &mut rx).await;

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("Error: {:?}", err);
    }
    Ok(())
}

async fn run_app<B: Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    tx: mpsc::Sender<UiMessage>,
    rx: &mut mpsc::Receiver<UiMessage>,
) -> io::Result<()>
where
    std::io::Error: From<<B as Backend>::Error>,
{
    loop {
        while let Ok(msg) = rx.try_recv() {
            match msg {
                UiMessage::SystemChat(msg, col) => app.add_chat(msg, col),
                UiMessage::StartStep(desc) => app.start_step(desc),
                UiMessage::CompleteStep(res, col) => app.complete_step(res, col),
                UiMessage::ErrorStep(err) => app.error_step(err),
                UiMessage::LoginSuccess(sid, chat_msg) => {
                    app.session_id = Some(sid);
                    app.add_chat(chat_msg, Color::LightGreen);
                }
                UiMessage::Done => app.focus = Focus::CommandMode,
            }
        }

        terminal.draw(|f| {
                let chunks = Layout::default()
                .direction(Direction::Vertical)
                    .margin(1)
                .constraints(
                    [
                        Constraint::Length(3), // Header
                        Constraint::Length(3), // Inputs
                        Constraint::Min(5),    // Logs/Chat
                        Constraint::Length(3), // Footer
                    ]
                    .as_ref(),
                )
                .split(f.area());

            let title = Paragraph::new(" ZKP Secure Auth Showcase CLI ")
                .style(Style::default().add_modifier(Modifier::BOLD))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .style(Style::default().fg(Color::Magenta)),
                );
            f.render_widget(title, chunks[0]);

            let chunks_constraints = if app.session_id.is_some() || app.focus == Focus::Processing {
                [Constraint::Percentage(100), Constraint::Percentage(0)]
            } else {
                [Constraint::Percentage(50), Constraint::Percentage(50)]
            };

            let input_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints(chunks_constraints.as_ref())
                .split(chunks[1]);

            let (u_style, p_style) = match app.focus {
                Focus::Username => (
                    Style::default().fg(Color::Yellow),
                    Style::default().fg(Color::DarkGray),
                ),
                Focus::Password => (
                    Style::default().fg(Color::DarkGray),
                    Style::default().fg(Color::Yellow),
                ),
                _ => (
                    Style::default().fg(Color::Green),
                    Style::default().fg(Color::Green),
                ),
            };

            let transparent_border_stay = Style::default().fg(Color::Black);

            let mut user_p = Paragraph::new(app.username_input.value()).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" [USR] Username ")
                    .style(u_style),
            );
            if app.session_id.is_some() {
                user_p = Paragraph::new(format!(" Your Username: {}  -  Your SessionId: {}", app.username_input.value(), app.session_id.clone().unwrap()))
                .block(
                    Block::default()
                        .borders(Borders::NONE)
                        .padding(Padding::top(1))
                        .style(u_style),
                );
            }
            if app.focus == Focus::Processing {
                user_p = Paragraph::new(format!(
                    " {} Processing ",
                    SPINNER_FRAMES[app.spinner_index % SPINNER_FRAMES.len()]
                ))
                .block(
                    Block::default()
                        .borders(Borders::NONE)
                        .padding(Padding::top(1))
                        .style(u_style),
                );

            }
            f.render_widget(user_p, input_chunks[0]);

            let pass_str = "*".repeat(app.password_input.value().len());
            let pass_p = Paragraph::new(pass_str).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" [PWD] Password ")
                    .style(p_style),
            );
            f.render_widget(pass_p, input_chunks[1]);

            let mut list_items = Vec::new();
            for step in &app.steps {
                let mut spans = vec![];

                if step.is_active {
                    spans.push(Span::styled(
                        format!(
                            "{} ",
                            SPINNER_FRAMES[app.spinner_index % SPINNER_FRAMES.len()]
                        ),
                        Style::default().fg(Color::Yellow),
                    ));
                } else if step.is_error {
                    spans.push(Span::styled(
                        "✗ ",
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ));
                } else if step.result_msg.is_some() {
                    spans.push(Span::styled(
                        "✓ ",
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ));
                }

                spans.push(Span::raw(&step.description));

                if let Some(ref res) = step.result_msg {
                    spans.push(Span::styled(
                        format!(" ➜ {}", res),
                        Style::default().fg(step.color),
                    ));
                }

                list_items.push(ListItem::new(Line::from(spans)));
            }
            let log_list = List::new(list_items);

                    let mut list_state = ListState::default();

                    if !app.steps.is_empty() {
                        list_state.select(Some(app.steps.len() - 1));
                    }

                    f.render_stateful_widget(log_list, chunks[2], &mut list_state);

            let footer_text = if app.session_id.is_some() {
                " COMMANDS: [L] Logout | [ESC] Quit "
            } else {
                match app.focus {
                    Focus::Username => {
                        " Type Username. Press [TAB] or [ENTER] to switch to Password. [ESC] to quit. "
                    }
                    Focus::Password => " Type Password. Press [ENTER] to confirm credentials. ",
                    Focus::CommandMode => {
                        " COMMANDS: [R] Register | [I] Interactive Login | [F] Fiat-Shamir Non-Interactive Login | [C] Clear Data | [ESC] Quit "
                    }
                    Focus::Processing => " ⏳ Processing Cryptography... Please wait. ",
                }
            };

            let footer = Paragraph::new(footer_text).block(
                Block::default()
                    .borders(Borders::ALL)
                    .style(Style::default().fg(Color::DarkGray)),
            );
            f.render_widget(footer, chunks[3]);
        })?;

        if event::poll(Duration::from_millis(80))? {
            if let Event::Key(key) = event::read()? {
                if app.session_id.is_some() {
                    match key.code {
                        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q') => return Ok(()),
                        KeyCode::Char('l') | KeyCode::Char('L') => {
                            app.session_id = None;
                            app.add_chat(
                                "▶ [SYSTEM]: Successfully logged out.".to_string(),
                                Color::Yellow,
                            );
                            app.focus = Focus::CommandMode;
                        }
                        _ => {}
                    }
                    continue;
                }

                match app.focus {
                    Focus::Username => match key.code {
                        KeyCode::Esc => return Ok(()),
                        KeyCode::Tab | KeyCode::Enter => app.focus = Focus::Password,
                        _ => {
                            app.username_input.handle_event(&Event::Key(key));
                        }
                    },
                    Focus::Password => match key.code {
                        KeyCode::Esc => return Ok(()),
                        KeyCode::Tab => app.focus = Focus::Username,
                        KeyCode::Enter => {
                            if app.username_input.value().is_empty()
                                || app.password_input.value().is_empty()
                            {
                                app.add_chat(
                                    "[!] [SYSTEM]: Username and Password cannot be empty!"
                                        .to_string(),
                                    Color::Yellow,
                                );
                            } else {
                                app.focus = Focus::CommandMode;
                                app.add_chat(
                                    "▶ [SYSTEM]: Credentials locked! Ready for commands."
                                        .to_string(),
                                    Color::Green,
                                );
                                app.add_chat(
                                    "▶ [SYSTEM]: Select an action from the bottom menu."
                                        .to_string(),
                                    Color::Gray,
                                );
                            }
                        }
                        _ => {
                            app.password_input.handle_event(&Event::Key(key));
                        }
                    },
                    Focus::CommandMode => {
                        let mut action = None;
                        match key.code {
                            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q') => return Ok(()),
                            KeyCode::Char('r') | KeyCode::Char('R') => {
                                action = Some(ZkpAction::Register)
                            }
                            KeyCode::Char('i') | KeyCode::Char('I') => {
                                action = Some(ZkpAction::InteractiveLogin)
                            }
                            KeyCode::Char('f') | KeyCode::Char('F') => {
                                action = Some(ZkpAction::FiatShamirLogin)
                            }
                            KeyCode::Char('c') | KeyCode::Char('C') => {
                                app.username_input.reset();
                                app.password_input.reset();
                                app.focus = Focus::Username;
                            }
                            _ => {}
                        }

                        if let Some(act) = action {
                            app.focus = Focus::Processing;
                            let tx_clone = tx.clone();
                            let u = app.username_input.value().to_string();
                            let p = app.password_input.value().to_string();
                            tokio::spawn(async move {
                                execute_zkp_action(tx_clone, act, u, p).await;
                            });
                        }
                    }
                    Focus::Processing => { /* Block inputs during processing */ }
                }
            }
        }
        app.spinner_index = app.spinner_index.wrapping_add(1);
    }
}

async fn execute_zkp_action(
    tx: mpsc::Sender<UiMessage>,
    action: ZkpAction,
    user: String,
    pass: String,
) {
    let delay = Duration::from_millis(1500);

    macro_rules! chat {
        ($msg:expr, $col:expr) => {
            let _ = tx.send(UiMessage::SystemChat($msg.to_string(), $col)).await;
        };
    }
    macro_rules! start {
        ($msg:expr) => {
            let _ = tx.send(UiMessage::StartStep($msg.to_string())).await;
        };
    }
    macro_rules! done {
        ($msg:expr, $col:expr) => {
            let _ = tx
                .send(UiMessage::CompleteStep($msg.to_string(), $col))
                .await;
            tokio::time::sleep(delay).await;
        };
    }
    macro_rules! err {
        ($msg:expr) => {
            let _ = tx.send(UiMessage::ErrorStep($msg.to_string())).await;
            let _ = tx.send(UiMessage::Done).await;
            return;
        };
    }

    let zkp = ChaumPedersenParameters::default();

    chat!(
        format!(
            "♦ [{}]: Initializing Zero-Knowledge Proof protocol...",
            user
        ),
        Color::LightBlue
    );

    start!("Connecting to gRPC Verification Server...");
    let mut client = match AuthServiceClient::connect("http://127.0.0.1:50051").await {
        Ok(c) => c,
        Err(err) => {
            err!(format!("Failed to connect to server: {}", err));
        }
    };
    done!("Connected to 127.0.0.1:50051", Color::DarkGray);

    chat!(
        "▶ [SYSTEM]: Deriving cryptographic secret 'x' from your password.",
        Color::Gray
    );
    chat!(
        "▶ [SYSTEM]: Using Argon2id (memory-hard KDF) + HKDF to generate a 2048-bit scalar.",
        Color::Gray
    );

    start!("Deriving Secret (x) via Argon2 & HKDF...");
    tokio::time::sleep(delay).await;
    let salt_hash = Sha256::digest(user.as_bytes());
    let mut argon2_key = [0u8; 32];

    let pass_clone = pass.clone();
    let argon_result = tokio::task::spawn_blocking(move || {
        Argon2::default()
            .hash_password_into(pass_clone.as_bytes(), &salt_hash, &mut argon2_key)
            .unwrap();
        let hkdf = Hkdf::<Sha256>::new(None, &argon2_key);
        let mut expanded_key = [0u8; 256];
        hkdf.expand(b"zkp-chaum-pedersen-secret-x", &mut expanded_key)
            .unwrap();
        expanded_key
    })
    .await
    .unwrap();

    let secret_raw = Uint::from_be_slice(&argon_result);
    let odd_q = Odd::new(zkp.subgroup_order).expect("Modulus must be odd");
    let q_params = MontyParams::new_vartime(odd_q);
    let secret_value = FixedMontyForm::<32>::new(&secret_raw, &q_params).retrieve();
    done!("Secret (x) securely bound to Z_q subgroup", Color::DarkGray);

    chat!("▶ [SYSTEM]: Computing Public Values (y1, y2).", Color::Gray);
    chat!(
        "▶ [SYSTEM]: Formulas: y1 = g1^x (mod p), y2 = g2^x (mod p)",
        Color::Gray
    );

    start!("Computing discrete logarithms y1 and y2...");
    let public_value_1 = zkp.exponentiate(&zkp.generator_1, &secret_value);
    let public_value_2 = zkp.exponentiate(&zkp.generator_2, &secret_value);
    done!("Public keys y1 and y2 computed", Color::DarkGray);

    match action {
        ZkpAction::Register => {
            chat!(
                "▶ [SYSTEM]: Executing REGISTRATION. Sending Public Values to the server.",
                Color::Magenta
            );
            chat!(
                "▶ [SYSTEM]: Server will store (y1, y2). The secret 'x' & password NEVER leaves client.",
                Color::Magenta
            );

            start!("Registering Public Keys (y1, y2)...");
            match client
                .register(RegisterRequest {
                    user: user.clone(),
                    public_value_1: public_value_1.to_be_bytes().to_vec(),
                    public_value_2: public_value_2.to_be_bytes().to_vec(),
                })
                .await
            {
                Ok(_) => {
                    done!("Successfully Registered on the Server", Color::Green);
                    chat!(
                        "★ [SYSTEM]: Registration complete! You can now authenticate.",
                        Color::Green
                    );
                }
                Err(e) => {
                    err!(format!("Registration Failed: {}", e.message()));
                }
            }
        }

        ZkpAction::InteractiveLogin => {
            chat!(
                "▶ [SYSTEM]: Executing INTERACTIVE ZKP LOGIN (3-Pass Protocol).",
                Color::Magenta
            );

            // Phase 1: Commitment
            chat!(
                "▶ [SYSTEM]: Phase 1 - Commitment. Generating random nonce 'k'.",
                Color::Gray
            );
            chat!(
                "▶ [SYSTEM]: Formulas: r1 = g1^k (mod p), r2 = g2^k (mod p)",
                Color::Gray
            );

            start!("Generating Commitments (r1, r2)...");
            let random_nonce = generate_random_nonce(&zkp.subgroup_order);
            let commitment_1 = zkp.exponentiate(&zkp.generator_1, &random_nonce);
            let commitment_2 = zkp.exponentiate(&zkp.generator_2, &random_nonce);
            done!("Commitments generated", Color::DarkGray);

            // Phase 2: Challenge
            start!("Sending Commitments and requesting Challenge (c) from Server...");
            let challenge_resp = match client
                .create_authentication_challenge(CreateAuthenticationChallengeRequest {
                    user: user.clone(),
                    commitment_1: commitment_1.to_be_bytes().to_vec(),
                    commitment_2: commitment_2.to_be_bytes().to_vec(),
                })
                .await
            {
                Ok(r) => r.into_inner(),
                Err(e) => {
                    err!(format!("Server rejected: {}", e.message()));
                }
            };
            let auth_id = challenge_resp.auth_id;
            let challenge = Uint::from_be_slice(&challenge_resp.challenge);
            done!("Received Challenge (c) from Server", Color::Yellow);

            // Phase 3: Response
            chat!(
                "▶ [SYSTEM]: Phase 3 - Response. Proving knowledge of 'x'.",
                Color::Gray
            );
            chat!("▶ [SYSTEM]: Formula: s = (k - c * x) mod q", Color::Gray);

            start!("Solving ZKP Mathematical Puzzle...");
            let response = zkp.compute_response(&random_nonce, &challenge, &secret_value);
            done!("Response (s) computed", Color::Cyan);

            start!("Sending final Proof (s) to Server for verification...");
            match client
                .verify_authentication(VerifyAuthenticationRequest {
                    auth_id,
                    response: response.to_be_bytes().to_vec(),
                })
                .await
            {
                Ok(res) => {
                    let sid = res.into_inner().session_id;
                    done!("Proof mathematically verified!", Color::LightGreen);
                    chat!(
                        "▶ [SYSTEM]: Server verified: r1 == (g1^s * y1^c) mod p && r2 == (g2^s * y2^c) mod p",
                        Color::Green
                    );
                    let _ = tx
                        .send(UiMessage::LoginSuccess(
                            sid.clone(),
                            format!("★ [SYSTEM]: Interactive Login Success! Session: {}", sid),
                        ))
                        .await;
                }

                Err(_) => {
                    err!("Zero-Knowledge Proof Verification Failed!");
                }
            }
        }

        ZkpAction::FiatShamirLogin => {
            chat!(
                "▶ [SYSTEM]: Executing NON-INTERACTIVE FIAT-SHAMIR LOGIN (1-Pass Protocol).",
                Color::Magenta
            );

            chat!(
                "▶ [SYSTEM]: Phase 1 - Commitment & Challenge Hash.",
                Color::Gray
            );
            chat!(
                "▶ [SYSTEM]: Formulas: r1 = g1^k, r2 = g2^k (mod p)",
                Color::Gray
            );
            chat!(
                "▶ [SYSTEM]: Formula: c = Hash(g1, g2, y1, y2, r1, r2) mod q",
                Color::Gray
            );

            start!("Generating Commitments & Local Fiat-Shamir Hash Challenge...");
            let random_nonce = generate_random_nonce(&zkp.subgroup_order);
            let commitment_1 = zkp.exponentiate(&zkp.generator_1, &random_nonce);
            let commitment_2 = zkp.exponentiate(&zkp.generator_2, &random_nonce);
            let challenge = zkp.compute_fiat_shamir_challenge(
                &public_value_1,
                &public_value_2,
                &commitment_1,
                &commitment_2,
            );
            done!("Local Challenge (c) hashed successfully", Color::Yellow);

            chat!(
                "▶ [SYSTEM]: Phase 2 - Response. Solving puzzle locally.",
                Color::Gray
            );
            chat!("▶ [SYSTEM]: Formula: s = (k - c * x) mod q", Color::Gray);

            start!("Solving ZKP Mathematical Puzzle...");
            let response = zkp.compute_response(&random_nonce, &challenge, &secret_value);
            done!("Response (s) computed", Color::Cyan);

            start!("Sending complete Non-Interactive Proof (c, s) to Server...");
            match client
                .verify_non_interactive(VerifyNonInteractiveRequest {
                    user: user.clone(),
                    challenge: challenge.to_be_bytes().to_vec(),
                    response: response.to_be_bytes().to_vec(),
                })
                .await
            {
                Ok(res) => {
                    let sid = res.into_inner().session_id;
                    done!("Proof mathematically verified!", Color::LightGreen);
                    chat!(
                        "▶ [SYSTEM]: Server recomputed commitments and verified Hash match.",
                        Color::Green
                    );
                    let _ = tx
                        .send(UiMessage::LoginSuccess(
                            sid.clone(),
                            format!(
                                "★ [SYSTEM]: Fast Fiat-Shamir Login Success! Session: {}",
                                sid
                            ),
                        ))
                        .await;
                }
                Err(_) => {
                    err!("Zero-Knowledge Proof Verification Failed!");
                }
            }
        }
    }

    let _ = tx.send(UiMessage::Done).await;
}
