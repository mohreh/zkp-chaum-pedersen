use criterion::{Criterion, black_box, criterion_group, criterion_main};
use crypto_bigint::U2048;
use zkp_chaum_pedersen::{ChaumPedersenParameters, generate_random_nonce};

fn bench_zkp_performance_and_constant_time(c: &mut Criterion) {
    let params = ChaumPedersenParameters::get_default_2048_parameters();

    let random_nonce = generate_random_nonce(&params.subgroup_order);
    let challenge = generate_random_nonce(&params.subgroup_order);

    let mut group = c.benchmark_group("Compute Response (Constant-Time Check)");

    let secret_zero = U2048::ZERO;
    group.bench_function("Secret = ZERO", |b| {
        b.iter(|| {
            params.compute_response(
                black_box(&random_nonce),
                black_box(&challenge),
                black_box(&secret_zero),
            )
        })
    });

    // q - 1
    let secret_max = params.subgroup_order.wrapping_sub(&U2048::from_u64(1));
    group.bench_function("Secret = MAX", |b| {
        b.iter(|| {
            params.compute_response(
                black_box(&random_nonce),
                black_box(&challenge),
                black_box(&secret_max),
            )
        })
    });

    let secret_random = generate_random_nonce(&params.subgroup_order);
    group.bench_function("Secret = RANDOM", |b| {
        b.iter(|| {
            params.compute_response(
                black_box(&random_nonce),
                black_box(&challenge),
                black_box(&secret_random),
            )
        })
    });

    group.finish();

    let mut heavy_group = c.benchmark_group("Heavy Cryptographic Operations");

    heavy_group.bench_function("Exponentiate (Base = g1)", |b| {
        b.iter(|| params.exponentiate(black_box(&params.generator_1), black_box(&secret_random)))
    });

    let pub_1 = params.exponentiate(&params.generator_1, &secret_random);
    let pub_2 = params.exponentiate(&params.generator_2, &secret_random);
    let comm_1 = params.exponentiate(&params.generator_1, &random_nonce);
    let comm_2 = params.exponentiate(&params.generator_2, &random_nonce);
    let resp = params.compute_response(&random_nonce, &challenge, &secret_random);

    heavy_group.bench_function("Verify Complete Proof", |b| {
        b.iter(|| {
            params.verify(
                black_box(&comm_1),
                black_box(&comm_2),
                black_box(&pub_1),
                black_box(&pub_2),
                black_box(&challenge),
                black_box(&resp),
            )
        })
    });

    heavy_group.finish();
}

criterion_group!(benches, bench_zkp_performance_and_constant_time);
criterion_main!(benches);
