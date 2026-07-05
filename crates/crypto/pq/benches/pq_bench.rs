use aether_crypto_pq::{
    decapsulate_ml_kem768, encapsulate_ml_kem768, generate_ml_dsa65_keypair,
    generate_ml_dsa87_keypair, generate_ml_kem768_keypair, pq_signature_context_for_alg,
    sign_ml_dsa65, sign_ml_dsa87, verify_ml_dsa65, verify_ml_dsa87, PqSignatureAlgorithm,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_ml_dsa65(c: &mut Criterion) {
    let message = [0xA5u8; 256];
    let context =
        pq_signature_context_for_alg("bench_agent_identity", 1, PqSignatureAlgorithm::MlDsa65);
    let keypair = generate_ml_dsa65_keypair().unwrap();
    let signature = sign_ml_dsa65(&keypair.private_key, &context, &message).unwrap();

    c.bench_function("ml_dsa65/keygen", |b| {
        b.iter(|| black_box(generate_ml_dsa65_keypair().unwrap()));
    });
    c.bench_function("ml_dsa65/sign_256B", |b| {
        b.iter(|| {
            black_box(
                sign_ml_dsa65(
                    black_box(&keypair.private_key),
                    black_box(&context),
                    black_box(&message),
                )
                .unwrap(),
            )
        });
    });
    c.bench_function("ml_dsa65/verify_256B", |b| {
        b.iter(|| {
            verify_ml_dsa65(
                black_box(&keypair.public_key),
                black_box(&context),
                black_box(&message),
                black_box(&signature.signature),
            )
            .unwrap()
        });
    });
}

fn bench_ml_dsa87(c: &mut Criterion) {
    let message = [0x5Au8; 256];
    let context =
        pq_signature_context_for_alg("bench_agent_identity", 1, PqSignatureAlgorithm::MlDsa87);
    let keypair = generate_ml_dsa87_keypair().unwrap();
    let signature = sign_ml_dsa87(&keypair.private_key, &context, &message).unwrap();

    c.bench_function("ml_dsa87/keygen", |b| {
        b.iter(|| black_box(generate_ml_dsa87_keypair().unwrap()));
    });
    c.bench_function("ml_dsa87/sign_256B", |b| {
        b.iter(|| {
            black_box(
                sign_ml_dsa87(
                    black_box(&keypair.private_key),
                    black_box(&context),
                    black_box(&message),
                )
                .unwrap(),
            )
        });
    });
    c.bench_function("ml_dsa87/verify_256B", |b| {
        b.iter(|| {
            verify_ml_dsa87(
                black_box(&keypair.public_key),
                black_box(&context),
                black_box(&message),
                black_box(&signature.signature),
            )
            .unwrap()
        });
    });
}

fn bench_ml_kem768(c: &mut Criterion) {
    let keypair = generate_ml_kem768_keypair().unwrap();
    let encapsulation = encapsulate_ml_kem768(&keypair.public_key).unwrap();

    c.bench_function("ml_kem768/keygen", |b| {
        b.iter(|| black_box(generate_ml_kem768_keypair().unwrap()));
    });
    c.bench_function("ml_kem768/encaps", |b| {
        b.iter(|| black_box(encapsulate_ml_kem768(black_box(&keypair.public_key)).unwrap()));
    });
    c.bench_function("ml_kem768/decaps", |b| {
        b.iter(|| {
            black_box(
                decapsulate_ml_kem768(
                    black_box(&keypair.private_key),
                    black_box(&encapsulation.ciphertext),
                )
                .unwrap(),
            )
        });
    });
}

criterion_group!(benches, bench_ml_dsa65, bench_ml_dsa87, bench_ml_kem768);
criterion_main!(benches);
