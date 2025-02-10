use criterion::{criterion_group, criterion_main, Criterion, black_box};

//Import functions
include!("../src/functions.rs");

//Benchmark for setup_phase
fn benchmark_setup_phase(c: &mut Criterion) {
    c.bench_function("setup_phase", |b| {
        b.iter(|| setup_phase(black_box(100)))
    });
}

//Benchmark for create_polynomial
fn benchmark_create_polynomial(c: &mut Criterion) {
    c.bench_function("create_polynomial", |b| {
        b.iter(|| create_polynomial(black_box(100)))
    });
}

//Benchmark for commitment_phase
fn benchmark_commitment_phase(c: &mut Criterion) {
    let max_degree = 100;
    let public_params = setup_phase(max_degree);
    let polynomial = create_polynomial(max_degree);
    
    c.bench_function("commitment_phase", |b| {
        b.iter(|| commitment_phase(black_box(&public_params.g1), black_box(&polynomial), black_box(max_degree)))
    });
}

//Benchmark for prove_multi_evaluations
fn benchmark_prove_multi_evaluations(c: &mut Criterion) {
    let max_degree = 100;
    let public_params = setup_phase(max_degree);
    let polynomial = create_polynomial(max_degree);
    let zs: Vec<Fr> = (0..3).map(|_| Fr::rand(&mut thread_rng())).collect();

    c.bench_function("prove_multi_evaluations", |b| {
        b.iter(|| prove_multi_evaluations(black_box(&public_params.g1), black_box(&polynomial), black_box(&zs)))
    });
}

//Benchmark for verify_multi_evaluations
fn benchmark_verify_multi_evaluations(c: &mut Criterion) {
    let max_degree = 100;
    let public_params = setup_phase(max_degree);
    let polynomial = create_polynomial(max_degree);
    let zs: Vec<Fr> = (0..3).map(|_| Fr::rand(&mut thread_rng())).collect();
    let (ys, proofs) = prove_multi_evaluations(&public_params.g1, &polynomial, &zs);
    let commitment = commitment_phase(&public_params.g1, &polynomial, max_degree);

    c.bench_function("verify_multi_evaluations", |b| {
        b.iter(|| verify_multi_evaluations(
            black_box(commitment),
            black_box(proofs.clone()),
            black_box(&zs),
            black_box(&ys),
            black_box(&public_params.g2),
        ))
    });
}

//Benchmarks registration
criterion_group!(
    benches,
    benchmark_setup_phase,
    benchmark_create_polynomial,
    benchmark_commitment_phase,
    benchmark_prove_multi_evaluations,
    benchmark_verify_multi_evaluations
);
criterion_main!(benches);
