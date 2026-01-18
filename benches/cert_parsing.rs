use criterion::{black_box, criterion_group, criterion_main, Criterion};

// Placeholder benchmark
// Real benchmarks will be added when parsing is implemented
fn bench_placeholder(c: &mut Criterion) {
    c.bench_function("placeholder", |b| {
        b.iter(|| {
            black_box(1 + 1)
        })
    });
}

criterion_group!(benches, bench_placeholder);
criterion_main!(benches);
