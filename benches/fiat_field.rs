use criterion::{criterion_group, criterion_main, black_box, Criterion};

use halo2curves::pluto_eris::fields::{fp_fiat::*, fp::*};
use halo2curves::ff::Field;

use rand_core::SeedableRng;
use rand_xorshift::XorShiftRng;

pub fn bench_pluto_fiat_field(c: &mut Criterion) {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let a = Fp::random(&mut rng);
    let b = Fp::random(&mut rng);

    let mg_a = montgomery_domain_field_element(a.0);
    let mg_b = montgomery_domain_field_element(b.0);
    let mut mg_ret = montgomery_domain_field_element([0, 0, 0, 0, 0, 0, 0]);


    let mut group = c.benchmark_group("Pluto Field Arithmetics");

    group.bench_function("pluto_fp_mul", |bencher| {
        bencher.iter(|| black_box(&a).mul(black_box(&b)))
    });

    group.bench_function("pluto_fiat_mul", |bencher| {
        bencher.iter(|| mul(black_box(&mut mg_ret), black_box(&mg_a), black_box(&mg_b)))
    });

    group.bench_function("pluto_fp_add", |bencher| {
        bencher.iter(|| black_box(&a).add(black_box(&b)))
    });

    group.bench_function("pluto_fiat_add", |bencher| {
        bencher.iter(|| add(black_box(&mut mg_ret), black_box(&mg_a), black_box(&mg_b)))
    });

    group.bench_function("pluto_fp_square", |bencher| {
        bencher.iter(|| black_box(&a).square())
    });

    group.bench_function("pluto_fiat_square", |bencher| {
        bencher.iter(|| square(black_box(&mut mg_ret), black_box(&mg_a)))
    });

    group.bench_function("pluto_fp_negative", |bencher| {
        bencher.iter(|| black_box(&a).neg())
    });

    group.bench_function("pluto_fiat_negative", |bencher| {
        bencher.iter(|| opp(black_box(&mut mg_ret), black_box(&mg_a)))
    });

    group.bench_function("pluto_fp_sub", |bencher| {
        bencher.iter(|| black_box(&a).sub(black_box(&b)))
    });

    group.bench_function("pluto_fiat_sub", |bencher| {
        bencher.iter(|| sub(black_box(&mut mg_ret), black_box(&mg_a), black_box(&mg_b)))
    });
}

criterion_group!(benches, bench_pluto_fiat_field);
criterion_main!(benches);