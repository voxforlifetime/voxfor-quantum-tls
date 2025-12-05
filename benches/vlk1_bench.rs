use criterion::{black_box, criterion_group, criterion_main, Criterion};
use voxfor_quantum_tls::vlk1::{KeyPair, encapsulate, decapsulate};

fn bench_vlk1_keygen(c: &mut Criterion) {
    c.bench_function("VLK-1 Key Generation", |b| {
        b.iter(|| {
            black_box(KeyPair::generate())
        });
    });
}

fn bench_vlk1_encapsulate(c: &mut Criterion) {
    let keypair = KeyPair::generate();
    
    c.bench_function("VLK-1 Encapsulation", |b| {
        b.iter(|| {
            black_box(encapsulate(&keypair.public_key))
        });
    });
}

fn bench_vlk1_decapsulate(c: &mut Criterion) {
    let keypair = KeyPair::generate();
    let (ciphertext, _) = encapsulate(&keypair.public_key).unwrap();
    
    c.bench_function("VLK-1 Decapsulation", |b| {
        b.iter(|| {
            black_box(decapsulate(&ciphertext, &keypair.secret_key))
        });
    });
}

criterion_group!(benches, bench_vlk1_keygen, bench_vlk1_encapsulate, bench_vlk1_decapsulate);
criterion_main!(benches);
