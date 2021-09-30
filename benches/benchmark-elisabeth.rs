use concrete_core::math::random::RandomGenerator;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use elisabeth::{u4, Encrypter, SystemParameters, LWE};
use pprof::criterion::{Output, PProfProfiler};

fn bench_encryption(c: &mut Criterion) {
    let id = if cfg!(not(feature = "multithread")) {
        "Elisabeth 60 - Encryption - Monothreaded"
    } else {
        "Elisabeth 60 - Encryption"
    };

    let (mut enc, _dec) = Encrypter::<u4>::new::<u4>(&SystemParameters::n60, None, None, None);

    let mut generator = RandomGenerator::new(None);
    let message = vec![u4(generator.random_uniform_n_lsb(4))];

    let mut ciphertext = vec![u4(0)];

    c.bench_function(id, move |b| {
        b.iter_batched(
            || message.clone(),
            |message1216| enc.encrypt(black_box(&mut ciphertext), black_box(&message1216)),
            BatchSize::SmallInput,
        )
    });
}

fn bench_transcryption(c: &mut Criterion) {
    let mut id = if cfg!(feature = "single_key") {
        "Elisabeth 60 - Transciphering - Single Keyswitching Key"
    } else {
        "Elisabeth 60 - Transciphering - Two Keyswitching Key"
    }
    .to_string();
    if cfg!(not(feature = "multithread")) {
        id += " - Monothreaded";
    }

    #[cfg(not(feature = "single_key"))]
    let ((sk, std_dev_lwe), _sk_out, pk) = SystemParameters::n60.generate_fhe_keys();
    #[cfg(feature = "single_key")]
    let ((sk, std_dev_lwe), pk) = SystemParameters::n60.generate_fhe_keys();

    let (mut encrypter, mut decrypter) = Encrypter::<u4>::new::<LWE>(
        &SystemParameters::n60,
        Some(&sk),
        Some(std_dev_lwe.0),
        Some(pk),
    );

    // message
    let mut generator = RandomGenerator::new(None);
    let message = vec![u4(generator.random_uniform_n_lsb::<u8>(4))];

    let mut ciphertext = vec![u4(0)];
    let mut transciphered = vec![LWE::allocate(sk.key_size().to_lwe_size())];

    encrypter.encrypt(&mut ciphertext, &message);

    decrypter.decrypt(&mut transciphered, &ciphertext);
    c.bench_function(id.as_str(), move |b| {
        b.iter_batched(
            || ciphertext.clone(),
            |ctx| decrypter.decrypt(black_box(&mut transciphered), black_box(&ctx)),
            BatchSize::SmallInput,
        )
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = bench_encryption, bench_transcryption
}
criterion_main!(benches);
