use concrete_core::{crypto::encoding::Plaintext, math::random::RandomGenerator};
use crossterm::{cursor, QueueableCommand};
use elisabeth::{u4, Encrypter, SystemParameters, Torus, LWE};
use std::{
    env,
    io::{stdout, Write},
    time::Instant,
};

fn main() {
    let args: Vec<String> = env::args().collect();
    let nb_nibble = args[1].parse().unwrap();

    let mut stdout = stdout();
    stdout.queue(cursor::SavePosition).unwrap();
    stdout
        .write(format!("Generating FHE keys...                       ").as_bytes())
        .unwrap();
    stdout.queue(cursor::RestorePosition).unwrap();
    stdout.flush().unwrap();

    #[cfg(not(feature = "single_key"))]
    let ((sk, std_dev_lwe), sk_out, pk) = SystemParameters::n60.generate_fhe_keys();
    #[cfg(feature = "single_key")]
    let ((sk, std_dev_lwe), pk) = SystemParameters::n60.generate_fhe_keys();

    stdout.queue(cursor::SavePosition).unwrap();
    stdout
        .write(format!("Generating Elisabeth keys...                 ").as_bytes())
        .unwrap();
    stdout.queue(cursor::RestorePosition).unwrap();
    stdout.flush().unwrap();

    let (mut encrypter, mut decrypter) = Encrypter::<u4>::new::<LWE>(
        &SystemParameters::n60,
        Some(&sk),
        Some(std_dev_lwe.0),
        Some(pk),
    );

    stdout.queue(cursor::SavePosition).unwrap();
    stdout
        .write(format!("Generating message...                        ").as_bytes())
        .unwrap();
    stdout.queue(cursor::RestorePosition).unwrap();
    stdout.flush().unwrap();

    // message
    let mut generator = RandomGenerator::new(None);
    let message = generator
        .random_uniform_n_lsb_tensor::<u8>(nb_nibble, 4)
        .into_container()
        .iter()
        .map(|f| u4(*f))
        .collect::<Vec<u4>>();

    let mut ciphertext = vec![u4(0); nb_nibble];
    let mut transciphered = vec![LWE::allocate(sk.key_size().to_lwe_size()); nb_nibble];

    stdout.queue(cursor::SavePosition).unwrap();
    stdout
        .write(format!("Encrypting...                                ").as_bytes())
        .unwrap();
    stdout.queue(cursor::RestorePosition).unwrap();
    stdout.flush().unwrap();

    encrypter.encrypt(&mut ciphertext, &message);

    stdout.queue(cursor::SavePosition).unwrap();
    stdout
        .write(format!("Transciphering...                            ").as_bytes())
        .unwrap();
    stdout.queue(cursor::RestorePosition).unwrap();
    stdout.flush().unwrap();

    let now = Instant::now();
    decrypter.decrypt(&mut transciphered, &ciphertext);
    println!(
        "{} nibbles transcrypted in {} s. ({} s/nibble, {} s/b)",
        nb_nibble,
        now.elapsed().as_secs(),
        now.elapsed().as_secs_f64() / (nb_nibble as f64),
        now.elapsed().as_secs_f64() / (4. * nb_nibble as f64),
    );

    let mut errors = 0;
    let sdk_samples = transciphered
        .iter_mut()
        .zip(message.iter())
        .map(|(lwe, mes)| {
            let mut encoded = Plaintext(0);

            #[cfg(not(feature = "single_key"))]
            sk_out.decrypt_lwe(&mut encoded, lwe.as_mut_lwe());
            #[cfg(feature = "single_key")]
            sk.decrypt_lwe(&mut encoded, lwe.as_mut_lwe());

            let mut decoded = encoded.0 >> 59;
            if decoded & 1 == 1 {
                decoded += 2;
            }
            decoded >>= 1;
            decoded %= 16;
            if decoded as u8 != mes.0 {
                errors += 1;
            }
            torus_modular_distance(encoded.0, (mes.0 as u64) << 60)
        })
        .collect::<Vec<_>>();

    // compute the mean of our errors
    let mut mean: f64 = sdk_samples.iter().sum();
    mean /= sdk_samples.len() as f64;

    // compute the variance of the errors
    let mut sdk_variance: f64 = sdk_samples.iter().map(|x| f64::powi(x - mean, 2)).sum();
    sdk_variance /= (sdk_samples.len() - 1) as f64;

    // compute the standard deviation
    let sdk_std_log2 = f64::log2(f64::sqrt(sdk_variance));

    println!(
        "Standard deviation of the noise of the outputs: 2^{}.",
        sdk_std_log2
    );

    if errors > 0 {
        panic!(
            "{} error{} over {} nibbles.",
            errors,
            if errors > 1 { "s" } else { "" },
            nb_nibble
        );
    }
}

fn torus_modular_distance(first: Torus, other: Torus) -> f64 {
    let d0 = first.wrapping_sub(other);
    let d1 = other.wrapping_sub(first);
    if d0 < d1 {
        let d: f64 = d0 as f64;
        d / 2_f64.powi(Torus::BITS as i32)
    } else {
        let d: f64 = d1 as f64;
        -d / 2_f64.powi(Torus::BITS as i32)
    }
}
