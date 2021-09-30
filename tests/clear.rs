use concrete_core::math::random::RandomGenerator;
use elisabeth::{u4, Encrypter, SystemParameters};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let nb_nibble = args[1].parse().unwrap();

    let (mut encryptor, mut decryptor) =
        Encrypter::<u4>::new::<u4>(&SystemParameters::n60, None, None, None);

    // message
    let mut generator = RandomGenerator::new(None);
    let message = generator
        .random_uniform_n_lsb_tensor::<u8>(nb_nibble, 4)
        .into_container()
        .iter()
        .map(|f| u4(*f))
        .collect::<Vec<u4>>();

    let mut ciphertext = vec![u4(0); nb_nibble];
    let mut decryption = vec![u4(0); nb_nibble];

    encryptor.encrypt(&mut ciphertext, &message);
    decryptor.decrypt(&mut decryption, &ciphertext);

    for (a, b) in message.iter().zip(decryption.iter()) {
        assert_eq!(a.0, b.0);
    }
}
