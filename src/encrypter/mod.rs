pub mod parameters;

use std::{env, fs, path::Path};

use crate::{
    filter::Filter, nibble::Nibble, public_key::PublicKey, symmetric_key::SymmetricKey, u4,
};
use concrete_core::{crypto::secret::LweSecretKey, math::random::RandomGenerator};
use parameters::{Parameters, SystemParameters};

pub struct Encrypter<T: Nibble> {
    symmetric_key: SymmetricKey<T>,
    filter: Filter,
    public_key: Option<PublicKey>,
}

/// The struct used to encrypt, decrypt and transcrypt nibbles.
impl<T: 'static + Nibble> Encrypter<T> {
    /// Generates to new encrypters, using possibly two different kind of nibbles T and U.
    /// One can be used to encrypted nibbles T and the other to transcrypt toward U.
    pub fn new<U: Nibble>(
        params: &SystemParameters,
        secret_key: Option<&LweSecretKey<Vec<bool>>>,
        std_dev: Option<f64>,
        public_key: Option<PublicKey>,
    ) -> (Self, Encrypter<U>) {
        let mut rng = RandomGenerator::new(None);
        let seed = rng.random_uniform();

        let Parameters {
            n,
            key_size,
            filter,
        } = params.parameters();

        let mut key1 =
            vec![
                T::from_u4_with_lwe_size(u4(0), secret_key.map(|s| s.key_size().to_lwe_size()));
                key_size
            ];
        let mut key2 =
            vec![
                U::from_u4_with_lwe_size(u4(0), secret_key.map(|s| s.key_size().to_lwe_size()));
                key_size
            ];

        Self::key_gen(&mut key1, &mut key2, secret_key, std_dev, &mut rng);

        (
            Self {
                symmetric_key: SymmetricKey::new(key1, n, seed),
                filter: filter.clone(),
                public_key: public_key.clone(),
            },
            Encrypter::<U> {
                symmetric_key: SymmetricKey::new(key2, n, seed),
                filter,
                public_key,
            },
        )
    }

    fn key_gen<U: Nibble>(
        key1: &mut [T],
        key2: &mut [U],
        secret_key: Option<&LweSecretKey<Vec<bool>>>,
        std_dev: Option<f64>,
        rng: &mut RandomGenerator,
    ) {
        let env_var = env::var("KEY_DIRECTORY").ok();
        let path = env_var.as_ref().map(|s| &**s);
        let key_stored = path
            .map(|p| Path::new(format!("{}/keys/symmetric", p).as_str()).is_dir())
            .unwrap_or(false);

        if key_stored {
            let sk1_serialized =
                fs::read(format!("{}/keys/symmetric/key_client", path.unwrap())).unwrap();
            let sk2_serialized =
                fs::read(format!("{}/keys/symmetric/key_server", path.unwrap())).unwrap();
            key1.clone_from_slice(
                bincode::deserialize::<Vec<T>>(&sk1_serialized)
                    .unwrap()
                    .as_slice(),
            );
            key2.clone_from_slice(
                bincode::deserialize::<Vec<U>>(&sk2_serialized)
                    .unwrap()
                    .as_slice(),
            );
        } else {
            for (k1, k2) in key1.iter_mut().zip(key2.iter_mut()) {
                let u = u4(rng.random_uniform::<u8>() % (1 << 4));
                *k1 = T::from_u4(u, secret_key, std_dev);
                *k2 = U::from_u4(u, secret_key, std_dev);
            }
        }
        if path.is_some() {
            fs::create_dir_all(format!("{}/keys/symmetric", path.unwrap())).unwrap();
            fs::write(
                format!("{}/keys/symmetric/key_client", path.unwrap()),
                &bincode::serialize(&key1.to_vec()).unwrap(),
            )
            .unwrap();
            fs::write(
                format!("{}/keys/symmetric/key_server", path.unwrap()),
                bincode::serialize(&key2.to_vec()).unwrap(),
            )
            .unwrap();
        }
    }

    fn stream(&mut self) -> T {
        let key_round = self.symmetric_key.random_whitened_subset();
        self.filter.call(&key_round, self.public_key.as_ref())
    }

    /// Encrypts the given vector of plaintexts.
    pub fn encrypt(&mut self, res: &mut [T], message: &[u4]) {
        for (c, m) in res.iter_mut().zip(message.iter()) {
            *c = self.stream();
            c.add_assign_u4(m);
        }
    }

    /// Decrypts the given vector of ciphertexts.
    /// Depending of the type of nibbles set at the generation of the encrypter, this function can either decrypt or transcrypt.
    pub fn decrypt(&mut self, res: &mut [T], ciphertext: &[u4]) {
        for (d, c) in res.iter_mut().zip(ciphertext.iter()) {
            *d = self.stream();
            d.negate();
            d.add_assign_u4(c);
        }
    }
}
