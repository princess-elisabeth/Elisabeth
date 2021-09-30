use crate::{filter::Filter, public_key::PublicKey, Torus};
use concrete_commons::{Numeric, StandardDev};
use concrete_core::{
    crypto::{
        bootstrap::BootstrapKey,
        lwe::LweKeyswitchKey,
        secret::{GlweSecretKey, LweSecretKey},
        GlweDimension, LweDimension,
    },
    math::{
        decomposition::{DecompositionBaseLog, DecompositionLevelCount},
        fft::Complex64,
        polynomial::PolynomialSize,
        random::{EncryptionRandomGenerator, RandomGenerator},
    },
};
use std::{env, fs, path::Path};

/// A list of preset parameters for Elisabeth.
#[allow(non_camel_case_types)]
pub enum SystemParameters {
    n60,
}
pub(super) struct Parameters {
    pub(super) n: usize,
    pub(super) key_size: usize,
    pub(super) filter: Filter,
}

impl SystemParameters {
    /// Returns the parameters for a given preset.
    pub(super) fn parameters(&self) -> Parameters {
        match self {
            Self::n60 => Parameters {
                key_size: 256,
                n: 60,
                filter: Filter::new(),
            },
        }
    }

    #[cfg(not(feature = "single_key"))]
    pub fn fhe_parameters(
        &self,
    ) -> (
        (LweDimension, StandardDev),
        (GlweDimension, PolynomialSize, StandardDev),
        (DecompositionBaseLog, DecompositionLevelCount),
        (DecompositionBaseLog, DecompositionLevelCount),
        (DecompositionBaseLog, DecompositionLevelCount),
    ) {
        (
            // LWE Parameters
            (
                LweDimension(784),
                StandardDev::from_standard_dev(2_f64.powf(-18.6658)),
            ),
            // GLWE Parameters
            (
                GlweDimension(3),
                PolynomialSize(512),
                StandardDev::from_standard_dev(2_f64.powf(-38.4997)),
            ),
            // Bootstrapping Key
            (DecompositionBaseLog(19), DecompositionLevelCount(1)),
            // Keyswitching Key
            (DecompositionBaseLog(6), DecompositionLevelCount(2)),
            // Reverse Keyswitching Key
            (DecompositionBaseLog(19), DecompositionLevelCount(1)),
        )
    }

    #[cfg(feature = "single_key")]
    pub fn fhe_parameters(
        &self,
    ) -> (
        (LweDimension, StandardDev),
        (GlweDimension, PolynomialSize, StandardDev),
        (DecompositionBaseLog, DecompositionLevelCount),
        (DecompositionBaseLog, DecompositionLevelCount),
    ) {
        (
            // LWE Parameters
            (
                LweDimension(754),
                StandardDev::from_standard_dev(2_f64.powf(-17.87)),
            ),
            // GLWE Parameters
            (
                GlweDimension(1),
                PolynomialSize(2048),
                StandardDev::from_standard_dev(2_f64.powf(-52.)),
            ),
            // Bootstrapping Key
            (DecompositionBaseLog(7), DecompositionLevelCount(6)),
            // Keyswitching Key
            (DecompositionBaseLog(2), DecompositionLevelCount(8)),
        )
    }

    #[cfg(not(feature = "single_key"))]
    pub fn generate_fhe_keys(
        &self,
    ) -> (
        (LweSecretKey<Vec<bool>>, StandardDev),
        LweSecretKey<Vec<bool>>,
        PublicKey,
    ) {
        let env_var = env::var("KEY_DIRECTORY").ok();
        let path = env_var.as_ref().map(|s| &**s);

        let key_stored = path
            .map(|p| Path::new(format!("{}/keys", p).as_str()).is_dir())
            .unwrap_or(false);

        if key_stored {
            let sk_serialized =
                fs::read(format!("{}/keys/secret/secret_key", path.unwrap())).unwrap();
            let std_dev_serialized =
                fs::read(format!("{}/keys/secret/standard_deviation", path.unwrap())).unwrap();
            let sk_out_serialized =
                fs::read(format!("{}/keys/secret/secret_key_out", path.unwrap())).unwrap();
            let pk_serialized =
                fs::read(format!("{}/keys/public/public_key", path.unwrap())).unwrap();

            (
                (
                    bincode::deserialize(&sk_serialized).unwrap(),
                    bincode::deserialize(&std_dev_serialized).unwrap(),
                ),
                bincode::deserialize(&sk_out_serialized).unwrap(),
                bincode::deserialize(&pk_serialized).unwrap(),
            )
        } else {
            //parameters
            let (
                (lwe_dimension, std_dev_lwe),
                (glwe_dimension, polynomial_size, std_dev_glwe),
                (base_log_bs, level_bs),
                (base_log_ks, level_ks),
                (base_log_ks_inv, level_ks_inv),
            ) = self.fhe_parameters();

            // secret keys
            let mut generator = RandomGenerator::new(None);
            let mut secret_generator = EncryptionRandomGenerator::new(None);
            let sk_rlwe = GlweSecretKey::generate(glwe_dimension, polynomial_size, &mut generator);
            let sk = LweSecretKey::generate(lwe_dimension, &mut generator);

            // bootstrapping key
            let mut coef_bsk = BootstrapKey::allocate(
                <Torus as Numeric>::ZERO,
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                level_bs,
                base_log_bs,
                lwe_dimension,
            );
            coef_bsk.fill_with_new_key(&sk, &sk_rlwe, std_dev_glwe, &mut secret_generator);
            let mut bsk = BootstrapKey::allocate(
                Complex64::new(0., 0.),
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                level_bs,
                base_log_bs,
                lwe_dimension,
            );
            bsk.fill_with_forward_fourier(&coef_bsk);

            let sk_out = sk_rlwe.into_lwe_secret_key();
            let mut ksk = LweKeyswitchKey::allocate(
                <Torus as Numeric>::ZERO,
                level_ks,
                base_log_ks,
                sk_out.key_size(),
                sk.key_size(),
            );
            ksk.fill_with_keyswitch_key(&sk_out, &sk, std_dev_lwe, &mut secret_generator);

            let mut ksk_inv = LweKeyswitchKey::allocate(
                <Torus as Numeric>::ZERO,
                level_ks_inv,
                base_log_ks_inv,
                sk.key_size(),
                sk_out.key_size(),
            );
            ksk_inv.fill_with_keyswitch_key(&sk, &sk_out, std_dev_glwe, &mut secret_generator);

            let pk = PublicKey { bsk, ksk, ksk_inv };

            if path.is_some() {
                fs::create_dir_all(format!("{}/keys/secret", path.unwrap())).unwrap();
                fs::create_dir_all(format!("{}/keys/public", path.unwrap())).unwrap();
                fs::write(
                    format!("{}/keys/secret/secret_key", path.unwrap()),
                    &bincode::serialize(&sk).unwrap(),
                )
                .unwrap();
                fs::write(
                    format!("{}/keys/secret/standard_deviation", path.unwrap()),
                    bincode::serialize(&std_dev_lwe).unwrap(),
                )
                .unwrap();
                fs::write(
                    format!("{}/keys/secret/secret_key_out", path.unwrap()),
                    &bincode::serialize(&sk_out).unwrap(),
                )
                .unwrap();
                fs::write(
                    format!("{}/keys/public/public_key", path.unwrap()),
                    bincode::serialize(&pk).unwrap(),
                )
                .unwrap();
            }

            ((sk, std_dev_lwe), sk_out, pk)
        }
    }

    #[cfg(feature = "single_key")]
    pub fn generate_fhe_keys(&self) -> ((LweSecretKey<Vec<bool>>, StandardDev), PublicKey) {
        let env_var = env::var("KEY_DIRECTORY").ok();
        let path = env_var.as_ref().map(|s| &**s);

        let key_stored = path
            .map(|p| Path::new(format!("{}/keys", p).as_str()).is_dir())
            .unwrap_or(false);

        if key_stored {
            let sk_serialized =
                fs::read(format!("{}/keys/secret/secret_key", path.unwrap())).unwrap();
            let std_dev_serialized =
                fs::read(format!("{}/keys/secret/standard_deviation", path.unwrap())).unwrap();
            let pk_serialized =
                fs::read(format!("{}/keys/public/public_key", path.unwrap())).unwrap();

            (
                (
                    bincode::deserialize(&sk_serialized).unwrap(),
                    bincode::deserialize(&std_dev_serialized).unwrap(),
                ),
                bincode::deserialize(&pk_serialized).unwrap(),
            )
        } else {
            //parameters
            let (
                (lwe_dimension, std_dev_lwe),
                (glwe_dimension, polynomial_size, std_dev_glwe),
                (base_log_bs, level_bs),
                (base_log_ks, level_ks),
            ) = self.fhe_parameters();

            // secret keys
            let mut generator = RandomGenerator::new(None);
            let mut secret_generator = EncryptionRandomGenerator::new(None);
            let sk_rlwe = GlweSecretKey::generate(glwe_dimension, polynomial_size, &mut generator);
            let sk = LweSecretKey::generate(lwe_dimension, &mut generator);

            // bootstrapping key
            let mut coef_bsk = BootstrapKey::allocate(
                <Torus as Numeric>::ZERO,
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                level_bs,
                base_log_bs,
                lwe_dimension,
            );
            coef_bsk.fill_with_new_key(&sk, &sk_rlwe, std_dev_glwe, &mut secret_generator);
            let mut bsk = BootstrapKey::allocate(
                Complex64::new(0., 0.),
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                level_bs,
                base_log_bs,
                lwe_dimension,
            );
            bsk.fill_with_forward_fourier(&coef_bsk);

            let sk_out = sk_rlwe.into_lwe_secret_key();
            let mut ksk = LweKeyswitchKey::allocate(
                <Torus as Numeric>::ZERO,
                level_ks,
                base_log_ks,
                sk_out.key_size(),
                sk.key_size(),
            );
            ksk.fill_with_keyswitch_key(&sk_out, &sk, std_dev_lwe, &mut secret_generator);

            let pk = PublicKey { bsk, ksk };

            if path.is_some() {
                fs::create_dir_all(format!("{}/keys/secret", path.unwrap())).unwrap();
                fs::create_dir_all(format!("{}/keys/public", path.unwrap())).unwrap();
                fs::write(
                    format!("{}/keys/secret/secret_key", path.unwrap()),
                    &bincode::serialize(&sk).unwrap(),
                )
                .unwrap();
                fs::write(
                    format!("{}/keys/secret/standard_deviation", path.unwrap()),
                    bincode::serialize(&std_dev_lwe).unwrap(),
                )
                .unwrap();
                fs::write(
                    format!("{}/keys/public/public_key", path.unwrap()),
                    bincode::serialize(&pk).unwrap(),
                )
                .unwrap();
            }

            ((sk, std_dev_lwe), pk)
        }
    }
}
