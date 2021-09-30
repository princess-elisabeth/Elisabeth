mod clear;
mod lwe;

use concrete_core::crypto::{secret::LweSecretKey, LweSize};
use serde::{de::DeserializeOwned, Serialize};

pub use clear::u4;
pub use lwe::LWE;

use crate::public_key::PublicKey;

/// Generic implementation of a nibble, that is a 4-bit integer that may or may not be encrypted.
pub trait Nibble: Clone + Sync + Send + Serialize + DeserializeOwned {
    /// Converts a u4 to a nibble.
    /// If the nibble is encrypted, this function needs the LWE size to work. It will then output a trivial encryption.
    fn from_u4_with_lwe_size(u: u4, lwe_size: Option<LweSize>) -> Self;

    /// Converts a u4 to a nibble.
    /// If the nibble is encrypted, this function needs the LWE secret key and a standard_deviation to work.
    fn from_u4(u: u4, secret_key: Option<&LweSecretKey<Vec<bool>>>, std_dev: Option<f64>) -> Self;

    /// Applies the given S-box to the nibble.
    /// If the nibble is encrypted, this function needs the LWE public key to work.
    fn apply_sbox(&self, sbox: &[u4], pk: Option<&PublicKey>) -> Self;

    /// Negates the nibble inplace.
    fn negate(&mut self);

    /// If this nibble is encrypted, changes its parameters so that they match a given standard.
    /// This is useful to map the ciphertext to some parameters at the end of the transcryption.
    fn keyswitch(&mut self, pk: Option<&PublicKey>);

    fn add(&self, rhs: &Self) -> Self;

    fn add_u4(&self, rhs: &u4) -> Self;

    fn add_assign(&mut self, rhs: &Self);

    fn add_assign_u4(&mut self, rhs: &u4);
}
