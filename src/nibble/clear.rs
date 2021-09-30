use crate::{nibble::Nibble, public_key::PublicKey};
use concrete_core::crypto::{secret::LweSecretKey, LweSize};
use serde::{Deserialize, Serialize};

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct u4(pub u8);

impl Nibble for u4 {
    fn from_u4_with_lwe_size(u: u4, _lwe_size: Option<LweSize>) -> Self {
        u
    }

    fn from_u4(
        u: u4,
        _secret_key: Option<&LweSecretKey<Vec<bool>>>,
        _std_dev: Option<f64>,
    ) -> Self {
        u
    }

    fn apply_sbox(&self, sbox: &[u4], _pk: Option<&PublicKey>) -> Self {
        sbox[self.0 as usize]
    }

    fn negate(&mut self) {
        self.0 = ((1 << 4) - self.0) % (1 << 4)
    }

    fn keyswitch(&mut self, _pk: Option<&PublicKey>) {}

    fn add(&self, rhs: &Self) -> Self {
        u4((self.0 + rhs.0) % (1 << 4))
    }

    fn add_u4(&self, rhs: &u4) -> Self {
        self.add(rhs)
    }

    fn add_assign(&mut self, rhs: &Self) {
        self.0 = (self.0 + rhs.0) % (1 << 4)
    }

    fn add_assign_u4(&mut self, rhs: &u4) {
        self.add_assign(rhs);
    }
}
