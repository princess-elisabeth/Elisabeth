use crate::Torus;
use concrete_core::{
    crypto::{bootstrap::BootstrapKey, lwe::LweKeyswitchKey},
    math::fft::Complex64,
};
use serde::{Deserialize, Serialize};

/// A struct that encapsulates both the bootstrapping and keyswitching key.
#[derive(Clone, Serialize, Deserialize)]
pub struct PublicKey {
    pub bsk: BootstrapKey<Vec<Complex64>>,
    pub ksk: LweKeyswitchKey<Vec<Torus>>,
    #[cfg(not(feature = "single_key"))]
    pub ksk_inv: LweKeyswitchKey<Vec<Torus>>,
}
