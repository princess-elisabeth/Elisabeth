use crate::{nibble::Nibble, public_key::PublicKey, u4, Torus};
use concrete_commons::{Numeric, StandardDev};
use concrete_core::{
    crypto::{
        cross::bootstrap,
        encoding::{Cleartext, Encoder, Plaintext, RealEncoder},
        glwe::GlweCiphertext,
        lwe::LweCiphertext,
        secret::LweSecretKey,
        LweSize,
    },
    math::{
        decomposition::{DecompositionBaseLog, DecompositionLevelCount, SignedDecomposable},
        random::EncryptionRandomGenerator,
        tensor::{AsMutSlice, AsMutTensor},
    },
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct LWE(LweCiphertext<Vec<Torus>>);

impl LWE {
    pub fn allocate(size: LweSize) -> Self {
        LWE(LweCiphertext::allocate(0, size))
    }

    pub fn from_lwe(ciphertext: LweCiphertext<Vec<Torus>>) -> Self {
        LWE(ciphertext)
    }

    pub fn as_mut_lwe(&mut self) -> &mut LweCiphertext<Vec<Torus>> {
        &mut self.0
    }

    pub fn as_lwe(&self) -> &LweCiphertext<Vec<Torus>> {
        &self.0
    }
}

impl Nibble for LWE {
    fn from_u4_with_lwe_size(u: u4, lwe_size: Option<LweSize>) -> Self {
        let mut output = LweCiphertext::allocate(<Torus as Numeric>::ZERO, lwe_size.unwrap());
        let body = output.get_mut_body();
        body.0 = (u.0 as Torus) << (<Torus as Numeric>::BITS - 4);
        LWE(output)
    }

    fn from_u4(u: u4, secret_key: Option<&LweSecretKey<Vec<bool>>>, std_dev: Option<f64>) -> Self {
        let sk = secret_key.unwrap();
        let std_dev = std_dev.unwrap();
        let noise_parameters = StandardDev::from_standard_dev(std_dev);
        let mut output =
            LweCiphertext::allocate(<Torus as Numeric>::ZERO, sk.key_size().to_lwe_size());
        let encoded = Plaintext((u.0 as Torus) << (<Torus as Numeric>::BITS - 4));
        sk.encrypt_lwe(
            &mut output,
            &encoded,
            noise_parameters,
            &mut EncryptionRandomGenerator::new(None),
        );
        LWE(output)
    }

    fn apply_sbox(&self, sbox: &[u4], pk: Option<&PublicKey>) -> Self {
        let bsk = &pk.as_ref().unwrap().bsk;

        let encoder = RealEncoder {
            offset: 0.,
            delta: 16.,
        };

        // allocation of the result
        let mut accumulator = GlweCiphertext::allocate(0, bsk.polynomial_size(), bsk.glwe_size());

        for (i, res) in accumulator
            .get_mut_body()
            .as_mut_tensor()
            .as_mut_slice()
            .iter_mut()
            .enumerate()
        {
            // create a valid encoding from i
            let shift =
                Torus::BITS as usize - 1 - (f64::log2(bsk.polynomial_size().0 as f64) as usize);
            let encoded = Plaintext(
                ((i as Torus) << shift)
                    .round_to_closest_multiple(DecompositionBaseLog(4), DecompositionLevelCount(1)),
            );

            // decode the encoding
            let decoded = encoder.decode(encoded).0 as u8;

            // apply the function
            let f_decoded = if decoded < 8 {
                f64::from(sbox[decoded as usize].0)
            } else {
                f64::from((16 - sbox[(decoded - 8) as usize].0) % 16)
            };

            *res = encoder.encode(Cleartext(f_decoded)).0;
            *res =
                res.round_to_closest_multiple(DecompositionBaseLog(4), DecompositionLevelCount(1));
        }

        // allocate the result
        let mut bootstrapped_result = LweCiphertext::allocate(
            0,
            LweSize(bsk.glwe_size().to_glwe_dimension().0 * bsk.polynomial_size().0 + 1),
        );

        // compute the bootstrap
        bootstrap(&mut bootstrapped_result, &self.0, &bsk, &mut accumulator);

        LWE(bootstrapped_result)
    }

    fn negate(&mut self) {
        self.0.update_with_neg();
    }

    #[cfg(not(feature = "single_key"))]
    fn keyswitch(&mut self, pk: Option<&PublicKey>) {
        if self.0.lwe_size() == pk.as_ref().unwrap().ksk.after_key_size().to_lwe_size() {
            let mut res =
                LweCiphertext::allocate(0, pk.unwrap().ksk_inv.after_key_size().to_lwe_size());
            pk.unwrap().ksk_inv.keyswitch_ciphertext(&mut res, &self.0);
            *self = LWE(res);
        } else {
            let mut res =
                LweCiphertext::allocate(0, pk.unwrap().ksk.after_key_size().to_lwe_size());
            pk.unwrap().ksk.keyswitch_ciphertext(&mut res, &self.0);
            *self = LWE(res);
        }
    }

    #[cfg(feature = "single_key")]
    fn keyswitch(&mut self, pk: Option<&PublicKey>) {
        let mut res = LweCiphertext::allocate(0, pk.unwrap().ksk.after_key_size().to_lwe_size());
        pk.unwrap().ksk.keyswitch_ciphertext(&mut res, &self.0);
        *self = LWE(res);
    }

    fn add(&self, rhs: &Self) -> Self {
        let mut output = self.clone();
        output.add_assign(&rhs);
        output
    }

    fn add_u4(&self, rhs: &u4) -> Self {
        let mut output = self.clone();
        output.add_assign_u4(&rhs);
        output
    }

    fn add_assign(&mut self, rhs: &Self) {
        self.0.update_with_add(&rhs.0);
    }

    fn add_assign_u4(&mut self, rhs: &u4) {
        self.add_assign(&Self::from_u4_with_lwe_size(*rhs, Some(self.0.lwe_size())));
    }
}
