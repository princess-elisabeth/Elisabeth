use crate::{nibble::Nibble, public_key::PublicKey, u4};
#[cfg(feature = "multithread")]
use rayon::{
    iter::{IntoParallelIterator, ParallelIterator},
    slice::ParallelSlice,
};

#[derive(Clone)]
pub struct Filter {
    sbox: Vec<[u4; 16]>,
    block_width: usize,
}

/// An algorithm used to generate a random nibble from the secret key.
impl Filter {
    /// Generate a new filter.
    pub fn new() -> Self {
        Self {
            sbox: vec![
                [
                    u4(0x3),
                    u4(0x2),
                    u4(0x6),
                    u4(0xC),
                    u4(0xA),
                    u4(0x0),
                    u4(0x1),
                    u4(0xB),
                    u4(0xD),
                    u4(0xE),
                    u4(0xA),
                    u4(0x4),
                    u4(0x6),
                    u4(0x0),
                    u4(0xF),
                    u4(0x5),
                ],
                [
                    u4(0x4),
                    u4(0xB),
                    u4(0x4),
                    u4(0x4),
                    u4(0x4),
                    u4(0xF),
                    u4(0x9),
                    u4(0xC),
                    u4(0xC),
                    u4(0x5),
                    u4(0xC),
                    u4(0xC),
                    u4(0xC),
                    u4(0x1),
                    u4(0x7),
                    u4(0x4),
                ],
                [
                    u4(0xB),
                    u4(0xA),
                    u4(0xC),
                    u4(0x2),
                    u4(0x2),
                    u4(0xB),
                    u4(0xD),
                    u4(0xE),
                    u4(0x5),
                    u4(0x6),
                    u4(0x4),
                    u4(0xE),
                    u4(0xE),
                    u4(0x5),
                    u4(0x3),
                    u4(0x2),
                ],
                [
                    u4(0x5),
                    u4(0x9),
                    u4(0xD),
                    u4(0x2),
                    u4(0xB),
                    u4(0xA),
                    u4(0xC),
                    u4(0x5),
                    u4(0xB),
                    u4(0x7),
                    u4(0x3),
                    u4(0xE),
                    u4(0x5),
                    u4(0x6),
                    u4(0x4),
                    u4(0xB),
                ],
                [
                    u4(0x3),
                    u4(0x0),
                    u4(0xB),
                    u4(0x8),
                    u4(0xD),
                    u4(0xE),
                    u4(0xD),
                    u4(0xB),
                    u4(0xD),
                    u4(0x0),
                    u4(0x5),
                    u4(0x8),
                    u4(0x3),
                    u4(0x2),
                    u4(0x3),
                    u4(0x5),
                ],
                [
                    u4(0x8),
                    u4(0xD),
                    u4(0xC),
                    u4(0xC),
                    u4(0x3),
                    u4(0xF),
                    u4(0xC),
                    u4(0x7),
                    u4(0x8),
                    u4(0x3),
                    u4(0x4),
                    u4(0x4),
                    u4(0xD),
                    u4(0x1),
                    u4(0x4),
                    u4(0x9),
                ],
                [
                    u4(0x4),
                    u4(0x2),
                    u4(0x9),
                    u4(0xD),
                    u4(0xA),
                    u4(0xC),
                    u4(0xA),
                    u4(0x7),
                    u4(0xC),
                    u4(0xE),
                    u4(0x7),
                    u4(0x3),
                    u4(0x6),
                    u4(0x4),
                    u4(0x6),
                    u4(0x9),
                ],
                [
                    u4(0xA),
                    u4(0x2),
                    u4(0x5),
                    u4(0x5),
                    u4(0x3),
                    u4(0xD),
                    u4(0xF),
                    u4(0x1),
                    u4(0x6),
                    u4(0xE),
                    u4(0xB),
                    u4(0xB),
                    u4(0xD),
                    u4(0x3),
                    u4(0x1),
                    u4(0xF),
                ],
            ],
            block_width: 5,
        }
    }

    /// Generate a random nibble from keyround and stores it into rop.
    /// If the key is encrypted, this function needs a public key to work.
    #[cfg(feature = "multithread")]
    pub fn call<T: Nibble>(&self, keyround: &[T], public_key: Option<&PublicKey>) -> T {
        let lwe_size = public_key.map(|pk| {
            if cfg!(feature = "single_key") {
                pk.ksk.after_key_size().to_lwe_size()
            } else {
                pk.ksk.before_key_size().to_lwe_size()
            }
        });

        keyround
            .par_chunks(self.block_width)
            .map(|block| self.filter_block(block, public_key))
            .reduce(
                || T::from_u4_with_lwe_size(u4(0), lwe_size),
                |acc, block_output| acc.add(&block_output),
            )
    }

    /// Generate a random nibble from keyround and stores it into rop.
    /// If the key is encrypted, this function needs a public key to work.
    #[cfg(not(feature = "multithread"))]
    pub fn call<T: Nibble>(&self, keyround: &[T], public_key: Option<&PublicKey>) -> T {
        keyround
            .chunks(self.block_width)
            .map(|block| self.filter_block(block, public_key))
            .reduce(|acc, block_output| acc.add(&block_output))
            .unwrap()
    }

    #[cfg(feature = "multithread")]
    #[allow(unused_mut)]
    fn filter_block<T: Nibble>(&self, block: &[T], public_key: Option<&PublicKey>) -> T {
        let lwe_dimension = public_key.map(|pk| pk.ksk.before_key_size().to_lwe_size());

        let mut last_block = block[self.block_width - 1].clone();
        #[cfg(not(feature = "single_key"))]
        last_block.keyswitch(public_key);

        let first_layer_output = (0..block.len() - 1)
            .into_par_iter()
            .map(|i| {
                (block[i].add(&block[(i + 1) % (self.block_width - 1)]))
                    .apply_sbox(&self.sbox[i], public_key)
            })
            .collect::<Vec<_>>();

        let mut second_layer_output = (0..block.len() - 1)
            .into_par_iter()
            .map(|i| {
                let mut sboxes_sum = first_layer_output[(i + 1) % (self.block_width - 1)]
                    .add(&first_layer_output[(i + 2) % (self.block_width - 1)]);
                sboxes_sum.keyswitch(public_key);
                (block[i].add(&sboxes_sum)).apply_sbox(&self.sbox[4 + i], public_key)
            })
            .reduce(
                || T::from_u4_with_lwe_size(u4(0), lwe_dimension),
                |acc, output| acc.add(&output),
            );
        #[cfg(feature = "single_key")]
        second_layer_output.keyswitch(public_key);
        second_layer_output.add(&last_block)
    }

    #[cfg(not(feature = "multithread"))]
    #[allow(unused_mut)]
    fn filter_block<T: Nibble>(&self, block: &[T], public_key: Option<&PublicKey>) -> T {
        let mut last_block = block[self.block_width - 1].clone();
        #[cfg(not(feature = "single_key"))]
        last_block.keyswitch(public_key);

        let first_layer_output = (0..block.len() - 1)
            .into_iter()
            .map(|i| {
                (block[i].add(&block[(i + 1) % (self.block_width - 1)]))
                    .apply_sbox(&self.sbox[i], public_key)
            })
            .collect::<Vec<_>>();

        let mut second_layer_output = (0..block.len() - 1)
            .into_iter()
            .map(|i| {
                let mut sboxes_sum = first_layer_output[(i + 1) % (self.block_width - 1)]
                    .add(&first_layer_output[(i + 2) % (self.block_width - 1)]);
                sboxes_sum.keyswitch(public_key);
                (block[i].add(&sboxes_sum)).apply_sbox(&self.sbox[4 + i], public_key)
            })
            .reduce(|acc, output| acc.add(&output))
            .unwrap();
        #[cfg(feature = "single_key")]
        second_layer_output.keyswitch(public_key);
        second_layer_output.add(&last_block)
    }
}
