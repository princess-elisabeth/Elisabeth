use crate::{nibble::Nibble, u4};
use concrete_core::math::random::RandomGenerator;
use std::cell::{Ref, RefCell};

pub struct SymmetricKey<M: Nibble> {
    key: Vec<M>,
    indices: RefCell<Vec<usize>>,
    key_round: RefCell<Vec<M>>,
    whitening: Vec<u4>,
    rng: RandomGenerator,
}

impl<M: Nibble> SymmetricKey<M> {
    pub fn new(key: Vec<M>, n: usize, seed: u128) -> Self {
        let mut indices = Vec::with_capacity(key.len() as usize);
        indices.extend(0..key.len());
        let key_round = key.iter().take(n).cloned().collect::<Vec<M>>();
        let whitening = vec![u4(0); n];
        Self {
            key,
            indices: RefCell::new(indices),
            key_round: RefCell::new(key_round),
            whitening,
            rng: RandomGenerator::new(Some(seed)),
        }
    }

    pub fn random_whitened_subset(&mut self) -> Ref<'_, Vec<M>> {
        let mut indices = self.indices.borrow_mut();
        let mut key_round = self.key_round.borrow_mut();
        let n = self.whitening.len();
        let key_len = self.key.len();

        for i in 0..n {
            let j = gen_range(&mut self.rng, i, key_len);
            indices.swap(i, j);
        }

        for w in self.whitening.iter_mut() {
            *w = u4(self.rng.random_uniform::<u8>() % (1 << 4));
        }

        key_round
            .iter_mut()
            .take(n)
            .zip(indices.iter().zip(self.whitening.iter()))
            .for_each(|(key_bit, (&i, w))| {
                *key_bit = self.key[i].clone();
                key_bit.add_assign_u4(w);
            });
        drop(key_round);

        self.key_round.borrow()
    }
}

fn gen_range(rng: &mut RandomGenerator, min: usize, max: usize) -> usize {
    if min > max {
        panic!("`min` of range must be less than or equal to `max`");
    }
    let bit_len = ((max - min) as f64).log2().floor() as usize;
    let mut a = (min as u32 + rng.random_uniform_n_lsb::<u32>(bit_len)) as usize;
    while a >= max {
        a = (min as u32 + rng.random_uniform_n_lsb::<u32>(bit_len)) as usize;
    }
    a
}
