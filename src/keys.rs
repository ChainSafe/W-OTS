use crate::hasher::Hasher;
use crate::params::{Params, WotsError, SEED_SIZE};

use rand_core::{OsRng, RngCore};

// Size of WOTS+ public keys
pub const PK_SIZE: usize = 32;

pub struct PrivateKey<H: Hasher> {
    seed: [u8; SEED_SIZE],
    p_seed: [u8; SEED_SIZE],
    chains: Option<Vec<Vec<u8>>>,
    secret_key: Vec<u8>,
    public_key: Option<Vec<u8>>,
    params: Params<H>,
}

impl<H: Hasher> PrivateKey<H> {
    fn new(params: Params<H>) -> Self {
        let mut seed = [0u8; SEED_SIZE];
        OsRng.fill_bytes(&mut seed);
        let mut p_seed = [0u8; SEED_SIZE];
        OsRng.fill_bytes(&mut p_seed);

        let sk = calculate_secret_key(&params, &seed);

        PrivateKey {
            seed: seed,
            p_seed: p_seed,
            chains: None,
            secret_key: sk,
            public_key: None,
            params: params,
        }
    }

    fn public_key(&mut self) -> Result<Vec<u8>, WotsError> {
        if self.public_key.is_some() {
            let pk = self.public_key.clone().unwrap();
            return Ok(pk);
        }

        let p_seed = self.p_seed;
        let res = self
            .params
            .compute_ladders(&p_seed, None, &self.secret_key, false, false);
        match res {
            Ok(public_key) => {
                self.public_key = Some(public_key.clone());
                return Ok(public_key);
            }
            Err(e) => {
                return Err(e);
            }
        }
    }
}

fn calculate_secret_key<H: Hasher>(params: &Params<H>, seed: &[u8]) -> Vec<u8> {
    let mut sks = vec![0u8; params.n * params.total];
    let mut buf = vec![0u8; H::size()];
    for i in 0..params.total {
        let mut hasher = H::new();
        hasher.write(seed.to_vec());
        hasher.write(vec![i as u8]);
        hasher.sum(&mut buf);
        sks[i * params.n..(i + 1) * params.n].copy_from_slice(&buf[0..params.n]);
    }
    sks
}
