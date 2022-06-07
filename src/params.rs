use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
//use rand_core::{OsRng, RngCore};

use crate::hasher::Hasher;

// Winterhits parameter (I think)
pub const W: u32 = 256;

// Secret and public seed size
pub const SeedSize: u32 = 32;

pub const MaxMsgSize: u32 = 254;

pub struct Params<H: Hasher> {
    // security parameter; size of secret key and ladder points (in bytes)
    n: u64,

    // size of message to be signed (after hashing) (in bytes)
    m: u64,

    prfHash: H,

    // total number of ladders
    total: u64,
}

impl<H: Hasher> Params<H> {
    fn new(n: u64, m: u64, prfHasher: H) -> Option<Params<H>> {
        if m < 1 || m > MaxMsgSize as u64 {
            return None;
        }

        //  if prfHasher.Size()

        let mut checksum_ladders = 2;
        if m == 1 {
            checksum_ladders = 1;
        }

        Some(Params {
            n: n,
            m: m,
            prfHash: prfHasher,
            total: m + checksum_ladders,
        })
    }

    fn msg_hash_and_compute_checksum(&self, msg: Vec<u8>) -> Vec<u8> {
        vec![0u8; 0]
    }

    fn compute_ladders(
        &mut self,
        p_seed: Vec<u8>,
        msg: Vec<u8>,
        points: Vec<u8>,
        chains: Vec<Vec<u8>>,
        sign: bool,
    ) -> Vec<u8> {
        let start: Vec<u8>;
        if msg.len() != 0 {
            // TODO: check nil vs. length==0?
            start = self.msg_hash_and_compute_checksum(msg);
        } else {
            start = vec![0u8; self.total as usize];
        }

        let random_elements = compute_random_elements(self.n, &p_seed, &mut self.prfHash);

        vec![0u8; 0]
    }

    // compute_chain returns the result of c(input, random_elements) iterated total times.
    fn compute_chain(
        &mut self,
        total: u64,
        input: &[u8],
        random_elements: Vec<Vec<u8>>,
    ) -> Vec<u8> {
        let mut prev = vec![0u8; self.n as usize];
        prev.clone_from_slice(input);

        for i in 1..total {
            let preimage: Vec<u8> = prev
                .iter()
                .zip(random_elements[i as usize].iter())
                .map(|(&x1, &x2)| x1 ^ x2)
                .collect();

            // TODO: make hasher configurable
            let mut hasher = Blake2bVar::new(self.n as usize).unwrap();
            // TODO: write private key "public seed"?
            hasher.update(&vec![i as u8]);
            hasher.update(&preimage);
            let mut buf = vec![0u8; self.n as usize];
            hasher.finalize_variable(&mut buf).unwrap();
            prev.clone_from_slice(&buf)
        }

        let mut result = vec![0u8; self.n as usize];
        result.clone_from_slice(&prev);
        result
    }
}

fn compute_random_elements<H: Hasher>(n: u64, p_seed: &[u8], prfHasher: &mut H) -> Vec<Vec<u8>> {
    let mut random_elements = vec![vec![0u8; n as usize]; (W - 1) as usize];
    let mut buf = vec![0u8; H::size()];

    for i in 0..W - 1 {
        let mut hasher = H::new();
        hasher.write(p_seed.to_vec());
        hasher.write(vec![(i + 1) as u8]);
        hasher.sum(&mut buf);
        random_elements[i as usize].clone_from_slice(&buf)
    }

    random_elements
}

#[cfg(test)]
mod tests {
    use crate::hasher::{Blake2bHasher, Hasher};
    use crate::params::Params;
    use rand_core::{OsRng, RngCore};

    #[test]
    fn compute_chain() {
        let mut params = Params::new(32, 32, Blake2bHasher::new()).unwrap();

        let total = 16; //arbitrary
        let input = vec![99u8; 32];
        let mut random_elements = vec![vec![0u8; 32]; total];
        for i in 0..total {
            let mut x = vec![0u8; 32];
            OsRng.fill_bytes(&mut x);
            random_elements[i] = x;
        }

        let res = params.compute_chain(16, &input, random_elements);
        assert!(res.len() == input.len());
        println!("{:?}", res);
    }
}
