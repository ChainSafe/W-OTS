use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
//use rand_core::{OsRng, RngCore};
use sha3::{Digest, Sha3_256};

use crate::hasher::Hasher;

// Winterhits parameter (I think)
pub const W: u32 = 256;

// Secret and public seed size
pub const SEED_SIZE: u32 = 32;

pub const MAX_MSG_SIZE: u32 = 254;

pub struct Params<H: Hasher> {
    // security parameter; size of secret key and ladder points (in bytes)
    n: u64,

    // size of message to be signed (after hashing) (in bytes)
    m: u64,

    // TODO: just make these generic parameters
    prf_hash: H,
    msg_hash: H,

    // total number of ladders
    total: u64,
}

impl<H: Hasher> Params<H> {
    fn new(n: u64, m: u64, prf_hash: H, msg_hash: H) -> Option<Params<H>> {
        if m < 1 || m > MAX_MSG_SIZE as u64 {
            // TODO: return error
            return None;
        }

        if H::size() < n as usize || H::size() < m as usize {
            // TODO: return error
            return None;
        }

        let mut checksum_ladders = 2;
        if m == 1 {
            checksum_ladders = 1;
        }

        Some(Params {
            n: n,
            m: m,
            prf_hash: prf_hash,
            msg_hash: msg_hash,
            total: m + checksum_ladders,
        })
    }

    fn msg_hash_and_compute_checksum(&self, msg: Vec<u8>) -> Vec<u8> {
        let mut hasher = H::new();
        let mut msg_buf = vec![0u8; H::size()];
        let mut hashed_msg = vec![0u8; self.m as usize];
        hasher.write(msg);
        hasher.sum(&mut msg_buf);
        hashed_msg[0..self.m as usize].clone_from_slice(&msg_buf[0..self.m as usize]);
        hashed_msg.append(&mut checksum(&hashed_msg));
        hashed_msg
    }

    fn compute_ladders(
        &mut self,
        p_seed: Vec<u8>,
        msg: Option<Vec<u8>>,
        points: Vec<u8>,
        chains: Option<Vec<Vec<u8>>>,
        sign: bool,
    ) -> Vec<u8> {
        let start: Vec<u8>;
        if msg.is_some() {
            start = self.msg_hash_and_compute_checksum(msg.unwrap());
        } else {
            start = vec![0u8; self.total as usize];
        }

        let random_elements = compute_random_elements::<H>(self.n, &p_seed);
        let mut value = vec![0u8; self.n as usize];

        let mut outputs: Vec<u8>;
        let has_chains = chains.is_some();

        if has_chains {
            outputs = chains.unwrap()[(W - 1) as usize].clone();
        } else {
            outputs = vec![0u8; (self.n * self.total) as usize];
        }

        let mut t_hasher = Sha3_256::new();

        let mut begin;
        let mut end;

        for i in 0..self.total {
            let from = (i * self.n) as usize;
            let to = ((i + 1) * self.n) as usize;
            value.clone_from_slice(&points[from..to]);

            if sign {
                begin = 0;
                end = start[i as usize];
            } else {
                begin = start[i as usize];
                end = (W - 1) as u8;
            }

            value = self.compute_chain(&p_seed, &value, &random_elements, begin, end);
            // TODO: if GENERATE()

            if !has_chains {
                outputs[from..to].clone_from_slice(&value);
            }

            if !sign {
                if parity(&value) {
                    Digest::update(&mut t_hasher, &value);
                }
            }
        }

        if !sign {
            let tweak = t_hasher.finalize();
            let mut t_hasher = Sha3_256::new();
            Digest::update(&mut t_hasher, &p_seed);
            Digest::update(&mut t_hasher, &tweak);
            Digest::update(&mut t_hasher, &outputs);
            return t_hasher.finalize().to_vec();
        }

        outputs
    }

    // compute_chain returns the result of c(input, random_elements) iterated total times.
    fn compute_chain(
        &mut self,
        p_seed: &[u8],
        input: &[u8],
        random_elements: &Vec<Vec<u8>>,
        begin: u8,
        end: u8,
    ) -> Vec<u8> {
        let mut prev = vec![0u8; self.n as usize];
        prev.clone_from_slice(input);

        for i in begin..end {
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

fn checksum(msg: &[u8]) -> Vec<u8> {
    let mut sum = ((W - 1) as u16) * (msg.len() as u16);
    for n in msg.iter() {
        sum -= *n as u16;
    }
    if msg.len() == 1 {
        return vec![sum as u8];
    }
    let upper = ((sum & 0x0) >> 8) as u8;
    let lower = sum as u8;
    vec![upper, lower]
}

fn compute_random_elements<H: Hasher>(n: u64, p_seed: &[u8]) -> Vec<Vec<u8>> {
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

fn parity(value: &[u8]) -> bool {
    let mut count = 0;
    for n in value.iter() {
        let mut v: u8 = *n;
        v ^= v >> 4;
        v ^= v >> 2;
        v ^= v >> 1;
        count += (v & 1) as i8
    }

    count % 2 == 1
}

#[cfg(test)]
mod tests {
    use crate::hasher::{Blake2bHasher, Hasher};
    use crate::params::Params;
    use rand_core::{OsRng, RngCore};

    #[test]
    fn compute_chain() {
        let mut params = Params::new(32, 32, Blake2bHasher::new(), Blake2bHasher::new()).unwrap();

        let total = 16; //arbitrary
        let input = vec![99u8; 32];
        let p_seed = vec![88u8; 32];

        let mut random_elements = vec![vec![0u8; 32]; total];
        for i in 0..total {
            let mut x = vec![0u8; 32];
            OsRng.fill_bytes(&mut x);
            random_elements[i] = x;
        }

        let res = params.compute_chain(&p_seed, &input, &random_elements, 0, total as u8);
        assert!(res.len() == input.len());
        println!("{:?}", res);
    }
}
