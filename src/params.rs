use sha3::{Digest, Sha3_256};
use thiserror::Error;

use crate::hasher::Hasher;
use crate::keys::PK_SIZE;
use crate::security::ParamsEncoding;

/// Winternits parameter
pub const W: usize = 256;

/// Secret and public seed size
pub const SEED_SIZE: usize = 32;

/// Maximum message size that ca n be signed
pub const MAX_MSG_SIZE: usize = 254;

#[derive(Error, Debug)]
pub enum WotsError {
    #[error("invalid m value: must be between 1 and 254")]
    InvalidMValue,
    #[error("custom parameters not supported; use Params::new_from_values")]
    CustomNotSupported,
    #[error("prf hash size must be less than n and msg hash size must be less than m")]
    InvalidHasher,
    #[error("invalid seed size: expected 32")]
    InvalidSeedSize,
    #[error("invalid message size: must be smaller than 254")]
    InvalidMessageSize,
    #[error("invalid points size for params; must be n * total")]
    InvalidPointsSize,
    #[error("must provide message for sign=true")]
    MustProvideMessage,
    #[error("chains must be set via generate before calling this function")]
    ChainsNotSet,
    #[error("invalid public key size: must be 32 bytes")]
    InvalidPublicKeySize,
    #[error("invalid signature size: must be n + total + SEED_SIZE")]
    InvalidSignatureSize,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("params cannot be consensus or custom")]
    InvalidParamsEncodingType,
    #[error("message should be None for ComputeLaddersMode::ComputePublicKey or ComputeLaddersMode::Generate")]
    NoMessageExpected,
    #[error("expected message for ComputeLaddersMode::Sign or ComputeLaddersMode::Verify")]
    ExpectedMessage,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ComputeLaddersMode {
    Generate,
    Sign,
    Verify,
    ComputePublicKey,
}

#[derive(Debug, Clone)]
pub struct Params<PRFH: Hasher + Clone, MSGH: Hasher + Clone> {
    /// security parameter; size of secret key and ladder points (in bytes)
    pub n: usize,

    /// size of message to be signed (after hashing) (in bytes)
    pub m: usize,

    /// total number of ladders
    pub total: usize,

    /// encoding level
    pub encoding: ParamsEncoding,

    prf_hash: std::marker::PhantomData<PRFH>,
    msg_hash: std::marker::PhantomData<MSGH>,
}

impl<PRFH: Hasher + Clone, MSGH: Hasher + Clone> Params<PRFH, MSGH> {
    pub fn new(encoding: ParamsEncoding) -> Result<Params<PRFH, MSGH>, WotsError> {
        let (n, m) = match encoding {
            ParamsEncoding::Level0 => (20, 24),
            ParamsEncoding::Level1 => (24, 24),
            ParamsEncoding::Level2 => (28, 24),
            ParamsEncoding::Level3 => (32, 24),
            ParamsEncoding::Consensus => (32, 32),
            ParamsEncoding::Custom => {
                return Err(WotsError::CustomNotSupported);
            }
        };

        if !(1..=MAX_MSG_SIZE).contains(&m) {
            return Err(WotsError::InvalidMValue);
        }

        if PRFH::size() < n || MSGH::size() < m {
            return Err(WotsError::InvalidHasher);
        }

        let mut checksum_ladders: usize = 2;
        if m == 1 {
            checksum_ladders = 1;
        }

        Ok(Params::<PRFH, MSGH> {
            n,
            m,
            total: m + checksum_ladders,
            prf_hash: std::marker::PhantomData::<PRFH>,
            msg_hash: std::marker::PhantomData::<MSGH>,
            encoding,
        })
    }

    pub fn new_from_values(n: usize, m: usize) -> Result<Params<PRFH, MSGH>, WotsError> {
        if !(1..=MAX_MSG_SIZE).contains(&m) {
            return Err(WotsError::InvalidMValue);
        }

        if PRFH::size() < n || MSGH::size() < m {
            return Err(WotsError::InvalidHasher);
        }

        let mut checksum_ladders: usize = 2;
        if m == 1 {
            checksum_ladders = 1;
        }

        Ok(Params::<PRFH, MSGH> {
            n,
            m,
            total: m + checksum_ladders,
            prf_hash: std::marker::PhantomData::<PRFH>,
            msg_hash: std::marker::PhantomData::<MSGH>,
            encoding: ParamsEncoding::Custom,
        })
    }

    pub fn msg_hash_and_compute_checksum(&self, msg: &[u8]) -> Vec<u8> {
        let mut hasher = MSGH::new();
        let mut msg_buf = vec![0u8; MSGH::size()];
        let mut hashed_msg = vec![0u8; self.m];
        hasher.write(msg.to_vec());
        hasher.sum(&mut msg_buf);
        hashed_msg[0..self.m].clone_from_slice(&msg_buf[0..self.m]);
        hashed_msg.append(&mut checksum(&hashed_msg));
        hashed_msg
    }

    pub fn compute_ladders(
        &self,
        p_seed: &[u8],
        maybe_msg: Option<Vec<u8>>,
        points: &[u8],
        mode: ComputeLaddersMode,
    ) -> Result<(Vec<u8>, Vec<Vec<u8>>), WotsError> {
        if p_seed.len() != SEED_SIZE {
            return Err(WotsError::InvalidSeedSize);
        }

        if points.len() < (self.n * self.total) as usize {
            return Err(WotsError::InvalidPointsSize);
        }

        if mode == ComputeLaddersMode::Sign && maybe_msg.is_none() {
            return Err(WotsError::MustProvideMessage);
        }

        let start = match maybe_msg {
            Some(msg) => {
                if mode != ComputeLaddersMode::Sign && mode != ComputeLaddersMode::Verify {
                    return Err(WotsError::NoMessageExpected);
                }

                self.msg_hash_and_compute_checksum(&msg)
            }
            None => {
                if mode != ComputeLaddersMode::Generate
                    && mode != ComputeLaddersMode::ComputePublicKey
                {
                    return Err(WotsError::ExpectedMessage);
                }
                vec![0u8; self.total]
            }
        };

        let random_elements = compute_random_elements::<PRFH>(self.n, p_seed);
        let mut value = vec![0u8; self.n];

        let mut outputs = vec![0u8; self.n * self.total];
        let mut chains = vec![vec![0u8; self.n * self.total]; W];
        if mode == ComputeLaddersMode::Generate {
            chains[0].copy_from_slice(points);
        }

        let mut t_hasher = Sha3_256::new();

        let mut begin;
        let mut end;

        for i in 0..self.total {
            let from = (i * self.n) as usize;
            let to = ((i + 1) * self.n) as usize;
            value.clone_from_slice(&points[from..to]);

            match mode {
                ComputeLaddersMode::Sign => {
                    begin = 0;
                    end = start[i as usize];
                }
                _ => {
                    begin = start[i as usize];
                    end = (W - 1) as u8;
                }
            };

            match mode {
                ComputeLaddersMode::Generate => {
                    value = self.compute_chain(
                        p_seed,
                        &value,
                        &random_elements,
                        Some(&mut chains),
                        i,
                        (begin, end),
                    );
                }
                _ => {
                    value =
                        self.compute_chain(p_seed, &value, &random_elements, None, i, (begin, end));
                }
            };

            outputs[from..to].copy_from_slice(&value);

            if mode != ComputeLaddersMode::Sign && parity(&value) {
                Digest::update(&mut t_hasher, &value);
            }
        }

        if mode != ComputeLaddersMode::Sign {
            let tweak = t_hasher.finalize();
            let mut t_hasher = Sha3_256::new();
            Digest::update(&mut t_hasher, &p_seed);
            Digest::update(&mut t_hasher, &tweak);
            Digest::update(&mut t_hasher, &outputs);

            return Ok((t_hasher.finalize().to_vec(), chains));
        }

        // if signing, then return outputs (length = n * total)
        Ok((outputs, chains))
    }

    // compute_chain returns the result of c(input, random_elements) iterated total times.
    fn compute_chain(
        &self,
        p_seed: &[u8],
        input: &[u8],
        random_elements: &[Vec<u8>],
        mut maybe_chains: Option<&mut [Vec<u8>]>,
        idx: usize,
        range: (u8, u8),
    ) -> Vec<u8> {
        let mut curr_value = vec![0u8; self.n];
        curr_value.clone_from_slice(input);

        for j in range.0..range.1 {
            let preimage: Vec<u8> = curr_value
                .iter()
                .zip(random_elements[j as usize].iter())
                .map(|(&x1, &x2)| x1 ^ x2)
                .collect();

            let mut hasher = PRFH::new();
            hasher.write(p_seed.to_vec());
            hasher.write(vec![(j + 1) as u8]);
            hasher.write(preimage);
            let mut buf = vec![0u8; PRFH::size()];
            hasher.sum(&mut buf);
            curr_value.clone_from_slice(&buf[0..self.n]);

            if let Some(ref mut chains) = maybe_chains {
                let from = idx * self.n;
                let to = (idx + 1) * self.n;
                chains[j as usize + 1][from..to].copy_from_slice(&curr_value);
            }
        }

        let mut result = vec![0u8; self.n as usize];
        result.clone_from_slice(&curr_value);
        result
    }

    pub fn get_encoding(&self) -> &ParamsEncoding {
        &self.encoding
    }

    pub fn verify(&self, msg: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), WotsError> {
        if public_key.len() != PK_SIZE {
            return Err(WotsError::InvalidPublicKeySize);
        }

        let pk = self.decode(msg, signature)?;
        if public_key != pk {
            return Err(WotsError::InvalidSignature);
        }

        Ok(())
    }

    pub fn decode(&self, msg: &[u8], signature: &[u8]) -> Result<Vec<u8>, WotsError> {
        if signature.len() != (self.total * self.n) + SEED_SIZE {
            return Err(WotsError::InvalidSignatureSize);
        }

        let (pk, _) = self.compute_ladders(
            &signature[0..SEED_SIZE],
            Some(msg.to_vec()),
            &signature[SEED_SIZE..],
            ComputeLaddersMode::Verify,
        )?;
        Ok(pk)
    }
}

pub fn checksum(msg: &[u8]) -> Vec<u8> {
    let mut sum = ((W - 1) as u16) * (msg.len() as u16);
    for n in msg.iter() {
        sum -= *n as u16;
    }
    if msg.len() == 1 {
        return vec![sum as u8];
    }
    let upper = ((sum & 0xff00) >> 8) as u8;
    let lower = sum as u8;
    vec![upper, lower]
}

fn compute_random_elements<H: Hasher>(n: usize, p_seed: &[u8]) -> Vec<Vec<u8>> {
    let mut random_elements = vec![vec![0u8; n]; W - 1];
    let mut buf = vec![0u8; H::size()];

    for i in 0..W - 1 {
        let mut hasher = H::new();
        hasher.write(p_seed.to_vec());
        hasher.write(vec![(i + 1) as u8]);
        hasher.sum(&mut buf);
        random_elements[i as usize].clone_from_slice(&buf[0..n])
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
        count += (v & 1) as i64
    }

    count % 2 == 1
}

#[cfg(test)]
mod tests {
    use crate::hasher::{Blake2bHasher, Hasher, Sha3_256Hasher};
    use crate::params::{ComputeLaddersMode, Params, MAX_MSG_SIZE, SEED_SIZE, W};
    use crate::security;
    use crate::security::ParamsEncoding;
    use rand::{rngs::OsRng, RngCore};

    #[test]
    fn new_params() {
        let res = Params::<Blake2bHasher, Blake2bHasher>::new(ParamsEncoding::Custom);
        assert!(res.is_err());

        let res = Params::<Blake2bHasher, Blake2bHasher>::new_from_values(32, MAX_MSG_SIZE + 1);
        assert!(res.is_err());

        // test PRF hash size too small
        let res = Params::<Blake2bHasher, Blake2bHasher>::new_from_values(64, 32);
        assert!(res.is_err());

        // test msg hash size too small
        let res = Params::<Blake2bHasher, Blake2bHasher>::new_from_values(32, 64);
        assert!(res.is_err());

        // test one checksum ladder
        let params = Params::<Blake2bHasher, Blake2bHasher>::new_from_values(32, 1).unwrap();
        assert_eq!(params.total, 2);

        // test two checksum ladders
        let params = Params::<Blake2bHasher, Blake2bHasher>::new_from_values(32, 2).unwrap();
        assert_eq!(params.total, 4);
    }

    #[test]
    fn compute_chain() {
        let params = security::consensus_params::<Blake2bHasher, Sha3_256Hasher>();
        let total = 16; //arbitrary
        let input = vec![99u8; 32];
        let p_seed = vec![88u8; SEED_SIZE];

        let mut random_elements = vec![vec![0u8; 32]; total];
        for i in 0..total {
            let mut x = vec![0u8; 32];
            OsRng.fill_bytes(&mut x);
            random_elements[i] = x;
        }

        let res =
            params.compute_chain(&p_seed, &input, &random_elements, None, 0, (0, total as u8));
        assert_eq!(res.len(), input.len());
    }

    #[test]
    fn compute_ladders_generate() {
        let params =
            Params::<Blake2bHasher, Blake2bHasher>::new(ParamsEncoding::Consensus).unwrap();
        let p_seed = vec![88u8; SEED_SIZE];
        let points = vec![99u8; params.n * params.total];

        let res = params
            .compute_ladders(&p_seed, None, &points, ComputeLaddersMode::Generate)
            .unwrap();
        assert_eq!(res.0.len(), Blake2bHasher::size());
        assert_eq!(res.1.len(), W);
    }

    #[test]
    fn compute_ladders_compute_pubkey() {
        let params =
            Params::<Blake2bHasher, Blake2bHasher>::new(ParamsEncoding::Consensus).unwrap();
        let p_seed = vec![88u8; SEED_SIZE];
        let points = vec![99u8; params.n * params.total];

        let res = params
            .compute_ladders(&p_seed, None, &points, ComputeLaddersMode::ComputePublicKey)
            .unwrap();
        assert_eq!(res.0.len(), Blake2bHasher::size());
    }

    #[test]
    fn compute_ladders_decode() {
        let params =
            Params::<Blake2bHasher, Blake2bHasher>::new(ParamsEncoding::Consensus).unwrap();
        let p_seed = vec![88u8; SEED_SIZE];
        let points = vec![99u8; params.n * params.total];
        let msg = vec![77u8; MAX_MSG_SIZE];

        let res = params
            .compute_ladders(&p_seed, Some(msg), &points, ComputeLaddersMode::Verify)
            .unwrap();
        assert_eq!(res.0.len(), Blake2bHasher::size());
    }

    #[test]
    fn compute_ladders_sign() {
        let params =
            Params::<Blake2bHasher, Blake2bHasher>::new(ParamsEncoding::Consensus).unwrap();
        let p_seed = vec![88u8; SEED_SIZE];
        let points = vec![99u8; params.n * params.total];
        let msg = vec![77u8; MAX_MSG_SIZE];

        let res = params
            .compute_ladders(&p_seed, Some(msg), &points, ComputeLaddersMode::Sign)
            .unwrap();
        assert_eq!(res.0.len(), params.n * params.total);
    }
}
