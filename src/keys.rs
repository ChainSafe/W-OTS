use crate::hasher::{Blake2bHasher, Hasher};
use crate::params::{Params, WotsError, MAX_MSG_SIZE, SEED_SIZE};

use rand_core::{OsRng, RngCore};

/// Size of WOTS+ public keys
pub const PK_SIZE: usize = 32;

pub struct Key<PRFH: Hasher, MSGH: Hasher> {
    seed: [u8; SEED_SIZE],
    p_seed: [u8; SEED_SIZE],
    chains: Option<Vec<Vec<u8>>>,
    secret_key: Vec<u8>,
    public_key: Option<Vec<u8>>,
    params: Params<PRFH, MSGH>,
    prf_hash: std::marker::PhantomData<PRFH>,
    msg_hash: std::marker::PhantomData<MSGH>,
}

impl<PRFH: Hasher, MSGH: Hasher> Key<PRFH, MSGH> {
    fn new(params: Params<PRFH, MSGH>) -> Self {
        let mut seed = [0u8; SEED_SIZE];
        OsRng.fill_bytes(&mut seed);
        let mut p_seed = [0u8; SEED_SIZE];
        OsRng.fill_bytes(&mut p_seed);

        let sk = calculate_secret_key::<PRFH, MSGH>(&params, &seed);

        Key::<PRFH, MSGH> {
            seed: seed,
            p_seed: p_seed,
            chains: None,
            secret_key: sk,
            public_key: None,
            params: params,
            prf_hash: std::marker::PhantomData::<PRFH>,
            msg_hash: std::marker::PhantomData::<MSGH>,
        }
    }

    fn generate(&mut self) -> Result<(), WotsError> {
        if self.chains.is_some() {
            return Ok(());
        }

        let p_seed = self.p_seed;
        let (public_key, chains) =
            self.params
                .compute_ladders(&p_seed, None, &self.secret_key, false, false)?;
        self.public_key = Some(public_key);
        self.chains = Some(chains);
        Ok(())
    }

    fn public_key(&mut self) -> Result<Vec<u8>, WotsError> {
        if self.public_key.is_some() {
            let pk = self.public_key.clone().unwrap();
            return Ok(pk);
        }

        let p_seed = self.p_seed;
        let (public_key, _) =
            self.params
                .compute_ladders(&p_seed, None, &self.secret_key, false, false)?;
        self.public_key = Some(public_key.clone());
        Ok(public_key)
    }

    fn sign(&mut self, msg: &[u8]) -> Result<Vec<u8>, WotsError> {
        if msg.len() > MAX_MSG_SIZE {
            return Err(WotsError::InvalidMessageSize);
        }

        if self.chains.is_some() {
            return self.fast_sign(&msg);
        }

        let p_seed = self.p_seed;
        let (signature, _) = self.params.compute_ladders(
            &p_seed,
            Some(msg.to_vec()),
            &self.secret_key,
            false,
            true,
        )?;
        Ok(self.build_signature(&signature))
    }

    fn fast_sign(&self, msg: &[u8]) -> Result<Vec<u8>, WotsError> {
        let data = self.params.msg_hash_and_compute_checksum(msg);
        let mut sig = vec![0u8; self.params.n * self.params.total];
        let chains = self.chains.as_ref().ok_or(WotsError::ChainsNotSet)?;
        for i in 0..self.params.total {
            sig[i * self.params.n..(i + 1) * self.params.n].copy_from_slice(
                &chains[data[i] as usize][i * self.params.n..(i + 1) * self.params.n],
            );
        }
        Ok(self.build_signature(&sig))
    }

    fn build_signature(&self, sig: &[u8]) -> Vec<u8> {
        let encoding = self.params.get_encoding();
        let mut sig_full = vec![0u8; 1 + SEED_SIZE + sig.len()];
        sig_full[0] = encoding.into();
        sig_full[1..1 + SEED_SIZE].copy_from_slice(&self.p_seed);
        sig_full[1 + SEED_SIZE..].copy_from_slice(sig);
        sig_full
    }
}

fn calculate_secret_key<PRFH: Hasher, MSGH: Hasher>(
    params: &Params<PRFH, MSGH>,
    seed: &[u8],
) -> Vec<u8> {
    let mut sks = vec![0u8; params.n * params.total];
    let mut buf = vec![0u8; PRFH::size()];
    for i in 0..params.total {
        let mut hasher = PRFH::new();
        hasher.write(seed.to_vec());
        hasher.write(vec![i as u8]);
        hasher.sum(&mut buf);
        sks[i * params.n..(i + 1) * params.n].copy_from_slice(&buf[0..params.n]);
    }
    sks
}

#[cfg(test)]
mod tests {
    use crate::hasher::{Blake2bHasher, Hasher, Sha3_224Hasher, Sha3_256Hasher};
    use crate::keys::{Key, PK_SIZE};
    use crate::params::{MAX_MSG_SIZE, SEED_SIZE};
    use crate::security;

    #[test]
    fn key_generate() {
        let params = security::consensus_params();
        let mut key = Key::<Blake2bHasher, Sha3_256Hasher>::new(params);
        key.generate().unwrap();
    }

    #[test]
    fn key_public_key() {
        let params = security::consensus_params();
        let mut key = Key::<Blake2bHasher, Sha3_256Hasher>::new(params);
        let pk = key.public_key().unwrap();
        assert_eq!(pk.len(), PK_SIZE);
        // TODO: should pubkey size still be 32 even w/ level0 etc. params?
    }

    #[test]
    fn key_public_key_generate() {
        let params = security::consensus_params();
        let mut key = Key::<Blake2bHasher, Sha3_256Hasher>::new(params);
        key.generate().unwrap();
        let pk = key.public_key().unwrap();
        assert_eq!(pk.len(), PK_SIZE);
    }

    #[test]
    fn key_sign() {
        let params = security::consensus_params();
        let sig_size = (params.n * params.total) + 1 + SEED_SIZE;
        let mut key = Key::<Blake2bHasher, Sha3_256Hasher>::new(params);

        // should fail to message too large
        let msg = vec![99u8; MAX_MSG_SIZE + 1];
        let res = key.sign(&msg);
        assert!(res.is_err());

        // should succeed with ok message
        let msg = vec![99u8; MAX_MSG_SIZE];
        let res = key.sign(&msg).unwrap();
        assert_eq!(res.len(), sig_size);
    }

    #[test]
    fn key_sign_generate() {
        let params = security::consensus_params();
        let sig_size = (params.n * params.total) + 1 + SEED_SIZE;
        let mut key = Key::<Blake2bHasher, Sha3_256Hasher>::new(params);
        key.generate().unwrap();

        // should fail to message too large
        let msg = vec![99u8; MAX_MSG_SIZE + 1];
        let res = key.sign(&msg);
        assert!(res.is_err());

        // should succeed with ok message
        let msg = vec![99u8; MAX_MSG_SIZE];
        let res = key.sign(&msg).unwrap();
        assert_eq!(res.len(), sig_size);
    }
}
