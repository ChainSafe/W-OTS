use crate::hasher::Hasher;
use crate::params::{ComputeLaddersMode, Params, WotsError, MAX_MSG_SIZE, SEED_SIZE};

#[cfg(feature = "std")]
use rand::{rngs::OsRng, RngCore};

/// Size of WOTS+ public keys
pub const PK_SIZE: usize = 32;

#[derive(Clone)]
pub struct Key<PRFH: Hasher + Clone, MSGH: Hasher + Clone> {
    pub seed: [u8; SEED_SIZE],
    pub p_seed: [u8; SEED_SIZE],
    pub chains: Option<Vec<Vec<u8>>>,
    pub secret_key: Vec<u8>,
    pub public_key: Vec<u8>,
    params: Params<PRFH, MSGH>,
    prf_hash: std::marker::PhantomData<PRFH>,
    msg_hash: std::marker::PhantomData<MSGH>,
}

impl<PRFH: Hasher + Clone, MSGH: Hasher + Clone> Key<PRFH, MSGH> {
    /// Generate new key pair from the provided `seed`.
    ///
    /// @WARNING: THIS WILL ONLY BE SECURE IF THE `seed` IS SECURE. If it can be guessed
    /// by an attacker then they can also derive your key.
    pub fn from_seed(
        params: Params<PRFH, MSGH>,
        seed: [u8; SEED_SIZE],
        p_seed: [u8; SEED_SIZE],
    ) -> Result<Self, WotsError> {
        let sk = calculate_secret_key::<PRFH, MSGH>(&params, &seed);
        let public_key = calculate_public_key(&params, &p_seed, &sk)?;
        Ok(Key::<PRFH, MSGH> {
            seed,
            p_seed,
            chains: None,
            secret_key: sk,
            public_key,
            params,
            prf_hash: std::marker::PhantomData::<PRFH>,
            msg_hash: std::marker::PhantomData::<MSGH>,
        })
    }

    #[cfg(feature = "std")]
    pub fn new(params: Params<PRFH, MSGH>) -> Result<Self, WotsError> {
        let mut seed = [0u8; SEED_SIZE];
        OsRng.fill_bytes(&mut seed);
        let mut p_seed = [0u8; SEED_SIZE];
        OsRng.fill_bytes(&mut p_seed);
        Self::from_seed(params, seed, p_seed)
    }

    pub fn generate(&mut self) -> Result<(), WotsError> {
        if self.chains.is_some() {
            return Ok(());
        }

        let (_, chains) = self.params.compute_ladders(
            &self.p_seed,
            None,
            &self.secret_key,
            ComputeLaddersMode::Generate,
        )?;
        self.chains = Some(chains);
        Ok(())
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, WotsError> {
        if msg.len() > MAX_MSG_SIZE {
            return Err(WotsError::InvalidMessageSize);
        }

        if self.chains.is_some() {
            return self.fast_sign(msg);
        }

        let (signature, _) = self.params.compute_ladders(
            &self.p_seed,
            Some(msg.to_vec()),
            &self.secret_key,
            ComputeLaddersMode::Sign,
        )?;
        Ok(self.build_signature(&signature))
    }

    fn fast_sign(&self, msg: &[u8]) -> Result<Vec<u8>, WotsError> {
        let data = self.params.msg_hash_and_compute_checksum(msg);
        let mut sig = vec![0u8; self.params.n * self.params.total];
        let chains = self.chains.as_ref().ok_or(WotsError::ChainsNotSet)?;
        for i in 0..self.params.total {
            let start = i * self.params.n;
            let end = (i + 1) * self.params.n;
            sig[start..end].copy_from_slice(&chains[data[i] as usize][start..end]);
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

fn calculate_secret_key<PRFH: Hasher + Clone, MSGH: Hasher + Clone>(
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

fn calculate_public_key<PRFH: Hasher + Clone, MSGH: Hasher + Clone>(
    params: &Params<PRFH, MSGH>,
    p_seed: &[u8],
    secret_key: &[u8],
) -> Result<Vec<u8>, WotsError> {
    let (public_key, _) = params.compute_ladders(
        p_seed,
        None,
        secret_key,
        ComputeLaddersMode::ComputePublicKey,
    )?;
    Ok(public_key)
}

#[cfg(test)]
mod tests {
    use crate::hasher::{Blake2bHasher, Sha3_256Hasher};
    use crate::keys::{Key, PK_SIZE};
    use crate::params::{MAX_MSG_SIZE, SEED_SIZE};
    use crate::security;

    #[test]
    fn key_generate() {
        let params = security::consensus_params();
        let mut key = Key::<Blake2bHasher, Sha3_256Hasher>::new(params).unwrap();
        key.generate().unwrap();
    }

    #[test]
    fn key_public_key() {
        let params = security::consensus_params();
        let key = Key::<Blake2bHasher, Sha3_256Hasher>::new(params).unwrap();
        assert_eq!(key.public_key.len(), PK_SIZE);
        // TODO: should pubkey size still be 32 even w/ level0 etc. params?
    }

    #[test]
    fn key_public_key_generate() {
        let params = security::consensus_params();
        let mut key = Key::<Blake2bHasher, Sha3_256Hasher>::new(params).unwrap();
        key.generate().unwrap();
        let pk = key.public_key;
        assert_eq!(pk.len(), PK_SIZE);
    }

    #[test]
    fn key_sign() {
        let params = security::consensus_params();
        let sig_size = (params.n * params.total) + 1 + SEED_SIZE;
        let key = Key::<Blake2bHasher, Sha3_256Hasher>::new(params).unwrap();

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
        let mut key = Key::<Blake2bHasher, Sha3_256Hasher>::new(params).unwrap();
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
