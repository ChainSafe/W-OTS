use std::convert::From;

use crate::hasher::{Blake2bHasher, Hasher, Sha3_224Hasher, Sha3_256Hasher};
use crate::params::{Params, WotsError};

#[derive(Debug, Clone)]
pub enum ParamsEncoding {
    Level0,
    Level1,
    Level2,
    Level3,
    Consensus,
    Custom,
}

impl From<u8> for ParamsEncoding {
    fn from(item: u8) -> Self {
        match item {
            0 => ParamsEncoding::Level0,
            1 => ParamsEncoding::Level1,
            2 => ParamsEncoding::Level2,
            3 => ParamsEncoding::Level3,
            4 => ParamsEncoding::Consensus,
            _ => ParamsEncoding::Custom,
        }
    }
}

impl From<&ParamsEncoding> for u8 {
    fn from(item: &ParamsEncoding) -> Self {
        match item {
            ParamsEncoding::Level0 => 0,
            ParamsEncoding::Level1 => 1,
            ParamsEncoding::Level2 => 2,
            ParamsEncoding::Level3 => 3,
            ParamsEncoding::Consensus => 4,
            ParamsEncoding::Custom => 5,
        }
    }
}

impl<PRFH: Hasher + Clone, MSGH: Hasher + Clone> From<&ParamsEncoding> for Params<PRFH, MSGH> {
    fn from(item: &ParamsEncoding) -> Self {
        match item {
            ParamsEncoding::Level0 => level_0_params(),
            ParamsEncoding::Level1 => level_1_params(),
            ParamsEncoding::Level2 => level_2_params(),
            ParamsEncoding::Level3 => level_3_params(),
            ParamsEncoding::Consensus => consensus_params(),
            ParamsEncoding::Custom => consensus_params(), // TODO
        }
    }
}

pub fn level_0_params<PRFH: Hasher + Clone, MSGH: Hasher + Clone>() -> Params<PRFH, MSGH> {
    Params::new(ParamsEncoding::Level0).expect("instantiating level0 params should not fail")
}

pub fn level_1_params<PRFH: Hasher + Clone, MSGH: Hasher + Clone>() -> Params<PRFH, MSGH> {
    Params::new(ParamsEncoding::Level1).expect("instantiating level1 params should not fail")
}

pub fn level_2_params<PRFH: Hasher + Clone, MSGH: Hasher + Clone>() -> Params<PRFH, MSGH> {
    Params::new(ParamsEncoding::Level2).expect("instantiating level2 params should not fail")
}

pub fn level_3_params<PRFH: Hasher + Clone, MSGH: Hasher + Clone>() -> Params<PRFH, MSGH> {
    Params::new(ParamsEncoding::Level3).expect("instantiating level3 params should not fail")
}

pub fn consensus_params<PRFH: Hasher + Clone, MSGH: Hasher + Clone>() -> Params<PRFH, MSGH> {
    Params::new(ParamsEncoding::Consensus).expect("instantiating consensus params should not fail")
}

pub fn verify(msg: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), WotsError> {
    match ParamsEncoding::from(signature[0]) {
        ParamsEncoding::Level0 => level_0_params::<Blake2bHasher, Sha3_224Hasher>().verify(
            msg,
            &signature[1..],
            public_key,
        ),
        ParamsEncoding::Level1 => level_1_params::<Blake2bHasher, Sha3_224Hasher>().verify(
            msg,
            &signature[1..],
            public_key,
        ),
        ParamsEncoding::Level2 => level_2_params::<Blake2bHasher, Sha3_224Hasher>().verify(
            msg,
            &signature[1..],
            public_key,
        ),
        ParamsEncoding::Level3 => level_3_params::<Blake2bHasher, Sha3_224Hasher>().verify(
            msg,
            &signature[1..],
            public_key,
        ),
        ParamsEncoding::Consensus => consensus_params::<Blake2bHasher, Sha3_256Hasher>().verify(
            msg,
            &signature[1..],
            public_key,
        ),
        _ => Err(WotsError::InvalidParamsEncodingType),
    }
}

/// Disallows verification of signatures signed using consensus parameters.
pub fn verify_no_consensus(
    msg: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<(), WotsError> {
    match ParamsEncoding::from(signature[0]) {
        ParamsEncoding::Level0 => level_0_params::<Blake2bHasher, Sha3_224Hasher>().verify(
            msg,
            &signature[1..],
            public_key,
        ),
        ParamsEncoding::Level1 => level_1_params::<Blake2bHasher, Sha3_224Hasher>().verify(
            msg,
            &signature[1..],
            public_key,
        ),
        ParamsEncoding::Level2 => level_2_params::<Blake2bHasher, Sha3_224Hasher>().verify(
            msg,
            &signature[1..],
            public_key,
        ),
        ParamsEncoding::Level3 => level_3_params::<Blake2bHasher, Sha3_224Hasher>().verify(
            msg,
            &signature[1..],
            public_key,
        ),
        _ => Err(WotsError::InvalidParamsEncodingType),
    }
}

#[cfg(test)]
mod tests {
    use crate::hasher::{Blake2bHasher, Sha3_224Hasher, Sha3_256Hasher};
    use crate::keys::Key;
    use crate::params::{MAX_MSG_SIZE, SEED_SIZE};
    use crate::security;
    use crate::security::{verify, verify_no_consensus};

    #[test]
    fn params_test() {
        let params = security::level_0_params::<Blake2bHasher, Sha3_224Hasher>();
        assert_eq!(params.n, 20);
        assert_eq!(params.m, 24);

        let params = security::level_1_params::<Blake2bHasher, Sha3_224Hasher>();
        assert_eq!(params.n, 24);
        assert_eq!(params.m, 24);

        let params = security::level_2_params::<Blake2bHasher, Sha3_224Hasher>();
        assert_eq!(params.n, 28);
        assert_eq!(params.m, 24);

        let params = security::level_3_params::<Blake2bHasher, Sha3_224Hasher>();
        assert_eq!(params.n, 32);
        assert_eq!(params.m, 24);

        let params = security::consensus_params::<Blake2bHasher, Sha3_256Hasher>();
        assert_eq!(params.n, 32);
        assert_eq!(params.m, 32);
    }

    #[test]
    fn verify_consensus_params_should_fail() {
        let params = security::consensus_params::<Blake2bHasher, Sha3_256Hasher>();
        let sig_size = (params.n * params.total) + 1 + SEED_SIZE;
        let mut key = Key::<Blake2bHasher, Sha3_256Hasher>::new(params).unwrap();
        key.generate().unwrap();

        // should succeed with ok message
        let msg = vec![99u8; MAX_MSG_SIZE];
        let res = key.sign(&msg).unwrap();
        assert_eq!(res.len(), sig_size);

        // should fail to verify with consensus parameters
        let res = verify_no_consensus(&msg, &res, &key.public_key);
        assert!(res.is_err());
    }

    #[test]
    fn verify_test_no_generate() {
        let params = security::level_3_params();
        let sig_size = (params.n * params.total) + 1 + SEED_SIZE;
        let key = Key::<Blake2bHasher, Sha3_224Hasher>::new(params).unwrap();

        let msg = vec![99u8; MAX_MSG_SIZE];
        let res = key.sign(&msg).unwrap();
        assert_eq!(res.len(), sig_size);

        verify(&msg, &res, &key.public_key).unwrap();
    }

    #[test]
    fn verify_test_generate() {
        let params = security::consensus_params();
        let sig_size = (params.n * params.total) + 1 + SEED_SIZE;
        let mut key = Key::<Blake2bHasher, Sha3_256Hasher>::new(params).unwrap();
        key.generate().unwrap();

        let msg = vec![99u8; MAX_MSG_SIZE];
        let res = key.sign(&msg).unwrap();
        assert_eq!(res.len(), sig_size);
        verify(&msg, &res, &key.public_key).unwrap();
    }
}
