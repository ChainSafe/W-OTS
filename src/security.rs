use std::convert::From;

use crate::hasher::{Blake2bHasher, Sha3_224Hasher, Sha3_256Hasher};
use crate::params::Params;

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

pub fn level_0_params() -> Params<Blake2bHasher, Sha3_224Hasher> {
    Params::<Blake2bHasher, Sha3_224Hasher>::new(ParamsEncoding::Level0)
        .expect("instantiating level0 params should not fail")
}

pub fn level_1_params() -> Params<Blake2bHasher, Sha3_224Hasher> {
    Params::<Blake2bHasher, Sha3_224Hasher>::new(ParamsEncoding::Level1)
        .expect("instantiating level1 params should not fail")
}

pub fn level_2_params() -> Params<Blake2bHasher, Sha3_224Hasher> {
    Params::<Blake2bHasher, Sha3_224Hasher>::new(ParamsEncoding::Level2)
        .expect("instantiating level2 params should not fail")
}

pub fn level_3_params() -> Params<Blake2bHasher, Sha3_224Hasher> {
    Params::<Blake2bHasher, Sha3_224Hasher>::new(ParamsEncoding::Level3)
        .expect("instantiating level3 params should not fail")
}

pub fn consensus_params() -> Params<Blake2bHasher, Sha3_256Hasher> {
    Params::<Blake2bHasher, Sha3_256Hasher>::new(ParamsEncoding::Consensus)
        .expect("instantiating consensus params should not fail")
}

#[cfg(test)]
mod tests {
    use crate::security;

    #[test]
    fn params_test() {
        let params = security::level_0_params();
        assert_eq!(params.n, 20);
        assert_eq!(params.m, 24);

        let params = security::level_1_params();
        assert_eq!(params.n, 24);
        assert_eq!(params.m, 24);

        let params = security::level_2_params();
        assert_eq!(params.n, 28);
        assert_eq!(params.m, 24);

        let params = security::level_3_params();
        assert_eq!(params.n, 32);
        assert_eq!(params.m, 24);

        let params = security::consensus_params();
        assert_eq!(params.n, 32);
        assert_eq!(params.m, 32);
    }
}
