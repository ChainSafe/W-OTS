use crate::hasher::{Blake2bHasher, Sha3_224, Sha3_256};
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

pub fn level_0_params() -> Params<Blake2bHasher, Sha3_224> {
    Params::<Blake2bHasher, Sha3_224>::new(ParamsEncoding::Level0).unwrap()
}

pub fn level_1_params() -> Params<Blake2bHasher, Sha3_224> {
    Params::<Blake2bHasher, Sha3_224>::new(ParamsEncoding::Level1).unwrap()
}

pub fn level_2_params() -> Params<Blake2bHasher, Sha3_224> {
    Params::<Blake2bHasher, Sha3_224>::new(ParamsEncoding::Level2).unwrap()
}

pub fn level_3_params() -> Params<Blake2bHasher, Sha3_224> {
    Params::<Blake2bHasher, Sha3_224>::new(ParamsEncoding::Level3).unwrap()
}

pub fn consensus_params() -> Params<Blake2bHasher, Sha3_256> {
    Params::<Blake2bHasher, Sha3_256>::new(ParamsEncoding::Consensus).unwrap()
}
