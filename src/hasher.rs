use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use sha3::{Digest, Sha3_224, Sha3_256};

pub trait Hasher {
    fn new() -> Self;
    fn write(&mut self, data: Vec<u8>);
    fn sum(self, out: &mut [u8]);
    fn size() -> usize;
}

#[derive(Debug)]
pub struct Blake2bHasher {
    hasher: blake2::Blake2bVar,
}

impl Hasher for Blake2bHasher {
    fn new() -> Blake2bHasher {
        Blake2bHasher {
            hasher: Blake2bVar::new(32).expect("instantiating blake2b should not fail"),
        }
    }

    fn size() -> usize {
        32
    }

    fn write(&mut self, data: Vec<u8>) {
        self.hasher.update(&data);
    }

    fn sum(self, out: &mut [u8]) {
        self.hasher.finalize_variable(out).unwrap();
    }
}

pub struct Sha3_224Hasher {
    hasher: Sha3_224,
}

impl Hasher for Sha3_224Hasher {
    fn new() -> Sha3_224Hasher {
        Sha3_224Hasher {
            hasher: Sha3_224::new(),
        }
    }

    fn size() -> usize {
        28
    }

    fn write(&mut self, data: Vec<u8>) {
        Digest::update(&mut self.hasher, &data);
    }

    fn sum(self, out: &mut [u8]) {
        let res = self.hasher.finalize();
        out.copy_from_slice(&res);
    }
}

pub struct Sha3_256Hasher {
    hasher: Sha3_256,
}

impl Hasher for Sha3_256Hasher {
    fn new() -> Sha3_256Hasher {
        Sha3_256Hasher {
            hasher: Sha3_256::new(),
        }
    }

    fn size() -> usize {
        32
    }

    fn write(&mut self, data: Vec<u8>) {
        Digest::update(&mut self.hasher, &data);
    }

    fn sum(self, out: &mut [u8]) {
        let res = self.hasher.finalize();
        out.copy_from_slice(&res);
    }
}
