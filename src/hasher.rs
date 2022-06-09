use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;

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
            hasher: Blake2bVar::new(32).unwrap(),
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
