use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;

pub trait Hasher {
    fn new() -> Self;
    fn reset(&mut self);
    fn write(&mut self, data: Vec<u8>);
    fn sum(&mut self) -> Vec<u8>;
}

pub struct Blake2bHasher {
    input: Vec<u8>,
    hasher: blake2::Blake2bVar,
}

impl Hasher for Blake2bHasher {
    fn new() -> Self {
        Blake2bHasher{
            input: vec![0u8; 0],
            hasher: Blake2bVar::new(256).unwrap(),
        }
    }

    fn reset(&mut self) {
        // TODO: why does this not work
        //self.hasher.reset();
    }

    fn write(&mut self, mut data: Vec<u8>) {
        self.input.append(&mut data);
    }

    fn sum(&mut self) -> Vec<u8> {
        self.hasher.update(&self.input);
        let mut buf = vec![0u8; 32];
        self.hasher.finalize_variable(&mut buf).unwrap();
        buf
    }
}
