use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;

pub struct Params {
    // security parameter; size of secret key and ladder points (in bytes)
    n: u64,

    // size of message to be signed (after hashing) (in bytes)
    m: u64,
}

impl Params {
    // compute_chain returns the result of c(input, random_elements) iterated total times.
    fn compute_chain(&self, total: u64, input: &[u8], random_elements: Vec<Vec<u8>>) -> Vec<u8> {
        let mut prev = vec![0u8; self.n as usize];
        prev.clone_from_slice(input);

        for i in 1..total {
            let preimage: Vec<u8> = prev
                .iter()
                .zip(random_elements[i as usize].iter())
                .map(|(&x1, &x2)| x1 ^ x2)
                .collect();

            // TODO: make hasher configurable
            let mut hasher = Blake2bVar::new(self.n as usize).unwrap();
            // TODO: write private key "public seed"?
            // hasher.write(vec![i as u8]);
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

pub struct PrivateKey {
    seed: Vec<u8>,
}

pub struct PublicKey {
    key: Vec<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use crate::Params;
    use rand_core::{OsRng, RngCore};

    #[test]
    fn compute_chain() {
        let params = Params { n: 32, m: 32 };

        let total = 16; //arbitrary
        let input = vec![99u8; 32];
        let mut random_elements = vec![vec![0u8; 32]; total];
        for i in 0..total {
            let mut x = vec![0u8; 32];
            OsRng.fill_bytes(&mut x);
            random_elements[i] = x;
        }

        let res = params.compute_chain(16, &input, random_elements);
        assert!(res.len() == input.len());
        println!("{:?}", res);
    }
}
