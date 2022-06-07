pub struct PrivateKey {
    seed: Vec<u8>,
    //random_elements: Vec<Vec<u8>>,
}

impl PrivateKey {
    fn new() -> Self {
        let mut seed = vec![0u8; SeedSize as usize];
        OsRng.fill_bytes(&mut seed);

        // // TODO: SeedSize or params.n?
        // let mut random_elements = vec![vec![0u8; SeedSize as usize]; total];
        // for i in 0..total {
        //     let mut x = vec![0u8; 32];
        //     OsRng.fill_bytes(&mut x);
        //     random_elements[i] = x;
        // }

        PrivateKey {
            seed: seed,
            //random_elements: random_elements,
        }
    }

    fn public_key(&self) -> PublicKey {
        let mut pubkey = vec![vec![0u8; SeedSize as usize]];

        PublicKey {
            key: pubkey,
        }
    }
}

pub struct PublicKey {
    key: Vec<Vec<u8>>,
}
