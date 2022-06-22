#[cfg(test)]
mod tests {
    use crate::hasher::{Blake2bHasher, Hasher, Sha3_224Hasher, Sha3_256Hasher};
    use crate::keys::Key;
    use crate::params::{checksum, Params, SEED_SIZE};
    use crate::security;
    use crate::security::ParamsEncoding;

    const TEST_DATA: &[u8; 10] = b"XX NETWORK";

    const TEST_VECTOR_256: [u8; 34] = [
        38, 127, 249, 206, 220, 112, 171, 226, 191, 50, 63, 220, 72, 3, 189, 209, 251, 182, 0, 86,
        98, 113, 43, 174, 7, 95, 115, 145, 216, 128, 64, 1, 16, 0,
    ];

    const CHECKSUM_256: [u8; 2] = [16, 0];

    const TEST_VECTOR_224: [u8; 30] = [
        82, 8, 4, 8, 108, 101, 58, 230, 192, 187, 159, 234, 252, 38, 125, 184, 97, 60, 179, 51,
        224, 146, 175, 237, 207, 0, 109, 245, 13, 112,
    ];

    const CHECKSUM_224: [u8; 2] = [13, 112];

    const TEST_VECTOR_192: [u8; 26] = [
        82, 8, 4, 8, 108, 101, 58, 230, 192, 187, 159, 234, 252, 38, 125, 184, 97, 60, 179, 51,
        224, 146, 175, 237, 11, 165,
    ];

    const CHECKSUM_192: [u8; 2] = [11, 165];

    #[test]
    fn checksum_256_test() {
        let mut hasher = Sha3_256Hasher::new();
        hasher.write(TEST_DATA.to_vec());
        let mut out = vec![0u8; Sha3_256Hasher::size()];
        hasher.sum(&mut out);

        let ret = checksum(&out);
        assert_eq!(ret, CHECKSUM_256);
    }

    #[test]
    fn checksum_224_test() {
        let mut hasher = Sha3_224Hasher::new();
        hasher.write(TEST_DATA.to_vec());
        let mut out = vec![0u8; Sha3_224Hasher::size()];
        hasher.sum(&mut out);

        let ret = checksum(&out);
        assert_eq!(ret, CHECKSUM_224);
    }

    #[test]
    fn checksum_192_test() {
        let mut hasher = Sha3_224Hasher::new();
        hasher.write(TEST_DATA.to_vec());
        let mut out = vec![0u8; Sha3_224Hasher::size()];
        hasher.sum(&mut out);

        let ret = checksum(&out[..24]);
        assert_eq!(ret, CHECKSUM_192);
    }

    #[test]
    fn max_checksum_256_test() {}

    #[test]
    fn min_checksum_test() {}

    #[test]
    fn key_sign_consistency_test() {
        for i in 0..5 {
            let encoding = ParamsEncoding::from(i as u8);
            match encoding {
                ParamsEncoding::Level0 => {
                    consistency_params_test::<Blake2bHasher, Sha3_224Hasher>(
                        security::level_0_params(),
                    );
                }
                ParamsEncoding::Level1 => {
                    consistency_params_test::<Blake2bHasher, Sha3_224Hasher>(
                        security::level_1_params(),
                    );
                }
                ParamsEncoding::Level2 => {
                    consistency_params_test::<Blake2bHasher, Sha3_224Hasher>(
                        security::level_2_params(),
                    );
                }
                ParamsEncoding::Level3 => {
                    consistency_params_test::<Blake2bHasher, Sha3_224Hasher>(
                        security::level_3_params(),
                    );
                }
                ParamsEncoding::Consensus => {
                    consistency_params_test::<Blake2bHasher, Sha3_256Hasher>(
                        security::consensus_params(),
                    );
                }
                _ => {
                    assert!(false);
                }
            };
        }
    }

    fn consistency_params_test<PRFH: Hasher + Clone, MSGH: Hasher + Clone>(
        params: Params<PRFH, MSGH>,
    ) {
        let params_copy = params.clone();
        println!("testing encoding {:?}", params.encoding);
        let mut key = Key::new(params_copy);
        key.generate().unwrap();
        let signature = key.sign(TEST_DATA).unwrap();
        assert_eq!(signature[0], u8::from(&params.encoding));
        assert_eq!(signature[1..1 + SEED_SIZE], key.p_seed);

        let compare = match params.m {
            32 => TEST_VECTOR_256.to_vec(),
            28 => TEST_VECTOR_224.to_vec(),
            24 => TEST_VECTOR_192.to_vec(),
            _ => {
                assert!(false);
                return;
            }
        };

        let public_key = key.public_key().unwrap();

        let offset = 1 + SEED_SIZE;
        let chains = &key.chains.unwrap();
        for i in 0..params.total {
            let start = i * params.n;
            let end = (i + 1) * params.n;
            assert_eq!(
                signature[offset + start..offset + end],
                chains[compare[i] as usize][start..end]
            );
        }

        params
            .verify(TEST_DATA, &signature[1..], &public_key)
            .unwrap();
    }
}
