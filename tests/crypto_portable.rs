#[path = "../src/crypto/mod.rs"]
mod crypto;

use crypto::{
    P256_ELEMENT_BYTES, P256_SIGNATURE_BYTES, P256PrivateKey, embedded_panic_crc32, hkdf_sha256,
    hmac_sha256, import_public, sha1, sha256, sha384, sha512, signature_to_der, verify_compact,
    verify_uncompressed,
};

fn hex_decode(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => panic!("bad hex"),
            };
            digit(pair[0]) * 16 + digit(pair[1])
        })
        .collect()
}

fn array64(text: &str) -> [u8; 64] {
    let bytes = hex_decode(text);
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    out
}

#[test]
fn sha_vectors_match_published_outputs() {
    assert_eq!(
        sha1(b"abc").to_vec(),
        hex_decode("a9993e364706816aba3e25717850c26c9cd0d89d")
    );
    assert_eq!(
        sha256(b"abc").to_vec(),
        hex_decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
    assert_eq!(
        sha384(b"abc").to_vec(),
        hex_decode(
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163\
             1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        )
    );
    assert_eq!(
        sha512(b"abc").to_vec(),
        hex_decode(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea2\
             0a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd\
             454d4423643ce80e2a9ac94fa54ca49f"
        )
    );
}

#[test]
fn hmac_and_hkdf_match_rfc_vectors() {
    assert_eq!(
        hmac_sha256(b"Jefe", b"what do ya want for nothing?").to_vec(),
        hex_decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
    );

    let ikm = [0x0bu8; 22];
    let salt: Vec<u8> = (0u8..13).collect();
    let info: Vec<u8> = (0xf0u8..0xfa).collect();
    let mut out = [0u8; 42];
    hkdf_sha256(&salt, &ikm, &info, &mut out);
    assert_eq!(
        out.to_vec(),
        hex_decode(
            "3cb25f25faacd57a90434f64d0362f2a\
             2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865"
        )
    );
}

#[test]
fn derived_signatures_verify_on_both_public_encodings() {
    let signer = P256PrivateKey::derive(b"portable-test-seed", b"portable-test-domain");
    let digest = sha256(b"the guest asked the enclave to sign this");
    let signature = signer.sign_digest(&digest);
    assert!(verify_compact(
        &signer.public_x_bytes(),
        &digest,
        &signature
    ));
    assert!(verify_uncompressed(
        &signer.public_uncompressed(),
        &digest,
        &signature
    ));
}

#[test]
fn derivation_signature_and_der_match_golden_outputs() {
    let key = P256PrivateKey::derive(&[0x5a; 32], b"pkcs10 test");
    let digest = sha256(b"apple-utils");
    let signature = key.sign_digest(&digest);
    let der = signature_to_der(&signature);

    assert_eq!(
        key.public_x_bytes().to_vec(),
        hex_decode("43ffd5464bfdcbc0186987d6a96262e17f12bf7473a35e3d58328eee4ce32631")
    );
    assert_eq!(
        key.public_uncompressed().to_vec(),
        hex_decode(
            "0443ffd5464bfdcbc0186987d6a96262e17f12bf7473a35e3d58328eee4ce32631\
             250594a871e01c7df96da56bedf88970482db76121e20f885f27baca5a189b15"
        )
    );
    assert_eq!(
        digest.to_vec(),
        hex_decode("ec91fc437b118706e0318250d319f1bb9bd7b00317c651090775e998e8160e17")
    );
    assert_eq!(
        signature.to_vec(),
        hex_decode(
            "7fbfe8a493cc1f69427e4607f66291ff696ae683955b62f31868cc22c2ec5bf9\
             aaf1a53918751baec82e21b49a5ba335e2ea21885db7a8dbf2de585348d83cd6"
        )
    );
    assert_eq!(
        der,
        hex_decode(
            "304502207fbfe8a493cc1f69427e4607f66291ff696ae683955b62f31868cc22c2ec5bf9\
             022100aaf1a53918751baec82e21b49a5ba335e2ea21885db7a8dbf2de585348d83cd6"
        )
    );
    assert!(verify_compact(&key.public_x_bytes(), &digest, &signature));
    assert!(verify_uncompressed(
        &key.public_uncompressed(),
        &digest,
        &signature
    ));
}

#[test]
fn imported_public_keys_round_trip_and_reject_tampering() {
    let key = P256PrivateKey::derive(&[0x5a; 32], b"pkcs10 test");
    let compact = import_public(&key.public_x_bytes()).expect("compact imports");
    let uncompressed = import_public(&key.public_uncompressed()).expect("sec1 imports");
    assert_eq!(compact.x_bytes(), key.public_x_bytes());
    assert_eq!(uncompressed.uncompressed(), key.public_uncompressed());

    let digest = sha256(b"apple-utils");
    let signature = key.sign_digest(&digest);
    assert!(verify_uncompressed(
        &compact.uncompressed(),
        &digest,
        &signature
    ));

    let mut wrong_digest = digest;
    wrong_digest[0] ^= 0x80;
    assert!(!verify_compact(
        &key.public_x_bytes(),
        &wrong_digest,
        &signature
    ));

    let mut wrong_sig = signature;
    wrong_sig[0] ^= 0x01;
    assert!(!verify_compact(&key.public_x_bytes(), &digest, &wrong_sig));

    let mut off_curve = key.public_uncompressed();
    off_curve[40] ^= 0x01;
    assert!(import_public(&off_curve).is_none());
}

#[test]
fn der_encoding_handles_high_bit_and_minimal_integers() {
    let mut signature = [0u8; P256_SIGNATURE_BYTES];
    signature[P256_ELEMENT_BYTES - 1] = 0x01;
    signature[P256_ELEMENT_BYTES] = 0xff;
    let der = signature_to_der(&signature);
    assert_eq!(der[0], 0x30);
    assert_eq!(usize::from(der[1]), der.len() - 2);
    assert_eq!(&der[2..5], &[0x02, 0x01, 0x01]);
    assert_eq!(der[5], 0x02);
    assert_eq!(der[6], 33);
    assert_eq!(der[7], 0x00);
    assert_eq!(der[8], 0xff);
    assert!(der[9..].iter().all(|byte| *byte == 0));
}

#[test]
fn crc32_matches_common_reflected_vector() {
    assert_eq!(embedded_panic_crc32(b""), 0);
    assert_eq!(embedded_panic_crc32(b"123456789"), 0xcbf4_3926);
}

#[test]
fn fixed_signature_verifies_against_published_public_key() {
    let digest = sha256(b"sample");
    let mut public = [0u8; 65];
    public.copy_from_slice(&hex_decode(
        "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6\
         7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
    ));
    let signature = array64(
        "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716\
         f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
    );
    assert!(verify_uncompressed(&public, &digest, &signature));
}
