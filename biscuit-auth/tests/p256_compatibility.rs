// SPDX-License-Identifier: Apache-2.0

use biscuit_auth::{builder::Algorithm, Biscuit, PrivateKey, PublicKey};
use rand::{rngs::StdRng, SeedableRng};

#[test]
fn rfc6979_signature_keeps_der_encoding() {
    // RFC 6979 A.2.5, P-256 with SHA-256: retain both DER integer padding
    // and the original high-S value rather than normalizing it.
    let private = PrivateKey::from_bytes_hex(
        "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        Algorithm::Secp256r1,
    )
    .expect("RFC 6979 private key");
    let key = private;
    let expected = hex::decode(concat!(
        "3046022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
        "022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
    ))
    .expect("RFC 6979 DER signature");

    let signature = key.sign(b"sample").expect("sign RFC 6979 message");
    assert_eq!(signature.to_bytes(), expected);
    key.public()
        .verify_signature(b"sample", &signature)
        .expect("verify original signature");
    assert!(key
        .public()
        .verify_signature(b"changed", &signature)
        .is_err());
}

#[test]
fn seeded_p256_keys_keep_compressed_sec1_encoding() {
    let mut rng = StdRng::seed_from_u64(1234);
    let key = PrivateKey::new_with_rng(Algorithm::Secp256r1, &mut rng);
    // The external signing key in the existing test037 fixture.
    assert_eq!(
        key.public().to_bytes_hex(),
        "025e918fd4463832aea2823dfd9716a36b4d9b1377bd53dd82ddf4c0bc75ed6bbf"
    );
    let restored = PublicKey::from_bytes(&key.public().to_bytes(), Algorithm::Secp256r1)
        .expect("read compressed SEC1 public key");
    restored
        .verify_signature(b"seeded key", &key.sign(b"seeded key").expect("sign"))
        .expect("verify with restored public key");
}

#[test]
fn existing_p256_token_vectors_still_verify() {
    let samples: serde_json::Value =
        serde_json::from_str(include_str!("../samples/samples.json")).expect("existing samples");
    let root = PrivateKey::from_bytes_hex(
        samples["root_private_key"].as_str().expect("fixture root"),
        Algorithm::Ed25519,
    )
    .expect("fixture root key")
    .public();

    let token_bytes = include_bytes!("../samples/test036_secp256r1.bc");
    let token = Biscuit::from(token_bytes, root).expect("verify existing P-256 block chain");
    assert_eq!(token.to_vec().expect("serialize token"), token_bytes);

    // This fixture predates the fork's external-signature-v6 changes. Its
    // legacy signature must still verify via the explicitly legacy API.
    let token_bytes = include_bytes!("../samples/test037_secp256r1_third_party.bc");
    let third_party = Biscuit::unsafe_deprecated_deserialize(token_bytes, root)
        .expect("verify existing legacy P-256 external signature");
    assert_eq!(third_party.to_vec().expect("serialize token"), token_bytes);

    for token in [token, third_party] {
        let mut authorizer = biscuit_auth::builder::AuthorizerBuilder::new()
            .code(r#"resource("file1"); operation("read"); allow if true;"#)
            .expect("read request")
            .build(&token)
            .expect("build authorizer");
        assert_eq!(authorizer.authorize().expect("authorize existing token"), 0);
    }
}
