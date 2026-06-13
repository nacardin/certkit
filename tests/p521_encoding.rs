//! Byte-stability regression test for P-521 key handling.
//!
//! Pins the SEC1 public key, SPKI DER, and PKCS#8 PEM produced for a fixed
//! P-521 private key, plus the SHA-512 ECDSA signing/verification round-trip.
//! The expected values were captured from the generic `ecdsa::SigningKey<NistP521>`
//! implementation, so this guards against any encoding drift if the underlying
//! key types are changed again.
#![cfg(feature = "p521")]

use certkit::key::{KeyPair, PublicKey};
use der::Encode;

const FIXED_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBfrIqujfrR9n757Ta
sjBuQb7F3etVYQkVQfv+jiPYWV5iwWxpCUGz0zo6M8WKVSRhOjvhB+U1LJjJL7xF
1QNKr1ehgYkDgYYABAGnwAFYss82OZGP0U7UaGyCiLF6zPNMbKrilmEdqRFu8pDN
5RHTvQB3WpKnhK/0IPa0M2mWou5Y7iy5N1tsdJVH8gAD1u4dJf2PFVJAx8kcXTRX
M8cYVVAJ8h9lEkivOk6/kfDEkJ3/t8z9BrLCbYvLy7ifSvRkBleUi7S5j8WSw9Hz
vQ==
-----END PRIVATE KEY-----";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// Captured from the pre-refactor code (with the `p384` workaround on).
const EXPECT_SEC1: &str = "0401a7c00158b2cf3639918fd14ed4686c8288b17accf34c6caae296611da9116ef290cde511d3bd00775a92a784aff420f6b4336996a2ee58ee2cb9375b6c749547f20003d6ee1d25fd8f155240c7c91c5d345733c718555009f21f651248af3a4ebf91f0c4909dffb7ccfd06b2c26d8bcbcbb89f4af4640657948bb4b98fc592c3d1f3bd";
const EXPECT_SPKI: &str = "30819b301006072a8648ce3d020106052b81040023038186000401a7c00158b2cf3639918fd14ed4686c8288b17accf34c6caae296611da9116ef290cde511d3bd00775a92a784aff420f6b4336996a2ee58ee2cb9375b6c749547f20003d6ee1d25fd8f155240c7c91c5d345733c718555009f21f651248af3a4ebf91f0c4909dffb7ccfd06b2c26d8bcbcbb89f4af4640657948bb4b98fc592c3d1f3bd";

#[test]
fn p521_byte_identical_encodings() {
    let kp = KeyPair::import_from_pkcs8_pem(FIXED_PEM).expect("import fixed P-521 PEM");

    let sec1 = kp.get_public_key_der();
    assert_eq!(hex(&sec1), EXPECT_SEC1, "SEC1 public key drifted");

    let spki_der = kp.as_spki().to_der().unwrap();
    assert_eq!(hex(&spki_der), EXPECT_SPKI, "SPKI DER drifted");

    // PKCS#8 PEM must re-encode to exactly the fixed input (canonical encoding).
    let reencoded_pem = kp.encode_private_key_pem().unwrap();
    assert_eq!(
        reencoded_pem.trim_end(),
        FIXED_PEM.trim_end(),
        "PKCS#8 PEM drifted"
    );

    // PublicKey paths.
    let pubk = PublicKey::from_key_pair(&kp);
    assert_eq!(hex(&pubk.to_der().unwrap()), EXPECT_SEC1);
    let pubk2 = PublicKey::from_x509spki(&kp.as_spki()).unwrap();
    assert_eq!(hex(&pubk2.to_der().unwrap()), EXPECT_SEC1);

    // Round-trip: re-import the re-encoded PEM and confirm SEC1 stable.
    let kp2 = KeyPair::import_from_pkcs8_pem(&reencoded_pem).unwrap();
    assert_eq!(sec1, kp2.get_public_key_der(), "round-trip SEC1 mismatch");

    // Signature: must be SHA-512 ECDSA, fixed 132-byte raw r||s, and verify.
    let data = b"certkit p521 deterministic verification message";
    let sig = kp.sign_data(data).unwrap();
    assert_eq!(sig.len(), 132, "P-521 raw signature must be 132 bytes");

    let vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).unwrap();
    let signature = p521::ecdsa::Signature::from_slice(&sig).unwrap();
    use p521::ecdsa::signature::Verifier;
    vk.verify(data, &signature)
        .expect("signature must verify under SHA-512 P-521");
}
