use ml_kem::{KemCore, MlKem768};
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256};

/// Ejemplo: Sha1::new() en un comentario no cuenta.
pub fn llaves(rng: &mut impl rand_core::CryptoRngCore) {
    let _ = MlKem768::generate(rng);
    let _ = RsaPrivateKey::new(&mut rng, 2048);
    let _ = Sha256::new();
}
