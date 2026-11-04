//! Firma híbrida de CBOM: ML-DSA-65 (FIPS 204) junto con Ed25519.
//!
//! La firma es un archivo aparte (`<cbom>.firma`): el formato JSF que
//! CycloneDX prevé para firmas incrustadas no incluye ML-DSA. Ambas firmas
//! cubren el mismo mensaje, que empieza con una etiqueta de dominio propia
//! de Suaya e incluye el algoritmo compuesto y la huella de la llave pública:
//! una firma Ed25519 separada de su pareja no vale como firma de Suaya y la
//! verificación exige las dos (protección contra el despojo de un componente).
//!
//! La implementación criptográfica es AWS-LC (por medio de aws-lc-rs), la
//! misma biblioteca que usa el sondeo TLS.

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::signature::{
    ED25519, Ed25519KeyPair, KeyPair, ML_DSA_65, ML_DSA_65_SIGNING, PqdsaKeyPair, UnparsedPublicKey,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha512};
use suaya_core::t;

pub const ALGORITMO: &str = "ML-DSA-65+Ed25519";
const FORMATO_PRIVADA: &str = "suaya-llave-firma-1";
const FORMATO_PUBLICA: &str = "suaya-llave-publica-1";
const FORMATO_FIRMA: &str = "suaya-firma-2";
const CONTEXTO: &str = "suaya-firma-cbom-v2";
const ITERACIONES: u32 = 600_000;

fn error(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// Par de llaves compuesto.
pub struct Llaves {
    ml_dsa: PqdsaKeyPair,
    ed25519: Ed25519KeyPair,
    pkcs8_ml_dsa: Vec<u8>,
    pkcs8_ed25519: Vec<u8>,
}

/// Llave pública compuesta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlavePublica {
    pub ml_dsa_65: Vec<u8>,
    pub ed25519: Vec<u8>,
}

impl LlavePublica {
    /// Huella corta (SHA-256 de ambas llaves, 16 bytes en hexadecimal).
    pub fn huella(&self) -> String {
        let mut h = Sha256::new();
        h.update(ALGORITMO.as_bytes());
        h.update([0]);
        h.update(&self.ml_dsa_65);
        h.update(&self.ed25519);
        hex::encode(&h.finalize()[..16])
    }

    pub fn a_json(&self) -> Value {
        json!({
            "formato": FORMATO_PUBLICA,
            "algoritmo": ALGORITMO,
            "huella": self.huella(),
            "ml_dsa_65": B64.encode(&self.ml_dsa_65),
            "ed25519": B64.encode(&self.ed25519),
        })
    }

    pub fn desde_json(v: &Value) -> Result<Self, String> {
        if v["formato"] != FORMATO_PUBLICA || v["algoritmo"] != ALGORITMO {
            return Err(t!(
                "no es una llave pública de Suaya ({ALGORITMO})",
                "not a Suaya public key ({ALGORITMO})"
            ));
        }
        let campo = |k: &str| {
            v[k].as_str()
                .ok_or_else(|| t!("falta el campo {k}", "missing field {k}"))
                .and_then(|s| B64.decode(s).map_err(error))
        };
        let llave = Self {
            ml_dsa_65: campo("ml_dsa_65")?,
            ed25519: campo("ed25519")?,
        };
        if v["huella"].as_str().is_some_and(|h| h != llave.huella()) {
            return Err(t!(
                "la huella declarada no corresponde a la llave",
                "the declared fingerprint does not match the key"
            ));
        }
        Ok(llave)
    }
}

impl Llaves {
    /// Genera un par nuevo.
    pub fn generar() -> Result<Self, String> {
        let rng = SystemRandom::new();
        let ml = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).map_err(error)?;
        let pkcs8_ml_dsa = ml.to_pkcs8v1().map_err(error)?.as_ref().to_vec();
        let pkcs8_ed25519 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(error)?
            .as_ref()
            .to_vec();
        Self::desde_pkcs8(pkcs8_ml_dsa, pkcs8_ed25519)
    }

    fn desde_pkcs8(pkcs8_ml_dsa: Vec<u8>, pkcs8_ed25519: Vec<u8>) -> Result<Self, String> {
        Ok(Self {
            ml_dsa: PqdsaKeyPair::from_pkcs8(&ML_DSA_65_SIGNING, &pkcs8_ml_dsa).map_err(error)?,
            ed25519: Ed25519KeyPair::from_pkcs8(&pkcs8_ed25519).map_err(error)?,
            pkcs8_ml_dsa,
            pkcs8_ed25519,
        })
    }

    pub fn publica(&self) -> LlavePublica {
        LlavePublica {
            ml_dsa_65: self.ml_dsa.public_key().as_ref().to_vec(),
            ed25519: self.ed25519.public_key().as_ref().to_vec(),
        }
    }

    /// Serializa la llave privada; con `clave`, cifrada con PBKDF2 y AES-256-GCM.
    pub fn a_json(&self, clave: Option<&str>) -> Result<Value, String> {
        let secreto = json!({
            "ml_dsa_65_pkcs8": B64.encode(&self.pkcs8_ml_dsa),
            "ed25519_pkcs8": B64.encode(&self.pkcs8_ed25519),
        });
        let mut v = json!({
            "formato": FORMATO_PRIVADA,
            "algoritmo": ALGORITMO,
            "publica": self.publica().a_json(),
        });
        match clave {
            None => v["secreto"] = secreto,
            Some(c) => {
                let rng = SystemRandom::new();
                let mut sal = [0u8; 16];
                let mut nonce = [0u8; 12];
                rng.fill(&mut sal).map_err(error)?;
                rng.fill(&mut nonce).map_err(error)?;
                let llave = derivar(c, &sal, ITERACIONES)?;
                let mut datos = serde_json::to_vec(&secreto).map_err(error)?;
                llave
                    .seal_in_place_append_tag(
                        Nonce::assume_unique_for_key(nonce),
                        Aad::from(FORMATO_PRIVADA.as_bytes()),
                        &mut datos,
                    )
                    .map_err(error)?;
                v["cifrado"] = json!({
                    "kdf": "PBKDF2-HMAC-SHA256",
                    "iteraciones": ITERACIONES,
                    "sal": B64.encode(sal),
                    "aead": "AES-256-GCM",
                    "nonce": B64.encode(nonce),
                    "datos": B64.encode(&datos),
                });
            }
        }
        Ok(v)
    }

    pub fn desde_json(v: &Value, clave: Option<&str>) -> Result<Self, String> {
        if v["formato"] != FORMATO_PRIVADA || v["algoritmo"] != ALGORITMO {
            return Err(t!(
                "no es una llave privada de firma de Suaya",
                "not a Suaya signing private key"
            ));
        }
        let secreto: Value = if let Some(c) = v.get("cifrado") {
            let clave = clave.ok_or_else(|| {
                t!(
                    "la llave está cifrada: indique la frase de paso",
                    "the key is encrypted: provide the passphrase"
                )
            })?;
            let b = |k: &str| {
                c[k].as_str()
                    .ok_or_else(|| t!("llave cifrada incompleta", "incomplete encrypted key"))
                    .and_then(|s| B64.decode(s).map_err(error))
            };
            let n = c["iteraciones"].as_u64().unwrap_or(0);
            if !(100_000..=1_000_000).contains(&n)
                || c["kdf"] != "PBKDF2-HMAC-SHA256"
                || c["aead"] != "AES-256-GCM"
            {
                return Err(t!(
                    "parámetros de cifrado inválidos",
                    "invalid encryption parameters"
                ));
            }
            let sal = b("sal")?;
            if sal.len() != 16 {
                return Err("sal inválida".into());
            }
            let llave = derivar(clave, &sal, n as u32)?;
            let nonce: [u8; 12] = b("nonce")?
                .try_into()
                .map_err(|_| t!("nonce inválido", "invalid nonce"))?;
            let mut datos = b("datos")?;
            let claro = llave
                .open_in_place(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(FORMATO_PRIVADA.as_bytes()),
                    &mut datos,
                )
                .map_err(|_| t!("frase de paso incorrecta", "wrong passphrase"))?;
            serde_json::from_slice(claro).map_err(error)?
        } else {
            v["secreto"].clone()
        };
        let campo = |k: &str| {
            secreto[k]
                .as_str()
                .ok_or_else(|| t!("falta el campo {k}", "missing field {k}"))
                .and_then(|s| B64.decode(s).map_err(error))
        };
        Self::desde_pkcs8(campo("ml_dsa_65_pkcs8")?, campo("ed25519_pkcs8")?)
    }
}

fn derivar(clave: &str, sal: &[u8], iteraciones: u32) -> Result<LessSafeKey, String> {
    let mut llave = [0u8; 32];
    aws_lc_rs::pbkdf2::derive(
        aws_lc_rs::pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(iteraciones).ok_or("iteraciones")?,
        sal,
        clave.as_bytes(),
        &mut llave,
    );
    Ok(LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, &llave).map_err(error)?,
    ))
}

/// Mensaje que firman ambos algoritmos.
fn mensaje(huella: &str, resumen: &[u8], fecha: &str) -> Vec<u8> {
    let mut m = Vec::new();
    for parte in [CONTEXTO.as_bytes(), ALGORITMO.as_bytes(), huella.as_bytes()] {
        m.extend_from_slice(parte);
        m.push(0);
    }
    m.extend_from_slice(resumen);
    m.extend_from_slice(&(fecha.len() as u64).to_be_bytes());
    m.extend_from_slice(fecha.as_bytes());
    m
}

/// Firma un documento y devuelve el JSON de la firma.
pub fn firmar(documento: &[u8], llaves: &Llaves, fecha: &str) -> Result<Value, String> {
    let publica = llaves.publica();
    let huella = publica.huella();
    let resumen = Sha512::digest(documento);
    let m = mensaje(&huella, &resumen, fecha);
    let mut firma_ml = vec![0u8; ML_DSA_65_SIGNING.signature_len()];
    let n = llaves.ml_dsa.sign(&m, &mut firma_ml).map_err(error)?;
    firma_ml.truncate(n);
    let firma_ed = llaves.ed25519.sign(&m);
    Ok(json!({
        "formato": FORMATO_FIRMA,
        "algoritmo": ALGORITMO,
        "contexto": CONTEXTO,
        "fecha": fecha,
        "resumen_sha512": hex::encode(resumen),
        "huella_llave": huella,
        "firma_ml_dsa_65": B64.encode(&firma_ml),
        "firma_ed25519": B64.encode(firma_ed.as_ref()),
    }))
}

/// Verifica una firma; ambas componentes deben ser válidas.
pub fn verificar(documento: &[u8], firma: &Value, publica: &LlavePublica) -> Result<(), String> {
    if firma["formato"] != FORMATO_FIRMA
        || firma["algoritmo"] != ALGORITMO
        || firma["contexto"] != CONTEXTO
    {
        return Err(t!(
            "formato de firma no reconocido",
            "unrecognized signature format"
        ));
    }
    let huella = publica.huella();
    if firma["huella_llave"] != huella.as_str() {
        return Err(t!(
            "la firma corresponde a otra llave (huella {})",
            "the signature belongs to another key (fingerprint {})",
            firma["huella_llave"].as_str().unwrap_or("?")
        ));
    }
    let resumen = Sha512::digest(documento);
    if firma["resumen_sha512"] != hex::encode(resumen).as_str() {
        return Err(t!(
            "el documento cambió después de firmarse",
            "the document changed after it was signed"
        ));
    }
    let fecha = firma["fecha"]
        .as_str()
        .filter(|s| s.len() <= 64)
        .ok_or("fecha inválida")?;
    let m = mensaje(&huella, &resumen, fecha);
    let b = |k: &str| {
        firma[k]
            .as_str()
            .ok_or_else(|| t!("falta {k}", "missing {k}"))
            .and_then(|s| B64.decode(s).map_err(error))
    };
    UnparsedPublicKey::new(&ML_DSA_65, &publica.ml_dsa_65)
        .verify(&m, &b("firma_ml_dsa_65")?)
        .map_err(|_| {
            t!(
                "la firma ML-DSA-65 no es válida",
                "the ML-DSA-65 signature is invalid"
            )
        })?;
    UnparsedPublicKey::new(&ED25519, &publica.ed25519)
        .verify(&m, &b("firma_ed25519")?)
        .map_err(|_| {
            t!(
                "la firma Ed25519 no es válida",
                "the Ed25519 signature is invalid"
            )
        })?;
    Ok(())
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn firmar_y_verificar() {
        let llaves = Llaves::generar().unwrap();
        let publica = llaves.publica();
        assert_eq!(publica.ed25519.len(), 32);
        let doc = br#"{"bomFormat":"CycloneDX"}"#;
        let f = firmar(doc, &llaves, "2026-10-16T00:00:00Z").unwrap();
        verificar(doc, &f, &publica).unwrap();
        // Documento alterado.
        assert!(verificar(b"{}", &f, &publica).is_err());
        // Despojar una componente invalida la firma.
        let mut sin_pq = f.clone();
        sin_pq["firma_ml_dsa_65"] = json!("");
        assert!(verificar(doc, &sin_pq, &publica).is_err());
        let mut sin_ed = f.clone();
        sin_ed["firma_ed25519"] = json!(B64.encode([0u8; 64]));
        assert!(verificar(doc, &sin_ed, &publica).is_err());
        // Otra llave.
        let otra = Llaves::generar().unwrap().publica();
        assert!(verificar(doc, &f, &otra).is_err());
    }

    #[test]
    fn llaves_en_json_cifradas_y_en_claro() {
        let llaves = Llaves::generar().unwrap();
        let claro = llaves.a_json(None).unwrap();
        let de_nuevo = Llaves::desde_json(&claro, None).unwrap();
        assert_eq!(de_nuevo.publica(), llaves.publica());
        let cifrada = llaves.a_json(Some("frase de prueba")).unwrap();
        assert!(cifrada.get("secreto").is_none());
        assert!(Llaves::desde_json(&cifrada, None).is_err());
        assert!(Llaves::desde_json(&cifrada, Some("otra")).is_err());
        let ok = Llaves::desde_json(&cifrada, Some("frase de prueba")).unwrap();
        assert_eq!(ok.publica(), llaves.publica());
        let publica = LlavePublica::desde_json(&llaves.publica().a_json()).unwrap();
        assert_eq!(publica, llaves.publica());
    }
}
