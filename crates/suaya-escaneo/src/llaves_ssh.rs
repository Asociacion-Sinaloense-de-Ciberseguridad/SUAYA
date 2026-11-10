//! Escáner de llaves SSH: llaves privadas OpenSSH, llaves públicas `.pub`,
//! `authorized_keys` y `known_hosts`.

use ssh_key::{Algorithm, EcdsaCurve, HashAlg, PrivateKey, PublicKey};
use suaya_core::{Activo, Conocimiento, Garantia};

use crate::Escaner;
use crate::comun::{Archivo, bits_de_entero, linea_de};
use crate::pem::material;

const CAPACIDAD: &str = "vpn-cifrado-red";

pub struct EscanerLlavesSsh;

impl Escaner for EscanerLlavesSsh {
    fn nombre(&self) -> &'static str {
        "llaves SSH"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        a.extension == "pub"
            || a.nombre == "authorized_keys"
            || a.nombre == "authorized_keys2"
            || a.nombre == "known_hosts"
    }

    fn analizar(&self, a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
        let texto = a.texto().ok_or("el archivo no es texto UTF-8")?;
        let mut activos = Vec::new();
        let mut desplazamiento = 0usize;

        for linea in texto.split_inclusive('\n') {
            let numero = linea_de(a.contenido, desplazamiento);
            desplazamiento += linea.len();
            let l = linea.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            if let Some(llave) = llave_publica_de_linea(l, &a.nombre) {
                activos.extend(activos_de_publica(&llave, a, Some(numero), c));
            }
        }
        Ok(activos)
    }
}

/// Extrae la llave pública de una línea, tolerando opciones (authorized_keys)
/// y patrones de host (known_hosts).
fn llave_publica_de_linea(l: &str, nombre_archivo: &str) -> Option<PublicKey> {
    if let Ok(k) = PublicKey::from_openssh(l) {
        return Some(k);
    }
    // Buscar el primer campo que sea un tipo de llave y reconstruir desde ahí.
    let campos: Vec<&str> = l.split_whitespace().collect();
    let _ = nombre_archivo;
    for i in 0..campos.len() {
        if campos[i].starts_with("ssh-")
            || campos[i].starts_with("ecdsa-")
            || campos[i].starts_with("sk-")
        {
            let resto = campos[i..].join(" ");
            if let Ok(k) = PublicKey::from_openssh(&resto) {
                return Some(k);
            }
        }
    }
    None
}

/// Nombre para el espacio `ssh-llave` de la base de conocimiento.
fn nombre_llave(alg: &Algorithm) -> String {
    match alg {
        Algorithm::Rsa { .. } => "rsa".into(),
        Algorithm::Ed25519 | Algorithm::SkEd25519 => "ed25519".into(),
        Algorithm::Dsa => "dsa".into(),
        Algorithm::Ecdsa { curve } => match curve {
            EcdsaCurve::NistP256 => "ecdsa-sha2-nistp256".into(),
            EcdsaCurve::NistP384 => "ecdsa-sha2-nistp384".into(),
            EcdsaCurve::NistP521 => "ecdsa-sha2-nistp521".into(),
        },
        Algorithm::SkEcdsaSha2NistP256 => "ecdsa-sha2-nistp256".into(),
        otro => otro.as_str().to_string(),
    }
}

fn tamano_rsa(k: &PublicKey) -> Option<u32> {
    k.key_data()
        .rsa()
        .and_then(|r| r.n.as_positive_bytes())
        .map(bits_de_entero)
}

fn activos_de_publica(
    k: &PublicKey,
    a: &Archivo,
    linea: Option<u32>,
    c: &Conocimiento,
) -> Vec<Activo> {
    let alg = k.algorithm();
    let def = c.por_alias("ssh-llave", &nombre_llave(&alg));
    let huella = k.fingerprint(HashAlg::Sha256).to_string();
    let huella_hex = crate::comun::huella_sha256(huella.as_bytes());
    let mut v = material(
        a,
        linea,
        c,
        def,
        alg.as_str(),
        tamano_rsa(k),
        "public-key",
        "OpenSSH",
        None,
        Some(huella_hex),
        crate::identidad::desde_ssh(k),
    );
    for x in &mut v {
        x.contextos.clear();
        x.agregar_contexto(CAPACIDAD, Garantia::Autenticacion);
    }
    if matches!(alg, Algorithm::SkEd25519 | Algorithm::SkEcdsaSha2NistP256)
        && let Some(m) = v.last_mut()
    {
        m.advertir("Llave respaldada por un autenticador FIDO (sk-); su migración depende del fabricante del token.");
    }
    if let Some(m) = v.last_mut()
        && !k.comment().is_empty()
    {
        m.nombre = format!("{} ({})", m.nombre, k.comment());
    }
    v
}

/// Activos de una llave de host recibida por la red: el blob del protocolo
/// SSH (una llave pública o un certificado SSH). `ubicacion` es el servicio
/// (`ssh://host:22`); la identidad de llave permite enlazarla con el archivo
/// `ssh_host_*_key.pub` del servidor.
pub fn activos_de_llave_ssh(
    blob: &[u8],
    ubicacion: &str,
    c: &Conocimiento,
) -> Result<Vec<Activo>, String> {
    let a = Archivo::nuevo(ubicacion, std::path::Path::new(ubicacion), &[], None);
    if let Ok(k) = PublicKey::from_bytes(blob) {
        return Ok(activos_de_publica(&k, &a, None, c));
    }
    let cert = ssh_key::Certificate::from_bytes(blob)
        .map_err(|e| format!("llave de host ilegible: {e}"))?;
    let k = PublicKey::from(cert.public_key().clone());
    let mut v = activos_de_publica(&k, &a, None, c);
    let ca = PublicKey::from(cert.signature_key().clone());
    let vence =
        time::OffsetDateTime::from_unix_timestamp(cert.valid_before().min(253_402_300_799) as i64)
            .map(|t| format!("{:04}-{:02}-{:02}", t.year(), u8::from(t.month()), t.day()))
            .unwrap_or_default();
    if let Some(m) = v.last_mut() {
        m.advertir(format!(
            "Certificado SSH de host firmado por una autoridad {} (vigente hasta {vence}).",
            ca.algorithm().as_str()
        ));
        if cert.valid_before() < time::OffsetDateTime::now_utc().unix_timestamp().max(0) as u64 {
            m.advertir("El certificado SSH de host está vencido.");
        }
    }
    Ok(v)
}

/// Llave privada en formato OpenSSH (bloque PEM `OPENSSH PRIVATE KEY`).
pub(crate) fn analizar_privada_openssh(
    texto_pem: &str,
    a: &Archivo,
    linea: Option<u32>,
    c: &Conocimiento,
) -> Result<Vec<Activo>, String> {
    // El decodificador exige líneas de 70 caracteres, como escribe ssh-keygen;
    // otras herramientas usan 64. Se normaliza antes de interpretar.
    let cuerpo: String = texto_pem
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with("-----"))
        .collect();
    let mut normalizado = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for trozo in cuerpo.as_bytes().chunks(70) {
        normalizado.push_str(std::str::from_utf8(trozo).unwrap_or_default());
        normalizado.push('\n');
    }
    normalizado.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    let k = PrivateKey::from_openssh(&normalizado)
        .map_err(|e| format!("llave OpenSSH inválida: {e}"))?;
    let publica = k.public_key();
    let alg = publica.algorithm();
    let def = c.por_alias("ssh-llave", &nombre_llave(&alg));
    let proteccion = if k.is_encrypted() {
        Some(format!(
            "cifrado OpenSSH ({}, KDF {})",
            k.cipher().as_str(),
            k.kdf().algorithm().as_str()
        ))
    } else {
        None
    };
    let mut v = material(
        a,
        linea,
        c,
        def,
        alg.as_str(),
        tamano_rsa(publica),
        "private-key",
        "OpenSSH",
        proteccion,
        None,
        crate::identidad::desde_ssh(publica),
    );
    for x in &mut v {
        x.contextos.clear();
        x.agregar_contexto(CAPACIDAD, Garantia::Autenticacion);
    }
    Ok(v)
}
