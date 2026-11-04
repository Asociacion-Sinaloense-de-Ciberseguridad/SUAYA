//! Identidad canónica de llaves públicas (ver `suaya_core::Detalles`).
//!
//! Se calcula igual para un certificado, un PKCS#8, un PKCS#1, un SEC1 o una
//! llave OpenSSH, de modo que el núcleo pueda enlazarlos entre sí. Cuando se
//! parte de una llave privada, el material secreto solo se usa en memoria
//! para obtener la parte pública y nunca se conserva.

use x509_parser::der_parser::ber::BerObjectContent;
use x509_parser::der_parser::der::parse_der;
use x509_parser::prelude::*;

use crate::comun::huella_sha256;

const OID_RSA: &str = "1.2.840.113549.1.1.1";
const OID_EC: &str = "1.2.840.10045.2.1";
const OID_ED25519: &str = "1.3.101.112";

fn tlv(etiqueta: u8, contenido: &[u8]) -> Vec<u8> {
    let mut v = vec![etiqueta];
    let n = contenido.len();
    if n < 0x80 {
        v.push(n as u8);
    } else {
        let bytes: Vec<u8> = n
            .to_be_bytes()
            .iter()
            .copied()
            .skip_while(|&b| b == 0)
            .collect();
        v.push(0x80 | bytes.len() as u8);
        v.extend(bytes);
    }
    v.extend_from_slice(contenido);
    v
}

/// INTEGER DER canónico a partir de un entero sin signo en big-endian.
fn entero(bytes: &[u8]) -> Vec<u8> {
    let sin_ceros: Vec<u8> = bytes.iter().copied().skip_while(|&b| b == 0).collect();
    let mut c = if sin_ceros.is_empty() {
        vec![0]
    } else {
        sin_ceros
    };
    if c[0] & 0x80 != 0 {
        c.insert(0, 0);
    }
    tlv(0x02, &c)
}

/// Identidad de una llave RSA a partir de su módulo y exponente.
pub fn rsa(n: &[u8], e: &[u8]) -> String {
    let mut cuerpo = entero(n);
    cuerpo.extend(entero(e));
    huella_sha256(&tlv(0x30, &cuerpo))
}

/// Identidad de una llave EC o EdDSA a partir de sus bytes públicos.
pub fn bytes(publicos: &[u8]) -> String {
    huella_sha256(publicos)
}

pub fn desde_spki(spki: &SubjectPublicKeyInfo) -> Option<String> {
    match spki.parsed().ok()? {
        x509_parser::public_key::PublicKey::RSA(r) => Some(rsa(r.modulus, r.exponent)),
        x509_parser::public_key::PublicKey::EC(p) => Some(bytes(p.data())),
        _ => Some(bytes(&spki.subject_public_key.data)),
    }
}

/// RSAPrivateKey PKCS#1: versión, módulo, exponente público, ...
pub fn desde_pkcs1_privada(der: &[u8]) -> Option<String> {
    let (_, o) = parse_der(der).ok()?;
    let s = o.as_sequence().ok()?;
    Some(rsa(s.get(1)?.as_slice().ok()?, s.get(2)?.as_slice().ok()?))
}

/// RSAPublicKey PKCS#1: módulo, exponente público.
pub fn desde_pkcs1_publica(der: &[u8]) -> Option<String> {
    let (_, o) = parse_der(der).ok()?;
    let s = o.as_sequence().ok()?;
    Some(rsa(s.first()?.as_slice().ok()?, s.get(1)?.as_slice().ok()?))
}

/// ECPrivateKey SEC1: la llave pública va en `[1] EXPLICIT BIT STRING`.
pub fn desde_sec1(der: &[u8]) -> Option<String> {
    let (_, o) = parse_der(der).ok()?;
    for e in o.as_sequence().ok()? {
        if e.header.tag().0 != 1 || !e.header.is_contextspecific() {
            continue;
        }
        let datos = match &e.content {
            BerObjectContent::Unknown(any) => any.data,
            _ => continue,
        };
        let (_, bits) = parse_der(datos).ok()?;
        if let BerObjectContent::BitString(_, b) = &bits.content {
            return Some(bytes(b.data));
        }
    }
    None
}

/// Identidad a partir de una PrivateKeyInfo PKCS#8 ya separada.
pub fn desde_pkcs8(oid: &str, privada: &[u8]) -> Option<String> {
    match oid {
        OID_RSA => desde_pkcs1_privada(privada),
        OID_EC => desde_sec1(privada),
        OID_ED25519 => {
            // CurvePrivateKey ::= OCTET STRING (la semilla de 32 bytes).
            let (_, o) = parse_der(privada).ok()?;
            let semilla: [u8; 32] = o.as_slice().ok()?.try_into().ok()?;
            let firmante = ed25519_dalek::SigningKey::from_bytes(&semilla);
            Some(bytes(firmante.verifying_key().as_bytes()))
        }
        _ => None,
    }
}

pub fn desde_ssh(k: &ssh_key::PublicKey) -> Option<String> {
    use ssh_key::public::KeyData;
    match k.key_data() {
        KeyData::Rsa(r) => Some(rsa(r.n.as_bytes(), r.e.as_bytes())),
        KeyData::Ed25519(e) => Some(bytes(&e.0)),
        KeyData::Ecdsa(e) => Some(bytes(e.as_sec1_bytes())),
        _ => None,
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn entero_canonico() {
        assert_eq!(entero(&[0x00, 0x00, 0x7f]), vec![0x02, 0x01, 0x7f]);
        assert_eq!(entero(&[0x80]), vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(entero(&[0x00, 0x80]), vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(rsa(&[0x00, 0xC5], &[1, 0, 1]), rsa(&[0xC5], &[0, 1, 0, 1]));
    }

    #[test]
    fn longitudes_largas() {
        let v = tlv(0x04, &[0u8; 300]);
        assert_eq!(&v[..4], &[0x04, 0x82, 0x01, 0x2C]);
    }
}
