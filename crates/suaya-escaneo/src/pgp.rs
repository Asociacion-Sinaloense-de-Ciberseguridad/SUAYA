//! Llaves y firmas OpenPGP (RFC 9580): llaves de los repositorios de
//! paquetes (apt, dnf/yum), llaveros de GnuPG (incluido `pubring.kbx`) y
//! firmas separadas (`.sig`, `Release.gpg`, `InRelease`).
//!
//! De cada llave registra el algoritmo, el tamaño y si es privada sin cifrar;
//! de cada firma, el hash. Nunca copia material secreto.

use base64::Engine;
use suaya_core::{Activo, AlgoritmoDef, Conocimiento, Detalles, Garantia, Riesgo};

use crate::Escaner;
use crate::comun::{Archivo, activo_algoritmo, huella_sha256, linea_de};
use crate::der::oid;

/// Un paquete OpenPGP.
struct Paquete<'a> {
    etiqueta: u8,
    cuerpo: &'a [u8],
}

/// Recorre los paquetes de un flujo binario (formatos nuevo y antiguo).
fn paquetes(b: &[u8]) -> Vec<Paquete<'_>> {
    let mut v = Vec::new();
    let mut p = 0usize;
    while p < b.len() && v.len() < 10_000 {
        let c = b[p];
        if c & 0x80 == 0 {
            break;
        }
        let (etiqueta, largo, cabecera) = if c & 0x40 != 0 {
            let etiqueta = c & 0x3f;
            let Some(&o1) = b.get(p + 1) else { break };
            match o1 {
                0..=191 => (etiqueta, o1 as usize, 2),
                192..=223 => {
                    let Some(&o2) = b.get(p + 2) else { break };
                    (etiqueta, ((o1 as usize - 192) << 8) + o2 as usize + 192, 3)
                }
                255 => {
                    let Some(l) = b.get(p + 2..p + 6) else { break };
                    (
                        etiqueta,
                        u32::from_be_bytes([l[0], l[1], l[2], l[3]]) as usize,
                        6,
                    )
                }
                // Largo parcial: solo en paquetes de datos, que no interesan.
                _ => break,
            }
        } else {
            let etiqueta = (c >> 2) & 0x0f;
            match c & 3 {
                0 => (etiqueta, *b.get(p + 1).unwrap_or(&0) as usize, 2),
                1 => {
                    let Some(l) = b.get(p + 1..p + 3) else { break };
                    (etiqueta, u16::from_be_bytes([l[0], l[1]]) as usize, 3)
                }
                2 => {
                    let Some(l) = b.get(p + 1..p + 5) else { break };
                    (
                        etiqueta,
                        u32::from_be_bytes([l[0], l[1], l[2], l[3]]) as usize,
                        5,
                    )
                }
                _ => (etiqueta, b.len() - p - 1, 1),
            }
        };
        let inicio = p + cabecera;
        let Some(fin) = inicio.checked_add(largo).filter(|f| *f <= b.len()) else {
            break;
        };
        v.push(Paquete {
            etiqueta,
            cuerpo: &b[inicio..fin],
        });
        p = fin;
    }
    v
}

/// Bloques blindados («-----BEGIN PGP ...-----») decodificados, con su línea.
fn blindados(a: &Archivo, texto: &str) -> Vec<(String, Vec<u8>, u32)> {
    let mut v = Vec::new();
    let mut resto = texto;
    let mut base = 0usize;
    while let Some(i) = resto.find("-----BEGIN PGP ") {
        let inicio = base + i;
        let tras = &texto[inicio..];
        let Some(fin_etiqueta) = tras.find("-----\n").or_else(|| tras.find("-----\r\n")) else {
            break;
        };
        let etiqueta = tras["-----BEGIN ".len()..fin_etiqueta].to_string();
        let Some(fin) = tras.find("-----END PGP ") else {
            break;
        };
        let cuerpo = &tras[fin_etiqueta..fin];
        // Cabeceras («Version: ...») hasta la primera línea vacía; la
        // suma de comprobación empieza con «=».
        let mut lineas = cuerpo.lines().skip(1).peekable();
        let tiene_cabeceras = cuerpo.lines().skip(1).take(8).any(|l| l.contains(": "));
        if tiene_cabeceras {
            for l in lineas.by_ref() {
                if l.trim().is_empty() {
                    break;
                }
            }
        }
        let b64: String = lineas
            .take_while(|l| !l.starts_with('='))
            .flat_map(|l| l.trim().chars())
            .collect();
        if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(b64) {
            v.push((etiqueta, der, linea_de(a.contenido, inicio)));
        }
        base = inicio + fin + 1;
        resto = &texto[base..];
        if v.len() >= 256 {
            break;
        }
    }
    v
}

/// Bloques OpenPGP de un llavero `pubring.kbx` de GnuPG.
fn keybox(b: &[u8]) -> Vec<&[u8]> {
    let mut v = Vec::new();
    let mut p = 0usize;
    while p + 16 <= b.len() && v.len() < 10_000 {
        let largo = u32::from_be_bytes([b[p], b[p + 1], b[p + 2], b[p + 3]]) as usize;
        if largo < 16 || p + largo > b.len() {
            break;
        }
        if b[p + 4] == 2 {
            let off = u32::from_be_bytes([b[p + 8], b[p + 9], b[p + 10], b[p + 11]]) as usize;
            let len = u32::from_be_bytes([b[p + 12], b[p + 13], b[p + 14], b[p + 15]]) as usize;
            if let Some(bloque) = b.get(p + off..p + off + len) {
                v.push(bloque);
            }
        }
        p += largo;
    }
    v
}

/// Bits de un MPI y lo que sigue.
fn mpi(b: &[u8]) -> Option<(u32, &[u8])> {
    let bits = u16::from_be_bytes([*b.first()?, *b.get(1)?]) as u32;
    let bytes = (bits as usize).div_ceil(8);
    Some((bits, b.get(2 + bytes..)?))
}

/// OID de curva de una llave ECC y el resto del material.
fn curva(m: &[u8]) -> Option<(String, &[u8])> {
    let n = *m.first()? as usize;
    let o = oid(m.get(1..1 + n)?)?;
    Some((o, m.get(1 + n..)?))
}

/// Algoritmo, nombre, tamaño, identificador OpenPGP y posición del material.
type LlavePgp<'c> = (Option<&'c AlgoritmoDef>, String, Option<u32>, u8, usize);

/// Algoritmo y tamaño de una llave pública, y el resto del cuerpo.
fn algoritmo_de_llave<'c>(cuerpo: &[u8], c: &'c Conocimiento) -> Option<LlavePgp<'c>> {
    let version = *cuerpo.first()?;
    let (alg, material, inicio_material) = match version {
        3 => (*cuerpo.get(7)?, cuerpo.get(8..)?, 8),
        4 => (*cuerpo.get(5)?, cuerpo.get(6..)?, 6),
        5 | 6 => (*cuerpo.get(5)?, cuerpo.get(10..)?, 10),
        _ => return None,
    };
    let (def, nombre, tamano, usados): (Option<&AlgoritmoDef>, String, Option<u32>, usize) =
        match alg {
            1..=3 => {
                let (bits, r) = mpi(material)?;
                let (_, r) = mpi(r)?;
                (
                    c.por_id("rsa"),
                    "RSA".into(),
                    Some(bits),
                    material.len() - r.len(),
                )
            }
            16 | 20 => {
                let (bits, r) = mpi(material)?;
                let (_, r) = mpi(r)?;
                let (_, r) = mpi(r)?;
                (
                    c.por_id("elgamal"),
                    "ElGamal".into(),
                    Some(bits),
                    material.len() - r.len(),
                )
            }
            17 => {
                let (bits, mut r) = mpi(material)?;
                for _ in 0..3 {
                    r = mpi(r)?.1;
                }
                (
                    c.por_id("dsa"),
                    "DSA".into(),
                    Some(bits),
                    material.len() - r.len(),
                )
            }
            18 | 19 | 22 => {
                let (o, r) = curva(material)?;
                let (_, r) = mpi(r)?;
                // ECDH lleva además los parámetros KDF (largo y bytes).
                let r = if alg == 18 {
                    let n = *r.first()? as usize;
                    r.get(1 + n..)?
                } else {
                    r
                };
                let id = match (alg, o.as_str()) {
                    (22, _) | (_, "1.3.6.1.4.1.11591.15.1") => Some("ed25519"),
                    (18, "1.3.6.1.4.1.3029.1.5.1") | (18, "1.3.101.110") => Some("x25519"),
                    (18, "1.2.840.10045.3.1.7") => Some("ecdh-p256"),
                    (18, "1.3.132.0.34") => Some("ecdh-p384"),
                    (18, "1.3.132.0.35") => Some("ecdh-p521"),
                    (18, "1.3.36.3.3.2.8.1.1.7") => Some("ecdh-brainpoolp256r1"),
                    (18, "1.3.36.3.3.2.8.1.1.11") => Some("ecdh-brainpoolp384r1"),
                    (18, "1.3.36.3.3.2.8.1.1.13") => Some("ecdh-brainpoolp512r1"),
                    _ => None,
                };
                let def = id.and_then(|i| c.por_id(i)).or_else(|| c.por_oid(&o));
                (def, format!("curva {o}"), None, material.len() - r.len())
            }
            25 => (c.por_id("x25519"), "X25519".into(), None, 32),
            26 => (c.por_id("x448"), "X448".into(), None, 56),
            27 => (c.por_id("ed25519"), "Ed25519".into(), None, 32),
            28 => (c.por_id("ed448"), "Ed448".into(), None, 57),
            otro => (
                None,
                format!("algoritmo OpenPGP {otro}"),
                None,
                material.len(),
            ),
        };
    let fin_publico = if version >= 5 {
        let n = u32::from_be_bytes(cuerpo.get(6..10)?.try_into().ok()?) as usize;
        inicio_material + n
    } else {
        inicio_material + usados
    };
    Some((def, nombre, tamano, version, fin_publico))
}

fn hash_de_firma(c: &Conocimiento, h: u8) -> (Option<&AlgoritmoDef>, String) {
    let id = match h {
        1 => Some("md5"),
        2 => Some("sha1"),
        8 => Some("sha256"),
        9 => Some("sha384"),
        10 => Some("sha512"),
        11 => Some("sha224"),
        12 => Some("sha3-256"),
        14 => Some("sha3-512"),
        _ => None,
    };
    (id.and_then(|i| c.por_id(i)), format!("hash OpenPGP {h}"))
}

fn capacidad(a: &Archivo) -> &'static str {
    let r = a.ruta.replace('\\', "/").to_ascii_lowercase();
    if [
        "apt/",
        "keyrings",
        "rpm-gpg",
        "trusted.gpg",
        "yum.repos",
        "release",
        "repomd",
        "/pki/rpm",
    ]
    .iter()
    .any(|x| r.contains(x))
        || a.extension == "sig"
    {
        "firma-codigo"
    } else {
        "sin-clasificar"
    }
}

/// Activos de un flujo de paquetes OpenPGP.
fn analizar_flujo(b: &[u8], a: &Archivo, linea: u32, c: &Conocimiento) -> Vec<Activo> {
    let cap = capacidad(a);
    let mut activos: Vec<Activo> = Vec::new();
    let mut usuario: Option<String> = None;
    let mut hashes_certificacion: Vec<u8> = Vec::new();
    let mut ultima_llave: Option<usize> = None;
    for p in paquetes(b) {
        match p.etiqueta {
            5 | 6 | 7 | 14 => {
                let Some((def, nombre, tamano, version, fin_publico)) =
                    algoritmo_de_llave(p.cuerpo, c)
                else {
                    continue;
                };
                let secreta = matches!(p.etiqueta, 5 | 7);
                let alg = activo_algoritmo(
                    def,
                    &nombre,
                    tamano,
                    cap,
                    Some(Garantia::Autenticacion),
                    a.ruta,
                    Some(linea),
                );
                let huella = huella_sha256(&p.cuerpo[..fin_publico.min(p.cuerpo.len())]);
                let protegida = if secreta {
                    match p.cuerpo.get(fin_publico) {
                        Some(0) => Some(false),
                        Some(_) => Some(true),
                        None => None,
                    }
                } else {
                    None
                };
                let mut m = Activo::nuevo(
                    format!("llave:openpgp:{}", &huella[..16]),
                    format!(
                        "Llave OpenPGP {}{}",
                        if matches!(p.etiqueta, 7 | 14) {
                            "(subllave) "
                        } else {
                            ""
                        },
                        alg.nombre
                    ),
                    Detalles::Material {
                        tipo_material: if secreta {
                            "private-key".into()
                        } else {
                            "public-key".into()
                        },
                        tamano,
                        formato: format!("OpenPGP v{version}"),
                        protegido_por: match protegida {
                            Some(true) => Some("frase de paso (S2K)".into()),
                            Some(false) => None,
                            None => None,
                        },
                        huella_sha256: Some(huella),
                        identidad_llave: None,
                    },
                )
                .con_contexto(cap, Garantia::Autenticacion)
                .con_ubicacion(a.ruta, Some(linea));
                m.relacionar("algorithm", &alg.referencia);
                if version == 3 {
                    m.advertir("Llave OpenPGP v3: formato retirado, con huella MD5.");
                    m.riesgo_fijado = Some(Riesgo::Obsoleto);
                }
                if protegida == Some(false) {
                    m.advertir("Llave privada OpenPGP sin cifrar: cualquiera que lea el archivo puede firmar o descifrar en su nombre.");
                    m.riesgo_fijado = Some(Riesgo::RotoClasico);
                }
                if let Some(u) = &usuario {
                    m.advertir(format!("Identidad: {u}."));
                }
                activos.push(alg);
                activos.push(m);
                ultima_llave = Some(activos.len() - 1);
            }
            13 => {
                let u: String = String::from_utf8_lossy(p.cuerpo)
                    .chars()
                    .take(200)
                    .collect();
                if let Some(i) = ultima_llave
                    && let Some(m) = activos.get_mut(i)
                    && !m.advertencias.iter().any(|w| w.starts_with("Identidad:"))
                {
                    m.advertir(format!("Identidad: {u}."));
                }
                usuario = Some(u);
            }
            2 => {
                let (pub_alg, hash) = match p.cuerpo.first() {
                    Some(3) => (p.cuerpo.get(15).copied(), p.cuerpo.get(16).copied()),
                    Some(4..=6) => (p.cuerpo.get(2).copied(), p.cuerpo.get(3).copied()),
                    _ => (None, None),
                };
                let Some(h) = hash else { continue };
                if ultima_llave.is_some() {
                    // Certificaciones dentro de una llave.
                    hashes_certificacion.push(h);
                } else {
                    let (def, respaldo) = hash_de_firma(c, h);
                    let mut x = activo_algoritmo(
                        def,
                        &respaldo,
                        None,
                        cap,
                        Some(Garantia::Integridad),
                        a.ruta,
                        Some(linea),
                    );
                    x.advertir("Hash de una firma OpenPGP separada.");
                    activos.push(x);
                    if matches!(pub_alg, Some(17)) {
                        activos.push(activo_algoritmo(
                            c.por_id("dsa"),
                            "DSA",
                            None,
                            cap,
                            Some(Garantia::Autenticacion),
                            a.ruta,
                            Some(linea),
                        ));
                    }
                }
            }
            _ => {}
        }
    }
    if !hashes_certificacion.is_empty()
        && hashes_certificacion.iter().all(|h| matches!(h, 1 | 2))
        && let Some(i) = ultima_llave
        && let Some(m) = activos.get_mut(i)
    {
        m.advertir("Las certificaciones de la llave usan SHA-1 o MD5: GnuPG y las distribuciones recientes las rechazan.");
    }
    activos
}

pub struct EscanerOpenpgp;

impl Escaner for EscanerOpenpgp {
    fn nombre(&self) -> &'static str {
        "llaves y firmas OpenPGP"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        if a.contiene(b"-----BEGIN ") && a.contiene(b"-----BEGIN PGP ") {
            return true;
        }
        let r = a.ruta.replace('\\', "/").to_ascii_lowercase();
        let primera = a.contenido.first().copied().unwrap_or(0);
        let binario_pgp = matches!(
            primera,
            0x98 | 0x99 | 0x94 | 0x95 | 0xC6 | 0xC5 | 0x88 | 0x89 | 0xC2
        );
        (matches!(a.extension.as_str(), "gpg" | "pgp" | "sig" | "key") && binario_pgp)
            || (a.nombre == "pubring.kbx" || a.contenido.get(8..12) == Some(b"KBXf"))
            || ((r.contains("trusted.gpg")
                || r.contains("keyrings/")
                || a.nombre.starts_with("rpm-gpg-key"))
                && binario_pgp)
    }

    fn analizar(&self, a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
        let mut activos = Vec::new();
        if a.contenido.get(8..12) == Some(b"KBXf") || a.nombre == "pubring.kbx" {
            for bloque in keybox(a.contenido) {
                activos.extend(analizar_flujo(bloque, a, 1, c));
            }
        } else if let Some(texto) = a.texto().filter(|t| t.contains("-----BEGIN PGP ")) {
            for (_, der, linea) in blindados(a, texto) {
                activos.extend(analizar_flujo(&der, a, linea, c));
            }
        } else {
            activos.extend(analizar_flujo(a.contenido, a, 1, c));
        }
        Ok(activos)
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Paquete en formato nuevo.
    fn paquete(etiqueta: u8, cuerpo: &[u8]) -> Vec<u8> {
        let mut v = vec![0xC0 | etiqueta];
        assert!(cuerpo.len() < 192);
        v.push(cuerpo.len() as u8);
        v.extend_from_slice(cuerpo);
        v
    }

    fn mpi(bits: u16, relleno: u8) -> Vec<u8> {
        let mut v = bits.to_be_bytes().to_vec();
        let n = (bits as usize).div_ceil(8);
        let mut cuerpo = vec![relleno; n];
        cuerpo[0] = 0x80;
        v.extend(cuerpo);
        v
    }

    #[test]
    fn llave_rsa_1024_con_certificacion_sha1_y_llave_ed25519() {
        let c = Conocimiento::embebido();
        let mut cuerpo = vec![4, 0, 0, 0, 1, 1];
        cuerpo.extend(mpi(1024, 7));
        cuerpo.extend(mpi(17, 1));
        // Una llave RSA de 1024 bits no cabe en un largo de un byte: formato antiguo.
        let mut flujo = vec![0x99];
        flujo.extend((cuerpo.len() as u16).to_be_bytes());
        flujo.extend(&cuerpo);
        flujo.extend(paquete(13, b"Repositorio <repo@ejemplo.mx>"));
        flujo.extend(paquete(2, &[4, 0x13, 1, 2, 0, 0]));
        let mut ed = vec![4, 0, 0, 0, 1, 27];
        ed.extend([9u8; 32]);
        flujo.extend(paquete(6, &ed));
        let a = Archivo::nuevo(
            "etc/apt/trusted.gpg.d/repo.gpg",
            std::path::Path::new("repo.gpg"),
            &flujo,
            None,
        );
        assert!(EscanerOpenpgp.aplica(&a));
        let v = EscanerOpenpgp.analizar(&a, &c).unwrap();
        assert!(v.iter().any(|x| x.referencia == "algoritmo:rsa-1024"));
        assert!(v.iter().any(|x| x.referencia == "algoritmo:ed25519"));
        let rsa = v
            .iter()
            .find(|x| x.nombre.contains("RSA") && x.referencia.starts_with("llave:"))
            .unwrap();
        assert!(rsa.contextos.iter().any(|x| x.capacidad == "firma-codigo"));
        assert!(
            rsa.advertencias
                .iter()
                .any(|w| w.contains("repo@ejemplo.mx"))
        );
    }

    #[test]
    fn llave_privada_sin_cifrar_blindada() {
        let c = Conocimiento::embebido();
        let mut cuerpo = vec![4, 0, 0, 0, 1, 27];
        cuerpo.extend([5u8; 32]);
        cuerpo.push(0); // S2K usage 0: sin cifrar.
        cuerpo.extend([1u8; 34]);
        let der = paquete(5, &cuerpo);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
        let texto = format!(
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\nComment: prueba\n\n{b64}\n=AbCd\n-----END PGP PRIVATE KEY BLOCK-----\n"
        );
        let a = Archivo::nuevo(
            "clave.asc",
            std::path::Path::new("clave.asc"),
            texto.as_bytes(),
            None,
        );
        assert!(EscanerOpenpgp.aplica(&a));
        let v = EscanerOpenpgp.analizar(&a, &c).unwrap();
        let m = v
            .iter()
            .find(|x| x.referencia.starts_with("llave:openpgp"))
            .unwrap();
        assert_eq!(m.riesgo_fijado, Some(Riesgo::RotoClasico));
    }
}
