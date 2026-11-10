//! Contenedores de llaves: PKCS #12 y Java KeyStore (JKS y JCEKS).
//!
//! - **JKS y JCEKS**: los certificados no están cifrados, así que se
//!   inventarían sin contraseña. Las llaves privadas se registran (tipo de
//!   entrada y protección) pero nunca se descifran.
//! - **PKCS #12**: sin contraseña se leen los algoritmos que protegen cada
//!   parte (RC2 de 40 bits, 3DES, PBES2 con AES...), la integridad (MAC) y
//!   los certificados que estén sin cifrar. Si la persona define
//!   `SUAYA_CLAVE_ALMACEN`, Suaya descifra también los certificados protegidos
//!   con PBES2 y AES. Nunca adivina contraseñas ni descifra llaves privadas.

use std::num::NonZeroU32;

use suaya_core::{Activo, Conocimiento, Detalles, Garantia, Riesgo};

use crate::Escaner;
use crate::comun::{Archivo, activo_algoritmo, id_corto};
use crate::der::{entero, hijos, octetos, oid, oid_de_algoritmo, tlv};
use crate::pem::certificado_en_archivo;

const EXTENSIONES: &[(&str, &str)] = &[
    ("p12", "PKCS#12"),
    ("pfx", "PKCS#12"),
    ("jks", "Java KeyStore"),
    ("jceks", "Java JCEKS"),
    ("bcfks", "BouncyCastle FIPS KeyStore"),
    ("keystore", "Java KeyStore"),
    ("truststore", "Java KeyStore"),
];

/// Variable de entorno con la contraseña de los almacenes PKCS #12.
pub const VARIABLE_CLAVE: &str = "SUAYA_CLAVE_ALMACEN";

pub struct EscanerContenedores;

impl Escaner for EscanerContenedores {
    fn nombre(&self) -> &'static str {
        "contenedores de llaves"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        EXTENSIONES.iter().any(|(e, _)| *e == a.extension)
            || a.nombre == "cacerts"
            || a.contenido.starts_with(&[0xFE, 0xED, 0xFE, 0xED])
            || a.contenido.starts_with(&[0xCE, 0xCE, 0xCE, 0xCE])
    }

    fn analizar(&self, a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
        if a.contenido.starts_with(&[0xFE, 0xED, 0xFE, 0xED])
            || a.contenido.starts_with(&[0xCE, 0xCE, 0xCE, 0xCE])
        {
            return jks(a, c);
        }
        if matches!(a.extension.as_str(), "p12" | "pfx") && a.contenido.first() == Some(&0x30) {
            let clave = std::env::var(VARIABLE_CLAVE).ok();
            return pkcs12(a, c, clave.as_deref());
        }
        Ok(vec![opaco(a)])
    }
}

/// Contenedor que no se puede leer (formato desconocido o BCFKS).
fn opaco(a: &Archivo) -> Activo {
    let formato = EXTENSIONES
        .iter()
        .find(|(e, _)| *e == a.extension)
        .map(|(_, f)| *f)
        .unwrap_or("desconocido");
    let mut activo = Activo::nuevo(
        format!("llave:contenedor:{}", id_corto(&a.ruta_estable)),
        format!("Contenedor {formato}"),
        Detalles::Material {
            tipo_material: "key".into(),
            tamano: None,
            formato: formato.into(),
            protegido_por: Some("contraseña".into()),
            huella_sha256: None,
            identidad_llave: None,
        },
    )
    .con_contexto("sin-clasificar", Garantia::Autenticacion)
    .con_ubicacion(a.ruta, None);
    activo.riesgo_fijado = Some(Riesgo::Desconocido);
    activo.advertir("Contenedor protegido por contraseña: Suaya no lo abre. Inventaríe su contenido con «keytool -list -v».");
    activo
}

fn contenedor(a: &Archivo, formato: &str, protegido: Option<String>) -> Activo {
    Activo::nuevo(
        format!("llave:contenedor:{}", id_corto(&a.ruta_estable)),
        format!("Contenedor {formato}"),
        Detalles::Material {
            tipo_material: "key".into(),
            tamano: None,
            formato: formato.into(),
            protegido_por: protegido,
            huella_sha256: None,
            identidad_llave: None,
        },
    )
    .con_contexto("sin-clasificar", Garantia::Autenticacion)
    .con_ubicacion(a.ruta, None)
}

fn agregar_certificado(
    der: &[u8],
    a: &Archivo,
    c: &Conocimiento,
    almacen: bool,
    m: &mut Activo,
    activos: &mut Vec<Activo>,
) {
    match certificado_en_archivo(der, a, c, almacen) {
        Ok(v) => {
            for x in v {
                if matches!(x.detalles, Detalles::Certificado { .. }) {
                    m.relacionar("certificate", &x.referencia);
                }
                activos.push(x);
            }
        }
        Err(e) => m.advertir(format!(
            "Un certificado del contenedor no se pudo leer: {e}."
        )),
    }
}

// ---------------------------------------------------------------------------
// JKS y JCEKS
// ---------------------------------------------------------------------------

fn jks(a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
    let b = a.contenido;
    let jceks = b.starts_with(&[0xCE, 0xCE, 0xCE, 0xCE]);
    let u32_en = |p: usize| -> Option<u32> {
        b.get(p..p + 4)
            .map(|x| u32::from_be_bytes([x[0], x[1], x[2], x[3]]))
    };
    let version = u32_en(4).ok_or("JKS truncado")?;
    let total = u32_en(8).ok_or("JKS truncado")?.min(10_000);
    let mut p = 12usize;
    let utf = |p: &mut usize| -> Option<String> {
        let n = u16::from_be_bytes([*b.get(*p)?, *b.get(*p + 1)?]) as usize;
        let s = String::from_utf8_lossy(b.get(*p + 2..*p + 2 + n)?).into_owned();
        *p += 2 + n;
        Some(s)
    };
    let mut certificados: Vec<&[u8]> = Vec::new();
    let (mut privadas, mut secretas, mut confiables) = (0usize, 0usize, 0usize);
    let mut completo = true;
    for _ in 0..total {
        let Some(etiqueta) = u32_en(p) else {
            completo = false;
            break;
        };
        p += 4;
        if utf(&mut p).is_none() {
            completo = false;
            break;
        }
        p += 8; // marca de tiempo
        let cert = |p: &mut usize| -> Option<&[u8]> {
            if version == 2 {
                utf(p)?;
            }
            let n = u32_en(*p)? as usize;
            let der = b.get(*p + 4..*p + 4 + n)?;
            *p += 4 + n;
            Some(der)
        };
        match etiqueta {
            1 => {
                privadas += 1;
                let Some(n) = u32_en(p) else { break };
                p += 4 + n as usize;
                let Some(cadena) = u32_en(p) else { break };
                p += 4;
                for _ in 0..cadena.min(32) {
                    match cert(&mut p) {
                        Some(d) => certificados.push(d),
                        None => break,
                    }
                }
            }
            2 => {
                confiables += 1;
                match cert(&mut p) {
                    Some(d) => certificados.push(d),
                    None => break,
                }
            }
            3 => {
                // Llave secreta de JCEKS: objeto Java serializado, de largo variable.
                secretas += 1;
                completo = false;
                break;
            }
            _ => {
                completo = false;
                break;
            }
        }
    }
    let formato = if jceks {
        "Java JCEKS"
    } else {
        "Java KeyStore (JKS)"
    };
    let mut m = contenedor(
        a,
        formato,
        (privadas > 0).then(|| "contraseña (protección propia de JKS)".into()),
    );
    let almacen = privadas == 0 && (confiables > 0 || a.nombre == "cacerts");
    let mut activos = Vec::new();
    for d in certificados {
        agregar_certificado(d, a, c, almacen, &mut m, &mut activos);
    }
    m.advertir(format!(
        "{formato}: {privadas} llaves privadas, {confiables} certificados de confianza{}.",
        if secretas > 0 {
            format!(", {secretas} o más llaves secretas")
        } else {
            String::new()
        }
    ));
    if privadas > 0 {
        m.advertir(if jceks {
            "JCEKS protege las llaves privadas con PBEWithMD5AndTripleDES: migre a PKCS #12 (keytool -importkeystore)."
        } else {
            "JKS protege las llaves privadas con un algoritmo propietario basado en SHA-1: migre a PKCS #12 (keytool -importkeystore)."
        });
        m.riesgo_fijado = Some(Riesgo::Obsoleto);
    }
    if !completo {
        m.advertir("No se leyeron todas las entradas del contenedor.");
    }
    activos.push(m);
    Ok(activos)
}

// ---------------------------------------------------------------------------
// PKCS #12
// ---------------------------------------------------------------------------

const OID_DATA: &str = "1.2.840.113549.1.7.1";
const OID_ENCRYPTED_DATA: &str = "1.2.840.113549.1.7.6";
const OID_PBES2: &str = "1.2.840.113549.1.5.13";
const OID_PBKDF2: &str = "1.2.840.113549.1.5.12";
const BAG_LLAVE: &str = "1.2.840.113549.1.12.10.1.1";
const BAG_LLAVE_CIFRADA: &str = "1.2.840.113549.1.12.10.1.2";
const BAG_CERTIFICADO: &str = "1.2.840.113549.1.12.10.1.3";

/// Algoritmo de protección de PKCS #12: (id de algoritmo, descripción).
fn proteccion(oid: &str) -> (Option<&'static str>, &'static str) {
    match oid {
        "1.2.840.113549.1.12.1.6" => (Some("rc2"), "RC2 de 40 bits con SHA-1"),
        "1.2.840.113549.1.12.1.5" => (Some("rc2"), "RC2 de 128 bits con SHA-1"),
        "1.2.840.113549.1.12.1.3" => (Some("3des-cbc"), "3DES con SHA-1"),
        "1.2.840.113549.1.12.1.4" => (Some("3des-cbc"), "3DES de dos llaves con SHA-1"),
        "1.2.840.113549.1.12.1.1" | "1.2.840.113549.1.12.1.2" => (Some("rc4"), "RC4 con SHA-1"),
        "1.2.840.113549.1.5.3" | "1.2.840.113549.1.5.10" => (Some("des"), "DES"),
        OID_PBES2 => (Some("pbes2"), "PBES2"),
        _ => (None, "algoritmo desconocido"),
    }
}

/// Parámetros de PBES2 con PBKDF2 y AES-CBC.
struct Pbes2 {
    sal: Vec<u8>,
    iteraciones: u32,
    prf: aws_lc_rs::pbkdf2::Algorithm,
    nombre_prf: &'static str,
    largo_llave: usize,
    iv: [u8; 16],
}

fn pbes2(parametros: &[u8]) -> Option<Pbes2> {
    let p = hijos(parametros);
    let kdf = hijos(p.first()?.contenido);
    if kdf.first().and_then(|x| oid(x.contenido)).as_deref() != Some(OID_PBKDF2) {
        return None;
    }
    let kp = hijos(kdf.get(1)?.contenido);
    let sal = kp
        .first()
        .filter(|x| x.etiqueta == 0x04)?
        .contenido
        .to_vec();
    let iteraciones = entero(kp.get(1)?.contenido)?;
    if !(1..=10_000_000).contains(&iteraciones) {
        return None;
    }
    let prf_oid = kp
        .iter()
        .skip(2)
        .find(|x| x.etiqueta == 0x30)
        .and_then(oid_de_algoritmo)
        .unwrap_or_else(|| "1.2.840.113549.2.7".into());
    let (prf, nombre_prf) = match prf_oid.as_str() {
        "1.2.840.113549.2.7" => (aws_lc_rs::pbkdf2::PBKDF2_HMAC_SHA1, "HMAC-SHA-1"),
        "1.2.840.113549.2.9" => (aws_lc_rs::pbkdf2::PBKDF2_HMAC_SHA256, "HMAC-SHA-256"),
        "1.2.840.113549.2.10" => (aws_lc_rs::pbkdf2::PBKDF2_HMAC_SHA384, "HMAC-SHA-384"),
        "1.2.840.113549.2.11" => (aws_lc_rs::pbkdf2::PBKDF2_HMAC_SHA512, "HMAC-SHA-512"),
        _ => return None,
    };
    let esquema = hijos(p.get(1)?.contenido);
    let largo_llave = match esquema.first().and_then(|x| oid(x.contenido))?.as_str() {
        "2.16.840.1.101.3.4.1.2" => 16,
        "2.16.840.1.101.3.4.1.22" => 24,
        "2.16.840.1.101.3.4.1.42" => 32,
        _ => return None,
    };
    let iv: [u8; 16] = esquema.get(1)?.contenido.try_into().ok()?;
    Some(Pbes2 {
        sal,
        iteraciones: iteraciones as u32,
        prf,
        nombre_prf,
        largo_llave,
        iv,
    })
}

fn descifrar(p: &Pbes2, clave: &str, cifrado: &[u8]) -> Option<Vec<u8>> {
    use aws_lc_rs::cipher::{
        AES_128, AES_192, AES_256, DecryptionContext, PaddedBlockDecryptingKey, UnboundCipherKey,
    };
    let mut llave = vec![0u8; p.largo_llave];
    aws_lc_rs::pbkdf2::derive(
        p.prf,
        NonZeroU32::new(p.iteraciones)?,
        &p.sal,
        clave.as_bytes(),
        &mut llave,
    );
    let algoritmo = match p.largo_llave {
        16 => &AES_128,
        24 => &AES_192,
        _ => &AES_256,
    };
    let llave = UnboundCipherKey::new(algoritmo, &llave).ok()?;
    let descifrador = PaddedBlockDecryptingKey::cbc_pkcs7(llave).ok()?;
    let mut buf = cifrado.to_vec();
    let claro = descifrador
        .decrypt(&mut buf, DecryptionContext::Iv128(p.iv.into()))
        .ok()?;
    Some(claro.to_vec())
}

#[derive(Default)]
struct Lectura {
    certificados: Vec<Vec<u8>>,
    protecciones: Vec<(Option<&'static str>, String)>,
    llaves_en_claro: usize,
    llaves_cifradas: usize,
    partes_cifradas: usize,
    partes_descifradas: usize,
}

fn bolsas(safe_contents: &[u8], l: &mut Lectura) {
    let Some((seq, _)) = tlv(safe_contents) else {
        return;
    };
    for bolsa in hijos(seq.contenido).into_iter().take(1024) {
        let h = hijos(bolsa.contenido);
        let Some(tipo) = h.first().and_then(|x| oid(x.contenido)) else {
            continue;
        };
        let Some(valor) = h.get(1).and_then(|x| hijos(x.contenido).into_iter().next()) else {
            continue;
        };
        match tipo.as_str() {
            BAG_CERTIFICADO => {
                if let Some(explicito) = hijos(valor.contenido).get(1)
                    && let Some(octs) = hijos(explicito.contenido).first()
                {
                    l.certificados.push(octetos(octs));
                }
            }
            BAG_LLAVE => l.llaves_en_claro += 1,
            BAG_LLAVE_CIFRADA => {
                l.llaves_cifradas += 1;
                if let Some(alg) = hijos(valor.contenido).first() {
                    let o = oid_de_algoritmo(alg).unwrap_or_default();
                    let (id, d) = proteccion(&o);
                    let mut texto = format!("llave privada: {d}");
                    if o == OID_PBES2
                        && let Some(p) =
                            hijos(alg.contenido).get(1).and_then(|x| pbes2(x.contenido))
                    {
                        texto = format!(
                            "llave privada: PBES2 con PBKDF2-{} ({} iteraciones) y AES-{}-CBC",
                            p.nombre_prf,
                            p.iteraciones,
                            p.largo_llave * 8
                        );
                    }
                    l.protecciones.push((id, texto));
                }
            }
            _ => {}
        }
    }
}

fn pkcs12(a: &Archivo, c: &Conocimiento, clave: Option<&str>) -> Result<Vec<Activo>, String> {
    let (pfx, _) = tlv(a.contenido).ok_or("PKCS #12 ilegible")?;
    let partes = hijos(pfx.contenido);
    let auth = partes.get(1).ok_or("PKCS #12 sin contenido")?;
    let auth_partes = hijos(auth.contenido);
    if auth_partes
        .first()
        .and_then(|x| oid(x.contenido))
        .as_deref()
        != Some(OID_DATA)
    {
        return Ok(vec![opaco(a)]);
    }
    let datos = auth_partes
        .get(1)
        .and_then(|x| hijos(x.contenido).into_iter().next())
        .map(|x| octetos(&x))
        .ok_or("PKCS #12 sin AuthenticatedSafe")?;
    let mut l = Lectura::default();
    let (seq, _) = tlv(&datos).ok_or("AuthenticatedSafe ilegible")?;
    for info in hijos(seq.contenido).into_iter().take(64) {
        let h = hijos(info.contenido);
        let tipo = h.first().and_then(|x| oid(x.contenido)).unwrap_or_default();
        let Some(contenido) = h.get(1).and_then(|x| hijos(x.contenido).into_iter().next()) else {
            continue;
        };
        if tipo == OID_DATA {
            bolsas(&octetos(&contenido), &mut l);
        } else if tipo == OID_ENCRYPTED_DATA {
            l.partes_cifradas += 1;
            // EncryptedData { version, EncryptedContentInfo { tipo, algoritmo, [0] cifrado } }.
            let ed = hijos(contenido.contenido);
            let Some(eci) = ed.get(1) else { continue };
            let eci = hijos(eci.contenido);
            let Some(alg) = eci.get(1) else { continue };
            let o = oid_de_algoritmo(alg).unwrap_or_default();
            let (id, d) = proteccion(&o);
            let param = (o == OID_PBES2)
                .then(|| hijos(alg.contenido).get(1).and_then(|x| pbes2(x.contenido)))
                .flatten();
            let texto = match &param {
                Some(p) => format!(
                    "certificados: PBES2 con PBKDF2-{} ({} iteraciones) y AES-{}-CBC",
                    p.nombre_prf,
                    p.iteraciones,
                    p.largo_llave * 8
                ),
                None => format!("certificados: {d}"),
            };
            l.protecciones.push((id, texto));
            if let (Some(p), Some(clave), Some(cifrado)) = (&param, clave, eci.get(2))
                && let Some(claro) = descifrar(p, clave, &octetos(cifrado))
            {
                l.partes_descifradas += 1;
                bolsas(&claro, &mut l);
            }
        }
    }
    // Integridad: MacData { DigestInfo { algoritmo, digest }, sal, iteraciones }.
    let mut integridad = None;
    if let Some(mac) = partes.get(2) {
        let mh = hijos(mac.contenido);
        let alg = mh
            .first()
            .and_then(|di| hijos(di.contenido).into_iter().next())
            .and_then(|x| oid_de_algoritmo(&x));
        let iteraciones = mh.get(2).and_then(|x| entero(x.contenido)).unwrap_or(1);
        integridad = alg.map(|o| (o, iteraciones));
    }

    let mut m = contenedor(
        a,
        "PKCS#12",
        Some(
            l.protecciones
                .iter()
                .map(|(_, d)| d.clone())
                .collect::<Vec<_>>()
                .join("; "),
        )
        .filter(|s| !s.is_empty()),
    );
    let mut activos = Vec::new();
    let mut ids: Vec<&str> = l.protecciones.iter().filter_map(|(id, _)| *id).collect();
    ids.sort_unstable();
    ids.dedup();
    for id in ids {
        let x = activo_algoritmo(
            c.por_id(id),
            id,
            None,
            "sin-clasificar",
            Some(Garantia::Confidencialidad),
            a.ruta,
            None,
        );
        m.relacionar("algorithm", &x.referencia);
        activos.push(x);
    }
    if let Some((o, iteraciones)) = &integridad {
        if c.por_oid(o).is_some_and(|d| d.id == "sha1") {
            m.advertir(format!(
                "La integridad del archivo usa HMAC con SHA-1 ({iteraciones} iteraciones), propio de exportaciones antiguas."
            ));
        }
    } else {
        m.advertir("El archivo no tiene código de integridad (MacData).");
    }
    if l.protecciones
        .iter()
        .any(|(id, _)| matches!(id, Some("rc2") | Some("rc4") | Some("des")))
    {
        m.advertir("Protección heredada (RC2, RC4 o DES): cualquiera con el archivo puede probar contraseñas a gran velocidad o leerlo sin ella. Vuelva a exportar con AES-256 (openssl pkcs12 -export sin -legacy).");
    }
    if l.llaves_en_claro > 0 {
        m.advertir(format!(
            "Contiene {} llaves privadas sin cifrar dentro del PKCS #12.",
            l.llaves_en_claro
        ));
        m.riesgo_fijado = Some(Riesgo::RotoClasico);
    }
    let pendientes = l.partes_cifradas - l.partes_descifradas;
    if pendientes > 0 {
        m.advertir(if clave.is_some() {
            format!("{pendientes} partes cifradas no se pudieron descifrar con la contraseña de {VARIABLE_CLAVE} (o usan un algoritmo heredado).")
        } else {
            format!("{pendientes} partes con certificados están cifradas: defina {VARIABLE_CLAVE} con la contraseña para inventariarlos.")
        });
    }
    for d in &l.certificados {
        agregar_certificado(d, a, c, false, &mut m, &mut activos);
    }
    m.advertir(format!(
        "PKCS #12: {} certificados leídos, {} llaves privadas cifradas.",
        l.certificados.len(),
        l.llaves_cifradas
    ));
    activos.push(m);
    Ok(activos)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn der(etiqueta: u8, contenido: &[u8]) -> Vec<u8> {
        let mut v = vec![etiqueta];
        let n = contenido.len();
        if n < 128 {
            v.push(n as u8);
        } else if n < 256 {
            v.extend([0x81, n as u8]);
        } else {
            v.extend([0x82, (n >> 8) as u8, n as u8]);
        }
        v.extend_from_slice(contenido);
        v
    }

    fn oid_der(t: &str) -> Vec<u8> {
        let p: Vec<u64> = t.split('.').map(|x| x.parse().unwrap()).collect();
        let mut v = vec![(p[0] * 40 + p[1]) as u8];
        for &n in &p[2..] {
            let mut bytes = vec![(n & 0x7f) as u8];
            let mut r = n >> 7;
            while r > 0 {
                bytes.push(0x80 | (r & 0x7f) as u8);
                r >>= 7;
            }
            bytes.reverse();
            v.extend(bytes);
        }
        der(0x06, &v)
    }

    #[test]
    fn pkcs12_heredado_con_llave_en_claro() {
        let c = Conocimiento::embebido();
        // SafeContents con una keyBag (en claro) dentro de «data».
        let bolsa = der(
            0x30,
            &[
                oid_der(BAG_LLAVE),
                der(0xA0, &der(0x30, &[0x02, 0x01, 0x00])),
            ]
            .concat(),
        );
        let safe = der(0x30, &bolsa);
        let ci_datos = der(
            0x30,
            &[oid_der(OID_DATA), der(0xA0, &der(0x04, &safe))].concat(),
        );
        // EncryptedData con RC2 de 40 bits.
        let alg = der(
            0x30,
            &[
                oid_der("1.2.840.113549.1.12.1.6"),
                der(
                    0x30,
                    &[der(0x04, &[1; 8]), der(0x02, &[0x08, 0x00])].concat(),
                ),
            ]
            .concat(),
        );
        let eci = der(
            0x30,
            &[oid_der(OID_DATA), alg, der(0x80, &[0u8; 16])].concat(),
        );
        let ed = der(0x30, &[der(0x02, &[0]), eci].concat());
        let ci_cifrado = der(
            0x30,
            &[oid_der(OID_ENCRYPTED_DATA), der(0xA0, &ed)].concat(),
        );
        let auth = der(0x30, &[ci_datos, ci_cifrado].concat());
        let pfx = der(
            0x30,
            &[
                der(0x02, &[3]),
                der(
                    0x30,
                    &[oid_der(OID_DATA), der(0xA0, &der(0x04, &auth))].concat(),
                ),
            ]
            .concat(),
        );
        let a = Archivo::nuevo("x.p12", std::path::Path::new("x.p12"), &pfx, None);
        let v = pkcs12(&a, &c, None).unwrap();
        let m = v.last().unwrap();
        assert_eq!(m.riesgo_fijado, Some(Riesgo::RotoClasico));
        assert!(v.iter().any(|x| x.algoritmo_id() == Some("rc2")));
        assert!(m.advertencias.iter().any(|w| w.contains(VARIABLE_CLAVE)));
        assert!(m.advertencias.iter().any(|w| w.contains("integridad")));
    }

    #[test]
    fn jks_con_llave_privada() {
        let c = Conocimiento::embebido();
        let mut b = vec![0xFE, 0xED, 0xFE, 0xED, 0, 0, 0, 2, 0, 0, 0, 1];
        b.extend([0, 0, 0, 1]); // llave privada
        b.extend([0, 1, b'a']);
        b.extend([0u8; 8]);
        b.extend([0, 0, 0, 2, 9, 9]); // llave cifrada (2 bytes)
        b.extend([0, 0, 0, 0]); // cadena vacía
        b.extend([0u8; 20]);
        let a = Archivo::nuevo("app.jks", std::path::Path::new("app.jks"), &b, None);
        assert!(EscanerContenedores.aplica(&a));
        let v = EscanerContenedores.analizar(&a, &c).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].riesgo_fijado, Some(Riesgo::Obsoleto));
        assert!(
            v[0].advertencias
                .iter()
                .any(|w| w.contains("1 llaves privadas"))
        );
    }

    #[test]
    fn descifrado_pbes2() {
        use aws_lc_rs::cipher::{
            AES_256, EncryptionContext, PaddedBlockEncryptingKey, UnboundCipherKey,
        };
        let p = Pbes2 {
            sal: vec![7; 16],
            iteraciones: 2048,
            prf: aws_lc_rs::pbkdf2::PBKDF2_HMAC_SHA256,
            nombre_prf: "HMAC-SHA-256",
            largo_llave: 32,
            iv: [3; 16],
        };
        let mut llave = [0u8; 32];
        aws_lc_rs::pbkdf2::derive(
            p.prf,
            NonZeroU32::new(2048).unwrap(),
            &p.sal,
            b"secreto",
            &mut llave,
        );
        let cifrador =
            PaddedBlockEncryptingKey::cbc_pkcs7(UnboundCipherKey::new(&AES_256, &llave).unwrap())
                .unwrap();
        let mut buf = b"contenido".to_vec();
        cifrador
            .less_safe_encrypt(&mut buf, EncryptionContext::Iv128(p.iv.into()))
            .unwrap();
        assert_eq!(
            descifrar(&p, "secreto", &buf).as_deref(),
            Some(&b"contenido"[..])
        );
        assert!(descifrar(&p, "otra", &buf).is_none_or(|x| x != b"contenido"));
    }
}
