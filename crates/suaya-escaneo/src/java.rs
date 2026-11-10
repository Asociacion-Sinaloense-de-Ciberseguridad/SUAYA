//! Aplicaciones Java y Android empaquetadas (JAR, WAR, EAR, AAR, APK).
//!
//! Sin el código fuente, Suaya lee:
//!
//! - **Firmas**: JAR firmados (`META-INF/*.SF` y `*.RSA`/`*.DSA`/`*.EC`) y el
//!   bloque de firma de APK v2 y v3.
//! - **Literales de la JCA** en el bytecode: las cadenas que una clase pasa a
//!   `Cipher.getInstance`, `MessageDigest.getInstance` y similares
//!   («AES/ECB/PKCS5Padding», «DESede», «SHA1withRSA», «TLSv1»), tanto en
//!   `.class` como en `classes.dex`.
//! - **Bibliotecas empaquetadas** (`BOOT-INF/lib/`, `WEB-INF/lib/`) por su
//!   nombre, como Bouncy Castle.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use regex::Regex;
use suaya_core::{Activo, Conocimiento, Detalles, Garantia, Riesgo};

use crate::Escaner;
use crate::comun::{Archivo, activo_algoritmo, id_corto};
use crate::der::cms;
use crate::pem::certificado_en_contexto;
use crate::zip::{self, Zip};

const CODIGO: &str = "codigo-aplicacion";
const FIRMA: &str = "firma-codigo";
/// Límites de lectura por archivo comprimido.
const MAXIMO_CLASE: usize = 4 << 20;
const MAXIMO_DEX: usize = 64 << 20;
const MAXIMO_CLASES: usize = 20_000;
const MAXIMO_TOTAL: usize = 256 << 20;

/// Literal de la JCA: (espacio de nombres de codigo.toml, nombre normalizado).
fn literal_jca(s: &str) -> Option<(&'static str, String)> {
    static R: OnceLock<[(Regex, &'static str); 6]> = OnceLock::new();
    let r = R.get_or_init(|| {
        let re = |p: &str| Regex::new(p).expect("expresión válida");
        [
            (re(r"^(?:AES|DES|DESede|TripleDES|RC2|RC4|ARCFOUR|Blowfish|RSA|ChaCha20)(?:/[A-Za-z0-9]+/[A-Za-z0-9]+)?$"), "java-cifrado"),
            (re(r"^(?:MD2|MD4|MD5|SHA-?1|SHA-?224|SHA-?256|SHA-?384|SHA-?512|SHA3-(?:224|256|384|512))$"), "codigo"),
            (re(r"^(?:MD5|SHA1|SHA224|SHA256|SHA384|SHA512)with(?:RSA|ECDSA|DSA)$"), "codigo"),
            (re(r"^Hmac(?:MD5|SHA1|SHA256|SHA384|SHA512)$"), "codigo"),
            (re(r"^(?:PBKDF2WithHmacSHA(?:1|256|512)|PBEWithMD5AndDES|PBEWithSHA1AndDESede)$"), "codigo"),
            (re(r"^(?:SSLv3|TLSv1|TLSv1\.1)$"), "tls"),
        ]
    });
    if s.len() > 64 {
        return None;
    }
    r.iter()
        .find(|(re, _)| re.is_match(s))
        .map(|(_, espacio)| (*espacio, s.trim().to_lowercase().replace(['_', '.'], "-")))
}

/// Cadenas literales (CONSTANT_String) de una clase de Java.
fn literales_clase(b: &[u8]) -> Vec<String> {
    if !b.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE]) || b.len() < 10 {
        return Vec::new();
    }
    let total = u16::from_be_bytes([b[8], b[9]]) as usize;
    let mut utf8: BTreeMap<usize, &[u8]> = BTreeMap::new();
    let mut cadenas: Vec<usize> = Vec::new();
    let mut p = 10usize;
    let mut i = 1usize;
    while i < total {
        let Some(&tag) = b.get(p) else { break };
        let avance = match tag {
            1 => {
                let Some(n) = b
                    .get(p + 1..p + 3)
                    .map(|x| u16::from_be_bytes([x[0], x[1]]) as usize)
                else {
                    break;
                };
                if let Some(s) = b.get(p + 3..p + 3 + n) {
                    utf8.insert(i, s);
                }
                3 + n
            }
            8 => {
                if let Some(x) = b.get(p + 1..p + 3) {
                    cadenas.push(u16::from_be_bytes([x[0], x[1]]) as usize);
                }
                3
            }
            3 | 4 => 5,
            5 | 6 => {
                i += 1;
                9
            }
            7 | 16 | 19 | 20 => 3,
            9 | 10 | 11 | 12 | 17 | 18 => 5,
            15 => 4,
            _ => break,
        };
        p += avance;
        i += 1;
    }
    cadenas
        .iter()
        .filter_map(|j| utf8.get(j))
        .filter_map(|s| std::str::from_utf8(s).ok())
        .map(str::to_string)
        .collect()
}

/// Cadenas de un `classes.dex` de Android.
fn cadenas_dex(b: &[u8]) -> Vec<String> {
    if !b.starts_with(b"dex\n") || b.len() < 0x70 {
        return Vec::new();
    }
    let u32_ = |p: usize| {
        b.get(p..p + 4)
            .map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]) as usize)
    };
    let (Some(n), Some(off)) = (u32_(0x38), u32_(0x3C)) else {
        return Vec::new();
    };
    let mut v = Vec::new();
    for i in 0..n.min(500_000) {
        let Some(dato) = u32_(off + 4 * i) else { break };
        // ULEB128 con el largo en UTF-16, luego MUTF-8 terminado en 0.
        let mut q = dato;
        while b.get(q).is_some_and(|x| x & 0x80 != 0) {
            q += 1;
        }
        q += 1;
        let Some(resto) = b.get(q..) else { continue };
        let fin = resto.iter().take(80).position(|&x| x == 0).unwrap_or(0);
        if fin > 0
            && let Ok(s) = std::str::from_utf8(&resto[..fin])
            && literal_jca(s).is_some()
        {
            v.push(s.to_string());
        }
    }
    v
}

/// Algoritmos de firma de APK (v2/v3) por su identificador.
fn algoritmo_apk(id: u32) -> Option<&'static str> {
    Some(match id {
        0x0101 | 0x0102 => "rsassa-pss",
        0x0103 => "rsassa-pkcs1-sha256",
        0x0104 => "rsassa-pkcs1-sha512",
        0x0201 => "ecdsa-sha256",
        0x0202 => "ecdsa-sha512",
        0x0301 => "dsa",
        _ => return None,
    })
}

/// Valores de longitud prefijada (u32 LE) de una secuencia del bloque de firma.
fn secuencia(b: &[u8]) -> Vec<&[u8]> {
    let mut v = Vec::new();
    let mut p = 0usize;
    while p + 4 <= b.len() && v.len() < 64 {
        let n = u32::from_le_bytes(b[p..p + 4].try_into().expect("4 bytes")) as usize;
        let Some(x) = b.get(p + 4..p + 4 + n) else {
            break;
        };
        v.push(x);
        p += 4 + n;
    }
    v
}

/// Certificados y algoritmos del bloque de firma de APK v2/v3.
fn bloque_apk(z: &Zip<'_>) -> Option<(u32, Vec<Vec<u8>>, Vec<u32>)> {
    let fin = z.inicio_directorio;
    let magia = z.datos.get(fin.checked_sub(16)?..fin)?;
    if magia != b"APK Sig Block 42" {
        return None;
    }
    let tam = u64::from_le_bytes(z.datos.get(fin - 24..fin - 16)?.try_into().ok()?) as usize;
    let inicio = fin.checked_sub(tam + 8)?;
    let mut p = inicio + 8;
    let (mut esquema, mut certificados, mut algoritmos) = (0u32, Vec::new(), Vec::new());
    while p + 12 <= fin - 24 {
        let largo = u64::from_le_bytes(z.datos.get(p..p + 8)?.try_into().ok()?) as usize;
        let id = u32::from_le_bytes(z.datos.get(p + 8..p + 12)?.try_into().ok()?);
        let valor = z.datos.get(p + 12..p + 8 + largo)?;
        let version = match id {
            0x7109_871a => 2,
            0xf053_68c0 | 0x1b93_ad61 => 3,
            _ => 0,
        };
        if version > 0 {
            esquema = esquema.max(version);
            for firmante in secuencia(valor)
                .first()
                .map(|x| secuencia(x))
                .unwrap_or_default()
            {
                let partes = secuencia(firmante);
                if let Some(firmado) = partes.first() {
                    let campos = secuencia(firmado);
                    if let Some(certs) = campos.get(1) {
                        certificados.extend(secuencia(certs).iter().map(|x| x.to_vec()));
                    }
                }
                if let Some(firmas) = partes.get(1) {
                    for f in secuencia(firmas) {
                        if let Some(x) = f.get(..4) {
                            algoritmos.push(u32::from_le_bytes(x.try_into().ok()?));
                        }
                    }
                }
            }
        }
        p += 8 + largo;
    }
    Some((esquema, certificados, algoritmos))
}

fn agregar(x: Activo, mapa: &mut BTreeMap<String, Activo>) {
    match mapa.get_mut(&x.referencia) {
        Some(p) => p.fusionar(x),
        None => {
            mapa.insert(x.referencia.clone(), x);
        }
    }
}

fn literales(
    cadenas: &[String],
    ubicacion: &str,
    c: &Conocimiento,
    mapa: &mut BTreeMap<String, Activo>,
) {
    for s in cadenas {
        let Some((espacio, nombre)) = literal_jca(s) else {
            continue;
        };
        let candidatos: Vec<String> = if espacio == "java-cifrado" {
            let partes: Vec<&str> = nombre.split('/').collect();
            let mut v = vec![nombre.clone()];
            if partes.len() > 2 {
                v.push(partes[..2].join("/"));
            }
            v.push(partes[0].to_string());
            v
        } else {
            vec![nombre.clone()]
        };
        let Some(d) = candidatos
            .iter()
            .find_map(|n| c.codigo.traducir(espacio, n))
            .and_then(|id| c.por_id(id))
        else {
            continue;
        };
        let mut x = activo_algoritmo(Some(d), s, None, CODIGO, None, ubicacion, None);
        x.advertir(format!(
            "Literal «{s}» en el bytecode: nombre de algoritmo que la aplicación pasa a la JCA."
        ));
        agregar(x, mapa);
    }
}

pub(crate) fn analizar_archivo_java(
    a: &Archivo,
    b: &[u8],
    c: &Conocimiento,
) -> Result<Vec<Activo>, String> {
    let z = zip::abrir(b).ok_or("archivo ZIP ilegible")?;
    let mut mapa: BTreeMap<String, Activo> = BTreeMap::new();
    let mut firma: Option<Activo> = None;
    let mut leidos = 0usize;
    let mut clases = 0usize;
    let mut omitidas = 0usize;
    let nueva_firma = || {
        Activo::nuevo(
            format!("protocolo:firma-java:{}", id_corto(&a.ruta_estable)),
            format!(
                "Firma de {} ({})",
                if a.extension == "apk" { "APK" } else { "JAR" },
                a.nombre
            ),
            Detalles::Protocolo {
                tipo_protocolo: "jar-signing".into(),
                versiones: Vec::new(),
                grupos: Vec::new(),
                cifrados: Vec::new(),
            },
        )
        .con_contexto(FIRMA, Garantia::Autenticacion)
        .con_ubicacion(a.ruta, None)
    };
    let mut digestiones_v1: Vec<String> = Vec::new();

    for e in &z.entradas {
        let nombre = e.nombre.as_str();
        let n = nombre.to_ascii_uppercase();
        let ubicacion = format!("{}!/{}", a.ruta, nombre);
        if n.starts_with("META-INF/")
            && (n.ends_with(".RSA") || n.ends_with(".DSA") || n.ends_with(".EC"))
        {
            if let Some(d) = zip::leer(&z, e, 1 << 20)
                && let Some(m) = cms(&d)
            {
                let f = firma.get_or_insert_with(nueva_firma);
                for der in &m.certificados {
                    if let Ok(xs) = certificado_en_contexto(der, a.ruta, FIRMA, c) {
                        for x in xs {
                            if matches!(x.detalles, Detalles::Certificado { .. }) {
                                f.relacionar("certificate", &x.referencia);
                            }
                            agregar(x, &mut mapa);
                        }
                    }
                }
                for o in m.digestiones.iter().chain(&m.firmas) {
                    if let Some(d) = c.por_oid(o) {
                        let x = activo_algoritmo(
                            Some(d),
                            o,
                            None,
                            FIRMA,
                            Some(Garantia::Autenticacion),
                            a.ruta,
                            None,
                        );
                        f.relacionar("algorithm", &x.referencia);
                        agregar(x, &mut mapa);
                    }
                }
            }
        } else if n.starts_with("META-INF/") && n.ends_with(".SF") {
            if let Some(d) = zip::leer(&z, e, 4 << 20) {
                let t = String::from_utf8_lossy(&d);
                for l in t.lines().take(64) {
                    if let Some(k) = l.split(':').next()
                        && let Some(alg) = k
                            .strip_suffix("-Digest-Manifest")
                            .or(k.strip_suffix("-Digest"))
                        && !digestiones_v1.contains(&alg.to_string())
                    {
                        digestiones_v1.push(alg.to_string());
                    }
                }
            }
        } else if n.ends_with(".JAR") && (n.contains("LIB/") || n.contains("BOOT-INF/")) {
            // Biblioteca empaquetada: se reconoce por su nombre, sin leerla.
            let base = nombre.rsplit('/').next().unwrap_or(nombre);
            let interno = Archivo::nuevo(&ubicacion, std::path::Path::new(base), &[], None);
            for x in crate::bibliotecas::analizar_grande(&interno, c) {
                agregar(x, &mut mapa);
            }
        } else if n.ends_with(".CLASS") {
            if clases >= MAXIMO_CLASES || leidos >= MAXIMO_TOTAL {
                omitidas += 1;
                continue;
            }
            if let Some(d) = zip::leer(&z, e, MAXIMO_CLASE) {
                clases += 1;
                leidos += d.len();
                literales(&literales_clase(&d), &ubicacion, c, &mut mapa);
            }
        } else if n.ends_with(".DEX")
            && leidos < MAXIMO_TOTAL
            && let Some(d) = zip::leer(&z, e, MAXIMO_DEX)
        {
            leidos += d.len();
            literales(&cadenas_dex(&d), &ubicacion, c, &mut mapa);
        }
    }

    if !digestiones_v1.is_empty() {
        let f = firma.get_or_insert_with(nueva_firma);
        for alg in &digestiones_v1 {
            let nombre = alg.to_lowercase();
            if let Some(d) = c
                .codigo
                .traducir("codigo", &nombre)
                .and_then(|id| c.por_id(id))
            {
                let x = activo_algoritmo(
                    Some(d),
                    alg,
                    None,
                    FIRMA,
                    Some(Garantia::Integridad),
                    a.ruta,
                    None,
                );
                f.relacionar("algorithm", &x.referencia);
                agregar(x, &mut mapa);
            }
        }
        if digestiones_v1
            .iter()
            .all(|d| matches!(d.to_uppercase().as_str(), "SHA1" | "SHA-1" | "MD5"))
        {
            f.advertir("La firma del JAR resume el contenido solo con SHA-1 o MD5: Java la trata como no firmada desde JDK 17. Vuelva a firmar con SHA-256.");
            f.riesgo_fijado = Some(Riesgo::Obsoleto);
        }
    }
    if let Some((esquema, certificados, algoritmos)) = bloque_apk(&z) {
        let f = firma.get_or_insert_with(nueva_firma);
        f.advertir(format!("APK firmado con el esquema v{esquema}."));
        for der in &certificados {
            if let Ok(xs) = certificado_en_contexto(der, a.ruta, FIRMA, c) {
                for x in xs {
                    if matches!(x.detalles, Detalles::Certificado { .. }) {
                        f.relacionar("certificate", &x.referencia);
                    }
                    agregar(x, &mut mapa);
                }
            }
        }
        for id in algoritmos {
            if let Some(d) = algoritmo_apk(id).and_then(|i| c.por_id(i)) {
                let x = activo_algoritmo(
                    Some(d),
                    &format!("0x{id:04x}"),
                    None,
                    FIRMA,
                    Some(Garantia::Autenticacion),
                    a.ruta,
                    None,
                );
                f.relacionar("algorithm", &x.referencia);
                agregar(x, &mut mapa);
            }
        }
    }
    let mut v: Vec<Activo> = mapa.into_values().collect();
    if let Some(mut f) = firma {
        if omitidas > 0 {
            f.advertir(format!(
                "Se omitieron {omitidas} clases por los límites de lectura."
            ));
        }
        v.push(f);
    }
    Ok(v)
}

pub struct EscanerArchivosJava;

impl Escaner for EscanerArchivosJava {
    fn nombre(&self) -> &'static str {
        "aplicaciones Java y Android"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        matches!(a.extension.as_str(), "jar" | "war" | "ear" | "aar" | "apk")
            && a.contenido.starts_with(b"PK")
    }

    fn analizar(&self, a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
        analizar_archivo_java(a, a.contenido, c)
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::zip::pruebas::zip_almacenado;

    /// Clase mínima con las cadenas literales indicadas.
    fn clase(literales: &[&str]) -> Vec<u8> {
        let mut b = vec![0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52];
        let total = 1 + 2 * literales.len();
        b.extend((total as u16).to_be_bytes());
        for (i, s) in literales.iter().enumerate() {
            b.push(1);
            b.extend((s.len() as u16).to_be_bytes());
            b.extend(s.as_bytes());
            b.push(8);
            b.extend(((1 + 2 * i) as u16).to_be_bytes());
        }
        b
    }

    #[test]
    fn literales_y_bibliotecas_en_un_jar() {
        let c = Conocimiento::embebido();
        let cl = clase(&["AES/ECB/PKCS5Padding", "SHA1withRSA", "hola mundo", "TLSv1"]);
        let jar = zip_almacenado(&[
            ("com/ejemplo/Cifrado.class", &cl),
            ("BOOT-INF/lib/bcprov-jdk18on-1.78.1.jar", b"PK"),
            (
                "META-INF/APP.SF",
                b"Signature-Version: 1.0\nSHA1-Digest-Manifest: abc=\n",
            ),
        ]);
        let a = Archivo::nuevo("app.jar", std::path::Path::new("app.jar"), &jar, None);
        assert!(EscanerArchivosJava.aplica(&a));
        let v = EscanerArchivosJava.analizar(&a, &c).unwrap();
        let ids: Vec<&str> = v.iter().filter_map(|x| x.algoritmo_id()).collect();
        assert!(
            ids.contains(&"modo-ecb")
                && ids.contains(&"rsassa-pkcs1-sha1")
                && ids.contains(&"tls-1.0"),
            "{ids:?}"
        );
        assert!(v.iter().any(|x| x.nombre.starts_with("Bouncy Castle")));
        let f = v
            .iter()
            .find(|x| x.referencia.starts_with("protocolo:firma-java"))
            .unwrap();
        assert_eq!(f.riesgo_fijado, Some(Riesgo::Obsoleto));
        let ecb = v
            .iter()
            .find(|x| x.algoritmo_id() == Some("modo-ecb"))
            .unwrap();
        assert!(
            ecb.ubicaciones[0]
                .ruta
                .ends_with("app.jar!/com/ejemplo/Cifrado.class")
        );
    }

    #[test]
    fn literales_validos() {
        assert!(literal_jca("DESede/CBC/PKCS5Padding").is_some());
        assert!(literal_jca("MD5").is_some());
        assert!(literal_jca("SHA-256").is_some());
        assert!(literal_jca("Bienvenido").is_none());
        assert!(literal_jca("AESUtil").is_none());
    }
}
