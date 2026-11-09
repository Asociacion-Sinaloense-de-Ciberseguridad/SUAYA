//! Ejecutables y firmware: firmas de código, símbolos criptográficos y
//! constantes de algoritmos.
//!
//! - **Firmas**: Authenticode en PE (Windows: `.exe`, `.dll`, `.sys`, `.efi`)
//!   y firma de código de macOS en Mach-O (incluidos binarios universales):
//!   certificados, hash del archivo y algoritmos del firmante.
//! - **Símbolos importados** (ELF, Mach-O e importaciones de PE): funciones de
//!   OpenSSL, CommonCrypto y similares que nombran un algoritmo
//!   (`EVP_des_ede3_cbc`, `MD5_Init`, `CC_SHA1`).
//! - **Constantes**: tablas de MD5, SHA-1, DES y Blowfish incrustadas, que
//!   delatan implementaciones propias o enlazadas estáticamente (firmware).
//!
//! Suaya no ejecuta ni verifica firmas: solo lee estructuras, con límites.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use aho_corasick::AhoCorasick;
use suaya_core::{Activo, Conocimiento, Detalles, Garantia, Riesgo};

use crate::Escaner;
use crate::comun::{Archivo, activo_algoritmo, id_corto};
use crate::der::{Cms, cms};
use crate::pem::certificado_en_contexto;

const FIRMA: &str = "firma-codigo";
const CODIGO: &str = "codigo-aplicacion";
const MAXIMO_SIMBOLOS: usize = 300_000;

fn u16le(b: &[u8], p: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(p..p + 2)?.try_into().ok()?))
}
fn u32le(b: &[u8], p: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(p..p + 4)?.try_into().ok()?))
}
fn u64le(b: &[u8], p: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(p..p + 8)?.try_into().ok()?))
}
fn u32be(b: &[u8], p: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(p..p + 4)?.try_into().ok()?))
}

fn cadena_c(b: &[u8], p: usize) -> Option<&str> {
    let resto = b.get(p..)?;
    let fin = resto.iter().take(512).position(|&x| x == 0)?;
    std::str::from_utf8(&resto[..fin]).ok()
}

// ---------------------------------------------------------------------------
// PE (Windows)
// ---------------------------------------------------------------------------

struct Pe {
    /// Directorios de datos: (rva o desplazamiento, tamaño).
    directorios: Vec<(u32, u32)>,
    /// Secciones: (dirección virtual, tamaño virtual, tamaño en archivo, desplazamiento).
    secciones: Vec<(u32, u32, u32, u32)>,
    pe32_mas: bool,
}

fn pe(b: &[u8]) -> Option<Pe> {
    if !b.starts_with(b"MZ") {
        return None;
    }
    let off = u32le(b, 0x3C)? as usize;
    if b.get(off..off + 4)? != b"PE\0\0" {
        return None;
    }
    let coff = off + 4;
    let nsec = u16le(b, coff + 2)? as usize;
    let opt_tam = u16le(b, coff + 16)? as usize;
    let opt = coff + 20;
    let pe32_mas = u16le(b, opt)? == 0x20b;
    let (num, dirs) = if pe32_mas {
        (opt + 108, opt + 112)
    } else {
        (opt + 92, opt + 96)
    };
    let n = (u32le(b, num)? as usize).min(16);
    let directorios = (0..n)
        .filter_map(|i| Some((u32le(b, dirs + 8 * i)?, u32le(b, dirs + 8 * i + 4)?)))
        .collect();
    let tabla = opt + opt_tam;
    let secciones = (0..nsec.min(96))
        .filter_map(|i| {
            let s = tabla + 40 * i;
            Some((
                u32le(b, s + 12)?,
                u32le(b, s + 8)?,
                u32le(b, s + 16)?,
                u32le(b, s + 20)?,
            ))
        })
        .collect();
    Some(Pe {
        directorios,
        secciones,
        pe32_mas,
    })
}

impl Pe {
    fn desplazamiento(&self, rva: u32) -> Option<usize> {
        self.secciones.iter().find_map(|&(va, vt, rt, ptr)| {
            (rva >= va && rva < va.saturating_add(vt.max(rt))).then(|| (ptr + (rva - va)) as usize)
        })
    }
}

/// Firmas Authenticode (WIN_CERTIFICATE de tipo PKCS #7).
fn authenticode(b: &[u8], p: &Pe) -> Vec<Cms> {
    let Some(&(inicio, tam)) = p.directorios.get(4) else {
        return Vec::new();
    };
    let (inicio, fin) = (inicio as usize, inicio as usize + tam as usize);
    let mut v = Vec::new();
    let mut q = inicio;
    while q + 8 <= fin.min(b.len()) && v.len() < 8 {
        let Some(largo) = u32le(b, q).map(|x| x as usize) else {
            break;
        };
        let tipo = u16le(b, q + 6).unwrap_or(0);
        if largo < 8 || q + largo > b.len() {
            break;
        }
        if tipo == 2
            && let Some(m) = cms(&b[q + 8..q + largo])
        {
            v.push(m);
        }
        q += largo.div_ceil(8) * 8;
    }
    v
}

/// Funciones importadas («biblioteca!función»).
fn importaciones_pe(b: &[u8], p: &Pe) -> Vec<String> {
    let mut v = Vec::new();
    let Some(&(rva, _)) = p.directorios.get(1) else {
        return v;
    };
    let Some(mut d) = p.desplazamiento(rva) else {
        return v;
    };
    for _ in 0..512 {
        let (Some(original), Some(nombre_rva), Some(primero)) =
            (u32le(b, d), u32le(b, d + 12), u32le(b, d + 16))
        else {
            break;
        };
        if nombre_rva == 0 {
            break;
        }
        let dll = p
            .desplazamiento(nombre_rva)
            .and_then(|o| cadena_c(b, o))
            .unwrap_or("")
            .to_ascii_lowercase();
        let thunks = if original != 0 { original } else { primero };
        if let Some(mut t) = p.desplazamiento(thunks) {
            for _ in 0..4096 {
                let (valor, ordinal) = if p.pe32_mas {
                    let x = u64le(b, t).unwrap_or(0);
                    (x & 0x7FFF_FFFF, x >> 63 == 1)
                } else {
                    let x = u32le(b, t).unwrap_or(0) as u64;
                    (x & 0x7FFF_FFFF, x >> 31 == 1)
                };
                if valor == 0 {
                    break;
                }
                if !ordinal
                    && let Some(o) = p.desplazamiento(valor as u32)
                    && let Some(f) = cadena_c(b, o + 2)
                {
                    v.push(format!("{dll}!{f}"));
                    if v.len() >= MAXIMO_SIMBOLOS {
                        return v;
                    }
                }
                t += if p.pe32_mas { 8 } else { 4 };
            }
        }
        d += 20;
    }
    v
}

// ---------------------------------------------------------------------------
// ELF
// ---------------------------------------------------------------------------

/// Símbolos no definidos (importados) de un ELF.
fn importaciones_elf(b: &[u8]) -> Vec<String> {
    let mut v = Vec::new();
    if !b.starts_with(b"\x7fELF") || b.len() < 64 {
        return v;
    }
    let es64 = b[4] == 2;
    let be = b[5] == 2;
    let u16_ = |p: usize| -> Option<u16> {
        let x: [u8; 2] = b.get(p..p + 2)?.try_into().ok()?;
        Some(if be {
            u16::from_be_bytes(x)
        } else {
            u16::from_le_bytes(x)
        })
    };
    let u32_ = |p: usize| -> Option<u32> {
        let x: [u8; 4] = b.get(p..p + 4)?.try_into().ok()?;
        Some(if be {
            u32::from_be_bytes(x)
        } else {
            u32::from_le_bytes(x)
        })
    };
    let u64_ = |p: usize| -> Option<u64> {
        let x: [u8; 8] = b.get(p..p + 8)?.try_into().ok()?;
        Some(if be {
            u64::from_be_bytes(x)
        } else {
            u64::from_le_bytes(x)
        })
    };
    let (shoff, shent, shnum) = if es64 {
        (
            u64_(0x28).unwrap_or(0) as usize,
            u16_(0x3A).unwrap_or(0) as usize,
            u16_(0x3C).unwrap_or(0) as usize,
        )
    } else {
        (
            u32_(0x20).unwrap_or(0) as usize,
            u16_(0x2E).unwrap_or(0) as usize,
            u16_(0x30).unwrap_or(0) as usize,
        )
    };
    if shent == 0 || shnum > 4096 {
        return v;
    }
    // (tipo, desplazamiento, tamaño, enlace, tamaño de entrada)
    let seccion = |i: usize| -> Option<(u32, usize, usize, usize, usize)> {
        let s = shoff.checked_add(i.checked_mul(shent)?)?;
        if es64 {
            Some((
                u32_(s + 4)?,
                u64_(s + 24)? as usize,
                u64_(s + 32)? as usize,
                u32_(s + 40)? as usize,
                u64_(s + 56)? as usize,
            ))
        } else {
            Some((
                u32_(s + 4)?,
                u32_(s + 16)? as usize,
                u32_(s + 20)? as usize,
                u32_(s + 24)? as usize,
                u32_(s + 36)? as usize,
            ))
        }
    };
    for i in 0..shnum {
        let Some((tipo, off, tam, enlace, ent)) = seccion(i) else {
            continue;
        };
        if !matches!(tipo, 2 | 11) || ent == 0 {
            continue;
        }
        let Some((_, str_off, str_tam, _, _)) = seccion(enlace) else {
            continue;
        };
        let Some(cadenas) = b.get(str_off..str_off.saturating_add(str_tam)) else {
            continue;
        };
        for j in 0..(tam / ent).min(MAXIMO_SIMBOLOS) {
            let e = off + j * ent;
            let (nombre, indice) = if es64 {
                (u32_(e), u16_(e + 6))
            } else {
                (u32_(e), u16_(e + 14))
            };
            if let (Some(n), Some(0)) = (nombre, indice)
                && let Some(s) = cadena_c(cadenas, n as usize)
                && !s.is_empty()
            {
                v.push(s.to_string());
            }
        }
    }
    v
}

// ---------------------------------------------------------------------------
// Mach-O (macOS, iOS)
// ---------------------------------------------------------------------------

/// Rebanadas de un binario universal (o el binario completo).
fn rebanadas(b: &[u8]) -> Vec<&[u8]> {
    if b.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE]) {
        let n = u32be(b, 4).unwrap_or(0) as usize;
        if n == 0 || n > 30 {
            return Vec::new(); // Probablemente una clase de Java.
        }
        return (0..n.min(8))
            .filter_map(|i| {
                let e = 8 + 20 * i;
                let off = u32be(b, e + 8)? as usize;
                let tam = u32be(b, e + 12)? as usize;
                b.get(off..off.checked_add(tam)?)
            })
            .collect();
    }
    if b.starts_with(&[0xCF, 0xFA, 0xED, 0xFE]) || b.starts_with(&[0xCE, 0xFA, 0xED, 0xFE]) {
        return vec![b];
    }
    Vec::new()
}

#[derive(Default)]
struct FirmaMacho {
    hashes: Vec<u8>,
    cms: Option<Cms>,
    ad_hoc: bool,
    identificador: Option<String>,
}

fn macho(b: &[u8]) -> (Vec<String>, Option<FirmaMacho>) {
    let es64 = b.starts_with(&[0xCF, 0xFA, 0xED, 0xFE]);
    let ncmds = u32le(b, 16).unwrap_or(0) as usize;
    let mut p = if es64 { 32 } else { 28 };
    let mut simbolos = Vec::new();
    let mut firma = None;
    for _ in 0..ncmds.min(512) {
        let (Some(cmd), Some(tam)) = (u32le(b, p), u32le(b, p + 4)) else {
            break;
        };
        match cmd {
            0x2 => {
                // LC_SYMTAB: símbolos no definidos (importados).
                let (symoff, nsyms, stroff) = (
                    u32le(b, p + 8).unwrap_or(0) as usize,
                    u32le(b, p + 12).unwrap_or(0) as usize,
                    u32le(b, p + 16).unwrap_or(0) as usize,
                );
                let ent = if es64 { 16 } else { 12 };
                for i in 0..nsyms.min(MAXIMO_SIMBOLOS) {
                    let e = symoff + i * ent;
                    let (Some(strx), Some(&tipo)) = (u32le(b, e), b.get(e + 4)) else {
                        break;
                    };
                    if tipo & 0x0e == 0
                        && tipo & 0x01 != 0
                        && let Some(s) = cadena_c(b, stroff + strx as usize)
                    {
                        simbolos.push(s.trim_start_matches('_').to_string());
                    }
                }
            }
            0x1d => {
                // LC_CODE_SIGNATURE: SuperBlob (en big-endian).
                let off = u32le(b, p + 8).unwrap_or(0) as usize;
                let mut f = FirmaMacho::default();
                if u32be(b, off) == Some(0xfade_0cc0) {
                    let cuenta = u32be(b, off + 8).unwrap_or(0) as usize;
                    for i in 0..cuenta.min(32) {
                        let Some(rel) = u32be(b, off + 12 + 8 * i + 4) else {
                            break;
                        };
                        let blob = off + rel as usize;
                        match u32be(b, blob) {
                            Some(0xfade_0c02) => {
                                if let Some(&h) = b.get(blob + 37) {
                                    f.hashes.push(h);
                                }
                                if f.identificador.is_none()
                                    && let Some(io) = u32be(b, blob + 20)
                                {
                                    f.identificador =
                                        cadena_c(b, blob + io as usize).map(str::to_string);
                                }
                            }
                            Some(0xfade_0b01) => {
                                let largo = u32be(b, blob + 4).unwrap_or(8) as usize;
                                if largo <= 8 {
                                    f.ad_hoc = true;
                                } else if let Some(d) = b.get(blob + 8..blob + largo) {
                                    f.cms = cms(d);
                                }
                            }
                            _ => {}
                        }
                    }
                }
                firma = Some(f);
            }
            _ => {}
        }
        if tam < 8 {
            break;
        }
        p += tam as usize;
    }
    (simbolos, firma)
}

// ---------------------------------------------------------------------------
// Símbolos y constantes a algoritmos
// ---------------------------------------------------------------------------

/// Nombre de algoritmo (de `[nombres.codigo]`) que delata una función.
fn algoritmo_de_simbolo(s: &str) -> Option<String> {
    let s = s.rsplit('!').next().unwrap_or(s).trim_start_matches('_');
    if let Some(r) = s.strip_prefix("EVP_") {
        let r = r.to_ascii_lowercase();
        const GENERICAS: &[&str] = &[
            "init", "ctx", "update", "final", "get", "pkey", "cipher", "digest", "md_", "encrypt",
            "decrypt", "sign", "verify", "seal", "open", "mac", "kdf", "rand", "q_", "add", "set",
            "bytes", "encode", "decode", "keygen", "derive",
        ];
        if GENERICAS
            .iter()
            .any(|g| r.starts_with(g) || r.contains(&format!("_{g}")))
        {
            return None;
        }
        return Some(r.replace('_', "-"));
    }
    Some(
        match s {
            "MD5" | "MD5_Init" | "MD5_Update" | "MD5_Final" | "CC_MD5" | "CC_MD5_Init"
            | "MD5Init" => "md5",
            "MD4" | "MD4_Init" | "MD4Init" => "md4",
            "SHA1" | "SHA1_Init" | "SHA1_Update" | "CC_SHA1" | "CC_SHA1_Init" => "sha1",
            "RC4" | "RC4_set_key" => "rc4",
            "DES_set_key"
            | "DES_set_key_checked"
            | "DES_set_key_unchecked"
            | "DES_ecb_encrypt"
            | "DES_ncbc_encrypt" => "des",
            "DES_ede3_cbc_encrypt" | "DES_ecb3_encrypt" => "des3",
            "BF_set_key" | "BF_cbc_encrypt" => "blowfish",
            "RC2_set_key" => "rc2",
            "RSA_generate_key" | "RSA_generate_key_ex" => "rsa",
            "DSA_generate_key" | "DSA_generate_parameters_ex" => "dsa",
            "DH_generate_key" => "dh",
            "EC_KEY_generate_key" | "EC_KEY_new_by_curve_name" => "ec",
            "ECDH_compute_key" => "ecdh",
            _ => return None,
        }
        .into(),
    )
}

/// Constantes de implementación de algoritmos débiles: (bytes, nombre).
const CONSTANTES: &[(&[u8], &str)] = &[
    // MD5: tabla T (0xd76aa478, 0xe8c7b756...) en little-endian.
    (&[0x78, 0xa4, 0x6a, 0xd7, 0x56, 0xb7, 0xc7, 0xe8], "md5"),
    (&[0xd7, 0x6a, 0xa4, 0x78, 0xe8, 0xc7, 0xb7, 0x56], "md5"),
    // SHA-1: los cinco valores iniciales (también los usa RIPEMD-160).
    (
        &[
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10, 0xf0, 0xe1, 0xd2, 0xc3,
        ],
        "sha1",
    ),
    (
        &[
            0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32,
            0x54, 0x76, 0xc3, 0xd2, 0xe1, 0xf0,
        ],
        "sha1",
    ),
    // DES: caja S1 como bytes.
    (
        &[
            0x0e, 0x04, 0x0d, 0x01, 0x02, 0x0f, 0x0b, 0x08, 0x03, 0x0a, 0x06, 0x0c, 0x05, 0x09,
            0x00, 0x07,
        ],
        "des",
    ),
    // Blowfish: arreglo P (dígitos de pi).
    (
        &[
            0x88, 0x6a, 0x3f, 0x24, 0xd3, 0x08, 0xa3, 0x85, 0x2e, 0x8a, 0x19, 0x13,
        ],
        "blowfish",
    ),
    (
        &[
            0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3, 0x13, 0x19, 0x8a, 0x2e,
        ],
        "blowfish",
    ),
];

fn constantes(b: &[u8]) -> Vec<&'static str> {
    static A: OnceLock<AhoCorasick> = OnceLock::new();
    let a = A.get_or_init(|| {
        AhoCorasick::new(CONSTANTES.iter().map(|(p, _)| *p)).expect("patrones válidos")
    });
    let mut v: Vec<&'static str> = a
        .find_iter(b)
        .map(|m| CONSTANTES[m.pattern().as_usize()].1)
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

// ---------------------------------------------------------------------------
// Activos
// ---------------------------------------------------------------------------

fn agregar(x: Activo, mapa: &mut BTreeMap<String, Activo>) {
    match mapa.get_mut(&x.referencia) {
        Some(p) => p.fusionar(x),
        None => {
            mapa.insert(x.referencia.clone(), x);
        }
    }
}

fn activo_firma(a: &Archivo, tipo: &str, nombre: String) -> Activo {
    Activo::nuevo(
        format!("protocolo:{tipo}:{}", id_corto(&a.ruta_estable)),
        nombre,
        Detalles::Protocolo {
            tipo_protocolo: tipo.into(),
            versiones: Vec::new(),
            grupos: Vec::new(),
            cifrados: Vec::new(),
        },
    )
    .con_contexto(FIRMA, Garantia::Autenticacion)
    .con_ubicacion(a.ruta, None)
}

fn agregar_cms(
    m: &Cms,
    a: &Archivo,
    c: &Conocimiento,
    p: &mut Activo,
    mapa: &mut BTreeMap<String, Activo>,
) {
    for der in &m.certificados {
        if let Ok(xs) = certificado_en_contexto(der, a.ruta, FIRMA, c) {
            for x in xs {
                if matches!(x.detalles, Detalles::Certificado { .. }) {
                    p.relacionar("certificate", &x.referencia);
                }
                agregar(x, mapa);
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
            p.relacionar("algorithm", &x.referencia);
            agregar(x, mapa);
        }
    }
}

/// Analiza un ejecutable (o firmware) completo en memoria.
pub(crate) fn analizar_ejecutable(a: &Archivo, b: &[u8], c: &Conocimiento) -> Vec<Activo> {
    let mut mapa: BTreeMap<String, Activo> = BTreeMap::new();
    let mut firmas: Vec<Activo> = Vec::new();
    let mut simbolos: Vec<String> = Vec::new();

    if let Some(p) = pe(b) {
        let ms = authenticode(b, &p);
        if !ms.is_empty() {
            let mut f = activo_firma(
                a,
                "authenticode",
                format!("Firma Authenticode ({})", a.nombre),
            );
            let mut hashes = Vec::new();
            for m in &ms {
                if let Some(h) = &m.hash_contenido {
                    hashes.push(
                        c.por_oid(h)
                            .map(|d| d.id.clone())
                            .unwrap_or_else(|| h.clone()),
                    );
                }
                agregar_cms(m, a, c, &mut f, &mut mapa);
            }
            if !hashes.is_empty() && hashes.iter().all(|h| h == "sha1" || h == "md5") {
                f.advertir("La firma Authenticode solo cubre el archivo con SHA-1 o MD5: Windows ya no la acepta para muchos usos. Vuelva a firmar con SHA-256.");
                f.riesgo_fijado = Some(Riesgo::Obsoleto);
            }
            f.advertir(format!(
                "{} firmas Authenticode; hash del archivo: {}.",
                ms.len(),
                hashes.join(", ")
            ));
            firmas.push(f);
        }
        simbolos = importaciones_pe(b, &p);
    } else if b.starts_with(b"\x7fELF") {
        simbolos = importaciones_elf(b);
    } else {
        for r in rebanadas(b) {
            let (s, firma) = macho(r);
            simbolos.extend(s);
            if let Some(fm) = firma {
                let mut f = activo_firma(
                    a,
                    "macos-codesign",
                    format!("Firma de código de macOS ({})", a.nombre),
                );
                if let Some(i) = &fm.identificador {
                    f.advertir(format!("Identificador: {i}."));
                }
                if fm.ad_hoc || fm.cms.is_none() {
                    f.advertir("Firma ad hoc: no identifica a quien la firmó.");
                }
                if let Some(m) = &fm.cms {
                    agregar_cms(m, a, c, &mut f, &mut mapa);
                }
                // Tipos de hash del CodeDirectory: 1 SHA-1, 2 SHA-256, 3 SHA-256 truncado, 4 SHA-384.
                let solo_sha1 = !fm.hashes.is_empty() && fm.hashes.iter().all(|h| *h == 1);
                for h in &fm.hashes {
                    let id = match h {
                        1 => "sha1",
                        2 | 3 => "sha256",
                        4 => "sha384",
                        _ => continue,
                    };
                    let x = activo_algoritmo(
                        c.por_id(id),
                        id,
                        None,
                        FIRMA,
                        Some(Garantia::Integridad),
                        a.ruta,
                        None,
                    );
                    f.relacionar("algorithm", &x.referencia);
                    agregar(x, &mut mapa);
                }
                if solo_sha1 {
                    f.advertir("El directorio de código solo tiene hashes SHA-1.");
                    f.riesgo_fijado = Some(Riesgo::Obsoleto);
                }
                if !firmas.iter().any(|x| x.referencia == f.referencia) {
                    firmas.push(f);
                }
            }
        }
    }

    simbolos.sort();
    simbolos.dedup();
    for s in simbolos.iter().take(MAXIMO_SIMBOLOS) {
        if let Some(n) = algoritmo_de_simbolo(s)
            && let Some(d) = c.codigo.traducir("codigo", &n).and_then(|id| c.por_id(id))
        {
            let mut x = activo_algoritmo(Some(d), &n, None, CODIGO, None, a.ruta, None);
            x.advertir(format!("Función importada por el binario: {s}."));
            agregar(x, &mut mapa);
        }
    }

    // Constantes: solo si no es una biblioteca criptográfica conocida ni un binario de Go
    // (que incluye sus paquetes estándar), para no confundir disponibilidad con uso.
    let biblioteca = [
        &b"OpenSSL "[..],
        b"LibreSSL ",
        b"Go buildinf:",
        b"wolfSSL",
        b"mbed TLS",
        b"BoringSSL",
    ]
    .iter()
    .any(|m| memchr::memmem::find(b, m).is_some());
    if !biblioteca {
        for n in constantes(b) {
            if let Some(d) = c.codigo.traducir("codigo", n).and_then(|id| c.por_id(id)) {
                let mut x = activo_algoritmo(Some(d), n, None, CODIGO, None, a.ruta, None);
                x.advertir("Constantes de implementación halladas en el binario: puede ser una implementación propia o enlazada estáticamente. Confirme su uso.");
                agregar(x, &mut mapa);
            }
        }
    }
    let mut v: Vec<Activo> = mapa.into_values().collect();
    v.extend(firmas);
    v
}

pub struct EscanerEjecutables;

/// Extensiones de firmware o imágenes sin cabecera ejecutable reconocible.
const FIRMWARE: &[&str] = &["bin", "fw", "rom", "efi", "img"];

impl Escaner for EscanerEjecutables {
    fn nombre(&self) -> &'static str {
        "ejecutables y firmware"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        crate::bibliotecas::es_binario(a.contenido) || FIRMWARE.contains(&a.extension.as_str())
    }

    fn analizar(&self, a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
        if a.contenido.starts_with(crate::luks::MAGIA) {
            return Ok(Vec::new());
        }
        Ok(analizar_ejecutable(a, a.contenido, c))
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn simbolos_a_algoritmos() {
        assert_eq!(
            algoritmo_de_simbolo("EVP_des_ede3_cbc").as_deref(),
            Some("des-ede3-cbc")
        );
        assert_eq!(algoritmo_de_simbolo("_CC_MD5").as_deref(), Some("md5"));
        assert_eq!(
            algoritmo_de_simbolo("libcrypto-3.dll!EVP_rc4").as_deref(),
            Some("rc4")
        );
        assert_eq!(algoritmo_de_simbolo("EVP_EncryptInit_ex"), None);
        assert_eq!(algoritmo_de_simbolo("EVP_CIPHER_CTX_new"), None);
        assert_eq!(algoritmo_de_simbolo("printf"), None);
    }

    #[test]
    fn constantes_en_firmware() {
        let c = Conocimiento::embebido();
        let mut b = vec![0u8; 64];
        b.extend([
            0x0e, 0x04, 0x0d, 0x01, 0x02, 0x0f, 0x0b, 0x08, 0x03, 0x0a, 0x06, 0x0c, 0x05, 0x09,
            0x00, 0x07,
        ]);
        b.extend([0x78, 0xa4, 0x6a, 0xd7, 0x56, 0xb7, 0xc7, 0xe8]);
        let a = Archivo::nuevo(
            "firmware.bin",
            std::path::Path::new("firmware.bin"),
            &b,
            None,
        );
        assert!(EscanerEjecutables.aplica(&a));
        let v = EscanerEjecutables.analizar(&a, &c).unwrap();
        assert!(v.iter().any(|x| x.algoritmo_id() == Some("des")));
        assert!(v.iter().any(|x| x.algoritmo_id() == Some("md5")));
        // En una biblioteca conocida no se reportan constantes.
        b.extend(b"OpenSSL 3.0.13 30 Jan 2024");
        let a = Archivo::nuevo(
            "libcrypto.bin",
            std::path::Path::new("libcrypto.bin"),
            &b,
            None,
        );
        assert!(EscanerEjecutables.analizar(&a, &c).unwrap().is_empty());
    }

    #[test]
    fn elf_con_importaciones() {
        // ELF64 mínimo con .dynsym y .dynstr: importa MD5_Init y printf.
        let mut b = vec![0u8; 64];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        let cadenas = b"\0MD5_Init\0printf\0";
        let str_off = b.len();
        b.extend(cadenas);
        while !b.len().is_multiple_of(8) {
            b.push(0);
        }
        let sym_off = b.len();
        for nombre in [1u32, 10u32] {
            let mut e = [0u8; 24];
            e[..4].copy_from_slice(&nombre.to_le_bytes());
            b.extend(e);
        }
        let shoff = b.len();
        let seccion = |tipo: u32, off: usize, tam: usize, enlace: u32, ent: u64| {
            let mut s = [0u8; 64];
            s[4..8].copy_from_slice(&tipo.to_le_bytes());
            s[24..32].copy_from_slice(&(off as u64).to_le_bytes());
            s[32..40].copy_from_slice(&(tam as u64).to_le_bytes());
            s[40..44].copy_from_slice(&enlace.to_le_bytes());
            s[56..64].copy_from_slice(&ent.to_le_bytes());
            s
        };
        let s0 = [0u8; 64];
        let s1 = seccion(11, sym_off, 48, 2, 24);
        let s2 = seccion(3, str_off, cadenas.len(), 0, 0);
        b.extend(s0);
        b.extend(s1);
        b.extend(s2);
        b[0x28..0x30].copy_from_slice(&(shoff as u64).to_le_bytes());
        b[0x3A..0x3C].copy_from_slice(&64u16.to_le_bytes());
        b[0x3C..0x3E].copy_from_slice(&3u16.to_le_bytes());
        let s = importaciones_elf(&b);
        assert_eq!(s, vec!["MD5_Init", "printf"]);
        let a = Archivo::nuevo("app", std::path::Path::new("app"), &b, None);
        let v = analizar_ejecutable(&a, &b, &Conocimiento::embebido());
        assert!(v.iter().any(|x| x.algoritmo_id() == Some("md5")));
    }
}
