//! Exportaciones del registro de Windows (`reg export`, archivos `.reg`).
//!
//! Windows guarda su configuración criptográfica en el registro. Suaya lee una
//! exportación, sin acceder al equipo, y reconoce:
//!
//! - **SChannel**: versiones de SSL/TLS habilitadas por lado (servidor y
//!   cliente), cifradores, hashes, tamaño mínimo de Diffie-Hellman, orden de
//!   suites (`Functions`) y curvas (`EccCurves`).
//! - **Kerberos**: `SupportedEncryptionTypes` (RC4 y DES).
//! - **BitLocker**: método de cifrado de las políticas de FVE.
//! - **.NET Framework**: `SchUseStrongCrypto` y `SystemDefaultTlsVersions`.
//! - **NTLM**: `LmCompatibilityLevel` (LM y NTLMv1).
//! - **Certificados** de los almacenes del sistema (`SystemCertificates`).
//! - **Políticas de navegador** que desactivan el acuerdo poscuántico.
//!
//! Para obtener la exportación: `reg export HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL schannel.reg`.

use std::collections::BTreeMap;

use suaya_core::{Activo, Conocimiento, Detalles, Garantia, Riesgo};

use crate::Escaner;
use crate::comun::{Archivo, activo_algoritmo, id_corto, por_alias};
use crate::config_sistema::{advertencias_cifrados, version_tls};
use crate::config_tls::evaluar_tls;
use crate::pem::certificado_en_contexto;

/// Un valor del registro.
#[derive(Debug, Clone, PartialEq)]
enum Dato {
    Dword(u32),
    Texto(String),
    Binario(Vec<u8>),
    Multi(Vec<String>),
}

#[derive(Debug, Clone)]
struct Valor {
    clave: String,
    nombre: String,
    dato: Dato,
    linea: u32,
}

/// Valores `Enabled` y `DisabledByDefault` de un protocolo de SChannel.
type EstadoProtocolo = (Option<u32>, Option<u32>);

fn decodificar(b: &[u8]) -> String {
    if b.starts_with(&[0xFF, 0xFE]) {
        let u: Vec<u16> = b[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        String::from_utf16_lossy(&u)
    } else if b.starts_with(&[0xFE, 0xFF]) {
        let u: Vec<u16> = b[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_be_bytes(*c))
            .collect();
        String::from_utf16_lossy(&u)
    } else {
        String::from_utf8_lossy(b.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(b)).into_owned()
    }
}

fn hex_bytes(t: &str) -> Vec<u8> {
    t.split(',')
        .filter_map(|x| u8::from_str_radix(x.trim(), 16).ok())
        .collect()
}

fn utf16_multi(b: &[u8]) -> Vec<String> {
    let u: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    String::from_utf16_lossy(&u)
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Interpreta el texto de una exportación (`REGEDIT4` o versión 5.00).
fn valores(texto: &str) -> Vec<Valor> {
    let mut v = Vec::new();
    let mut clave = String::new();
    let lineas: Vec<&str> = texto.lines().collect();
    let mut i = 0;
    while i < lineas.len() && v.len() < 200_000 {
        let inicio = i;
        let mut l = lineas[i].trim_end().to_string();
        while l.ends_with('\\') && i + 1 < lineas.len() {
            l.pop();
            i += 1;
            l.push_str(lineas[i].trim());
        }
        i += 1;
        let t = l.trim();
        if let Some(k) = t.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
            clave = k.to_string();
            continue;
        }
        let (nombre, resto) = if let Some(r) = t.strip_prefix("@=") {
            ("@".to_string(), r)
        } else if let Some(r) = t.strip_prefix('"') {
            // Nombre entre comillas, con \" y \\ escapados.
            let mut nombre = String::new();
            let mut cs = r.char_indices();
            let mut fin = None;
            while let Some((j, ch)) = cs.next() {
                match ch {
                    '\\' => {
                        if let Some((_, x)) = cs.next() {
                            nombre.push(x);
                        }
                    }
                    '"' => {
                        fin = Some(j);
                        break;
                    }
                    _ => nombre.push(ch),
                }
            }
            let Some(fin) = fin else { continue };
            match r[fin + 1..].strip_prefix('=') {
                Some(x) => (nombre, x),
                None => continue,
            }
        } else {
            continue;
        };
        let dato = if let Some(h) = resto.strip_prefix("dword:") {
            match u32::from_str_radix(h.trim(), 16) {
                Ok(n) => Dato::Dword(n),
                Err(_) => continue,
            }
        } else if let Some(h) = resto.strip_prefix("hex(7):") {
            Dato::Multi(utf16_multi(&hex_bytes(h)))
        } else if let Some(h) = resto.strip_prefix("hex(2):") {
            Dato::Texto(utf16_multi(&hex_bytes(h)).join(""))
        } else if let Some(h) = resto.strip_prefix("hex:") {
            Dato::Binario(hex_bytes(h))
        } else if let Some(s) = resto.strip_prefix('"').and_then(|x| x.strip_suffix('"')) {
            Dato::Texto(s.replace("\\\\", "\\").replace("\\\"", "\""))
        } else {
            continue;
        };
        v.push(Valor {
            clave: clave.clone(),
            nombre,
            dato,
            linea: inicio as u32 + 1,
        });
    }
    v
}

fn agregar(x: Activo, algoritmos: &mut BTreeMap<String, Activo>) {
    match algoritmos.get_mut(&x.referencia) {
        Some(previo) => previo.fusionar(x),
        None => {
            algoritmos.insert(x.referencia.clone(), x);
        }
    }
}

/// DER del certificado dentro de un «Blob» de SystemCertificates: una serie
/// de propiedades (id, reservado, largo, datos); la 32 es el certificado.
fn certificado_de_blob(b: &[u8]) -> Option<&[u8]> {
    let mut p = 0usize;
    while p + 12 <= b.len() {
        let id = u32::from_le_bytes(b[p..p + 4].try_into().ok()?);
        let largo = u32::from_le_bytes(b[p + 8..p + 12].try_into().ok()?) as usize;
        let datos = b.get(p + 12..p + 12 + largo)?;
        if id == 32 && datos.first() == Some(&0x30) {
            return Some(datos);
        }
        p += 12 + largo;
    }
    None
}

pub struct EscanerRegistroWindows;

impl Escaner for EscanerRegistroWindows {
    fn nombre(&self) -> &'static str {
        "registro de Windows"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        if a.extension != "reg" {
            return false;
        }
        let inicio = decodificar(&a.contenido[..a.contenido.len().min(256)]);
        inicio.contains("Windows Registry Editor") || inicio.contains("REGEDIT4")
    }

    fn analizar(&self, a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
        let texto = decodificar(a.contenido);
        let vs = valores(&texto);
        let mut activos: Vec<Activo> = Vec::new();
        let mut algoritmos: BTreeMap<String, Activo> = BTreeMap::new();
        let alg = |id: &str, tamano: Option<u32>, cap: &str, g: Garantia, linea: u32| {
            activo_algoritmo(c.por_id(id), id, tamano, cap, Some(g), a.ruta, Some(linea))
        };

        // Estado por lado y versión: (Enabled, DisabledByDefault).
        let mut protocolos: BTreeMap<String, BTreeMap<&'static str, EstadoProtocolo>> =
            BTreeMap::new();
        let mut suites: Vec<String> = Vec::new();
        let mut curvas: Vec<String> = Vec::new();
        let mut avisos_schannel: Vec<String> = Vec::new();
        let mut riesgo_schannel: Option<Riesgo> = None;
        let mut pq_off: Option<u32> = None;

        for v in &vs {
            let k = v.clave.to_ascii_lowercase();
            let n = v.nombre.to_ascii_lowercase();
            let partes: Vec<&str> = k.split('\\').collect();
            let despues = |marca: &str| {
                partes
                    .iter()
                    .position(|p| *p == marca)
                    .map(|i| &partes[i + 1..])
            };

            if let Some(r) = despues("protocols").filter(|_| k.contains("\\schannel\\")) {
                if let (Some(proto), Some(lado)) = (r.first(), r.get(1))
                    && let Some(version) = version_tls(&proto.replace(' ', ""))
                    && matches!(*lado, "server" | "client")
                    && let Dato::Dword(x) = v.dato
                {
                    let e = protocolos
                        .entry(lado.to_string())
                        .or_default()
                        .entry(version)
                        .or_default();
                    match n.as_str() {
                        "enabled" => e.0 = Some(x),
                        "disabledbydefault" => e.1 = Some(x),
                        _ => {}
                    }
                }
            } else if let Some(r) = despues("ciphers").filter(|_| k.contains("\\schannel\\")) {
                if n == "enabled"
                    && let (Some(cifrador), Dato::Dword(x)) = (r.first(), &v.dato)
                    && *x != 0
                {
                    let id = match cifrador {
                        c if c.starts_with("rc4") => Some("rc4"),
                        c if c.starts_with("rc2") => Some("rc2"),
                        c if c.starts_with("triple des") => Some("3des-cbc"),
                        c if c.starts_with("des ") => Some("des"),
                        c if c.starts_with("aes 128") => Some("aes-128-cbc"),
                        c if c.starts_with("aes 256") => Some("aes-256-cbc"),
                        c if c.starts_with("null") => {
                            avisos_schannel.push(
                                "El cifrador NULL está habilitado: permite conexiones sin cifrar."
                                    .into(),
                            );
                            riesgo_schannel = Some(Riesgo::RotoClasico);
                            None
                        }
                        _ => None,
                    };
                    if let Some(id) = id {
                        agregar(
                            alg(
                                id,
                                None,
                                "servidores-web",
                                Garantia::Confidencialidad,
                                v.linea,
                            ),
                            &mut algoritmos,
                        );
                    }
                }
            } else if let Some(r) = despues("hashes").filter(|_| k.contains("\\schannel\\")) {
                if n == "enabled"
                    && let (Some(h), Dato::Dword(x)) = (r.first(), &v.dato)
                    && *x != 0
                {
                    let id = match *h {
                        "md5" => Some("md5"),
                        "sha" => Some("sha1"),
                        "sha256" => Some("sha256"),
                        "sha384" => Some("sha384"),
                        "sha512" => Some("sha512"),
                        _ => None,
                    };
                    if let Some(id) = id {
                        agregar(
                            alg(id, None, "servidores-web", Garantia::Integridad, v.linea),
                            &mut algoritmos,
                        );
                    }
                }
            } else if let Some(r) =
                despues("keyexchangealgorithms").filter(|_| k.contains("\\schannel\\"))
            {
                match (r.first().copied(), n.as_str(), &v.dato) {
                    (Some("diffie-hellman"), "serverminkeybitlength" | "clientminkeybitlength", Dato::Dword(bits)) => {
                        let id = if *bits < 2048 { "ffdh-1024" } else { "ffdh" };
                        let mut x = alg(id, Some(*bits), "servidores-web", Garantia::Confidencialidad, v.linea);
                        x.advertir(format!("Tamaño mínimo de Diffie-Hellman en SChannel: {bits} bits."));
                        agregar(x, &mut algoritmos);
                    }
                    (Some("pkcs"), "enabled", Dato::Dword(x)) if *x != 0 => avisos_schannel.push(
                        "El intercambio de llaves RSA estático (PKCS) está habilitado: sin secreto perfecto hacia adelante.".into(),
                    ),
                    _ => {}
                }
            } else if k.ends_with("\\cryptography\\configuration\\ssl\\00010002") {
                match (n.as_str(), &v.dato) {
                    ("functions", Dato::Texto(t)) => {
                        suites = t
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                    }
                    ("ecccurves", Dato::Multi(m)) => curvas = m.clone(),
                    _ => {}
                }
            } else if k.ends_with("\\kerberos\\parameters") && n == "supportedencryptiontypes" {
                if let Dato::Dword(bits) = v.dato {
                    let mut p = Activo::nuevo(
                        format!(
                            "protocolo:kerberos:{}",
                            id_corto(&format!("{}#{}", a.ruta_estable, v.clave))
                        ),
                        "Kerberos de Windows (SupportedEncryptionTypes)",
                        Detalles::Protocolo {
                            tipo_protocolo: "kerberos".into(),
                            versiones: Vec::new(),
                            grupos: Vec::new(),
                            cifrados: Vec::new(),
                        },
                    )
                    .con_contexto("sin-clasificar", Garantia::Confidencialidad)
                    .con_ubicacion(a.ruta, Some(v.linea));
                    let mut tipos = Vec::new();
                    for (bit, nombre) in [
                        (0x1, "des-cbc-crc"),
                        (0x2, "des-cbc-md5"),
                        (0x4, "rc4-hmac"),
                        (0x8, "aes128-cts-hmac-sha1-96"),
                        (0x10, "aes256-cts-hmac-sha1-96"),
                    ] {
                        if bits & bit != 0 {
                            tipos.push(nombre.to_string());
                            let x = por_alias(
                                c,
                                "kerberos",
                                nombre,
                                "sin-clasificar",
                                Some(Garantia::Confidencialidad),
                                a.ruta,
                                Some(v.linea),
                            );
                            p.relacionar("algorithm", &x.referencia);
                            agregar(x, &mut algoritmos);
                        }
                    }
                    if bits & 0x7 != 0 {
                        p.advertir("Admite RC4 o DES en Kerberos: los tickets pueden descifrarse fuera de línea (por ejemplo, con Kerberoasting).");
                        p.riesgo_fijado = Some(Riesgo::RotoClasico);
                    }
                    if let Detalles::Protocolo { cifrados, .. } = &mut p.detalles {
                        *cifrados = tipos;
                    }
                    activos.push(p);
                }
            } else if k.ends_with("\\policies\\microsoft\\fve") && n.starts_with("encryptionmethod")
            {
                if let Dato::Dword(m) = v.dato {
                    let id = match m {
                        1 | 3 => Some("aes-128-cbc"),
                        2 | 4 => Some("aes-256-cbc"),
                        6 => Some("aes-128-xts"),
                        7 => Some("aes-256-xts"),
                        _ => None,
                    };
                    if let Some(id) = id {
                        let mut x = alg(
                            id,
                            None,
                            "cifrado-volumen",
                            Garantia::Confidencialidad,
                            v.linea,
                        );
                        x.advertir(format!(
                            "Método de cifrado de BitLocker exigido por política ({}).",
                            v.nombre
                        ));
                        agregar(x, &mut algoritmos);
                    }
                }
            } else if (k.contains("\\.netframework\\v4.0.30319")
                || k.contains("\\.netframework\\v2.0.50727"))
                && matches!(
                    n.as_str(),
                    "schusestrongcrypto" | "systemdefaulttlsversions"
                )
                && v.dato == Dato::Dword(0)
            {
                let mut p = Activo::nuevo(
                    format!(
                        "protocolo:tls:{}",
                        id_corto(&format!("{}#{}#{}", a.ruta_estable, v.clave, n))
                    ),
                    format!("TLS de .NET Framework ({})", v.nombre),
                    Detalles::Protocolo {
                        tipo_protocolo: "tls".into(),
                        versiones: Vec::new(),
                        grupos: Vec::new(),
                        cifrados: Vec::new(),
                    },
                )
                .con_contexto("codigo-aplicacion", Garantia::Confidencialidad)
                .con_ubicacion(a.ruta, Some(v.linea));
                p.advertir(format!(
                    "{} = 0: las aplicaciones de .NET Framework pueden usar SSL 3.0 o TLS 1.0 en lugar de los protocolos del sistema.",
                    v.nombre
                ));
                p.riesgo_fijado = Some(Riesgo::Obsoleto);
                activos.push(p);
            } else if k.ends_with("\\control\\lsa") && n == "lmcompatibilitylevel" {
                if let Dato::Dword(nivel) = v.dato
                    && nivel < 3
                {
                    let mut p = Activo::nuevo(
                        format!("protocolo:ntlm:{}", id_corto(&a.ruta_estable)),
                        "NTLM de Windows (LmCompatibilityLevel)",
                        Detalles::Protocolo {
                            tipo_protocolo: "ntlm".into(),
                            versiones: vec![format!("LmCompatibilityLevel {nivel}")],
                            grupos: Vec::new(),
                            cifrados: Vec::new(),
                        },
                    )
                    .con_contexto("sin-clasificar", Garantia::Autenticacion)
                    .con_ubicacion(a.ruta, Some(v.linea));
                    p.advertir("LmCompatibilityLevel menor que 3 permite LM o NTLMv1 (DES y MD4), que se rompen en horas.");
                    p.riesgo_fijado = Some(Riesgo::RotoClasico);
                    let x = alg(
                        "md4",
                        None,
                        "sin-clasificar",
                        Garantia::Autenticacion,
                        v.linea,
                    );
                    p.relacionar("algorithm", &x.referencia);
                    agregar(x, &mut algoritmos);
                    activos.push(p);
                }
            } else if let Some(r) = despues("systemcertificates") {
                if n == "blob"
                    && let (Some(almacen), Dato::Binario(b)) = (r.first(), &v.dato)
                    && *almacen != "disallowed"
                    && let Some(der) = certificado_de_blob(b)
                {
                    let capacidad = match *almacen {
                        "root" | "authroot" | "trustedpeople" => "almacen-confianza",
                        "ca" => "pki-ca",
                        "trustedpublisher" => "firma-codigo",
                        _ => "servidores-web",
                    };
                    match certificado_en_contexto(der, a.ruta, capacidad, c) {
                        Ok(xs) => {
                            for x in xs {
                                agregar(x, &mut algoritmos);
                            }
                        }
                        Err(e) => {
                            return Err(format!("certificado del almacén {almacen}: {e}"));
                        }
                    }
                }
            } else if (k.ends_with("\\policies\\google\\chrome")
                || k.ends_with("\\policies\\microsoft\\edge")
                || k.ends_with("\\policies\\mozilla\\firefox"))
                && n == "postquantumkeyagreementenabled"
                && v.dato == Dato::Dword(0)
            {
                pq_off = Some(v.linea);
            }
        }

        // SChannel: un activo por lado con las versiones declaradas.
        let hay_suites = !suites.is_empty() || !curvas.is_empty();
        let lados: Vec<String> = if protocolos.is_empty() && hay_suites {
            vec!["general".into()]
        } else {
            protocolos.keys().cloned().collect()
        };
        for lado in lados {
            let estados = protocolos.get(&lado).cloned().unwrap_or_default();
            let mut versiones: Vec<String> = Vec::new();
            let mut deshabilitadas: Vec<&str> = Vec::new();
            for (ver, (habilitado, por_omision)) in &estados {
                let activo = match (habilitado, por_omision) {
                    (Some(0), _) => false,
                    (_, Some(1)) => false,
                    (Some(_), _) | (None, Some(0)) => true,
                    _ => continue,
                };
                if activo {
                    versiones.push(ver.to_string());
                } else {
                    deshabilitadas.push(ver);
                }
            }
            let titulo = match lado.as_str() {
                "server" => "servidor",
                "client" => "cliente",
                _ => "general",
            };
            let mut p = Activo::nuevo(
                format!(
                    "protocolo:tls:{}",
                    id_corto(&format!("{}#schannel#{lado}", a.ruta_estable))
                ),
                format!("SChannel de Windows ({titulo})"),
                Detalles::Protocolo {
                    tipo_protocolo: "tls".into(),
                    versiones: versiones.clone(),
                    grupos: curvas.clone(),
                    cifrados: suites.clone(),
                },
            )
            .con_contexto("servidores-web", Garantia::Confidencialidad)
            .con_ubicacion(a.ruta, None);
            if !deshabilitadas.is_empty() {
                p.advertir(format!(
                    "Versiones deshabilitadas explícitamente: {}.",
                    deshabilitadas.join(", ")
                ));
            }
            if versiones.is_empty() {
                p.advertir("No habilita versiones de forma explícita: las demás dependen de la versión de Windows.");
            }
            let grupos: Vec<String> = curvas
                .iter()
                .map(|cv| match cv.to_ascii_lowercase().as_str() {
                    "curve25519" => "x25519".to_string(),
                    "nistp256" => "secp256r1".to_string(),
                    "nistp384" => "secp384r1".to_string(),
                    "nistp521" => "secp521r1".to_string(),
                    otra => otra.to_string(),
                })
                .collect();
            for g in &grupos {
                let x = por_alias(
                    c,
                    "tls-grupo",
                    g,
                    "servidores-web",
                    Some(Garantia::Confidencialidad),
                    a.ruta,
                    None,
                );
                p.relacionar("algorithm", &x.referencia);
                agregar(x, &mut algoritmos);
            }
            evaluar_tls(
                &mut p,
                &versiones,
                (!grupos.is_empty()).then_some(grupos.as_slice()),
                "No se declara el orden de curvas (EccCurves): SChannel usa sus grupos predeterminados.",
                Riesgo::Desconocido,
                c,
            );
            let (avisos, r) = advertencias_cifrados(&suites.join(","));
            for x in avisos.into_iter().chain(avisos_schannel.iter().cloned()) {
                p.advertir(x);
            }
            for r in r.into_iter().chain(riesgo_schannel) {
                if p.riesgo_fijado.is_none_or(|x| r.gravedad() < x.gravedad()) {
                    p.riesgo_fijado = Some(r);
                }
            }
            for x in algoritmos.values().filter(|x| {
                x.contextos
                    .iter()
                    .any(|ctx| ctx.capacidad == "servidores-web")
                    && matches!(x.detalles, Detalles::Algoritmo { .. })
            }) {
                p.relacionar("algorithm", &x.referencia);
            }
            activos.push(p);
        }

        if let Some(linea) = pq_off {
            let mut p = Activo::nuevo(
                format!(
                    "protocolo:tls:{}",
                    id_corto(&format!("{}#pq", a.ruta_estable))
                ),
                "Política de navegador: acuerdo de llaves poscuántico desactivado",
                Detalles::Protocolo {
                    tipo_protocolo: "tls".into(),
                    versiones: Vec::new(),
                    grupos: Vec::new(),
                    cifrados: Vec::new(),
                },
            )
            .con_contexto("navegadores-web", Garantia::Confidencialidad)
            .con_ubicacion(a.ruta, Some(linea));
            p.advertir("PostQuantumKeyAgreementEnabled = 0 impide que el navegador negocie X25519MLKEM768 en las versiones que respetan la política.");
            p.riesgo_fijado = Some(Riesgo::VulnerableCuantico);
            activos.push(p);
        }

        let mut v: Vec<Activo> = algoritmos.into_values().collect();
        v.extend(activos);
        Ok(v)
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn utf16(t: &str) -> Vec<u8> {
        let mut b = vec![0xFF, 0xFE];
        for u in t.encode_utf16() {
            b.extend_from_slice(&u.to_le_bytes());
        }
        b
    }

    #[test]
    fn schannel_kerberos_bitlocker_y_navegador() {
        let c = Conocimiento::embebido();
        let t = "Windows Registry Editor Version 5.00\r\n\r\n\
[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server]\r\n\
\"Enabled\"=dword:00000001\r\n\
\"DisabledByDefault\"=dword:00000000\r\n\r\n\
[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\Server]\r\n\
\"Enabled\"=dword:ffffffff\r\n\r\n\
[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 3.0\\Server]\r\n\
\"Enabled\"=dword:00000000\r\n\r\n\
[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\RC4 128/128]\r\n\
\"Enabled\"=dword:ffffffff\r\n\r\n\
[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002]\r\n\
\"Functions\"=\"TLS_AES_256_GCM_SHA384,TLS_RSA_WITH_3DES_EDE_CBC_SHA\"\r\n\
\"EccCurves\"=hex(7):63,00,75,00,72,00,76,00,65,00,32,00,35,00,35,00,31,00,39,00,00,00,\\\r\n\
  4e,00,69,00,73,00,74,00,50,00,32,00,35,00,36,00,00,00,00,00\r\n\r\n\
[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters]\r\n\
\"SupportedEncryptionTypes\"=dword:0000001c\r\n\r\n\
[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE]\r\n\
\"EncryptionMethodWithXtsOs\"=dword:00000006\r\n\r\n\
[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa]\r\n\
\"LmCompatibilityLevel\"=dword:00000001\r\n\r\n\
[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Google\\Chrome]\r\n\
\"PostQuantumKeyAgreementEnabled\"=dword:00000000\r\n";
        let b = utf16(t);
        let a = Archivo::nuevo(
            "schannel.reg",
            std::path::Path::new("schannel.reg"),
            &b,
            None,
        );
        assert!(EscanerRegistroWindows.aplica(&a));
        let v = EscanerRegistroWindows.analizar(&a, &c).unwrap();
        let servidor = v
            .iter()
            .find(|x| x.nombre == "SChannel de Windows (servidor)")
            .unwrap();
        assert_eq!(servidor.riesgo_fijado, Some(Riesgo::RotoClasico));
        if let Detalles::Protocolo {
            versiones, grupos, ..
        } = &servidor.detalles
        {
            assert_eq!(versiones, &["TLSv1", "TLSv1.2"]);
            assert_eq!(grupos, &["curve25519", "NistP256"]);
        }
        assert!(servidor.advertencias.iter().any(|w| w.contains("SSLv3")));
        assert!(v.iter().any(|x| x.algoritmo_id() == Some("rc4")));
        assert!(v.iter().any(|x| x.algoritmo_id() == Some("aes-128-xts")));
        let k = v
            .iter()
            .find(|x| x.referencia.starts_with("protocolo:kerberos"))
            .unwrap();
        assert_eq!(k.riesgo_fijado, Some(Riesgo::RotoClasico));
        assert!(v.iter().any(|x| x.nombre.starts_with("NTLM")));
        assert!(
            v.iter()
                .any(|x| x.nombre.starts_with("Política de navegador"))
        );
    }

    #[test]
    fn blob_de_certificado() {
        let der = [0x30u8, 0x03, 0x02, 0x01, 0x00];
        let mut b = Vec::new();
        for (id, datos) in [(3u32, &[1u8, 2, 3][..]), (32, &der[..])] {
            b.extend_from_slice(&id.to_le_bytes());
            b.extend_from_slice(&1u32.to_le_bytes());
            b.extend_from_slice(&(datos.len() as u32).to_le_bytes());
            b.extend_from_slice(datos);
        }
        assert_eq!(certificado_de_blob(&b), Some(&der[..]));
        assert_eq!(certificado_de_blob(&b[..10]), None);
    }
}
