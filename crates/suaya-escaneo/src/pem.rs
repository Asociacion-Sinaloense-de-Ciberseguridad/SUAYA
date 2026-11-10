//! Escáner de certificados X.509 y llaves en PEM o DER.
//!
//! Reconoce: CERTIFICATE, PUBLIC KEY, PRIVATE KEY (PKCS#8),
//! ENCRYPTED PRIVATE KEY, RSA PRIVATE/PUBLIC KEY (PKCS#1),
//! EC PRIVATE KEY (SEC1), DSA PRIVATE KEY y OPENSSH PRIVATE KEY.

use base64::Engine;
use suaya_core::{Activo, Conocimiento, Detalles, Garantia};
use x509_parser::der_parser::ber::{BerObject, BerObjectContent};
use x509_parser::der_parser::der::parse_der;
use x509_parser::prelude::*;

use crate::comun::{Archivo, activo_algoritmo, bits_de_entero, huella_sha256, id_corto};
use crate::identidad;
use crate::llaves_ssh;
use crate::{Escaner, garantia_de};

const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const EXT_DER: &[&str] = &["der", "cer", "crt", "cert"];
/// Fragmentos de ruta típicos de almacenes de confianza del sistema.
const RUTAS_ALMACEN: &[&str] = &[
    "ca-certificates",
    "ca-bundle",
    "ca-trust",
    "/etc/ssl/certs/",
    "cacert",
    "trust-source",
];
/// A partir de cuántos certificados se considera que un archivo es un almacén.
const MINIMO_ALMACEN: usize = 10;

fn ruta_de_almacen(ruta: &str) -> bool {
    let r = ruta.to_lowercase();
    RUTAS_ALMACEN.iter().any(|f| r.contains(f))
}

pub struct EscanerPem;

impl Escaner for EscanerPem {
    fn nombre(&self) -> &'static str {
        "certificados y llaves"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        a.contiene(b"-----BEGIN ")
            || (EXT_DER.contains(&a.extension.as_str()) && a.contenido.first() == Some(&0x30))
    }

    fn analizar(&self, a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
        if !a.contiene(b"-----BEGIN ") {
            // DER binario: intentar certificado y luego llave pública.
            return match analizar_certificado(a.contenido, a, None, c, ruta_de_almacen(a.ruta)) {
                Ok(v) => Ok(v),
                Err(_) => analizar_llave_publica(a.contenido, a, None, c)
                    .map_err(|e| format!("archivo DER no reconocido: {e}")),
            };
        }

        let texto = String::from_utf8_lossy(a.contenido);
        let (activos, errores) = analizar_texto_pem(&texto, a, None, c);
        if activos.is_empty() && !errores.is_empty() {
            return Err(errores.join("; "));
        }
        Ok(activos)
    }
}

/// Analiza todos los bloques PEM de un texto. Si se indica `linea_fija`, todos
/// los hallazgos se ubican en esa línea (útil para PEM incrustado en base64).
pub fn analizar_texto_pem(
    texto: &str,
    a: &Archivo,
    linea_fija: Option<u32>,
    c: &Conocimiento,
) -> (Vec<Activo>, Vec<String>) {
    let mut activos = Vec::new();
    let mut errores = Vec::new();
    let bloques = bloques_pem(texto);
    let certificados = bloques
        .iter()
        .filter(|b| b.etiqueta.ends_with("CERTIFICATE"))
        .count();
    let almacen = certificados >= MINIMO_ALMACEN || ruta_de_almacen(a.ruta);
    for mut bloque in bloques {
        if let Some(l) = linea_fija {
            bloque.linea = l;
        }
        let linea = Some(bloque.linea);
        let r = match bloque.etiqueta.as_str() {
            "CERTIFICATE" | "X509 CERTIFICATE" | "TRUSTED CERTIFICATE" => {
                analizar_certificado(&bloque.der, a, linea, c, almacen)
            }
            "PUBLIC KEY" => analizar_llave_publica(&bloque.der, a, linea, c),
            "PRIVATE KEY" => analizar_pkcs8(&bloque.der, a, linea, c),
            "ENCRYPTED PRIVATE KEY" => analizar_pkcs8_cifrada(&bloque.der, a, linea, c),
            "RSA PRIVATE KEY" | "RSA PUBLIC KEY" | "EC PRIVATE KEY" | "DSA PRIVATE KEY" => {
                analizar_heredada(&bloque, a, c)
            }
            "OPENSSH PRIVATE KEY" => {
                llaves_ssh::analizar_privada_openssh(&bloque.texto, a, linea, c)
            }
            _ => continue,
        };
        match r {
            Ok(mut v) => activos.append(&mut v),
            Err(e) => errores.push(format!(
                "bloque {} (línea {}): {e}",
                bloque.etiqueta, bloque.linea
            )),
        }
    }
    (activos, errores)
}

// ---------------------------------------------------------------------------
// Bloques PEM
// ---------------------------------------------------------------------------

pub(crate) struct BloquePem {
    pub etiqueta: String,
    pub linea: u32,
    pub encabezados: Vec<String>,
    pub der: Vec<u8>,
    /// Texto completo del bloque, armadura incluida.
    pub texto: String,
}

pub(crate) fn bloques_pem(texto: &str) -> Vec<BloquePem> {
    let mut bloques = Vec::new();
    let mut actual: Option<(String, u32, Vec<String>, String, String)> = None;

    for (i, linea) in texto.lines().enumerate() {
        let l = linea.trim();
        if let Some((etiqueta, inicio, encabezados, base64, completo)) = actual.as_mut() {
            completo.push_str(l);
            completo.push('\n');
            if l.starts_with("-----END ") {
                let der = base64::engine::general_purpose::STANDARD
                    .decode(base64.as_bytes())
                    .unwrap_or_default();
                bloques.push(BloquePem {
                    etiqueta: etiqueta.clone(),
                    linea: *inicio,
                    encabezados: encabezados.clone(),
                    der,
                    texto: completo.clone(),
                });
                actual = None;
            } else if l.contains(':') {
                encabezados.push(l.to_string());
            } else {
                base64.push_str(l);
            }
        } else if let Some(resto) = l.strip_prefix("-----BEGIN ") {
            let etiqueta = resto.trim_end_matches('-').trim().to_string();
            actual = Some((
                etiqueta,
                i as u32 + 1,
                Vec::new(),
                String::new(),
                format!("{l}\n"),
            ));
        }
    }
    bloques
}

// ---------------------------------------------------------------------------
// Certificados
// ---------------------------------------------------------------------------

fn capacidad_del_certificado(cert: &X509Certificate) -> &'static str {
    if cert.is_ca() {
        return "pki-ca";
    }
    if let Ok(Some(eku)) = cert.extended_key_usage() {
        if eku.value.code_signing {
            return "firma-codigo";
        }
        if eku.value.server_auth {
            return "servidores-web";
        }
    }
    "sin-clasificar"
}

/// Analiza un certificado DER hallado dentro de otro archivo (un almacén de
/// llaves), con la capacidad que se deduce de sus usos.
pub(crate) fn certificado_en_archivo(
    der: &[u8],
    a: &Archivo,
    c: &Conocimiento,
    almacen: bool,
) -> Result<Vec<Activo>, String> {
    analizar_certificado(der, a, None, c, almacen)
}

fn analizar_certificado(
    der: &[u8],
    a: &Archivo,
    linea: Option<u32>,
    c: &Conocimiento,
    almacen: bool,
) -> Result<Vec<Activo>, String> {
    let (_, cert) =
        X509Certificate::from_der(der).map_err(|e| format!("certificado inválido: {e}"))?;
    // Solo las autoridades certificadoras forman parte de un almacén de
    // confianza; un certificado de servidor guardado ahí conserva su uso.
    let almacen = almacen && cert.is_ca();
    let capacidad = if almacen {
        "almacen-confianza"
    } else {
        capacidad_del_certificado(&cert)
    };
    // En una raíz autofirmada, la firma propia no aporta seguridad: la
    // confianza viene de su inclusión en el almacén. Solo importa su llave.
    let raiz = cert.is_ca() && cert.subject().as_raw() == cert.issuer().as_raw();

    // Algoritmo de firma.
    let oid_firma = cert.signature_algorithm.algorithm.to_id_string();
    let def_firma = c.por_oid(&oid_firma);
    let firma = activo_algoritmo(
        def_firma,
        &format!("OID {oid_firma}"),
        None,
        capacidad,
        Some(Garantia::Autenticacion),
        a.ruta,
        linea,
    );

    // Llave pública.
    let spki = cert.public_key();
    let (def_llave, respaldo) = def_de_spki(spki, c);
    let tamano = spki
        .parsed()
        .ok()
        .map(|p| p.key_size() as u32)
        .filter(|&t| t > 0);
    let llave = activo_algoritmo(
        def_llave,
        &respaldo,
        tamano,
        capacidad,
        Some(Garantia::Autenticacion),
        a.ruta,
        linea,
    );

    // Datos del certificado.
    let huella = huella_sha256(cert.tbs_certificate.as_ref());
    let sujeto = cert.subject().to_string();
    let nombre = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            if sujeto.is_empty() {
                "certificado sin sujeto".into()
            } else {
                sujeto.clone()
            }
        });
    let no_antes = fecha(cert.validity().not_before.to_datetime());
    let no_despues_dt = cert.validity().not_after.to_datetime();
    let vencido = no_despues_dt < ::time::OffsetDateTime::now_utc();

    let mut activo = Activo::nuevo(
        format!("certificado:{}", &huella[..16]),
        nombre,
        Detalles::Certificado {
            sujeto,
            emisor: cert.issuer().to_string(),
            serie: cert.raw_serial_as_string(),
            no_antes,
            no_despues: fecha(no_despues_dt),
            huella_sha256: huella,
            identidad_llave: identidad::desde_spki(spki),
            extension_archivo: if a.extension.is_empty() {
                None
            } else {
                Some(a.extension.clone())
            },
            vencido,
        },
    )
    .con_contexto(capacidad, Garantia::Autenticacion)
    .con_ubicacion(a.ruta, linea);
    activo.relacionar("publicKeyAlgorithm", &llave.referencia);
    if raiz {
        activo.advertir(format!(
            "Raíz autofirmada con {}: la firma propia de un ancla de confianza no afecta la seguridad; lo relevante es su llave pública.",
            firma.nombre
        ));
    } else {
        activo.relacionar("signatureAlgorithm", &firma.referencia);
    }
    if almacen {
        activo.advertir("Forma parte de un almacén de confianza: su reemplazo depende de las autoridades certificadoras y del proveedor del sistema operativo.");
    }

    if vencido {
        activo.advertir(format!("Certificado vencido el {}.", fecha(no_despues_dt)));
    }
    if let Some(p) = &c.politica {
        let considerados = if raiz {
            [None, def_llave]
        } else {
            [def_firma, def_llave]
        };
        let vulnerable = considerados.iter().flatten().any(|d| {
            matches!(
                d.riesgo,
                suaya_core::Riesgo::VulnerableCuantico | suaya_core::Riesgo::RotoClasico
            )
        });
        if vulnerable && no_despues_dt.year() > p.anio_retiro_vulnerables {
            activo.advertir(format!(
                "Vigente hasta {} con un algoritmo vulnerable; NIST prevé retirar RSA y ECC de 112 bits después de {} y prohibirlos después de {} ({}).",
                no_despues_dt.year(),
                p.anio_retiro_vulnerables,
                p.anio_prohibicion_vulnerables,
                p.referencia
            ));
        }
    }

    if raiz {
        Ok(vec![llave, activo])
    } else {
        Ok(vec![firma, llave, activo])
    }
}

fn fecha(dt: ::time::OffsetDateTime) -> String {
    dt.format(&::time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// Datos de un certificado para diagnosticar un intercambio de certificados.
#[derive(Debug, Clone, PartialEq)]
pub struct ResumenCertificado {
    pub nombre: String,
    pub sujeto: String,
    pub emisor: String,
    /// Nombres DNS y direcciones IP de la extensión SubjectAltName.
    pub nombres_alternativos: Vec<String>,
    pub no_antes: String,
    pub no_despues: String,
    /// Días completos hasta `no_despues` (negativo si ya venció).
    pub dias_restantes: i64,
    pub es_ca: bool,
    /// Sujeto y emisor idénticos.
    pub autofirmado: bool,
    pub algoritmo_llave: String,
    pub tamano_llave: Option<u32>,
    pub riesgo_llave: suaya_core::Riesgo,
    pub algoritmo_firma: String,
    pub riesgo_firma: suaya_core::Riesgo,
    /// Huella SHA-256 del TBSCertificate, en hexadecimal.
    pub huella_sha256: String,
    pub tamano_der: usize,
    /// Sujeto y emisor en DER, para comprobar el orden de una cadena.
    pub sujeto_der: Vec<u8>,
    pub emisor_der: Vec<u8>,
}

/// Resume un certificado DER con los nombres y riesgos de la base de conocimiento.
pub fn resumen_certificado(der: &[u8], c: &Conocimiento) -> Result<ResumenCertificado, String> {
    let (_, cert) =
        X509Certificate::from_der(der).map_err(|e| format!("certificado inválido: {e}"))?;
    let oid_firma = cert.signature_algorithm.algorithm.to_id_string();
    let def_firma = c.por_oid(&oid_firma);
    let spki = cert.public_key();
    let (def_llave, respaldo) = def_de_spki(spki, c);
    let tamano = spki
        .parsed()
        .ok()
        .map(|p| p.key_size() as u32)
        .filter(|&t| t > 0);
    let mut nombres_alternativos = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for n in &san.value.general_names {
            match n {
                GeneralName::DNSName(d) => nombres_alternativos.push(d.to_string()),
                GeneralName::IPAddress(ip) => match ip.len() {
                    4 => nombres_alternativos
                        .push(std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]).to_string()),
                    16 => {
                        let mut b = [0u8; 16];
                        b.copy_from_slice(ip);
                        nombres_alternativos.push(std::net::Ipv6Addr::from(b).to_string());
                    }
                    _ => {}
                },
                _ => {}
            }
        }
    }
    let sujeto = cert.subject().to_string();
    let no_despues = cert.validity().not_after.to_datetime();
    Ok(ResumenCertificado {
        nombre: cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .map(str::to_string)
            .unwrap_or_else(|| sujeto.clone()),
        sujeto,
        emisor: cert.issuer().to_string(),
        nombres_alternativos,
        no_antes: fecha(cert.validity().not_before.to_datetime()),
        no_despues: fecha(no_despues),
        dias_restantes: (no_despues - ::time::OffsetDateTime::now_utc()).whole_days(),
        es_ca: cert.is_ca(),
        autofirmado: cert.subject().as_raw() == cert.issuer().as_raw(),
        algoritmo_llave: def_llave.map(|d| d.nombre.clone()).unwrap_or(respaldo),
        tamano_llave: tamano,
        riesgo_llave: def_llave
            .map(|d| d.riesgo_para_tamano(tamano))
            .unwrap_or(suaya_core::Riesgo::Desconocido),
        algoritmo_firma: def_firma
            .map(|d| d.nombre.clone())
            .unwrap_or_else(|| format!("OID {oid_firma}")),
        riesgo_firma: def_firma
            .map(|d| d.riesgo)
            .unwrap_or(suaya_core::Riesgo::Desconocido),
        huella_sha256: huella_sha256(cert.tbs_certificate.as_ref()),
        tamano_der: der.len(),
        sujeto_der: cert.subject().as_raw().to_vec(),
        emisor_der: cert.issuer().as_raw().to_vec(),
    })
}

/// Algoritmo (id de la base), nombre y tamaño de una llave
/// pública en SubjectPublicKeyInfo DER (por ejemplo, una llave DKIM).
pub fn llave_de_spki(
    der: &[u8],
    c: &Conocimiento,
) -> Option<(Option<String>, String, Option<u32>)> {
    let (_, spki) = SubjectPublicKeyInfo::from_der(der).ok()?;
    let (def, respaldo) = def_de_spki(&spki, c);
    let tamano = spki
        .parsed()
        .ok()
        .map(|p| p.key_size() as u32)
        .filter(|&t| t > 0);
    let nombre = def.map_or(respaldo, |d| d.nombre.clone());
    Some((def.map(|d| d.id.clone()), nombre, tamano))
}

/// Resuelve la definición del algoritmo de una SubjectPublicKeyInfo.
fn def_de_spki<'c>(
    spki: &SubjectPublicKeyInfo,
    c: &'c Conocimiento,
) -> (Option<&'c suaya_core::AlgoritmoDef>, String) {
    let oid = spki.algorithm.algorithm.to_id_string();
    if oid == OID_EC_PUBLIC_KEY {
        let curva = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.as_oid().ok())
            .map(|o| o.to_id_string());
        match curva {
            Some(cv) => (c.por_oid(&cv), format!("EC curva {cv}")),
            None => (None, "EC curva no declarada".into()),
        }
    } else {
        (c.por_oid(&oid), format!("OID {oid}"))
    }
}

// ---------------------------------------------------------------------------
// Llaves
// ---------------------------------------------------------------------------

fn analizar_llave_publica(
    der: &[u8],
    a: &Archivo,
    linea: Option<u32>,
    c: &Conocimiento,
) -> Result<Vec<Activo>, String> {
    let (_, spki) =
        SubjectPublicKeyInfo::from_der(der).map_err(|e| format!("llave pública inválida: {e}"))?;
    let (def, respaldo) = def_de_spki(&spki, c);
    let tamano = spki
        .parsed()
        .ok()
        .map(|p| p.key_size() as u32)
        .filter(|&t| t > 0);
    Ok(material(
        a,
        linea,
        c,
        def,
        &respaldo,
        tamano,
        "public-key",
        "PEM/DER (SubjectPublicKeyInfo)",
        None,
        Some(huella_sha256(der)),
        identidad::desde_spki(&spki),
    ))
}

fn analizar_pkcs8(
    der: &[u8],
    a: &Archivo,
    linea: Option<u32>,
    c: &Conocimiento,
) -> Result<Vec<Activo>, String> {
    let (_, raiz) = parse_der(der).map_err(|e| format!("PKCS#8 inválido: {e}"))?;
    let seq = raiz.as_sequence().map_err(|_| "PKCS#8 sin secuencia")?;
    let alg = seq
        .get(1)
        .and_then(|o| o.as_sequence().ok())
        .ok_or("PKCS#8 sin AlgorithmIdentifier")?;
    let oid = alg
        .first()
        .and_then(|o| o.as_oid().ok())
        .ok_or("PKCS#8 sin OID")?
        .to_id_string();

    let (def, respaldo, tamano) = if oid == OID_EC_PUBLIC_KEY {
        let curva = alg
            .get(1)
            .and_then(|o| o.as_oid().ok())
            .map(|o| o.to_id_string());
        match curva {
            Some(cv) => (c.por_oid(&cv), format!("EC curva {cv}"), None),
            None => (None, "EC curva no declarada".to_string(), None),
        }
    } else {
        let tamano = if c.por_oid(&oid).map(|d| d.id.as_str()) == Some("rsa") {
            seq.get(2)
                .and_then(|o| o.as_slice().ok())
                .and_then(modulo_pkcs1_privada)
        } else {
            None
        };
        (c.por_oid(&oid), format!("OID {oid}"), tamano)
    };

    Ok(material(
        a,
        linea,
        c,
        def,
        &respaldo,
        tamano,
        "private-key",
        "PEM (PKCS#8)",
        None,
        None,
        seq.get(2)
            .and_then(|o| o.as_slice().ok())
            .and_then(|interno| identidad::desde_pkcs8(&oid, interno)),
    ))
}

fn analizar_pkcs8_cifrada(
    der: &[u8],
    a: &Archivo,
    linea: Option<u32>,
    c: &Conocimiento,
) -> Result<Vec<Activo>, String> {
    let (_, raiz) = parse_der(der).map_err(|e| format!("PKCS#8 cifrado inválido: {e}"))?;
    let seq = raiz
        .as_sequence()
        .map_err(|_| "PKCS#8 cifrado sin secuencia")?;
    let proteccion = seq
        .first()
        .map(|alg| describir_proteccion(alg, c))
        .unwrap_or_else(|| "desconocida".into());
    let mut v = material(
        a,
        linea,
        c,
        None,
        "llave privada cifrada",
        None,
        "private-key",
        "PEM (PKCS#8 cifrado)",
        Some(proteccion),
        None,
        None,
    );
    if let Some(m) = v.last_mut() {
        m.riesgo_fijado = Some(suaya_core::Riesgo::Desconocido);
        m.advertir(
            "Llave cifrada: su algoritmo no es visible sin la contraseña. Inventaríe el certificado o la llave pública que la acompaña.",
        );
    }
    Ok(v)
}

/// Describe un AlgorithmIdentifier de cifrado con contraseña (PBES2 y similares).
fn describir_proteccion(alg: &BerObject, c: &Conocimiento) -> String {
    let nombre_oid = |o: &BerObject| -> Option<String> {
        let oid = o.as_oid().ok()?.to_id_string();
        Some(c.por_oid(&oid).map(|d| d.nombre.clone()).unwrap_or(oid))
    };
    let Ok(partes) = alg.as_sequence() else {
        return "desconocida".into();
    };
    let principal = partes
        .first()
        .and_then(nombre_oid)
        .unwrap_or_else(|| "desconocido".into());
    // PBES2: parámetros = SEQUENCE { kdf AlgorithmIdentifier, cifrado AlgorithmIdentifier }
    let detalle: Vec<String> = partes
        .get(1)
        .and_then(|p| p.as_sequence().ok())
        .map(|ps| {
            ps.iter()
                .filter_map(|x| {
                    x.as_sequence()
                        .ok()
                        .and_then(|s| s.first())
                        .and_then(nombre_oid)
                })
                .collect()
        })
        .unwrap_or_default();
    if detalle.is_empty() {
        principal
    } else {
        format!("{principal} ({})", detalle.join(" + "))
    }
}

/// Llaves en formatos heredados de OpenSSL (PKCS#1, SEC1, DSA).
fn analizar_heredada(b: &BloquePem, a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
    let linea = Some(b.linea);
    let cifrado_heredado = b
        .encabezados
        .iter()
        .find(|h| h.starts_with("DEK-Info:"))
        .map(|h| {
            format!(
                "cifrado heredado de OpenSSL ({})",
                h.trim_start_matches("DEK-Info:").trim()
            )
        });
    let es_publica = b.etiqueta.contains("PUBLIC");
    let tipo = if es_publica {
        "public-key"
    } else {
        "private-key"
    };

    let (def, respaldo, tamano, formato) = match b.etiqueta.as_str() {
        "RSA PRIVATE KEY" | "RSA PUBLIC KEY" => {
            let tamano = if cifrado_heredado.is_some() {
                None
            } else if es_publica {
                parse_der(&b.der).ok().and_then(|(_, o)| {
                    o.as_sequence().ok().and_then(|s| {
                        s.first()
                            .and_then(|m| m.as_slice().ok())
                            .map(bits_de_entero)
                    })
                })
            } else {
                modulo_pkcs1_privada(&b.der)
            };
            (c.por_id("rsa"), "RSA".to_string(), tamano, "PEM (PKCS#1)")
        }
        "EC PRIVATE KEY" => {
            let curva = if cifrado_heredado.is_some() {
                None
            } else {
                curva_sec1(&b.der)
            };
            match curva {
                Some(cv) => (c.por_oid(&cv), format!("EC curva {cv}"), None, "PEM (SEC1)"),
                None => (
                    None,
                    "EC (curva no visible)".to_string(),
                    None,
                    "PEM (SEC1)",
                ),
            }
        }
        _ => (
            c.por_id("dsa"),
            "DSA".to_string(),
            None,
            "PEM (DSA heredado)",
        ),
    };

    let identidad_llave = if cifrado_heredado.is_some() {
        None
    } else {
        match b.etiqueta.as_str() {
            "RSA PRIVATE KEY" => identidad::desde_pkcs1_privada(&b.der),
            "RSA PUBLIC KEY" => identidad::desde_pkcs1_publica(&b.der),
            "EC PRIVATE KEY" => identidad::desde_sec1(&b.der),
            _ => None,
        }
    };
    let mut v = material(
        a,
        linea,
        c,
        def,
        &respaldo,
        tamano,
        tipo,
        formato,
        cifrado_heredado.clone(),
        None,
        identidad_llave,
    );
    if cifrado_heredado.is_some()
        && let Some(m) = v.last_mut()
    {
        m.advertir("Formato de cifrado heredado de OpenSSL; preferir PKCS#8 con PBES2 o scrypt.");
    }
    Ok(v)
}

/// Bits del módulo en una RSAPrivateKey PKCS#1 (versión, módulo, ...).
fn modulo_pkcs1_privada(der: &[u8]) -> Option<u32> {
    let (_, o) = parse_der(der).ok()?;
    let seq = o.as_sequence().ok()?;
    let modulo = seq.get(1)?.as_slice().ok()?;
    Some(bits_de_entero(modulo))
}

/// OID de la curva en una ECPrivateKey SEC1: parameters [0] EXPLICIT OID.
fn curva_sec1(der: &[u8]) -> Option<String> {
    let (_, o) = parse_der(der).ok()?;
    for elemento in o.as_sequence().ok()? {
        if elemento.header.tag().0 != 0 || !elemento.header.is_contextspecific() {
            continue;
        }
        let interno = match &elemento.content {
            BerObjectContent::Tagged(_, _, inner) => inner.as_oid().ok().map(|x| x.to_id_string()),
            BerObjectContent::Unknown(any) => parse_der(any.data)
                .ok()
                .and_then(|(_, x)| x.as_oid().ok().map(|y| y.to_id_string())),
            _ => None,
        };
        if interno.is_some() {
            return interno;
        }
    }
    None
}

/// Construye el activo del algoritmo y el activo de material de la llave.
#[allow(clippy::too_many_arguments)]
pub(crate) fn material(
    a: &Archivo,
    linea: Option<u32>,
    _c: &Conocimiento,
    def: Option<&suaya_core::AlgoritmoDef>,
    respaldo: &str,
    tamano: Option<u32>,
    tipo: &str,
    formato: &str,
    protegido_por: Option<String>,
    huella_publica: Option<String>,
    identidad_llave: Option<String>,
) -> Vec<Activo> {
    let garantia = garantia_de(def);
    let es_privada = tipo == "private-key";
    let alg = if def.is_some() || !respaldo.starts_with("llave privada cifrada") {
        Some(activo_algoritmo(
            def,
            respaldo,
            tamano,
            "sin-clasificar",
            Some(garantia),
            a.ruta,
            linea,
        ))
    } else {
        None
    };

    // Las llaves públicas se identifican por su identidad, para fusionar la
    // misma llave hallada en formatos distintos; las privadas, por ubicación,
    // porque cada copia es un hallazgo en sí misma.
    let referencia = match (&identidad_llave, &huella_publica) {
        (Some(id), _) if !es_privada => format!("llave:{}", &id[..16]),
        (None, Some(h)) if !es_privada => format!("llave:{}", &h[..16]),
        _ => format!(
            "llave:{}",
            id_corto(&format!("{}#{}", a.ruta_estable, linea.unwrap_or(0)))
        ),
    };
    let descripcion_alg = alg
        .as_ref()
        .map(|x| x.nombre.clone())
        .unwrap_or_else(|| "cifrada (algoritmo no visible)".into());
    let nombre = if es_privada {
        format!("Llave privada {descripcion_alg}")
    } else {
        format!("Llave pública {descripcion_alg}")
    };

    let mut m = Activo::nuevo(
        referencia,
        nombre,
        Detalles::Material {
            tipo_material: tipo.to_string(),
            tamano,
            formato: formato.to_string(),
            protegido_por: protegido_por.clone(),
            huella_sha256: huella_publica,
            identidad_llave,
        },
    )
    .con_contexto("sin-clasificar", garantia)
    .con_ubicacion(a.ruta, linea);
    if let Some(x) = &alg {
        m.relacionar("algorithm", &x.referencia);
    }

    if es_privada && let Some(origen) = a.origen_incrustado() {
        m.advertir(format!(
                "Llave privada incrustada en {origen}: quien tenga acceso a este archivo, o a su historial en control de versiones, tiene la llave. Use un gestor de secretos (por ejemplo, Sealed Secrets, External Secrets o SOPS)."
            ));
    }
    if es_privada
        && protegido_por.is_none()
        && let Some(modo) = a.modo
        && modo & 0o077 != 0
    {
        m.advertir(format!(
                    "Llave privada sin cifrar con permisos de lectura para grupo u otros ({:o}). Restringir a 600.",
                    modo & 0o777
                ));
    }

    let mut v = Vec::new();
    if let Some(x) = alg {
        v.push(x);
    }
    v.push(m);
    v
}

/// Analiza un certificado DER obtenido fuera del sistema de archivos (por
/// ejemplo, durante un sondeo TLS) y lo asigna a la capacidad indicada.
pub fn certificado_en_contexto(
    der: &[u8],
    ubicacion: &str,
    capacidad: &str,
    c: &Conocimiento,
) -> Result<Vec<Activo>, String> {
    let a = Archivo::nuevo(ubicacion, std::path::Path::new(ubicacion), der, None);
    let mut activos = analizar_certificado(der, &a, None, c, false)?;
    for x in &mut activos {
        x.contextos.clear();
        x.agregar_contexto(capacidad, Garantia::Autenticacion);
    }
    Ok(activos)
}
