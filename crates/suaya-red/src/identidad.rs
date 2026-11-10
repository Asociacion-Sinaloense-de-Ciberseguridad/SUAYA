//! Sondeo de proveedores de identidad federada.
//!
//! - **OpenID Connect** (`oidc://login.ejemplo.mx/realms/clientes`): lee el
//!   documento de descubrimiento (`/.well-known/openid-configuration`), los
//!   algoritmos que anuncia para firmar y cifrar tokens y el conjunto de
//!   llaves públicas (JWKS) de `jwks_uri`. Si la ruta ya es un JWKS
//!   (`oidc://www.googleapis.com/oauth2/v3/certs`), lo lee directamente.
//! - **SAML** (`saml://idp.ejemplo.mx/ruta/metadata.xml`): lee los metadatos
//!   y extrae certificados (`X509Certificate`) y algoritmos de firma,
//!   digestión y cifrado.
//!
//! Solo se sigue `jwks_uri` si usa HTTPS y su servidor es el del objetivo o
//! comparte su dominio (dos últimas etiquetas); si no, se indica el objetivo
//! explícito que habría que sondear. Todo se lee por HTTPS con verificación
//! estricta del certificado.

use base64::Engine;
use serde_json::Value;
use suaya_core::{Activo, Conocimiento, Detalles, Garantia, Riesgo};
use suaya_escaneo::api::{
    activo_algoritmo, activos_de_jwks, certificado_en_contexto, id_corto, por_alias,
};

use crate::http::{self, ConfianzaTls, Credenciales, Servidor};
use crate::{Objetivo, Opciones, Protocolo};

/// Capacidad de los hallazgos de identidad (decisión de Suaya, ver `madurez.toml`).
pub(crate) const CAPACIDAD: &str = "identidad-federada";

/// Tope de un documento (los metadatos de una federación pueden ser grandes).
const MAXIMO_DOCUMENTO: usize = 64 * 1024 * 1024;

const DESCUBRIMIENTO: &str = "/.well-known/openid-configuration";

/// Algoritmos anunciados para un uso («id_token (firma)»: RS256, ES256).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Anuncio {
    pub uso: String,
    pub confidencialidad: bool,
    pub algoritmos: Vec<String>,
}

/// Llave de un JWKS, resumida.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LlaveJwk {
    pub kid: Option<String>,
    pub kty: String,
    pub alg: Option<String>,
    /// Curva (EC, OKP) o bits (RSA).
    pub parametro: Option<String>,
    pub bits: Option<u32>,
}

/// Certificado de metadatos SAML con su uso (`signing`, `encryption`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CertificadoSaml {
    pub uso: Option<String>,
    pub der: Vec<u8>,
}

/// Lo que publica un proveedor de identidad.
#[derive(Debug, Default)]
pub(crate) struct ObservacionIdentidad {
    pub documento: String,
    pub emisor: Option<String>,
    pub anuncios: Vec<Anuncio>,
    pub jwks: Option<String>,
    pub llaves: Vec<LlaveJwk>,
    /// Texto del JWKS, para el inventario.
    pub texto_jwks: Option<String>,
    /// `jwks_uri` que no se siguió por apuntar a otro servidor.
    pub jwks_externo: Option<String>,
    pub certificados: Vec<CertificadoSaml>,
    /// Algoritmos de los metadatos SAML: (elemento, URI).
    pub metodos: Vec<(String, String)>,
    /// `validUntil` de los metadatos SAML.
    pub vigencia: Option<String>,
    pub errores: Vec<String>,
}

// ---------------------------------------------------------------------------
// HTTPS
// ---------------------------------------------------------------------------

/// Solo rutas imprimibles sin espacios: van tal cual en la línea de petición.
fn ruta_valida(ruta: &str) -> bool {
    ruta.starts_with('/') && ruta.chars().all(|c| c.is_ascii_graphic())
}

fn leer(
    servidor: &Servidor,
    ruta: &str,
    aceptar: &str,
    op: &Opciones,
) -> Result<(u16, String), String> {
    if !ruta_valida(ruta) {
        return Err(format!("ruta inválida: {ruta}"));
    }
    let confianza = ConfianzaTls {
        autoridad_pem: op.autoridad_pem.clone(),
        raices_sistema: true,
        ..Default::default()
    };
    let r = http::abrir(
        servidor,
        ruta,
        &[("Accept", aceptar)],
        &Credenciales::default(),
        &confianza,
        op.tiempo_limite,
    )?;
    let estado = r.estado;
    let cuerpo = r.leer_todo(MAXIMO_DOCUMENTO)?;
    Ok((estado, String::from_utf8_lossy(&cuerpo).into_owned()))
}

fn servidor_de(o: &Objetivo) -> Servidor {
    Servidor {
        seguro: true,
        host: o.host.clone(),
        puerto: o.puerto,
        prefijo: String::new(),
    }
}

fn url(s: &Servidor, ruta: &str) -> String {
    let host = if s.host.contains(':') {
        format!("[{}]", s.host)
    } else {
        s.host.clone()
    };
    if s.puerto == 443 {
        format!("https://{host}{ruta}")
    } else {
        format!("https://{host}:{}{ruta}", s.puerto)
    }
}

/// Dominio registrable aproximado: las dos últimas etiquetas
/// («login.ejemplo.mx» → «ejemplo.mx»), o tres bajo un dominio de país con
/// segundo nivel corto («login.ejemplo.com.mx» → «ejemplo.com.mx»). Ante la
/// duda se queda con más etiquetas, que es lo más restrictivo.
fn dominio_base(host: &str) -> String {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    let partes: Vec<&str> = h.rsplit('.').collect();
    let n = match partes.as_slice() {
        [tld, sld, _, ..] if tld.len() == 2 && sld.len() <= 3 => 3,
        _ => 2,
    };
    let mut base: Vec<&str> = partes.into_iter().take(n).collect();
    base.reverse();
    base.join(".")
}

/// `jwks_uri` permitido: HTTPS y mismo servidor o mismo dominio base, sin
/// direcciones IP distintas a la del objetivo.
fn jwks_permitido(o: &Objetivo, s: &Servidor) -> bool {
    if !s.seguro {
        return false;
    }
    let objetivo = o.host.to_ascii_lowercase();
    let host = s.host.to_ascii_lowercase();
    if host == objetivo {
        return true;
    }
    let es_ip = |h: &str| h.parse::<std::net::IpAddr>().is_ok();
    !es_ip(&host) && !es_ip(&objetivo) && dominio_base(&host) == dominio_base(&objetivo)
}

// ---------------------------------------------------------------------------
// OpenID Connect
// ---------------------------------------------------------------------------

fn bits_base64url(n: &str) -> Option<u32> {
    let b = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(n.trim_end_matches('='))
        .ok()?;
    let i = b.iter().position(|&x| x != 0)?;
    Some((b.len() - i) as u32 * 8 - b[i].leading_zeros())
}

fn llaves_jwks(v: &Value) -> Vec<LlaveJwk> {
    let Some(llaves) = v.get("keys").and_then(Value::as_array) else {
        return Vec::new();
    };
    llaves
        .iter()
        .take(1000)
        .filter_map(|k| {
            let texto = |c: &str| k.get(c).and_then(Value::as_str).map(str::to_string);
            let kty = texto("kty")?;
            let bits = texto("n").as_deref().and_then(bits_base64url);
            let parametro = texto("crv").or_else(|| bits.map(|b| format!("{b} bits")));
            Some(LlaveJwk {
                kid: texto("kid"),
                kty,
                alg: texto("alg"),
                parametro,
                bits,
            })
        })
        .collect()
}

pub(crate) fn llaves_para_fuzz(v: &Value) -> usize {
    llaves_jwks(v).len()
}

fn es_jwks(v: &Value) -> bool {
    v.get("keys").is_some_and(Value::is_array)
}

/// Uso legible de una clave `*_values_supported` del descubrimiento.
fn uso_de_clave(clave: &str) -> Option<(String, bool)> {
    let base = clave.strip_suffix("_values_supported")?;
    let (sujeto, tipo) = if let Some(s) = base.strip_suffix("_signing_alg") {
        (s, "firma")
    } else if let Some(s) = base.strip_suffix("_encryption_alg") {
        (s, "cifrado de llave")
    } else if let Some(s) = base.strip_suffix("_encryption_enc") {
        (s, "cifrado de contenido")
    } else {
        (base.strip_suffix("_alg")?, "firma")
    };
    Some((format!("{sujeto} ({tipo})"), tipo != "firma"))
}

fn observar_oidc(o: &Objetivo, op: &Opciones) -> Result<ObservacionIdentidad, String> {
    let s = servidor_de(o);
    let base = o.ruta.trim_end_matches('/');
    let ruta_doc = if base.ends_with(DESCUBRIMIENTO) {
        base.to_string()
    } else {
        format!("{base}{DESCUBRIMIENTO}")
    };
    let mut obs = ObservacionIdentidad::default();
    let (estado, texto) = leer(&s, &ruta_doc, "application/json", op)?;
    let doc = serde_json::from_str::<Value>(&texto)
        .ok()
        .filter(|_| estado == 200);
    let Some(doc) = doc.filter(|d| d.get("issuer").is_some() || d.get("jwks_uri").is_some()) else {
        // ¿La ruta es directamente un JWKS?
        if !base.is_empty() && !base.ends_with(DESCUBRIMIENTO) {
            let (estado, texto) = leer(&s, base, "application/json", op)?;
            if let Ok(v) = serde_json::from_str::<Value>(&texto)
                && estado == 200
                && es_jwks(&v)
            {
                obs.documento = url(&s, base);
                obs.jwks = Some(obs.documento.clone());
                obs.llaves = llaves_jwks(&v);
                obs.texto_jwks = Some(texto);
                return Ok(obs);
            }
        }
        return Err(format!(
            "no se halló el documento de descubrimiento OpenID Connect en {} (estado HTTP {estado})",
            url(&s, &ruta_doc)
        ));
    };
    obs.documento = url(&s, &ruta_doc);
    obs.emisor = doc
        .get("issuer")
        .and_then(Value::as_str)
        .map(str::to_string);
    if let Some(m) = doc.as_object() {
        for (clave, valor) in m {
            let (Some((uso, confidencialidad)), Some(lista)) =
                (uso_de_clave(clave), valor.as_array())
            else {
                continue;
            };
            let algoritmos: Vec<String> = lista
                .iter()
                .filter_map(Value::as_str)
                .take(64)
                .map(str::to_string)
                .collect();
            if !algoritmos.is_empty() {
                obs.anuncios.push(Anuncio {
                    uso,
                    confidencialidad,
                    algoritmos,
                });
            }
        }
    }
    let Some(jwks_uri) = doc.get("jwks_uri").and_then(Value::as_str) else {
        obs.errores.push("el documento no declara jwks_uri".into());
        return Ok(obs);
    };
    let destino = match Servidor::interpretar(jwks_uri) {
        Ok(d) if jwks_permitido(o, &d) => d,
        Ok(_) | Err(_) => {
            obs.jwks_externo = Some(jwks_uri.to_string());
            return Ok(obs);
        }
    };
    let ruta = if destino.prefijo.is_empty() {
        "/".to_string()
    } else {
        destino.prefijo.clone()
    };
    let destino = Servidor {
        prefijo: String::new(),
        ..destino
    };
    match leer(&destino, &ruta, "application/json", op) {
        Ok((200, texto)) => match serde_json::from_str::<Value>(&texto) {
            Ok(v) if es_jwks(&v) => {
                obs.jwks = Some(jwks_uri.to_string());
                obs.llaves = llaves_jwks(&v);
                obs.texto_jwks = Some(texto);
            }
            _ => obs.errores.push(format!("{jwks_uri} no es un JWKS")),
        },
        Ok((estado, _)) => obs
            .errores
            .push(format!("{jwks_uri}: estado HTTP {estado}")),
        Err(e) => obs.errores.push(format!("{jwks_uri}: {e}")),
    }
    Ok(obs)
}

// ---------------------------------------------------------------------------
// SAML
// ---------------------------------------------------------------------------

/// Valor de un atributo en el texto de una etiqueta XML.
fn atributo<'a>(etiqueta: &'a str, nombre: &str) -> Option<&'a str> {
    let mut resto = etiqueta;
    while let Some(i) = resto.find(nombre) {
        let antes = resto[..i].chars().last();
        let despues = resto[i + nombre.len()..].trim_start();
        resto = &resto[i + nombre.len()..];
        if !antes.is_some_and(char::is_whitespace) {
            continue;
        }
        let Some(valor) = despues.strip_prefix('=') else {
            continue;
        };
        let valor = valor.trim_start();
        let comilla = valor.chars().next()?;
        if comilla != '"' && comilla != '\'' {
            continue;
        }
        let fin = valor[1..].find(comilla)?;
        return Some(&valor[1..1 + fin]);
    }
    None
}

/// Interpreta metadatos SAML: certificados, algoritmos y vigencia.
pub(crate) fn interpretar_saml(xml: &str, obs: &mut ObservacionIdentidad) {
    let mut uso: Option<String> = None;
    let mut p = 0;
    while let Some(i) = xml[p..].find('<') {
        let inicio = p + i + 1;
        let Some(f) = xml[inicio..].find('>') else {
            break;
        };
        let etiqueta = &xml[inicio..inicio + f];
        p = inicio + f + 1;
        if etiqueta.starts_with(['!', '?']) {
            continue;
        }
        let cierre = etiqueta.starts_with('/');
        let nombre = etiqueta
            .trim_start_matches('/')
            .split(|c: char| c.is_whitespace() || c == '/')
            .next()
            .unwrap_or("");
        let local = nombre.rsplit(':').next().unwrap_or(nombre);
        match (local, cierre) {
            ("EntityDescriptor" | "EntitiesDescriptor", false) => {
                if obs.vigencia.is_none() {
                    obs.vigencia = atributo(etiqueta, "validUntil").map(str::to_string);
                }
            }
            ("KeyDescriptor", false) => uso = atributo(etiqueta, "use").map(str::to_string),
            ("KeyDescriptor", true) => uso = None,
            ("X509Certificate", false) => {
                let fin = xml[p..].find('<').map_or(xml.len(), |j| p + j);
                let b64: String = xml[p..fin].split_whitespace().collect();
                if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(&b64)
                    && !obs.certificados.iter().any(|c| c.der == der)
                    && obs.certificados.len() < 1000
                {
                    obs.certificados.push(CertificadoSaml {
                        uso: uso.clone(),
                        der,
                    });
                }
            }
            ("SignatureMethod" | "DigestMethod" | "SigningMethod" | "EncryptionMethod", false) => {
                if let Some(uri) = atributo(etiqueta, "Algorithm") {
                    let par = (local.to_string(), uri.trim().to_string());
                    if !obs.metodos.contains(&par) && obs.metodos.len() < 1000 {
                        obs.metodos.push(par);
                    }
                }
            }
            _ => {}
        }
    }
}

fn observar_saml(o: &Objetivo, op: &Opciones) -> Result<ObservacionIdentidad, String> {
    if o.ruta.is_empty() {
        return Err(format!(
            "indique la ruta de los metadatos, p. ej. saml://{}/FederationMetadata/2007-06/FederationMetadata.xml",
            o.host
        ));
    }
    let s = servidor_de(o);
    let (estado, texto) = leer(
        &s,
        &o.ruta,
        "application/samlmetadata+xml, application/xml, text/xml",
        op,
    )?;
    if estado != 200 {
        return Err(format!("{}: estado HTTP {estado}", url(&s, &o.ruta)));
    }
    if !texto.contains("EntityDescriptor") {
        return Err(format!("{} no contiene metadatos SAML", url(&s, &o.ruta)));
    }
    let mut obs = ObservacionIdentidad {
        documento: url(&s, &o.ruta),
        ..Default::default()
    };
    interpretar_saml(&texto, &mut obs);
    Ok(obs)
}

pub(crate) fn observar(o: &Objetivo, op: &Opciones) -> Result<ObservacionIdentidad, String> {
    match o.protocolo {
        Protocolo::Saml => observar_saml(o, op),
        _ => observar_oidc(o, op),
    }
}

// ---------------------------------------------------------------------------
// Activos
// ---------------------------------------------------------------------------

fn agregar(x: Activo, todos: &mut Vec<Activo>) -> String {
    let referencia = x.referencia.clone();
    match todos.iter_mut().find(|y| y.referencia == referencia) {
        Some(y) => y.fusionar(x),
        None => todos.push(x),
    }
    referencia
}

/// Garantía de un elemento de metadatos SAML.
fn garantia_de_metodo(elemento: &str) -> Garantia {
    match elemento {
        "DigestMethod" => Garantia::Integridad,
        "EncryptionMethod" => Garantia::Confidencialidad,
        _ => Garantia::Autenticacion,
    }
}

pub(crate) fn activos(o: &Objetivo, obs: &ObservacionIdentidad, c: &Conocimiento) -> Vec<Activo> {
    let ubicacion = o.ubicacion();
    let saml = o.protocolo == Protocolo::Saml;
    let mut todos: Vec<Activo> = Vec::new();
    let mut p = Activo::nuevo(
        format!(
            "protocolo:{}:{}",
            if saml { "saml" } else { "oidc" },
            id_corto(&ubicacion)
        ),
        if saml {
            format!("Metadatos SAML de {}", o.host)
        } else {
            format!("OpenID Connect en {}", o.host)
        },
        Detalles::Protocolo {
            tipo_protocolo: if saml { "saml" } else { "oidc" }.into(),
            versiones: Vec::new(),
            grupos: Vec::new(),
            cifrados: Vec::new(),
        },
    )
    .con_contexto(CAPACIDAD, Garantia::Autenticacion)
    .con_ubicacion(&ubicacion, None);
    p.advertir(format!("Documento: {}.", obs.documento));
    let mut riesgos: Vec<Riesgo> = Vec::new();

    // Algoritmos anunciados (OIDC).
    for a in &obs.anuncios {
        let g = if a.confidencialidad {
            Garantia::Confidencialidad
        } else {
            Garantia::Autenticacion
        };
        p.advertir(format!("{}: {}.", a.uso, a.algoritmos.join(", ")));
        for alg in &a.algoritmos {
            if alg.eq_ignore_ascii_case("none") {
                if a.uso.starts_with("id_token") || a.uso.starts_with("userinfo") {
                    let mut x = activo_algoritmo(
                        None,
                        "alg none",
                        None,
                        CAPACIDAD,
                        Some(g),
                        &ubicacion,
                        None,
                    );
                    x.riesgo_fijado = Some(Riesgo::RotoClasico);
                    x.advertir(format!("{} acepta «none»: tokens sin firma.", a.uso));
                    p.relacionar("algorithm", &agregar(x, &mut todos));
                    riesgos.push(Riesgo::RotoClasico);
                }
                continue;
            }
            let def = c.por_alias("jose", alg);
            if let Some(d) = def
                && !a.confidencialidad
            {
                riesgos.push(d.riesgo);
            }
            let mut x = activo_algoritmo(def, alg, None, CAPACIDAD, Some(g), &ubicacion, None);
            if alg.eq_ignore_ascii_case("RSA1_5") {
                x.advertir("RSA1_5 usa el relleno PKCS #1 v1.5, expuesto a ataques de oráculo (Bleichenbacher).");
            }
            p.relacionar("algorithm", &agregar(x, &mut todos));
        }
    }

    // JWKS.
    if let (Some(texto), Some(jwks)) = (&obs.texto_jwks, &obs.jwks) {
        p.advertir(format!(
            "Llaves publicadas en {jwks}: {}.",
            obs.llaves.len()
        ));
        for x in activos_de_jwks(texto, jwks, CAPACIDAD, c).unwrap_or_default() {
            let tipo = match x.detalles {
                Detalles::Certificado { .. } => "certificate",
                _ => "algorithm",
            };
            if let Some(d) = x.algoritmo_id().and_then(|i| c.por_id(i))
                && d.garantia == Garantia::Autenticacion
            {
                riesgos.push(d.riesgo);
            }
            p.relacionar(tipo, &agregar(x, &mut todos));
        }
    }
    if let Some(externo) = &obs.jwks_externo {
        let sugerencia = Servidor::interpretar(externo)
            .ok()
            .filter(|d| d.seguro)
            .map(|d| format!("; sondéelo con oidc://{}{}", d.host, d.prefijo))
            .unwrap_or_default();
        p.advertir(format!(
            "jwks_uri apunta fuera del objetivo ({externo}) y no se siguió{sugerencia}."
        ));
    }

    // SAML.
    for cert in &obs.certificados {
        let Ok(v) = certificado_en_contexto(&cert.der, &ubicacion, CAPACIDAD, c) else {
            continue;
        };
        for mut x in v {
            if cert.uso.as_deref() == Some("encryption") {
                x.agregar_contexto(CAPACIDAD, Garantia::Confidencialidad);
            }
            let tipo = match x.detalles {
                Detalles::Certificado { .. } => "certificate",
                _ => "algorithm",
            };
            p.relacionar(tipo, &agregar(x, &mut todos));
        }
    }
    if saml {
        p.advertir(format!(
            "Certificados en los metadatos: {}.",
            obs.certificados.len()
        ));
    }
    for (elemento, uri) in &obs.metodos {
        let g = garantia_de_metodo(elemento);
        let mut x = por_alias(c, "xmldsig", uri, CAPACIDAD, Some(g), &ubicacion, None);
        if uri.ends_with("#rsa-1_5") {
            x.advertir(
                "RSA PKCS #1 v1.5 para cifrar: expuesto a ataques de oráculo (Bleichenbacher).",
            );
        }
        if let Some(d) = x.algoritmo_id().and_then(|i| c.por_id(i))
            && g == Garantia::Autenticacion
        {
            riesgos.push(d.riesgo);
        }
        p.relacionar("algorithm", &agregar(x, &mut todos));
    }
    let hoy = crate::dns::fecha(crate::dns::ahora());
    if let Some(v) = &obs.vigencia
        && v.get(..10).is_some_and(|f| f < hoy.as_str())
    {
        p.advertir(format!("Los metadatos vencieron (validUntil {v})."));
    }

    if riesgos
        .iter()
        .any(|r| matches!(r, Riesgo::HibridoPq | Riesgo::ResistenteCuantico))
    {
        p.advertir("Anuncia firmas poscuánticas (ML-DSA, RFC 9964).");
    } else if !riesgos.is_empty() {
        p.advertir("Los tokens y aserciones se firman solo con algoritmos clásicos: una computadora cuántica relevante podría falsificarlos.");
    }
    p.advertir("Observado en la red: refleja lo que el proveedor de identidad publica realmente.");
    todos.push(p);
    todos
}

pub(crate) fn sondear(
    o: &Objetivo,
    c: &Conocimiento,
    op: &Opciones,
) -> Result<(Vec<Activo>, Vec<String>), String> {
    let obs = observar(o, op)?;
    Ok((activos(o, &obs, c), obs.errores.clone()))
}

#[cfg(test)]
mod pruebas {
    use super::*;

    const METADATOS: &str = r#"<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="2020-01-01T00:00:00Z" entityID="https://idp.ejemplo.mx">
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
    <ds:Reference><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/></ds:Reference>
  </ds:SignedInfo></ds:Signature>
  <md:IDPSSODescriptor>
    <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>
      CERTIFICADO
    </ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    <md:KeyDescriptor use='encryption'>
      <md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
    </md:KeyDescriptor>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#;

    fn certificado() -> Vec<u8> {
        let k = rcgen::KeyPair::generate().unwrap();
        let p = rcgen::CertificateParams::new(vec!["idp.ejemplo.mx".into()]).unwrap();
        p.self_signed(&k).unwrap().der().to_vec()
    }

    #[test]
    fn metadatos_saml() {
        let der = certificado();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
        let xml = METADATOS.replace("CERTIFICADO", &b64);
        let mut obs = ObservacionIdentidad {
            documento: "https://idp.ejemplo.mx/metadata".into(),
            ..Default::default()
        };
        interpretar_saml(&xml, &mut obs);
        assert_eq!(obs.vigencia.as_deref(), Some("2020-01-01T00:00:00Z"));
        assert_eq!(obs.certificados.len(), 1);
        assert_eq!(obs.certificados[0].uso.as_deref(), Some("signing"));
        assert_eq!(obs.certificados[0].der, der);
        assert_eq!(obs.metodos.len(), 3);
        assert_eq!(obs.metodos[2].0, "EncryptionMethod");

        let o = Objetivo::interpretar("saml://idp.ejemplo.mx/metadata").unwrap();
        let c = Conocimiento::embebido();
        let v = activos(&o, &obs, &c);
        let refs: Vec<&str> = v.iter().map(|a| a.referencia.as_str()).collect();
        assert!(refs.contains(&"algoritmo:rsassa-pkcs1-sha1"), "{refs:?}");
        assert!(refs.contains(&"algoritmo:sha256"), "{refs:?}");
        assert!(refs.contains(&"algoritmo:rsa"), "{refs:?}");
        assert!(
            v.iter()
                .any(|a| matches!(a.detalles, Detalles::Certificado { .. }))
        );
        let p = v
            .iter()
            .find(|a| a.referencia.starts_with("protocolo:saml:"))
            .unwrap();
        let avisos = p.advertencias.join("\n");
        assert!(avisos.contains("vencieron"), "{avisos}");
        assert!(avisos.contains("solo con algoritmos clásicos"), "{avisos}");
    }

    #[test]
    fn descubrimiento_y_jwks() {
        assert_eq!(
            uso_de_clave("id_token_signing_alg_values_supported"),
            Some(("id_token (firma)".into(), false))
        );
        assert_eq!(
            uso_de_clave("id_token_encryption_enc_values_supported"),
            Some(("id_token (cifrado de contenido)".into(), true))
        );
        assert_eq!(uso_de_clave("scopes_supported"), None);
        assert_eq!(dominio_base("login.ejemplo.com.mx"), "ejemplo.com.mx");
        assert_eq!(dominio_base("login.ejemplo.mx"), "ejemplo.mx");
        assert_eq!(dominio_base("www.googleapis.com"), "googleapis.com");
        assert_eq!(dominio_base("localhost"), "localhost");
        let o = Objetivo::interpretar("oidc://login.ejemplo.mx").unwrap();
        let permitido = |u: &str| jwks_permitido(&o, &Servidor::interpretar(u).unwrap());
        assert!(permitido("https://login.ejemplo.mx/certs"));
        assert!(permitido("https://llaves.ejemplo.mx/certs"));
        assert!(!permitido("http://login.ejemplo.mx/certs"));
        assert!(!permitido("https://otro.example/certs"));
        assert!(!permitido("https://169.254.169.254/latest"));
        assert!(!ruta_valida("/a b"));
        assert!(!ruta_valida("/a\r\nHost: x"));

        let jwks = r#"{"keys":[
            {"kty":"RSA","kid":"r1","alg":"RS256","n":"wQ","e":"AQAB"},
            {"kty":"EC","kid":"e1","crv":"P-256","x":"AA","y":"AA"},
            {"kty":"AKP","kid":"m1","alg":"ML-DSA-44","pub":"AA"}]}"#;
        let v: Value = serde_json::from_str(jwks).unwrap();
        let llaves = llaves_jwks(&v);
        assert_eq!(llaves.len(), 3);
        assert_eq!(llaves[0].bits, Some(8));
        assert_eq!(llaves[1].parametro.as_deref(), Some("P-256"));
        let obs = ObservacionIdentidad {
            documento: "https://login.ejemplo.mx/.well-known/openid-configuration".into(),
            anuncios: vec![Anuncio {
                uso: "id_token (firma)".into(),
                confidencialidad: false,
                algoritmos: vec!["RS256".into(), "none".into(), "ML-DSA-44".into()],
            }],
            jwks: Some("https://login.ejemplo.mx/certs".into()),
            llaves,
            texto_jwks: Some(jwks.into()),
            ..Default::default()
        };
        let c = Conocimiento::embebido();
        let v = activos(&o, &obs, &c);
        let refs: Vec<&str> = v.iter().map(|a| a.referencia.as_str()).collect();
        assert!(refs.contains(&"algoritmo:rsassa-pkcs1-sha256"), "{refs:?}");
        assert!(refs.contains(&"algoritmo:ml-dsa-44"), "{refs:?}");
        assert!(refs.contains(&"algoritmo:ec-p256"), "{refs:?}");
        let ninguno = v.iter().find(|a| a.nombre == "alg none").unwrap();
        assert_eq!(ninguno.riesgo_fijado, Some(Riesgo::RotoClasico));
        let p = v
            .iter()
            .find(|a| a.referencia.starts_with("protocolo:oidc:"))
            .unwrap();
        assert!(p.advertencias.iter().any(|x| x.contains("poscuánticas")));
    }
}
