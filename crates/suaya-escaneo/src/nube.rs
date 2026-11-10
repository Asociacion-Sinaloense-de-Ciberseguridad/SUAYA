//! Infraestructura como código y exportaciones de nube.
//!
//! Detecta la criptografía que se creará o configurará al desplegar, sin
//! credenciales ni acceso a la nube:
//!
//! - **Terraform** (HCL): `tls_private_key`, llaves de AWS KMS, certificados
//!   de ACM, políticas TLS de balanceadores, CloudFront y API Gateway, llaves
//!   de Azure Key Vault, Application Gateway, Google Cloud KMS y políticas SSL
//!   de Google, y cualquier versión mínima de TLS de otros recursos.
//! - **JSON**: plantillas de CloudFormation y ARM, salidas de las CLI de nube
//!   (`aws kms describe-key`, `aws elbv2 describe-listeners`,
//!   `az keyvault key show`, `gcloud kms keys list --format=json`), conjuntos
//!   de llaves JWK (JWKS, incluidas las llaves ML-DSA `AKP` de RFC 9964 y
//!   los certificados `x5c`) y solicitudes de cfssl.
//! - **YAML y Bicep**: plantillas de CloudFormation y Bicep.
//!
//! Todo se asigna a la capacidad «conectividad-nube».

use std::collections::BTreeMap;

use serde_json::Value;
use suaya_core::{Activo, AlgoritmoDef, Conocimiento, Detalles, Garantia, Riesgo};

use crate::Escaner;
use crate::comun::{Archivo, activo_algoritmo, id_corto, linea_de};
use crate::config_sistema::{rango_versiones, version_tls};
use crate::config_tls::evaluar_tls;

const CAPACIDAD: &str = "conectividad-nube";

/// Lo que se halló en un archivo: algoritmos y configuraciones TLS.
#[derive(Default)]
struct Hallazgos {
    algoritmos: BTreeMap<String, Activo>,
    protocolos: Vec<Activo>,
    /// Certificados (`x5c`) y sus algoritmos.
    certificados: BTreeMap<String, Activo>,
}

impl Hallazgos {
    fn algoritmo(&mut self, x: Activo) {
        match self.algoritmos.get_mut(&x.referencia) {
            Some(p) => p.fusionar(x),
            None => {
                self.algoritmos.insert(x.referencia.clone(), x);
            }
        }
    }

    fn todos(self) -> Vec<Activo> {
        let mut v: Vec<Activo> = self.algoritmos.into_values().collect();
        v.extend(self.protocolos);
        v.extend(self.certificados.into_values());
        v
    }
}

fn algoritmo(
    def: Option<&AlgoritmoDef>,
    respaldo: &str,
    tamano: Option<u32>,
    a: &Archivo,
    linea: u32,
    origen: &str,
) -> Activo {
    let mut x = activo_algoritmo(def, respaldo, tamano, CAPACIDAD, None, a.ruta, Some(linea));
    x.advertir(format!("Declarado en {origen}."));
    x
}

/// Especificación de llave de un servicio de nube (AWS KMS, ACM, Google KMS,
/// Azure) como identificador y tamaño: «RSA_2048», «EC_prime256v1»…
fn especificacion(c: &Conocimiento, espacio: &str, valor: &str) -> Option<(String, Option<u32>)> {
    let v = valor.trim().to_ascii_lowercase().replace('-', "_");
    if v.starts_with("rsa")
        && let Some(bits) = v
            .split('_')
            .find_map(|p| p.parse::<u32>().ok().filter(|b| (512..=16384).contains(b)))
    {
        return Some(("rsa".into(), Some(bits)));
    }
    let directo = match v.as_str() {
        "ec_prime256v1" | "ec_secp256r1" | "p_256" | "p256" => Some("ec-p256"),
        "ec_secp384r1" | "p_384" | "p384" => Some("ec-p384"),
        "ec_secp521r1" | "p_521" | "p521" => Some("ec-p521"),
        "p_256k" => Some("ec-secp256k1"),
        "p224" | "p_224" => Some("ec-p224"),
        _ => None,
    };
    if let Some(id) = directo {
        return Some((id.into(), None));
    }
    c.por_alias(espacio, &v)
        .or_else(|| c.por_alias(espacio, valor.trim()))
        .map(|d| (d.id.clone(), None))
}

fn llave_de_nube(
    h: &mut Hallazgos,
    c: &Conocimiento,
    espacio: &str,
    valor: &str,
    a: &Archivo,
    linea: u32,
    origen: &str,
) {
    let (def, tamano) = match especificacion(c, espacio, valor) {
        Some((id, t)) => (c.por_id(&id), t),
        None => (None, None),
    };
    h.algoritmo(algoritmo(def, valor, tamano, a, linea, origen));
}

/// Versión mínima de TLS de un valor de nube («TLS1_2», «TLSv1.2_2021»,
/// «TLS_1_0», «TLSv1_2016», «Policy-Min-TLS-1-2-PFS-2023-10», «1.2»).
fn version_minima(valor: &str) -> Option<&'static str> {
    let v = valor.trim().trim_matches(['"', '\'']);
    if let Some(r) = v.strip_prefix("Policy-Min-TLS-") {
        return version_minima(&format!("TLS_{}", r.chars().take(3).collect::<String>()));
    }
    if let Some(x) = version_tls(v) {
        return Some(x);
    }
    let u = v.to_ascii_uppercase();
    if u.starts_with("SSLV3") || u.starts_with("SSL3") {
        return Some("SSLv3");
    }
    let resto = u
        .trim_start_matches("VERSION")
        .trim_start_matches("TLSV")
        .trim_start_matches("TLS")
        .trim_start_matches(['_', '-', '.', ' ']);
    let b = resto.as_bytes();
    let mayor = *b.first()?;
    if !mayor.is_ascii_digit() {
        return None;
    }
    // «1_2» es 1.2; «1_2016» es la versión 1 de 2016.
    let menor = (b.len() >= 3
        && matches!(b[1], b'_' | b'.' | b'-')
        && b[2].is_ascii_digit()
        && !b.get(3).is_some_and(u8::is_ascii_digit))
    .then(|| b[2]);
    let texto = match menor {
        Some(m) => format!("{}.{}", mayor as char, m as char),
        None => (mayor as char).to_string(),
    };
    version_tls(&texto)
}

/// Política de seguridad de un balanceador de AWS: versión mínima y si ofrece
/// intercambio híbrido poscuántico (nombres con «PQ», según AWS).
fn politica_elb(nombre: &str) -> (Option<&'static str>, bool) {
    let n = nombre.trim();
    let pq = n.split('-').any(|p| p == "PQ");
    let min = if matches!(
        n,
        "ELBSecurityPolicy-2016-08" | "ELBSecurityPolicy-FS-2018-06"
    ) || n.contains("TLS13-1-0")
        || n.contains("-TLS-1-0-")
    {
        Some("TLSv1")
    } else if n.contains("TLS13-1-1") || n.contains("-TLS-1-1-") || n.contains("FS-1-1") {
        Some("TLSv1.1")
    } else if n.contains("TLS13-1-2") || n.contains("-TLS-1-2-") || n.contains("FS-1-2") {
        Some("TLSv1.2")
    } else if n.contains("TLS13-1-3") {
        Some("TLSv1.3")
    } else {
        None
    };
    (min, pq)
}

/// Política predefinida de Azure Application Gateway.
fn politica_appgw(nombre: &str) -> Option<&'static str> {
    match nombre.trim() {
        "AppGwSslPolicy20150501" => Some("TLSv1"),
        "AppGwSslPolicy20170401" => Some("TLSv1.1"),
        "AppGwSslPolicy20170401S" | "AppGwSslPolicy20220101" | "AppGwSslPolicy20220101S" => {
            Some("TLSv1.2")
        }
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn protocolo(
    h: &mut Hallazgos,
    c: &Conocimiento,
    a: &Archivo,
    origen: &str,
    linea: u32,
    min: Option<&str>,
    hibrido: Option<bool>,
    nota: Option<String>,
) {
    let versiones = min.map(|m| rango_versiones(m, None)).unwrap_or_default();
    let mut p = Activo::nuevo(
        format!(
            "protocolo:tls:{}",
            id_corto(&format!("{}#{origen}", a.ruta_estable))
        ),
        format!("TLS de nube: {origen}"),
        Detalles::Protocolo {
            tipo_protocolo: "tls".into(),
            versiones: versiones.clone(),
            grupos: Vec::new(),
            cifrados: Vec::new(),
        },
    )
    .con_contexto(CAPACIDAD, Garantia::Confidencialidad)
    .con_ubicacion(a.ruta, Some(linea));
    if let Some(n) = nota {
        p.advertir(n);
    }
    let grupos: Option<Vec<String>> = hibrido.map(|pq| {
        if pq {
            vec![
                "x25519mlkem768".into(),
                "secp256r1mlkem768".into(),
                "x25519".into(),
            ]
        } else {
            Vec::new()
        }
    });
    if versiones.is_empty() {
        p.advertir(
            "No declara la versión mínima de TLS: se aplica la predeterminada del servicio.",
        );
        p.riesgo_fijado = Some(Riesgo::Desconocido);
    } else {
        evaluar_tls(
            &mut p,
            &versiones,
            grupos.as_deref(),
            "El servicio no declara sus grupos de intercambio de llaves: verifique con «suaya sondear».",
            Riesgo::Desconocido,
            c,
        );
    }
    if hibrido == Some(true) {
        p.advertir("La política ofrece intercambio híbrido poscuántico (SecP256r1MLKEM768, SecP384r1MLKEM1024 y X25519MLKEM768).");
    } else if hibrido == Some(false) {
        p.advertir("La política no ofrece intercambio híbrido poscuántico: AWS lo incluye solo en las políticas con «PQ» en el nombre.");
    }
    h.protocolos.push(p);
}

// ---------------------------------------------------------------------------
// Terraform
// ---------------------------------------------------------------------------

/// Un bloque `resource` de Terraform con sus atributos (también anidados).
struct Recurso {
    tipo: String,
    nombre: String,
    linea: u32,
    /// Ruta del atributo («viewer_certificate.minimum_protocol_version»), valor y línea.
    atributos: Vec<(String, String, u32)>,
}

impl Recurso {
    fn valor(&self, ruta: &str) -> Option<(&str, u32)> {
        self.atributos
            .iter()
            .find(|(k, _, _)| k == ruta || k.ends_with(&format!(".{ruta}")))
            .map(|(_, v, l)| (v.as_str(), *l))
    }

    fn origen(&self) -> String {
        format!("{}.{} (Terraform)", self.tipo, self.nombre)
    }
}

fn recursos_terraform(a: &Archivo, texto: &str) -> Vec<Recurso> {
    let mut v: Vec<Recurso> = Vec::new();
    // Pila de bloques abiertos: (nombre, es_recurso).
    let mut pila: Vec<(String, bool)> = Vec::new();
    let mut heredoc: Option<String> = None;
    let mut en_comentario = false;
    let mut desplazamiento = 0usize;
    for crudo in texto.split_inclusive('\n') {
        let numero = linea_de(a.contenido, desplazamiento);
        desplazamiento += crudo.len();
        let mut l = crudo.trim().to_string();
        if let Some(fin) = &heredoc {
            if l == *fin {
                heredoc = None;
            }
            continue;
        }
        if en_comentario {
            match l.find("*/") {
                Some(i) => {
                    en_comentario = false;
                    l = l[i + 2..].trim().to_string();
                }
                None => continue,
            }
        }
        if let Some(i) = l.find("/*")
            && !l[..i].contains('"')
        {
            en_comentario = !l[i..].contains("*/");
            l.truncate(i);
        }
        if l.starts_with('#') || l.starts_with("//") || l.is_empty() {
            continue;
        }
        if let Some(i) = l.find("<<") {
            let marca = l[i + 2..].trim_start_matches('-').trim().to_string();
            if !marca.is_empty() {
                heredoc = Some(marca);
            }
        }
        // Apertura de bloque: «resource "tipo" "nombre" {» o «bloque {».
        if l.ends_with('{') {
            let cabeza = l.trim_end_matches('{').trim();
            let partes: Vec<&str> = cabeza.split_whitespace().collect();
            if partes.first() == Some(&"resource") && partes.len() >= 3 {
                v.push(Recurso {
                    tipo: partes[1].trim_matches('"').to_string(),
                    nombre: partes[2].trim_matches('"').to_string(),
                    linea: numero,
                    atributos: Vec::new(),
                });
                pila.push((String::new(), true));
            } else if !cabeza.contains('=') {
                pila.push((
                    partes.first().unwrap_or(&"").trim_matches('"').to_string(),
                    false,
                ));
            } else {
                // «atributo = {» (mapa): se cuenta para equilibrar llaves.
                pila.push((String::new(), false));
            }
            continue;
        }
        if l.starts_with('}') {
            pila.pop();
            continue;
        }
        if let Some((k, val)) = l.split_once('=')
            && pila.iter().any(|(_, r)| *r)
            && let Some(r) = v.last_mut()
        {
            let k = k.trim();
            if k.is_empty() || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                continue;
            }
            let anidado: Vec<&str> = pila
                .iter()
                .skip_while(|(_, es)| !*es)
                .skip(1)
                .map(|(n, _)| n.as_str())
                .filter(|n| !n.is_empty())
                .collect();
            let ruta = if anidado.is_empty() {
                k.to_string()
            } else {
                format!("{}.{k}", anidado.join("."))
            };
            let valor = val
                .split(" #")
                .next()
                .unwrap_or(val)
                .trim()
                .trim_matches('"')
                .to_string();
            r.atributos.push((ruta, valor, numero));
        }
    }
    v
}

fn analizar_terraform(h: &mut Hallazgos, a: &Archivo, texto: &str, c: &Conocimiento) {
    for r in recursos_terraform(a, texto) {
        let origen = r.origen();
        match r.tipo.as_str() {
            "tls_private_key" => {
                let (alg, l) = r.valor("algorithm").unwrap_or(("RSA", r.linea));
                match alg.to_ascii_uppercase().as_str() {
                    "RSA" => {
                        let (bits, lb) = r
                            .valor("rsa_bits")
                            .and_then(|(b, l)| b.parse::<u32>().ok().map(|b| (b, l)))
                            .unwrap_or((2048, l));
                        let mut x = algoritmo(c.por_id("rsa"), "RSA", Some(bits), a, lb, &origen);
                        if r.valor("rsa_bits").is_none() {
                            x.advertir("rsa_bits no se declara: el proveedor tls usa 2048 bits.");
                        }
                        h.algoritmo(x);
                    }
                    "ECDSA" => {
                        let (curva, lc) = r.valor("ecdsa_curve").unwrap_or(("P224", l));
                        let def =
                            especificacion(c, "x509", curva).and_then(|(id, _)| c.por_id(&id));
                        let mut x = algoritmo(def, curva, None, a, lc, &origen);
                        if r.valor("ecdsa_curve").is_none() {
                            x.advertir("ecdsa_curve no se declara: el proveedor tls usa P224.");
                        }
                        h.algoritmo(x);
                    }
                    "ED25519" => h.algoritmo(algoritmo(
                        c.por_id("ed25519"),
                        "Ed25519",
                        None,
                        a,
                        l,
                        &origen,
                    )),
                    otro => h.algoritmo(algoritmo(None, otro, None, a, l, &origen)),
                }
            }
            "aws_kms_key" | "aws_kms_external_key" | "aws_kms_replica_key" => {
                let (spec, l) = r
                    .valor("key_spec")
                    .or_else(|| r.valor("customer_master_key_spec"))
                    .unwrap_or(("SYMMETRIC_DEFAULT", r.linea));
                llave_de_nube(h, c, "aws-kms", spec, a, l, &origen);
            }
            "aws_acm_certificate" | "aws_acmpca_certificate_authority" => {
                let (alg, l) = r.valor("key_algorithm").unwrap_or(("RSA_2048", r.linea));
                llave_de_nube(h, c, "aws-kms", alg, a, l, &origen);
            }
            "aws_lb_listener" | "aws_alb_listener" => {
                let protocolo_lb = r.valor("protocol").map(|(p, _)| p.to_ascii_uppercase());
                if let Some((pol, l)) = r.valor("ssl_policy") {
                    let (min, pq) = politica_elb(pol);
                    protocolo(
                        h,
                        c,
                        a,
                        &origen,
                        l,
                        min,
                        Some(pq),
                        Some(format!("Política de seguridad {pol}.")),
                    );
                } else if matches!(protocolo_lb.as_deref(), Some("HTTPS") | Some("TLS")) {
                    protocolo(
                        h, c, a, &origen, r.linea, Some("TLSv1"), Some(false),
                        Some("ssl_policy no se declara: fuera de la consola, AWS aplica ELBSecurityPolicy-2016-08, que admite TLS 1.0.".into()),
                    );
                }
            }
            "aws_cloudfront_distribution" => {
                if let Some((v, l)) = r.valor("minimum_protocol_version") {
                    protocolo(
                        h,
                        c,
                        a,
                        &origen,
                        l,
                        version_minima(v),
                        None,
                        Some(format!("minimum_protocol_version = {v}.")),
                    );
                }
            }
            "aws_api_gateway_domain_name" | "aws_apigatewayv2_domain_name" => {
                if let Some((v, l)) = r.valor("security_policy") {
                    protocolo(
                        h,
                        c,
                        a,
                        &origen,
                        l,
                        version_minima(v),
                        None,
                        Some(format!("security_policy = {v}.")),
                    );
                }
            }
            "azurerm_key_vault_key" | "azurerm_key_vault_managed_hardware_security_module_key" => {
                let (tipo, l) = r.valor("key_type").unwrap_or(("RSA", r.linea));
                let tipo = tipo.to_ascii_uppercase();
                if tipo.starts_with("RSA") {
                    let bits = r.valor("key_size").and_then(|(b, _)| b.parse().ok());
                    h.algoritmo(algoritmo(c.por_id("rsa"), "RSA", bits, a, l, &origen));
                } else if tipo.starts_with("EC") {
                    let (curva, lc) = r.valor("curve").unwrap_or(("P-256", l));
                    llave_de_nube(h, c, "x509", curva, a, lc, &origen);
                } else {
                    h.algoritmo(algoritmo(
                        c.por_id("aes-256-gcm"),
                        &tipo,
                        None,
                        a,
                        l,
                        &origen,
                    ));
                }
            }
            "azurerm_application_gateway" => {
                if let Some((nombre, l)) = r.valor("ssl_policy.policy_name") {
                    protocolo(
                        h,
                        c,
                        a,
                        &origen,
                        l,
                        politica_appgw(nombre),
                        None,
                        Some(format!("Política {nombre}.")),
                    );
                } else if let Some((v, l)) = r.valor("ssl_policy.min_protocol_version") {
                    protocolo(h, c, a, &origen, l, version_minima(v), None, None);
                }
            }
            "google_kms_crypto_key" => {
                let (alg, l) = r
                    .valor("version_template.algorithm")
                    .unwrap_or(("GOOGLE_SYMMETRIC_ENCRYPTION", r.linea));
                llave_de_nube(h, c, "gcp-kms", alg, a, l, &origen);
            }
            "google_compute_ssl_policy" => {
                let (v, l) = r.valor("min_tls_version").unwrap_or(("TLS_1_0", r.linea));
                let nota = if r.valor("min_tls_version").is_none() {
                    "min_tls_version no se declara: Google Cloud usa TLS 1.0 por omisión."
                        .to_string()
                } else {
                    format!("min_tls_version = {v}.")
                };
                protocolo(h, c, a, &origen, l, version_minima(v), None, Some(nota));
            }
            _ => {
                // Cualquier otro recurso con una versión mínima de TLS declarada.
                for (k, v, l) in &r.atributos {
                    let k = k.rsplit('.').next().unwrap_or(k);
                    if matches!(
                        k,
                        "min_tls_version"
                            | "minimum_tls_version"
                            | "tls_min_version"
                            | "minimum_protocol_version"
                            | "min_protocol_version"
                            | "ssl_minimal_tls_version_enforced"
                            | "tls_security_policy"
                    ) {
                        protocolo(
                            h,
                            c,
                            a,
                            &origen,
                            *l,
                            version_minima(v),
                            None,
                            Some(format!("{k} = {v}.")),
                        );
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// JSON: CloudFormation, ARM, salidas de CLI, JWKS y cfssl
// ---------------------------------------------------------------------------

fn bits_base64url(n: &str) -> Option<u32> {
    use base64::Engine;
    let b = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(n.trim_end_matches('='))
        .ok()?;
    Some(crate::comun::bits_de_entero(&b))
}

fn linea_de_texto(a: &Archivo, texto: &str, aguja: &str) -> u32 {
    texto.find(aguja).map_or(1, |i| linea_de(a.contenido, i))
}

fn recorrer_json(
    h: &mut Hallazgos,
    v: &Value,
    a: &Archivo,
    texto: &str,
    c: &Conocimiento,
    profundidad: usize,
) {
    if profundidad > 64 {
        return;
    }
    match v {
        Value::Array(xs) => {
            for x in xs.iter().take(10_000) {
                recorrer_json(h, x, a, texto, c, profundidad + 1);
            }
        }
        Value::Object(m) => {
            let cadena = |k: &str| m.get(k).and_then(Value::as_str);
            let linea = |valor: &str| linea_de_texto(a, texto, &format!("\"{valor}\""));
            for k in ["KeySpec", "CustomerMasterKeySpec"] {
                if let Some(s) = cadena(k) {
                    llave_de_nube(h, c, "aws-kms", s, a, linea(s), &format!("{k} (AWS KMS)"));
                }
            }
            if let Some(s) = cadena("KeyAlgorithm") {
                llave_de_nube(h, c, "aws-kms", s, a, linea(s), "KeyAlgorithm (AWS ACM)");
            }
            if let Some(s) = cadena("SslPolicy") {
                let (min, pq) = politica_elb(s);
                protocolo(
                    h,
                    c,
                    a,
                    &format!("SslPolicy {s}"),
                    linea(s),
                    min,
                    Some(pq),
                    None,
                );
            }
            if let Some(s) = cadena("MinimumProtocolVersion") {
                protocolo(
                    h,
                    c,
                    a,
                    &format!("MinimumProtocolVersion {s}"),
                    linea(s),
                    version_minima(s),
                    None,
                    None,
                );
            }
            if let Some(s) =
                cadena("SecurityPolicy").filter(|s| s.to_ascii_uppercase().starts_with("TLS"))
            {
                protocolo(
                    h,
                    c,
                    a,
                    &format!("SecurityPolicy {s}"),
                    linea(s),
                    version_minima(s),
                    None,
                    None,
                );
            }
            for (k, x) in m {
                let kl = k.to_ascii_lowercase();
                if kl.contains("tls")
                    && (kl.contains("min") || kl.contains("minimum"))
                    && kl.contains("version")
                    && let Some(s) = x.as_str()
                {
                    protocolo(
                        h,
                        c,
                        a,
                        &format!("{k} {s}"),
                        linea(s),
                        version_minima(s),
                        None,
                        None,
                    );
                }
            }
            // Google Cloud KMS: «versionTemplate.algorithm» o llave con «protectionLevel».
            if let Some(s) = m
                .get("versionTemplate")
                .and_then(|t| t.get("algorithm"))
                .and_then(Value::as_str)
                .or_else(|| m.get("protectionLevel").and(cadena("algorithm")))
            {
                llave_de_nube(h, c, "gcp-kms", s, a, linea(s), "Google Cloud KMS");
            }
            // JWK (también Azure Key Vault): kty con n, crv o key_size.
            if let Some(kty) = cadena("kty") {
                let origen = "JWK";
                let l = linea(kty);
                match kty.to_ascii_uppercase().as_str() {
                    "RSA" | "RSA-HSM" => {
                        let bits = cadena("n").and_then(bits_base64url).or_else(|| {
                            m.get("key_size")
                                .or(m.get("keySize"))
                                .and_then(Value::as_u64)
                                .map(|b| b as u32)
                        });
                        h.algoritmo(algoritmo(c.por_id("rsa"), "RSA", bits, a, l, origen));
                    }
                    "EC" | "EC-HSM" => {
                        let crv = cadena("crv").or(cadena("curve")).unwrap_or("P-256");
                        llave_de_nube(h, c, "x509", crv, a, l, origen);
                    }
                    // RFC 9964: llave de un algoritmo concreto (ML-DSA), en «alg».
                    "AKP" => {
                        let alg = cadena("alg").unwrap_or(kty);
                        h.algoritmo(algoritmo(c.por_alias("jose", alg), alg, None, a, l, origen));
                    }
                    "OKP" => {
                        let id = match cadena("crv").unwrap_or("") {
                            "Ed25519" => Some("ed25519"),
                            "Ed448" => Some("ed448"),
                            "X25519" => Some("x25519"),
                            "X448" => Some("x448"),
                            _ => None,
                        };
                        h.algoritmo(algoritmo(
                            id.and_then(|i| c.por_id(i)),
                            kty,
                            None,
                            a,
                            l,
                            origen,
                        ));
                    }
                    _ => {}
                }
                if let Some(alg) = cadena("alg") {
                    if alg.eq_ignore_ascii_case("none") {
                        let mut x = algoritmo(None, "alg none", None, a, linea(alg), origen);
                        x.riesgo_fijado = Some(Riesgo::RotoClasico);
                        x.advertir("alg = none: tokens sin firma.");
                        h.algoritmo(x);
                    } else if let Some(def) = c.por_alias("jose", alg) {
                        let mut x = algoritmo(Some(def), alg, None, a, linea(alg), origen);
                        if alg.eq_ignore_ascii_case("RSA1_5") {
                            x.advertir("RSA1_5 usa el relleno PKCS #1 v1.5, expuesto a ataques de oráculo (Bleichenbacher).");
                        }
                        h.algoritmo(x);
                    }
                }
            }
            // Cadena de certificados de la llave (RFC 7517, «x5c»).
            if let Some(x5c) = m.get("x5c").and_then(Value::as_array) {
                use base64::Engine;
                for der in x5c
                    .iter()
                    .filter_map(Value::as_str)
                    .take(10)
                    .filter_map(|x| base64::engine::general_purpose::STANDARD.decode(x).ok())
                {
                    for x in
                        crate::pem::certificado_en_archivo(&der, a, c, false).unwrap_or_default()
                    {
                        match h.certificados.get_mut(&x.referencia) {
                            Some(p) => p.fusionar(x),
                            None => {
                                h.certificados.insert(x.referencia.clone(), x);
                            }
                        }
                    }
                }
            }
            // Azure: propiedades de llave de un certificado de Key Vault.
            if let (Some(tipo), true) = (
                cadena("keyType"),
                m.contains_key("keySize") || m.contains_key("curve"),
            ) {
                let l = linea(tipo);
                if tipo.to_ascii_uppercase().starts_with("RSA") {
                    let bits = m.get("keySize").and_then(Value::as_u64).map(|b| b as u32);
                    h.algoritmo(algoritmo(
                        c.por_id("rsa"),
                        "RSA",
                        bits,
                        a,
                        l,
                        "Azure Key Vault",
                    ));
                } else if let Some(cv) = cadena("curve") {
                    llave_de_nube(h, c, "x509", cv, a, l, "Azure Key Vault");
                }
            }
            // cfssl: «"key": {"algo": "rsa", "size": 2048}».
            if let (Some(algo), Some(size)) =
                (cadena("algo"), m.get("size").and_then(Value::as_u64))
            {
                let l = linea(algo);
                match algo.to_ascii_lowercase().as_str() {
                    "rsa" => h.algoritmo(algoritmo(
                        c.por_id("rsa"),
                        "RSA",
                        Some(size as u32),
                        a,
                        l,
                        "cfssl",
                    )),
                    "ecdsa" => {
                        let id = match size {
                            256 => Some("ec-p256"),
                            384 => Some("ec-p384"),
                            521 => Some("ec-p521"),
                            _ => None,
                        };
                        h.algoritmo(algoritmo(
                            id.and_then(|i| c.por_id(i)),
                            "ECDSA",
                            None,
                            a,
                            l,
                            "cfssl",
                        ));
                    }
                    _ => {}
                }
            }
            for x in m.values() {
                recorrer_json(h, x, a, texto, c, profundidad + 1);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// YAML de CloudFormation y Bicep
// ---------------------------------------------------------------------------

fn analizar_clave_valor(h: &mut Hallazgos, a: &Archivo, texto: &str, c: &Conocimiento) {
    let mut desplazamiento = 0usize;
    // Llaves de Azure en Bicep: «kty» y «keySize»/«curveName» por separado.
    let mut azure_rsa: Option<u32> = None;
    for crudo in texto.split_inclusive('\n') {
        let l_num = linea_de(a.contenido, desplazamiento);
        desplazamiento += crudo.len();
        let l = crudo.trim();
        if l.starts_with('#') || l.starts_with("//") {
            continue;
        }
        let Some((k, v)) = l.split_once(':') else {
            continue;
        };
        let k = k.trim().trim_matches(['"', '\'']);
        let v = v
            .trim()
            .trim_end_matches(',')
            .trim()
            .trim_matches(['"', '\''])
            .trim();
        if v.is_empty() || v.starts_with('!') || v.starts_with('{') {
            continue;
        }
        match k {
            "KeySpec" | "CustomerMasterKeySpec" => {
                llave_de_nube(h, c, "aws-kms", v, a, l_num, "AWS KMS")
            }
            "KeyAlgorithm" => llave_de_nube(h, c, "aws-kms", v, a, l_num, "AWS ACM"),
            "SslPolicy" => {
                let (min, pq) = politica_elb(v);
                protocolo(
                    h,
                    c,
                    a,
                    &format!("SslPolicy {v}"),
                    l_num,
                    min,
                    Some(pq),
                    None,
                );
            }
            "MinimumProtocolVersion" | "SecurityPolicy"
                if v.to_ascii_uppercase().starts_with("TLS") =>
            {
                protocolo(
                    h,
                    c,
                    a,
                    &format!("{k} {v}"),
                    l_num,
                    version_minima(v),
                    None,
                    None,
                );
            }
            "minimumTlsVersion" | "minTlsVersion" | "minimalTlsVersion" | "MinimumTlsVersion" => {
                protocolo(
                    h,
                    c,
                    a,
                    &format!("{k} {v}"),
                    l_num,
                    version_minima(v),
                    None,
                    None,
                );
            }
            "kty" if v.to_ascii_uppercase().starts_with("RSA") => azure_rsa = Some(l_num),
            "keySize" => {
                if let (Some(lr), Ok(bits)) = (azure_rsa.take(), v.parse::<u32>()) {
                    h.algoritmo(algoritmo(
                        c.por_id("rsa"),
                        "RSA",
                        Some(bits),
                        a,
                        lr,
                        "Azure Key Vault (Bicep)",
                    ));
                }
            }
            "curveName" => llave_de_nube(h, c, "x509", v, a, l_num, "Azure Key Vault (Bicep)"),
            _ => {}
        }
    }
    if let Some(l) = azure_rsa {
        h.algoritmo(algoritmo(
            c.por_id("rsa"),
            "RSA",
            None,
            a,
            l,
            "Azure Key Vault (Bicep)",
        ));
    }
}

/// Activos de un conjunto de llaves JWK (JWKS) obtenido de la red:
/// algoritmos, tamaños y certificados `x5c`, en la capacidad indicada.
pub fn activos_de_jwks(
    texto: &str,
    ubicacion: &str,
    capacidad: &str,
    c: &Conocimiento,
) -> Result<Vec<Activo>, String> {
    let v: Value = serde_json::from_str(texto).map_err(|e| format!("JSON inválido: {e}"))?;
    let a = Archivo::nuevo(
        ubicacion,
        std::path::Path::new(ubicacion),
        texto.as_bytes(),
        None,
    );
    let mut h = Hallazgos::default();
    recorrer_json(&mut h, &v, &a, texto, c, 0);
    let mut activos = h.todos();
    for x in &mut activos {
        x.contextos.clear();
        x.agregar_contexto(capacidad, Garantia::Autenticacion);
    }
    Ok(activos)
}

pub struct EscanerNube;

impl Escaner for EscanerNube {
    fn nombre(&self) -> &'static str {
        "infraestructura como código y nube"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        match a.extension.as_str() {
            "tf" => true,
            "bicep" => true,
            "json" => {
                a.contiene(b"KeySpec")
                    || a.contiene(b"KeyAlgorithm")
                    || a.contiene(b"SslPolicy")
                    || a.contiene(b"\"kty\"")
                    || a.contiene(b"versionTemplate")
                    || a.contiene(b"MinimumProtocolVersion")
                    || a.contiene(b"\"algo\"")
                    || a.contiene(b"TlsVersion")
            }
            "yaml" | "yml" | "template" => {
                a.contiene(b"AWSTemplateFormatVersion") || a.contiene(b"AWS::")
            }
            _ => false,
        }
    }

    fn analizar(&self, a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
        let texto = a.texto().ok_or("el archivo no es texto UTF-8")?;
        let mut h = Hallazgos::default();
        match a.extension.as_str() {
            "tf" => analizar_terraform(&mut h, a, texto, c),
            "json" => {
                let v: Value =
                    serde_json::from_str(texto).map_err(|e| format!("JSON inválido: {e}"))?;
                recorrer_json(&mut h, &v, a, texto, c, 0);
            }
            _ => analizar_clave_valor(&mut h, a, texto, c),
        }
        Ok(h.todos())
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn analizar(ruta: &str, t: &str) -> Vec<Activo> {
        let a = Archivo::nuevo(ruta, std::path::Path::new(ruta), t.as_bytes(), None);
        assert!(EscanerNube.aplica(&a), "{ruta}");
        EscanerNube.analizar(&a, &Conocimiento::embebido()).unwrap()
    }

    fn ids(v: &[Activo]) -> Vec<String> {
        v.iter().map(|x| x.referencia.clone()).collect()
    }

    #[test]
    fn terraform() {
        let tf = r#"
# resource "tls_private_key" "comentada" { algorithm = "RSA" }
resource "tls_private_key" "ca" {
  algorithm = "RSA"
  rsa_bits  = 4096
}
resource "tls_private_key" "ec" {
  algorithm = "ECDSA"
}
resource "aws_kms_key" "firma" {
  key_spec  = "ML_DSA_65"
  key_usage = "SIGN_VERIFY"
}
resource "aws_kms_key" "datos" {
  description = "sin especificación"
}
resource "aws_lb_listener" "web" {
  port       = 443
  protocol   = "HTTPS"
  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"
}
resource "aws_lb_listener" "viejo" {
  protocol = "HTTPS"
}
resource "aws_cloudfront_distribution" "cdn" {
  viewer_certificate {
    minimum_protocol_version = "TLSv1_2016"
  }
}
resource "google_kms_crypto_key" "k" {
  version_template {
    algorithm = "RSA_SIGN_PKCS1_2048_SHA256"
  }
}
resource "azurerm_storage_account" "s" {
  min_tls_version = "TLS1_0"
}
"#;
        let v = analizar("infra/main.tf", tf);
        let r = ids(&v);
        assert!(r.contains(&"algoritmo:rsa-4096".to_string()), "{r:?}");
        assert!(r.contains(&"algoritmo:rsa-2048".to_string()));
        assert!(r.contains(&"algoritmo:ec-p224".to_string()));
        assert!(r.contains(&"algoritmo:ml-dsa-65".to_string()));
        assert!(r.contains(&"algoritmo:aes-256-gcm".to_string()));
        let web = v
            .iter()
            .find(|x| x.nombre.contains("aws_lb_listener.web"))
            .unwrap();
        assert_eq!(web.riesgo_fijado, Some(Riesgo::HibridoPq));
        let viejo = v
            .iter()
            .find(|x| x.nombre.contains("aws_lb_listener.viejo"))
            .unwrap();
        assert_eq!(viejo.riesgo_fijado, Some(Riesgo::Obsoleto));
        let cdn = v.iter().find(|x| x.nombre.contains("cloudfront")).unwrap();
        assert_eq!(cdn.riesgo_fijado, Some(Riesgo::Obsoleto));
        assert!(
            v.iter()
                .any(|x| x.nombre.contains("azurerm_storage_account"))
        );
        assert!(!r.iter().any(|x| x.contains("comentada")));
    }

    #[test]
    fn json_de_cli_jwks_y_cfssl() {
        let v = analizar(
            "salida/kms.json",
            r#"{"KeyMetadata": {"KeyId": "1234", "KeySpec": "RSA_3072", "KeyUsage": "SIGN_VERIFY"}}"#,
        );
        assert_eq!(ids(&v), vec!["algoritmo:rsa-3072"]);
        let v = analizar(
            "web/.well-known/jwks.json",
            r#"{"keys": [{"kty": "RSA", "alg": "RS256", "n": "wQECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn-AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq-wsbKztLW2t7i5uru8vb6_wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t_g4eLj5OXm5-jp6uvs7e7v8PHy8_T19vf4-fr7_P3-_w", "e": "AQAB"}, {"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}"#,
        );
        let r = ids(&v);
        assert!(
            r.contains(&"algoritmo:rsassa-pkcs1-sha256".to_string()),
            "{r:?}"
        );
        assert!(r.contains(&"algoritmo:ed25519".to_string()));
        assert!(r.contains(&"algoritmo:rsa-2048".to_string()));
        let v = analizar(
            "pki/ca-csr.json",
            r#"{"CN": "CA", "key": {"algo": "ecdsa", "size": 384}}"#,
        );
        assert_eq!(ids(&v), vec!["algoritmo:ec-p384"]);
    }

    #[test]
    fn cloudformation_yaml() {
        let v = analizar(
            "plantilla.yaml",
            "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  Llave:\n    Type: AWS::KMS::Key\n    Properties:\n      KeySpec: ECC_NIST_P384\n  Oyente:\n    Type: AWS::ElasticLoadBalancingV2::Listener\n    Properties:\n      SslPolicy: ELBSecurityPolicy-2016-08\n",
        );
        assert!(ids(&v).contains(&"algoritmo:ec-p384".to_string()));
        let p = v
            .iter()
            .find(|x| x.referencia.starts_with("protocolo:"))
            .unwrap();
        assert_eq!(p.riesgo_fijado, Some(Riesgo::Obsoleto));
    }

    #[test]
    fn versiones_minimas_de_nube() {
        assert_eq!(version_minima("TLS1_2"), Some("TLSv1.2"));
        assert_eq!(version_minima("TLS_1_0"), Some("TLSv1"));
        assert_eq!(version_minima("TLSv1.2_2021"), Some("TLSv1.2"));
        assert_eq!(version_minima("TLSv1_2016"), Some("TLSv1"));
        assert_eq!(
            version_minima("Policy-Min-TLS-1-2-PFS-2023-10"),
            Some("TLSv1.2")
        );
        assert_eq!(version_minima("1.2"), Some("TLSv1.2"));
        assert_eq!(
            politica_elb("ELBSecurityPolicy-TLS13-1-0-PQ-2025-09"),
            (Some("TLSv1"), true)
        );
        assert_eq!(
            politica_elb("ELBSecurityPolicy-TLS13-1-3-2021-06"),
            (Some("TLSv1.3"), false)
        );
    }
}
