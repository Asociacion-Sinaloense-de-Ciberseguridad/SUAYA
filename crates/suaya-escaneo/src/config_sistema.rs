//! Configuración criptográfica del sistema: los valores que heredan todos los
//! programas que no configuran TLS o Kerberos por su cuenta.
//!
//! - **OpenSSL**: `openssl.cnf` y el fragmento `opensslcnf.config` de
//!   crypto-policies (versión mínima, grupos, nivel de seguridad, proveedor
//!   `legacy`) y los valores de `[req]` y `[CA_default]` con los que se
//!   generan llaves y certificados.
//! - **crypto-policies** de RHEL, Fedora y derivados: la política activa.
//! - **GnuTLS**: `/etc/gnutls/config` y el fragmento de crypto-policies.
//! - **Kerberos**: `krb5.conf` (tipos de cifrado permitidos).
//! - **Políticas de navegador** que desactivan el acuerdo de llaves
//!   poscuántico (`PostQuantumKeyAgreementEnabled`).

use std::collections::BTreeMap;

use suaya_core::{Activo, Conocimiento, Detalles, Garantia, Riesgo};

use crate::Escaner;
use crate::comun::{Archivo, activo_algoritmo, id_corto, linea_de, por_alias};
use crate::config_tls::{SIN_GRUPOS_OPENSSL, evaluar_tls};

const CAPACIDAD_TLS: &str = "servidores-web";
const ORDEN_VERSIONES: [&str; 6] = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"];

/// Nombre canónico de una versión de SSL/TLS escrita de cualquiera de las
/// formas habituales («TLSv1_2», «tls1.2», «VersionTLS12», «3.3», «1.2»).
pub(crate) fn version_tls(t: &str) -> Option<&'static str> {
    let n: String = t
        .trim()
        .trim_matches(['"', '\'', '(', ')', '[', ']', ','])
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.')
        .collect();
    let n = n
        .trim_start_matches("versiontls")
        .trim_start_matches("version")
        .trim_start_matches("tlsv")
        .trim_start_matches("tls");
    Some(match n {
        "sslv2" | "ssl2" | "ssl20" | "ssl2.0" => "SSLv2",
        "sslv3" | "ssl3" | "ssl30" | "ssl3.0" | "3.0" => "SSLv3",
        "1" | "10" | "1.0" | "3.1" => "TLSv1",
        "11" | "1.1" | "3.2" => "TLSv1.1",
        "12" | "1.2" | "3.3" => "TLSv1.2",
        "13" | "1.3" | "3.4" => "TLSv1.3",
        _ => return None,
    })
}

/// Versiones desde una mínima hasta una máxima (o la más reciente).
pub(crate) fn rango_versiones(min: &str, max: Option<&str>) -> Vec<String> {
    let i = ORDEN_VERSIONES.iter().position(|v| *v == min).unwrap_or(0);
    let j = max
        .and_then(|m| ORDEN_VERSIONES.iter().position(|v| *v == m))
        .unwrap_or(ORDEN_VERSIONES.len() - 1);
    ORDEN_VERSIONES[i..=j.max(i)]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// Revisa una lista de cifrados de OpenSSL o IANA y devuelve advertencias.
pub(crate) fn advertencias_cifrados(lista: &str) -> (Vec<String>, Option<Riesgo>) {
    let mut avisos = Vec::new();
    let mut riesgo = None;
    let tokens: Vec<&str> = lista
        .split([':', ',', ' ', ';'])
        .map(str::trim)
        .filter(|t| !t.is_empty() && !t.starts_with('!') && !t.starts_with('-'))
        .collect();
    let hay = |f: &dyn Fn(&str) -> bool| tokens.iter().any(|t| f(&t.to_ascii_uppercase()));
    if hay(&|t| t.contains("RC4")) {
        avisos.push("Habilita cifrados con RC4, roto.".to_string());
        riesgo = Some(Riesgo::RotoClasico);
    }
    if hay(&|t| t.contains("3DES") || t.contains("DES-CBC3") || t.contains("DES_EDE3")) {
        avisos.push("Habilita cifrados con 3DES (Sweet32).".to_string());
        riesgo = Some(Riesgo::RotoClasico);
    }
    if hay(&|t| {
        t.contains("NULL") && !t.contains("ANULL") || t.contains("EXPORT") || t.starts_with("EXP-")
    }) {
        avisos.push("Habilita cifrados nulos o de exportación.".to_string());
        riesgo = Some(Riesgo::RotoClasico);
    }
    if hay(&|t| {
        t.starts_with("TLS_RSA_WITH") || t.starts_with("AES128-") || t.starts_with("AES256-")
    }) {
        avisos.push(
            "Habilita intercambio de llaves RSA estático: sin secreto perfecto hacia adelante."
                .to_string(),
        );
    }
    (avisos, riesgo)
}

fn protocolo(a: &Archivo, nombre: String, tipo: &str, capacidad: &str) -> Activo {
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
    .con_contexto(capacidad, Garantia::Confidencialidad)
    .con_ubicacion(a.ruta, None)
}

fn fijar_listas(p: &mut Activo, v: Vec<String>, g: Vec<String>, cif: Vec<String>) {
    if let Detalles::Protocolo {
        versiones,
        grupos,
        cifrados,
        ..
    } = &mut p.detalles
    {
        *versiones = v;
        *grupos = g;
        *cifrados = cif;
    }
}

/// Sube el riesgo fijado del activo si `r` es más grave.
pub(crate) fn agravar(p: &mut Activo, r: Riesgo) {
    p.riesgo_fijado = Some(match p.riesgo_fijado {
        Some(x) if x.gravedad() <= r.gravedad() => x,
        _ => r,
    });
}

/// Líneas `clave = valor` con número de línea y sección actual (INI simple).
fn entradas_ini(a: &Archivo, texto: &str) -> Vec<(String, String, String, u32)> {
    let mut v = Vec::new();
    let mut seccion = String::new();
    let mut desplazamiento = 0usize;
    for linea in texto.split_inclusive('\n') {
        let numero = linea_de(a.contenido, desplazamiento);
        desplazamiento += linea.len();
        let l = linea.split('#').next().unwrap_or("").trim();
        if l.is_empty() {
            continue;
        }
        if let Some(s) = l.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
            seccion = s.trim().to_ascii_lowercase();
            continue;
        }
        if let Some((k, val)) = l.split_once('=') {
            v.push((
                seccion.clone(),
                k.trim().to_string(),
                val.trim().trim_matches('"').to_string(),
                numero,
            ));
        }
    }
    v
}

// ---------------------------------------------------------------------------
// OpenSSL
// ---------------------------------------------------------------------------

pub struct EscanerOpenssl;

const PISTAS_OPENSSL: &[&[u8]] = &[
    b"MinProtocol",
    b"CipherString",
    b"Ciphersuites",
    b"Groups",
    b"openssl_conf",
    b"default_bits",
    b"default_md",
    b"SignatureAlgorithms",
];

impl Escaner for EscanerOpenssl {
    fn nombre(&self) -> &'static str {
        "configuración de OpenSSL"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        let n = a.nombre.as_str();
        (n == "openssl.cnf"
            || n == "openssl.conf"
            || n == "opensslcnf.config"
            || n.ends_with(".cnf") && !n.starts_with("my") && !a.contiene(b"[mysqld"))
            && PISTAS_OPENSSL.iter().any(|p| a.contiene(p))
    }

    fn analizar(&self, a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
        let texto = a.texto().ok_or("el archivo no es texto UTF-8")?;
        let entradas = entradas_ini(a, texto);
        let mut activos = Vec::new();
        let valor = |clave: &str| {
            entradas
                .iter()
                .find(|(_, k, _, _)| k.eq_ignore_ascii_case(clave))
                .map(|(_, _, v, l)| (v.as_str(), *l))
        };

        // Valores con los que «openssl req» y «openssl ca» generan llaves y firman.
        for (seccion, k, v, l) in &entradas {
            if k.eq_ignore_ascii_case("default_bits")
                && let Ok(bits) = v.parse::<u32>()
            {
                let mut x = activo_algoritmo(
                    c.por_id("rsa"),
                    "RSA",
                    Some(bits),
                    "pki-ca",
                    Some(Garantia::Autenticacion),
                    a.ruta,
                    Some(*l),
                );
                x.advertir(format!(
                    "Tamaño de llave predeterminado de «openssl req» en [{seccion}]."
                ));
                activos.push(x);
            }
            if k.eq_ignore_ascii_case("default_md")
                && !matches!(v.to_ascii_lowercase().as_str(), "default" | "")
            {
                let nombre = v.to_ascii_lowercase().replace('_', "-");
                let def = c
                    .codigo
                    .traducir("codigo", &nombre)
                    .and_then(|id| c.por_id(id));
                let mut x = activo_algoritmo(
                    def,
                    v,
                    None,
                    "pki-ca",
                    Some(Garantia::Autenticacion),
                    a.ruta,
                    Some(*l),
                );
                x.advertir(format!(
                    "Función hash predeterminada para firmar certificados en [{seccion}]."
                ));
                activos.push(x);
            }
        }

        let min = valor("MinProtocol");
        let max = valor("MaxProtocol");
        let grupos = valor("Groups").or_else(|| valor("Curves"));
        let cifrado = valor("CipherString");
        let suites13 = valor("Ciphersuites");
        let firmas = valor("SignatureAlgorithms");
        // Proveedor «legacy» de OpenSSL 3: una sección *legacy* con «activate = 1».
        let legado = entradas.iter().any(|(s, k, v, _)| {
            s.contains("legacy") && k.eq_ignore_ascii_case("activate") && v == "1"
        });
        if min.is_none()
            && grupos.is_none()
            && cifrado.is_none()
            && suites13.is_none()
            && firmas.is_none()
            && !legado
        {
            return Ok(activos);
        }

        let mut p = protocolo(
            a,
            format!("Configuración de OpenSSL ({})", a.nombre),
            "tls",
            CAPACIDAD_TLS,
        );
        p.advertir("Valores predeterminados de OpenSSL: los heredan las aplicaciones que no configuran TLS por su cuenta.");
        let versiones = match min.and_then(|(v, _)| version_tls(v)) {
            Some(m) => rango_versiones(m, max.and_then(|(v, _)| version_tls(v))),
            None => {
                p.advertir("MinProtocol no se declara: la versión mínima depende de la versión de OpenSSL y de su nivel de seguridad.");
                Vec::new()
            }
        };
        let mut lista_grupos = Vec::new();
        let mut algoritmos = Vec::new();
        if let Some((g, l)) = grupos {
            for x in g.split([':', ',']).map(str::trim).filter(|x| !x.is_empty()) {
                let x = x.trim_start_matches('?').trim_start_matches('*');
                lista_grupos.push(x.to_string());
                algoritmos.push(por_alias(
                    c,
                    "tls-grupo",
                    x,
                    CAPACIDAD_TLS,
                    Some(Garantia::Confidencialidad),
                    a.ruta,
                    Some(l),
                ));
            }
        }
        let mut cifrados = Vec::new();
        if let Some((cs, _)) = cifrado {
            cifrados.push(cs.to_string());
            let nivel = cs
                .split(['@', ':'])
                .find_map(|t| t.strip_prefix("SECLEVEL="))
                .and_then(|n| n.parse::<u8>().ok());
            match nivel {
                Some(0) => {
                    p.advertir("@SECLEVEL=0 desactiva las restricciones de seguridad de OpenSSL: admite llaves y algoritmos rotos.");
                    agravar(&mut p, Riesgo::RotoClasico);
                }
                Some(1) => {
                    p.advertir(
                        "@SECLEVEL=1 admite llaves RSA y DH de 1024 bits (80 bits de seguridad).",
                    );
                    agravar(&mut p, Riesgo::Obsoleto);
                }
                _ => {}
            }
            let (avisos, r) = advertencias_cifrados(cs);
            for x in avisos {
                p.advertir(x);
            }
            if let Some(r) = r {
                agravar(&mut p, r);
            }
        }
        if let Some((s, _)) = suites13 {
            cifrados.push(s.to_string());
        }
        if let Some((f, l)) = firmas
            && f.to_ascii_uppercase()
                .split([':', '+'])
                .any(|t| t == "SHA1")
        {
            p.advertir(format!(
                "SignatureAlgorithms admite firmas con SHA-1 (línea {l})."
            ));
            agravar(&mut p, Riesgo::Obsoleto);
        }
        if legado {
            p.advertir("Activa el proveedor «legacy» de OpenSSL 3, que vuelve a ofrecer MD4, RC4, DES, Blowfish y otros algoritmos retirados.");
            agravar(&mut p, Riesgo::Obsoleto);
        }
        let previo = p.riesgo_fijado;
        evaluar_tls(
            &mut p,
            &versiones,
            grupos.is_some().then_some(lista_grupos.as_slice()),
            SIN_GRUPOS_OPENSSL,
            Riesgo::Desconocido,
            c,
        );
        if let Some(r) = previo {
            agravar(&mut p, r);
        }
        fijar_listas(&mut p, versiones, lista_grupos, cifrados);
        for x in &algoritmos {
            p.relacionar("algorithm", &x.referencia);
        }
        activos.extend(algoritmos);
        activos.push(p);
        Ok(activos)
    }
}

// ---------------------------------------------------------------------------
// crypto-policies (RHEL, Fedora y derivados)
// ---------------------------------------------------------------------------

pub struct EscanerCryptoPolicies;

impl Escaner for EscanerCryptoPolicies {
    fn nombre(&self) -> &'static str {
        "política criptográfica del sistema"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        a.nombre == "config" && a.ruta.replace('\\', "/").contains("crypto-policies/config")
    }

    fn analizar(&self, a: &Archivo, _c: &Conocimiento) -> Result<Vec<Activo>, String> {
        let texto = a.texto().ok_or("el archivo no es texto UTF-8")?;
        let Some(politica) = texto
            .lines()
            .map(|l| l.split('#').next().unwrap_or("").trim())
            .find(|l| !l.is_empty())
        else {
            return Ok(Vec::new());
        };
        if politica.len() > 200 || !politica.chars().all(|c| c.is_ascii_graphic()) {
            return Err("política ilegible".into());
        }
        let partes: Vec<String> = politica
            .split(':')
            .map(|s| s.to_ascii_uppercase())
            .collect();
        let mut p = protocolo(
            a,
            format!("Política criptográfica del sistema ({politica})"),
            "tls",
            CAPACIDAD_TLS,
        );
        p.advertir("La política de crypto-policies fija los valores predeterminados de OpenSSL, GnuTLS, NSS, OpenSSH, Java y Kerberos del sistema.");
        p.riesgo_fijado = Some(Riesgo::Desconocido);
        match partes[0].as_str() {
            "LEGACY" => {
                p.advertir("Política LEGACY: vuelve a habilitar algoritmos y protocolos retirados (por ejemplo, SHA-1 en firmas y versiones antiguas de TLS, según la versión del sistema).");
                p.riesgo_fijado = Some(Riesgo::Obsoleto);
            }
            "FUTURE" => p.advertir(
                "Política FUTURE: exige parámetros más fuertes (por ejemplo, RSA de 3072 bits o más).",
            ),
            "FIPS" => p.advertir("Política FIPS: limita los algoritmos a los aprobados por FIPS 140."),
            "DEFAULT" => {}
            otra => p.advertir(format!(
                "Política personalizada «{otra}»: revise su definición en /etc/crypto-policies/policies."
            )),
        }
        for sub in &partes[1..] {
            if sub == "SHA1" {
                p.advertir("La subpolítica SHA1 vuelve a admitir SHA-1 en firmas.");
                p.riesgo_fijado = Some(Riesgo::Obsoleto);
            } else if sub.contains("PQ") {
                p.advertir(format!(
                    "Subpolítica {sub}: habilita algoritmos poscuánticos (por ejemplo, intercambios híbridos con ML-KEM)."
                ));
            } else if sub == "AD-SUPPORT" || sub.starts_with("AD-SUPPORT") {
                p.advertir("Subpolítica AD-SUPPORT: habilita cifrados de Kerberos para Active Directory; revise los tipos de cifrado permitidos.");
            }
        }
        p.advertir("Para conocer los grupos que se negocian realmente, sondee los servicios con «suaya sondear».");
        Ok(vec![p])
    }
}

// ---------------------------------------------------------------------------
// GnuTLS
// ---------------------------------------------------------------------------

pub struct EscanerGnutls;

impl Escaner for EscanerGnutls {
    fn nombre(&self) -> &'static str {
        "configuración de GnuTLS"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        let r = a.ruta.replace('\\', "/");
        (a.nombre == "gnutls.config" || (a.nombre == "config" && r.contains("gnutls/config")))
            && (a.contiene(b"VERS-") || a.contiene(b"version") || a.contiene(b"GROUP-"))
    }

    fn analizar(&self, a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
        let texto = a.texto().ok_or("el archivo no es texto UTF-8")?;
        let mut versiones: Vec<String> = Vec::new();
        let mut quitar: Vec<String> = Vec::new();
        let mut grupos: Vec<String> = Vec::new();
        let mut algoritmos = Vec::new();
        let mut p = protocolo(
            a,
            format!("Configuración de GnuTLS ({})", a.nombre),
            "tls",
            CAPACIDAD_TLS,
        );
        for linea in texto.lines() {
            let l = linea.split('#').next().unwrap_or("").trim();
            // Formato de cadena de prioridad: «+VERS-TLS1.2:-VERS-TLS1.0:+GROUP-X25519».
            for t in l.split([':', ' ', '=']).map(str::trim) {
                let (signo, cuerpo) = match t.chars().next() {
                    Some('+') => ('+', &t[1..]),
                    Some('-') | Some('!') => ('-', &t[1..]),
                    _ => (' ', t),
                };
                if let Some(v) = cuerpo.strip_prefix("VERS-").and_then(version_tls) {
                    if signo == '-' {
                        quitar.push(v.into());
                    } else if signo == '+' {
                        versiones.push(v.into());
                    }
                }
                if signo == '+'
                    && let Some(g) = cuerpo.strip_prefix("GROUP-")
                {
                    grupos.push(g.to_string());
                }
            }
            // Formato de [overrides]: «enabled-version = TLS1.3», «tls-enabled-group = GROUP-X25519».
            if let Some((k, v)) = l.split_once('=') {
                let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
                if k.contains("enabled-version")
                    && let Some(x) = version_tls(v)
                {
                    versiones.push(x.into());
                }
                if k.contains("disabled-version")
                    && let Some(x) = version_tls(v)
                {
                    quitar.push(x.into());
                }
                if k.contains("enabled-group") || k.contains("enabled-curve") {
                    grupos.push(v.trim_start_matches("GROUP-").to_string());
                }
            }
        }
        versiones.retain(|v| !quitar.contains(v));
        versiones.sort_by_key(|v| ORDEN_VERSIONES.iter().position(|o| o == v));
        versiones.dedup();
        grupos.dedup();
        let mut nombres_grupos = Vec::new();
        for g in &grupos {
            if g.eq_ignore_ascii_case("ALL") {
                continue;
            }
            let alias = g.to_ascii_lowercase().replace('-', "");
            nombres_grupos.push(alias.clone());
            algoritmos.push(por_alias(
                c,
                "tls-grupo",
                &alias,
                CAPACIDAD_TLS,
                Some(Garantia::Confidencialidad),
                a.ruta,
                None,
            ));
        }
        evaluar_tls(
            &mut p,
            &versiones,
            (!nombres_grupos.is_empty()).then_some(nombres_grupos.as_slice()),
            "No se declaran grupos: dependen de la versión de GnuTLS.",
            Riesgo::Desconocido,
            c,
        );
        fijar_listas(&mut p, versiones, nombres_grupos, Vec::new());
        for x in &algoritmos {
            p.relacionar("algorithm", &x.referencia);
        }
        let mut v = algoritmos;
        v.push(p);
        Ok(v)
    }
}

// ---------------------------------------------------------------------------
// Kerberos (krb5.conf)
// ---------------------------------------------------------------------------

pub struct EscanerKerberos;

impl Escaner for EscanerKerberos {
    fn nombre(&self) -> &'static str {
        "configuración de Kerberos"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        (a.nombre == "krb5.conf" || a.ruta.replace('\\', "/").contains("krb5.conf.d/"))
            && a.contiene(b"[libdefaults]")
    }

    fn analizar(&self, a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
        let texto = a.texto().ok_or("el archivo no es texto UTF-8")?;
        let entradas = entradas_ini(a, texto);
        let mut p = protocolo(
            a,
            format!("Kerberos ({})", a.nombre),
            "kerberos",
            "sin-clasificar",
        );
        let mut algoritmos: BTreeMap<String, Activo> = BTreeMap::new();
        let mut tipos = Vec::new();
        let mut riesgos = Vec::new();
        for (seccion, k, v, l) in &entradas {
            if seccion != "libdefaults" {
                continue;
            }
            let k = k.to_ascii_lowercase();
            if k == "allow_weak_crypto"
                && matches!(v.to_ascii_lowercase().as_str(), "true" | "yes" | "1")
            {
                p.advertir(
                    "allow_weak_crypto habilita tipos de cifrado débiles (DES y similares).",
                );
                riesgos.push(Riesgo::RotoClasico);
            }
            if matches!(
                k.as_str(),
                "permitted_enctypes" | "default_tkt_enctypes" | "default_tgs_enctypes"
            ) {
                for t in v.split([' ', ',']).map(str::trim).filter(|t| !t.is_empty()) {
                    let t = t.trim_start_matches('+').to_ascii_lowercase();
                    if t == "default" || t.starts_with('-') {
                        continue;
                    }
                    if !tipos.contains(&t) {
                        tipos.push(t.clone());
                    }
                    let x = por_alias(
                        c,
                        "kerberos",
                        &t,
                        "sin-clasificar",
                        Some(Garantia::Confidencialidad),
                        a.ruta,
                        Some(*l),
                    );
                    if let Some(d) = x.algoritmo_id().and_then(|i| c.por_id(i)) {
                        riesgos.push(d.riesgo);
                    }
                    algoritmos.entry(x.referencia.clone()).or_insert(x);
                }
            }
        }
        if tipos.is_empty() && riesgos.is_empty() {
            p.advertir("No declara tipos de cifrado: se usan los predeterminados de la biblioteca de Kerberos.");
            p.riesgo_fijado = Some(Riesgo::Desconocido);
        } else {
            if riesgos.iter().any(|r| matches!(r, Riesgo::RotoClasico)) {
                p.advertir("Permite tipos de cifrado rotos (RC4 o DES): un atacante puede descifrar tickets fuera de línea.");
            }
            p.riesgo_fijado = riesgos.into_iter().min_by_key(|r| r.gravedad());
        }
        fijar_listas(&mut p, Vec::new(), Vec::new(), tipos);
        let mut v: Vec<Activo> = algoritmos.into_values().collect();
        for x in &v {
            p.relacionar("algorithm", &x.referencia);
        }
        v.push(p);
        Ok(v)
    }
}

// ---------------------------------------------------------------------------
// Políticas de navegador
// ---------------------------------------------------------------------------

pub struct EscanerPoliticaNavegador;

/// Valor de `PostQuantumKeyAgreementEnabled` en JSON, plist o registro de texto.
pub(crate) fn pq_desactivado(texto: &str) -> Option<usize> {
    let i = texto.find("PostQuantumKeyAgreementEnabled")?;
    let resto = &texto[i + "PostQuantumKeyAgreementEnabled".len()..];
    let fragmento: String = resto
        .chars()
        .take(80)
        .collect::<String>()
        .to_ascii_lowercase();
    let falso = fragmento
        .trim_start_matches(['"', '\''])
        .trim_start()
        .trim_start_matches([':', '='])
        .trim_start();
    (falso.starts_with("false")
        || falso.starts_with("0")
        || falso.starts_with("dword:00000000")
        || fragmento.contains("<false/>") && !fragmento.contains("<true/>"))
    .then_some(i)
}

impl Escaner for EscanerPoliticaNavegador {
    fn nombre(&self) -> &'static str {
        "políticas de navegador"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        a.extension != "reg" && a.contiene(b"PostQuantumKeyAgreementEnabled")
    }

    fn analizar(&self, a: &Archivo, _c: &Conocimiento) -> Result<Vec<Activo>, String> {
        let texto = a.texto().ok_or("el archivo no es texto UTF-8")?;
        Ok(politica_pq(a, texto, linea_de(a.contenido, 0))
            .into_iter()
            .collect())
    }
}

/// Activo de una política que desactiva el acuerdo de llaves poscuántico.
pub(crate) fn politica_pq(a: &Archivo, texto: &str, _base: u32) -> Option<Activo> {
    let i = pq_desactivado(texto)?;
    let mut p = protocolo(
        a,
        "Política de navegador: acuerdo de llaves poscuántico desactivado".to_string(),
        "tls",
        "navegadores-web",
    );
    p.ubicaciones.clear();
    p.agregar_ubicacion(
        a.ruta,
        Some(linea_de(a.contenido, i.min(a.contenido.len()))),
    );
    p.advertir("PostQuantumKeyAgreementEnabled = false impide que el navegador negocie X25519MLKEM768 en las versiones que respetan la política: el tráfico queda expuesto a «capturar ahora, descifrar después».");
    p.riesgo_fijado = Some(Riesgo::VulnerableCuantico);
    Some(p)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn archivo<'a>(ruta: &'a str, contenido: &'a [u8]) -> Archivo<'a> {
        Archivo::nuevo(ruta, std::path::Path::new(ruta), contenido, None)
    }

    #[test]
    fn versiones() {
        assert_eq!(version_tls("TLSv1_2"), Some("TLSv1.2"));
        assert_eq!(version_tls("VersionTLS10"), Some("TLSv1"));
        assert_eq!(version_tls("tls1.3"), Some("TLSv1.3"));
        assert_eq!(version_tls("3.3"), Some("TLSv1.2"));
        assert_eq!(version_tls("SSLv3"), Some("SSLv3"));
        assert_eq!(version_tls("TLS1_1"), Some("TLSv1.1"));
        assert_eq!(version_tls("x"), None);
        assert_eq!(rango_versiones("TLSv1.2", None), vec!["TLSv1.2", "TLSv1.3"]);
    }

    #[test]
    fn openssl_cnf() {
        let c = Conocimiento::embebido();
        let t = b"openssl_conf = init\n[req]\ndefault_bits = 1024\ndefault_md = sha1\n[system_default_sect]\nMinProtocol = TLSv1\nCipherString = DEFAULT@SECLEVEL=1\nGroups = X25519MLKEM768:X25519\n[provider_sect]\nlegacy = legacy_sect\n[legacy_sect]\nactivate = 1\n";
        let a = archivo("etc/ssl/openssl.cnf", t);
        assert!(EscanerOpenssl.aplica(&a));
        let v = EscanerOpenssl.analizar(&a, &c).unwrap();
        assert!(v.iter().any(|x| x.referencia == "algoritmo:rsa-1024"));
        assert!(v.iter().any(|x| x.algoritmo_id() == Some("sha1")));
        let p = v
            .iter()
            .find(|x| x.referencia.starts_with("protocolo:"))
            .unwrap();
        assert_eq!(p.riesgo_fijado, Some(Riesgo::Obsoleto));
        assert!(p.advertencias.iter().any(|w| w.contains("legacy")));
        assert!(p.advertencias.iter().any(|w| w.contains("SECLEVEL=1")));
        if let Detalles::Protocolo {
            versiones, grupos, ..
        } = &p.detalles
        {
            assert_eq!(versiones.len(), 4);
            assert_eq!(grupos, &["X25519MLKEM768", "X25519"]);
        }
    }

    #[test]
    fn crypto_policies_y_gnutls() {
        let c = Conocimiento::embebido();
        let a = archivo("etc/crypto-policies/config", b"# comentario\nLEGACY:SHA1\n");
        assert!(EscanerCryptoPolicies.aplica(&a));
        let v = EscanerCryptoPolicies.analizar(&a, &c).unwrap();
        assert_eq!(v[0].riesgo_fijado, Some(Riesgo::Obsoleto));
        let a = archivo(
            "etc/crypto-policies/back-ends/gnutls.config",
            b"SYSTEM=NONE:+VERS-ALL:-VERS-SSL3.0:+VERS-TLS1.0:+VERS-TLS1.2:+VERS-TLS1.3:+GROUP-X25519-MLKEM768:+GROUP-X25519\n",
        );
        assert!(EscanerGnutls.aplica(&a));
        let v = EscanerGnutls.analizar(&a, &c).unwrap();
        let p = v.last().unwrap();
        assert_eq!(p.riesgo_fijado, Some(Riesgo::Obsoleto));
        assert!(
            v.iter()
                .any(|x| x.algoritmo_id() == Some("x25519-mlkem768"))
        );
    }

    #[test]
    fn kerberos_y_politica_de_navegador() {
        let c = Conocimiento::embebido();
        let a = archivo(
            "etc/krb5.conf",
            b"[libdefaults]\n default_realm = EJEMPLO.MX\n permitted_enctypes = aes256-cts-hmac-sha1-96 rc4-hmac\n allow_weak_crypto = true\n",
        );
        let v = EscanerKerberos.analizar(&a, &c).unwrap();
        assert!(v.iter().any(|x| x.algoritmo_id() == Some("rc4")));
        assert_eq!(v.last().unwrap().riesgo_fijado, Some(Riesgo::RotoClasico));

        let j = br#"{"policies": {"PostQuantumKeyAgreementEnabled": false}}"#;
        let a = archivo("distribution/policies.json", j);
        assert!(EscanerPoliticaNavegador.aplica(&a));
        assert_eq!(EscanerPoliticaNavegador.analizar(&a, &c).unwrap().len(), 1);
        let si = br#"{"PostQuantumKeyAgreementEnabled": true}"#;
        let a = archivo("managed/politica.json", si);
        assert!(
            EscanerPoliticaNavegador
                .analizar(&a, &c)
                .unwrap()
                .is_empty()
        );
        let plist = b"<key>PostQuantumKeyAgreementEnabled</key>\n<false/>";
        assert!(pq_desactivado(std::str::from_utf8(plist).unwrap()).is_some());
    }
}
