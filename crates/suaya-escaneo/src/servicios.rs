//! Configuración TLS de servicios descrita como datos (`conocimiento/servicios.toml`).
//!
//! Cada servicio declara en qué archivos y con qué claves fija sus versiones
//! de TLS, sus cifradores y sus curvas. Este escáner es genérico: busca esas
//! claves en las formas habituales (`clave = valor`, `clave: valor`,
//! `clave valor` o el atributo XML `clave="valor"`) y evalúa lo encontrado con
//! el mismo criterio que nginx o Apache.

use std::collections::BTreeMap;

use regex::Regex;
use suaya_core::{Activo, Conocimiento, Detalles, Garantia, Riesgo, ServicioDef};

use crate::Escaner;
use crate::comun::{Archivo, id_corto, linea_de, por_alias};
use crate::config_sistema::{advertencias_cifrados, agravar, rango_versiones, version_tls};
use crate::config_tls::evaluar_tls;

/// Coincidencia de un nombre de archivo con un patrón con «*».
fn coincide_archivo(patron: &str, nombre: &str) -> bool {
    let p = patron.to_ascii_lowercase();
    let partes: Vec<&str> = p.split('*').collect();
    if partes.len() == 1 {
        return p == nombre;
    }
    let mut resto = nombre;
    for (i, parte) in partes.iter().enumerate() {
        if i == 0 {
            match resto.strip_prefix(parte) {
                Some(r) => resto = r,
                None => return false,
            }
        } else if i == partes.len() - 1 {
            return resto.ends_with(parte);
        } else {
            match resto.find(parte) {
                Some(j) => resto = &resto[j + parte.len()..],
                None => return false,
            }
        }
    }
    true
}

fn aplica_servicio(s: &ServicioDef, a: &Archivo) -> bool {
    s.archivos.iter().any(|p| coincide_archivo(p, &a.nombre))
        && (s.pistas.is_empty() || s.pistas.iter().any(|p| a.contiene(p.as_bytes())))
}

/// Expresiones que extraen el valor de una clave en sus formas habituales.
fn expresiones(clave: &str) -> std::sync::Arc<(Regex, Regex)> {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock};
    type Cache = Mutex<HashMap<String, Arc<(Regex, Regex)>>>;
    static CACHE: OnceLock<Cache> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if let Some(x) = cache.lock().ok().and_then(|m| m.get(clave).cloned()) {
        return x;
    }
    let nuevas = Arc::new(compilar_clave(clave));
    if let Ok(mut m) = cache.lock()
        && m.len() < 4096
    {
        m.insert(clave.to_string(), nuevas.clone());
    }
    nuevas
}

fn compilar_clave(clave: &str) -> (Regex, Regex) {
    // Insensible a mayúsculas solo en las partes literales (ASCII) de la clave.
    let k = clave
        .split('*')
        .map(|parte| {
            if parte.is_empty() {
                String::new()
            } else {
                format!("(?i-u:{})", regex::escape(parte))
            }
        })
        .collect::<Vec<_>>()
        .join(r#"[^\s=:"']*"#);
    let linea = Regex::new(&format!(
        r#"(?m)^[ \t]*-?[ \t]*["']?{k}["']?[ \t]*(?:=|:|[ \t])[ \t]*(.*?)[ \t]*;?[ \t]*$"#
    ))
    .expect("expresión de clave válida");
    let atributo = Regex::new(&format!(r#"\b{k}\s*=\s*["']([^"']*)["']"#))
        .expect("expresión de atributo válida");
    (linea, atributo)
}

/// Sustituye los comentarios XML por espacios sin mover el resto del texto.
fn sin_comentarios_xml(texto: &str) -> String {
    let mut s = texto.as_bytes().to_vec();
    let mut i = 0;
    while let Some(p) = texto[i..].find("<!--") {
        let inicio = i + p;
        let fin = texto[inicio..]
            .find("-->")
            .map_or(texto.len(), |q| inicio + q + 3);
        for x in &mut s[inicio..fin] {
            if *x != b'\n' {
                *x = b' ';
            }
        }
        i = fin;
    }
    String::from_utf8(s).unwrap_or_else(|_| texto.to_string())
}

/// Elementos de una lista YAML en bloque que sigue a la línea `desde`.
fn lista_yaml(texto: &str, desde: usize) -> String {
    let mut v = Vec::new();
    for l in texto[desde..].lines().skip(1) {
        match l.trim_start().strip_prefix("- ") {
            Some(x) => v.push(x.trim().trim_matches(['"', '\'']).to_string()),
            None if l.trim().is_empty() => continue,
            None => break,
        }
        if v.len() >= 64 {
            break;
        }
    }
    v.join(",")
}

/// Valores declarados para una clave, con su línea; omite comentarios.
fn valores(a: &Archivo, texto: &str, clave: &str) -> Vec<(String, u32)> {
    let par = expresiones(clave);
    let mut v = Vec::new();
    for re in [&par.0, &par.1] {
        for c in re.captures_iter(texto).take(200) {
            let inicio = c.get(0).map_or(0, |m| m.start());
            let inicio_linea = texto[..inicio].rfind('\n').map_or(0, |i| i + 1);
            let l = texto[inicio_linea..].trim_start();
            if l.starts_with('#')
                || l.starts_with(';')
                || l.starts_with("//")
                || l.starts_with("<!--")
            {
                continue;
            }
            let crudo = c.get(1).map_or("", |m| m.as_str());
            // Comentario al final de la línea en formatos que lo admiten.
            let crudo = crudo.split(" #").next().unwrap_or(crudo);
            let mut limpio = crudo
                .trim()
                .trim_matches(['"', '\'', '[', ']', '(', ')', '{', '}'])
                .trim()
                .to_string();
            if limpio.is_empty() {
                limpio = lista_yaml(texto, inicio);
            }
            let limpio = limpio.as_str();
            if v.iter()
                .any(|(x, l): &(String, u32)| *x == limpio && *l == linea_de(a.contenido, inicio))
            {
                continue;
            }
            v.push((limpio.to_string(), linea_de(a.contenido, inicio)));
        }
    }
    v
}

fn elementos(valor: &str) -> Vec<String> {
    valor
        .split([',', ' ', '\t', ':', '+', ';'])
        .map(|t| t.trim().trim_matches(['"', '\'', '[', ']']).to_string())
        .filter(|t| !t.is_empty())
        .collect()
}

/// Nombres de grupo de Go, Envoy u OpenSSL en la forma de los alias TLS.
fn nombre_grupo(g: &str) -> String {
    let n = g.to_ascii_lowercase().replace(['_', '-'], "");
    match n.as_str() {
        "curvep256" | "p256" | "prime256v1" => "secp256r1".into(),
        "curvep384" | "p384" => "secp384r1".into(),
        "curvep521" | "p521" => "secp521r1".into(),
        _ => n,
    }
}

pub struct EscanerServicios;

impl Escaner for EscanerServicios {
    fn nombre(&self) -> &'static str {
        "configuración TLS de servicios"
    }

    fn aplica(&self, _a: &Archivo) -> bool {
        // La lista de servicios vive en la base de conocimiento; se decide en `analizar`.
        true
    }

    fn analizar(&self, a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
        let servicios: Vec<&ServicioDef> = c
            .servicios
            .servicios
            .iter()
            .filter(|s| aplica_servicio(s, a))
            .collect();
        if servicios.is_empty() {
            return Ok(Vec::new());
        }
        let Some(texto) = a.texto() else {
            return Ok(Vec::new());
        };
        let limpio;
        let texto = if a.extension == "xml" || texto.contains("<!--") {
            limpio = sin_comentarios_xml(texto);
            limpio.as_str()
        } else {
            texto
        };
        let mut activos = Vec::new();
        for s in servicios {
            activos.extend(analizar_servicio(s, a, texto, c));
        }
        Ok(activos)
    }
}

fn analizar_servicio(s: &ServicioDef, a: &Archivo, texto: &str, c: &Conocimiento) -> Vec<Activo> {
    let cap = s.capacidad.as_str();
    let de = |claves: &[String]| -> Vec<(String, u32)> {
        claves.iter().flat_map(|k| valores(a, texto, k)).collect()
    };
    let mut versiones: Vec<String> = Vec::new();
    let mut excluidas: Vec<String> = Vec::new();
    for (v, _) in de(&s.versiones) {
        for t in elementos(&v) {
            let (fuera, nombre) = match t.strip_prefix(['!', '-']) {
                Some(r) => (true, r.to_string()),
                None => (false, t.clone()),
            };
            if nombre.eq_ignore_ascii_case("all") {
                if !fuera {
                    versiones.extend(rango_versiones("TLSv1", None));
                }
                continue;
            }
            if let Some(x) = version_tls(&nombre) {
                if fuera {
                    excluidas.push(x.into());
                } else {
                    versiones.push(x.into());
                }
            }
        }
    }
    let minimas = de(&s.version_minima);
    let maxima = de(&s.version_maxima)
        .first()
        .and_then(|(v, _)| version_tls(v))
        .map(str::to_string);
    if let Some((v, _)) = minimas.first() {
        let partes = elementos(v);
        if let Some(min) = partes.first().and_then(|x| version_tls(x)) {
            let max = maxima.clone().or_else(|| {
                partes
                    .get(1)
                    .and_then(|x| version_tls(x))
                    .map(str::to_string)
            });
            versiones.extend(rango_versiones(min, max.as_deref()));
        }
    }
    for (v, _) in de(&s.versiones_excluidas) {
        excluidas.extend(
            elementos(&v)
                .iter()
                .filter_map(|x| version_tls(x))
                .map(str::to_string),
        );
    }
    versiones.retain(|v| !excluidas.contains(v));
    versiones.sort_by_key(|v| {
        ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
            .iter()
            .position(|o| o == v)
    });
    versiones.dedup();

    let cifrados: Vec<(String, u32)> = de(&s.cifrados);
    let mut algoritmos: BTreeMap<String, Activo> = BTreeMap::new();
    let mut grupos: Vec<String> = Vec::new();
    for (v, l) in de(&s.grupos) {
        for g in elementos(&v) {
            let n = nombre_grupo(&g);
            if !grupos.contains(&n) {
                grupos.push(n.clone());
            }
            let x = por_alias(
                c,
                "tls-grupo",
                &n,
                cap,
                Some(Garantia::Confidencialidad),
                a.ruta,
                Some(l),
            );
            algoritmos.entry(x.referencia.clone()).or_insert(x);
        }
    }
    let mut riesgos_algoritmos: Vec<Riesgo> = Vec::new();
    for lista in &s.algoritmos {
        for (v, l) in valores(a, texto, &lista.clave) {
            for t in elementos(&v) {
                let x = por_alias(c, &lista.espacio, &t, cap, None, a.ruta, Some(l));
                if let Some(d) = x.algoritmo_id().and_then(|i| c.por_id(i)) {
                    riesgos_algoritmos.push(d.riesgo);
                }
                algoritmos.entry(x.referencia.clone()).or_insert(x);
            }
        }
    }
    let mut avisos: Vec<(String, Riesgo, u32)> = Vec::new();
    for aviso in &s.avisos {
        for (v, l) in valores(a, texto, &aviso.clave) {
            let v = v.to_ascii_lowercase();
            if aviso.valores.iter().any(|x| x.to_ascii_lowercase() == v) {
                avisos.push((aviso.texto.clone(), aviso.riesgo, l));
            }
        }
    }
    if versiones.is_empty()
        && excluidas.is_empty()
        && cifrados.is_empty()
        && grupos.is_empty()
        && algoritmos.is_empty()
        && avisos.is_empty()
    {
        return Vec::new();
    }

    let mut p = Activo::nuevo(
        format!(
            "protocolo:tls:{}",
            id_corto(&format!("{}#{}", a.ruta_estable, s.id))
        ),
        format!("{} ({})", s.nombre, a.nombre),
        Detalles::Protocolo {
            tipo_protocolo: "tls".into(),
            versiones: versiones.clone(),
            grupos: grupos.clone(),
            cifrados: cifrados.iter().map(|(v, _)| v.clone()).collect(),
        },
    )
    .con_contexto(cap, Garantia::Confidencialidad)
    .con_ubicacion(a.ruta, None);
    if let Some(n) = &s.nota {
        p.advertir(n.clone());
    }
    if !excluidas.is_empty() {
        p.advertir(format!(
            "Versiones deshabilitadas explícitamente: {}.",
            excluidas.join(", ")
        ));
    }
    if !versiones.is_empty() || !grupos.is_empty() {
        evaluar_tls(
            &mut p,
            &versiones,
            (!grupos.is_empty()).then_some(grupos.as_slice()),
            "No declara grupos de intercambio de llaves: dependen de la biblioteca TLS del servicio. Sondee el servicio con «suaya sondear».",
            Riesgo::Desconocido,
            c,
        );
    } else {
        p.advertir("No declara las versiones de TLS: dependen de los valores predeterminados del servicio. Sondee el servicio con «suaya sondear».");
        p.riesgo_fijado = Some(Riesgo::Desconocido);
    }
    for (v, _) in &cifrados {
        let (avs, r) = advertencias_cifrados(v);
        for x in avs {
            p.advertir(x);
        }
        if let Some(r) = r {
            agravar(&mut p, r);
        }
    }
    for r in riesgos_algoritmos {
        if matches!(r, Riesgo::RotoClasico | Riesgo::Obsoleto) {
            agravar(&mut p, r);
        }
    }
    for (texto, r, l) in &avisos {
        p.advertir(format!("{texto} [línea {l}]"));
        agravar(&mut p, *r);
    }
    let mut v: Vec<Activo> = algoritmos.into_values().collect();
    for x in &v {
        p.relacionar("algorithm", &x.referencia);
    }
    v.push(p);
    v
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn analizar(ruta: &str, t: &[u8]) -> Vec<Activo> {
        let a = Archivo::nuevo(ruta, std::path::Path::new(ruta), t, None);
        EscanerServicios
            .analizar(&a, &Conocimiento::embebido())
            .unwrap()
    }

    fn protocolo(v: &[Activo]) -> &Activo {
        v.iter()
            .find(|x| x.referencia.starts_with("protocolo:"))
            .unwrap()
    }

    #[test]
    fn patrones_de_archivo() {
        assert!(coincide_archivo("*.properties", "server.properties"));
        assert!(coincide_archivo("application*.yml", "application-prod.yml"));
        assert!(!coincide_archivo("application*.yml", "app.yml"));
        assert!(coincide_archivo("server.xml", "server.xml"));
    }

    #[test]
    fn kafka_tomcat_y_dovecot() {
        let v = analizar(
            "config/server.properties",
            b"ssl.enabled.protocols=TLSv1.2,TLSv1.1\nssl.cipher.suites=TLS_RSA_WITH_AES_128_CBC_SHA\nsecurity.inter.broker.protocol=PLAINTEXT\n",
        );
        let p = protocolo(&v);
        assert_eq!(p.riesgo_fijado, Some(Riesgo::RotoClasico));
        if let Detalles::Protocolo { versiones, .. } = &p.detalles {
            assert_eq!(versiones, &["TLSv1.1", "TLSv1.2"]);
        }
        let v = analizar(
            "conf/server.xml",
            br#"<Connector port="8443" SSLEnabled="true"><SSLHostConfig protocols="TLSv1.2+TLSv1.3" ciphers="ECDHE-RSA-AES256-GCM-SHA384"/></Connector><!-- protocols="SSLv3" -->"#,
        );
        if let Detalles::Protocolo { versiones, .. } = &protocolo(&v).detalles {
            assert_eq!(versiones, &["TLSv1.2", "TLSv1.3"]);
        }
        let v = analizar(
            "etc/dovecot/conf.d/10-ssl.conf",
            b"ssl = yes\nssl_min_protocol = TLSv1.2\n#ssl_min_protocol = TLSv1\nssl_curve_list = X25519MLKEM768:X25519\n",
        );
        let p = protocolo(&v);
        assert_eq!(p.riesgo_fijado, Some(Riesgo::HibridoPq));
        assert!(
            v.iter()
                .any(|x| x.algoritmo_id() == Some("x25519-mlkem768"))
        );
    }

    #[test]
    fn oracle_mongodb_y_traefik() {
        let v = analizar(
            "network/admin/sqlnet.ora",
            b"SQLNET.ENCRYPTION_SERVER = ACCEPTED\nSQLNET.ENCRYPTION_TYPES_SERVER = (AES256, RC4_128, DES)\nSQLNET.ALLOWED_LOGON_VERSION_SERVER = 11\n",
        );
        assert!(v.iter().any(|x| x.algoritmo_id() == Some("rc4")));
        assert!(v.iter().any(|x| x.algoritmo_id() == Some("aes-256-cbc")));
        let p = protocolo(&v);
        assert_eq!(p.riesgo_fijado, Some(Riesgo::RotoClasico));
        assert!(p.advertencias.iter().any(|w| w.contains("verificadores")));

        let v = analizar(
            "etc/mongod.conf",
            b"net:\n  tls:\n    mode: preferTLS\n    disabledProtocols: TLS1_0,TLS1_1\n",
        );
        let p = protocolo(&v);
        assert_eq!(p.riesgo_fijado, Some(Riesgo::RotoClasico));

        let v = analizar(
            "traefik.yml",
            b"tls:\n  options:\n    default:\n      minVersion: VersionTLS12\n      curvePreferences:\n        - X25519MLKEM768\n        - CurveP256\n",
        );
        let p = protocolo(&v);
        if let Detalles::Protocolo { versiones, .. } = &p.detalles {
            assert_eq!(versiones, &["TLSv1.2", "TLSv1.3"]);
        }
        assert!(
            v.iter()
                .any(|x| x.algoritmo_id() == Some("x25519-mlkem768"))
        );
        assert!(v.iter().any(|x| x.algoritmo_id() == Some("ecdh-p256")));
        assert_eq!(p.riesgo_fijado, Some(Riesgo::HibridoPq));
    }
}
