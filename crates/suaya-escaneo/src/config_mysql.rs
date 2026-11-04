//! Escáner de configuración de MySQL y MariaDB (`my.cnf`, `*.cnf`).
//!
//! Se leen las secciones del servidor (`[mysqld]`, `[mariadb]`, `[server]` y
//! sus variantes por versión). Las opciones se aceptan con guiones o guiones
//! bajos, como hace el propio servidor.

use std::path::Path;

use suaya_core::{Activo, Conocimiento, Detalles, Garantia, Riesgo};

use crate::Escaner;
use crate::comun::{Archivo, REL_RUTA_CERTIFICADO, id_corto, linea_de};
use crate::config_tls::evaluar_tls;

/// Decisión de Suaya: el servidor de base de datos termina TLS como un
/// servidor web, así que se evalúa con la madurez de esa capacidad (igual
/// que PostgreSQL).
const CAPACIDAD: &str = "servidores-web";
const SIN_GRUPOS: &str = "La configuración no fija los grupos de intercambio de llaves de TLS: el servidor usa los predeterminados de su biblioteca OpenSSL (desde OpenSSL 3.5 incluyen X25519MLKEM768; antes solo hay grupos clásicos). Verifique la versión de OpenSSL enlazada.";

pub struct EscanerConfigMysql;

fn es_seccion_servidor(s: &str) -> bool {
    let s = s.trim().to_lowercase();
    s == "mysqld"
        || s == "mariadb"
        || s == "server"
        || s == "mysqld_safe"
        || s.starts_with("mysqld-")
        || s.starts_with("mariadb-")
        || s.starts_with("mysqld.")
}

fn verdadero(v: &str) -> bool {
    matches!(
        v.trim().to_lowercase().as_str(),
        "" | "on" | "1" | "true" | "yes" | "force_plus_permanent" | "force"
    )
}

impl Escaner for EscanerConfigMysql {
    fn nombre(&self) -> &'static str {
        "configuración de MySQL/MariaDB"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        (a.nombre.ends_with(".cnf") || a.nombre == "my.ini")
            && (a.contiene(b"[mysqld") || a.contiene(b"[mariadb") || a.contiene(b"[server]"))
    }

    fn analizar(&self, a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
        let texto = a.texto().ok_or("el archivo no es texto UTF-8")?;
        let mut valores: Vec<(String, String, u32)> = Vec::new();
        let mut en_servidor = false;
        let mut mariadb = false;
        let mut desplazamiento = 0usize;
        for linea in texto.split_inclusive('\n') {
            let numero = linea_de(a.contenido, desplazamiento);
            desplazamiento += linea.len();
            let l = linea.trim();
            if l.is_empty() || l.starts_with('#') || l.starts_with(';') {
                continue;
            }
            if let Some(s) = l.strip_prefix('[').and_then(|r| r.split(']').next()) {
                en_servidor = es_seccion_servidor(s);
                mariadb |= s.to_lowercase().starts_with("mariadb");
                continue;
            }
            if !en_servidor {
                continue;
            }
            let (clave, valor) = match l.split_once('=') {
                Some((k, v)) => (k, v),
                None => (l, ""),
            };
            let clave = clave.trim().to_lowercase().replace('-', "_");
            let valor = valor
                .split('#')
                .next()
                .unwrap_or("")
                .trim()
                .trim_matches(['"', '\''])
                .to_string();
            valores.push((clave, valor, numero));
        }
        let valor = |k: &str| {
            valores
                .iter()
                .rev()
                .find(|(c, _, _)| c == k)
                .map(|(_, v, n)| (v.clone(), *n))
        };
        let hay_tls = |k: &str| valores.iter().any(|(c, _, _)| c.starts_with(k));
        if valores.is_empty() {
            return Ok(Vec::new());
        }

        let referencia = format!("protocolo:tls:{}", id_corto(&a.ruta_estable));
        let nombre = format!("MySQL/MariaDB ({})", a.nombre);
        let enlace = valor("bind_address").map(|(v, _)| v);
        let solo_local = valor("skip_networking").is_some()
            || enlace.as_deref().is_some_and(|b| {
                b.split(',')
                    .map(str::trim)
                    .all(|d| matches!(d, "localhost" | "127.0.0.1" | "::1"))
            });

        let deshabilitado = valor("skip_ssl").is_some()
            || valor("ssl").is_some_and(|(v, _)| !verdadero(&v))
            || valor("tls_version").is_some_and(|(v, _)| v.trim().is_empty());
        let linea_ssl = valor("ssl")
            .or_else(|| valor("skip_ssl"))
            .or_else(|| valor("ssl_cert"))
            .or_else(|| valor("tls_version"))
            .map(|(_, n)| n);

        if deshabilitado {
            if solo_local {
                return Ok(Vec::new());
            }
            let mut p = Activo::nuevo(
                referencia,
                nombre,
                Detalles::Protocolo {
                    tipo_protocolo: "tls".into(),
                    versiones: Vec::new(),
                    grupos: Vec::new(),
                    cifrados: Vec::new(),
                },
            )
            .con_contexto(CAPACIDAD, Garantia::Confidencialidad)
            .con_ubicacion(a.ruta, linea_ssl);
            p.riesgo_fijado = Some(Riesgo::RotoClasico);
            p.advertir(
                "TLS deshabilitado en el servidor: las consultas, los resultados y las credenciales viajan sin cifrar.",
            );
            return Ok(vec![p]);
        }

        // MySQL 5.7 y posteriores activan TLS por omisión; MariaDB, solo
        // desde 11.4. Sin opciones de TLS en MariaDB no se puede afirmar.
        if mariadb && !hay_tls("ssl") && !hay_tls("tls") {
            if solo_local {
                return Ok(Vec::new());
            }
            let mut p = Activo::nuevo(
                referencia,
                nombre,
                Detalles::Protocolo {
                    tipo_protocolo: "tls".into(),
                    versiones: Vec::new(),
                    grupos: Vec::new(),
                    cifrados: Vec::new(),
                },
            )
            .con_contexto(CAPACIDAD, Garantia::Confidencialidad)
            .con_ubicacion(a.ruta, None);
            p.riesgo_fijado = Some(Riesgo::Desconocido);
            p.advertir(
                "MariaDB sin opciones de TLS: antes de la versión 11.4 el servidor no cifra por omisión. Declare ssl_cert, ssl_key y require_secure_transport=ON.",
            );
            return Ok(vec![p]);
        }

        let (versiones, linea_versiones) = match valor("tls_version") {
            Some((v, n)) => (
                v.split(',')
                    .map(|x| x.trim().to_string())
                    .filter(|x| !x.is_empty())
                    .collect::<Vec<_>>(),
                Some(n),
            ),
            None => (vec!["TLSv1.2".to_string(), "TLSv1.3".to_string()], None),
        };
        let mut protocolo = Activo::nuevo(
            referencia,
            nombre,
            Detalles::Protocolo {
                tipo_protocolo: "tls".into(),
                versiones: versiones.clone(),
                grupos: Vec::new(),
                cifrados: valor("ssl_cipher")
                    .into_iter()
                    .chain(valor("tls_ciphersuites"))
                    .map(|(v, _)| v)
                    .collect(),
            },
        )
        .con_contexto(CAPACIDAD, Garantia::Confidencialidad)
        .con_ubicacion(a.ruta, linea_versiones.or(linea_ssl));
        if linea_versiones.is_none() {
            protocolo.advertir(
                "No declara tls_version: se asume el predeterminado de las versiones actuales (TLSv1.2 y TLSv1.3).",
            );
        }
        evaluar_tls(
            &mut protocolo,
            &versiones,
            None,
            SIN_GRUPOS,
            Riesgo::Desconocido,
            c,
        );

        if !valor("require_secure_transport").is_some_and(|(v, _)| verdadero(&v)) && !solo_local {
            protocolo.advertir(
                "No exige transporte cifrado (require_secure_transport=ON): un cliente puede conectarse sin TLS y exponer sus credenciales.",
            );
        }

        // Las rutas relativas se resuelven contra el directorio de datos.
        match valor("ssl_cert") {
            Some((cert, _)) => {
                let ruta_cert = if Path::new(&cert).is_absolute() {
                    cert
                } else {
                    let base = valor("datadir")
                        .map(|(d, _)| d)
                        .or_else(|| Path::new(a.ruta).parent().map(|p| p.display().to_string()))
                        .unwrap_or_default();
                    Path::new(&base).join(&cert).display().to_string()
                };
                protocolo.relacionar(REL_RUTA_CERTIFICADO, &ruta_cert);
            }
            None if !mariadb => protocolo.advertir(
                "Sin ssl_cert, MySQL usa el certificado autofirmado que genera en su directorio de datos (RSA de 2048 bits): los clientes no pueden verificar la identidad del servidor.",
            ),
            None => {}
        }
        Ok(vec![protocolo])
    }
}
