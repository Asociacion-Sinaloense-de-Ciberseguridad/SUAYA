//! Escáner de configuración TLS de servidores web (nginx y Apache httpd).
//!
//! Determina las versiones de TLS habilitadas y los grupos de intercambio de
//! llaves declarados, para saber si el servidor puede negociar un híbrido
//! poscuántico como `X25519MLKEM768`.

use suaya_core::{Activo, Conocimiento, Detalles, Garantia, Riesgo};

use crate::Escaner;
use crate::comun::{Archivo, REL_RUTA_CERTIFICADO, id_corto, linea_de, por_alias};

const CAPACIDAD: &str = "servidores-web";
/// Directivas que identifican una configuración TLS de nginx o Apache.
/// Otros servidores (PostgreSQL, Postfix, HAProxy) tendrán su propio escáner.
const PISTAS: &[&[u8]] = &[
    b"ssl_certificate",
    b"ssl_protocols",
    b"SSLProtocol",
    b"SSLCertificateFile",
    b"SSLEngine",
];

pub struct EscanerConfigTls;

impl Escaner for EscanerConfigTls {
    fn nombre(&self) -> &'static str {
        "configuración TLS"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        PISTAS.iter().any(|p| a.contiene(p))
    }

    fn analizar(&self, a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
        let texto = a.texto().ok_or("el archivo no es texto UTF-8")?;
        let mut versiones: Option<Vec<String>> = None;
        let mut grupos: Option<Vec<String>> = None;
        let mut cifrados: Vec<String> = Vec::new();
        let mut rutas_cert: Vec<String> = Vec::new();
        let mut algoritmos: Vec<Activo> = Vec::new();
        let mut es_apache = false;
        let mut desplazamiento = 0usize;

        for linea in texto.split_inclusive('\n') {
            let numero = Some(linea_de(a.contenido, desplazamiento));
            desplazamiento += linea.len();
            let l = linea.trim().trim_end_matches(';').trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            let campos: Vec<&str> = l.split_whitespace().collect();
            let Some(directiva) = campos.first() else {
                continue;
            };
            let argumentos = &campos[1..];

            match directiva.to_lowercase().as_str() {
                "ssl_protocols" => {
                    versiones
                        .get_or_insert_with(Vec::new)
                        .extend(argumentos.iter().map(|s| s.to_string()));
                }
                "sslprotocol" => {
                    es_apache = true;
                    versiones = Some(versiones_apache(argumentos));
                }
                "ssl_ecdh_curve" => {
                    if let Some(v) = argumentos.first()
                        && !v.eq_ignore_ascii_case("auto")
                    {
                        for g in v.split(':') {
                            grupos.get_or_insert_with(Vec::new).push(g.to_string());
                            algoritmos.push(por_alias(
                                c,
                                "tls-grupo",
                                g,
                                CAPACIDAD,
                                Some(Garantia::Confidencialidad),
                                a.ruta,
                                numero,
                            ));
                        }
                    }
                }
                "ssl_conf_command" | "sslopensslconfcmd" => {
                    es_apache |= directiva.eq_ignore_ascii_case("SSLOpenSSLConfCmd");
                    if let [cmd, valor, ..] = argumentos
                        && (cmd.eq_ignore_ascii_case("groups")
                            || cmd.eq_ignore_ascii_case("curves"))
                    {
                        for g in valor.split(':') {
                            grupos.get_or_insert_with(Vec::new).push(g.to_string());
                            algoritmos.push(por_alias(
                                c,
                                "tls-grupo",
                                g,
                                CAPACIDAD,
                                Some(Garantia::Confidencialidad),
                                a.ruta,
                                numero,
                            ));
                        }
                    }
                }
                "ssl_ciphers" | "sslciphersuite" => {
                    cifrados.extend(argumentos.iter().map(|s| s.trim_matches('"').to_string()))
                }
                "ssl_certificate" | "sslcertificatefile" => {
                    if let Some(r) = argumentos.first() {
                        rutas_cert.push(r.trim_matches('"').to_string());
                    }
                }
                _ => {}
            }
        }

        let mut protocolo = Activo::nuevo(
            format!("protocolo:tls:{}", id_corto(&a.ruta_estable)),
            format!("Configuración TLS ({})", a.nombre),
            Detalles::Protocolo {
                tipo_protocolo: "tls".into(),
                versiones: Vec::new(),
                grupos: grupos.clone().unwrap_or_default(),
                cifrados,
            },
        )
        .con_contexto(CAPACIDAD, Garantia::Confidencialidad)
        .con_ubicacion(a.ruta, None);

        let versiones = match versiones {
            Some(v) => v,
            None if es_apache => {
                protocolo.advertir(
                    "SSLProtocol no se declara; depende de la versión de Apache y OpenSSL.",
                );
                Vec::new()
            }
            None => {
                protocolo.advertir("ssl_protocols no se declara; se asume el predeterminado de nginx 1.23.4 o posterior (TLSv1.2 TLSv1.3).");
                vec!["TLSv1.2".into(), "TLSv1.3".into()]
            }
        };
        if let Detalles::Protocolo { versiones: v, .. } = &mut protocolo.detalles {
            *v = versiones.clone();
        }

        evaluar_tls(
            &mut protocolo,
            &versiones,
            grupos.as_deref(),
            SIN_GRUPOS_OPENSSL,
            Riesgo::Desconocido,
            c,
        );

        for alg in &algoritmos {
            protocolo.relacionar("algorithm", &alg.referencia);
        }
        for r in rutas_cert {
            protocolo.relacionar(REL_RUTA_CERTIFICADO, &r);
        }

        let mut activos = algoritmos;
        activos.push(protocolo);
        Ok(activos)
    }
}

/// Advertencia para servidores que delegan los grupos en OpenSSL.
pub(crate) const SIN_GRUPOS_OPENSSL: &str = "No declara grupos de intercambio de llaves: con OpenSSL 3.5 o posterior el predeterminado incluye X25519MLKEM768; con versiones anteriores solo hay grupos clásicos. Verificar la versión de OpenSSL o sondear el servicio con «suaya sondear».";

/// Fija el riesgo de una configuración TLS declarada a partir de sus
/// versiones habilitadas y sus grupos (si se declaran).
pub(crate) fn evaluar_tls(
    protocolo: &mut Activo,
    versiones: &[String],
    grupos: Option<&[String]>,
    aviso_sin_grupos: &str,
    riesgo_sin_grupos: Riesgo,
    c: &Conocimiento,
) {
    let tiene_13 = versiones.iter().any(|v| v.eq_ignore_ascii_case("TLSv1.3"));
    let tiene_12 = versiones.iter().any(|v| v.eq_ignore_ascii_case("TLSv1.2"));
    let mut candidatos: Vec<Riesgo> = versiones
        .iter()
        .filter_map(|v| c.por_alias("tls-protocolo", v).map(|d| d.riesgo))
        .filter(|r| matches!(r, Riesgo::RotoClasico | Riesgo::Obsoleto))
        .collect();
    if !candidatos.is_empty() {
        protocolo.advertir("Habilita versiones de SSL/TLS rotas u obsoletas (RFC 8996).");
    }

    let riesgo_grupos = match grupos {
        _ if !tiene_13 && !versiones.is_empty() => {
            protocolo.advertir("Sin TLS 1.3 no es posible negociar grupos híbridos poscuánticos.");
            Riesgo::VulnerableCuantico
        }
        None => {
            protocolo.advertir(aviso_sin_grupos);
            riesgo_sin_grupos
        }
        Some(gs) => {
            let rs: Vec<Riesgo> = gs
                .iter()
                .map(|g| {
                    c.por_alias("tls-grupo", g)
                        .map(|d| d.riesgo)
                        .unwrap_or(Riesgo::Desconocido)
                })
                .collect();
            if rs
                .iter()
                .any(|r| matches!(r, Riesgo::HibridoPq | Riesgo::ResistenteCuantico))
            {
                if rs.contains(&Riesgo::VulnerableCuantico) {
                    protocolo.advertir("También acepta grupos clásicos: los clientes antiguos negociarán sin protección poscuántica.");
                }
                if tiene_12 {
                    protocolo.advertir(
                        "TLS 1.2 sigue habilitado: esas conexiones no pueden usar grupos híbridos.",
                    );
                }
                Riesgo::HibridoPq
            } else {
                Riesgo::VulnerableCuantico
            }
        }
    };
    candidatos.push(riesgo_grupos);
    protocolo.riesgo_fijado = candidatos.into_iter().min_by_key(|r| r.gravedad());
}

/// Interpreta `SSLProtocol` de Apache (p. ej. `all -SSLv3 -TLSv1 -TLSv1.1`).
fn versiones_apache(argumentos: &[&str]) -> Vec<String> {
    const TODAS: [&str; 4] = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"];
    let mut v: Vec<String> = Vec::new();
    for arg in argumentos {
        let (signo, nombre) = match arg.chars().next() {
            Some('+') => ('+', &arg[1..]),
            Some('-') => ('-', &arg[1..]),
            _ => ('=', *arg),
        };
        let nombres: Vec<String> = if nombre.eq_ignore_ascii_case("all") {
            TODAS.iter().map(|s| s.to_string()).collect()
        } else {
            vec![nombre.to_string()]
        };
        for n in nombres {
            match signo {
                '-' => v.retain(|x| !x.eq_ignore_ascii_case(&n)),
                _ => {
                    if !v.iter().any(|x| x.eq_ignore_ascii_case(&n)) {
                        v.push(n)
                    }
                }
            }
        }
    }
    v
}

#[cfg(test)]
mod pruebas {
    use super::versiones_apache;

    #[test]
    fn apache_all_menos_viejas() {
        assert_eq!(
            versiones_apache(&["all", "-SSLv3", "-TLSv1", "-TLSv1.1"]),
            vec!["TLSv1.2", "TLSv1.3"]
        );
        assert_eq!(versiones_apache(&["-all", "+TLSv1.3"]), vec!["TLSv1.3"]);
    }
}
