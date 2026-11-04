//! Escáner de configuración de HAProxy (`haproxy.cfg`).
//!
//! Evalúa cada línea `bind ... ssl` combinando sus opciones con los valores
//! predeterminados de la sección `global` (`ssl-default-bind-*`).

use suaya_core::{Activo, Conocimiento, Detalles, Garantia, Riesgo};

use crate::Escaner;
use crate::comun::{Archivo, REL_RUTA_CERTIFICADO, id_corto, linea_de, por_alias};
use crate::config_tls::{SIN_GRUPOS_OPENSSL, evaluar_tls};

const CAPACIDAD: &str = "servidores-web";
const VERSIONES: [&str; 5] = ["SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"];
/// Versión mínima predeterminada desde HAProxy 2.2.
const MINIMA_PREDETERMINADA: &str = "TLSv1.2";

pub struct EscanerConfigHaproxy;

impl Escaner for EscanerConfigHaproxy {
    fn nombre(&self) -> &'static str {
        "configuración de HAProxy"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        a.nombre == "haproxy.cfg" || (a.extension == "cfg" && a.ruta.contains("haproxy"))
    }

    fn analizar(&self, a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
        let texto = a.texto().ok_or("el archivo no es texto UTF-8")?;
        let mut opciones_globales: Vec<String> = Vec::new();
        let mut curvas_globales: Option<String> = None;
        let mut binds: Vec<(u32, Vec<String>)> = Vec::new();
        let mut desplazamiento = 0usize;

        for linea in texto.split_inclusive('\n') {
            let numero = linea_de(a.contenido, desplazamiento);
            desplazamiento += linea.len();
            let sin_comentario = linea.split('#').next().unwrap_or("").trim();
            let campos: Vec<String> = sin_comentario
                .split_whitespace()
                .map(str::to_string)
                .collect();
            match campos.first().map(String::as_str) {
                Some("ssl-default-bind-options") => {
                    opciones_globales.extend(campos[1..].iter().cloned())
                }
                Some("ssl-default-bind-curves") => curvas_globales = campos.get(1).cloned(),
                Some("bind") if campos.iter().any(|x| x == "ssl") => binds.push((numero, campos)),
                _ => {}
            }
        }

        let mut activos = Vec::new();
        for (numero, campos) in binds {
            let direccion = campos.get(1).cloned().unwrap_or_default();
            let mut opciones = opciones_globales.clone();
            opciones.extend(campos[2..].iter().cloned());
            let valor = |clave: &str| -> Option<String> {
                opciones
                    .iter()
                    .rposition(|x| x == clave)
                    .and_then(|i| opciones.get(i + 1).cloned())
            };

            let versiones =
                versiones_habilitadas(&opciones, valor("ssl-min-ver"), valor("ssl-max-ver"));
            let curvas = valor("curves").or_else(|| curvas_globales.clone());
            let grupos: Option<Vec<String>> =
                curvas.map(|v| v.split(':').map(str::to_string).collect());

            let mut protocolo = Activo::nuevo(
                format!(
                    "protocolo:tls:{}",
                    id_corto(&format!("{}#{numero}", a.ruta_estable))
                ),
                format!("HAProxy bind {direccion} ({})", a.nombre),
                Detalles::Protocolo {
                    tipo_protocolo: "tls".into(),
                    versiones: versiones.clone(),
                    grupos: grupos.clone().unwrap_or_default(),
                    cifrados: valor("ciphersuites")
                        .or_else(|| valor("ciphers"))
                        .into_iter()
                        .collect(),
                },
            )
            .con_contexto(CAPACIDAD, Garantia::Confidencialidad)
            .con_ubicacion(a.ruta, Some(numero));

            for g in grupos.iter().flatten() {
                let alg = por_alias(
                    c,
                    "tls-grupo",
                    g,
                    CAPACIDAD,
                    Some(Garantia::Confidencialidad),
                    a.ruta,
                    Some(numero),
                );
                protocolo.relacionar("algorithm", &alg.referencia);
                activos.push(alg);
            }
            evaluar_tls(
                &mut protocolo,
                &versiones,
                grupos.as_deref(),
                SIN_GRUPOS_OPENSSL,
                Riesgo::Desconocido,
                c,
            );
            for (i, x) in opciones.iter().enumerate() {
                if x == "crt"
                    && let Some(ruta) = opciones.get(i + 1)
                {
                    protocolo.relacionar(REL_RUTA_CERTIFICADO, ruta);
                }
            }
            activos.push(protocolo);
        }
        Ok(activos)
    }
}

/// Versiones habilitadas según `ssl-min-ver`, `ssl-max-ver`, `no-*` y `force-*`.
fn versiones_habilitadas(
    opciones: &[String],
    minima: Option<String>,
    maxima: Option<String>,
) -> Vec<String> {
    let posicion = |v: &str| VERSIONES.iter().position(|x| x.eq_ignore_ascii_case(v));
    let forzada = opciones.iter().rev().find_map(|o| match o.as_str() {
        "force-sslv3" => Some("SSLv3"),
        "force-tlsv10" => Some("TLSv1.0"),
        "force-tlsv11" => Some("TLSv1.1"),
        "force-tlsv12" => Some("TLSv1.2"),
        "force-tlsv13" => Some("TLSv1.3"),
        _ => None,
    });
    if let Some(f) = forzada {
        return vec![f.to_string()];
    }
    let desde = minima
        .as_deref()
        .and_then(posicion)
        .unwrap_or_else(|| posicion(MINIMA_PREDETERMINADA).unwrap_or(3));
    let hasta = maxima
        .as_deref()
        .and_then(posicion)
        .unwrap_or(VERSIONES.len() - 1);
    VERSIONES
        .iter()
        .enumerate()
        .filter(|(i, _)| *i >= desde && *i <= hasta)
        .map(|(_, v)| *v)
        .filter(|v| {
            let excluida = match *v {
                "SSLv3" => "no-sslv3",
                "TLSv1.0" => "no-tlsv10",
                "TLSv1.1" => "no-tlsv11",
                "TLSv1.2" => "no-tlsv12",
                _ => "no-tlsv13",
            };
            !opciones.iter().any(|o| o == excluida)
        })
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod pruebas {
    use super::versiones_habilitadas;

    fn o(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn versiones() {
        assert_eq!(
            versiones_habilitadas(&o(&[]), None, None),
            vec!["TLSv1.2", "TLSv1.3"]
        );
        assert_eq!(
            versiones_habilitadas(&o(&[]), Some("TLSv1.0".into()), None),
            vec!["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
        );
        assert_eq!(
            versiones_habilitadas(&o(&["no-tlsv12"]), None, None),
            vec!["TLSv1.3"]
        );
        assert_eq!(
            versiones_habilitadas(&o(&["force-tlsv12"]), None, None),
            vec!["TLSv1.2"]
        );
    }
}
