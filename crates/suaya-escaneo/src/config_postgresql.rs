//! Escáner de configuración de PostgreSQL (`postgresql.conf`).

use std::path::Path;

use suaya_core::{Activo, Conocimiento, Detalles, Garantia, Riesgo};

use crate::Escaner;
use crate::comun::{Archivo, REL_RUTA_CERTIFICADO, id_corto, linea_de, por_alias};
use crate::config_tls::evaluar_tls;

/// Decisión de Suaya: el servidor PostgreSQL termina TLS como un servidor
/// web, así que se evalúa con la madurez de esa capacidad.
const CAPACIDAD: &str = "servidores-web";
const VERSIONES: [&str; 4] = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"];
const SIN_GRUPOS: &str = "No declara ssl_groups ni ssl_ecdh_curve: los grupos predeterminados de PostgreSQL son clásicos. Declare un grupo híbrido (p. ej. X25519MLKEM768) si su versión de PostgreSQL y OpenSSL lo admiten.";

pub struct EscanerConfigPostgresql;

impl Escaner for EscanerConfigPostgresql {
    fn nombre(&self) -> &'static str {
        "configuración de PostgreSQL"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        a.nombre == "postgresql.conf" || a.nombre == "postgresql.auto.conf"
    }

    fn analizar(&self, a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
        let texto = a.texto().ok_or("el archivo no es texto UTF-8")?;
        let mut valores: Vec<(String, String, u32)> = Vec::new();
        let mut desplazamiento = 0usize;
        for linea in texto.split_inclusive('\n') {
            let numero = linea_de(a.contenido, desplazamiento);
            desplazamiento += linea.len();
            let l = linea.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            let (clave, resto) = match l.split_once(|ch: char| ch == '=' || ch.is_whitespace()) {
                Some((k, r)) => (
                    k.trim().to_lowercase(),
                    r.trim().trim_start_matches('=').trim(),
                ),
                None => continue,
            };
            let valor = if let Some(r) = resto.strip_prefix('\'') {
                r.split('\'').next().unwrap_or("").to_string()
            } else {
                resto.split('#').next().unwrap_or("").trim().to_string()
            };
            valores.push((clave, valor, numero));
        }
        // La última asignación de cada parámetro es la vigente.
        let valor = |k: &str| {
            valores
                .iter()
                .rev()
                .find(|(c, _, _)| c == k)
                .map(|(_, v, n)| (v.clone(), *n))
        };

        let ssl = valor("ssl")
            .map(|(v, _)| matches!(v.to_lowercase().as_str(), "on" | "true" | "yes" | "1"));
        let escucha = valor("listen_addresses")
            .map(|(v, _)| v)
            .unwrap_or_else(|| "localhost".into());
        let solo_local = escucha
            .split(',')
            .map(str::trim)
            .all(|d| matches!(d, "localhost" | "127.0.0.1" | "::1" | ""));

        let referencia = format!("protocolo:tls:{}", id_corto(&a.ruta_estable));
        let nombre = format!("PostgreSQL ({})", a.nombre);

        if ssl != Some(true) {
            // postgresql.auto.conf solo contiene ajustes puntuales.
            if solo_local || (ssl.is_none() && a.nombre == "postgresql.auto.conf") {
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
            .con_ubicacion(a.ruta, valor("ssl").map(|(_, n)| n));
            if ssl.is_none() {
                p.riesgo_fijado = Some(Riesgo::Desconocido);
                p.advertir(format!(
                    "No declara «ssl» (predeterminado: off) y escucha en «{escucha}». Si no se activa en postgresql.auto.conf o en un archivo incluido, las conexiones viajan sin cifrar."
                ));
            } else {
                p.riesgo_fijado = Some(Riesgo::RotoClasico);
                p.advertir(format!(
                    "SSL deshabilitado y escucha en «{escucha}»: las conexiones a la base de datos viajan sin cifrar."
                ));
            }
            return Ok(vec![p]);
        }

        let posicion = |v: &str| VERSIONES.iter().position(|x| x.eq_ignore_ascii_case(v));
        let desde = valor("ssl_min_protocol_version")
            .and_then(|(v, _)| posicion(&v))
            .unwrap_or(2);
        let hasta = valor("ssl_max_protocol_version")
            .and_then(|(v, _)| posicion(&v))
            .unwrap_or(VERSIONES.len() - 1);
        let versiones: Vec<String> = VERSIONES[desde..=hasta.max(desde)]
            .iter()
            .map(|s| s.to_string())
            .collect();

        let (grupos, linea_grupos) = match valor("ssl_groups").or_else(|| valor("ssl_ecdh_curve")) {
            Some((v, n)) => (
                Some(v.split(':').map(str::to_string).collect::<Vec<_>>()),
                Some(n),
            ),
            None => (None, None),
        };

        let mut protocolo = Activo::nuevo(
            referencia,
            nombre,
            Detalles::Protocolo {
                tipo_protocolo: "tls".into(),
                versiones: versiones.clone(),
                grupos: grupos.clone().unwrap_or_default(),
                cifrados: valor("ssl_ciphers").map(|(v, _)| v).into_iter().collect(),
            },
        )
        .con_contexto(CAPACIDAD, Garantia::Confidencialidad)
        .con_ubicacion(a.ruta, valor("ssl").map(|(_, n)| n));

        let mut activos = Vec::new();
        for g in grupos.iter().flatten() {
            let alg = por_alias(
                c,
                "tls-grupo",
                g,
                CAPACIDAD,
                Some(Garantia::Confidencialidad),
                a.ruta,
                linea_grupos,
            );
            protocolo.relacionar("algorithm", &alg.referencia);
            activos.push(alg);
        }
        evaluar_tls(
            &mut protocolo,
            &versiones,
            grupos.as_deref(),
            SIN_GRUPOS,
            Riesgo::VulnerableCuantico,
            c,
        );

        // Las rutas relativas se resuelven contra el directorio del archivo.
        if let Some((certificado, _)) = valor("ssl_cert_file") {
            let ruta_cert = if Path::new(&certificado).is_absolute() {
                certificado
            } else {
                Path::new(a.ruta)
                    .parent()
                    .map(|d| d.join(&certificado).display().to_string())
                    .unwrap_or(certificado)
            };
            protocolo.relacionar(REL_RUTA_CERTIFICADO, &ruta_cert);
        }

        activos.push(protocolo);
        Ok(activos)
    }
}
