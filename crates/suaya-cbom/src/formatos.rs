//! Otros formatos a partir de un CBOM de Suaya, para las herramientas que ya
//! usa la organización:
//!
//! - **SARIF 2.1.0** ([`sarif`]): análisis de código en GitHub, GitLab y
//!   otros visores. Una regla por receta de corrección (o por riesgo, si no
//!   hay receta) y un resultado por ubicación; las excepciones vigentes van
//!   como `suppressions`.
//! - **CSV** ([`csv`]) para hojas de cálculo, con protección contra la
//!   inyección de fórmulas.
//! - **JSON Lines** ([`jsonl`]) para un SIEM o un lago de datos: un activo por
//!   línea.
//! - **Tickets** ([`tickets`]): un ticket por activo que requiere acción
//!   (prioridades crítica a media), listo para un gestor de incidencias.
//! - **PCI DSS** ([`pci`]): inventario de suites, protocolos, llaves y
//!   certificados para los requisitos 12.3.3 y 4.2.1.1 de PCI DSS v4.0.

use std::collections::BTreeMap;
use std::fmt::Write;

use serde_json::{Value, json};
use suaya_core::idioma::{traducir, tx};
use suaya_core::{Conocimiento, etiqueta_prioridad, t};

use crate::lectura::{CbomLeido, Registro, algoritmo_de_referencia};

/// Tope de resultados SARIF (GitHub admite 25 000 por ejecución).
const MAXIMO_SARIF: usize = 5000;
/// Ubicaciones por activo en SARIF.
const UBICACIONES_POR_ACTIVO: usize = 50;

fn tr(t: &str) -> String {
    traducir(t).into_owned()
}

/// Severidad de seguridad (0 a 10) que GitHub usa para ordenar las alertas.
fn severidad(prioridad: u8) -> &'static str {
    match prioridad {
        1 => "9.0",
        2 => "7.0",
        3 => "5.0",
        _ => "3.0",
    }
}

fn nivel_sarif(prioridad: u8) -> &'static str {
    match prioridad {
        1 | 2 => "error",
        3 => "warning",
        _ => "note",
    }
}

/// Ubicación de archivo como referencia URI relativa (o `file://` si es absoluta).
fn uri_de_ruta(ruta: &str) -> Option<String> {
    if ruta.is_empty() || ruta.contains("://") {
        return None;
    }
    let ruta = ruta.strip_prefix("./").unwrap_or(ruta).replace('\\', "/");
    let mut codificada = String::with_capacity(ruta.len());
    for b in ruta.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) {
            codificada.push(b as char);
        } else {
            let _ = write!(codificada, "%{b:02X}");
        }
    }
    Some(if codificada.starts_with('/') {
        format!("file://{codificada}")
    } else {
        codificada
    })
}

fn accionables(cbom: &CbomLeido) -> impl Iterator<Item = &Registro> {
    cbom.registros
        .iter()
        .filter(|r| (1..=4).contains(&r.prioridad))
}

fn excepcion_vigente(r: &Registro) -> Option<&str> {
    r.excepcion
        .as_ref()
        .filter(|(_, _, vigente)| *vigente)
        .map(|(id, _, _)| id.as_str())
}

// ---------------------------------------------------------------------------
// SARIF
// ---------------------------------------------------------------------------

/// SARIF 2.1.0 con los activos que requieren acción.
pub fn sarif(cbom: &CbomLeido, c: &Conocimiento) -> Value {
    // Reglas: por receta o, si no hay, por riesgo.
    let mut reglas: BTreeMap<String, (Value, u8)> = BTreeMap::new();
    let mut resultados = Vec::new();
    for r in accionables(cbom) {
        let receta = r.receta(c);
        let (id, nombre, pasos) = match receta {
            Some(x) => (
                format!("suaya/{}", x.id),
                x.titulo().to_string(),
                x.pasos().to_vec(),
            ),
            None => (
                format!("suaya/{}", r.riesgo),
                etiqueta_riesgo(&r.riesgo),
                Vec::new(),
            ),
        };
        let entrada = reglas.entry(id.clone()).or_insert_with(|| {
            let mut ayuda = format!("**{nombre}**\n\n");
            for (i, p) in pasos.iter().enumerate() {
                let _ = writeln!(ayuda, "{}. {p}", i + 1);
            }
            if let Some(x) = receta {
                for u in &x.referencias {
                    let _ = writeln!(ayuda, "\n{u}");
                }
            }
            let regla = json!({
                "id": id,
                "name": nombre,
                "shortDescription": { "text": nombre },
                "fullDescription": { "text": nombre },
                "help": { "text": pasos.join("\n"), "markdown": ayuda },
                "properties": { "tags": ["security", "cryptography", "post-quantum"] },
            });
            (regla, r.prioridad)
        });
        entrada.1 = entrada.1.min(r.prioridad);

        let mensaje = format!(
            "{}: {} ({}). {}",
            tr(&r.nombre),
            etiqueta_accion(&r.accion),
            etiqueta_prioridad(r.prioridad).to_lowercase(),
            tr(&r.justificacion)
        );
        let mut base = json!({
            "ruleId": id,
            "level": nivel_sarif(r.prioridad),
            "message": { "text": mensaje },
            "properties": {
                "suaya:referencia": r.referencia,
                "suaya:prioridad": r.prioridad,
                "suaya:riesgo": r.riesgo,
                "suaya:capacidad": r.capacidad,
                "suaya:garantia": r.garantia,
            },
        });
        if let Some(id) = excepcion_vigente(r) {
            base["suppressions"] = json!([{ "kind": "external", "justification": id }]);
        }
        let archivos: Vec<(String, Option<u64>)> = r
            .ocurrencias
            .iter()
            .filter_map(|(ruta, linea)| Some((uri_de_ruta(ruta)?, *linea)))
            .take(UBICACIONES_POR_ACTIVO)
            .collect();
        if archivos.is_empty() {
            // Servicios de red: ubicación lógica (los visores de código no la muestran).
            let mut x = base.clone();
            x["locations"] = json!([{
                "logicalLocations": r.ubicaciones.iter().take(10).map(|u| json!({
                    "fullyQualifiedName": u, "kind": "resource"
                })).collect::<Vec<_>>()
            }]);
            x["partialFingerprints"] = json!({ "suayaReferencia/v1": r.referencia });
            resultados.push(x);
        }
        for (uri, linea) in archivos {
            let mut ubicacion = json!({ "artifactLocation": { "uri": uri } });
            if let Some(l) = linea.filter(|l| *l > 0) {
                ubicacion["region"] = json!({ "startLine": l });
            }
            let mut x = base.clone();
            x["locations"] = json!([{ "physicalLocation": ubicacion }]);
            x["partialFingerprints"] =
                json!({ "suayaReferencia/v1": format!("{}|{uri}", r.referencia) });
            resultados.push(x);
        }
        if resultados.len() >= MAXIMO_SARIF {
            resultados.truncate(MAXIMO_SARIF);
            break;
        }
    }
    let reglas: Vec<Value> = reglas
        .into_values()
        .map(|(mut regla, prioridad)| {
            regla["defaultConfiguration"] = json!({ "level": nivel_sarif(prioridad) });
            regla["properties"]["security-severity"] = json!(severidad(prioridad));
            regla
        })
        .collect();
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "Suaya",
                "semanticVersion": suaya_core::VERSION,
                "rules": reglas,
            }},
            "automationDetails": { "id": format!("suaya/{}", cbom.sistema) },
            "results": resultados,
        }],
    })
}

fn etiqueta_riesgo(riesgo: &str) -> String {
    suaya_core::Riesgo::desde_texto(riesgo)
        .map(|r| r.etiqueta().to_string())
        .unwrap_or_else(|| riesgo.to_string())
}

fn etiqueta_garantia(garantia: &str) -> String {
    suaya_core::Garantia::desde_texto(garantia)
        .map(|g| g.etiqueta().to_string())
        .unwrap_or_else(|| garantia.to_string())
}

fn etiqueta_accion(accion: &str) -> String {
    suaya_core::Accion::desde_texto(accion)
        .map(|a| a.etiqueta().to_string())
        .unwrap_or_else(|| accion.to_string())
}

// ---------------------------------------------------------------------------
// CSV y JSON Lines
// ---------------------------------------------------------------------------

/// Celda CSV (RFC 4180) que una hoja de cálculo no interpreta como fórmula.
fn celda_csv(t: &str) -> String {
    let t = if t.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{t}")
    } else {
        t.to_string()
    };
    if t.contains([',', '"', '\n', '\r']) || t.starts_with(' ') || t.ends_with(' ') {
        format!("\"{}\"", t.replace('"', "\"\""))
    } else {
        t
    }
}

const COLUMNAS: [(&str, &str); 19] = [
    ("referencia", "reference"),
    ("nombre", "name"),
    ("tipo", "type"),
    ("riesgo", "risk"),
    ("accion", "action"),
    ("prioridad", "priority"),
    ("capacidad", "capability"),
    ("garantia", "assurance"),
    ("madurez", "maturity"),
    ("ubicaciones", "locations"),
    ("cumplimiento", "compliance"),
    ("plazo", "deadline"),
    ("sistemas", "systems"),
    ("responsables", "owners"),
    ("criticidad", "criticality"),
    ("exposicion", "exposure"),
    ("holgura_mosca", "mosca_slack"),
    ("excepcion", "exception"),
    ("receta", "recipe"),
];

fn campos(r: &Registro, c: &Conocimiento) -> Vec<String> {
    vec![
        r.referencia.clone(),
        tr(&r.nombre),
        r.tipo_activo.clone(),
        r.riesgo.clone(),
        r.accion.clone(),
        r.prioridad.to_string(),
        r.capacidad.clone(),
        r.garantia.clone(),
        r.madurez.clone(),
        r.ubicaciones.join(" | "),
        r.cumplimiento.clone(),
        r.plazo.map(|p| p.to_string()).unwrap_or_default(),
        r.sistemas.join(" | "),
        r.responsables.join(" | "),
        r.criticidad.clone(),
        r.exposicion.clone(),
        r.holgura_mosca.map(|h| h.to_string()).unwrap_or_default(),
        r.excepcion
            .as_ref()
            .map(|(id, _, _)| id.clone())
            .unwrap_or_default(),
        r.receta(c).map(|x| x.id.clone()).unwrap_or_default(),
    ]
}

/// CSV con un activo por fila (encabezados en el idioma actual).
pub fn csv(cbom: &CbomLeido, c: &Conocimiento) -> String {
    let ingles = suaya_core::idioma::es_ingles();
    let mut s = COLUMNAS
        .iter()
        .map(|(es, en)| if ingles { *en } else { *es })
        .collect::<Vec<_>>()
        .join(",");
    s.push_str("\r\n");
    for r in &cbom.registros {
        let fila: Vec<String> = campos(r, c).iter().map(|x| celda_csv(x)).collect();
        s.push_str(&fila.join(","));
        s.push_str("\r\n");
    }
    s
}

/// JSON Lines: un objeto por activo, con la fecha y el sistema del escaneo.
pub fn jsonl(cbom: &CbomLeido, c: &Conocimiento) -> String {
    let mut s = String::new();
    for r in &cbom.registros {
        let v = json!({
            "fecha": cbom.fecha,
            "sistema": cbom.sistema,
            "referencia": r.referencia,
            "nombre": tr(&r.nombre),
            "tipo": r.tipo_activo,
            "riesgo": r.riesgo,
            "accion": r.accion,
            "prioridad": r.prioridad,
            "capacidad": r.capacidad,
            "garantia": r.garantia,
            "madurez": r.madurez,
            "algoritmo": algoritmo_de_referencia(&r.referencia, c),
            "ubicaciones": r.ubicaciones,
            "cumplimiento": (!r.cumplimiento.is_empty()).then_some(&r.cumplimiento),
            "plazo": r.plazo,
            "sistemas": r.sistemas,
            "responsables": r.responsables,
            "criticidad": (!r.criticidad.is_empty()).then_some(&r.criticidad),
            "exposicion": (!r.exposicion.is_empty()).then_some(&r.exposicion),
            "holgura_mosca": r.holgura_mosca,
            "excepcion": r.excepcion.as_ref().map(|(id, vence, vigente)| json!({
                "id": id, "vence": vence, "vigente": vigente
            })),
            "receta": r.receta(c).map(|x| x.id.clone()),
            "advertencias": r.advertencias.iter().map(|a| tr(a)).collect::<Vec<_>>(),
        });
        s.push_str(&v.to_string());
        s.push('\n');
    }
    s
}

// ---------------------------------------------------------------------------
// Tickets
// ---------------------------------------------------------------------------

/// Un ticket por activo de prioridad crítica, alta o media sin excepción vigente.
pub fn tickets(cbom: &CbomLeido, c: &Conocimiento) -> Value {
    let mut lista: Vec<&Registro> = cbom
        .registros
        .iter()
        .filter(|r| (1..=3).contains(&r.prioridad) && excepcion_vigente(r).is_none())
        .collect();
    lista.sort_by_key(|r| (r.prioridad, r.nombre.clone()));
    let tickets: Vec<Value> = lista
        .iter()
        .map(|r| {
            let nombre = tr(&r.nombre);
            let receta = r.receta(c);
            let mut cuerpo = String::new();
            let _ = writeln!(cuerpo, "{}\n", tr(&r.justificacion));
            let _ = writeln!(cuerpo, "**{}**", tx("Ubicaciones", "Locations"));
            for u in r.ubicaciones.iter().take(20) {
                let _ = writeln!(cuerpo, "- `{u}`");
            }
            if r.ubicaciones.len() > 20 {
                let n = r.ubicaciones.len() - 20;
                let _ = writeln!(cuerpo, "- {}", t!("y {n} más", "and {n} more"));
            }
            if !r.advertencias.is_empty() {
                let _ = writeln!(cuerpo, "\n**{}**", tx("Observaciones", "Observations"));
                for a in &r.advertencias {
                    let _ = writeln!(cuerpo, "- {}", tr(a));
                }
            }
            if let Some(x) = receta {
                let _ = writeln!(cuerpo, "\n**{}: {}**", tx("Cómo corregir", "How to fix"), x.titulo());
                for (i, p) in x.pasos().iter().enumerate() {
                    let _ = writeln!(cuerpo, "{}. {p}", i + 1);
                }
            }
            let mut etiquetas = vec![
                "suaya".to_string(),
                "criptografia".to_string(),
                format!("prioridad-{}", r.prioridad),
                r.capacidad.clone(),
            ];
            if !r.criticidad.is_empty() {
                etiquetas.push(format!("criticidad-{}", r.criticidad));
            }
            json!({
                "titulo": format!("[{}] {}: {nombre}", etiqueta_prioridad(r.prioridad), etiqueta_accion(&r.accion)),
                "prioridad": r.prioridad,
                "referencia": r.referencia,
                "responsables": r.responsables,
                "sistemas": r.sistemas,
                "etiquetas": etiquetas,
                "receta": receta.map(|x| x.id.clone()),
                "descripcion": cuerpo,
            })
        })
        .collect();
    json!({
        "herramienta": format!("Suaya {}", suaya_core::VERSION),
        "sistema": cbom.sistema,
        "fecha": cbom.fecha,
        "tickets": tickets,
    })
}

// ---------------------------------------------------------------------------
// PCI DSS
// ---------------------------------------------------------------------------

fn celda(t: &str) -> String {
    t.replace('|', "\\|").replace('\n', " ")
}

/// Inventario para PCI DSS v4.0: suites y protocolos (12.3.3) y llaves y
/// certificados (4.2.1.1), en Markdown.
pub fn pci(cbom: &CbomLeido, c: &Conocimiento) -> String {
    let mut s = String::new();
    let _ = writeln!(
        s,
        "# {}\n",
        tx(
            "Inventario criptográfico para PCI DSS v4.0",
            "Cryptographic inventory for PCI DSS v4.0"
        )
    );
    let fecha = cbom.fecha.get(..10).unwrap_or(&cbom.fecha);
    let proxima = fecha
        .get(..4)
        .and_then(|a| a.parse::<i32>().ok())
        .map(|a| format!("{}{}", a + 1, fecha.get(4..).unwrap_or("")))
        .unwrap_or_default();
    let _ = writeln!(s, "| | |\n|---|---|");
    let _ = writeln!(
        s,
        "| **{}** | {} |",
        tx("Sistema", "System"),
        celda(&cbom.sistema)
    );
    let _ = writeln!(
        s,
        "| **{}** | {fecha} |",
        tx("Fecha del inventario", "Inventory date")
    );
    let _ = writeln!(
        s,
        "| **{}** | {proxima} |",
        tx("Próxima revisión (12 meses)", "Next review (12 months)")
    );
    let _ = writeln!(
        s,
        "| **{}** | {} |\n",
        tx("Herramienta", "Tool"),
        cbom.version_herramienta
    );
    let _ = writeln!(
        s,
        "{}\n",
        tx(
            "El requisito 12.3.3 pide documentar y revisar al menos una vez al año las suites y protocolos criptográficos en uso, con su propósito y ubicación, vigilar su viabilidad y tener una estrategia de respuesta ante cambios; el 4.2.1.1, mantener un inventario de las llaves y certificados de confianza con que se protege la transmisión de datos de tarjetas. Este documento se generó a partir del CBOM de Suaya; la evaluación del alcance (qué sistemas tocan datos de tarjetas) corresponde a la organización.",
            "Requirement 12.3.3 calls for documenting and reviewing, at least once a year, the cryptographic cipher suites and protocols in use, with their purpose and location, monitoring their continued viability and having a strategy to respond to changes; 4.2.1.1, for keeping an inventory of the trusted keys and certificates that protect cardholder data in transit. This document was generated from the Suaya CBOM; assessing scope (which systems touch cardholder data) is the organization's responsibility."
        )
    );
    let fila = |s: &mut String, r: &Registro| {
        let donde = match r.ubicaciones.len() {
            0 => String::new(),
            1 => r.ubicaciones[0].clone(),
            n => t!("{} (y {} más)", "{} (and {} more)", r.ubicaciones[0], n - 1),
        };
        let respuesta = match r.plazo {
            Some(p) => format!(
                "{} ({})",
                etiqueta_accion(&r.accion),
                t!("plazo {p}", "deadline {p}")
            ),
            None => etiqueta_accion(&r.accion),
        };
        let _ = writeln!(
            s,
            "| {} | {} / {} | {} | {} | {} |",
            celda(&tr(&r.nombre)),
            celda(&tr(c.nombre_capacidad(&r.capacidad))),
            etiqueta_garantia(&r.garantia),
            celda(&donde),
            etiqueta_riesgo(&r.riesgo),
            celda(&respuesta)
        );
    };
    let mut ordenados: Vec<&Registro> = cbom.registros.iter().collect();
    ordenados.sort_by_key(|r| (r.prioridad, r.nombre.clone()));
    for (titulo, requisito, tipos) in [
        (
            tx(
                "Protocolos y suites criptográficas",
                "Protocols and cipher suites",
            ),
            "12.3.3",
            &["protocol", "algorithm"][..],
        ),
        (
            tx("Llaves y certificados", "Keys and certificates"),
            "4.2.1.1",
            &["certificate", "related-crypto-material"][..],
        ),
    ] {
        let lista: Vec<&&Registro> = ordenados
            .iter()
            .filter(|r| tipos.contains(&r.tipo_activo.as_str()))
            .collect();
        let n = lista.len();
        let _ = writeln!(
            s,
            "## {titulo} · {}\n",
            t!(
                "requisito {requisito}, {n} elementos",
                "requirement {requisito}, {n} items"
            )
        );
        if lista.is_empty() {
            let _ = writeln!(s, "{}\n", tx("No se encontraron.", "None found."));
            continue;
        }
        let _ = writeln!(
            s,
            "| {} | {} | {} | {} | {} |\n|---|---|---|---|---|",
            tx("Elemento", "Item"),
            tx("Uso (capacidad / garantía)", "Use (capability / assurance)"),
            tx("Ubicación", "Location"),
            tx("Viabilidad (riesgo)", "Viability (risk)"),
            tx("Respuesta prevista", "Planned response")
        );
        for r in lista {
            fila(&mut s, r);
        }
        let _ = writeln!(s);
    }
    let _ = writeln!(
        s,
        "## {}\n",
        tx("Estrategia de respuesta", "Response strategy")
    );
    let cuenta = |a: &str| cbom.registros.iter().filter(|r| r.accion == a).count();
    for (accion, es, en) in [
        (
            "corregir-ya",
            "corregir de inmediato (inseguro hoy)",
            "fix immediately (insecure today)",
        ),
        (
            "reemplazar",
            "reemplazar (obsoleto)",
            "replace (deprecated)",
        ),
        (
            "migrar-ahora",
            "migrar ya a criptografía poscuántica o híbrida",
            "migrate now to post-quantum or hybrid cryptography",
        ),
        (
            "planificar-piloto",
            "planificar y probar la migración",
            "plan and pilot the migration",
        ),
        (
            "monitorear",
            "documentar y monitorear",
            "document and monitor",
        ),
    ] {
        let n = cuenta(accion);
        if n > 0 {
            let _ = writeln!(s, "- {n} {}", tx(es, en));
        }
    }
    if let Some((nombre, _)) = &cbom.perfil {
        let n = |e: &str| {
            cbom.registros
                .iter()
                .filter(|r| r.cumplimiento == e)
                .count()
        };
        let _ = writeln!(
            s,
            "\n{}",
            t!(
                "Perfil {}: {} no conformes, {} en transición, {} conformes.",
                "Profile {}: {} non-compliant, {} in transition, {} compliant.",
                tr(nombre),
                n("no-conforme"),
                n("transicion"),
                n("conforme")
            )
        );
    }
    s.replace('<', "&lt;").replace('>', "&gt;")
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn celdas_y_uris() {
        assert_eq!(celda_csv("=1+1"), "'=1+1");
        assert_eq!(celda_csv("a,b"), "\"a,b\"");
        assert_eq!(celda_csv("di \"x\""), "\"di \"\"x\"\"\"");
        assert_eq!(celda_csv("normal"), "normal");
        assert_eq!(
            uri_de_ruta("./etc/nginx/nginx.conf").as_deref(),
            Some("etc/nginx/nginx.conf")
        );
        assert_eq!(
            uri_de_ruta("mi carpeta/a.pem").as_deref(),
            Some("mi%20carpeta/a.pem")
        );
        assert_eq!(
            uri_de_ruta("/abs/b.pem").as_deref(),
            Some("file:///abs/b.pem")
        );
        assert_eq!(uri_de_ruta("tls://x:443"), None);
    }
}
