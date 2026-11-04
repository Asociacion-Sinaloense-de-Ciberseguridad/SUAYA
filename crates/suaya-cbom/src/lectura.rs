//! Lectura de un CBOM generado por Suaya.

use serde_json::Value;

/// Un componente del CBOM, con las propiedades `suaya:` ya extraídas.
#[derive(Debug, Clone)]
pub struct Registro {
    pub referencia: String,
    pub nombre: String,
    /// `algorithm`, `certificate`, `related-crypto-material`, `protocol` o
    /// `library` (biblioteca criptográfica).
    pub tipo_activo: String,
    pub riesgo: String,
    pub accion: String,
    pub prioridad: u8,
    pub capacidad: String,
    pub garantia: String,
    pub madurez: String,
    pub justificacion: String,
    pub advertencias: Vec<String>,
    pub ubicaciones: Vec<String>,
    /// Relaciones (tipo, referencia) de `relatedCryptographicAssets`.
    pub relaciones: Vec<(String, String)>,
    /// Estado frente al perfil de política, si se evaluó.
    pub cumplimiento: String,
    pub plazo: Option<i32>,
    pub nota_cumplimiento: String,
}

#[derive(Debug, Clone)]
pub struct CbomLeido {
    pub estado: String,
    pub sistema: String,
    pub fecha: String,
    pub version_herramienta: String,
    pub base_conocimiento: String,
    pub fuente_madurez: String,
    /// Perfil de política evaluado: (nombre, referencia).
    pub perfil: Option<(String, String)>,
    pub registros: Vec<Registro>,
}

fn propiedades<'a>(v: &'a Value, nombre: &str) -> Vec<&'a str> {
    v.get("properties")
        .and_then(Value::as_array)
        .map(|ps| {
            ps.iter()
                .filter(|p| p.get("name").and_then(Value::as_str) == Some(nombre))
                .filter_map(|p| p.get("value").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default()
}

fn una<'a>(v: &'a Value, nombre: &str) -> &'a str {
    propiedades(v, nombre).first().copied().unwrap_or("")
}

fn relaciones(c: &Value) -> Vec<(String, String)> {
    let Some(cp) = c.get("cryptoProperties").and_then(Value::as_object) else {
        return Vec::new();
    };
    cp.values()
        .filter_map(|v| {
            v.get("relatedCryptographicAssets")
                .and_then(Value::as_array)
        })
        .flatten()
        .filter_map(|r| {
            Some((
                r.get("type")?.as_str()?.to_string(),
                r.get("ref")?.as_str()?.to_string(),
            ))
        })
        .collect()
}

/// Interpreta el texto JSON de un CBOM.
pub fn leer(texto: &str) -> Result<CbomLeido, String> {
    let v: Value = serde_json::from_str(texto).map_err(|e| format!("JSON inválido: {e}"))?;
    if v.get("bomFormat").and_then(Value::as_str) != Some("CycloneDX") {
        return Err("el archivo no es un BOM CycloneDX".into());
    }
    let meta = v.get("metadata").cloned().unwrap_or(Value::Null);
    let herramienta = meta
        .pointer("/tools/components/0")
        .map(|t| {
            format!(
                "{} {}",
                t.get("name").and_then(Value::as_str).unwrap_or("?"),
                t.get("version").and_then(Value::as_str).unwrap_or("")
            )
        })
        .unwrap_or_default();

    let registros = v
        .get("components")
        .and_then(Value::as_array)
        .map(|cs| {
            cs.iter()
                .filter(|c| {
                    matches!(
                        c.get("type").and_then(Value::as_str),
                        Some("cryptographic-asset") | Some("library")
                    ) && (c.get("type").and_then(Value::as_str) == Some("cryptographic-asset")
                        || !una(c, "suaya:biblioteca").is_empty())
                })
                .map(|c| Registro {
                    referencia: c
                        .get("bom-ref")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    nombre: c
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    tipo_activo: if c.get("type").and_then(Value::as_str) == Some("library") {
                        "library".to_string()
                    } else {
                        c.pointer("/cryptoProperties/assetType")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string()
                    },
                    riesgo: una(c, "suaya:riesgo").to_string(),
                    accion: una(c, "suaya:accion").to_string(),
                    prioridad: una(c, "suaya:prioridad").parse().unwrap_or(9),
                    capacidad: una(c, "suaya:capacidad").to_string(),
                    garantia: una(c, "suaya:garantia").to_string(),
                    madurez: una(c, "suaya:madurez-ecosistema").to_string(),
                    justificacion: una(c, "suaya:justificacion").to_string(),
                    advertencias: propiedades(c, "suaya:advertencia")
                        .iter()
                        .map(|s| s.to_string())
                        .collect(),
                    ubicaciones: c
                        .pointer("/evidence/occurrences")
                        .and_then(Value::as_array)
                        .map(|os| {
                            os.iter()
                                .map(|o| {
                                    let ruta =
                                        o.get("location").and_then(Value::as_str).unwrap_or("");
                                    match o.get("line").and_then(Value::as_u64) {
                                        Some(l) => format!("{ruta}:{l}"),
                                        None => ruta.to_string(),
                                    }
                                })
                                .collect()
                        })
                        .unwrap_or_default(),
                    relaciones: relaciones(c),
                    cumplimiento: una(c, "suaya:cumplimiento").to_string(),
                    plazo: una(c, "suaya:plazo").parse().ok(),
                    nota_cumplimiento: una(c, "suaya:cumplimiento-nota").to_string(),
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(CbomLeido {
        estado: una(&meta, "suaya:estado").to_string(),
        sistema: meta
            .pointer("/component/name")
            .and_then(Value::as_str)
            .unwrap_or("Sistema")
            .to_string(),
        fecha: meta
            .get("timestamp")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        version_herramienta: herramienta,
        base_conocimiento: una(&meta, "suaya:base-conocimiento").to_string(),
        fuente_madurez: una(&meta, "suaya:fuente-madurez").to_string(),
        perfil: match una(&meta, "suaya:perfil-politica") {
            "" => None,
            n => Some((
                n.to_string(),
                una(&meta, "suaya:perfil-referencia").to_string(),
            )),
        },
        registros,
    })
}
