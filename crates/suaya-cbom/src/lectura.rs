//! Lectura de un CBOM generado por Suaya.

use serde_json::Value;
use suaya_core::{ActivoReceta, Conocimiento, Garantia, Receta, Riesgo};

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
    /// Las mismas ubicaciones como (ruta o URI, línea).
    pub ocurrencias: Vec<(String, Option<u64>)>,
    /// Relaciones (tipo, referencia) de `relatedCryptographicAssets`.
    pub relaciones: Vec<(String, String)>,
    /// Estado frente al perfil de política, si se evaluó.
    pub cumplimiento: String,
    pub plazo: Option<i32>,
    pub nota_cumplimiento: String,
    /// Sistemas de la organización a los que pertenece (`--organizacion`).
    pub sistemas: Vec<String>,
    pub responsables: Vec<String>,
    /// `alta`, `media` o `baja`; vacío si no se declaró.
    pub criticidad: String,
    /// `internet` o `interna`; vacío si no se declaró.
    pub exposicion: String,
    /// Holgura de la desigualdad de Mosca en años (negativa: expuesto).
    pub holgura_mosca: Option<i32>,
    /// Excepción aplicada: (id, vence, vigente).
    pub excepcion: Option<(String, String, bool)>,
}

/// Identificador de `algoritmos.toml` de una referencia `algoritmo:<id>`
/// (sin el tamaño, como en `algoritmo:rsa-2048`).
pub fn algoritmo_de_referencia(referencia: &str, c: &Conocimiento) -> Option<String> {
    let id = referencia.strip_prefix("algoritmo:")?;
    if c.por_id(id).is_some() {
        return Some(id.to_string());
    }
    let (base, tamano) = id.rsplit_once('-')?;
    (!tamano.is_empty() && tamano.bytes().all(|b| b.is_ascii_digit()) && c.por_id(base).is_some())
        .then(|| base.to_string())
}

impl Registro {
    /// Receta de corrección de `remediacion.toml` que se aplica al activo.
    pub fn receta<'a>(&self, c: &'a Conocimiento) -> Option<&'a Receta> {
        let riesgo = Riesgo::desde_texto(&self.riesgo)?;
        let algoritmo = algoritmo_de_referencia(&self.referencia, c);
        c.receta_para(&ActivoReceta {
            algoritmo: algoritmo.as_deref(),
            tipo: &self.tipo_activo,
            riesgo,
            capacidad: &self.capacidad,
            garantia: Garantia::desde_texto(&self.garantia),
        })
    }
}

/// Sistema declarado en el contexto de la organización.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SistemaDeclarado {
    pub nombre: String,
    pub responsable: String,
    pub criticidad: String,
    pub exposicion: String,
}

/// Excepción declarada en el contexto de la organización.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExcepcionDeclarada {
    pub id: String,
    pub justificacion: String,
    pub aprobada_por: String,
    pub vence: String,
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
    /// Año supuesto de una computadora cuántica relevante, si se usó un contexto.
    pub horizonte_cuantico: Option<i32>,
    pub sistemas: Vec<SistemaDeclarado>,
    pub excepciones: Vec<ExcepcionDeclarada>,
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
                    ocurrencias: c
                        .pointer("/evidence/occurrences")
                        .and_then(Value::as_array)
                        .map(|os| {
                            os.iter()
                                .map(|o| {
                                    (
                                        o.get("location")
                                            .and_then(Value::as_str)
                                            .unwrap_or("")
                                            .to_string(),
                                        o.get("line").and_then(Value::as_u64),
                                    )
                                })
                                .collect()
                        })
                        .unwrap_or_default(),
                    relaciones: relaciones(c),
                    cumplimiento: una(c, "suaya:cumplimiento").to_string(),
                    plazo: una(c, "suaya:plazo").parse().ok(),
                    nota_cumplimiento: una(c, "suaya:cumplimiento-nota").to_string(),
                    sistemas: propiedades(c, "suaya:sistema")
                        .iter()
                        .map(|s| s.to_string())
                        .collect(),
                    responsables: propiedades(c, "suaya:responsable")
                        .iter()
                        .map(|s| s.to_string())
                        .collect(),
                    criticidad: una(c, "suaya:criticidad").to_string(),
                    exposicion: una(c, "suaya:exposicion").to_string(),
                    holgura_mosca: una(c, "suaya:mosca-holgura").parse().ok(),
                    excepcion: match una(c, "suaya:excepcion") {
                        "" => None,
                        id => Some((
                            id.to_string(),
                            una(c, "suaya:excepcion-vence").to_string(),
                            una(c, "suaya:excepcion-vigente") == "true",
                        )),
                    },
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
        horizonte_cuantico: una(&meta, "suaya:horizonte-cuantico").parse().ok(),
        sistemas: propiedades(&meta, "suaya:contexto-sistema")
            .iter()
            .filter_map(|x| serde_json::from_str::<Value>(x).ok())
            .map(|v| {
                let campo = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
                SistemaDeclarado {
                    nombre: campo("nombre"),
                    responsable: campo("responsable"),
                    criticidad: campo("criticidad"),
                    exposicion: campo("exposicion"),
                }
            })
            .filter(|x| !x.nombre.is_empty())
            .collect(),
        excepciones: propiedades(&meta, "suaya:contexto-excepcion")
            .iter()
            .filter_map(|x| serde_json::from_str::<Value>(x).ok())
            .map(|v| {
                let campo = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
                ExcepcionDeclarada {
                    id: campo("id"),
                    justificacion: campo("justificacion"),
                    aprobada_por: campo("aprobada_por"),
                    vence: campo("vence"),
                }
            })
            .filter(|x| !x.id.is_empty())
            .collect(),
        registros,
    })
}
