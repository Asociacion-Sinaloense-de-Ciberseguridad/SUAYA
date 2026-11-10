//! Base de conocimiento de Suaya.
//!
//! Se compone de dos archivos TOML:
//!
//! - `algoritmos.toml`: registro de algoritmos, OIDs, alias y riesgo.
//! - `madurez.toml`: madurez del ecosistema PQC por capacidad y garantía.
//!
//! Ambos se incrustan en el binario al compilar, y pueden sustituirse en
//! tiempo de ejecución con [`Conocimiento::desde_directorio`].

use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

use crate::modelo::{Garantia, NivelMadurez, Riesgo};

const ALGORITMOS_EMBEBIDOS: &str = include_str!("../../../conocimiento/algoritmos.toml");
const MADUREZ_EMBEBIDA: &str = include_str!("../../../conocimiento/madurez.toml");
const CODIGO_EMBEBIDO: &str = include_str!("../../../conocimiento/codigo.toml");
const BIBLIOTECAS_EMBEBIDAS: &str = include_str!("../../../conocimiento/bibliotecas.toml");
const SERVICIOS_EMBEBIDOS: &str = include_str!("../../../conocimiento/servicios.toml");
const RECETAS_EMBEBIDAS: &str = include_str!("../../../conocimiento/remediacion.toml");

/// Lenguajes que entiende el escáner de código. «shell» abarca scripts,
/// Dockerfile, Makefile y los YAML de integración continua y Ansible.
pub const LENGUAJES_CODIGO: [&str; 13] = [
    "python",
    "java",
    "go",
    "javascript",
    "csharp",
    "rust",
    "c",
    "php",
    "ruby",
    "swift",
    "dart",
    "powershell",
    "shell",
];

#[derive(Debug, thiserror::Error)]
pub enum ErrorConocimiento {
    #[error("no se pudo leer {ruta}: {fuente}")]
    Lectura {
        ruta: String,
        fuente: std::io::Error,
    },
    #[error("formato inválido en {archivo}: {fuente}")]
    Formato {
        archivo: String,
        fuente: Box<toml::de::Error>,
    },
    #[error("inconsistencia en la base de conocimiento: {0}")]
    Inconsistencia(String),
}

/// Metadatos de un archivo de conocimiento.
#[derive(Debug, Clone, Deserialize)]
pub struct Meta {
    pub version: String,
    #[serde(default)]
    pub descripcion: Option<String>,
    #[serde(default)]
    pub fuente: Option<String>,
    #[serde(default)]
    pub edicion: Option<String>,
    #[serde(default)]
    pub fecha_evidencia: Option<String>,
    #[serde(default)]
    pub caso_difusion: Option<String>,
}

/// Definición de un algoritmo en `algoritmos.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct AlgoritmoDef {
    pub id: String,
    pub nombre: String,
    #[serde(default)]
    pub familia: Option<String>,
    pub primitiva: String,
    #[serde(default)]
    pub oids: Vec<String>,
    #[serde(default)]
    pub alias: Vec<String>,
    pub riesgo: Riesgo,
    pub garantia: Garantia,
    #[serde(default)]
    pub conjunto_parametros: Option<String>,
    #[serde(default)]
    pub curva: Option<String>,
    #[serde(default)]
    pub modo: Option<String>,
    #[serde(default)]
    pub tamano_llave: Option<u32>,
    #[serde(default)]
    pub tamano_minimo_clasico: Option<u32>,
    #[serde(default)]
    pub nivel_clasico: Option<u32>,
    #[serde(default)]
    pub nivel_nist_cuantico: Option<u32>,
    #[serde(default)]
    pub funciones: Vec<String>,
    /// Identificadores IANA de grupo TLS (NamedGroup) de este algoritmo.
    #[serde(default)]
    pub codigos_tls: Vec<u16>,
    #[serde(default)]
    pub nota: Option<String>,
    /// Advertencia que acompaña a todo hallazgo de este algoritmo
    /// (por ejemplo, riesgos de despojo en firmas híbridas, RFC 9955).
    #[serde(default)]
    pub advertencia: Option<String>,
}

/// Fechas de transición para advertir sobre vigencias largas.
#[derive(Debug, Clone, Deserialize)]
pub struct Politica {
    pub anio_retiro_vulnerables: i32,
    pub anio_prohibicion_vulnerables: i32,
    pub referencia: String,
}

impl AlgoritmoDef {
    /// Riesgo efectivo considerando el tamaño de llave observado.
    pub fn riesgo_para_tamano(&self, tamano: Option<u32>) -> Riesgo {
        match (self.tamano_minimo_clasico, tamano) {
            (Some(minimo), Some(t)) if t < minimo => Riesgo::RotoClasico,
            _ => self.riesgo,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct NivelDef {
    pub id: NivelMadurez,
    pub nombre: String,
    pub rango: u8,
    pub definicion: String,
}

/// Capacidad tecnológica evaluada en `madurez.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct CapacidadDef {
    pub id: String,
    pub nombre: String,
    pub confidencialidad: NivelMadurez,
    pub autenticacion: NivelMadurez,
    #[serde(default)]
    pub incluye: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ArchivoAlgoritmos {
    meta: Meta,
    #[serde(default)]
    politica: Option<Politica>,
    #[serde(rename = "algoritmo", default)]
    algoritmos: Vec<AlgoritmoDef>,
}

#[derive(Debug, Deserialize)]
struct ArchivoMadurez {
    meta: Meta,
    #[serde(rename = "nivel", default)]
    niveles: Vec<NivelDef>,
    #[serde(rename = "capacidad", default)]
    capacidades: Vec<CapacidadDef>,
}

/// Regla de uso de un algoritmo en código fuente (`codigo.toml`).
#[derive(Debug, Clone, Deserialize)]
pub struct ReglaCodigo {
    pub lenguajes: Vec<String>,
    pub patron: String,
    #[serde(default)]
    pub algoritmo: Option<String>,
    #[serde(default)]
    pub espacio: Option<String>,
    #[serde(default)]
    pub captura: Option<usize>,
    #[serde(default)]
    pub formato: Option<String>,
    #[serde(default)]
    pub tamano: Option<usize>,
    #[serde(default)]
    pub requiere: Option<String>,
    #[serde(default)]
    pub ignorar: Vec<String>,
    /// Capacidad tecnológica del hallazgo (predeterminada: código de aplicaciones).
    #[serde(default)]
    pub capacidad: Option<String>,
    #[serde(default)]
    pub nota: Option<String>,
}

/// Uso inseguro de TLS en código fuente (`codigo.toml`).
#[derive(Debug, Clone, Deserialize)]
pub struct HallazgoCodigo {
    pub lenguajes: Vec<String>,
    pub patron: String,
    #[serde(default)]
    pub requiere: Option<String>,
    pub riesgo: Riesgo,
    pub advertencia: String,
}

/// Reglas de código fuente.
#[derive(Debug, Clone, Deserialize)]
pub struct BaseCodigo {
    pub meta: Meta,
    #[serde(rename = "regla", default)]
    pub reglas: Vec<ReglaCodigo>,
    #[serde(rename = "hallazgo", default)]
    pub hallazgos: Vec<HallazgoCodigo>,
    /// Espacio, nombre normalizado e id de algoritmo.
    #[serde(default)]
    pub nombres: std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>,
}

impl BaseCodigo {
    /// Id del algoritmo para un nombre ya normalizado.
    pub fn traducir(&self, espacio: &str, nombre: &str) -> Option<&str> {
        self.nombres
            .get(espacio)
            .and_then(|t| t.get(nombre))
            .map(String::as_str)
    }
}

/// Valor peligroso de una clave de configuración de un servicio.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AvisoServicio {
    pub clave: String,
    pub valores: Vec<String>,
    pub texto: String,
    pub riesgo: Riesgo,
}

/// Clave cuyo valor es una lista de algoritmos con alias en `algoritmos.toml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListaAlgoritmosServicio {
    pub clave: String,
    pub espacio: String,
}

/// Dónde declara un servicio su configuración de TLS (`servicios.toml`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServicioDef {
    pub id: String,
    pub nombre: String,
    pub archivos: Vec<String>,
    #[serde(default)]
    pub pistas: Vec<String>,
    pub capacidad: String,
    #[serde(default)]
    pub versiones: Vec<String>,
    #[serde(default)]
    pub version_minima: Vec<String>,
    #[serde(default)]
    pub version_maxima: Vec<String>,
    #[serde(default)]
    pub versiones_excluidas: Vec<String>,
    #[serde(default)]
    pub cifrados: Vec<String>,
    #[serde(default)]
    pub grupos: Vec<String>,
    #[serde(default)]
    pub algoritmos: Vec<ListaAlgoritmosServicio>,
    #[serde(default)]
    pub avisos: Vec<AvisoServicio>,
    #[serde(default)]
    pub nota: Option<String>,
}

/// Servicios descritos en `servicios.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct BaseServicios {
    pub meta: Meta,
    #[serde(rename = "servicio", default)]
    pub servicios: Vec<ServicioDef>,
}

/// Receta de corrección (`remediacion.toml`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receta {
    pub id: String,
    pub titulo: String,
    pub titulo_en: String,
    #[serde(default)]
    pub pasos: Vec<String>,
    #[serde(default)]
    pub pasos_en: Vec<String>,
    #[serde(default)]
    pub referencias: Vec<String>,
    #[serde(default)]
    pub algoritmos: Vec<String>,
    #[serde(default)]
    pub tipos: Vec<String>,
    #[serde(default)]
    pub riesgos: Vec<Riesgo>,
    #[serde(default)]
    pub capacidades: Vec<String>,
    #[serde(default)]
    pub garantias: Vec<Garantia>,
    /// Códigos de hallazgo del diagnóstico (`CERT-VENCE`, `IKE-CLASICO`...).
    #[serde(default)]
    pub hallazgos: Vec<String>,
}

/// Tipos de activo que puede nombrar una receta.
const TIPOS_RECETA: [&str; 5] = [
    "algorithm",
    "certificate",
    "related-crypto-material",
    "protocol",
    "library",
];

impl Receta {
    /// Título en el idioma actual.
    pub fn titulo(&self) -> &str {
        if crate::idioma::es_ingles() {
            &self.titulo_en
        } else {
            &self.titulo
        }
    }

    /// Pasos en el idioma actual.
    pub fn pasos(&self) -> &[String] {
        if crate::idioma::es_ingles() && !self.pasos_en.is_empty() {
            &self.pasos_en
        } else {
            &self.pasos
        }
    }

    fn criterios_de_activo(&self) -> bool {
        !(self.algoritmos.is_empty()
            && self.tipos.is_empty()
            && self.riesgos.is_empty()
            && self.capacidades.is_empty()
            && self.garantias.is_empty())
    }

    fn aplica(&self, a: &ActivoReceta) -> bool {
        self.criterios_de_activo()
            && (self.algoritmos.is_empty()
                || a.algoritmo
                    .is_some_and(|x| self.algoritmos.iter().any(|y| y == x)))
            && (self.tipos.is_empty() || self.tipos.iter().any(|t| t == a.tipo))
            && (self.riesgos.is_empty() || self.riesgos.contains(&a.riesgo))
            && (self.capacidades.is_empty() || self.capacidades.iter().any(|c| c == a.capacidad))
            && (self.garantias.is_empty()
                || a.garantia.is_some_and(|g| self.garantias.contains(&g)))
    }
}

/// Lo que una receta necesita saber de un activo.
#[derive(Debug, Clone, Copy)]
pub struct ActivoReceta<'a> {
    /// Identificador de `algoritmos.toml`, si el activo es un algoritmo.
    pub algoritmo: Option<&'a str>,
    /// Tipo de activo según CycloneDX (`algorithm`, `certificate`...).
    pub tipo: &'a str,
    pub riesgo: Riesgo,
    pub capacidad: &'a str,
    pub garantia: Option<Garantia>,
}

/// Recetas descritas en `remediacion.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct BaseRecetas {
    pub meta: Meta,
    #[serde(rename = "receta", default)]
    pub recetas: Vec<Receta>,
}

impl BaseRecetas {
    /// Interpreta y valida `remediacion.toml` contra el resto de la base.
    fn desde_texto(t: &str, c: &Conocimiento) -> Result<Self, ErrorConocimiento> {
        let b: BaseRecetas = toml::from_str(t).map_err(|e| ErrorConocimiento::Formato {
            archivo: "remediacion.toml".into(),
            fuente: Box::new(e),
        })?;
        let error = |t: String| {
            Err(ErrorConocimiento::Inconsistencia(format!(
                "remediacion.toml: {t}"
            )))
        };
        let mut ids = std::collections::HashSet::new();
        for r in &b.recetas {
            if !ids.insert(r.id.as_str()) {
                return error(format!("receta duplicada: {}", r.id));
            }
            if !r.criterios_de_activo() && r.hallazgos.is_empty() {
                return error(format!("{} no declara a qué se aplica", r.id));
            }
            if r.pasos.is_empty() || (!r.pasos_en.is_empty() && r.pasos_en.len() != r.pasos.len()) {
                return error(format!("{} debe tener pasos, y en inglés los mismos", r.id));
            }
            if let Some(x) = r.algoritmos.iter().find(|x| c.por_id(x).is_none()) {
                return error(format!("{} usa un algoritmo inexistente: {x}", r.id));
            }
            if let Some(x) = r.capacidades.iter().find(|x| c.capacidad(x).is_none()) {
                return error(format!("{} usa una capacidad inexistente: {x}", r.id));
            }
            if let Some(x) = r.tipos.iter().find(|x| !TIPOS_RECETA.contains(&x.as_str())) {
                return error(format!("{} usa un tipo de activo desconocido: {x}", r.id));
            }
        }
        Ok(b)
    }
}

/// Rama de una biblioteca con su fecha de fin de soporte.
#[derive(Debug, Clone, Deserialize)]
pub struct RamaDef {
    pub version: String,
    pub fin_soporte: String,
}

/// Biblioteca o entorno criptográfico (`bibliotecas.toml`).
#[derive(Debug, Clone, Deserialize)]
pub struct BibliotecaDef {
    pub id: String,
    pub nombre: String,
    #[serde(default)]
    pub paquetes: Vec<String>,
    #[serde(default)]
    pub pq_disponible: Option<String>,
    #[serde(default)]
    pub pq_predeterminado: Option<String>,
    #[serde(default)]
    pub nota_pq: Option<String>,
    #[serde(default)]
    pub riesgo_predeterminado: Option<Riesgo>,
    #[serde(default)]
    pub nota: Option<String>,
    #[serde(default)]
    pub version_en_metadatos: bool,
    /// Capacidad tecnológica (predeterminada: código de aplicaciones).
    #[serde(default)]
    pub capacidad: Option<String>,
    #[serde(rename = "rama", default)]
    pub ramas: Vec<RamaDef>,
}

/// Resultado de evaluar una versión concreta de una biblioteca.
#[derive(Debug, Clone, PartialEq)]
pub struct EvaluacionBiblioteca {
    pub riesgo: Riesgo,
    pub advertencias: Vec<String>,
}

/// Segmentos numéricos de una versión («1.1.1w» -> [1, 1, 1]).
pub fn segmentos_version(v: &str) -> Vec<u64> {
    v.trim_start_matches(['v', 'V'])
        .trim_start_matches("go")
        .split(['.', '-', '+', '_'])
        .map_while(|s| {
            let d: String = s.chars().take_while(char::is_ascii_digit).collect();
            d.parse().ok()
        })
        .collect()
}

/// Compara dos versiones por sus segmentos numéricos.
pub fn comparar_versiones(a: &str, b: &str) -> std::cmp::Ordering {
    let (x, y) = (segmentos_version(a), segmentos_version(b));
    for i in 0..x.len().max(y.len()) {
        let o = x.get(i).unwrap_or(&0).cmp(y.get(i).unwrap_or(&0));
        if o != std::cmp::Ordering::Equal {
            return o;
        }
    }
    std::cmp::Ordering::Equal
}

impl BibliotecaDef {
    /// Versión efectiva (descarta prefijos de compilación como «300.3.1+»).
    pub fn version_efectiva<'a>(&self, version: &'a str) -> &'a str {
        if self.version_en_metadatos {
            version.split_once('+').map_or(version, |(_, v)| v)
        } else {
            version
        }
    }

    /// Rama más específica que contiene la versión.
    pub fn rama(&self, version: &str) -> Option<&RamaDef> {
        let v = segmentos_version(version);
        self.ramas
            .iter()
            .filter(|r| {
                let p = segmentos_version(&r.version);
                !p.is_empty() && v.len() >= p.len() && v[..p.len()] == p[..]
            })
            .max_by_key(|r| segmentos_version(&r.version).len())
    }

    /// Riesgo y advertencias de una versión, con la fecha de hoy (AAAA-MM-DD).
    pub fn evaluar(&self, version: Option<&str>, hoy: &str) -> EvaluacionBiblioteca {
        let mut advertencias: Vec<String> = self.nota.iter().cloned().collect();
        let base = self.riesgo_predeterminado.unwrap_or(Riesgo::Desconocido);
        let Some(version) = version.map(|v| self.version_efectiva(v)) else {
            if let Some(d) = &self.pq_disponible {
                advertencias.push(format!(
                    "Versión no determinada: {} ofrece PQC desde la versión {d}.",
                    self.nombre
                ));
            }
            return EvaluacionBiblioteca {
                riesgo: base,
                advertencias,
            };
        };
        let mut riesgo = base;
        let mayor_o_igual = |umbral: &Option<String>| {
            umbral
                .as_deref()
                .map(|u| comparar_versiones(version, u) != std::cmp::Ordering::Less)
        };
        match (
            mayor_o_igual(&self.pq_predeterminado),
            mayor_o_igual(&self.pq_disponible),
        ) {
            (Some(true), _) => {
                riesgo = Riesgo::HibridoPq;
                if let Some(n) = &self.nota_pq {
                    advertencias.push(n.clone());
                }
            }
            (_, Some(true)) => {
                riesgo = Riesgo::Desconocido;
                let extra = self
                    .nota_pq
                    .as_ref()
                    .map(|n| format!(" {n}"))
                    .unwrap_or_default();
                advertencias.push(if self.pq_predeterminado.is_some() {
                    format!(
                        "La versión {version} ofrece PQC, pero no la usa por omisión: verifique la configuración.{extra}"
                    )
                } else {
                    format!("La versión {version} ofrece PQC: verifique que la aplicación la use.{extra}")
                });
            }
            (_, Some(false)) => {
                riesgo = Riesgo::VulnerableCuantico;
                advertencias.push(format!(
                    "La versión {version} no ofrece criptografía poscuántica: actualice al menos a {}.",
                    self.pq_predeterminado
                        .as_ref()
                        .or(self.pq_disponible.as_ref())
                        .map(String::as_str)
                        .unwrap_or("una versión con PQC")
                ));
            }
            _ => {}
        }
        if let Some(r) = self.rama(version) {
            if r.fin_soporte.as_str() < hoy {
                riesgo = Riesgo::Obsoleto;
                advertencias.push(format!(
                    "La rama {} de {} dejó de recibir correcciones de seguridad el {}.",
                    r.version, self.nombre, r.fin_soporte
                ));
            } else if let (Some(fin), Some(h)) = (fecha_en_dias(&r.fin_soporte), fecha_en_dias(hoy))
                && fin - h <= 180
            {
                advertencias.push(format!(
                    "La rama {} de {} termina su soporte el {}: planifique la actualización.",
                    r.version, self.nombre, r.fin_soporte
                ));
            }
        }
        EvaluacionBiblioteca {
            riesgo,
            advertencias,
        }
    }
}

/// Días desde una época fija para una fecha AAAA-MM-DD (aproximado a meses de 31 días).
fn fecha_en_dias(f: &str) -> Option<i64> {
    let mut p = f.split('-').map(|x| x.parse::<i64>().ok());
    let (a, m, d) = (p.next()??, p.next()??, p.next()??);
    Some(a * 372 + (m - 1) * 31 + d)
}

#[derive(Debug, Clone, Deserialize)]
struct ArchivoBibliotecas {
    meta: Meta,
    #[serde(rename = "biblioteca", default)]
    bibliotecas: Vec<BibliotecaDef>,
}

/// Base de conocimiento cargada e indexada.
#[derive(Debug, Clone)]
pub struct Conocimiento {
    pub meta_algoritmos: Meta,
    pub meta_madurez: Meta,
    pub politica: Option<Politica>,
    pub algoritmos: Vec<AlgoritmoDef>,
    pub niveles: Vec<NivelDef>,
    pub capacidades: Vec<CapacidadDef>,
    pub codigo: BaseCodigo,
    pub meta_bibliotecas: Meta,
    pub bibliotecas: Vec<BibliotecaDef>,
    pub servicios: BaseServicios,
    pub recetas: BaseRecetas,
    por_paquete: HashMap<String, usize>,
    por_oid: HashMap<String, usize>,
    por_alias: HashMap<String, usize>,
    por_id: HashMap<String, usize>,
    por_codigo_tls: HashMap<u16, usize>,
}

impl Conocimiento {
    /// Base de conocimiento incrustada en el binario.
    pub fn embebido() -> Self {
        Self::desde_textos(ALGORITMOS_EMBEBIDOS, MADUREZ_EMBEBIDA)
            .expect("la base de conocimiento incrustada debe ser válida (lo verifican las pruebas)")
    }

    /// Carga `algoritmos.toml` y `madurez.toml` desde un directorio.
    pub fn desde_directorio(dir: &Path) -> Result<Self, ErrorConocimiento> {
        let leer = |nombre: &str| {
            let ruta = dir.join(nombre);
            std::fs::read_to_string(&ruta).map_err(|fuente| ErrorConocimiento::Lectura {
                ruta: ruta.display().to_string(),
                fuente,
            })
        };
        // Los archivos de reglas posteriores a 0.6 son opcionales: si el
        // directorio no los trae, se usan los incrustados.
        let opcional = |nombre: &str, incrustado: &'static str| {
            let ruta = dir.join(nombre);
            if ruta.exists() {
                std::fs::read_to_string(&ruta).map_err(|fuente| ErrorConocimiento::Lectura {
                    ruta: ruta.display().to_string(),
                    fuente,
                })
            } else {
                Ok(incrustado.to_string())
            }
        };
        let mut c = Self::desde_partes_con_servicios(
            &leer("algoritmos.toml")?,
            &leer("madurez.toml")?,
            &opcional("codigo.toml", CODIGO_EMBEBIDO)?,
            &opcional("bibliotecas.toml", BIBLIOTECAS_EMBEBIDAS)?,
            &opcional("servicios.toml", SERVICIOS_EMBEBIDOS)?,
        )?;
        c.recetas =
            BaseRecetas::desde_texto(&opcional("remediacion.toml", RECETAS_EMBEBIDAS)?, &c)?;
        Ok(c)
    }

    pub fn desde_textos(algoritmos: &str, madurez: &str) -> Result<Self, ErrorConocimiento> {
        Self::desde_partes(algoritmos, madurez, CODIGO_EMBEBIDO, BIBLIOTECAS_EMBEBIDAS)
    }

    pub fn desde_partes(
        algoritmos: &str,
        madurez: &str,
        codigo: &str,
        bibliotecas: &str,
    ) -> Result<Self, ErrorConocimiento> {
        Self::desde_partes_con_servicios(
            algoritmos,
            madurez,
            codigo,
            bibliotecas,
            SERVICIOS_EMBEBIDOS,
        )
    }

    pub fn desde_partes_con_servicios(
        algoritmos: &str,
        madurez: &str,
        codigo: &str,
        bibliotecas: &str,
        servicios: &str,
    ) -> Result<Self, ErrorConocimiento> {
        let a: ArchivoAlgoritmos =
            toml::from_str(algoritmos).map_err(|e| ErrorConocimiento::Formato {
                archivo: "algoritmos.toml".into(),
                fuente: Box::new(e),
            })?;
        let m: ArchivoMadurez =
            toml::from_str(madurez).map_err(|e| ErrorConocimiento::Formato {
                archivo: "madurez.toml".into(),
                fuente: Box::new(e),
            })?;

        let mut por_oid = HashMap::new();
        let mut por_alias = HashMap::new();
        let mut por_id = HashMap::new();
        let mut por_codigo_tls = HashMap::new();
        for (i, alg) in a.algoritmos.iter().enumerate() {
            for codigo in &alg.codigos_tls {
                if por_codigo_tls.insert(*codigo, i).is_some() {
                    return Err(ErrorConocimiento::Inconsistencia(format!(
                        "código de grupo TLS duplicado: {codigo}"
                    )));
                }
            }
            if por_id.insert(alg.id.clone(), i).is_some() {
                return Err(ErrorConocimiento::Inconsistencia(format!(
                    "id duplicado: {}",
                    alg.id
                )));
            }
            for oid in &alg.oids {
                if por_oid.insert(oid.clone(), i).is_some() {
                    return Err(ErrorConocimiento::Inconsistencia(format!(
                        "OID duplicado: {oid}"
                    )));
                }
            }
            for alias in &alg.alias {
                let clave = alias.to_lowercase();
                if !clave.contains(':') {
                    return Err(ErrorConocimiento::Inconsistencia(format!(
                        "el alias '{alias}' de '{}' debe tener la forma espacio:nombre",
                        alg.id
                    )));
                }
                if por_alias.insert(clave, i).is_some() {
                    return Err(ErrorConocimiento::Inconsistencia(format!(
                        "alias duplicado: {alias}"
                    )));
                }
            }
        }
        let codigo: BaseCodigo =
            toml::from_str(codigo).map_err(|e| ErrorConocimiento::Formato {
                archivo: "codigo.toml".into(),
                fuente: Box::new(e),
            })?;
        let incoherencia = |t: String| Err(ErrorConocimiento::Inconsistencia(t));
        for (espacio, tabla) in &codigo.nombres {
            for (nombre, id) in tabla {
                if !por_id.contains_key(id) {
                    return incoherencia(format!(
                        "codigo.toml: [nombres.{espacio}] «{nombre}» apunta a un algoritmo inexistente: {id}"
                    ));
                }
            }
        }
        let capacidad_valida = |id: &str| m.capacidades.iter().any(|c| c.id == id);
        for r in &codigo.reglas {
            for l in &r.lenguajes {
                if !LENGUAJES_CODIGO.contains(&l.as_str()) {
                    return incoherencia(format!("codigo.toml: lenguaje desconocido: {l}"));
                }
            }
            if let Some(cap) = &r.capacidad
                && !capacidad_valida(cap)
            {
                return incoherencia(format!(
                    "codigo.toml: la regla «{}» usa una capacidad inexistente: {cap}",
                    r.patron
                ));
            }
            match (&r.algoritmo, &r.espacio) {
                (Some(id), None) if !por_id.contains_key(id) => {
                    return incoherencia(format!(
                        "codigo.toml: la regla «{}» usa un algoritmo inexistente: {id}",
                        r.patron
                    ));
                }
                (None, Some(e)) if !codigo.nombres.contains_key(e) => {
                    return incoherencia(format!(
                        "codigo.toml: la regla «{}» usa un espacio sin [nombres.{e}]",
                        r.patron
                    ));
                }
                (Some(_), Some(_)) | (None, None) => {
                    return incoherencia(format!(
                        "codigo.toml: la regla «{}» debe declarar algoritmo o espacio (solo uno)",
                        r.patron
                    ));
                }
                _ => {}
            }
        }
        let b: ArchivoBibliotecas =
            toml::from_str(bibliotecas).map_err(|e| ErrorConocimiento::Formato {
                archivo: "bibliotecas.toml".into(),
                fuente: Box::new(e),
            })?;
        let mut por_paquete = HashMap::new();
        for (i, def) in b.bibliotecas.iter().enumerate() {
            for p in &def.paquetes {
                if !p.contains(':') {
                    return incoherencia(format!(
                        "bibliotecas.toml: el paquete «{p}» de {} debe tener la forma ecosistema:nombre",
                        def.id
                    ));
                }
                if por_paquete.insert(p.to_lowercase(), i).is_some() {
                    return incoherencia(format!("bibliotecas.toml: paquete duplicado: {p}"));
                }
            }
            if let Some(cap) = &def.capacidad
                && !capacidad_valida(cap)
            {
                return incoherencia(format!(
                    "bibliotecas.toml: {} usa una capacidad inexistente: {cap}",
                    def.id
                ));
            }
            for r in &def.ramas {
                if fecha_en_dias(&r.fin_soporte).is_none() {
                    return incoherencia(format!(
                        "bibliotecas.toml: fecha inválida en {}: {}",
                        def.id, r.fin_soporte
                    ));
                }
            }
        }
        let sv: BaseServicios =
            toml::from_str(servicios).map_err(|e| ErrorConocimiento::Formato {
                archivo: "servicios.toml".into(),
                fuente: Box::new(e),
            })?;
        let mut ids_servicio = std::collections::HashSet::new();
        for s in &sv.servicios {
            if !ids_servicio.insert(s.id.as_str()) {
                return incoherencia(format!("servicios.toml: servicio duplicado: {}", s.id));
            }
            if !capacidad_valida(&s.capacidad) {
                return incoherencia(format!(
                    "servicios.toml: {} usa una capacidad inexistente: {}",
                    s.id, s.capacidad
                ));
            }
            if s.archivos.is_empty() {
                return incoherencia(format!("servicios.toml: {} no declara archivos", s.id));
            }
        }
        if !m.capacidades.iter().any(|c| c.id == "sin-clasificar") {
            return Err(ErrorConocimiento::Inconsistencia(
                "madurez.toml debe definir la capacidad 'sin-clasificar'".into(),
            ));
        }

        let mut c = Self {
            meta_algoritmos: a.meta,
            meta_madurez: m.meta,
            politica: a.politica,
            algoritmos: a.algoritmos,
            niveles: m.niveles,
            capacidades: m.capacidades,
            codigo,
            meta_bibliotecas: b.meta,
            bibliotecas: b.bibliotecas,
            servicios: sv,
            recetas: BaseRecetas {
                meta: Meta {
                    version: String::new(),
                    descripcion: None,
                    fuente: None,
                    edicion: None,
                    fecha_evidencia: None,
                    caso_difusion: None,
                },
                recetas: Vec::new(),
            },
            por_paquete,
            por_oid,
            por_alias,
            por_id,
            por_codigo_tls,
        };
        // Las recetas se validan contra los algoritmos y capacidades ya cargados.
        c.recetas = BaseRecetas::desde_texto(RECETAS_EMBEBIDAS, &c)?;
        Ok(c)
    }

    /// Primera receta que se aplica a un activo.
    pub fn receta_para(&self, a: &ActivoReceta) -> Option<&Receta> {
        self.recetas.recetas.iter().find(|r| r.aplica(a))
    }

    /// Receta para un código de hallazgo del diagnóstico.
    pub fn receta_de_hallazgo(&self, codigo: &str) -> Option<&Receta> {
        self.recetas
            .recetas
            .iter()
            .find(|r| r.hallazgos.iter().any(|h| h == codigo))
    }

    /// Biblioteca por paquete: ecosistema («pypi», «npm»...) y nombre.
    pub fn por_paquete(&self, ecosistema: &str, nombre: &str) -> Option<&BibliotecaDef> {
        self.por_paquete
            .get(&format!("{ecosistema}:{nombre}").to_lowercase())
            .map(|&i| &self.bibliotecas[i])
    }

    pub fn biblioteca(&self, id: &str) -> Option<&BibliotecaDef> {
        self.bibliotecas.iter().find(|b| b.id == id)
    }

    pub fn por_oid(&self, oid: &str) -> Option<&AlgoritmoDef> {
        self.por_oid.get(oid).map(|&i| &self.algoritmos[i])
    }

    /// Busca por alias dentro de un espacio de nombres (`ssh-kex`, `tls-grupo`...).
    pub fn por_alias(&self, espacio: &str, nombre: &str) -> Option<&AlgoritmoDef> {
        let clave = format!("{}:{}", espacio, nombre.trim()).to_lowercase();
        self.por_alias.get(&clave).map(|&i| &self.algoritmos[i])
    }

    /// Busca por identificador IANA de grupo TLS.
    pub fn por_codigo_tls(&self, codigo: u16) -> Option<&AlgoritmoDef> {
        self.por_codigo_tls
            .get(&codigo)
            .map(|&i| &self.algoritmos[i])
    }

    /// Todos los grupos TLS conocidos, en el orden de la base de conocimiento.
    pub fn grupos_tls(&self) -> Vec<(u16, &AlgoritmoDef)> {
        self.algoritmos
            .iter()
            .flat_map(|d| d.codigos_tls.iter().map(move |c| (*c, d)))
            .collect()
    }

    pub fn por_id(&self, id: &str) -> Option<&AlgoritmoDef> {
        self.por_id.get(id).map(|&i| &self.algoritmos[i])
    }

    pub fn capacidad(&self, id: &str) -> Option<&CapacidadDef> {
        self.capacidades.iter().find(|c| c.id == id)
    }

    /// Nivel de madurez del ecosistema para una capacidad y garantía.
    /// La integridad (hash, MAC) no requiere migración por Shor: no aplica.
    pub fn madurez(&self, capacidad: &str, garantia: Garantia) -> NivelMadurez {
        let cap = self
            .capacidad(capacidad)
            .or_else(|| self.capacidad("sin-clasificar"));
        match (cap, garantia) {
            (_, Garantia::Integridad) => NivelMadurez::NoAplica,
            (Some(c), Garantia::Confidencialidad) => c.confidencialidad,
            (Some(c), Garantia::Autenticacion) => c.autenticacion,
            (None, _) => NivelMadurez::Desconocido,
        }
    }

    pub fn nombre_capacidad<'a>(&'a self, id: &'a str) -> &'a str {
        self.capacidad(id).map(|c| c.nombre.as_str()).unwrap_or(id)
    }

    /// Texto de procedencia para reportes y metadatos del CBOM.
    pub fn procedencia(&self) -> String {
        format!(
            "algoritmos {} · código {} · bibliotecas {} · servicios {} · remediación {} · madurez {} ({}, edición {})",
            self.meta_algoritmos.version,
            self.codigo.meta.version,
            self.meta_bibliotecas.version,
            self.servicios.meta.version,
            self.recetas.meta.version,
            self.meta_madurez.version,
            self.meta_madurez
                .fuente
                .as_deref()
                .unwrap_or("fuente no declarada"),
            self.meta_madurez.edicion.as_deref().unwrap_or("s/f"),
        )
    }
}

#[cfg(test)]
mod pruebas_bibliotecas {
    use super::*;

    #[test]
    fn versiones_y_soporte() {
        assert_eq!(
            comparar_versiones("3.0.13", "3.5.0"),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            comparar_versiones("1.1.1w", "1.1.1"),
            std::cmp::Ordering::Equal
        );
        assert_eq!(
            comparar_versiones("go1.24.1", "1.24"),
            std::cmp::Ordering::Greater
        );
        let c = Conocimiento::embebido();
        let o = c.biblioteca("openssl").unwrap();
        assert_eq!(o.rama("3.0.13").unwrap().version, "3.0");
        assert_eq!(o.rama("1.1.1w").unwrap().version, "1.1.1");
        assert_eq!(
            o.evaluar(Some("3.5.1"), "2026-10-16").riesgo,
            Riesgo::HibridoPq
        );
        assert_eq!(
            o.evaluar(Some("3.0.13"), "2026-10-16").riesgo,
            Riesgo::Obsoleto
        );
        assert_eq!(
            o.evaluar(Some("3.0.13"), "2026-01-01").riesgo,
            Riesgo::VulnerableCuantico
        );
        let cerca = o.evaluar(Some("3.6.0"), "2026-10-16");
        assert!(cerca.advertencias.iter().any(|a| a.contains("planifique")));
        assert_eq!(o.version_efectiva("300.3.1+3.3.1"), "3.3.1");
        assert!(c.por_paquete("PyPI", "Cryptography").is_some());
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn la_base_embebida_es_valida() {
        let c = Conocimiento::embebido();
        assert!(c.algoritmos.len() > 60);
        assert_eq!(c.politica.as_ref().unwrap().anio_retiro_vulnerables, 2030);
        assert_eq!(c.capacidades.len(), 13);
        assert_eq!(c.niveles.len(), 7);
    }

    #[test]
    fn recetas_de_correccion() {
        let c = Conocimiento::embebido();
        let receta = |algoritmo: Option<&str>, tipo: &str, riesgo, capacidad: &str, garantia| {
            c.receta_para(&ActivoReceta {
                algoritmo,
                tipo,
                riesgo,
                capacidad,
                garantia,
            })
            .map(|r| r.id.as_str())
        };
        let conf = Some(Garantia::Confidencialidad);
        let aut = Some(Garantia::Autenticacion);
        assert_eq!(
            receta(
                Some("x25519"),
                "algorithm",
                Riesgo::VulnerableCuantico,
                "servidores-web",
                conf
            ),
            Some("tls-hibrido")
        );
        assert_eq!(
            receta(
                Some("x25519"),
                "algorithm",
                Riesgo::VulnerableCuantico,
                "vpn-cifrado-red",
                conf
            ),
            Some("vpn-hibrido")
        );
        assert_eq!(
            receta(Some("rsa"), "algorithm", Riesgo::RotoClasico, "pki-ca", aut),
            Some("rsa-corta")
        );
        assert_eq!(
            receta(
                None,
                "certificate",
                Riesgo::VulnerableCuantico,
                "servidores-web",
                aut
            ),
            Some("firmas-pq")
        );
        assert_eq!(
            receta(
                None,
                "library",
                Riesgo::VulnerableCuantico,
                "codigo-aplicacion",
                conf
            ),
            Some("bibliotecas")
        );
        assert_eq!(
            receta(None, "protocol", Riesgo::HibridoPq, "servidores-web", conf),
            None
        );
        assert_eq!(
            c.receta_de_hallazgo("KEX-CLASICO").map(|r| r.id.as_str()),
            Some("tls-hibrido")
        );
        assert_eq!(
            c.receta_de_hallazgo("CERT-VENCE").map(|r| r.id.as_str()),
            Some("vigencia-certificados")
        );
        assert!(c.receta_de_hallazgo("CON-LENTO").is_none());
        assert!(
            c.recetas
                .recetas
                .iter()
                .all(|r| r.pasos_en.len() == r.pasos.len())
        );
    }

    #[test]
    fn busquedas_basicas() {
        let c = Conocimiento::embebido();
        let compuesta = c.por_oid("1.3.6.1.5.5.7.6.45").unwrap();
        assert_eq!(compuesta.id, "composite-mldsa65-ecdsa-p256-sha512");
        assert_eq!(compuesta.riesgo, Riesgo::HibridoPq);
        assert_eq!(
            c.por_oid("2.16.840.1.101.3.4.3.18").unwrap().id,
            "ml-dsa-65"
        );
        assert_eq!(c.por_oid("1.2.840.10045.3.1.7").unwrap().id, "ec-p256");
        assert_eq!(
            c.por_alias("tls-grupo", "X25519MLKEM768").unwrap().riesgo,
            Riesgo::HibridoPq
        );
        assert_eq!(
            c.por_alias("ssh-kex", "mlkem768x25519-sha256").unwrap().id,
            "x25519-mlkem768"
        );
        assert!(c.por_alias("ssh-kex", "x25519").is_none());
        assert_eq!(c.por_codigo_tls(0x11EC).unwrap().id, "x25519-mlkem768");
        assert_eq!(c.por_codigo_tls(0x001D).unwrap().id, "x25519");
    }

    #[test]
    fn rsa_pequeno_es_roto() {
        let c = Conocimiento::embebido();
        let rsa = c.por_id("rsa").unwrap();
        assert_eq!(rsa.riesgo_para_tamano(Some(1024)), Riesgo::RotoClasico);
        assert_eq!(
            rsa.riesgo_para_tamano(Some(3072)),
            Riesgo::VulnerableCuantico
        );
    }

    #[test]
    fn madurez_segun_reporte() {
        let c = Conocimiento::embebido();
        assert_eq!(
            c.madurez("servidores-web", Garantia::Confidencialidad),
            NivelMadurez::Integracion
        );
        assert_eq!(
            c.madurez("vpn-cifrado-red", Garantia::Autenticacion),
            NivelMadurez::ComponentesDisponibles
        );
        assert_eq!(
            c.madurez("firma-codigo", Garantia::Confidencialidad),
            NivelMadurez::NoAplica
        );
        assert_eq!(
            c.madurez("inexistente", Garantia::Autenticacion),
            NivelMadurez::Habilitado
        );
    }
}
