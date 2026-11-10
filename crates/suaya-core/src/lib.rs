//! # suaya-core
//!
//! Núcleo de Suaya. Contiene:
//!
//! - [`modelo`]: los tipos que describen un activo criptográfico hallado.
//! - [`conocimiento`]: la base de conocimiento (algoritmos y madurez del
//!   ecosistema), cargada desde archivos TOML versionados.
//! - [`clasificacion`]: el motor que decide riesgo, acción y prioridad.
//!
//! Principio de diseño: el código no contiene listas de algoritmos ni niveles
//! de madurez. Todo criterio vive en `conocimiento/*.toml`, de modo que la
//! herramienta misma es criptoágil: cambiar de criterio es cambiar datos.

pub mod clasificacion;
pub mod conocimiento;
pub mod contexto;
pub mod enlace;
pub mod idioma;
pub mod modelo;
pub mod politica;

pub use clasificacion::{Accion, Clasificacion, clasificar, etiqueta_prioridad};
pub use conocimiento::{
    ActivoReceta, AlgoritmoDef, BibliotecaDef, Conocimiento, ErrorConocimiento,
    EvaluacionBiblioteca, Receta, ServicioDef, comparar_versiones,
};
pub use modelo::*;
pub use politica::{Cumplimiento, EstadoCumplimiento, Perfil};

/// Versión de Suaya, tomada del manifiesto del paquete.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
