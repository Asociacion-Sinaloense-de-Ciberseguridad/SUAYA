//! # suaya-cbom
//!
//! - [`exportar`]: traduce el inventario de Suaya a un CBOM CycloneDX 1.7.
//! - [`lectura`]: interpreta un CBOM generado por Suaya.
//! - [`reporte`]: produce el reporte ejecutivo en español (Markdown).
//! - [`comparar`]: compara dos CBOM para seguir el avance de una migración.
//!
//! La clasificación de Suaya viaja dentro del CBOM como propiedades con el
//! prefijo `suaya:`, de modo que el CBOM es autosuficiente: cualquier
//! herramienta CycloneDX lo lee, y Suaya puede reconstruir su reporte sin
//! volver a escanear.

pub mod comparar;
pub mod exportar;
pub mod firma;
pub mod lectura;
pub mod reporte;

pub use comparar::comparar;
pub use exportar::{OpcionesCbom, generar};
pub use lectura::{CbomLeido, leer};
pub use reporte::{reporte_html, reporte_markdown};

/// Versión de la especificación CycloneDX que emite Suaya.
pub const VERSION_CYCLONEDX: &str = "1.7";
