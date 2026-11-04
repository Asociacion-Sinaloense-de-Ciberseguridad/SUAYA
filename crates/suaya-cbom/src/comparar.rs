//! Comparación de dos CBOM de Suaya, para seguir el avance de una migración.

use std::collections::BTreeMap;
use std::fmt::Write;

use suaya_core::etiqueta_prioridad;
use suaya_core::idioma::{traducir, tx};
use suaya_core::t;

use crate::lectura::{CbomLeido, Registro};

/// Resultado de comparar dos inventarios.
#[derive(Debug, Default)]
pub struct Diferencias<'a> {
    pub nuevos: Vec<&'a Registro>,
    pub eliminados: Vec<&'a Registro>,
    /// (anterior, actual) cuando cambió el riesgo o la prioridad.
    pub cambiados: Vec<(&'a Registro, &'a Registro)>,
}

impl Diferencias<'_> {
    /// Hay regresión si aparecen activos críticos o altos, o si alguno empeora.
    pub fn hay_regresion(&self) -> bool {
        self.nuevos.iter().any(|r| r.prioridad <= 2)
            || self
                .cambiados
                .iter()
                .any(|(a, b)| b.prioridad < a.prioridad)
    }

    pub fn como_texto(&self, anterior: &CbomLeido, actual: &CbomLeido) -> String {
        let mut s = String::new();
        let _ = writeln!(
            s,
            "{}",
            tx("Comparación de inventarios", "Inventory comparison")
        );
        let (fa, na) = (&anterior.fecha, anterior.registros.len());
        let (fb, nb) = (&actual.fecha, actual.registros.len());
        let _ = writeln!(
            s,
            "{}",
            t!(
                "  anterior: {fa} ({na} activos)",
                "  previous: {fa} ({na} assets)"
            )
        );
        let _ = writeln!(
            s,
            "{}",
            t!(
                "  actual:   {fb} ({nb} activos)",
                "  current:  {fb} ({nb} assets)"
            )
        );
        let _ = writeln!(s);
        let riesgo = |r: &Registro| {
            serde_json::from_value::<suaya_core::Riesgo>(serde_json::json!(r.riesgo))
                .map(|x| x.etiqueta().to_string())
                .unwrap_or_else(|_| r.riesgo.clone())
        };
        let linea = |r: &Registro| {
            format!(
                "{} [{}, {}]",
                traducir(&r.nombre),
                etiqueta_prioridad(r.prioridad),
                riesgo(r)
            )
        };
        let n = self.nuevos.len();
        let _ = writeln!(s, "{}", t!("Nuevos ({n}):", "New ({n}):"));
        for r in &self.nuevos {
            let _ = writeln!(s, "  + {}", linea(r));
        }
        let n = self.eliminados.len();
        let _ = writeln!(s, "{}", t!("Eliminados ({n}):", "Removed ({n}):"));
        for r in &self.eliminados {
            let _ = writeln!(s, "  - {}", linea(r));
        }
        let n = self.cambiados.len();
        let _ = writeln!(s, "{}", t!("Cambiados ({n}):", "Changed ({n}):"));
        for (a, b) in &self.cambiados {
            let flecha = if b.prioridad > a.prioridad {
                tx("mejora", "better")
            } else if b.prioridad < a.prioridad {
                tx("empeora", "worse")
            } else {
                tx("cambia", "changed")
            };
            let _ = writeln!(
                s,
                "  ~ {}: {} ({}) -> {} ({}) [{flecha}]",
                traducir(&b.nombre),
                riesgo(a),
                etiqueta_prioridad(a.prioridad),
                riesgo(b),
                etiqueta_prioridad(b.prioridad)
            );
        }
        s
    }
}

pub fn comparar<'a>(anterior: &'a CbomLeido, actual: &'a CbomLeido) -> Diferencias<'a> {
    let a: BTreeMap<&str, &Registro> = anterior
        .registros
        .iter()
        .map(|r| (r.referencia.as_str(), r))
        .collect();
    let b: BTreeMap<&str, &Registro> = actual
        .registros
        .iter()
        .map(|r| (r.referencia.as_str(), r))
        .collect();
    let mut d = Diferencias::default();
    for (k, rb) in &b {
        match a.get(k) {
            None => d.nuevos.push(rb),
            Some(ra) if ra.riesgo != rb.riesgo || ra.prioridad != rb.prioridad => {
                d.cambiados.push((ra, rb))
            }
            _ => {}
        }
    }
    for (k, ra) in &a {
        if !b.contains_key(k) {
            d.eliminados.push(ra);
        }
    }
    d
}
