//! Evolución de varios CBOM de Suaya en el tiempo: cuántos activos hay en
//! cada prioridad, cuántos ya están protegidos y cuántos siguen expuestos,
//! escaneo por escaneo.

use std::fmt::Write;

use serde::Serialize;
use serde_json::{Value, json};
use suaya_core::idioma::tx;
use suaya_core::t;

use crate::lectura::CbomLeido;

/// Un escaneo en la serie.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Punto {
    pub fecha: String,
    pub sistema: String,
    pub total: usize,
    /// Activos de prioridad 1 (crítica) a 5 (informativa).
    pub por_prioridad: [usize; 5],
    /// Híbridos o resistentes a cómputo cuántico.
    pub protegidos: usize,
    pub vulnerables: usize,
    /// Rotos u obsoletos.
    pub inseguros: usize,
    /// No conformes con el perfil evaluado, si lo hubo.
    pub no_conformes: Option<usize>,
    pub expuestos_mosca: usize,
}

impl Punto {
    fn de(c: &CbomLeido) -> Self {
        let n = |f: &dyn Fn(&crate::lectura::Registro) -> bool| {
            c.registros.iter().filter(|r| f(r)).count()
        };
        let mut por_prioridad = [0usize; 5];
        for r in &c.registros {
            if (1..=5).contains(&r.prioridad) {
                por_prioridad[r.prioridad as usize - 1] += 1;
            }
        }
        Punto {
            fecha: c.fecha.clone(),
            sistema: c.sistema.clone(),
            total: c.registros.len(),
            por_prioridad,
            protegidos: n(&|r| r.riesgo == "hibrido-pq" || r.riesgo == "resistente-cuantico"),
            vulnerables: n(&|r| r.riesgo == "vulnerable-cuantico"),
            inseguros: n(&|r| r.riesgo == "roto-clasico" || r.riesgo == "obsoleto"),
            no_conformes: c
                .perfil
                .as_ref()
                .map(|_| n(&|r| r.cumplimiento == "no-conforme")),
            expuestos_mosca: n(&|r| r.holgura_mosca.is_some_and(|h| h < 0)),
        }
    }

    /// Porcentaje de activos protegidos.
    pub fn porcentaje_protegido(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            100.0 * self.protegidos as f64 / self.total as f64
        }
    }
}

/// Serie ordenada por fecha de escaneo.
pub fn tendencias(cboms: &[CbomLeido]) -> Vec<Punto> {
    let mut v: Vec<Punto> = cboms.iter().map(Punto::de).collect();
    v.sort_by(|a, b| a.fecha.cmp(&b.fecha));
    v
}

/// El último escaneo tiene más hallazgos críticos o altos que el anterior.
pub fn empeora(serie: &[Punto]) -> bool {
    match serie {
        [.., a, b] => {
            b.por_prioridad[0] + b.por_prioridad[1] > a.por_prioridad[0] + a.por_prioridad[1]
        }
        _ => false,
    }
}

fn diferencia(a: usize, b: usize) -> String {
    match b as i64 - a as i64 {
        0 => "=".into(),
        d if d > 0 => format!("+{d}"),
        d => d.to_string(),
    }
}

const ENCABEZADOS: [(&str, &str); 10] = [
    ("Fecha", "Date"),
    ("Activos", "Assets"),
    ("Críticos", "Critical"),
    ("Altos", "High"),
    ("Medios", "Medium"),
    ("Bajos", "Low"),
    ("Protegidos", "Protected"),
    ("Vulnerables", "Vulnerable"),
    ("No conformes", "Non-compliant"),
    ("Expuestos (Mosca)", "Exposed (Mosca)"),
];

fn fila(p: &Punto) -> [String; 10] {
    [
        p.fecha.get(..10).unwrap_or(&p.fecha).to_string(),
        p.total.to_string(),
        p.por_prioridad[0].to_string(),
        p.por_prioridad[1].to_string(),
        p.por_prioridad[2].to_string(),
        p.por_prioridad[3].to_string(),
        format!("{} ({:.0} %)", p.protegidos, p.porcentaje_protegido()),
        p.vulnerables.to_string(),
        p.no_conformes
            .map(|n| n.to_string())
            .unwrap_or_else(|| "-".into()),
        p.expuestos_mosca.to_string(),
    ]
}

fn resumen(serie: &[Punto]) -> Option<String> {
    let (a, b) = (serie.first()?, serie.last()?);
    if serie.len() < 2 {
        return None;
    }
    Some(t!(
        "Del {} al {}: críticos {}, altos {}, protegidos {}, vulnerables {}.",
        "From {} to {}: critical {}, high {}, protected {}, vulnerable {}.",
        a.fecha.get(..10).unwrap_or(&a.fecha),
        b.fecha.get(..10).unwrap_or(&b.fecha),
        diferencia(a.por_prioridad[0], b.por_prioridad[0]),
        diferencia(a.por_prioridad[1], b.por_prioridad[1]),
        diferencia(a.protegidos, b.protegidos),
        diferencia(a.vulnerables, b.vulnerables)
    ))
}

fn encabezados() -> Vec<&'static str> {
    ENCABEZADOS.iter().map(|(es, en)| tx(es, en)).collect()
}

/// Tabla alineada para la terminal.
pub fn como_texto(serie: &[Punto]) -> String {
    let filas: Vec<[String; 10]> = serie.iter().map(fila).collect();
    let cab = encabezados();
    let anchos: Vec<usize> = (0..10)
        .map(|i| {
            filas
                .iter()
                .map(|f| f[i].chars().count())
                .chain([cab[i].chars().count()])
                .max()
                .unwrap_or(0)
        })
        .collect();
    let mut s = String::new();
    let linea = |s: &mut String, celdas: &[String]| {
        let partes: Vec<String> = celdas
            .iter()
            .zip(&anchos)
            .enumerate()
            .map(|(i, (x, w))| {
                if i == 0 {
                    format!("{x:<w$}")
                } else {
                    format!("{x:>w$}")
                }
            })
            .collect();
        let _ = writeln!(s, "{}", partes.join("  ").trim_end());
    };
    linea(
        &mut s,
        &cab.iter().map(|x| x.to_string()).collect::<Vec<_>>(),
    );
    for f in &filas {
        linea(&mut s, f);
    }
    if let Some(r) = resumen(serie) {
        let _ = writeln!(s, "\n{r}");
    }
    s
}

/// Tabla Markdown.
pub fn como_markdown(serie: &[Punto]) -> String {
    let mut s = format!(
        "# {}\n\n",
        tx(
            "Tendencias de la migración poscuántica",
            "Post-quantum migration trends"
        )
    );
    let _ = writeln!(s, "| {} |", encabezados().join(" | "));
    let _ = writeln!(s, "|---|{}", "---:|".repeat(9));
    for p in serie {
        let _ = writeln!(s, "| {} |", fila(p).join(" | "));
    }
    if let Some(r) = resumen(serie) {
        let _ = writeln!(s, "\n{r}");
    }
    s
}

/// CSV con los mismos datos (sin formato de porcentaje).
pub fn como_csv(serie: &[Punto]) -> String {
    let mut s = String::from(
        "fecha,sistema,total,criticos,altos,medios,bajos,informativos,protegidos,vulnerables,inseguros,no_conformes,expuestos_mosca\r\n",
    );
    for p in serie {
        let sistema = if p.sistema.contains([',', '"', '\n']) {
            format!("\"{}\"", p.sistema.replace('"', "\"\""))
        } else {
            p.sistema.clone()
        };
        let _ = write!(
            s,
            "{},{sistema},{},{},{},{},{},{},{},{},{},{},{}\r\n",
            p.fecha,
            p.total,
            p.por_prioridad[0],
            p.por_prioridad[1],
            p.por_prioridad[2],
            p.por_prioridad[3],
            p.por_prioridad[4],
            p.protegidos,
            p.vulnerables,
            p.inseguros,
            p.no_conformes.map(|n| n.to_string()).unwrap_or_default(),
            p.expuestos_mosca
        );
    }
    s
}

pub fn como_json(serie: &[Punto]) -> Value {
    json!({
        "herramienta": format!("Suaya {}", suaya_core::VERSION),
        "escaneos": serie,
        "empeora": empeora(serie),
    })
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn punto(fecha: &str, criticos: usize, protegidos: usize) -> Punto {
        Punto {
            fecha: fecha.into(),
            sistema: "x".into(),
            total: 10,
            por_prioridad: [criticos, 0, 0, 0, 10 - criticos],
            protegidos,
            vulnerables: 0,
            inseguros: criticos,
            no_conformes: None,
            expuestos_mosca: 0,
        }
    }

    #[test]
    fn serie_y_regresion() {
        let serie = vec![
            punto("2026-01-01T00:00:00Z", 3, 1),
            punto("2026-06-01T00:00:00Z", 1, 4),
        ];
        assert!(!empeora(&serie));
        let texto = como_texto(&serie);
        assert!(
            texto.contains("críticos -2") || texto.contains("critical -2"),
            "{texto}"
        );
        assert!(
            texto.contains("protegidos +3") || texto.contains("protected +3"),
            "{texto}"
        );
        assert!(empeora(&[serie[1].clone(), serie[0].clone()]));
        assert_eq!(como_csv(&serie).lines().count(), 3);
        assert!(como_markdown(&serie).contains("| 2026-06-01 | 10 | 1 |"));
    }
}
