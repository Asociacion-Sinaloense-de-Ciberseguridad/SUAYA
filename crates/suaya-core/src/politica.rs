//! Perfiles de política: evalúan el inventario contra un marco normativo
//! (NIST IR 8547, CNSA 2.0 o uno propio) y asignan a cada activo un estado de
//! cumplimiento y, si aplica, una fecha límite.
//!
//! Igual que la base de conocimiento, los perfiles son datos TOML. Una
//! organización o un regulador puede escribir el suyo a partir de
//! `conocimiento/perfiles/plantilla.toml` sin tocar el código.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::conocimiento::Conocimiento;
use crate::modelo::{Activo, Detalles, Inventario, Riesgo};

const PERFILES_EMBEBIDOS: &[(&str, &str)] = &[
    (
        "nist-ir-8547",
        include_str!("../../../conocimiento/perfiles/nist-ir-8547.toml"),
    ),
    (
        "cnsa-2.0",
        include_str!("../../../conocimiento/perfiles/cnsa-2.0.toml"),
    ),
    (
        "ue-hoja-de-ruta",
        include_str!("../../../conocimiento/perfiles/ue-hoja-de-ruta.toml"),
    ),
    (
        "ncsc-reino-unido",
        include_str!("../../../conocimiento/perfiles/reino-unido-ncsc.toml"),
    ),
    (
        "canada-cccs",
        include_str!("../../../conocimiento/perfiles/canada-cccs.toml"),
    ),
    (
        "pci-dss-4",
        include_str!("../../../conocimiento/perfiles/pci-dss-4.toml"),
    ),
    (
        "plantilla",
        include_str!("../../../conocimiento/perfiles/plantilla.toml"),
    ),
];

/// Estado de un activo frente a un perfil.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EstadoCumplimiento {
    NoConforme,
    Transicion,
    Conforme,
    SinEvaluar,
}

impl EstadoCumplimiento {
    pub fn como_texto(self) -> &'static str {
        match self {
            EstadoCumplimiento::NoConforme => "no-conforme",
            EstadoCumplimiento::Transicion => "transicion",
            EstadoCumplimiento::Conforme => "conforme",
            EstadoCumplimiento::SinEvaluar => "sin-evaluar",
        }
    }

    pub fn etiqueta(self) -> &'static str {
        match self {
            EstadoCumplimiento::NoConforme => crate::idioma::tx("No conforme", "Non-compliant"),
            EstadoCumplimiento::Transicion => crate::idioma::tx("En transición", "In transition"),
            EstadoCumplimiento::Conforme => crate::idioma::tx("Conforme", "Compliant"),
            EstadoCumplimiento::SinEvaluar => crate::idioma::tx("Sin evaluar", "Not evaluated"),
        }
    }
}

/// Resultado de evaluar un activo.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cumplimiento {
    pub perfil: String,
    pub estado: EstadoCumplimiento,
    /// Año a partir del cual el activo deja de estar permitido.
    pub prohibicion: Option<i32>,
    /// Año a partir del cual el activo está en retiro.
    pub retiro: Option<i32>,
    pub nota: String,
    /// Índice de la regla del perfil que decidió el estado.
    #[serde(default)]
    pub regla: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Regla {
    #[serde(default)]
    pub algoritmos: Vec<String>,
    #[serde(default)]
    pub familias: Vec<String>,
    #[serde(default)]
    pub riesgos: Vec<Riesgo>,
    #[serde(default)]
    pub capacidades: Vec<String>,
    #[serde(default)]
    pub tamano_minimo: Option<u32>,
    /// Criticidad del sistema según el archivo de contexto (`alta`, `media`, `baja`).
    #[serde(default)]
    pub criticidades: Vec<crate::modelo::Criticidad>,
    pub estado: EstadoCumplimiento,
    #[serde(default)]
    pub retiro: Option<i32>,
    #[serde(default)]
    pub prohibicion: Option<i32>,
    #[serde(default)]
    pub nota: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Encabezado {
    pub id: String,
    pub nombre: String,
    pub referencia: String,
    #[serde(default = "sin_evaluar")]
    pub predeterminado: EstadoCumplimiento,
    #[serde(default)]
    pub ignorar_primitivas: Vec<String>,
}

fn sin_evaluar() -> EstadoCumplimiento {
    EstadoCumplimiento::SinEvaluar
}

/// Perfil de política cargado.
#[derive(Debug, Clone, Deserialize)]
pub struct Perfil {
    pub perfil: Encabezado,
    #[serde(default)]
    pub plazos: BTreeMap<String, i32>,
    #[serde(rename = "regla", default)]
    pub reglas: Vec<Regla>,
}

impl Regla {
    /// Descripción legible de a qué aplica la regla y qué exige.
    pub fn describir(&self) -> String {
        let mut partes: Vec<String> = Vec::new();
        if !self.algoritmos.is_empty() {
            let v = self.algoritmos.join(", ");
            partes.push(crate::t!("algoritmos {v}", "algorithms {v}"));
        }
        if !self.familias.is_empty() {
            let v = self.familias.join(", ");
            partes.push(crate::t!("familias {v}", "families {v}"));
        }
        if !self.riesgos.is_empty() {
            let v: Vec<&str> = self.riesgos.iter().map(|r| r.etiqueta()).collect();
            let v = v.join(", ");
            partes.push(crate::t!("riesgo {v}", "risk {v}"));
        }
        if !self.capacidades.is_empty() {
            let v = self.capacidades.join(", ");
            partes.push(crate::t!("capacidades {v}", "capabilities {v}"));
        }
        if let Some(t) = self.tamano_minimo {
            partes.push(crate::t!("de al menos {t} bits", "of at least {t} bits"));
        }
        if !self.criticidades.is_empty() {
            let v: Vec<&str> = self.criticidades.iter().map(|c| c.etiqueta()).collect();
            let v = v.join(", ");
            partes.push(crate::t!(
                "sistemas de criticidad {v}",
                "systems of criticality {v}"
            ));
        }
        let alcance = if partes.is_empty() {
            crate::idioma::tx("cualquier activo", "any asset").to_string()
        } else {
            partes.join("; ")
        };
        let estado = self.estado.etiqueta();
        let mut t = crate::t!("{alcance}: {estado}", "{alcance}: {estado}");
        if let Some(p) = self.prohibicion {
            t.push_str(&crate::t!(" hasta {p}", " until {p}"));
        }
        t
    }
}

impl Perfil {
    pub fn desde_texto(texto: &str) -> Result<Self, String> {
        toml::from_str(texto).map_err(|e| format!("perfil inválido: {e}"))
    }

    /// Carga un perfil incrustado por su identificador o un archivo TOML.
    pub fn cargar(id_o_ruta: &str) -> Result<Self, String> {
        if let Some((_, t)) = PERFILES_EMBEBIDOS.iter().find(|(id, _)| *id == id_o_ruta) {
            return Self::desde_texto(t);
        }
        let ruta = Path::new(id_o_ruta);
        if ruta.exists() {
            let t = std::fs::read_to_string(ruta)
                .map_err(|e| format!("no se pudo leer {id_o_ruta}: {e}"))?;
            return Self::desde_texto(&t);
        }
        Err(format!(
            "perfil desconocido: {id_o_ruta} (incluidos: {})",
            PERFILES_EMBEBIDOS
                .iter()
                .map(|(id, _)| *id)
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }

    pub fn incluidos() -> Vec<Self> {
        PERFILES_EMBEBIDOS
            .iter()
            .filter_map(|(_, t)| Self::desde_texto(t).ok())
            .collect()
    }

    fn plazo(&self, capacidades: &[&str]) -> Option<i32> {
        capacidades
            .iter()
            .filter_map(|c| self.plazos.get(*c))
            .min()
            .or_else(|| self.plazos.get("predeterminado"))
            .copied()
    }

    /// Evalúa un activo de tipo algoritmo.
    fn evaluar_algoritmo(
        &self,
        a: &Activo,
        riesgo: Riesgo,
        c: &Conocimiento,
        anio: i32,
    ) -> Option<Cumplimiento> {
        let (id, tamano) = match &a.detalles {
            Detalles::Algoritmo {
                algoritmo_id,
                tamano_llave,
            } => (algoritmo_id.as_deref(), *tamano_llave),
            _ => return None,
        };
        self.evaluar_con(a, id, tamano, riesgo, c, anio, true)
    }

    /// Evalúa con las reglas del perfil. Sin algoritmo (`id` vacío) solo
    /// aplican las reglas por riesgo; `con_predeterminado` decide qué pasa
    /// cuando ninguna regla coincide.
    #[allow(clippy::too_many_arguments)]
    fn evaluar_con(
        &self,
        a: &Activo,
        id: Option<&str>,
        tamano: Option<u32>,
        riesgo: Riesgo,
        c: &Conocimiento,
        anio: i32,
        con_predeterminado: bool,
    ) -> Option<Cumplimiento> {
        let def = id.and_then(|i| c.por_id(i));
        if def.is_some_and(|d| self.perfil.ignorar_primitivas.contains(&d.primitiva)) {
            return None;
        }
        let capacidades: Vec<&str> = a.contextos.iter().map(|x| x.capacidad.as_str()).collect();
        let indice = self.reglas.iter().position(|r| {
            (r.algoritmos.is_empty() || id.is_some_and(|i| r.algoritmos.iter().any(|x| x == i)))
                && (r.familias.is_empty()
                    || def
                        .and_then(|d| d.familia.as_ref())
                        .is_some_and(|f| r.familias.contains(f)))
                && (r.riesgos.is_empty() || r.riesgos.contains(&riesgo))
                && (r.capacidades.is_empty()
                    || capacidades
                        .iter()
                        .any(|c| r.capacidades.iter().any(|x| x == c)))
                && r.tamano_minimo
                    .is_none_or(|m| tamano.is_some_and(|t| t >= m))
                && (r.criticidades.is_empty()
                    || a.organizacion
                        .as_ref()
                        .and_then(|o| o.criticidad)
                        .is_some_and(|k| r.criticidades.contains(&k)))
        });
        let regla = indice.map(|i| &self.reglas[i]);
        let Some(r) = regla else {
            if !con_predeterminado {
                return None;
            }
            return Some(Cumplimiento {
                perfil: self.perfil.id.clone(),
                estado: self.perfil.predeterminado,
                prohibicion: None,
                retiro: None,
                nota: "Ninguna regla del perfil cubre este algoritmo.".into(),
                regla: None,
            });
        };
        let mut estado = r.estado;
        let mut prohibicion = None;
        let mut nota = r.nota.clone().unwrap_or_default();
        if estado == EstadoCumplimiento::Transicion {
            prohibicion = r.prohibicion.or_else(|| self.plazo(&capacidades));
            if let Some(p) = prohibicion
                && anio >= p
            {
                estado = EstadoCumplimiento::NoConforme;
                nota = format!("Plazo vencido en {p}. {nota}");
            }
        }
        Some(Cumplimiento {
            perfil: self.perfil.id.clone(),
            estado,
            prohibicion,
            retiro: if r.estado == EstadoCumplimiento::Transicion {
                r.retiro
            } else {
                None
            },
            nota: nota.trim().to_string(),
            regla: indice,
        })
    }

    /// Evalúa todo el inventario (ya clasificado) para el año indicado.
    pub fn evaluar(&self, inv: &mut Inventario, c: &Conocimiento, anio: i32) {
        for a in inv.activos.iter_mut() {
            let riesgo = a
                .clasificacion
                .as_ref()
                .map(|x| x.riesgo)
                .unwrap_or(Riesgo::Desconocido);
            a.cumplimiento = self.evaluar_algoritmo(a, riesgo, c, anio);
        }
        // Certificados, llaves y protocolos: el peor estado de sus algoritmos.
        let por_ref: BTreeMap<String, Cumplimiento> = inv
            .activos
            .iter()
            .filter_map(|a| a.cumplimiento.clone().map(|x| (a.referencia.clone(), x)))
            .collect();
        let clave = |x: &Cumplimiento| (x.estado, x.prohibicion.unwrap_or(i32::MAX));
        for a in inv.activos.iter_mut() {
            if matches!(a.detalles, Detalles::Algoritmo { .. }) {
                continue;
            }
            let peor = a
                .relaciones
                .iter()
                .filter_map(|r| por_ref.get(&r.referencia))
                .min_by_key(|x| clave(x))
                .cloned();
            let riesgo = a
                .clasificacion
                .as_ref()
                .map(|x| x.riesgo)
                .unwrap_or(Riesgo::Desconocido);
            // El riesgo propio del activo cuenta cuando lo agrava (por ejemplo,
            // un protocolo que habilita TLS 1.0) o cuando no hay algoritmos
            // relacionados que evaluar.
            let propio = if matches!(riesgo, Riesgo::RotoClasico | Riesgo::Obsoleto)
                || (peor.is_none() && riesgo != Riesgo::Desconocido)
            {
                self.evaluar_con(a, None, None, riesgo, c, anio, false)
            } else {
                None
            };
            a.cumplimiento = match (peor, propio) {
                (Some(x), Some(y)) => Some(if clave(&y) < clave(&x) { y } else { x }),
                (x, y) => x.or(y),
            };
        }
        // Lo que no tiene algoritmo identificado queda explícitamente sin evaluar.
        for a in inv.activos.iter_mut() {
            if a.cumplimiento.is_none() {
                a.cumplimiento = Some(Cumplimiento {
                    perfil: self.perfil.id.clone(),
                    estado: EstadoCumplimiento::SinEvaluar,
                    prohibicion: None,
                    retiro: None,
                    nota: "Sin algoritmo identificado que el perfil pueda evaluar.".into(),
                    regla: None,
                });
            }
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::modelo::{Detalles, Garantia};

    fn alg(id: &str, tamano: Option<u32>, capacidad: &str) -> Activo {
        Activo::nuevo(
            format!(
                "algoritmo:{id}{}",
                tamano.map(|t| format!("-{t}")).unwrap_or_default()
            ),
            id,
            Detalles::Algoritmo {
                algoritmo_id: Some(id.into()),
                tamano_llave: tamano,
            },
        )
        .con_contexto(capacidad, Garantia::Autenticacion)
    }

    fn evaluar(perfil: &str, activos: Vec<Activo>, anio: i32) -> Vec<Option<Cumplimiento>> {
        let c = Conocimiento::embebido();
        let mut inv = Inventario::default();
        inv.extender(activos);
        crate::clasificar(&mut inv, &c);
        Perfil::cargar(perfil).unwrap().evaluar(&mut inv, &c, anio);
        let mut v: Vec<(String, Option<Cumplimiento>)> = inv
            .activos
            .into_iter()
            .map(|a| (a.referencia, a.cumplimiento))
            .collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v.into_iter().map(|(_, c)| c).collect()
    }

    #[test]
    fn los_perfiles_incluidos_son_validos() {
        assert_eq!(Perfil::incluidos().len(), 7);
        assert!(Perfil::cargar("inexistente").is_err());
    }

    #[test]
    fn plazo_por_criticidad_del_sistema() {
        let c = Conocimiento::embebido();
        let ue = Perfil::cargar("ue-hoja-de-ruta").unwrap();
        let activo = |criticidad: Option<crate::modelo::Criticidad>| {
            let mut a = Activo::nuevo(
                "algoritmo:x25519",
                "X25519",
                Detalles::Algoritmo {
                    algoritmo_id: Some("x25519".into()),
                    tamano_llave: None,
                },
            )
            .con_contexto("servidores-web", crate::Garantia::Confidencialidad);
            a.organizacion = criticidad.map(|k| crate::modelo::ContextoOrganizacional {
                criticidad: Some(k),
                ..Default::default()
            });
            let mut inv = Inventario::default();
            inv.agregar(a);
            crate::clasificar(&mut inv, &c);
            ue.evaluar(&mut inv, &c, 2026);
            inv.activos[0].cumplimiento.clone().unwrap()
        };
        assert_eq!(
            activo(Some(crate::modelo::Criticidad::Alta)).prohibicion,
            Some(2030)
        );
        assert_eq!(
            activo(Some(crate::modelo::Criticidad::Baja)).prohibicion,
            Some(2035)
        );
        assert_eq!(activo(None).prohibicion, Some(2035));
        // CNSA 2.0: LMS es conforme solo para firmar software y firmware.
        let cnsa = Perfil::cargar("cnsa-2.0").unwrap();
        let lms = |capacidad: &str| {
            let mut inv = Inventario::default();
            inv.agregar(
                Activo::nuevo(
                    "algoritmo:hss-lms",
                    "HSS/LMS",
                    Detalles::Algoritmo {
                        algoritmo_id: Some("hss-lms".into()),
                        tamano_llave: None,
                    },
                )
                .con_contexto(capacidad, crate::Garantia::Autenticacion),
            );
            crate::clasificar(&mut inv, &c);
            cnsa.evaluar(&mut inv, &c, 2026);
            inv.activos[0].cumplimiento.clone().unwrap().estado
        };
        assert_eq!(lms("firma-codigo"), EstadoCumplimiento::Conforme);
        assert_eq!(lms("servidores-web"), EstadoCumplimiento::NoConforme);
    }

    #[test]
    fn nist_ir_8547() {
        let r = evaluar(
            "nist-ir-8547",
            vec![
                alg("ecdh-p256", None, "servidores-web"),
                alg("ml-kem-768", None, "servidores-web"),
            ],
            2026,
        );
        let p256 = r[0].as_ref().unwrap();
        assert_eq!(
            (p256.estado, p256.retiro, p256.prohibicion),
            (EstadoCumplimiento::Transicion, Some(2030), Some(2035))
        );
        assert_eq!(r[1].as_ref().unwrap().estado, EstadoCumplimiento::Conforme);
        let vencido = evaluar(
            "nist-ir-8547",
            vec![alg("ecdh-p256", None, "servidores-web")],
            2035,
        );
        assert_eq!(
            vencido[0].as_ref().unwrap().estado,
            EstadoCumplimiento::NoConforme
        );
    }

    #[test]
    fn cnsa_2_0_plazos_por_capacidad_y_tamano() {
        let r = evaluar(
            "cnsa-2.0",
            vec![
                alg("rsa", Some(2048), "vpn-cifrado-red"),
                alg("rsa", Some(3072), "vpn-cifrado-red"),
                alg("ml-kem-768", None, "servidores-web"),
                alg("ml-kem-1024", None, "servidores-web"),
                alg("ec-p384", None, "servidores-web"),
            ],
            2026,
        );
        // Orden por referencia: ec-p384, ml-kem-1024, ml-kem-768, rsa-2048, rsa-3072.
        let estados: Vec<_> = r
            .iter()
            .map(|x| x.as_ref().map(|c| (c.estado, c.prohibicion)))
            .collect();
        assert_eq!(
            estados[0],
            Some((EstadoCumplimiento::Transicion, Some(2033)))
        );
        assert_eq!(estados[1], Some((EstadoCumplimiento::Conforme, None)));
        assert_eq!(estados[2].unwrap().0, EstadoCumplimiento::NoConforme);
        assert_eq!(estados[3].unwrap().0, EstadoCumplimiento::NoConforme);
        assert_eq!(
            estados[4],
            Some((EstadoCumplimiento::Transicion, Some(2030)))
        );
    }
}
