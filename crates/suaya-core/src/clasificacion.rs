//! Motor de clasificación.
//!
//! Cada activo se evalúa en cuatro ejes:
//!
//! 1. **Riesgo**: roto, obsoleto, vulnerable a Shor, debilitado por Grover,
//!    híbrido o resistente.
//! 2. **Garantía**: confidencialidad, autenticación o integridad.
//! 3. **Capacidad**: en qué tipo de tecnología vive el activo.
//! 4. **Madurez del ecosistema**: si ya existen productos para migrarlo.
//!
//! El cruce de estos ejes produce una [`Accion`] y una prioridad de 1 a 5.
//! La confidencialidad se prioriza sobre la autenticación porque el tráfico
//! cifrado hoy puede guardarse y descifrarse cuando exista una computadora
//! cuántica capaz ("cosechar ahora, descifrar después").

use serde::{Deserialize, Serialize};

use crate::conocimiento::Conocimiento;
use crate::modelo::{Activo, Contexto, Detalles, Garantia, Inventario, NivelMadurez, Riesgo};

/// Acción recomendada para un activo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Accion {
    /// Inseguro hoy: corregir de inmediato.
    CorregirYa,
    /// Retirado por los estándares: reemplazar.
    Reemplazar,
    /// Vulnerable y el ecosistema ya permite migrar.
    MigrarAhora,
    /// Vulnerable; existen componentes, conviene planificar y hacer pilotos.
    PlanificarPiloto,
    /// Vulnerable, pero el ecosistema aún no ofrece una vía de migración.
    Monitorear,
    /// Revisar parámetros (por ejemplo, subir AES-128 a AES-256).
    RevisarParametros,
    /// Información insuficiente: verificar manualmente.
    Verificar,
    /// Sin acción requerida.
    Conforme,
}

impl Accion {
    /// Interpreta el texto de [`Accion::como_texto`] (p. ej. de un CBOM).
    pub fn desde_texto(t: &str) -> Option<Self> {
        [
            Accion::CorregirYa,
            Accion::Reemplazar,
            Accion::MigrarAhora,
            Accion::PlanificarPiloto,
            Accion::Monitorear,
            Accion::RevisarParametros,
            Accion::Verificar,
            Accion::Conforme,
        ]
        .into_iter()
        .find(|a| a.como_texto() == t)
    }

    pub fn como_texto(self) -> &'static str {
        match self {
            Accion::CorregirYa => "corregir-ya",
            Accion::Reemplazar => "reemplazar",
            Accion::MigrarAhora => "migrar-ahora",
            Accion::PlanificarPiloto => "planificar-piloto",
            Accion::Monitorear => "monitorear",
            Accion::RevisarParametros => "revisar-parametros",
            Accion::Verificar => "verificar",
            Accion::Conforme => "conforme",
        }
    }

    pub fn etiqueta(self) -> &'static str {
        match self {
            Accion::CorregirYa => crate::idioma::tx("Corregir de inmediato", "Fix immediately"),
            Accion::Reemplazar => crate::idioma::tx("Reemplazar", "Replace"),
            Accion::MigrarAhora => crate::idioma::tx("Migrar ahora", "Migrate now"),
            Accion::PlanificarPiloto => {
                crate::idioma::tx("Planificar y hacer piloto", "Plan and pilot")
            }
            Accion::Monitorear => {
                crate::idioma::tx("Monitorear el ecosistema", "Monitor the ecosystem")
            }
            Accion::RevisarParametros => {
                crate::idioma::tx("Revisar parámetros", "Review parameters")
            }
            Accion::Verificar => crate::idioma::tx("Verificar manualmente", "Verify manually"),
            Accion::Conforme => crate::idioma::tx("Conforme", "Compliant"),
        }
    }
}

/// Resultado de clasificar un activo.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Clasificacion {
    pub riesgo: Riesgo,
    pub accion: Accion,
    /// 1 crítica, 2 alta, 3 media, 4 baja, 5 informativa.
    pub prioridad: u8,
    /// Contexto que determinó la prioridad (el más urgente).
    pub capacidad: String,
    pub garantia: Garantia,
    pub madurez: NivelMadurez,
    pub justificacion: String,
}

pub fn etiqueta_prioridad(p: u8) -> &'static str {
    match p {
        1 => crate::idioma::tx("Crítica", "Critical"),
        2 => crate::idioma::tx("Alta", "High"),
        3 => crate::idioma::tx("Media", "Medium"),
        4 => crate::idioma::tx("Baja", "Low"),
        _ => crate::idioma::tx("Informativa", "Informational"),
    }
}

/// Clasifica todos los activos del inventario.
///
/// Primero los algoritmos (su riesgo sale de la base de conocimiento) y
/// después certificados, llaves y protocolos, que heredan el riesgo más
/// grave de los algoritmos con los que se relacionan.
pub fn clasificar(inventario: &mut Inventario, conocimiento: &Conocimiento) {
    crate::enlace::enlazar_llaves(inventario);
    let mut riesgos: Vec<(String, Riesgo)> = Vec::new();

    for activo in inventario.activos.iter_mut() {
        if matches!(activo.detalles, Detalles::Algoritmo { .. }) {
            let riesgo = riesgo_de_algoritmo(activo, conocimiento);
            riesgos.push((activo.referencia.clone(), riesgo));
            activo.clasificacion = Some(evaluar(activo, riesgo, conocimiento));
        }
    }

    for activo in inventario.activos.iter_mut() {
        if matches!(activo.detalles, Detalles::Algoritmo { .. }) {
            continue;
        }
        let riesgo = activo.riesgo_fijado.unwrap_or_else(|| {
            activo
                .relaciones
                .iter()
                .filter_map(|r| {
                    riesgos
                        .iter()
                        .find(|(ref_, _)| *ref_ == r.referencia)
                        .map(|(_, x)| *x)
                })
                .min_by_key(|r| r.gravedad())
                .unwrap_or(Riesgo::Desconocido)
        });
        activo.clasificacion = Some(evaluar(activo, riesgo, conocimiento));
    }

    inventario.ordenar();
}

fn riesgo_de_algoritmo(activo: &Activo, c: &Conocimiento) -> Riesgo {
    if let Some(r) = activo.riesgo_fijado {
        return r;
    }
    match &activo.detalles {
        Detalles::Algoritmo {
            algoritmo_id: Some(id),
            tamano_llave,
        } => c
            .por_id(id)
            .map(|def| def.riesgo_para_tamano(*tamano_llave))
            .unwrap_or(Riesgo::Desconocido),
        _ => Riesgo::Desconocido,
    }
}

fn garantia_predeterminada(activo: &Activo, c: &Conocimiento) -> Garantia {
    activo
        .algoritmo_id()
        .and_then(|id| c.por_id(id))
        .map(|d| d.garantia)
        .unwrap_or(Garantia::Autenticacion)
}

fn evaluar(activo: &Activo, riesgo: Riesgo, c: &Conocimiento) -> Clasificacion {
    // «Sin clasificar» solo cuenta si no hay ningún contexto más preciso.
    let precisos: Vec<Contexto> = activo
        .contextos
        .iter()
        .filter(|c| c.capacidad != "sin-clasificar")
        .cloned()
        .collect();
    let contextos: Vec<Contexto> = if !precisos.is_empty() {
        precisos
    } else if activo.contextos.is_empty() {
        vec![Contexto {
            capacidad: "sin-clasificar".into(),
            garantia: garantia_predeterminada(activo, c),
        }]
    } else {
        activo.contextos.clone()
    };

    contextos
        .iter()
        .map(|ctx| evaluar_en_contexto(riesgo, ctx, c))
        .min_by_key(|cl| cl.prioridad)
        .expect("siempre hay al menos un contexto")
}

fn evaluar_en_contexto(riesgo: Riesgo, ctx: &Contexto, c: &Conocimiento) -> Clasificacion {
    let madurez = c.madurez(&ctx.capacidad, ctx.garantia);
    let capacidad = c.nombre_capacidad(&ctx.capacidad).to_string();
    let es_conf = ctx.garantia == Garantia::Confidencialidad;
    let garantia = ctx.garantia.etiqueta().to_lowercase();

    let (accion, prioridad, justificacion) = match riesgo {
        Riesgo::RotoClasico => (
            Accion::CorregirYa,
            1,
            "Inseguro hoy, sin necesidad de una computadora cuántica.".to_string(),
        ),
        Riesgo::Obsoleto => (
            Accion::Reemplazar,
            2,
            "Retirado o en retiro por los estándares vigentes.".to_string(),
        ),
        Riesgo::VulnerableCuantico => match madurez.rango() {
            5..=6 => (
                Accion::MigrarAhora,
                if es_conf { 2 } else { 3 },
                format!(
                    "Vulnerable al algoritmo de Shor. En {capacidad} el ecosistema ya ofrece PQC para {garantia} ({}): la migración es accionable hoy.",
                    madurez.etiqueta().to_lowercase()
                ),
            ),
            3..=4 => (
                Accion::PlanificarPiloto,
                if es_conf { 3 } else { 4 },
                format!(
                    "Vulnerable al algoritmo de Shor. En {capacidad} el ecosistema para {garantia} está en «{}»: conviene planificar y probar, aún no migrar en producción.",
                    madurez.etiqueta()
                ),
            ),
            _ => (
                Accion::Monitorear,
                4,
                format!(
                    "Vulnerable al algoritmo de Shor, pero en {capacidad} aún no hay una vía de migración madura para {garantia}. Documentar y monitorear.",
                ),
            ),
        },
        Riesgo::Desconocido => (
            Accion::Verificar,
            3,
            "Suaya no pudo determinar el algoritmo o sus parámetros; requiere revisión manual."
                .to_string(),
        ),
        Riesgo::DebilitadoGrover => (
            Accion::RevisarParametros,
            4,
            "El algoritmo de Grover reduce su margen de seguridad; considerar llaves de 256 bits."
                .to_string(),
        ),
        Riesgo::HibridoPq => (
            Accion::Conforme,
            5,
            "Combina protección clásica y poscuántica.".to_string(),
        ),
        Riesgo::ResistenteCuantico => (
            Accion::Conforme,
            5,
            "Resistente a los ataques cuánticos conocidos.".to_string(),
        ),
    };

    Clasificacion {
        riesgo,
        accion,
        prioridad,
        capacidad: ctx.capacidad.clone(),
        garantia: ctx.garantia,
        madurez,
        justificacion,
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::modelo::Detalles;

    fn algoritmo(id: &str, tamano: Option<u32>) -> Activo {
        Activo::nuevo(
            format!("algoritmo:{id}"),
            id,
            Detalles::Algoritmo {
                algoritmo_id: Some(id.into()),
                tamano_llave: tamano,
            },
        )
    }

    #[test]
    fn vulnerable_en_capacidad_madura_se_migra() {
        let c = Conocimiento::embebido();
        let mut inv = Inventario::default();
        inv.agregar(
            algoritmo("x25519", None).con_contexto("servidores-web", Garantia::Confidencialidad),
        );
        clasificar(&mut inv, &c);
        let cl = inv.activos[0].clasificacion.as_ref().unwrap();
        assert_eq!(cl.accion, Accion::MigrarAhora);
        assert_eq!(cl.prioridad, 2);
    }

    #[test]
    fn autenticacion_vpn_se_planifica() {
        let c = Conocimiento::embebido();
        let mut inv = Inventario::default();
        inv.agregar(
            algoritmo("ed25519", None).con_contexto("vpn-cifrado-red", Garantia::Autenticacion),
        );
        clasificar(&mut inv, &c);
        assert_eq!(
            inv.activos[0].clasificacion.as_ref().unwrap().accion,
            Accion::PlanificarPiloto
        );
    }

    #[test]
    fn rsa_1024_es_critico() {
        let c = Conocimiento::embebido();
        let mut inv = Inventario::default();
        inv.agregar(algoritmo("rsa", Some(1024)).con_contexto("pki-ca", Garantia::Autenticacion));
        clasificar(&mut inv, &c);
        let cl = inv.activos[0].clasificacion.as_ref().unwrap();
        assert_eq!(cl.accion, Accion::CorregirYa);
        assert_eq!(cl.prioridad, 1);
    }

    #[test]
    fn el_certificado_hereda_el_peor_riesgo() {
        let c = Conocimiento::embebido();
        let mut inv = Inventario::default();
        inv.agregar(algoritmo("ml-dsa-65", None));
        inv.agregar(algoritmo("rsassa-pkcs1-sha1", None));
        let mut cert = Activo::nuevo(
            "certificado:x",
            "x",
            Detalles::Certificado {
                sujeto: "CN=x".into(),
                emisor: "CN=x".into(),
                serie: "01".into(),
                no_antes: "".into(),
                no_despues: "".into(),
                huella_sha256: "".into(),
                extension_archivo: None,
                vencido: false,
                identidad_llave: None,
            },
        );
        cert.relacionar("publicKey", "algoritmo:ml-dsa-65");
        cert.relacionar("signature", "algoritmo:rsassa-pkcs1-sha1");
        inv.agregar(cert);
        clasificar(&mut inv, &c);
        let cert = inv
            .activos
            .iter()
            .find(|a| a.referencia == "certificado:x")
            .unwrap();
        assert_eq!(
            cert.clasificacion.as_ref().unwrap().riesgo,
            Riesgo::RotoClasico
        );
    }

    #[test]
    fn se_elige_el_contexto_mas_urgente() {
        let c = Conocimiento::embebido();
        let mut inv = Inventario::default();
        inv.agregar(
            algoritmo("ecdh-p256", None)
                .con_contexto("cifrado-volumen", Garantia::Confidencialidad)
                .con_contexto("servidores-web", Garantia::Confidencialidad),
        );
        clasificar(&mut inv, &c);
        let cl = inv.activos[0].clasificacion.as_ref().unwrap();
        assert_eq!(cl.capacidad, "servidores-web");
        assert_eq!(cl.accion, Accion::MigrarAhora);
    }
}
