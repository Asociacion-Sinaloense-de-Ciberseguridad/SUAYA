//! Reporte ejecutivo a partir de un CBOM de Suaya, en Markdown o en HTML.
//!
//! Ambos formatos se generan desde el mismo [`Modelo`], de modo que dicen lo
//! mismo. El idioma sigue a [`suaya_core::idioma`]: las etiquetas propias se
//! escriben con `t!` y el texto de los hallazgos (nombres, advertencias,
//! notas) se traduce con el catálogo al presentarlo.

use std::collections::{BTreeMap, HashSet};
use std::fmt::Write;

use serde_json::json;
use suaya_core::idioma::{traducir, tx};
use suaya_core::{Accion, Conocimiento, Riesgo, etiqueta_prioridad, t};

use crate::lectura::{CbomLeido, Registro};

/// Capacidad que agrupa los certificados de almacenes de confianza.
const ALMACEN: &str = "almacen-confianza";

fn etiqueta_riesgo(texto: &str) -> String {
    serde_json::from_value::<Riesgo>(json!(texto))
        .map(|r| r.etiqueta().to_string())
        .unwrap_or_else(|_| texto.into())
}

fn etiqueta_accion(texto: &str) -> String {
    serde_json::from_value::<Accion>(json!(texto))
        .map(|a| a.etiqueta().to_string())
        .unwrap_or_else(|_| texto.into())
}

fn etiqueta_tipo(tipo: &str) -> &'static str {
    match tipo {
        "algorithm" => tx("Algoritmo", "Algorithm"),
        "certificate" => tx("Certificado", "Certificate"),
        "related-crypto-material" => tx("Llave o material", "Key or material"),
        "protocol" => tx("Protocolo", "Protocol"),
        "library" => tx("Biblioteca", "Library"),
        _ => tx("Otro", "Other"),
    }
}

fn tr(texto: &str) -> String {
    traducir(texto).into_owned()
}

/// Una fila de hallazgo.
pub struct Fila {
    pub nombre: String,
    pub tipo: &'static str,
    pub riesgo_id: String,
    pub riesgo: String,
    pub accion: String,
    pub capacidad: String,
    pub ubicacion: String,
}

/// Hallazgos de una prioridad, con sus observaciones.
pub struct Seccion {
    pub prioridad: u8,
    pub etiqueta: String,
    pub filas: Vec<Fila>,
    /// (activo, texto, sangría).
    pub observaciones: Vec<(String, String, bool)>,
}

pub struct FilaCapacidad {
    pub nombre: String,
    pub confidencialidad: String,
    pub autenticacion: String,
    pub activos: usize,
    pub migrar: usize,
    pub planificar: usize,
    pub monitorear: usize,
}

pub struct SeccionCumplimiento {
    pub nombre: String,
    pub referencia: String,
    /// (id, etiqueta, activos).
    pub estados: Vec<(&'static str, String, usize)>,
    /// (año, activos, ejemplos, restantes).
    pub plazos: Vec<(i32, usize, Vec<String>, usize)>,
    /// (activo, tipo, motivo).
    pub no_conformes: Vec<(String, &'static str, String)>,
    pub no_conformes_restantes: usize,
}

/// Una receta de corrección y los activos que cubre.
pub struct FilaReceta {
    pub titulo: String,
    pub pasos: Vec<String>,
    pub referencias: Vec<String>,
    pub activos: usize,
    /// La prioridad más urgente de sus activos.
    pub prioridad: u8,
    pub ejemplos: Vec<String>,
}

/// Un sistema de la organización (`--organizacion`).
pub struct FilaSistema {
    pub nombre: String,
    pub responsable: String,
    pub criticidad: String,
    pub exposicion: String,
    pub activos: usize,
    /// Prioridad crítica o alta.
    pub urgentes: usize,
    /// Expuestos según la desigualdad de Mosca.
    pub expuestos: usize,
}

/// Una excepción declarada y los activos que cubre.
pub struct FilaExcepcion {
    pub id: String,
    pub vence: String,
    pub vigente: bool,
    pub justificacion: String,
    pub aprobada_por: String,
    pub activos: usize,
}

pub struct SeccionOrganizacion {
    pub horizonte: Option<i32>,
    pub sistemas: Vec<FilaSistema>,
    pub sin_sistema: usize,
    /// (activo, sistemas, años de exposición).
    pub expuestos: Vec<(String, String, i32)>,
    pub excepciones: Vec<FilaExcepcion>,
}

/// Todo lo que dice el reporte, ya calculado y en el idioma actual.
pub struct Modelo {
    pub sistema: String,
    pub fecha: String,
    pub herramienta: String,
    pub base_conocimiento: String,
    pub total: usize,
    pub criticos: usize,
    pub migrables: usize,
    pub planificar: usize,
    pub protegidos: usize,
    /// (prioridad, etiqueta, activos).
    pub por_prioridad: Vec<(u8, String, usize)>,
    /// (riesgo, etiqueta, activos), de más a menos grave.
    pub por_riesgo: Vec<(String, String, usize)>,
    pub llaves_agrupadas: usize,
    pub capacidades: Vec<FilaCapacidad>,
    pub secciones: Vec<Seccion>,
    pub cumplimiento: Option<SeccionCumplimiento>,
    pub organizacion: Option<SeccionOrganizacion>,
    pub recetas: Vec<FilaReceta>,
    /// (certificados raíz, (riesgo, cantidad)).
    pub almacen: Option<(usize, Vec<(String, usize)>)>,
    pub conformes: Vec<String>,
    pub notas_conformes: Vec<(String, String)>,
    pub metodologia: Vec<String>,
}

impl Modelo {
    pub fn desde(cbom: &CbomLeido, c: &Conocimiento) -> Self {
        let regs = &cbom.registros;
        let cuenta = |f: &dyn Fn(&Registro) -> bool| regs.iter().filter(|r| f(r)).count();

        let mut por_riesgo: Vec<(String, String, usize)> = Vec::new();
        for r in [
            Riesgo::RotoClasico,
            Riesgo::Obsoleto,
            Riesgo::VulnerableCuantico,
            Riesgo::Desconocido,
            Riesgo::DebilitadoGrover,
            Riesgo::HibridoPq,
            Riesgo::ResistenteCuantico,
        ] {
            let n = cuenta(&|x| x.riesgo == r.como_texto());
            if n > 0 {
                por_riesgo.push((r.como_texto().into(), r.etiqueta().into(), n));
            }
        }

        let certificados_presentes: HashSet<&str> = regs
            .iter()
            .filter(|r| r.tipo_activo == "certificate")
            .map(|r| r.referencia.as_str())
            .collect();
        let certificado_de = |r: &Registro| -> Option<String> {
            if r.tipo_activo != "related-crypto-material" {
                return None;
            }
            r.relaciones
                .iter()
                .find(|(t, x)| t == "certificate" && certificados_presentes.contains(x.as_str()))
                .map(|(_, x)| x.clone())
        };
        let mut llaves_de: BTreeMap<String, Vec<&Registro>> = BTreeMap::new();
        for r in regs {
            if let Some(cert) = certificado_de(r) {
                llaves_de.entry(cert).or_default().push(r);
            }
        }

        let mut por_capacidad: BTreeMap<&str, Vec<&Registro>> = BTreeMap::new();
        for r in regs {
            por_capacidad
                .entry(r.capacidad.as_str())
                .or_default()
                .push(r);
        }
        let capacidades = c
            .capacidades
            .iter()
            .filter_map(|cap| {
                let lista = por_capacidad.get(cap.id.as_str())?;
                let n = |accion: &str| lista.iter().filter(|r| r.accion == accion).count();
                Some(FilaCapacidad {
                    nombre: tr(&cap.nombre),
                    confidencialidad: cap.confidencialidad.etiqueta().into(),
                    autenticacion: cap.autenticacion.etiqueta().into(),
                    activos: lista.len(),
                    migrar: n("migrar-ahora"),
                    planificar: n("planificar-piloto"),
                    monitorear: n("monitorear"),
                })
            })
            .collect();

        let mut secciones = Vec::new();
        for p in 1..=4u8 {
            let lista: Vec<&Registro> = regs
                .iter()
                .filter(|r| r.prioridad == p && !(r.capacidad == ALMACEN && p >= 3))
                .filter(|r| certificado_de(r).is_none())
                .collect();
            if lista.is_empty() {
                continue;
            }
            let filas = lista
                .iter()
                .map(|r| Fila {
                    nombre: tr(&r.nombre),
                    tipo: etiqueta_tipo(&r.tipo_activo),
                    riesgo_id: r.riesgo.clone(),
                    riesgo: etiqueta_riesgo(&r.riesgo),
                    accion: etiqueta_accion(&r.accion),
                    capacidad: tr(c.nombre_capacidad(&r.capacidad)),
                    ubicacion: match r.ubicaciones.len() {
                        0 => String::new(),
                        1 => r.ubicaciones[0].clone(),
                        n => t!("{} (y {} más)", "{} (and {} more)", r.ubicaciones[0], n - 1),
                    },
                })
                .collect();
            let mut observaciones = Vec::new();
            for r in &lista {
                let nombre = tr(&r.nombre);
                for adv in &r.advertencias {
                    observaciones.push((nombre.clone(), tr(adv), false));
                }
                for llave in llaves_de.get(&r.referencia).into_iter().flatten() {
                    let donde = llave.ubicaciones.first().cloned().unwrap_or_default();
                    observaciones.push((
                        nombre.clone(),
                        t!(
                            "llave privada asociada en `{donde}`.",
                            "associated private key at `{donde}`."
                        ),
                        false,
                    ));
                    for adv in &llave.advertencias {
                        observaciones.push((nombre.clone(), tr(adv), true));
                    }
                }
            }
            secciones.push(Seccion {
                prioridad: p,
                etiqueta: etiqueta_prioridad(p).to_lowercase(),
                filas,
                observaciones,
            });
        }

        let cumplimiento = cbom.perfil.as_ref().map(|(nombre, referencia)| {
            let evaluados: Vec<&Registro> =
                regs.iter().filter(|r| !r.cumplimiento.is_empty()).collect();
            let n = |e: &str| evaluados.iter().filter(|r| r.cumplimiento == e).count();
            let estados = vec![
                (
                    "no-conforme",
                    tx("No conforme", "Non-compliant").to_string(),
                    n("no-conforme"),
                ),
                (
                    "transicion",
                    tx("En transición", "In transition").to_string(),
                    n("transicion"),
                ),
                (
                    "conforme",
                    tx("Conforme", "Compliant").to_string(),
                    n("conforme"),
                ),
                (
                    "sin-evaluar",
                    tx("Sin evaluar", "Not evaluated").to_string(),
                    n("sin-evaluar"),
                ),
            ];
            let mut por_anio: BTreeMap<i32, Vec<&Registro>> = BTreeMap::new();
            for r in evaluados.iter().filter(|r| r.cumplimiento == "transicion") {
                if let Some(p) = r.plazo {
                    por_anio.entry(p).or_default().push(r);
                }
            }
            let plazos = por_anio
                .iter()
                .map(|(anio, lista)| {
                    let mut ejemplos: Vec<String> = lista.iter().map(|r| tr(&r.nombre)).collect();
                    ejemplos.sort();
                    ejemplos.dedup();
                    let resto = ejemplos.len().saturating_sub(4);
                    ejemplos.truncate(4);
                    (*anio, lista.len(), ejemplos, resto)
                })
                .collect();
            let mut no_conformes: Vec<&&Registro> = evaluados
                .iter()
                .filter(|r| r.cumplimiento == "no-conforme")
                .collect();
            no_conformes.sort_by_key(|r| (r.prioridad, r.nombre.clone()));
            let restantes = no_conformes.len().saturating_sub(25);
            SeccionCumplimiento {
                nombre: tr(nombre),
                referencia: tr(referencia),
                estados,
                plazos,
                no_conformes: no_conformes
                    .iter()
                    .take(25)
                    .map(|r| {
                        (
                            tr(&r.nombre),
                            etiqueta_tipo(&r.tipo_activo),
                            tr(&r.nota_cumplimiento),
                        )
                    })
                    .collect(),
                no_conformes_restantes: restantes,
            }
        });

        let organizacion = (!cbom.sistemas.is_empty() || !cbom.excepciones.is_empty()).then(|| {
            let hoy = fecha_de(&cbom.fecha);
            let sistemas = cbom
                .sistemas
                .iter()
                .map(|x| {
                    let suyos: Vec<&Registro> = regs
                        .iter()
                        .filter(|r| r.sistemas.contains(&x.nombre))
                        .collect();
                    FilaSistema {
                        nombre: x.nombre.clone(),
                        responsable: x.responsable.clone(),
                        criticidad: match x.criticidad.as_str() {
                            "alta" => tx("Alta", "High").into(),
                            "media" => tx("Media", "Medium").into(),
                            "baja" => tx("Baja", "Low").into(),
                            _ => String::new(),
                        },
                        exposicion: match x.exposicion.as_str() {
                            "internet" => "Internet".into(),
                            "interna" => tx("Interna", "Internal").into(),
                            _ => String::new(),
                        },
                        activos: suyos.len(),
                        urgentes: suyos.iter().filter(|r| r.prioridad <= 2).count(),
                        expuestos: suyos
                            .iter()
                            .filter(|r| r.holgura_mosca.is_some_and(|h| h < 0))
                            .count(),
                    }
                })
                .collect();
            let mut expuestos: Vec<(String, String, i32)> = regs
                .iter()
                .filter_map(|r| {
                    let h = r.holgura_mosca.filter(|h| *h < 0)?;
                    Some((tr(&r.nombre), r.sistemas.join(", "), -h))
                })
                .collect();
            expuestos.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
            let excepciones = cbom
                .excepciones
                .iter()
                .map(|e| FilaExcepcion {
                    id: e.id.clone(),
                    vence: e.vence.clone(),
                    vigente: hoy.as_deref().is_none_or(|h| e.vence.as_str() >= h),
                    justificacion: e.justificacion.clone(),
                    aprobada_por: e.aprobada_por.clone(),
                    activos: regs
                        .iter()
                        .filter(|r| r.excepcion.as_ref().is_some_and(|(id, _, _)| *id == e.id))
                        .count(),
                })
                .collect();
            SeccionOrganizacion {
                horizonte: cbom.horizonte_cuantico,
                sistemas,
                sin_sistema: regs.iter().filter(|r| r.sistemas.is_empty()).count(),
                expuestos,
                excepciones,
            }
        });

        // Recetas de corrección de lo que requiere acción.
        let mut por_receta: BTreeMap<&str, (&suaya_core::Receta, Vec<&Registro>)> = BTreeMap::new();
        for r in regs.iter().filter(|r| (1..=4).contains(&r.prioridad)) {
            if let Some(x) = r.receta(c) {
                por_receta
                    .entry(x.id.as_str())
                    .or_insert((x, Vec::new()))
                    .1
                    .push(r);
            }
        }
        let mut recetas: Vec<FilaReceta> = por_receta
            .into_values()
            .map(|(x, lista)| {
                let mut ejemplos: Vec<String> = lista.iter().map(|r| tr(&r.nombre)).collect();
                ejemplos.sort();
                ejemplos.dedup();
                ejemplos.truncate(6);
                FilaReceta {
                    titulo: x.titulo().to_string(),
                    pasos: x.pasos().to_vec(),
                    referencias: x.referencias.clone(),
                    activos: lista.len(),
                    prioridad: lista.iter().map(|r| r.prioridad).min().unwrap_or(9),
                    ejemplos,
                }
            })
            .collect();
        recetas.sort_by(|a, b| {
            a.prioridad
                .cmp(&b.prioridad)
                .then(b.activos.cmp(&a.activos))
        });

        let almacen_regs: Vec<&Registro> = regs
            .iter()
            .filter(|r| r.capacidad == ALMACEN && r.prioridad >= 3)
            .collect();
        let almacen = (!almacen_regs.is_empty()).then(|| {
            let certs: Vec<&&Registro> = almacen_regs
                .iter()
                .filter(|r| r.tipo_activo == "certificate")
                .collect();
            let mut por: BTreeMap<String, usize> = BTreeMap::new();
            for r in &certs {
                *por.entry(etiqueta_riesgo(&r.riesgo)).or_default() += 1;
            }
            (certs.len(), por.into_iter().collect())
        });

        let conformes_regs: Vec<&Registro> = regs.iter().filter(|r| r.prioridad >= 5).collect();
        let conformes = conformes_regs.iter().map(|r| tr(&r.nombre)).collect();
        let notas_conformes = conformes_regs
            .iter()
            .flat_map(|r| r.advertencias.iter().map(move |a| (tr(&r.nombre), tr(a))))
            .collect();

        let mut metodologia = vec![t!(
            "Cada activo se evalúa en cuatro ejes: **riesgo** (roto, obsoleto, vulnerable al algoritmo de Shor, debilitado por Grover, híbrido o resistente), **garantía** (confidencialidad, autenticación o integridad), **capacidad tecnológica** y **madurez del ecosistema** para adoptar PQC. La confidencialidad se prioriza porque los datos cifrados hoy pueden almacenarse y descifrarse en el futuro.",
            "Each asset is assessed on four axes: **risk** (broken, deprecated, vulnerable to Shor's algorithm, weakened by Grover, hybrid or resistant), **assurance** (confidentiality, authentication or integrity), **technology capability** and **ecosystem maturity** for adopting PQC. Confidentiality comes first because data encrypted today can be stored and decrypted in the future."
        )];
        if let Some(fuente) = &c.meta_madurez.fuente {
            let edicion = c.meta_madurez.edicion.as_deref().unwrap_or("s/f");
            let evidencia = c.meta_madurez.fecha_evidencia.as_deref().unwrap_or("s/f");
            let caso = c.meta_madurez.caso_difusion.as_deref().unwrap_or("s/n");
            metodologia.push(t!(
                "Los niveles de madurez provienen de: {fuente}, edición {edicion}, con evidencia de {evidencia}. © MITRE, aprobado para difusión pública (caso {caso}). Suaya usa sus niveles con atribución y no reproduce su texto.",
                "Maturity levels come from: {fuente}, {edicion} edition, with evidence from {evidencia}. © MITRE, approved for public release (case {caso}). Suaya uses its levels with attribution and does not reproduce its text."
            ));
        }
        metodologia.push(t!(
            "**Alcance.** Suaya inspecciona archivos, configuraciones, código y los servicios que se le indican; no observa el tráfico real. Cuando una configuración no declara un parámetro, el resultado depende de la versión instalada del software y se marca para verificación. Suaya nunca copia material secreto al inventario.",
            "**Scope.** Suaya inspects files, configurations, code and the services it is pointed at; it does not observe real traffic. When a configuration does not declare a parameter, the result depends on the installed software version and is flagged for verification. Suaya never copies secret material into the inventory."
        ));

        Modelo {
            sistema: cbom.sistema.clone(),
            fecha: cbom.fecha.clone(),
            herramienta: cbom.version_herramienta.clone(),
            base_conocimiento: tr(&cbom.base_conocimiento),
            total: regs.len(),
            criticos: cuenta(&|r| r.prioridad == 1),
            migrables: cuenta(&|r| r.accion == "migrar-ahora"),
            planificar: cuenta(&|r| r.accion == "planificar-piloto"),
            protegidos: cuenta(&|r| r.riesgo == "hibrido-pq" || r.riesgo == "resistente-cuantico"),
            por_prioridad: (1..=5u8)
                .map(|p| {
                    (
                        p,
                        etiqueta_prioridad(p).to_string(),
                        cuenta(&|r| r.prioridad == p),
                    )
                })
                .collect(),
            por_riesgo,
            llaves_agrupadas: regs.iter().filter(|r| certificado_de(r).is_some()).count(),
            capacidades,
            secciones,
            cumplimiento,
            organizacion,
            recetas,
            almacen,
            conformes,
            notas_conformes,
            metodologia,
        }
    }

    fn resumen(&self) -> String {
        t!(
            "Suaya inventarió **{} activos criptográficos**. **{}** requieren corrección inmediata porque ya son inseguros hoy, sin necesidad de una computadora cuántica. **{}** son vulnerables a cómputo cuántico y **pueden migrarse ya**, porque el ecosistema de su capacidad ofrece soluciones generales con PQC. **{}** deben planificarse con pilotos, porque solo existen componentes o versiones preliminares. **{}** ya son conformes: resistentes a cómputo cuántico o protegidos con un esquema híbrido.",
            "Suaya inventoried **{} cryptographic assets**. **{}** need immediate correction because they are already insecure today, with no quantum computer required. **{}** are quantum-vulnerable and **can be migrated now**, because the ecosystem for their capability offers general-availability PQC. **{}** should be planned with pilots, because only components or preliminary versions exist. **{}** are already compliant: quantum-resistant or protected with a hybrid scheme.",
            self.total,
            self.criticos,
            self.migrables,
            self.planificar,
            self.protegidos
        )
    }

    fn texto_almacen(&self, certificados: usize) -> String {
        t!(
            "Se encontraron **{certificados} certificados raíz** en almacenes de confianza. Su reemplazo no depende de quien opera el sistema, sino de las autoridades certificadoras y del proveedor del sistema operativo, por lo que se resumen aquí y la acción recomendada es monitorear y mantener el sistema actualizado.",
            "**{certificados} root certificates** were found in trust stores. Replacing them does not depend on whoever operates the system but on the certificate authorities and the operating system vendor, so they are summarized here and the recommended action is to monitor and keep the system updated."
        )
    }
}

fn aviso_parcial() -> &'static str {
    tx(
        "Cobertura parcial o no declarada. No interpretar ausencia de hallazgos como ausencia de riesgo.",
        "Partial or undeclared coverage. Do not read an absence of findings as an absence of risk.",
    )
}

fn texto_recetas() -> &'static str {
    tx(
        "Pasos de corrección de la base de conocimiento (remediacion.toml) para los hallazgos de este reporte, de lo más urgente a lo menos. Verifique cada directiva contra la documentación de su producto antes de aplicarla.",
        "Remediation steps from the knowledge base (remediacion.toml) for the findings in this report, from most to least urgent. Check each directive against your product documentation before applying it.",
    )
}

fn resumen_receta(x: &FilaReceta) -> String {
    let (n, p, ejemplos) = (
        x.activos,
        etiqueta_prioridad(x.prioridad).to_lowercase(),
        x.ejemplos.join(", "),
    );
    if n == 1 {
        t!(
            "Se aplica a 1 activo (prioridad {p}): {ejemplos}.",
            "Applies to 1 asset ({p} priority): {ejemplos}."
        )
    } else {
        t!(
            "Se aplica a {n} activos (prioridad más urgente: {p}), p. ej. {ejemplos}.",
            "Applies to {n} assets (most urgent priority: {p}), e.g. {ejemplos}."
        )
    }
}

/// Fecha AAAA-MM-DD de una marca de tiempo RFC 3339.
fn fecha_de(marca: &str) -> Option<String> {
    marca
        .get(..10)
        .filter(|f| f.as_bytes().get(4) == Some(&b'-'))
        .map(str::to_string)
}

impl SeccionOrganizacion {
    fn introduccion(&self) -> String {
        let mut t = tx(
            "El contexto declarado por la organización asigna cada activo a sus sistemas y responsables. La desigualdad de Mosca (x + y > z) compara cuántos años deben seguir confidenciales los datos (x) más lo que tarda la migración (y) con los años que faltan para una computadora cuántica relevante (z): si se cumple, lo que hoy se captura cifrado podrá descifrarse mientras siga siendo valioso.",
            "The context declared by the organization assigns each asset to its systems and owners. Mosca's inequality (x + y > z) compares how many years the data must stay confidential (x) plus how long the migration takes (y) with the years left until a relevant quantum computer (z): if it holds, what is captured encrypted today can be decrypted while it is still valuable.",
        )
        .to_string();
        if let Some(h) = self.horizonte {
            t.push(' ');
            t.push_str(&t!("Horizonte supuesto: {h}.", "Assumed horizon: {h}."));
        }
        t
    }
}

fn capitalizar(t: &str) -> String {
    let mut c = t.chars();
    match c.next() {
        Some(p) => p.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

fn celda(texto: &str) -> String {
    esc(texto).replace('|', "\\|").replace('\n', " ")
}

/// Genera el reporte ejecutivo en Markdown.
pub fn reporte_markdown(cbom: &CbomLeido, c: &Conocimiento) -> String {
    let m = Modelo::desde(cbom, c);
    let mut s = String::new();
    if cbom.estado != "completed" {
        let _ = writeln!(s, "**{}**\n", aviso_parcial());
    }
    let _ = writeln!(
        s,
        "# {}\n",
        tx(
            "Reporte de preparación poscuántica",
            "Post-quantum readiness report"
        )
    );
    let _ = writeln!(s, "| | |\n|---|---|");
    let _ = writeln!(
        s,
        "| **{}** | {} |",
        tx("Sistema", "System"),
        celda(&m.sistema)
    );
    let _ = writeln!(
        s,
        "| **{}** | {} |",
        tx("Fecha del escaneo", "Scan date"),
        m.fecha
    );
    let _ = writeln!(
        s,
        "| **{}** | {} |",
        tx("Herramienta", "Tool"),
        m.herramienta
    );
    let _ = writeln!(
        s,
        "| **{}** | {} |\n",
        tx("Base de conocimiento", "Knowledge base"),
        celda(&m.base_conocimiento)
    );

    let _ = writeln!(s, "## {}\n", tx("Resumen ejecutivo", "Executive summary"));
    let _ = writeln!(s, "{}\n", m.resumen());
    let _ = writeln!(
        s,
        "| {} | {} |\n|---|---:|",
        tx("Prioridad", "Priority"),
        tx("Activos", "Assets")
    );
    for (_, etiqueta, n) in &m.por_prioridad {
        let _ = writeln!(s, "| {etiqueta} | {n} |");
    }
    let _ = writeln!(s);
    if m.llaves_agrupadas > 0 {
        let n = m.llaves_agrupadas;
        let _ = writeln!(
            s,
            "{}\n",
            t!(
                "Las {n} llaves privadas que tienen certificado se presentan junto a él, en las observaciones de cada prioridad.",
                "The {n} private keys that have a certificate are shown with it, in the observations of each priority."
            )
        );
    }

    let _ = writeln!(
        s,
        "## {}\n",
        tx(
            "Qué se puede migrar hoy y qué no",
            "What can be migrated today and what cannot"
        )
    );
    let _ = writeln!(
        s,
        "{}\n",
        tx(
            "La madurez del ecosistema indica si ya existen productos para migrar cada tipo de garantía en cada capacidad tecnológica.",
            "Ecosystem maturity shows whether products already exist to migrate each type of assurance in each technology capability."
        )
    );
    let _ = writeln!(
        s,
        "| {} | {} | {} | {} | {} | {} | {} |\n|---|---|---|---:|---:|---:|---:|",
        tx("Capacidad", "Capability"),
        tx("Madurez: confidencialidad", "Maturity: confidentiality"),
        tx("Madurez: autenticación", "Maturity: authentication"),
        tx("Activos", "Assets"),
        tx("Migrar ahora", "Migrate now"),
        tx("Planificar", "Plan"),
        tx("Monitorear", "Monitor")
    );
    for f in &m.capacidades {
        let _ = writeln!(
            s,
            "| {} | {} | {} | {} | {} | {} | {} |",
            f.nombre,
            f.confidencialidad,
            f.autenticacion,
            f.activos,
            f.migrar,
            f.planificar,
            f.monitorear
        );
    }
    let _ = writeln!(s);

    if let Some(o) = &m.organizacion {
        let _ = writeln!(
            s,
            "## {}\n",
            tx("Contexto de la organización", "Organizational context")
        );
        let _ = writeln!(s, "{}\n", o.introduccion());
        if !o.sistemas.is_empty() {
            let _ = writeln!(
                s,
                "| {} | {} | {} | {} | {} | {} | {} |\n|---|---|---|---|---:|---:|---:|",
                tx("Sistema", "System"),
                tx("Responsable", "Owner"),
                tx("Criticidad", "Criticality"),
                tx("Exposición", "Exposure"),
                tx("Activos", "Assets"),
                tx("Críticos o altos", "Critical or high"),
                tx("Expuestos (Mosca)", "Exposed (Mosca)")
            );
            for f in &o.sistemas {
                let _ = writeln!(
                    s,
                    "| {} | {} | {} | {} | {} | {} | {} |",
                    celda(&f.nombre),
                    celda(&f.responsable),
                    f.criticidad,
                    f.exposicion,
                    f.activos,
                    f.urgentes,
                    f.expuestos
                );
            }
            let _ = writeln!(s);
            if o.sin_sistema > 0 {
                let n = o.sin_sistema;
                let _ = writeln!(
                    s,
                    "{}\n",
                    t!(
                        "{n} activos no corresponden a ningún sistema declarado.",
                        "{n} assets do not belong to any declared system."
                    )
                );
            }
        }
        if !o.expuestos.is_empty() {
            let _ = writeln!(
                s,
                "### {}\n",
                tx(
                    "Expuestos a «capturar ahora, descifrar después»",
                    "Exposed to \"harvest now, decrypt later\""
                )
            );
            let _ = writeln!(
                s,
                "| {} | {} | {} |\n|---|---|---:|",
                tx("Activo", "Asset"),
                tx("Sistemas", "Systems"),
                tx("Años de exposición", "Years of exposure")
            );
            for (activo, sistemas, anios) in o.expuestos.iter().take(25) {
                let _ = writeln!(s, "| {} | {} | {anios} |", celda(activo), celda(sistemas));
            }
            let _ = writeln!(s);
        }
        if !o.excepciones.is_empty() {
            let _ = writeln!(s, "### {}\n", tx("Excepciones", "Exceptions"));
            let _ = writeln!(
                s,
                "| {} | {} | {} | {} | {} | {} |\n|---|---|---|---|---|---:|",
                tx("Excepción", "Exception"),
                tx("Vence", "Expires"),
                tx("Estado", "Status"),
                tx("Justificación", "Justification"),
                tx("Aprobada por", "Approved by"),
                tx("Activos", "Assets")
            );
            for e in &o.excepciones {
                let _ = writeln!(
                    s,
                    "| {} | {} | {} | {} | {} | {} |",
                    celda(&e.id),
                    e.vence,
                    if e.vigente {
                        tx("Vigente", "Active")
                    } else {
                        tx("Vencida", "Expired")
                    },
                    celda(&e.justificacion),
                    celda(&e.aprobada_por),
                    e.activos
                );
            }
            let _ = writeln!(s);
        }
    }

    let _ = writeln!(
        s,
        "## {}\n",
        tx(
            "Hallazgos que requieren acción",
            "Findings that require action"
        )
    );
    for sec in &m.secciones {
        let (etiqueta, mayuscula, n) = (&sec.etiqueta, capitalizar(&sec.etiqueta), sec.filas.len());
        let _ = writeln!(
            s,
            "### {}\n",
            t!("Prioridad {etiqueta} ({n})", "{mayuscula} priority ({n})")
        );
        let _ = writeln!(
            s,
            "| {} | {} | {} | {} | {} | {} |\n|---|---|---|---|---|---|",
            tx("Activo", "Asset"),
            tx("Tipo", "Type"),
            tx("Riesgo", "Risk"),
            tx("Acción", "Action"),
            tx("Capacidad", "Capability"),
            tx("Ubicación", "Location")
        );
        for f in &sec.filas {
            let _ = writeln!(
                s,
                "| {} | {} | {} | {} | {} | `{}` |",
                celda(&f.nombre),
                f.tipo,
                f.riesgo,
                f.accion,
                f.capacidad,
                celda(&f.ubicacion)
            );
        }
        let _ = writeln!(s);
        if !sec.observaciones.is_empty() {
            let _ = writeln!(s, "**{}**\n", tx("Observaciones", "Observations"));
            for (nombre, texto, sangria) in &sec.observaciones {
                if *sangria {
                    let _ = writeln!(s, "  - {texto}");
                } else {
                    let _ = writeln!(s, "- **{}**: {texto}", celda(nombre));
                }
            }
            let _ = writeln!(s);
        }
    }

    if !m.recetas.is_empty() {
        let _ = writeln!(s, "## {}\n", tx("Cómo corregir", "How to fix"));
        let _ = writeln!(s, "{}\n", texto_recetas());
        for x in &m.recetas {
            let _ = writeln!(s, "### {}\n", x.titulo);
            let _ = writeln!(s, "{}\n", resumen_receta(x));
            for (i, paso) in x.pasos.iter().enumerate() {
                let _ = writeln!(s, "{}. {paso}", i + 1);
            }
            if !x.referencias.is_empty() {
                let _ = writeln!(
                    s,
                    "\n{}: {}",
                    tx("Referencias", "References"),
                    x.referencias.join(", ")
                );
            }
            let _ = writeln!(s);
        }
    }

    if let Some(cu) = &m.cumplimiento {
        let _ = writeln!(
            s,
            "## {} {}\n",
            tx("Cumplimiento con", "Compliance with"),
            cu.nombre
        );
        let _ = writeln!(s, "{}: {}.\n", tx("Referencia", "Reference"), cu.referencia);
        let _ = writeln!(
            s,
            "| {} | {} |\n|---|---:|",
            tx("Estado", "Status"),
            tx("Activos", "Assets")
        );
        for (_, etiqueta, n) in &cu.estados {
            let _ = writeln!(s, "| {etiqueta} | {n} |");
        }
        let _ = writeln!(s);
        if !cu.plazos.is_empty() {
            let _ = writeln!(
                s,
                "**{}**\n",
                tx("Calendario de migración", "Migration calendar")
            );
            let _ = writeln!(
                s,
                "| {} | {} | {} |\n|---|---:|---|",
                tx("Fecha límite", "Deadline"),
                tx("Activos", "Assets"),
                tx("Ejemplos", "Examples")
            );
            for (anio, n, ejemplos, resto) in &cu.plazos {
                let mas = if *resto > 0 {
                    t!(" y {resto} más", " and {resto} more")
                } else {
                    String::new()
                };
                let _ = writeln!(s, "| {anio} | {n} | {}{mas} |", celda(&ejemplos.join(", ")));
            }
            let _ = writeln!(s);
        }
        if !cu.no_conformes.is_empty() {
            let _ = writeln!(
                s,
                "**{}**\n",
                tx("Activos no conformes", "Non-compliant assets")
            );
            let _ = writeln!(
                s,
                "| {} | {} | {} |\n|---|---|---|",
                tx("Activo", "Asset"),
                tx("Tipo", "Type"),
                tx("Motivo", "Reason")
            );
            for (nombre, tipo, motivo) in &cu.no_conformes {
                let _ = writeln!(s, "| {} | {tipo} | {} |", celda(nombre), celda(motivo));
            }
            if cu.no_conformes_restantes > 0 {
                let n = cu.no_conformes_restantes;
                let _ = writeln!(s, "| {} | | |", t!("... y {n} más", "... and {n} more"));
            }
            let _ = writeln!(s);
        }
    }

    if let Some((certificados, por_riesgo)) = &m.almacen {
        let _ = writeln!(
            s,
            "## {}\n",
            tx("Almacén de confianza del sistema", "System trust store")
        );
        let _ = writeln!(s, "{}\n", m.texto_almacen(*certificados));
        let _ = writeln!(
            s,
            "| {} | {} |\n|---|---:|",
            tx("Riesgo", "Risk"),
            tx("Certificados", "Certificates")
        );
        for (riesgo, n) in por_riesgo {
            let _ = writeln!(s, "| {riesgo} | {n} |");
        }
        let _ = writeln!(s);
    }

    if !m.conformes.is_empty() {
        let _ = writeln!(
            s,
            "## {} ({})\n",
            tx("Activos conformes", "Compliant assets"),
            m.conformes.len()
        );
        let _ = writeln!(s, "{}.\n", m.conformes.join(", "));
        if !m.notas_conformes.is_empty() {
            let _ = writeln!(s, "**{}**\n", tx("Observaciones", "Observations"));
            for (nombre, adv) in &m.notas_conformes {
                let _ = writeln!(s, "- **{}**: {adv}", celda(nombre));
            }
            let _ = writeln!(s);
        }
    }

    let _ = writeln!(s, "## {}\n", tx("Metodología", "Methodology"));
    let ultimo = m.metodologia.len().saturating_sub(1);
    for (i, p) in m.metodologia.iter().enumerate() {
        if i == ultimo {
            let _ = writeln!(s, "{p}");
        } else {
            let _ = writeln!(s, "{p}\n");
        }
    }
    s.replace('<', "&lt;").replace('>', "&gt;")
}

// ---------------------------------------------------------------------------
// HTML
// ---------------------------------------------------------------------------

fn esc(t: &str) -> String {
    t.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Convierte el poco Markdown de los textos (`**negrita**` y `` `código` ``).
fn en_linea(t: &str) -> String {
    let mut s = String::new();
    let mut negrita = false;
    let mut codigo = false;
    let mut resto = esc(t);
    while !resto.is_empty() {
        if let Some(r) = resto.strip_prefix("**").filter(|_| !codigo) {
            s.push_str(if negrita { "</strong>" } else { "<strong>" });
            negrita = !negrita;
            resto = r.to_string();
        } else if let Some(r) = resto.strip_prefix('`') {
            s.push_str(if codigo { "</code>" } else { "<code>" });
            codigo = !codigo;
            resto = r.to_string();
        } else {
            let ch = resto.chars().next().unwrap_or(' ');
            s.push(ch);
            resto = resto[ch.len_utf8()..].to_string();
        }
    }
    if codigo {
        s.push_str("</code>");
    }
    if negrita {
        s.push_str("</strong>");
    }
    s
}

/// Clase CSS de un riesgo (para color y leyenda).
fn clase_riesgo(id: &str) -> &'static str {
    match id {
        "roto-clasico" => "r-roto",
        "obsoleto" => "r-obsoleto",
        "vulnerable-cuantico" => "r-vulnerable",
        "debilitado-grover" => "r-grover",
        "hibrido-pq" => "r-hibrido",
        "resistente-cuantico" => "r-resistente",
        _ => "r-desconocido",
    }
}

fn clase_prioridad(p: u8) -> &'static str {
    match p {
        1 => "p1",
        2 => "p2",
        3 => "p3",
        4 => "p4",
        _ => "p5",
    }
}

/// Barras horizontales en HTML (el texto conserva su tamaño en cualquier
/// pantalla): (etiqueta, valor, clase).
fn barras(titulo: &str, datos: &[(String, usize, &'static str)]) -> String {
    let maximo = datos.iter().map(|d| d.1).max().unwrap_or(0).max(1);
    let mut s = format!(
        r#"<figure class="grafica"><figcaption>{}</figcaption><div class="barras" role="img" aria-label="{}">"#,
        esc(titulo),
        esc(titulo)
    );
    for (etiqueta, valor, clase) in datos {
        let ancho = (*valor as f64 / maximo as f64 * 100.0).max(if *valor > 0 { 0.6 } else { 0.0 });
        let _ = write!(
            s,
            r#"<div class="fila"><span class="nombre">{}</span><span class="pista"><span class="barra {clase}" style="width:{ancho:.1}%"></span></span><span class="valor">{valor}</span></div>"#,
            esc(etiqueta)
        );
    }
    s.push_str("</div></figure>");
    s
}

/// Barra apilada (proporciones) con leyenda: (etiqueta, valor, clase).
fn apilada(titulo: &str, datos: &[(String, usize, &'static str)]) -> String {
    let total: usize = datos.iter().map(|d| d.1).sum();
    let mut s = format!(
        r#"<figure class="grafica"><figcaption>{}</figcaption><svg viewBox="0 0 640 34" role="img" aria-label="{}">"#,
        esc(titulo),
        esc(titulo)
    );
    let mut x = 0.0f64;
    for (etiqueta, valor, clase) in datos {
        if total == 0 || *valor == 0 {
            continue;
        }
        let ancho = *valor as f64 / total as f64 * 640.0;
        let _ = write!(
            s,
            r#"<rect x="{x:.1}" y="4" width="{ancho:.1}" height="26" class="{clase}"><title>{}: {valor}</title></rect>"#,
            esc(etiqueta)
        );
        x += ancho;
    }
    s.push_str(r#"</svg><ul class="leyenda">"#);
    for (etiqueta, valor, clase) in datos {
        let _ = write!(
            s,
            r#"<li><span class="muestra {clase}"></span>{} <strong>{valor}</strong></li>"#,
            esc(etiqueta)
        );
    }
    s.push_str("</ul></figure>");
    s
}

const ESTILO: &str = r#"
:root{--fondo:#fbfaf7;--papel:#ffffff;--texto:#1d232a;--suave:#56606b;--linea:#e2ded6;--acento:#1f5f8b;
--roto:#b42318;--obsoleto:#d9590f;--vulnerable:#b88a00;--grover:#4f7cac;--hibrido:#2e8b57;--resistente:#1b6e45;--desconocido:#8a8f98;
--p1:#b42318;--p2:#d9590f;--p3:#b88a00;--p4:#4f7cac;--p5:#8a8f98;--codigo:#f1eee8}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--fondo:#14171b;--papel:#1c2026;--texto:#e7e3dc;--suave:#a4abb4;--linea:#30353d;--acento:#7fb4dc;--codigo:#262b33}}
:root[data-theme=dark]{--fondo:#14171b;--papel:#1c2026;--texto:#e7e3dc;--suave:#a4abb4;--linea:#30353d;--acento:#7fb4dc;--codigo:#262b33}
*{box-sizing:border-box}
body{margin:0;background:var(--fondo);color:var(--texto);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans",sans-serif}
main{max-width:1060px;margin:0 auto;padding:32px 16px 64px}
header.portada{border-bottom:3px solid var(--acento);padding-bottom:18px;margin-bottom:28px}
header.portada p.marca{margin:0;color:var(--acento);font-weight:700;letter-spacing:.08em;text-transform:uppercase;font-size:12px}
h1{font-size:28px;margin:6px 0 14px}h2{font-size:21px;margin:40px 0 12px;padding-top:8px;border-top:1px solid var(--linea)}h3{font-size:17px;margin:26px 0 10px}
dl.datos{display:grid;grid-template-columns:max-content 1fr;gap:4px 18px;margin:0;color:var(--suave)}dl.datos dt{font-weight:600;color:var(--texto)}dl.datos dd{margin:0}
.cifras{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:18px 0}
.cifra{background:var(--papel);border:1px solid var(--linea);border-radius:8px;padding:12px 14px}.cifra b{display:block;font-size:26px;line-height:1.1}.cifra span{color:var(--suave);font-size:13px}
.tabla{overflow-x:auto;border:1px solid var(--linea);border-radius:8px;background:var(--papel);margin:10px 0 16px}
table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--linea);vertical-align:top}th{background:var(--codigo);font-weight:600}tr:last-child td{border-bottom:none}td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}
code{background:var(--codigo);padding:1px 5px;border-radius:4px;font-size:12.5px;word-break:break-all}
.etiqueta{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;color:#fff;white-space:nowrap}
ul.obs{padding-left:20px}ul.obs li{margin:4px 0}ul.obs li.sub{margin-left:18px;list-style:circle}
figure.grafica{margin:14px 0;background:var(--papel);border:1px solid var(--linea);border-radius:8px;padding:12px 14px}figure.grafica figcaption{font-weight:600;margin-bottom:6px}
svg{width:100%;height:auto;display:block}
.barras{display:grid;gap:7px}.fila{display:grid;grid-template-columns:minmax(120px,32%) 1fr 3.5em;align-items:center;gap:10px;font-size:14px}.fila .nombre{text-align:right;color:var(--suave)}.pista{background:var(--codigo);border-radius:3px;height:18px;overflow:hidden}.barra{display:block;height:100%;border-radius:3px}.fila .valor{font-weight:600;font-variant-numeric:tabular-nums}
section:first-of-type h2{border-top:none;padding-top:0}
ul.leyenda{list-style:none;padding:0;margin:8px 0 0;display:flex;flex-wrap:wrap;gap:6px 16px;font-size:13px}.muestra{display:inline-block;width:11px;height:11px;border-radius:2px;margin-right:6px;vertical-align:-1px}
.r-roto{fill:var(--roto);background:var(--roto)}.r-obsoleto{fill:var(--obsoleto);background:var(--obsoleto)}.r-vulnerable{fill:var(--vulnerable);background:var(--vulnerable)}.r-grover{fill:var(--grover);background:var(--grover)}.r-hibrido{fill:var(--hibrido);background:var(--hibrido)}.r-resistente{fill:var(--resistente);background:var(--resistente)}.r-desconocido{fill:var(--desconocido);background:var(--desconocido)}
.p1{fill:var(--p1);background:var(--p1)}.p2{fill:var(--p2);background:var(--p2)}.p3{fill:var(--p3);background:var(--p3)}.p4{fill:var(--p4);background:var(--p4)}.p5{fill:var(--p5);background:var(--p5)}
.c-no-conforme{fill:var(--roto);background:var(--roto)}.c-transicion{fill:var(--vulnerable);background:var(--vulnerable)}.c-conforme{fill:var(--hibrido);background:var(--hibrido)}.c-sin-evaluar{fill:var(--desconocido);background:var(--desconocido)}
footer{margin-top:48px;color:var(--suave);font-size:13px;border-top:1px solid var(--linea);padding-top:14px}
@page{size:A4;margin:16mm 14mm}
@media print{:root{--fondo:#fff;--papel:#fff;--texto:#000;--suave:#333;--linea:#bbb;--codigo:#f2f2f2}body{font-size:11pt}main{max-width:none;padding:0}h2{break-after:avoid}tr,figure,.cifra{break-inside:avoid}.tabla{overflow:visible;border-color:#bbb}a{color:inherit}}
@media (max-width:600px){h1{font-size:23px}dl.datos{grid-template-columns:1fr}.fila{grid-template-columns:1fr 3em}.fila .nombre{grid-column:1/-1;text-align:left}}
@media print{.barra,.muestra,.etiqueta,rect{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
"#;

/// Genera el reporte ejecutivo como página HTML autocontenida (sin red ni
/// JavaScript), imprimible a PDF desde cualquier navegador.
pub fn reporte_html(cbom: &CbomLeido, c: &Conocimiento) -> String {
    let m = Modelo::desde(cbom, c);
    let idioma = suaya_core::idioma::actual().codigo();
    let titulo = tx(
        "Reporte de preparación poscuántica",
        "Post-quantum readiness report",
    );
    let mut s = String::new();
    let _ = write!(
        s,
        r#"<!doctype html><html lang="{idioma}"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{} · {}</title><style>{ESTILO}</style></head><body><main>"#,
        esc(titulo),
        esc(&m.sistema)
    );
    if cbom.estado != "completed" {
        let _ = write!(s, "<p role=\"status\">{}</p>", esc(aviso_parcial()));
    }
    let _ = write!(
        s,
        r#"<header class="portada"><p class="marca">Suaya</p><h1>{}</h1><dl class="datos"><dt>{}</dt><dd>{}</dd><dt>{}</dt><dd>{}</dd><dt>{}</dt><dd>{}</dd><dt>{}</dt><dd>{}</dd></dl></header>"#,
        esc(titulo),
        tx("Sistema", "System"),
        esc(&m.sistema),
        tx("Fecha del escaneo", "Scan date"),
        esc(&m.fecha),
        tx("Herramienta", "Tool"),
        esc(&m.herramienta),
        tx("Base de conocimiento", "Knowledge base"),
        esc(&m.base_conocimiento)
    );

    let _ = write!(
        s,
        "<section><h2>{}</h2><p>{}</p>",
        tx("Resumen ejecutivo", "Executive summary"),
        en_linea(&m.resumen())
    );
    let _ = write!(
        s,
        r#"<div class="cifras"><div class="cifra"><b>{}</b><span>{}</span></div><div class="cifra"><b>{}</b><span>{}</span></div><div class="cifra"><b>{}</b><span>{}</span></div><div class="cifra"><b>{}</b><span>{}</span></div><div class="cifra"><b>{}</b><span>{}</span></div></div>"#,
        m.total,
        tx("activos inventariados", "assets inventoried"),
        m.criticos,
        tx("corregir de inmediato", "fix immediately"),
        m.migrables,
        tx("migrables hoy", "migratable today"),
        m.planificar,
        tx("planificar con piloto", "plan with a pilot"),
        m.protegidos,
        tx("ya protegidos", "already protected")
    );
    let prioridades: Vec<(String, usize, &'static str)> = m
        .por_prioridad
        .iter()
        .map(|(p, e, n)| (e.clone(), *n, clase_prioridad(*p)))
        .collect();
    s.push_str(&apilada(
        tx("Activos por prioridad", "Assets by priority"),
        &prioridades,
    ));
    let riesgos: Vec<(String, usize, &'static str)> = m
        .por_riesgo
        .iter()
        .map(|(id, e, n)| (e.clone(), *n, clase_riesgo(id)))
        .collect();
    s.push_str(&barras(
        tx("Activos por riesgo", "Assets by risk"),
        &riesgos,
    ));
    s.push_str("</section>");

    let _ = write!(
        s,
        r#"<section><h2>{}</h2><p>{}</p><div class="tabla"><table><thead><tr><th>{}</th><th>{}</th><th>{}</th><th class="n">{}</th><th class="n">{}</th><th class="n">{}</th><th class="n">{}</th></tr></thead><tbody>"#,
        tx(
            "Qué se puede migrar hoy y qué no",
            "What can be migrated today and what cannot"
        ),
        tx(
            "La madurez del ecosistema indica si ya existen productos para migrar cada tipo de garantía en cada capacidad tecnológica.",
            "Ecosystem maturity shows whether products already exist to migrate each type of assurance in each technology capability."
        ),
        tx("Capacidad", "Capability"),
        tx("Madurez: confidencialidad", "Maturity: confidentiality"),
        tx("Madurez: autenticación", "Maturity: authentication"),
        tx("Activos", "Assets"),
        tx("Migrar ahora", "Migrate now"),
        tx("Planificar", "Plan"),
        tx("Monitorear", "Monitor")
    );
    for f in &m.capacidades {
        let _ = write!(
            s,
            r#"<tr><td>{}</td><td>{}</td><td>{}</td><td class="n">{}</td><td class="n">{}</td><td class="n">{}</td><td class="n">{}</td></tr>"#,
            esc(&f.nombre),
            esc(&f.confidencialidad),
            esc(&f.autenticacion),
            f.activos,
            f.migrar,
            f.planificar,
            f.monitorear
        );
    }
    s.push_str("</tbody></table></div></section>");

    if let Some(o) = &m.organizacion {
        let _ = write!(
            s,
            "<section><h2>{}</h2><p>{}</p>",
            tx("Contexto de la organización", "Organizational context"),
            en_linea(&o.introduccion())
        );
        if !o.sistemas.is_empty() {
            let _ = write!(
                s,
                r#"<div class="tabla"><table><thead><tr><th>{}</th><th>{}</th><th>{}</th><th>{}</th><th class="n">{}</th><th class="n">{}</th><th class="n">{}</th></tr></thead><tbody>"#,
                tx("Sistema", "System"),
                tx("Responsable", "Owner"),
                tx("Criticidad", "Criticality"),
                tx("Exposición", "Exposure"),
                tx("Activos", "Assets"),
                tx("Críticos o altos", "Critical or high"),
                tx("Expuestos (Mosca)", "Exposed (Mosca)")
            );
            for f in &o.sistemas {
                let _ = write!(
                    s,
                    r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td class="n">{}</td><td class="n">{}</td><td class="n">{}</td></tr>"#,
                    esc(&f.nombre),
                    esc(&f.responsable),
                    esc(&f.criticidad),
                    esc(&f.exposicion),
                    f.activos,
                    f.urgentes,
                    f.expuestos
                );
            }
            s.push_str("</tbody></table></div>");
            if o.sin_sistema > 0 {
                let n = o.sin_sistema;
                let _ = write!(
                    s,
                    "<p>{}</p>",
                    esc(&t!(
                        "{n} activos no corresponden a ningún sistema declarado.",
                        "{n} assets do not belong to any declared system."
                    ))
                );
            }
        }
        if !o.expuestos.is_empty() {
            let _ = write!(
                s,
                r#"<h3>{}</h3><div class="tabla"><table><thead><tr><th>{}</th><th>{}</th><th class="n">{}</th></tr></thead><tbody>"#,
                esc(tx(
                    "Expuestos a «capturar ahora, descifrar después»",
                    "Exposed to \"harvest now, decrypt later\""
                )),
                tx("Activo", "Asset"),
                tx("Sistemas", "Systems"),
                tx("Años de exposición", "Years of exposure")
            );
            for (activo, sistemas, anios) in o.expuestos.iter().take(25) {
                let _ = write!(
                    s,
                    r#"<tr><td>{}</td><td>{}</td><td class="n">{anios}</td></tr>"#,
                    esc(activo),
                    esc(sistemas)
                );
            }
            s.push_str("</tbody></table></div>");
        }
        if !o.excepciones.is_empty() {
            let _ = write!(
                s,
                r#"<h3>{}</h3><div class="tabla"><table><thead><tr><th>{}</th><th>{}</th><th>{}</th><th>{}</th><th>{}</th><th class="n">{}</th></tr></thead><tbody>"#,
                tx("Excepciones", "Exceptions"),
                tx("Excepción", "Exception"),
                tx("Vence", "Expires"),
                tx("Estado", "Status"),
                tx("Justificación", "Justification"),
                tx("Aprobada por", "Approved by"),
                tx("Activos", "Assets")
            );
            for e in &o.excepciones {
                let _ = write!(
                    s,
                    r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td class="n">{}</td></tr>"#,
                    esc(&e.id),
                    esc(&e.vence),
                    if e.vigente {
                        tx("Vigente", "Active")
                    } else {
                        tx("Vencida", "Expired")
                    },
                    esc(&e.justificacion),
                    esc(&e.aprobada_por),
                    e.activos
                );
            }
            s.push_str("</tbody></table></div>");
        }
        s.push_str("</section>");
    }

    let _ = write!(
        s,
        "<section><h2>{}</h2>",
        tx(
            "Hallazgos que requieren acción",
            "Findings that require action"
        )
    );
    for sec in &m.secciones {
        let _ = write!(
            s,
            r#"<h3>{}</h3><div class="tabla"><table><thead><tr><th>{}</th><th>{}</th><th>{}</th><th>{}</th><th>{}</th><th>{}</th></tr></thead><tbody>"#,
            {
                let insignia = format!(
                    r#"<span class="etiqueta {}">{}</span>"#,
                    clase_prioridad(sec.prioridad),
                    esc(&capitalizar(&sec.etiqueta))
                );
                let n = sec.filas.len();
                t!("Prioridad {insignia} ({n})", "{insignia} priority ({n})")
            },
            tx("Activo", "Asset"),
            tx("Tipo", "Type"),
            tx("Riesgo", "Risk"),
            tx("Acción", "Action"),
            tx("Capacidad", "Capability"),
            tx("Ubicación", "Location")
        );
        for f in &sec.filas {
            let _ = write!(
                s,
                r#"<tr><td>{}</td><td>{}</td><td><span class="etiqueta {}">{}</span></td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>"#,
                esc(&f.nombre),
                f.tipo,
                clase_riesgo(&f.riesgo_id),
                esc(&f.riesgo),
                esc(&f.accion),
                esc(&f.capacidad),
                esc(&f.ubicacion)
            );
        }
        s.push_str("</tbody></table></div>");
        if !sec.observaciones.is_empty() {
            let _ = write!(
                s,
                r#"<details open><summary>{}</summary><ul class="obs">"#,
                tx("Observaciones", "Observations")
            );
            for (nombre, texto, sangria) in &sec.observaciones {
                if *sangria {
                    let _ = write!(s, r#"<li class="sub">{}</li>"#, en_linea(texto));
                } else {
                    let _ = write!(
                        s,
                        "<li><strong>{}</strong>: {}</li>",
                        esc(nombre),
                        en_linea(texto)
                    );
                }
            }
            s.push_str("</ul></details>");
        }
    }
    s.push_str("</section>");

    if !m.recetas.is_empty() {
        let _ = write!(
            s,
            "<section><h2>{}</h2><p>{}</p>",
            tx("Cómo corregir", "How to fix"),
            esc(texto_recetas())
        );
        for x in &m.recetas {
            let _ = write!(
                s,
                "<h3>{}</h3><p>{}</p><ol>",
                esc(&x.titulo),
                esc(&resumen_receta(x))
            );
            for paso in &x.pasos {
                let _ = write!(s, "<li>{}</li>", esc(paso));
            }
            s.push_str("</ol>");
            if !x.referencias.is_empty() {
                let enlaces: Vec<String> = x
                    .referencias
                    .iter()
                    .filter(|u| u.starts_with("https://"))
                    .map(|u| format!(r#"<a href="{0}">{0}</a>"#, esc(u)))
                    .collect();
                let _ = write!(
                    s,
                    "<p>{}: {}</p>",
                    tx("Referencias", "References"),
                    enlaces.join(", ")
                );
            }
        }
        s.push_str("</section>");
    }

    if let Some(cu) = &m.cumplimiento {
        let _ = write!(
            s,
            "<section><h2>{} {}</h2><p>{}: {}.</p>",
            tx("Cumplimiento con", "Compliance with"),
            esc(&cu.nombre),
            tx("Referencia", "Reference"),
            esc(&cu.referencia)
        );
        let estados: Vec<(String, usize, &'static str)> = cu
            .estados
            .iter()
            .map(|(id, e, n)| {
                (
                    e.clone(),
                    *n,
                    match *id {
                        "no-conforme" => "c-no-conforme",
                        "transicion" => "c-transicion",
                        "conforme" => "c-conforme",
                        _ => "c-sin-evaluar",
                    },
                )
            })
            .collect();
        s.push_str(&apilada(
            tx("Estado de cumplimiento", "Compliance status"),
            &estados,
        ));
        if !cu.plazos.is_empty() {
            let calendario: Vec<(String, usize, &'static str)> = cu
                .plazos
                .iter()
                .map(|(anio, n, _, _)| (anio.to_string(), *n, "c-transicion"))
                .collect();
            s.push_str(&barras(
                tx(
                    "Calendario de migración: activos por fecha límite",
                    "Migration calendar: assets by deadline",
                ),
                &calendario,
            ));
            let _ = write!(
                s,
                r#"<div class="tabla"><table><thead><tr><th>{}</th><th class="n">{}</th><th>{}</th></tr></thead><tbody>"#,
                tx("Fecha límite", "Deadline"),
                tx("Activos", "Assets"),
                tx("Ejemplos", "Examples")
            );
            for (anio, n, ejemplos, resto) in &cu.plazos {
                let mas = if *resto > 0 {
                    t!(" y {resto} más", " and {resto} more")
                } else {
                    String::new()
                };
                let _ = write!(
                    s,
                    r#"<tr><td>{anio}</td><td class="n">{n}</td><td>{}{}</td></tr>"#,
                    esc(&ejemplos.join(", ")),
                    esc(&mas)
                );
            }
            s.push_str("</tbody></table></div>");
        }
        if !cu.no_conformes.is_empty() {
            let _ = write!(
                s,
                r#"<h3>{}</h3><div class="tabla"><table><thead><tr><th>{}</th><th>{}</th><th>{}</th></tr></thead><tbody>"#,
                tx("Activos no conformes", "Non-compliant assets"),
                tx("Activo", "Asset"),
                tx("Tipo", "Type"),
                tx("Motivo", "Reason")
            );
            for (nombre, tipo, motivo) in &cu.no_conformes {
                let _ = write!(
                    s,
                    "<tr><td>{}</td><td>{tipo}</td><td>{}</td></tr>",
                    esc(nombre),
                    esc(motivo)
                );
            }
            if cu.no_conformes_restantes > 0 {
                let n = cu.no_conformes_restantes;
                let _ = write!(
                    s,
                    r#"<tr><td colspan="3">{}</td></tr>"#,
                    t!("... y {n} más", "... and {n} more")
                );
            }
            s.push_str("</tbody></table></div>");
        }
        s.push_str("</section>");
    }

    if let Some((certificados, por_riesgo)) = &m.almacen {
        let _ = write!(
            s,
            r#"<section><h2>{}</h2><p>{}</p><div class="tabla"><table><thead><tr><th>{}</th><th class="n">{}</th></tr></thead><tbody>"#,
            tx("Almacén de confianza del sistema", "System trust store"),
            en_linea(&m.texto_almacen(*certificados)),
            tx("Riesgo", "Risk"),
            tx("Certificados", "Certificates")
        );
        for (riesgo, n) in por_riesgo {
            let _ = write!(
                s,
                r#"<tr><td>{}</td><td class="n">{n}</td></tr>"#,
                esc(riesgo)
            );
        }
        s.push_str("</tbody></table></div></section>");
    }

    if !m.conformes.is_empty() {
        let _ = write!(
            s,
            "<section><h2>{} ({})</h2><p>{}.</p>",
            tx("Activos conformes", "Compliant assets"),
            m.conformes.len(),
            esc(&m.conformes.join(", "))
        );
        if !m.notas_conformes.is_empty() {
            let _ = write!(
                s,
                r#"<details><summary>{}</summary><ul class="obs">"#,
                tx("Observaciones", "Observations")
            );
            for (nombre, adv) in &m.notas_conformes {
                let _ = write!(
                    s,
                    "<li><strong>{}</strong>: {}</li>",
                    esc(nombre),
                    en_linea(adv)
                );
            }
            s.push_str("</ul></details>");
        }
        s.push_str("</section>");
    }

    let _ = write!(s, "<section><h2>{}</h2>", tx("Metodología", "Methodology"));
    for p in &m.metodologia {
        let _ = write!(s, "<p>{}</p>", en_linea(p));
    }
    let _ = writeln!(
        s,
        "</section><footer>{}</footer></main></body></html>",
        tx(
            "Generado por Suaya, software libre de inventario criptográfico (Apache-2.0). Para guardar en PDF, use Imprimir en el navegador.",
            "Generated by Suaya, free and open cryptographic inventory software (Apache-2.0). To save as PDF, use Print in the browser."
        )
    );
    s
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn markdown_en_linea() {
        assert_eq!(
            en_linea("**hola** `a<b` y **más**"),
            "<strong>hola</strong> <code>a&lt;b</code> y <strong>más</strong>"
        );
    }
}
