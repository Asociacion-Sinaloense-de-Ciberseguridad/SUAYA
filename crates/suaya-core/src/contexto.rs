//! Contexto de la organización: sistemas, responsables, exposición, vida útil
//! de los datos y excepciones con vencimiento.
//!
//! El inventario dice qué criptografía hay; el contexto dice qué importa más.
//! Se declara en un archivo TOML (`--organizacion suaya-organizacion.toml`):
//!
//! ```toml
//! [organizacion]
//! horizonte_cuantico = 2035   # año supuesto de una computadora cuántica relevante
//!
//! [[sistema]]
//! nombre = "Portal de clientes"
//! responsable = "equipo-web@ejemplo.mx"
//! criticidad = "alta"          # alta | media | baja
//! exposicion = "internet"      # internet | interna
//! vida_datos = 10              # años que los datos deben seguir confidenciales
//! migracion = 3                # años que tomará migrar
//! rutas = ["srv/web/**"]
//! objetivos = ["tls://portal.ejemplo.mx:443"]
//!
//! [[excepcion]]
//! id = "EXC-2026-014"
//! justificacion = "Equipo heredado; se reemplaza en 2027."
//! aprobada_por = "Comité de riesgos"
//! vence = "2027-06-30"
//! algoritmos = ["tls-1.0"]
//! rutas = ["srv/legado/**"]
//! ```
//!
//! Con `vida_datos`, Suaya evalúa la desigualdad de Mosca (x + y > z): si los
//! datos deben protegerse más tiempo del que falta para el horizonte, menos lo
//! que tarda la migración, lo que hoy se captura cifrado podrá descifrarse
//! mientras siga siendo valioso. Esos activos suben a prioridad alta.
//!
//! Una excepción vigente no cambia la clasificación ni oculta el activo: lo
//! marca como riesgo aceptado y lo excluye del umbral `--fallar-en`. Vencida,
//! vuelve a contar y se advierte.

use serde::Deserialize;

use crate::modelo::{
    ContextoOrganizacional, Criticidad, Excepcion, Exposicion, Garantia, Inventario, Mosca, Riesgo,
};

/// Horizonte predeterminado: la fecha de prohibición de NIST IR 8547 como
/// referencia de planeación, no como predicción.
pub const HORIZONTE_PREDETERMINADO: i32 = 2035;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Organizacion {
    #[serde(default)]
    pub nombre: Option<String>,
    #[serde(default)]
    pub horizonte_cuantico: Option<i32>,
    /// Años de migración cuando un sistema no declara los suyos.
    #[serde(default)]
    pub migracion_predeterminada: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sistema {
    pub nombre: String,
    #[serde(default)]
    pub responsable: Option<String>,
    #[serde(default)]
    pub criticidad: Option<Criticidad>,
    #[serde(default)]
    pub exposicion: Option<Exposicion>,
    #[serde(default)]
    pub vida_datos: Option<u32>,
    #[serde(default)]
    pub migracion: Option<u32>,
    #[serde(default)]
    pub rutas: Vec<String>,
    #[serde(default)]
    pub objetivos: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReglaExcepcion {
    pub id: String,
    pub justificacion: String,
    #[serde(default)]
    pub aprobada_por: Option<String>,
    pub vence: String,
    #[serde(default)]
    pub algoritmos: Vec<String>,
    #[serde(default)]
    pub referencias: Vec<String>,
    #[serde(default)]
    pub riesgos: Vec<Riesgo>,
    /// Todas las ubicaciones del activo deben coincidir con alguna.
    #[serde(default)]
    pub rutas: Vec<String>,
}

/// Archivo de contexto cargado y validado.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchivoContexto {
    #[serde(default)]
    pub organizacion: Organizacion,
    #[serde(rename = "sistema", default)]
    pub sistemas: Vec<Sistema>,
    #[serde(rename = "excepcion", default)]
    pub excepciones: Vec<ReglaExcepcion>,
}

/// Resumen de lo aplicado, para la pantalla y el reporte.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Aplicado {
    pub con_sistema: usize,
    pub expuestos_mosca: usize,
    pub excepciones_vigentes: usize,
    pub excepciones_vencidas: usize,
    /// Excepciones del archivo que no cubrieron ningún activo.
    pub excepciones_sin_uso: Vec<String>,
}

fn fecha_valida(f: &str) -> bool {
    let p: Vec<&str> = f.split('-').collect();
    p.len() == 3
        && p[0].len() == 4
        && p[1].len() == 2
        && p[2].len() == 2
        && p.iter().all(|x| x.bytes().all(|b| b.is_ascii_digit()))
        && (1..=12).contains(&p[1].parse::<u32>().unwrap_or(0))
        && (1..=31).contains(&p[2].parse::<u32>().unwrap_or(0))
}

impl ArchivoContexto {
    pub fn desde_texto(t: &str) -> Result<Self, String> {
        let a: ArchivoContexto =
            toml::from_str(t).map_err(|e| format!("archivo de contexto inválido: {e}"))?;
        a.validar()?;
        Ok(a)
    }

    pub fn cargar(ruta: &std::path::Path) -> Result<Self, String> {
        let meta = std::fs::metadata(ruta)
            .map_err(|e| format!("no se pudo leer {}: {e}", ruta.display()))?;
        if meta.len() > 4 * 1024 * 1024 {
            return Err(format!(
                "{}: el archivo de contexto excede 4 MiB",
                ruta.display()
            ));
        }
        let t = std::fs::read_to_string(ruta)
            .map_err(|e| format!("no se pudo leer {}: {e}", ruta.display()))?;
        Self::desde_texto(&t)
    }

    fn validar(&self) -> Result<(), String> {
        if let Some(h) = self.organizacion.horizonte_cuantico
            && !(2025..=2100).contains(&h)
        {
            return Err(format!(
                "horizonte_cuantico fuera de rango (2025 a 2100): {h}"
            ));
        }
        let mut nombres = std::collections::BTreeSet::new();
        for s in &self.sistemas {
            if s.nombre.trim().is_empty() {
                return Err("un [[sistema]] no tiene nombre".into());
            }
            if !nombres.insert(s.nombre.as_str()) {
                return Err(format!("sistema duplicado: {}", s.nombre));
            }
            if s.rutas.is_empty() && s.objetivos.is_empty() {
                return Err(format!(
                    "el sistema «{}» no declara rutas ni objetivos",
                    s.nombre
                ));
            }
            if s.vida_datos.is_some_and(|v| v > 100) || s.migracion.is_some_and(|v| v > 50) {
                return Err(format!(
                    "el sistema «{}» declara años fuera de rango",
                    s.nombre
                ));
            }
            for p in s.rutas.iter().chain(&s.objetivos) {
                if p.trim().is_empty() {
                    return Err(format!("el sistema «{}» tiene un patrón vacío", s.nombre));
                }
                patron(p)?;
            }
        }
        let mut ids = std::collections::BTreeSet::new();
        for e in &self.excepciones {
            if e.id.trim().is_empty() || !ids.insert(e.id.as_str()) {
                return Err(format!("excepción sin id o duplicada: «{}»", e.id));
            }
            if e.justificacion.trim().is_empty() {
                return Err(format!("la excepción {} no tiene justificación", e.id));
            }
            if !fecha_valida(&e.vence) {
                return Err(format!(
                    "la excepción {} tiene una fecha de vencimiento inválida (use AAAA-MM-DD): {}",
                    e.id, e.vence
                ));
            }
            for p in &e.rutas {
                patron(p)?;
            }
            if e.algoritmos.is_empty() && e.referencias.is_empty() && e.rutas.is_empty() {
                return Err(format!(
                    "la excepción {} debe acotar su alcance con algoritmos, referencias o rutas",
                    e.id
                ));
            }
        }
        Ok(())
    }

    /// Año supuesto de una computadora cuántica relevante.
    pub fn horizonte(&self) -> i32 {
        self.organizacion
            .horizonte_cuantico
            .unwrap_or(HORIZONTE_PREDETERMINADO)
    }

    /// Aplica el contexto a un inventario ya clasificado. `hoy` es AAAA-MM-DD.
    pub fn aplicar(&self, inv: &mut Inventario, hoy: &str) -> Aplicado {
        let anio: i32 = hoy.get(..4).and_then(|a| a.parse().ok()).unwrap_or(2026);
        let horizonte = self.horizonte();
        let mut resumen = Aplicado::default();
        let mut usadas = vec![false; self.excepciones.len()];
        // Los patrones se validaron al cargar.
        let compilar = |v: &[String]| -> Vec<regex::Regex> {
            v.iter().filter_map(|p| patron(p).ok()).collect()
        };
        let de_sistemas: Vec<Vec<regex::Regex>> = self
            .sistemas
            .iter()
            .map(|s| {
                let mut v = compilar(&s.rutas);
                v.extend(compilar(&s.objetivos));
                v
            })
            .collect();
        let de_excepciones: Vec<Vec<regex::Regex>> = self
            .excepciones
            .iter()
            .map(|e| compilar(&e.rutas))
            .collect();

        for a in inv.activos.iter_mut() {
            let rutas: Vec<String> = a.ubicaciones.iter().map(|u| normalizar(&u.ruta)).collect();
            let sistemas: Vec<&Sistema> = self
                .sistemas
                .iter()
                .zip(&de_sistemas)
                .filter(|(_, pats)| rutas.iter().any(|r| pats.iter().any(|p| p.is_match(r))))
                .map(|(s, _)| s)
                .collect();

            let mut org = ContextoOrganizacional::default();
            for s in &sistemas {
                org.sistemas.push(s.nombre.clone());
                if let Some(r) = &s.responsable
                    && !org.responsables.contains(r)
                {
                    org.responsables.push(r.clone());
                }
            }
            org.criticidad = sistemas.iter().filter_map(|s| s.criticidad).min();
            org.exposicion = if sistemas
                .iter()
                .any(|s| s.exposicion == Some(Exposicion::Internet))
            {
                Some(Exposicion::Internet)
            } else {
                sistemas.iter().find_map(|s| s.exposicion)
            };

            // Mosca: solo la confidencialidad puede capturarse hoy y descifrarse después.
            let vida = sistemas.iter().filter_map(|s| s.vida_datos).max();
            if let (Some(x), Some(cl)) = (vida, a.clasificacion.as_mut())
                && cl.garantia == Garantia::Confidencialidad
                && cl.riesgo == Riesgo::VulnerableCuantico
            {
                let y = sistemas
                    .iter()
                    .filter(|s| s.vida_datos.is_some())
                    .filter_map(|s| s.migracion)
                    .max()
                    .or(self.organizacion.migracion_predeterminada)
                    .unwrap_or(0);
                let z = horizonte - anio;
                let m = Mosca {
                    vida_datos: x,
                    migracion: y,
                    horizonte,
                    holgura: z - (x as i32 + y as i32),
                };
                if m.expuesto() {
                    resumen.expuestos_mosca += 1;
                    if cl.prioridad > 2 {
                        cl.prioridad = 2;
                    }
                    cl.justificacion.push_str(&format!(
                        " Expuesto a «capturar ahora, descifrar después»: los datos deben protegerse {x} años y la migración tarda {y}; con el horizonte supuesto de {horizonte} faltan {} años.",
                        -m.holgura
                    ));
                }
                org.mosca = Some(m);
            }

            for (i, e) in self.excepciones.iter().enumerate() {
                let riesgo = a.clasificacion.as_ref().map(|c| c.riesgo);
                let algoritmo = a.algoritmo_id();
                let cubre = (e.algoritmos.is_empty()
                    || algoritmo.is_some_and(|id| e.algoritmos.iter().any(|x| x == id)))
                    && (e.referencias.is_empty() || e.referencias.contains(&a.referencia))
                    && (e.riesgos.is_empty() || riesgo.is_some_and(|r| e.riesgos.contains(&r)))
                    && (e.rutas.is_empty()
                        || (!rutas.is_empty()
                            && rutas
                                .iter()
                                .all(|r| de_excepciones[i].iter().any(|p| p.is_match(r)))));
                if !cubre {
                    continue;
                }
                usadas[i] = true;
                let vigente = e.vence.as_str() >= hoy;
                if vigente {
                    resumen.excepciones_vigentes += 1;
                } else {
                    resumen.excepciones_vencidas += 1;
                    a.advertir(format!(
                        "La excepción {} venció el {}: el riesgo vuelve a contar.",
                        e.id, e.vence
                    ));
                }
                org.excepcion = Some(Excepcion {
                    id: e.id.clone(),
                    justificacion: e.justificacion.clone(),
                    aprobada_por: e.aprobada_por.clone(),
                    vence: e.vence.clone(),
                    vigente,
                });
                break;
            }

            if !org.sistemas.is_empty() || org.excepcion.is_some() {
                if !org.sistemas.is_empty() {
                    resumen.con_sistema += 1;
                }
                a.organizacion = Some(org);
            }
        }
        resumen.excepciones_sin_uso = self
            .excepciones
            .iter()
            .zip(&usadas)
            .filter(|(_, u)| !**u)
            .map(|(e, _)| e.id.clone())
            .collect();
        inv.ordenar();
        resumen
    }
}

/// Un activo con una excepción vigente no cuenta para los umbrales de falla.
pub fn exceptuado(a: &crate::modelo::Activo) -> bool {
    a.organizacion
        .as_ref()
        .and_then(|o| o.excepcion.as_ref())
        .is_some_and(|e| e.vigente)
}

/// Convierte un patrón de ubicación en una expresión regular. `**` cruza
/// separadores, `*` no y `?` es un carácter. Un patrón relativo coincide con
/// la ruta completa o con cualquier sufijo que empiece en un separador, de
/// modo que «srv/web/**» encuentra «/datos/escaneo/srv/web/nginx.conf».
pub fn patron(p: &str) -> Result<regex::Regex, String> {
    // Sin distinguir mayúsculas en ASCII: patrón y ruta se comparan en minúsculas.
    let p = p.trim().replace('\\', "/").to_ascii_lowercase();
    let mut r = String::from("^");
    if !(p.starts_with('/') || p.contains("://")) {
        r.push_str("(?:.*/)?");
    }
    let b: Vec<char> = p.chars().collect();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            '*' if b.get(i + 1) == Some(&'*') => {
                if b.get(i + 2) == Some(&'/') {
                    r.push_str("(?:.*/)?");
                    i += 3;
                } else {
                    r.push_str(".*");
                    i += 2;
                }
            }
            '*' => {
                r.push_str("[^/]*");
                i += 1;
            }
            '?' => {
                r.push_str("[^/]");
                i += 1;
            }
            c => {
                r.push_str(&regex::escape(&c.to_string()));
                i += 1;
            }
        }
    }
    r.push('$');
    regex::Regex::new(&r).map_err(|e| format!("patrón inválido «{p}»: {e}"))
}

/// Forma en que se comparan las ubicaciones con los patrones.
fn normalizar(ruta: &str) -> String {
    ruta.replace('\\', "/").to_ascii_lowercase()
}

/// Coincidencia de un patrón con una ubicación (ver [`patron`]).
pub fn coincide_ruta(p: &str, ruta: &str) -> bool {
    patron(p).is_ok_and(|re| re.is_match(&normalizar(ruta)))
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::modelo::{Activo, Detalles};
    use crate::{Conocimiento, clasificar};

    #[test]
    fn comodines() {
        assert!(coincide_ruta(
            "srv/web/**",
            "/datos/srv/web/nginx/nginx.conf"
        ));
        assert!(coincide_ruta("srv/web/**", "srv/web/a.conf"));
        assert!(!coincide_ruta("srv/web/*", "srv/web/sub/a.conf"));
        assert!(coincide_ruta("srv/web/*", "srv/web/a.conf"));
        assert!(coincide_ruta("**/sshd_config", "etc/ssh/sshd_config"));
        assert!(coincide_ruta("etc/**/sshd_config", "etc/sshd_config"));
        assert!(coincide_ruta(
            "tls://*.ejemplo.mx:443",
            "tls://portal.ejemplo.mx:443"
        ));
        assert!(!coincide_ruta(
            "tls://*.ejemplo.mx:443",
            "tls://portal.otro.mx:443"
        ));
        assert!(!coincide_ruta("/srv/**", "datos/srv/a"));
        assert!(coincide_ruta("*.pem", "certs/a.pem"));
        assert!(coincide_ruta("A?.PEM", "x/ab.pem"));
    }

    fn inventario() -> Inventario {
        let c = Conocimiento::embebido();
        let mut inv = Inventario::default();
        let alg = |id: &str, ruta: &str, cap: &str, g: Garantia| {
            Activo::nuevo(
                format!("algoritmo:{id}"),
                id,
                Detalles::Algoritmo {
                    algoritmo_id: Some(id.into()),
                    tamano_llave: None,
                },
            )
            .con_contexto(cap, g)
            .con_ubicacion(ruta, Some(1))
        };
        inv.agregar(alg(
            "ecdh-p256",
            "srv/web/nginx.conf",
            "vpn-cifrado-red",
            Garantia::Confidencialidad,
        ));
        inv.agregar(alg(
            "tls-1.0",
            "srv/legado/app.conf",
            "servidores-web",
            Garantia::Confidencialidad,
        ));
        inv.agregar(alg(
            "ed25519",
            "srv/web/llave.pub",
            "servidores-web",
            Garantia::Autenticacion,
        ));
        clasificar(&mut inv, &c);
        inv
    }

    const CONTEXTO: &str = r#"
[organizacion]
horizonte_cuantico = 2035

[[sistema]]
nombre = "Portal"
responsable = "web@ejemplo.mx"
criticidad = "alta"
exposicion = "internet"
vida_datos = 10
migracion = 3
rutas = ["srv/web/**"]

[[sistema]]
nombre = "Legado"
criticidad = "baja"
rutas = ["srv/legado/**"]

[[excepcion]]
id = "EXC-1"
justificacion = "Equipo heredado"
vence = "2027-06-30"
algoritmos = ["tls-1.0"]
rutas = ["srv/legado/**"]

[[excepcion]]
id = "EXC-2"
justificacion = "Nunca coincide"
vence = "2027-01-01"
referencias = ["no-existe"]
"#;

    #[test]
    fn sistemas_mosca_y_excepciones() {
        let ctx = ArchivoContexto::desde_texto(CONTEXTO).unwrap();
        let mut inv = inventario();
        let r = ctx.aplicar(&mut inv, "2026-11-06");
        let buscar = |id: &str| {
            inv.activos
                .iter()
                .find(|a| a.algoritmo_id() == Some(id))
                .unwrap()
        };
        let ecdh = buscar("ecdh-p256");
        let org = ecdh.organizacion.as_ref().unwrap();
        assert_eq!(org.sistemas, vec!["Portal"]);
        assert_eq!(org.criticidad, Some(Criticidad::Alta));
        assert_eq!(org.exposicion, Some(Exposicion::Internet));
        let m = org.mosca.as_ref().unwrap();
        // z = 2035 - 2026 = 9; x + y = 13: cuatro años de déficit.
        assert_eq!(m.holgura, -4);
        assert!(m.expuesto());
        assert_eq!(ecdh.clasificacion.as_ref().unwrap().prioridad, 2);
        // La autenticación no se evalúa con Mosca.
        assert!(
            buscar("ed25519")
                .organizacion
                .as_ref()
                .unwrap()
                .mosca
                .is_none()
        );
        let tls = buscar("tls-1.0");
        assert!(exceptuado(tls));
        assert_eq!(r.excepciones_vigentes, 1);
        assert_eq!(r.expuestos_mosca, 1);
        assert_eq!(r.excepciones_sin_uso, vec!["EXC-2"]);

        // Vencida, la excepción ya no exceptúa y se advierte.
        let mut inv = inventario();
        ctx.aplicar(&mut inv, "2027-07-01");
        let tls = inv
            .activos
            .iter()
            .find(|a| a.algoritmo_id() == Some("tls-1.0"))
            .unwrap();
        assert!(!exceptuado(tls));
        assert!(tls.advertencias.iter().any(|w| w.contains("EXC-1")));
    }

    #[test]
    fn validacion() {
        for malo in [
            "[[sistema]]\nnombre = \"A\"\n",
            "[[sistema]]\nnombre = \"A\"\nrutas=[\"x\"]\n[[sistema]]\nnombre = \"A\"\nrutas=[\"y\"]\n",
            "[[excepcion]]\nid=\"E\"\njustificacion=\"j\"\nvence=\"2027-13-01\"\nrutas=[\"x\"]\n",
            "[[excepcion]]\nid=\"E\"\njustificacion=\"j\"\nvence=\"2027-01-01\"\n",
            "[organizacion]\nhorizonte_cuantico = 1999\n",
            "[[sistema]]\nnombre = \"A\"\nrutas=[\"x\"]\ncriticidad=\"urgente\"\n",
            "[[sistema]]\nnombre = \"A\"\nrutas=[\"x\"]\notro=1\n",
        ] {
            assert!(ArchivoContexto::desde_texto(malo).is_err(), "{malo}");
        }
    }
}
