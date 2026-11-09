//! Idioma de la interfaz y de los reportes.
//!
//! Suaya escribe en español. En inglés hay dos mecanismos:
//!
//! - El texto propio de la interfaz y de los reportes usa la macro
//!   [`t!`](crate::t), que guarda ambas versiones junto al código.
//! - El texto de los hallazgos (advertencias, justificaciones, nombres y notas
//!   de la base de conocimiento) se traduce al presentarlo con [`traducir`],
//!   a partir del catálogo `conocimiento/traducciones/en.toml`. Cada entrada
//!   es una plantilla: `{}` o `{nombre}` coinciden con cualquier valor, que
//!   se traduce a su vez si también está en el catálogo.
//!
//! En portugués (`pt`), `tx`, [`t!`](crate::t) y [`traducir`] consultan el
//! catálogo `conocimiento/traducciones/pt.toml` con las mismas plantillas.
//! Cubre el reporte, las etiquetas y el resumen de la línea de órdenes.
//!
//! Lo que el catálogo no cubre se muestra en español, nunca se pierde.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, Ordering};

use regex::Regex;
use serde::Deserialize;

const CATALOGO_EN: &str = include_str!("../../../conocimiento/traducciones/en.toml");
const CATALOGO_PT: &str = include_str!("../../../conocimiento/traducciones/pt.toml");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Idioma {
    Es,
    En,
    Pt,
}

static ACTUAL: AtomicU8 = AtomicU8::new(0);

thread_local! {
    /// Idioma de este hilo, si se fijó con [`con_idioma`] (pruebas, servidores).
    static LOCAL: std::cell::Cell<Option<Idioma>> = const { std::cell::Cell::new(None) };
}

/// Ejecuta `f` con un idioma en este hilo, sin tocar el del proceso.
pub fn con_idioma<R>(i: Idioma, f: impl FnOnce() -> R) -> R {
    let previo = LOCAL.with(|l| l.replace(Some(i)));
    let r = f();
    LOCAL.with(|l| l.set(previo));
    r
}

impl Idioma {
    pub fn interpretar(t: &str) -> Option<Self> {
        match t.trim().to_lowercase().as_str() {
            "es" | "español" | "espanol" | "spanish" => Some(Self::Es),
            "en" | "inglés" | "ingles" | "english" => Some(Self::En),
            "pt" | "pt-br" | "portugués" | "portugues" | "português" | "portuguese" => {
                Some(Self::Pt)
            }
            _ => None,
        }
    }

    pub fn codigo(self) -> &'static str {
        match self {
            Self::Es => "es",
            Self::En => "en",
            Self::Pt => "pt",
        }
    }
}

/// Fija el idioma para el resto del proceso.
pub fn fijar(i: Idioma) {
    ACTUAL.store(i as u8, Ordering::Relaxed);
}

pub fn actual() -> Idioma {
    if let Some(i) = LOCAL.with(|l| l.get()) {
        return i;
    }
    match ACTUAL.load(Ordering::Relaxed) {
        x if x == Idioma::En as u8 => Idioma::En,
        x if x == Idioma::Pt as u8 => Idioma::Pt,
        _ => Idioma::Es,
    }
}

pub fn es_ingles() -> bool {
    actual() == Idioma::En
}

pub fn es_portugues() -> bool {
    actual() == Idioma::Pt
}

/// Idioma pedido en la línea de órdenes (`--idioma en`) o en `SUAYA_IDIOMA`.
pub fn desde_entorno<I: IntoIterator<Item = String>>(argumentos: I) -> Idioma {
    let mut previo = String::new();
    for a in argumentos {
        if let Some(v) = a
            .strip_prefix("--idioma=")
            .or_else(|| a.strip_prefix("--language="))
            && let Some(i) = Idioma::interpretar(v)
        {
            return i;
        }
        if (previo == "--idioma" || previo == "--language")
            && let Some(i) = Idioma::interpretar(&a)
        {
            return i;
        }
        previo = a;
    }
    std::env::var("SUAYA_IDIOMA")
        .ok()
        .and_then(|v| Idioma::interpretar(&v))
        .unwrap_or(Idioma::Es)
}

/// Texto en el idioma actual, para cadenas fijas. En portugués se busca la
/// versión en español en el catálogo; si no está, queda en español.
pub fn tx(es: &'static str, en: &'static str) -> &'static str {
    match actual() {
        Idioma::En => en,
        Idioma::Pt => catalogo(Destino::Pt)
            .exactos
            .get(es)
            .map_or(es, String::as_str),
        Idioma::Es => es,
    }
}

/// Texto en el idioma actual. Ambas plantillas aceptan los mismos argumentos
/// que `format!`, incluidas las variables capturadas (`{nombre}`).
#[macro_export]
macro_rules! t {
    ($es:literal, $en:literal $(,)?) => {
        if $crate::idioma::es_ingles() {
            format!($en)
        } else {
            $crate::idioma::en_idioma_actual(format!($es))
        }
    };
    ($es:literal, $en:literal, $($arg:tt)+) => {
        if $crate::idioma::es_ingles() {
            format!($en, $($arg)+)
        } else {
            $crate::idioma::en_idioma_actual(format!($es, $($arg)+))
        }
    };
}

#[derive(Deserialize)]
struct Entrada {
    es: String,
    #[serde(default)]
    en: Option<String>,
    #[serde(default)]
    pt: Option<String>,
}

/// Idioma de destino de un catálogo.
#[derive(Clone, Copy)]
enum Destino {
    En,
    Pt,
}

#[derive(Deserialize)]
struct ArchivoCatalogo {
    #[serde(rename = "texto", default)]
    textos: Vec<Entrada>,
}

struct Plantilla {
    patron: Regex,
    /// Cantidad de texto fijo, para ordenar de más a menos específica.
    fijo: usize,
    /// Nombres de los marcadores, en orden («0», «1»... para `{}`).
    marcadores: Vec<String>,
    destino: String,
}

struct Catalogo {
    exactos: HashMap<String, String>,
    plantillas: Vec<Plantilla>,
}

fn marcadores(plantilla: &str) -> Vec<(usize, usize, String)> {
    // (inicio, fin, nombre) de cada «{...}», sin contar «{{» ni «}}».
    let b = plantilla.as_bytes();
    let mut v = Vec::new();
    let mut i = 0;
    let mut posicional = 0;
    while i < b.len() {
        if b[i] == b'{' {
            if b.get(i + 1) == Some(&b'{') {
                i += 2;
                continue;
            }
            if let Some(f) = plantilla[i..].find('}') {
                let dentro = &plantilla[i + 1..i + f];
                let nombre = dentro.split(':').next().unwrap_or("").to_string();
                let nombre = if nombre.is_empty() {
                    posicional += 1;
                    (posicional - 1).to_string()
                } else {
                    nombre
                };
                v.push((i, i + f + 1, nombre));
                i += f + 1;
                continue;
            }
        }
        i += 1;
    }
    v
}

#[cfg(test)]
fn compilar(texto: &str) -> Result<Catalogo, String> {
    compilar_para(texto, Destino::En)
}

fn compilar_para(texto: &str, d: Destino) -> Result<Catalogo, String> {
    let a: ArchivoCatalogo = toml::from_str(texto).map_err(|e| e.to_string())?;
    let mut exactos = HashMap::new();
    let mut plantillas = Vec::new();
    for e in a.textos {
        let destino = match d {
            Destino::En => e.en,
            Destino::Pt => e.pt,
        }
        .ok_or_else(|| format!("entrada sin traducción: {}", e.es))?;
        let ms = marcadores(&e.es);
        if ms.is_empty() {
            exactos.insert(e.es.replace("{{", "{").replace("}}", "}"), destino);
            continue;
        }
        let mut patron = String::from("^");
        let mut ultimo = 0;
        for (inicio, fin, _) in &ms {
            patron.push_str(&regex::escape(
                &e.es[ultimo..*inicio].replace("{{", "{").replace("}}", "}"),
            ));
            patron.push_str("(.+?)");
            ultimo = *fin;
        }
        patron.push_str(&regex::escape(&e.es[ultimo..]));
        patron.push('$');
        let fijo = e.es.len() - ms.iter().map(|(i, f, _)| f - i).sum::<usize>();
        plantillas.push(Plantilla {
            fijo,
            patron: Regex::new(&format!("(?s){patron}")).map_err(|x| x.to_string())?,
            marcadores: ms.into_iter().map(|(_, _, n)| n).collect(),
            destino,
        });
    }
    // Las plantillas más específicas (más texto fijo) se prueban primero.
    plantillas.sort_by_key(|p| std::cmp::Reverse(p.fijo));
    Ok(Catalogo {
        exactos,
        plantillas,
    })
}

fn catalogo(d: Destino) -> &'static Catalogo {
    static EN: OnceLock<Catalogo> = OnceLock::new();
    static PT: OnceLock<Catalogo> = OnceLock::new();
    match d {
        Destino::En => EN.get_or_init(|| {
            compilar_para(CATALOGO_EN, d).expect("el catálogo en.toml debe ser válido")
        }),
        Destino::Pt => PT.get_or_init(|| {
            compilar_para(CATALOGO_PT, d).expect("el catálogo pt.toml debe ser válido")
        }),
    }
}

/// Valida los catálogos incrustados (lo usan las pruebas).
pub fn validar_catalogo() -> Result<usize, String> {
    let en = compilar_para(CATALOGO_EN, Destino::En)?;
    let pt = compilar_para(CATALOGO_PT, Destino::Pt)?;
    Ok(en.exactos.len() + en.plantillas.len() + pt.exactos.len() + pt.plantillas.len())
}

fn traducir_en(texto: &str, profundidad: u8) -> Option<String> {
    traducir_con(Destino::En, texto, profundidad)
}

fn traducir_con(d: Destino, texto: &str, profundidad: u8) -> Option<String> {
    let c = catalogo(d);
    if let Some(en) = c.exactos.get(texto) {
        return Some(en.clone());
    }
    if profundidad > 3 {
        return None;
    }
    for p in &c.plantillas {
        if let Some(cap) = p.patron.captures(texto) {
            let mut salida = String::new();
            let ms = marcadores(&p.destino);
            let mut ultimo = 0;
            let mut posicional = 0usize;
            for (inicio, fin, nombre) in ms {
                salida.push_str(
                    &p.destino[ultimo..inicio]
                        .replace("{{", "{")
                        .replace("}}", "}"),
                );
                let indice = p
                    .marcadores
                    .iter()
                    .position(|m| *m == nombre)
                    .or_else(|| nombre.parse::<usize>().ok())
                    .unwrap_or_else(|| {
                        posicional += 1;
                        posicional - 1
                    });
                let valor = cap.get(indice + 1).map_or("", |m| m.as_str());
                // Se traduce el valor sin sus espacios externos, que se conservan.
                let nucleo = valor.trim();
                let inicio_v = &valor[..valor.len() - valor.trim_start().len()];
                let fin_v = &valor[valor.trim_end().len()..];
                match traducir_con(d, nucleo, profundidad + 1) {
                    Some(t) if !nucleo.is_empty() => {
                        salida.push_str(inicio_v);
                        salida.push_str(&t);
                        salida.push_str(fin_v);
                    }
                    _ => salida.push_str(valor),
                }
                ultimo = fin;
            }
            salida.push_str(&p.destino[ultimo..].replace("{{", "{").replace("}}", "}"));
            return Some(salida);
        }
    }
    None
}

/// Traduce un texto de Suaya al idioma actual (en español no cambia nada).
pub fn traducir(texto: &str) -> Cow<'_, str> {
    let d = match actual() {
        Idioma::En => Destino::En,
        Idioma::Pt => Destino::Pt,
        Idioma::Es => return Cow::Borrowed(texto),
    };
    if texto.is_empty() {
        return Cow::Borrowed(texto);
    }
    match traducir_con(d, texto, 0) {
        Some(t) => Cow::Owned(t),
        None => Cow::Borrowed(texto),
    }
}

/// Texto ya formateado en español, en el idioma actual (lo usa [`t!`](crate::t)
/// fuera del inglés, que tiene su propia plantilla).
pub fn en_idioma_actual(texto: String) -> String {
    if es_portugues() {
        traducir_con(Destino::Pt, &texto, 0).unwrap_or(texto)
    } else {
        texto
    }
}

/// Traduce sin depender del idioma actual (para pruebas y exportaciones).
pub fn al_ingles(texto: &str) -> Option<String> {
    traducir_en(texto, 0)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn plantillas() {
        let c = compilar(
            r#"
[[texto]]
es = "Servidores web"
en = "Web servers"
[[texto]]
es = "La rama {} de {} terminó el {fecha}."
en = "{1} branch {0} ended on {fecha}."
[[texto]]
es = "Capacidad: {capacidad}"
en = "Capability: {capacidad}"
"#,
        )
        .unwrap();
        assert_eq!(c.plantillas.len(), 2);
        assert!(validar_catalogo().unwrap() > 0);
    }

    #[test]
    fn portugues_con_respaldo_en_espanol() {
        con_idioma(Idioma::Pt, || {
            assert_eq!(tx("Prioridad", "Priority"), "Prioridade");
            assert_eq!(
                tx("Texto que no está en el catálogo", "x"),
                "Texto que no está en el catálogo"
            );
            assert_eq!(
                crate::t!(
                    "Prioridad {etiqueta} ({n})",
                    "{etiqueta} priority ({n})",
                    etiqueta = "alta",
                    n = 3
                ),
                "Prioridade alta (3)"
            );
            assert_eq!(traducir("Servidores web"), "Servidores web");
            assert_eq!(
                traducir("VPN y cifrado de red"),
                "VPN e criptografia de rede"
            );
        });
        assert_eq!(Idioma::interpretar("pt-BR"), Some(Idioma::Pt));
        assert_eq!(Idioma::Pt.codigo(), "pt");
    }

    #[test]
    fn marcadores_con_formato() {
        let m = marcadores("a {} b {x:?} c {{literal}} {:04}");
        let nombres: Vec<&str> = m.iter().map(|x| x.2.as_str()).collect();
        assert_eq!(nombres, ["0", "x", "1"]);
    }
}
