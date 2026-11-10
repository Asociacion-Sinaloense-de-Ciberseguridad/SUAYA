//! Inventario de bibliotecas y entornos criptográficos y su versión.
//!
//! Fuentes, de la más precisa a la menos:
//!
//! - **Binarios**: la cadena de versión que OpenSSL y LibreSSL incrustan
//!   («OpenSSL 3.0.13 30 Jan 2024») y la información de compilación de Go
//!   (versión del compilador y módulos, como `golang.org/x/crypto`).
//! - **Paquetes instalados**: `*.dist-info/METADATA` de Python, el archivo
//!   `release` de un JDK y los JAR de Bouncy Castle por su nombre.
//! - **Manifiestos y archivos de bloqueo**: `go.mod`, `Cargo.lock`,
//!   `requirements*.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock`,
//!   `package-lock.json`, `package.json`, `pom.xml`, `build.gradle`, `*.csproj`
//!   y `packages.config`.
//!
//! Solo se reportan las bibliotecas descritas en `conocimiento/bibliotecas.toml`.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use regex::Regex;
use regex::bytes::Regex as RegexBytes;
use suaya_core::{Activo, Conocimiento, Detalles, Garantia};

use crate::Escaner;
use crate::codigo::CAPACIDAD;
use crate::comun::{Archivo, linea_de};

/// Tamaño máximo de un binario que se revisa por su cadena de versión.
pub const MAXIMO_BINARIO: u64 = 512 * 1024 * 1024;

/// Un hallazgo antes de convertirse en activo.
struct Encontrada {
    ecosistema: &'static str,
    paquete: String,
    version: Option<String>,
    linea: Option<u32>,
    nota: Option<&'static str>,
}

fn re(p: &str) -> Regex {
    Regex::new(p).expect("expresión fija válida")
}

fn re_bytes(p: &str) -> RegexBytes {
    RegexBytes::new(p).expect("expresión fija válida")
}

/// ¿Es un ejecutable o biblioteca compartida (ELF, PE o Mach-O)?
pub fn es_binario(b: &[u8]) -> bool {
    b.starts_with(b"\x7fELF")
        || b.starts_with(b"MZ")
        || b.starts_with(&[0xCF, 0xFA, 0xED, 0xFE])
        || b.starts_with(&[0xCE, 0xFA, 0xED, 0xFE])
        || b.starts_with(&[0xFE, 0xED, 0xFA, 0xCF])
        || b.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE])
}

/// Nombre de una biblioteca criptográfica compartida (`libssl.so.3`,
/// `libcrypto-3-x64.dll`, `libssl.3.dylib`), que se revisa aunque sea grande.
pub fn es_biblioteca_compartida(nombre: &str) -> bool {
    let n = nombre.to_ascii_lowercase();
    (n.starts_with("libssl") || n.starts_with("libcrypto") || n.starts_with("liboqs"))
        && (n.contains(".so") || n.ends_with(".dll") || n.ends_with(".dylib"))
}

/// JAR de Bouncy Castle por su nombre (`bcprov-jdk18on-1.78.1.jar`).
pub fn jar_por_nombre(nombre: &str) -> Option<(String, String)> {
    static R: OnceLock<Regex> = OnceLock::new();
    let r = R.get_or_init(|| re(r"^(bcprov-jdk[0-9a-z]+)-([0-9][0-9.]*[0-9])\.jar$"));
    let c = r.captures(nombre)?;
    Some((c[1].to_string(), c[2].to_string()))
}

fn en_binario(b: &[u8]) -> Vec<Encontrada> {
    static OPENSSL: OnceLock<RegexBytes> = OnceLock::new();
    static LIBRESSL: OnceLock<RegexBytes> = OnceLock::new();
    static GO_VERSION: OnceLock<RegexBytes> = OnceLock::new();
    static GO_DEP: OnceLock<RegexBytes> = OnceLock::new();
    let mut v = Vec::new();
    let openssl = OPENSSL.get_or_init(|| {
        re_bytes(r"OpenSSL ([0-9]+\.[0-9]+\.[0-9]+[a-z]{0,2})(?:-[a-z]+)?\s+[0-9]{1,2} [A-Z][a-z]{2} [0-9]{4}")
    });
    // Un binario puede citar otras versiones (compatibilidad, mensajes): la
    // mayor es la de la biblioteca que trae.
    let mayor = openssl
        .captures_iter(b)
        .take(16)
        .map(|c| String::from_utf8_lossy(&c[1]).to_string())
        .max_by(|x, y| suaya_core::comparar_versiones(x, y).then_with(|| x.cmp(y)));
    if let Some(ver) = mayor {
        v.push(Encontrada {
            ecosistema: "binario",
            paquete: "openssl".into(),
            version: Some(ver),
            linea: None,
            nota: None,
        });
    }
    let libressl = LIBRESSL.get_or_init(|| re_bytes(r"LibreSSL ([0-9]+\.[0-9]+\.[0-9]+)"));
    if let Some(c) = libressl.captures(b) {
        v.push(Encontrada {
            ecosistema: "binario",
            paquete: "libressl".into(),
            version: Some(String::from_utf8_lossy(&c[1]).to_string()),
            linea: None,
            nota: None,
        });
    }
    // Información de compilación de Go (desde Go 1.18 incluye los módulos).
    if let Some(p) = b.windows(14).position(|w| w == b"\xff Go buildinf:") {
        let go = GO_VERSION.get_or_init(|| re_bytes(r"go(1\.[0-9]{1,3}(?:\.[0-9]{1,3})?)"));
        let ventana = &b[p..b.len().min(p + 4096)];
        let version = go
            .captures(ventana)
            .or_else(|| go.captures(b))
            .map(|c| String::from_utf8_lossy(&c[1]).to_string());
        v.push(Encontrada {
            ecosistema: "binario",
            paquete: "go".into(),
            version,
            linea: None,
            nota: None,
        });
        let dep = GO_DEP.get_or_init(|| re_bytes(r"dep\t([^\t\n]+)\t(v[^\t\n]+)"));
        for c in dep.captures_iter(b).take(500) {
            v.push(Encontrada {
                ecosistema: "golang",
                paquete: String::from_utf8_lossy(&c[1]).to_string(),
                version: Some(String::from_utf8_lossy(&c[2]).to_string()),
                linea: None,
                nota: None,
            });
        }
    }
    v
}

/// Pares `name = "..."` y `version = "..."` de un archivo de bloqueo TOML
/// (`Cargo.lock`, `poetry.lock`, `uv.lock`).
fn en_bloqueo_toml(texto: &str, ecosistema: &'static str, contenido: &[u8]) -> Vec<Encontrada> {
    let mut v = Vec::new();
    let mut nombre: Option<(String, usize)> = None;
    let mut desplazamiento = 0usize;
    for linea in texto.split_inclusive('\n') {
        let l = linea.trim();
        if l == "[[package]]" {
            nombre = None;
        } else if let Some(n) = l.strip_prefix("name = \"") {
            nombre = Some((n.trim_end_matches('"').to_string(), desplazamiento));
        } else if let Some(ver) = l.strip_prefix("version = \"")
            && let Some((n, d)) = nombre.take()
        {
            v.push(Encontrada {
                ecosistema,
                paquete: n,
                version: Some(ver.trim_end_matches('"').to_string()),
                linea: Some(linea_de(contenido, d)),
                nota: None,
            });
        }
        desplazamiento += linea.len();
    }
    v
}

fn en_manifiesto(a: &Archivo, texto: &str) -> Vec<Encontrada> {
    let n = a.nombre.as_str();
    let linea = |m: usize| Some(linea_de(a.contenido, m));
    let mut v = Vec::new();
    if n == "go.mod" {
        static TOOLCHAIN: OnceLock<Regex> = OnceLock::new();
        static GO: OnceLock<Regex> = OnceLock::new();
        static REQ: OnceLock<Regex> = OnceLock::new();
        let toolchain = TOOLCHAIN.get_or_init(|| re(r"(?m)^toolchain\s+go([0-9][0-9.]*)"));
        let go = GO.get_or_init(|| re(r"(?m)^go\s+([0-9][0-9.]*)"));
        if let Some(c) = toolchain.captures(texto) {
            v.push(Encontrada {
                ecosistema: "golang",
                paquete: "stdlib".into(),
                version: Some(c[1].to_string()),
                linea: linea(c.get(0).map_or(0, |m| m.start())),
                nota: None,
            });
        } else if let Some(c) = go.captures(texto) {
            v.push(Encontrada {
                ecosistema: "golang",
                paquete: "stdlib".into(),
                version: Some(c[1].to_string()),
                linea: linea(c.get(0).map_or(0, |m| m.start())),
                nota: Some(
                    "Versión mínima declarada en go.mod: la versión con la que se compila puede ser mayor.",
                ),
            });
        }
        let req = REQ.get_or_init(|| re(r"(?m)^(?:require\s+)?\s*([A-Za-z0-9][A-Za-z0-9._~/\-]*\.[A-Za-z0-9._~/\-]+)\s+(v[0-9][A-Za-z0-9.+\-]*)"));
        for c in req.captures_iter(texto) {
            v.push(Encontrada {
                ecosistema: "golang",
                paquete: c[1].to_string(),
                version: Some(c[2].to_string()),
                linea: linea(c.get(0).map_or(0, |m| m.start())),
                nota: None,
            });
        }
    } else if n == "cargo.lock" {
        v = en_bloqueo_toml(texto, "cargo", a.contenido);
    } else if n == "poetry.lock" || n == "uv.lock" {
        v = en_bloqueo_toml(texto, "pypi", a.contenido);
    } else if n.starts_with("requirements") && n.ends_with(".txt") {
        static R: OnceLock<Regex> = OnceLock::new();
        let r = R.get_or_init(|| {
            re(r"(?m)^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)(?:\[[^\]]*\])?\s*(?:(==|~=|>=|===)\s*([0-9][A-Za-z0-9.+\-]*))?")
        });
        for c in r.captures_iter(texto) {
            let exacta = matches!(c.get(2).map(|m| m.as_str()), Some("==") | Some("==="));
            v.push(Encontrada {
                ecosistema: "pypi",
                paquete: c[1].to_lowercase().replace('_', "-"),
                version: c.get(3).map(|m| m.as_str().to_string()),
                linea: linea(c.get(0).map_or(0, |m| m.start())),
                nota: (!exacta && c.get(3).is_some())
                    .then_some("Versión mínima declarada: la instalada puede ser mayor."),
            });
        }
    } else if n == "pipfile.lock" || n == "package-lock.json" || n == "package.json" {
        let Ok(j) = serde_json::from_str::<serde_json::Value>(texto) else {
            return v;
        };
        let mut agregar = |eco: &'static str, nombre: &str, ver: Option<String>, nota| {
            let pos = texto.find(&format!("\"{nombre}\"")).unwrap_or(0);
            v.push(Encontrada {
                ecosistema: eco,
                paquete: nombre.to_string(),
                version: ver,
                linea: linea(pos),
                nota,
            });
        };
        if n == "pipfile.lock" {
            for seccion in ["default", "develop"] {
                if let Some(o) = j[seccion].as_object() {
                    for (k, x) in o {
                        let ver = x["version"]
                            .as_str()
                            .map(|s| s.trim_start_matches("==").to_string());
                        agregar("pypi", &k.to_lowercase(), ver, None);
                    }
                }
            }
        } else if n == "package-lock.json" {
            if let Some(o) = j["packages"].as_object() {
                for (k, x) in o {
                    if let Some(nombre) = k.rsplit_once("node_modules/").map(|(_, n)| n) {
                        agregar(
                            "npm",
                            nombre,
                            x["version"].as_str().map(str::to_string),
                            None,
                        );
                    }
                }
            } else if let Some(o) = j["dependencies"].as_object() {
                for (k, x) in o {
                    agregar("npm", k, x["version"].as_str().map(str::to_string), None);
                }
            }
        } else {
            for seccion in ["dependencies", "devDependencies", "optionalDependencies"] {
                if let Some(o) = j[seccion].as_object() {
                    for (k, x) in o {
                        let ver = x.as_str().map(|s| {
                            s.trim_start_matches(['^', '~', '=', '>', '<', ' '])
                                .to_string()
                        });
                        agregar(
                            "npm",
                            k,
                            ver,
                            Some(
                                "Versión declarada en package.json (rango): la instalada puede ser mayor.",
                            ),
                        );
                    }
                }
            }
        }
    } else if n == "pom.xml" {
        static DEP: OnceLock<Regex> = OnceLock::new();
        static PROP: OnceLock<Regex> = OnceLock::new();
        let dep = DEP.get_or_init(|| {
            re(r"(?s)<dependency>\s*<groupId>\s*([^<\s]+)\s*</groupId>\s*<artifactId>\s*([^<\s]+)\s*</artifactId>\s*(?:<version>\s*([^<\s]+)\s*</version>)?")
        });
        let prop =
            PROP.get_or_init(|| re(r"<([A-Za-z0-9._\-]+)>\s*([^<\s]+)\s*</[A-Za-z0-9._\-]+>"));
        let propiedades: BTreeMap<String, String> = prop
            .captures_iter(texto)
            .map(|c| (c[1].to_string(), c[2].to_string()))
            .collect();
        for c in dep.captures_iter(texto) {
            let version = c.get(3).map(|m| {
                let t = m.as_str();
                t.strip_prefix("${")
                    .and_then(|x| x.strip_suffix('}'))
                    .and_then(|k| propiedades.get(k).cloned())
                    .unwrap_or_else(|| t.to_string())
            });
            v.push(Encontrada {
                ecosistema: "maven",
                paquete: format!("{}:{}", &c[1], &c[2]),
                version,
                linea: linea(c.get(0).map_or(0, |m| m.start())),
                nota: None,
            });
        }
    } else if n.starts_with("build.gradle") {
        static R: OnceLock<Regex> = OnceLock::new();
        let r = R.get_or_init(|| {
            re(r#"['"]([A-Za-z0-9._\-]+):([A-Za-z0-9._\-]+):([0-9][A-Za-z0-9._\-]*)['"]"#)
        });
        for c in r.captures_iter(texto) {
            v.push(Encontrada {
                ecosistema: "maven",
                paquete: format!("{}:{}", &c[1], &c[2]),
                version: Some(c[3].to_string()),
                linea: linea(c.get(0).map_or(0, |m| m.start())),
                nota: None,
            });
        }
    } else if n.ends_with(".csproj") || n == "packages.config" || n == "directory.packages.props" {
        static R: OnceLock<Regex> = OnceLock::new();
        let r = R.get_or_init(|| {
            re(r#"(?i)<Package(?:Reference|Version)?\s+(?:Include|id)="([^"]+)"\s+(?:Version|version)="([^"]+)""#)
        });
        for c in r.captures_iter(texto) {
            v.push(Encontrada {
                ecosistema: "nuget",
                paquete: c[1].to_string(),
                version: Some(c[2].to_string()),
                linea: linea(c.get(0).map_or(0, |m| m.start())),
                nota: None,
            });
        }
    } else if n == "metadata" && a.ruta.contains(".dist-info") {
        let campo = |k: &str| {
            texto
                .lines()
                .find_map(|l| l.strip_prefix(k))
                .map(|x| x.trim().to_string())
        };
        if let Some(nombre) = campo("Name:") {
            v.push(Encontrada {
                ecosistema: "pypi",
                paquete: nombre.to_lowercase().replace('_', "-"),
                version: campo("Version:"),
                linea: None,
                nota: None,
            });
        }
    } else if n == "info.plist" {
        // Paquete de aplicación de macOS (por ejemplo, un navegador).
        static ID: OnceLock<Regex> = OnceLock::new();
        static VER: OnceLock<Regex> = OnceLock::new();
        let id = ID
            .get_or_init(|| re(r"<key>CFBundleIdentifier</key>\s*<string>([^<]{1,200})</string>"));
        let ver = VER.get_or_init(|| {
            re(r"<key>CFBundleShortVersionString</key>\s*<string>([0-9][0-9.]{0,40})</string>")
        });
        if let Some(c) = id.captures(texto) {
            v.push(Encontrada {
                ecosistema: "aplicacion",
                paquete: c[1].trim().to_lowercase(),
                version: ver.captures(texto).map(|x| x[1].to_string()),
                linea: linea(c.get(0).map_or(0, |m| m.start())),
                nota: None,
            });
        }
    } else if n == "application.ini" {
        // Firefox y derivados: [App] Name=Firefox, Version=132.0.
        static R: OnceLock<Regex> = OnceLock::new();
        let r = R.get_or_init(|| re(r"(?m)^Name=([A-Za-z][A-Za-z0-9 ._-]{0,60})\s*$"));
        static V: OnceLock<Regex> = OnceLock::new();
        let ver = V.get_or_init(|| re(r"(?m)^Version=([0-9][0-9A-Za-z.]{0,40})\s*$"));
        if let Some(c) = r.captures(texto) {
            v.push(Encontrada {
                ecosistema: "aplicacion",
                paquete: c[1].trim().to_lowercase(),
                version: ver.captures(texto).map(|x| x[1].to_string()),
                linea: linea(c.get(0).map_or(0, |m| m.start())),
                nota: None,
            });
        }
    } else if n == "release" {
        static R: OnceLock<Regex> = OnceLock::new();
        let r = R.get_or_init(|| re(r#"(?m)^JAVA_VERSION="([0-9][0-9._]*)""#));
        if let Some(c) = r.captures(texto) {
            v.push(Encontrada {
                ecosistema: "runtime",
                paquete: "java".into(),
                version: Some(c[1].to_string()),
                linea: linea(c.get(0).map_or(0, |m| m.start())),
                nota: None,
            });
        }
    }
    v
}

/// Identificador de paquete (purl) cuando el ecosistema lo define.
fn purl(ecosistema: &str, paquete: &str, version: Option<&str>) -> Option<String> {
    let base = match ecosistema {
        "pypi" => format!("pkg:pypi/{paquete}"),
        "npm" => format!("pkg:npm/{}", paquete.replace('@', "%40")),
        "cargo" => format!("pkg:cargo/{paquete}"),
        "golang" if paquete != "stdlib" => format!("pkg:golang/{paquete}"),
        "nuget" => format!("pkg:nuget/{paquete}"),
        "maven" => {
            let (g, a) = paquete.split_once(':')?;
            format!("pkg:maven/{g}/{a}")
        }
        "binario" if paquete == "openssl" || paquete == "libressl" => {
            format!("pkg:generic/{paquete}")
        }
        _ => return None,
    };
    Some(match version {
        Some(v) => format!("{base}@{v}"),
        None => base,
    })
}

/// Fecha de hoy (AAAA-MM-DD), o la de `SUAYA_FECHA` para pruebas reproducibles.
pub fn hoy() -> String {
    std::env::var("SUAYA_FECHA")
        .ok()
        .filter(|f| f.len() == 10)
        .unwrap_or_else(|| {
            let d = time::OffsetDateTime::now_utc().date();
            format!("{:04}-{:02}-{:02}", d.year(), u8::from(d.month()), d.day())
        })
}

/// Convierte los hallazgos de un archivo en activos.
fn activos(encontradas: Vec<Encontrada>, a: &Archivo, c: &Conocimiento) -> Vec<Activo> {
    let fecha = hoy();
    let mut por_ref: BTreeMap<String, Activo> = BTreeMap::new();
    for e in encontradas {
        let Some(def) = c.por_paquete(e.ecosistema, &e.paquete) else {
            continue;
        };
        let version = e
            .version
            .as_deref()
            .map(|v| def.version_efectiva(v).to_string());
        let referencia = format!(
            "biblioteca:{}:{}",
            def.id,
            version.as_deref().unwrap_or("sin-version")
        );
        if let Some(previo) = por_ref.get_mut(&referencia) {
            previo.agregar_ubicacion(a.ruta, e.linea);
            continue;
        }
        let evaluacion = def.evaluar(version.as_deref(), &fecha);
        let nombre = match &version {
            Some(v) => format!("{} {v}", def.nombre),
            None => def.nombre.clone(),
        };
        let mut activo = Activo::nuevo(
            referencia.clone(),
            nombre,
            Detalles::Biblioteca {
                biblioteca_id: def.id.clone(),
                version: version.clone(),
                purl: purl(e.ecosistema, &e.paquete, e.version.as_deref()),
            },
        )
        .con_contexto(
            def.capacidad.as_deref().unwrap_or(CAPACIDAD),
            Garantia::Confidencialidad,
        )
        .con_ubicacion(a.ruta, e.linea);
        activo.riesgo_fijado = Some(evaluacion.riesgo);
        for adv in evaluacion.advertencias {
            activo.advertir(adv);
        }
        if let Some(n) = e.nota {
            activo.advertir(n);
        }
        por_ref.insert(referencia, activo);
    }
    por_ref.into_values().collect()
}

/// Analiza un archivo grande sin pasar por los demás escáneres: bibliotecas
/// compartidas y binarios (con `--binarios`) por su cadena de versión, y los
/// JAR por su nombre, sin leerlos.
pub fn analizar_grande(a: &Archivo, c: &Conocimiento) -> Vec<Activo> {
    let mut e = Vec::new();
    if let Some((artefacto, version)) = jar_por_nombre(&a.nombre) {
        e.push(Encontrada {
            ecosistema: "jar",
            paquete: artefacto,
            version: Some(version),
            linea: None,
            nota: None,
        });
    } else if es_binario(a.contenido) {
        e = en_binario(a.contenido);
    }
    activos(e, a, c)
}

/// Analiza un binario grande por partes, sin cargarlo entero en memoria: se
/// lee en bloques con un solapamiento suficiente para no partir una cadena
/// de versión ni la información de compilación de Go.
pub fn binario_por_partes(
    mut lector: impl std::io::Read,
    a: &Archivo,
    c: &Conocimiento,
) -> std::io::Result<Vec<Activo>> {
    const BLOQUE: usize = 8 * 1024 * 1024;
    const SOLAPE: usize = 64 * 1024;
    let mut bufer: Vec<u8> = Vec::with_capacity(BLOQUE + SOLAPE);
    let mut bloque = vec![0u8; BLOQUE];
    let mut primero = true;
    let mut total = 0u64;
    let mut encontradas: Vec<Encontrada> = Vec::new();
    loop {
        let mut llenos = 0;
        while llenos < BLOQUE {
            let n = lector.read(&mut bloque[llenos..])?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > MAXIMO_BINARIO {
                return Err(std::io::Error::other("binario excede límite de lectura"));
            }
            llenos += n;
        }
        if llenos == 0 {
            break;
        }
        bufer.extend_from_slice(&bloque[..llenos]);
        if primero && !es_binario(&bufer) {
            return Ok(Vec::new());
        }
        primero = false;
        encontradas.extend(en_binario(&bufer));
        let corte = bufer.len().saturating_sub(SOLAPE);
        bufer.drain(..corte);
        if llenos < BLOQUE {
            break;
        }
    }
    // OpenSSL: la mayor versión vista; Go: la primera con versión.
    let mayor = encontradas
        .iter()
        .filter(|e| e.paquete == "openssl" && e.ecosistema == "binario")
        .filter_map(|e| e.version.clone())
        .max_by(|x, y| suaya_core::comparar_versiones(x, y).then_with(|| x.cmp(y)));
    let mut go_visto = false;
    encontradas.retain(|e| match (e.ecosistema, e.paquete.as_str()) {
        ("binario", "openssl") => e.version == mayor,
        ("binario", "go") => {
            let primero = !go_visto && e.version.is_some();
            go_visto |= primero;
            primero
        }
        _ => true,
    });
    Ok(activos(encontradas, a, c))
}

pub struct EscanerBibliotecas;

const MANIFIESTOS: [&str; 10] = [
    "go.mod",
    "cargo.lock",
    "poetry.lock",
    "uv.lock",
    "pipfile.lock",
    "package-lock.json",
    "package.json",
    "pom.xml",
    "packages.config",
    "directory.packages.props",
];

impl Escaner for EscanerBibliotecas {
    fn nombre(&self) -> &'static str {
        "bibliotecas criptográficas"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        let n = a.nombre.as_str();
        MANIFIESTOS.contains(&n)
            || (n.starts_with("requirements") && n.ends_with(".txt"))
            || n.starts_with("build.gradle")
            || n.ends_with(".csproj")
            || (n == "metadata" && a.ruta.contains(".dist-info"))
            || (n == "release" && a.contiene(b"JAVA_VERSION="))
            || (n == "info.plist" && a.contiene(b"CFBundleIdentifier"))
            || (n == "application.ini" && a.contiene(b"[App]"))
            || jar_por_nombre(n).is_some()
            || es_binario(a.contenido)
    }

    fn analizar(&self, a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
        if jar_por_nombre(&a.nombre).is_some() || es_binario(a.contenido) {
            return Ok(analizar_grande(a, c));
        }
        let texto = a.texto().ok_or("el archivo no es texto UTF-8")?;
        Ok(activos(en_manifiesto(a, texto), a, c))
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn nombres_de_jar_y_bibliotecas() {
        assert_eq!(
            jar_por_nombre("bcprov-jdk18on-1.78.1.jar"),
            Some(("bcprov-jdk18on".into(), "1.78.1".into()))
        );
        assert!(jar_por_nombre("otro-1.0.jar").is_none());
        assert!(es_biblioteca_compartida("libcrypto.so.3"));
        assert!(es_biblioteca_compartida("libssl-3-x64.dll"));
        assert!(!es_biblioteca_compartida("libz.so.1"));
    }

    #[test]
    fn navegadores_por_info_plist_y_application_ini() {
        let c = Conocimiento::embebido();
        let plist = b"<plist><dict><key>CFBundleIdentifier</key><string>com.google.Chrome</string>\n<key>CFBundleShortVersionString</key><string>120.0.6099.109</string></dict></plist>";
        let a = Archivo::nuevo(
            "Chrome.app/Contents/Info.plist",
            std::path::Path::new("Info.plist"),
            plist,
            None,
        );
        let v = EscanerBibliotecas.analizar(&a, &c).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].contextos[0].capacidad, "navegadores-web");
        assert_eq!(
            v[0].riesgo_fijado,
            Some(suaya_core::Riesgo::VulnerableCuantico)
        );
        let ini = b"[App]\nVendor=Mozilla\nName=Firefox\nVersion=133.0.3\n";
        let a = Archivo::nuevo(
            "firefox/application.ini",
            std::path::Path::new("application.ini"),
            ini,
            None,
        );
        assert!(EscanerBibliotecas.aplica(&a));
        let v = EscanerBibliotecas.analizar(&a, &c).unwrap();
        assert_eq!(v[0].riesgo_fijado, Some(suaya_core::Riesgo::HibridoPq));
    }

    #[test]
    fn cadenas_en_binarios() {
        let mut b = b"\x7fELF\x02\x01".to_vec();
        b.extend_from_slice(b"\0junk\0OpenSSL 1.1.1w  11 Sep 2023\0more\0");
        let e = en_binario(&b);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].version.as_deref(), Some("1.1.1w"));

        let mut g = b"\x7fELF".to_vec();
        g.extend_from_slice(b"\xff Go buildinf:\x08\x02\x00\x00go1.22.5\0path\tejemplo\nmod\tejemplo\t(devel)\t\ndep\tgolang.org/x/crypto\tv0.21.0\th1:abc=\n");
        let e = en_binario(&g);
        assert!(
            e.iter()
                .any(|x| x.paquete == "go" && x.version.as_deref() == Some("1.22.5"))
        );
        assert!(e.iter().any(|x| x.paquete == "golang.org/x/crypto"));
    }
}
