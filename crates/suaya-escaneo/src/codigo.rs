//! Escáner de uso criptográfico en código fuente.
//!
//! Cada archivo pasa primero por un analizador léxico de su lenguaje que
//! sustituye los comentarios por espacios (conserva los saltos de línea y las
//! cadenas), de modo que un algoritmo mencionado en un comentario no cuente
//! como uso. Después se aplican las reglas de `conocimiento/codigo.toml`.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, OnceLock};

use regex::Regex;
use suaya_core::{Activo, Conocimiento, Detalles, Garantia, Riesgo};

use crate::Escaner;
use crate::comun::{Archivo, activo_algoritmo, id_corto, linea_de};

/// Decisión de Suaya (ver madurez.toml): capacidad del código de aplicaciones.
pub const CAPACIDAD: &str = "codigo-aplicacion";
/// Ubicaciones que se registran por algoritmo y archivo.
const MAXIMO_UBICACIONES: usize = 50;

/// Lenguaje de un archivo según su nombre o extensión.
pub fn lenguaje(nombre: &str) -> Option<&'static str> {
    let nombre = nombre.to_ascii_lowercase();
    if matches!(
        nombre.as_str(),
        "dockerfile" | "containerfile" | "makefile" | "gnumakefile" | "jenkinsfile"
    ) || nombre.starts_with("dockerfile.")
        || nombre.starts_with("containerfile.")
    {
        return Some("shell");
    }
    let ext = nombre.rsplit_once('.')?.1;
    Some(match ext {
        "py" | "pyw" => "python",
        "java" | "kt" | "kts" | "scala" | "groovy" => "java",
        "go" => "go",
        "js" | "mjs" | "cjs" | "jsx" | "ts" | "tsx" | "mts" | "cts" => "javascript",
        "cs" => "csharp",
        "rs" => "rust",
        "c" | "h" | "cc" | "cpp" | "cxx" | "hpp" | "hh" | "hxx" | "m" | "mm" => "c",
        "php" | "phtml" => "php",
        "rb" | "rake" | "gemspec" => "ruby",
        "swift" => "swift",
        "dart" => "dart",
        "ps1" | "psm1" => "powershell",
        "sh" | "bash" | "zsh" | "ksh" | "mk" | "yml" | "yaml" => "shell",
        _ => return None,
    })
}

/// Sustituye los comentarios por espacios sin mover el resto del texto.
pub fn sin_comentarios(texto: &str, lenguaje: &str) -> String {
    let b = texto.as_bytes();
    let mut s = b.to_vec();
    let n = b.len();
    let mut i = 0usize;
    let borrar = |s: &mut Vec<u8>, desde: usize, hasta: usize| {
        for x in &mut s[desde..hasta.min(n)] {
            if *x != b'\n' {
                *x = b' ';
            }
        }
    };
    // Avanza sobre una cadena que termina con `fin`, respetando «\».
    let cadena = |i: usize, fin: &[u8], escapes: bool| -> usize {
        let mut j = i;
        while j < n {
            if escapes && b[j] == b'\\' {
                j += 2;
                continue;
            }
            if b[j..].starts_with(fin) {
                return j + fin.len();
            }
            j += 1;
        }
        n
    };
    let fin_de_linea = |i: usize| b[i..].iter().position(|&x| x == b'\n').map_or(n, |p| i + p);
    // Comentario con «#»: Python, Ruby, PHP, PowerShell y shell.
    let almohadilla = matches!(lenguaje, "python" | "ruby" | "php" | "powershell" | "shell");
    // Comentarios «//» y «/* */».
    let estilo_c = matches!(
        lenguaje,
        "java" | "go" | "javascript" | "csharp" | "rust" | "c" | "swift" | "dart" | "php"
    );
    // Lenguajes donde la comilla simple delimita cadenas (no caracteres).
    let comilla_simple = matches!(
        lenguaje,
        "javascript" | "python" | "php" | "ruby" | "dart" | "powershell" | "shell"
    );
    // En shell y PowerShell «#» solo comenta al inicio de una palabra.
    let inicio_de_palabra =
        |i: usize| i == 0 || matches!(b[i - 1], b' ' | b'\t' | b'\n' | b'\r' | b';');
    while i < n {
        let c = b[i];
        if lenguaje == "python" && (b[i..].starts_with(b"\"\"\"") || b[i..].starts_with(b"\'\'\'"))
        {
            let q = &b[i..i + 3];
            i = cadena(i + 3, q, true);
        } else if lenguaje == "ruby"
            && (i == 0 || b[i - 1] == b'\n')
            && b[i..].starts_with(b"=begin")
        {
            let fin = b[i..]
                .windows(5)
                .position(|w| w == b"\n=end")
                .map_or(n, |p| fin_de_linea(i + p + 1));
            borrar(&mut s, i, fin);
            i = fin;
        } else if lenguaje == "powershell" && b[i..].starts_with(b"<#") {
            let fin = b[i + 2..]
                .windows(2)
                .position(|w| w == b"#>")
                .map_or(n, |p| i + 2 + p + 2);
            borrar(&mut s, i, fin);
            i = fin;
        } else if (almohadilla
            && c == b'#'
            && !(lenguaje == "php" && b.get(i + 1) == Some(&b'['))
            && (!matches!(lenguaje, "shell" | "powershell") || inicio_de_palabra(i)))
            || (estilo_c && b[i..].starts_with(b"//"))
        {
            let fin = fin_de_linea(i);
            borrar(&mut s, i, fin);
            i = fin;
        } else if estilo_c && b[i..].starts_with(b"/*") {
            let fin = b[i + 2..]
                .windows(2)
                .position(|w| w == b"*/")
                .map_or(n, |p| i + 2 + p + 2);
            borrar(&mut s, i, fin);
            i = fin;
        } else if lenguaje == "rust"
            && c == b'r'
            && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_'))
            && matches!(b.get(i + 1), Some(b'"') | Some(b'#'))
        {
            // Cadena cruda r"..." o r#"..."#.
            let almohadillas = b[i + 1..].iter().take_while(|&&x| x == b'#').count();
            if b.get(i + 1 + almohadillas) == Some(&b'"') {
                let mut fin = vec![b'"'];
                fin.extend(std::iter::repeat_n(b'#', almohadillas));
                i = cadena(i + 2 + almohadillas, &fin, false);
            } else {
                i += 1;
            }
        } else if lenguaje == "csharp" && c == b'@' && b.get(i + 1) == Some(&b'"') {
            // Cadena literal de C#: "" escapa la comilla.
            let mut j = i + 2;
            while j < n {
                if b[j] == b'"' {
                    if b.get(j + 1) == Some(&b'"') {
                        j += 2;
                        continue;
                    }
                    break;
                }
                j += 1;
            }
            i = j + 1;
        } else if c == b'"' {
            i = cadena(i + 1, b"\"", true);
        } else if c == b'`' && (lenguaje == "javascript" || lenguaje == "go") {
            i = cadena(i + 1, b"`", lenguaje == "javascript");
        } else if c == b'\'' {
            if comilla_simple {
                // En shell y PowerShell la comilla simple no admite escapes.
                i = cadena(i + 1, b"'", !matches!(lenguaje, "shell" | "powershell"));
            } else {
                // Carácter literal ('x', '\n') o, en Rust, un tiempo de vida.
                let largo = if b.get(i + 1) == Some(&b'\\') {
                    b[i + 2..]
                        .iter()
                        .take(10)
                        .position(|&x| x == b'\'')
                        .map(|p| p + 3)
                } else {
                    let ch = texto[i + 1..].chars().next().map_or(1, char::len_utf8);
                    (b.get(i + 1 + ch) == Some(&b'\'')).then_some(ch + 2)
                };
                i += largo.unwrap_or(1);
            }
        } else {
            i += 1;
        }
    }
    String::from_utf8(s).unwrap_or_else(|_| texto.to_string())
}

/// Normaliza un nombre capturado: minúsculas y «_» o «.» como «-».
fn normalizar(t: &str) -> String {
    t.trim().to_lowercase().replace(['_', '.'], "-")
}

struct Regla {
    lenguajes: Vec<String>,
    patron: Regex,
    requiere: Option<Regex>,
    algoritmo: Option<String>,
    espacio: Option<String>,
    captura: usize,
    formato: Option<String>,
    tamano: Option<usize>,
    ignorar: Vec<String>,
    nota: Option<String>,
    capacidad: Option<String>,
}

struct Hallazgo {
    lenguajes: Vec<String>,
    patron: Regex,
    requiere: Option<Regex>,
    riesgo: Riesgo,
    advertencia: String,
}

struct Compiladas {
    reglas: Vec<Regla>,
    hallazgos: Vec<Hallazgo>,
}

fn compilar(c: &Conocimiento) -> Result<Compiladas, String> {
    let re =
        |p: &str| Regex::new(p).map_err(|e| format!("codigo.toml: patrón inválido «{p}»: {e}"));
    let opcional = |p: &Option<String>| p.as_deref().map(re).transpose();
    let mut reglas = Vec::new();
    for r in &c.codigo.reglas {
        reglas.push(Regla {
            lenguajes: r.lenguajes.clone(),
            patron: re(&r.patron)?,
            requiere: opcional(&r.requiere)?,
            algoritmo: r.algoritmo.clone(),
            espacio: r.espacio.clone(),
            captura: r.captura.unwrap_or(1),
            formato: r.formato.clone(),
            tamano: r.tamano,
            ignorar: r.ignorar.iter().map(|x| normalizar(x)).collect(),
            nota: r.nota.clone(),
            capacidad: r.capacidad.clone(),
        });
    }
    let mut hallazgos = Vec::new();
    for h in &c.codigo.hallazgos {
        hallazgos.push(Hallazgo {
            lenguajes: h.lenguajes.clone(),
            patron: re(&h.patron)?,
            requiere: opcional(&h.requiere)?,
            riesgo: h.riesgo,
            advertencia: h.advertencia.clone(),
        });
    }
    Ok(Compiladas { reglas, hallazgos })
}

/// Reglas compiladas, compartidas entre escaneos con la misma base: compilar
/// las expresiones cuesta más que aplicarlas a un archivo típico.
fn compiladas_para(c: &Conocimiento) -> Result<Arc<Compiladas>, String> {
    static CACHE: OnceLock<Mutex<HashMap<String, Arc<Compiladas>>>> = OnceLock::new();
    let mut clave = String::new();
    for r in &c.codigo.reglas {
        clave.push_str(&r.patron);
        clave.push('\u{1}');
        clave.push_str(r.requiere.as_deref().unwrap_or(""));
        clave.push('\u{2}');
    }
    for h in &c.codigo.hallazgos {
        clave.push_str(&h.patron);
        clave.push('\u{3}');
    }
    let clave = crate::comun::huella_sha256(clave.as_bytes());
    let cache = CACHE.get_or_init(Default::default);
    if let Some(x) = cache.lock().ok().and_then(|m| m.get(&clave).cloned()) {
        return Ok(x);
    }
    let nuevas = Arc::new(compilar(c)?);
    if let Ok(mut m) = cache.lock() {
        m.insert(clave, nuevas.clone());
    }
    Ok(nuevas)
}

/// Compila las reglas de una base de conocimiento (lo usan las pruebas).
pub fn validar_reglas(c: &Conocimiento) -> Result<(), String> {
    compilar(c).map(|_| ())
}

#[derive(Default)]
pub struct EscanerCodigo {
    compiladas: OnceLock<Result<Arc<Compiladas>, String>>,
}

impl EscanerCodigo {
    /// Busca el id del algoritmo para lo capturado.
    fn resolver<'a>(
        c: &'a Conocimiento,
        espacio: &str,
        nombre: &str,
    ) -> Option<&'a suaya_core::AlgoritmoDef> {
        let candidatos: Vec<String> = if espacio == "java-cifrado" {
            let partes: Vec<&str> = nombre.split('/').collect();
            let mut v = vec![nombre.to_string()];
            if partes.len() > 2 {
                v.push(partes[..2].join("/"));
            }
            if partes.len() > 1 {
                v.push(partes[0].to_string());
            }
            v
        } else {
            vec![nombre.to_string()]
        };
        candidatos
            .iter()
            .find_map(|n| c.codigo.traducir(espacio, n))
            .and_then(|id| c.por_id(id))
    }
}

impl Escaner for EscanerCodigo {
    fn nombre(&self) -> &'static str {
        "uso criptográfico en código fuente"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        lenguaje(&a.nombre).is_some()
    }

    fn analizar(&self, a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
        let compiladas = self
            .compiladas
            .get_or_init(|| compiladas_para(c))
            .as_ref()
            .map_err(Clone::clone)?;
        let lenguaje = lenguaje(&a.nombre).ok_or("lenguaje no reconocido")?;
        let Some(texto) = a.texto() else {
            return Ok(Vec::new());
        };
        let limpio = sin_comentarios(texto, lenguaje);
        let aplica = |lenguajes: &[String], requiere: &Option<Regex>| {
            lenguajes.iter().any(|l| l == lenguaje)
                && requiere.as_ref().is_none_or(|r| r.is_match(&limpio))
        };

        let mut por_referencia: BTreeMap<String, Activo> = BTreeMap::new();
        for r in compiladas
            .reglas
            .iter()
            .filter(|r| aplica(&r.lenguajes, &r.requiere))
        {
            for m in r.patron.captures_iter(&limpio) {
                let inicio = m.get(0).map_or(0, |x| x.start());
                let linea = linea_de(a.contenido, inicio);
                let tamano = r
                    .tamano
                    .and_then(|g| m.get(g))
                    .and_then(|x| x.as_str().parse::<u32>().ok());
                let (def, respaldo) = match (&r.algoritmo, &r.espacio) {
                    (Some(id), _) => (c.por_id(id), id.clone()),
                    (None, Some(espacio)) => {
                        let Some(capturado) = m.get(r.captura) else {
                            continue;
                        };
                        let crudo = match &r.formato {
                            Some(f) => {
                                let mut t = f.clone();
                                for i in 1..m.len() {
                                    t = t.replace(
                                        &format!("{{{i}}}"),
                                        m.get(i).map_or("", |x| x.as_str()),
                                    );
                                }
                                t
                            }
                            None => capturado.as_str().to_string(),
                        };
                        let nombre = normalizar(&crudo);
                        if r.ignorar.contains(&nombre) {
                            continue;
                        }
                        (Self::resolver(c, espacio, &nombre), crudo)
                    }
                    (None, None) => continue,
                };
                let capacidad = r.capacidad.as_deref().unwrap_or(CAPACIDAD);
                let mut activo =
                    activo_algoritmo(def, &respaldo, tamano, capacidad, None, a.ruta, Some(linea));
                if let Some(n) = &r.nota {
                    activo.advertir(n.clone());
                }
                match por_referencia.get_mut(&activo.referencia) {
                    Some(previo) => {
                        for ctx in &activo.contextos {
                            previo.agregar_contexto(&ctx.capacidad, ctx.garantia);
                        }
                        if previo.ubicaciones.len() < MAXIMO_UBICACIONES
                            && !previo.ubicaciones.iter().any(|u| u.linea == Some(linea))
                        {
                            previo.ubicaciones.extend(activo.ubicaciones);
                        }
                    }
                    None => {
                        por_referencia.insert(activo.referencia.clone(), activo);
                    }
                }
            }
        }

        // Un genérico (RSA sin tamaño, «AES», curva no determinada) sobra si
        // el mismo archivo ya fija la variante.
        let referencias: Vec<String> = por_referencia.keys().cloned().collect();
        for (generico, prefijo) in [
            ("algoritmo:rsa", "algoritmo:rsa-"),
            ("algoritmo:ec", "algoritmo:ec-"),
            ("algoritmo:ecdh", "algoritmo:ecdh-"),
            ("algoritmo:aes", "algoritmo:aes-"),
        ] {
            if referencias.iter().any(|r| r.starts_with(prefijo)) {
                por_referencia.remove(generico);
            }
        }
        let mut activos: Vec<Activo> = por_referencia.into_values().collect();

        // Usos inseguros de TLS: un activo de protocolo por archivo.
        let mut avisos: Vec<(Riesgo, String, u32)> = Vec::new();
        for h in compiladas
            .hallazgos
            .iter()
            .filter(|h| aplica(&h.lenguajes, &h.requiere))
        {
            for m in h.patron.find_iter(&limpio).take(MAXIMO_UBICACIONES) {
                avisos.push((
                    h.riesgo,
                    h.advertencia.clone(),
                    linea_de(a.contenido, m.start()),
                ));
            }
        }
        if !avisos.is_empty() {
            let mut p = Activo::nuevo(
                format!("protocolo:tls:codigo:{}", id_corto(&a.ruta_estable)),
                format!("TLS en código ({})", a.nombre),
                Detalles::Protocolo {
                    tipo_protocolo: "tls".into(),
                    versiones: Vec::new(),
                    grupos: Vec::new(),
                    cifrados: Vec::new(),
                },
            )
            .con_contexto(CAPACIDAD, Garantia::Autenticacion);
            let mut lineas: Vec<u32> = avisos.iter().map(|(_, _, l)| *l).collect();
            lineas.sort_unstable();
            lineas.dedup();
            for l in &lineas {
                p = p.con_ubicacion(a.ruta, Some(*l));
            }
            let mut textos: BTreeMap<String, Vec<u32>> = BTreeMap::new();
            for (_, t, l) in &avisos {
                textos.entry(t.clone()).or_default().push(*l);
            }
            for (t, ls) in textos {
                let ls: Vec<String> = ls.iter().map(u32::to_string).collect();
                p.advertir(format!("{t} [línea {}]", ls.join(", ")));
            }
            p.riesgo_fijado = avisos
                .iter()
                .map(|(r, _, _)| *r)
                .min_by_key(|r| r.gravedad());
            activos.push(p);
        }
        Ok(activos)
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn comentarios_fuera_cadenas_dentro() {
        let t = "x = hashlib.md5()  # hashlib.sha1()\ny = \"# no es comentario\"\n";
        let l = sin_comentarios(t, "python");
        assert!(l.contains("hashlib.md5()") && !l.contains("sha1"));
        assert!(l.contains("# no es comentario"));
        assert_eq!(l.len(), t.len());

        let t = "// MessageDigest.getInstance(\"MD5\")\nString s = \"// sigue\"; /* SHA1\n */ char c = '\"';\nMessageDigest.getInstance(\"SHA-256\");";
        let l = sin_comentarios(t, "java");
        assert!(!l.contains("MD5") && !l.contains("SHA1"));
        assert!(l.contains("\"// sigue\"") && l.contains("SHA-256"));
        assert_eq!(l.lines().count(), t.lines().count());

        let t = "let r = r#\"// no\"#; // sí\nfn f<'a>(x: &'a str) {} // md5";
        let l = sin_comentarios(t, "rust");
        assert!(l.contains("// no") && !l.contains("sí") && !l.contains("md5"));

        let t = "openssl genrsa 2048 # openssl genrsa 1024\necho a#b\nRUN echo '# no'";
        let l = sin_comentarios(t, "shell");
        assert!(l.contains("genrsa 2048") && !l.contains("1024"));
        assert!(l.contains("a#b") && l.contains("'# no'"));

        let t = "<# MD5 #>\n$h = [System.Security.Cryptography.SHA256]::Create() # SHA1";
        let l = sin_comentarios(t, "powershell");
        assert!(!l.contains("MD5") && l.contains("SHA256") && !l.contains("SHA1"));

        let t = "=begin\nDigest::MD5\n=end\nDigest::SHA256 # Digest::SHA1";
        let l = sin_comentarios(t, "ruby");
        assert!(!l.contains("MD5") && l.contains("SHA256") && !l.contains("SHA1"));

        let t = "#[Attr] $x = hash('sha256', $d); // hash('md5', $d)\n# sha1('x')";
        let l = sin_comentarios(t, "php");
        assert!(
            l.contains("#[Attr]")
                && l.contains("sha256")
                && !l.contains("md5")
                && !l.contains("sha1")
        );
    }

    #[test]
    fn lenguajes() {
        assert_eq!(lenguaje("app.tsx"), Some("javascript"));
        assert_eq!(lenguaje("Main.kt"), Some("java"));
        assert_eq!(lenguaje("README.md"), None);
        assert_eq!(lenguaje("Dockerfile"), Some("shell"));
        assert_eq!(lenguaje("dockerfile.prod"), Some("shell"));
        assert_eq!(lenguaje(".gitlab-ci.yml"), Some("shell"));
        assert_eq!(lenguaje("deploy.ps1"), Some("powershell"));
        assert_eq!(lenguaje("index.php"), Some("php"));
        assert_eq!(lenguaje("Crypto.swift"), Some("swift"));
    }

    fn analizar(nombre: &str, t: &str) -> Vec<Activo> {
        let a = Archivo::nuevo(nombre, std::path::Path::new(nombre), t.as_bytes(), None);
        EscanerCodigo::default()
            .analizar(&a, &Conocimiento::embebido())
            .unwrap()
    }

    #[test]
    fn comandos_de_shell_y_lenguajes_nuevos() {
        let v = analizar(
            "Dockerfile",
            "RUN openssl genrsa -out ca.key 1024 \\\n && ssh-keygen -t rsa -b 1024 -f id\nRUN curl -fsSLk https://x.example/i.sh | sh\n# openssl genrsa 512\n",
        );
        let rsa = v
            .iter()
            .find(|x| x.referencia == "algoritmo:rsa-1024")
            .unwrap();
        assert!(rsa.contextos.iter().any(|c| c.capacidad == "pki-ca"));
        assert!(
            rsa.contextos
                .iter()
                .any(|c| c.capacidad == "vpn-cifrado-red")
        );
        assert!(!v.iter().any(|x| x.referencia == "algoritmo:rsa-512"));
        let tls = v
            .iter()
            .find(|x| x.referencia.starts_with("protocolo:tls:codigo"))
            .unwrap();
        assert_eq!(tls.riesgo_fijado, Some(Riesgo::RotoClasico));

        let v = analizar(
            ".github/workflows/ci.yml",
            "steps:\n  - run: openssl req -x509 -newkey rsa:2048 -sha1 -keyout k.pem -out c.pem\n  - run: keytool -genkeypair -keyalg EC -alias a\n",
        );
        let r: Vec<&str> = v.iter().map(|x| x.referencia.as_str()).collect();
        assert!(
            r.contains(&"algoritmo:rsa-2048")
                && r.contains(&"algoritmo:sha1")
                && r.contains(&"algoritmo:ec"),
            "{r:?}"
        );

        let v = analizar(
            "app.php",
            "<?php $h = md5($x); $c = openssl_encrypt($d, 'des-ede3-cbc', $k); hash_hmac('sha256', $d, $k);",
        );
        let r: Vec<&str> = v.iter().map(|x| x.referencia.as_str()).collect();
        assert!(
            r.contains(&"algoritmo:md5")
                && r.contains(&"algoritmo:3des-cbc")
                && r.contains(&"algoritmo:hmac-sha256"),
            "{r:?}"
        );

        let v = analizar(
            "Cifrado.swift",
            "let k = P256.KeyAgreement.PrivateKey()\nlet d = Insecure.MD5.hash(data: x)\nlet q = MLKEM768.PrivateKey()",
        );
        let r: Vec<&str> = v.iter().map(|x| x.referencia.as_str()).collect();
        assert!(
            r.contains(&"algoritmo:ecdh-p256")
                && r.contains(&"algoritmo:md5")
                && r.contains(&"algoritmo:ml-kem-768"),
            "{r:?}"
        );

        let v = analizar(
            "despliegue.ps1",
            "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls\nNew-SelfSignedCertificate -DnsName x -KeyAlgorithm RSA -KeyLength 1024 -HashAlgorithm SHA1",
        );
        let r: Vec<&str> = v.iter().map(|x| x.referencia.as_str()).collect();
        assert!(
            r.contains(&"algoritmo:tls-1.0")
                && r.contains(&"algoritmo:rsa-1024")
                && r.contains(&"algoritmo:sha1"),
            "{r:?}"
        );
    }

    #[test]
    fn reglas_validas() {
        validar_reglas(&Conocimiento::embebido()).unwrap();
    }
}
