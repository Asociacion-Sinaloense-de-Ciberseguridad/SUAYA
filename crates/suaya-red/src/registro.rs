//! Imágenes de contenedor desde un registro OCI (API de distribución v2).
//!
//! Suaya descarga solo la imagen que el usuario nombra (`docker://`), capa
//! por capa, y la analiza en flujo con [`AnalizadorImagen`]: nada se escribe
//! a disco. Cada manifiesto y cada capa se verifican contra su resumen
//! SHA-256 antes de aceptar sus hallazgos.
//!
//! Autenticación, en este orden:
//!
//! 1. Variables `SUAYA_REGISTRO_USUARIO` y `SUAYA_REGISTRO_CLAVE`.
//! 2. `~/.docker/config.json` (o `$DOCKER_CONFIG/config.json`): `credHelpers`,
//!    `auths` y `credsStore`, igual que Docker.
//! 3. Acceso anónimo.
//!
//! Con el desafío `Bearer` del registro se obtiene un token de solo lectura
//! (`pull`). Las credenciales nunca se envían por HTTP sin cifrar (salvo a
//! `localhost`) ni a otro servidor tras una redirección, y nunca se escriben
//! en el inventario.

use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

use base64::Engine;
use sha2::{Digest, Sha256};
use suaya_core::Conocimiento;
use suaya_escaneo::{AnalizadorImagen, Escaner, Opciones as OpcionesEscaneo, Resultado};

use crate::http::{self, ConfianzaTls, Credenciales, RespuestaFlujo, Servidor};

/// Tope de un manifiesto o índice.
const MAXIMO_MANIFIESTO: usize = 4 * 1024 * 1024;
/// Tope de la suma de capas comprimidas que declara un manifiesto.
const MAXIMO_IMAGEN: u64 = 64 * 1024 * 1024 * 1024;
const MAXIMO_CAPAS: usize = 1000;
const MAXIMO_REDIRECCIONES: usize = 5;

const ACEPTAR_MANIFIESTO: &str = "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json";

/// Referencia a una imagen: `[registro/]repositorio[:etiqueta][@sha256:...]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Referencia {
    /// Registro tal como se escribe (`ghcr.io`, `localhost:5000`, `docker.io`).
    pub registro: String,
    pub repositorio: String,
    pub etiqueta: Option<String>,
    pub resumen: Option<String>,
}

fn es_local(host: &str) -> bool {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    h.eq_ignore_ascii_case("localhost")
        || h.parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

impl Referencia {
    /// Interpreta la referencia con las mismas reglas que Docker.
    pub fn interpretar(texto: &str) -> Result<Self, String> {
        let texto = texto.strip_prefix("docker://").unwrap_or(texto).trim();
        if texto.is_empty() || texto.contains(char::is_whitespace) {
            return Err(format!("referencia de imagen inválida: «{texto}»"));
        }
        let (resto, resumen) = match texto.split_once('@') {
            Some((r, d)) => (r, Some(d.to_string())),
            None => (texto, None),
        };
        if let Some(d) = &resumen {
            let valido = d
                .strip_prefix("sha256:")
                .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()));
            if !valido {
                return Err(format!(
                    "resumen no soportado en «{texto}» (se espera sha256:<64 hex>)"
                ));
            }
        }
        let (primero, despues) = resto.split_once('/').unwrap_or(("", resto));
        let tiene_registro = !primero.is_empty()
            && (primero.contains('.') || primero.contains(':') || primero == "localhost");
        let (registro, ruta) = if tiene_registro {
            (primero.to_string(), despues.to_string())
        } else {
            ("docker.io".to_string(), resto.to_string())
        };
        // La etiqueta va tras el último «:» del último segmento.
        let (repositorio, etiqueta) = match ruta.rsplit_once(':') {
            Some((r, e)) if !e.contains('/') => (r.to_string(), Some(e.to_string())),
            _ => (ruta, None),
        };
        let repositorio = if registro == "docker.io" && !repositorio.contains('/') {
            format!("library/{repositorio}")
        } else {
            repositorio
        };
        let valido = |s: &str| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-/".contains(&b))
        };
        if !valido(&repositorio) {
            return Err(format!("repositorio inválido en «{texto}»"));
        }
        let etiqueta_invalida = etiqueta.as_ref().is_some_and(|e| {
            e.is_empty()
                || e.len() > 128
                || !e
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        });
        if etiqueta_invalida {
            return Err(format!("etiqueta inválida en «{texto}»"));
        }
        let etiqueta = if etiqueta.is_none() && resumen.is_none() {
            Some("latest".to_string())
        } else {
            etiqueta
        };
        Ok(Self {
            registro,
            repositorio,
            etiqueta,
            resumen,
        })
    }

    /// Texto canónico, útil como etiqueta estable de la imagen.
    pub fn texto(&self) -> String {
        let mut t = format!("{}/{}", self.registro, self.repositorio);
        if let Some(e) = &self.etiqueta {
            t.push(':');
            t.push_str(e);
        }
        if let Some(d) = &self.resumen {
            t.push('@');
            t.push_str(d);
        }
        t
    }

    fn servidor_api(&self, permitir_http_local: bool) -> Result<Servidor, String> {
        let host = if self.registro == "docker.io" {
            "registry-1.docker.io"
        } else {
            self.registro.as_str()
        };
        let seguro = Servidor::interpretar(&format!("https://{host}"))?;
        // HTTP requiere autorización explícita y un destino loopback válido.
        let esquema = if permitir_http_local && es_local(&seguro.host) {
            "http"
        } else {
            "https"
        };
        Servidor::interpretar(&format!("{esquema}://{host}"))
    }
}

/// Opciones de descarga.
#[derive(Clone)]
pub struct Opciones {
    pub tiempo_limite: Duration,
    /// Sistema y arquitectura, por ejemplo `linux/amd64` o `linux/arm/v7`.
    pub plataforma: String,
    /// Autoridad adicional para registros privados, en PEM.
    pub autoridad_pem: Option<Vec<u8>>,
    /// Ruta de `config.json` de Docker; si falta, la habitual.
    pub config_docker: Option<PathBuf>,
    /// HTTP de desarrollo solo en loopback; TLS es el valor predeterminado.
    pub permitir_http_local: bool,
    /// Entradas REGISTRO=ORIGEN, administradas por el operador, nunca por el desafío.
    pub origenes_token: Vec<String>,
}

impl Default for Opciones {
    fn default() -> Self {
        Self {
            tiempo_limite: Duration::from_secs(10),
            plataforma: plataforma_local(),
            autoridad_pem: None,
            config_docker: None,
            permitir_http_local: false,
            origenes_token: Vec::new(),
        }
    }
}

/// `linux/<arquitectura de este equipo>`, con los nombres de OCI.
pub fn plataforma_local() -> String {
    let arquitectura = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "386",
        "powerpc64" => "ppc64le",
        otra => otra,
    };
    format!("linux/{arquitectura}")
}

/// Usuario y clave para el registro.
#[derive(Clone)]
struct Basica {
    usuario: String,
    clave: String,
}

impl Basica {
    fn encabezado(&self) -> String {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", self.usuario, self.clave))
        )
    }
}

fn ruta_config_docker(op: &Opciones) -> Option<PathBuf> {
    if let Some(r) = &op.config_docker {
        return Some(r.clone());
    }
    if let Some(d) = std::env::var_os("DOCKER_CONFIG") {
        return Some(PathBuf::from(d).join("config.json"));
    }
    let casa = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    Some(PathBuf::from(casa).join(".docker").join("config.json"))
}

/// Ejecuta `docker-credential-<ayudante> get`, como hace Docker.
fn credencial_de_ayudante(ayudante: &str, servidor: &str) -> Result<Option<Basica>, String> {
    if !ayudante
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(format!(
            "nombre de ayudante de credenciales inválido: {ayudante}"
        ));
    }
    let comando = format!("docker-credential-{ayudante}");
    let mut proceso = std::process::Command::new(&comando)
        .arg("get")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("no se pudo ejecutar «{comando}»: {e}"))?;
    if let Some(mut entrada) = proceso.stdin.take() {
        use std::io::Write;
        entrada
            .write_all(servidor.as_bytes())
            .map_err(|e| e.to_string())?;
    }
    let salida = proceso.wait_with_output().map_err(|e| e.to_string())?;
    if !salida.status.success() {
        // El ayudante responde con error cuando no tiene credenciales.
        return Ok(None);
    }
    let v: serde_json::Value = serde_json::from_slice(&salida.stdout)
        .map_err(|_| format!("«{comando}» devolvió una respuesta no válida"))?;
    match (v["Username"].as_str(), v["Secret"].as_str()) {
        (Some(u), Some(s)) if !s.is_empty() => Ok(Some(Basica {
            usuario: u.to_string(),
            clave: s.to_string(),
        })),
        _ => Ok(None),
    }
}

fn buscar_credenciales(r: &Referencia, op: &Opciones, avisos: &mut Vec<String>) -> Option<Basica> {
    if let (Ok(u), Ok(c)) = (
        std::env::var("SUAYA_REGISTRO_USUARIO"),
        std::env::var("SUAYA_REGISTRO_CLAVE"),
    ) {
        return Some(Basica {
            usuario: u,
            clave: c,
        });
    }
    let ruta = ruta_config_docker(op)?;
    let texto = std::fs::read_to_string(&ruta).ok()?;
    let config: serde_json::Value = match serde_json::from_str(&texto) {
        Ok(v) => v,
        Err(e) => {
            avisos.push(format!("{}: {e}", ruta.display()));
            return None;
        }
    };
    let claves: Vec<String> = if r.registro == "docker.io" {
        vec![
            "https://index.docker.io/v1/".into(),
            "index.docker.io".into(),
            "docker.io".into(),
        ]
    } else {
        vec![
            r.registro.clone(),
            format!("https://{}", r.registro),
            format!("http://{}", r.registro),
        ]
    };
    let mut ayudar = |ayudante: &str| match credencial_de_ayudante(ayudante, &claves[0]) {
        Ok(b) => b,
        Err(e) => {
            avisos.push(e);
            None
        }
    };
    for k in &claves {
        if let Some(a) = config["credHelpers"][k.as_str()].as_str() {
            return ayudar(a);
        }
    }
    for k in &claves {
        let entrada = &config["auths"][k.as_str()];
        if let Some(auth) = entrada["auth"].as_str() {
            let decodificado = base64::engine::general_purpose::STANDARD
                .decode(auth.trim())
                .ok()
                .and_then(|b| String::from_utf8(b).ok());
            if let Some((u, c)) = decodificado.as_deref().and_then(|t| t.split_once(':')) {
                return Some(Basica {
                    usuario: u.to_string(),
                    clave: c.to_string(),
                });
            }
        }
    }
    if let Some(a) = config["credsStore"].as_str() {
        return ayudar(a);
    }
    None
}

/// Divide una URL absoluta en servidor (sin prefijo) y ruta con consulta.
fn dividir_url(url: &str) -> Result<(Servidor, String), String> {
    let (esquema, resto) = url
        .split_once("://")
        .ok_or_else(|| format!("URL inválida: {url}"))?;
    let fin = resto.find(['/', '?']).unwrap_or(resto.len());
    let mut servidor = Servidor::interpretar(&format!("{esquema}://{}", &resto[..fin]))?;
    servidor.prefijo.clear();
    let ruta = &resto[fin..];
    let ruta = if ruta.is_empty() {
        "/".to_string()
    } else if ruta.starts_with('?') {
        format!("/{ruta}")
    } else {
        ruta.to_string()
    };
    Ok((servidor, ruta))
}

fn mismo_origen(a: &Servidor, b: &Servidor) -> bool {
    a.seguro == b.seguro && a.host.eq_ignore_ascii_case(&b.host) && a.puerto == b.puerto
}

fn codificar(t: &str) -> String {
    let mut s = String::new();
    for b in t.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            s.push(b as char);
        } else {
            s.push_str(&format!("%{b:02X}"));
        }
    }
    s
}

/// Parámetros de un desafío `WWW-Authenticate`.
fn interpretar_desafio(valor: &str) -> (String, Vec<(String, String)>) {
    let (esquema, resto) = valor.trim().split_once(' ').unwrap_or((valor.trim(), ""));
    let mut parametros = Vec::new();
    let mut resto = resto.trim();
    while !resto.is_empty() {
        let Some((k, v)) = resto.split_once('=') else {
            break;
        };
        let k = k.trim().trim_start_matches(',').trim().to_ascii_lowercase();
        let v = v.trim_start();
        let (valor, siguiente) = if let Some(v) = v.strip_prefix('"') {
            match v.find('"') {
                Some(i) => (&v[..i], &v[i + 1..]),
                None => (v, ""),
            }
        } else {
            match v.find(',') {
                Some(i) => (&v[..i], &v[i..]),
                None => (v, ""),
            }
        };
        parametros.push((k, valor.to_string()));
        resto = siguiente.trim_start_matches([',', ' ']);
    }
    (esquema.to_ascii_lowercase(), parametros)
}

/// Sesión con un registro: servidor, credenciales y token vigente.
struct Sesion {
    api: Servidor,
    basica: Option<Basica>,
    autorizacion: Option<String>,
    confianza: ConfianzaTls,
    tiempo: Duration,
    repositorio: String,
    origenes_token: Vec<Servidor>,
    permitir_http_local: bool,
}

impl Sesion {
    /// GET que sigue redirecciones; la autorización solo viaja al registro.
    fn abrir(
        &self,
        servidor: &Servidor,
        ruta: &str,
        aceptar: &str,
        autorizacion: Option<&str>,
    ) -> Result<RespuestaFlujo, String> {
        let mut servidor = servidor.clone();
        let mut ruta = ruta.to_string();
        for _ in 0..=MAXIMO_REDIRECCIONES {
            if !servidor.seguro && !(self.permitir_http_local && es_local(&servidor.host)) {
                return Err("HTTP solo se permite explícitamente en loopback".into());
            }
            let mut encabezados = vec![("Accept", aceptar)];
            let autorizado = mismo_origen(&servidor, &self.api);
            if let (Some(a), true) = (autorizacion, autorizado) {
                encabezados.push(("Authorization", a));
            }
            let r = http::abrir(
                &servidor,
                &ruta,
                &encabezados,
                &Credenciales::default(),
                &self.confianza,
                self.tiempo,
            )?;
            if r.estado == 401 && !mismo_origen(&servidor, &self.api) {
                return Err("desafío de autenticación de otro origen rechazado".into());
            }
            if !matches!(r.estado, 301 | 302 | 303 | 307 | 308) {
                return Ok(r);
            }
            let destino = r
                .encabezado("location")
                .ok_or("redirección sin Location")?
                .to_string();
            let (nuevo, nueva_ruta) = if destino.contains("://") {
                dividir_url(&destino)?
            } else if destino.starts_with('/') {
                (servidor.clone(), destino)
            } else {
                return Err(format!("redirección no soportada: {destino}"));
            };
            if servidor.seguro && !nuevo.seguro {
                return Err(format!(
                    "el registro redirigió de HTTPS a HTTP ({}); se rechaza",
                    nuevo.host
                ));
            }
            servidor = nuevo;
            ruta = nueva_ruta;
        }
        Err("demasiadas redirecciones".into())
    }

    /// Resuelve un 401: obtiene un token (`Bearer`) o usa `Basic`.
    fn autenticar(&mut self, desafio: &str) -> Result<(), String> {
        let (esquema, parametros) = interpretar_desafio(desafio);
        let p = |k: &str| {
            parametros
                .iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.clone())
        };
        let puede_enviar_clave =
            |s: &Servidor| s.seguro || (self.permitir_http_local && es_local(&s.host));
        match esquema.as_str() {
            "basic" => {
                let b = self
                    .basica
                    .as_ref()
                    .ok_or("el registro exige usuario y clave (autenticación Basic)")?;
                if !puede_enviar_clave(&self.api) {
                    return Err("el registro pide la clave sin cifrar; se rechaza".into());
                }
                self.autorizacion = Some(b.encabezado());
                Ok(())
            }
            "bearer" => {
                let reino = p("realm").ok_or("desafío Bearer sin realm")?;
                let (servidor_token, mut ruta) = dividir_url(&reino)?;
                if !mismo_origen(&servidor_token, &self.api)
                    && !self
                        .origenes_token
                        .iter()
                        .any(|s| mismo_origen(s, &servidor_token))
                {
                    return Err("origen de token no autorizado para este registro".into());
                }
                if !puede_enviar_clave(&servidor_token) {
                    return Err("transporte del servicio de tokens no autorizado".into());
                }
                let alcance = format!("repository:{}:pull", self.repositorio);
                let mut consulta = Vec::new();
                if let Some(s) = p("service") {
                    consulta.push(format!("service={}", codificar(&s)));
                }
                consulta.push(format!("scope={}", codificar(&alcance)));
                ruta.push(if ruta.contains('?') { '&' } else { '?' });
                ruta.push_str(&consulta.join("&"));

                let mut encabezados = vec![("Accept", "application/json")];
                let basica = match &self.basica {
                    Some(b) if puede_enviar_clave(&servidor_token) => Some(b.encabezado()),
                    Some(_) => {
                        return Err(
                            "el servicio de tokens no usa HTTPS; no se le envía la clave".into(),
                        );
                    }
                    None => None,
                };
                if let Some(b) = &basica {
                    encabezados.push(("Authorization", b.as_str()));
                }
                let r = http::abrir(
                    &servidor_token,
                    &ruta,
                    &encabezados,
                    &Credenciales::default(),
                    &self.confianza,
                    self.tiempo,
                )?;
                let estado = r.estado;
                let cuerpo = r.leer_todo(1024 * 1024)?;
                if estado != 200 {
                    return Err(format!(
                        "el servicio de tokens respondió {estado}{}",
                        if self.basica.is_some() {
                            " (revise las credenciales)"
                        } else {
                            " (la imagen puede ser privada: configure credenciales)"
                        }
                    ));
                }
                let v: serde_json::Value = serde_json::from_slice(&cuerpo)
                    .map_err(|_| "respuesta del servicio de tokens no válida")?;
                let token = v["token"]
                    .as_str()
                    .or(v["access_token"].as_str())
                    .filter(|t| !t.is_empty() && !t.contains(['\r', '\n']))
                    .ok_or("el servicio de tokens no devolvió un token")?;
                self.autorizacion = Some(format!("Bearer {token}"));
                Ok(())
            }
            otro => Err(format!("esquema de autenticación no soportado: {otro}")),
        }
    }

    /// GET al registro, autenticándose una vez si responde 401.
    fn obtener(&mut self, ruta: &str, aceptar: &str) -> Result<RespuestaFlujo, String> {
        let api = self.api.clone();
        let r = self.abrir(&api, ruta, aceptar, self.autorizacion.as_deref())?;
        if r.estado != 401 {
            return Ok(r);
        }
        let desafio = r
            .encabezado("www-authenticate")
            .ok_or("el registro respondió 401 sin desafío de autenticación")?
            .to_string();
        drop(r);
        self.autenticar(&desafio)?;
        let r = self.abrir(&api, ruta, aceptar, self.autorizacion.as_deref())?;
        if r.estado == 401 || r.estado == 403 {
            return Err(format!(
                "acceso denegado por el registro ({}){}",
                r.estado,
                if self.basica.is_some() {
                    ""
                } else {
                    "; configure credenciales con docker login o SUAYA_REGISTRO_USUARIO"
                }
            ));
        }
        Ok(r)
    }

    /// Manifiesto o índice, verificado si se pidió por resumen.
    fn manifiesto(&mut self, referencia: &str) -> Result<(serde_json::Value, String), String> {
        let ruta = format!("/v2/{}/manifests/{referencia}", self.repositorio);
        let r = self.obtener(&ruta, ACEPTAR_MANIFIESTO)?;
        if r.estado == 404 {
            return Err(format!("la imagen no existe en el registro ({referencia})"));
        }
        if r.estado != 200 {
            return Err(format!(
                "el registro respondió {} al pedir el manifiesto",
                r.estado
            ));
        }
        let tipo = r.encabezado("content-type").unwrap_or("").to_string();
        let cuerpo = r.leer_todo(MAXIMO_MANIFIESTO)?;
        let resumen = format!("sha256:{}", hex::encode(Sha256::digest(&cuerpo)));
        if referencia.starts_with("sha256:") && resumen != referencia {
            return Err(format!(
                "el manifiesto no coincide con su resumen (se esperaba {referencia}, llegó {resumen})"
            ));
        }
        let mut v: serde_json::Value =
            serde_json::from_slice(&cuerpo).map_err(|e| format!("manifiesto no válido: {e}"))?;
        if v.get("mediaType").is_none() && !tipo.is_empty() {
            v["mediaType"] =
                serde_json::Value::String(tipo.split(';').next().unwrap_or("").trim().to_string());
        }
        Ok((v, resumen))
    }
}

/// Elige del índice el manifiesto de la plataforma pedida.
fn elegir_plataforma(indice: &serde_json::Value, plataforma: &str) -> Result<String, String> {
    let mut partes = plataforma.split('/');
    let so = partes.next().unwrap_or("linux");
    let arquitectura = partes.next().unwrap_or("amd64");
    let variante = partes.next();
    let lista = indice["manifests"]
        .as_array()
        .ok_or("índice sin manifiestos")?;
    let candidatos: Vec<&serde_json::Value> = lista
        .iter()
        .filter(|m| {
            m["platform"]["os"].as_str() == Some(so)
                && m["platform"]["architecture"].as_str() == Some(arquitectura)
        })
        .collect();
    let elegido = candidatos
        .iter()
        .find(|m| variante.is_none() || m["platform"]["variant"].as_str() == variante)
        .or(candidatos.first())
        .ok_or_else(|| {
            let hay: Vec<String> = lista
                .iter()
                .filter_map(|m| {
                    let so = m["platform"]["os"].as_str()?;
                    let ar = m["platform"]["architecture"].as_str()?;
                    (so != "unknown").then(|| format!("{so}/{ar}"))
                })
                .collect();
            format!(
                "la imagen no está publicada para {plataforma} (disponibles: {}); use --plataforma",
                hay.join(", ")
            )
        })?;
    elegido["digest"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| "manifiesto del índice sin resumen".to_string())
}

/// Lector que calcula el SHA-256 y cuenta bytes mientras se lee.
struct Verificado<R> {
    interior: R,
    hash: Sha256,
    leidos: u64,
}

impl<R: Read> Read for Verificado<R> {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        let n = self.interior.read(b)?;
        self.hash.update(&b[..n]);
        self.leidos += n as u64;
        Ok(n)
    }
}

/// Descarga y analiza una imagen; sus hallazgos se agregan a `resultado`.
pub fn inventariar_imagen(
    texto: &str,
    escaneres: &[Box<dyn Escaner>],
    c: &Conocimiento,
    op_escaneo: &OpcionesEscaneo,
    op: &Opciones,
    resultado: &mut Resultado,
) -> Result<(), String> {
    let referencia = Referencia::interpretar(texto)?;
    let mut avisos = Vec::new();
    let basica = buscar_credenciales(&referencia, op, &mut avisos);
    resultado.avisos.extend(avisos);
    let mut origenes_token = Vec::new();
    // Docker Hub es la única relación externa incorporada y explícita.
    if referencia.registro == "docker.io" {
        origenes_token.push(Servidor::interpretar("https://auth.docker.io")?);
    }
    for regla in &op.origenes_token {
        let (registro, origen) = regla
            .split_once('=')
            .ok_or("use REGISTRO=ORIGEN para autorizar tokens")?;
        let (servidor, ruta) = dividir_url(origen)?;
        if ruta != "/"
            || (!servidor.seguro && !(op.permitir_http_local && es_local(&servidor.host)))
        {
            return Err("origen de token inválido o transporte no autorizado".into());
        }
        if registro == referencia.registro {
            origenes_token.push(servidor);
        }
    }
    let mut sesion = Sesion {
        api: referencia.servidor_api(op.permitir_http_local)?,
        origenes_token,
        permitir_http_local: op.permitir_http_local,
        basica,
        autorizacion: None,
        confianza: ConfianzaTls {
            autoridad_pem: op.autoridad_pem.clone(),
            sin_verificar: false,
            nombre_servidor: None,
            raices_sistema: true,
        },
        tiempo: op.tiempo_limite,
        repositorio: referencia.repositorio.clone(),
    };

    let pedido = referencia
        .resumen
        .clone()
        .or(referencia.etiqueta.clone())
        .unwrap_or_else(|| "latest".into());
    let (mut manifiesto, mut resumen) = sesion.manifiesto(&pedido)?;
    for _ in 0..2 {
        let tipo = manifiesto["mediaType"].as_str().unwrap_or("");
        let es_indice = tipo.contains("index") || tipo.contains("manifest.list");
        if !es_indice && manifiesto.get("manifests").is_none() {
            break;
        }
        let elegido = elegir_plataforma(&manifiesto, &op.plataforma)?;
        (manifiesto, resumen) = sesion.manifiesto(&elegido)?;
    }
    if manifiesto["schemaVersion"].as_i64() != Some(2) {
        return Err("solo se admiten manifiestos de esquema 2 (OCI o Docker v2)".into());
    }
    let capas = manifiesto["layers"]
        .as_array()
        .ok_or("el manifiesto no declara capas")?;
    if capas.len() > MAXIMO_CAPAS {
        return Err("la imagen excede el número máximo de capas".into());
    }
    let total = capas.iter().try_fold(0u64, |total, capa| {
        total
            .checked_add(capa["size"].as_u64().ok_or("capa sin tamaño")?)
            .ok_or("tamaño de imagen desbordado")
    })?;
    if total > MAXIMO_IMAGEN {
        return Err("la imagen excede el tamaño máximo admitido".into());
    }

    let etiqueta = referencia.texto();
    let mut analizador = AnalizadorImagen::nuevo(&etiqueta, &etiqueta);
    for (i, capa) in capas.iter().enumerate() {
        let tipo = capa["mediaType"].as_str().unwrap_or("");
        if tipo.contains("foreign") || tipo.contains("nondistributable") {
            resultado.avisos.push(format!(
                "{etiqueta}: capa {} no distribuible (se omite)",
                i + 1
            ));
            continue;
        }
        let digest = capa["digest"].as_str().ok_or("capa sin resumen")?;
        let esperado = digest
            .strip_prefix("sha256:")
            .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(|| format!("resumen de capa no soportado: {digest}"))?
            .to_ascii_lowercase();
        let tamano = capa["size"].as_u64().ok_or("capa sin tamaño")?;
        let ruta = format!("/v2/{}/blobs/{digest}", sesion.repositorio);
        let r = sesion.obtener(&ruta, "*/*")?;
        if r.estado != 200 {
            return Err(format!(
                "el registro respondió {} al pedir la capa {}",
                r.estado,
                i + 1
            ));
        }
        let mut lector = Verificado {
            interior: r.cuerpo.take(tamano + 1),
            hash: Sha256::new(),
            leidos: 0,
        };
        analizador.capa(i, &mut lector, escaneres, c, op_escaneo)?;
        // Se lee el resto (relleno del tar, cola del compresor) para verificar.
        std::io::copy(&mut lector, &mut std::io::sink())
            .map_err(|e| format!("capa {}: {e}", i + 1))?;
        let obtenido = hex::encode(lector.hash.finalize_reset());
        if lector.leidos != tamano || obtenido != esperado {
            return Err(format!(
                "la capa {} no coincide con su resumen o tamaño; se descarta la imagen",
                i + 1
            ));
        }
    }
    analizador.terminar(resultado);
    resultado.avisos.push(format!(
        "{etiqueta}: {} capas verificadas ({resumen}, {})",
        capas.len(),
        op.plataforma
    ));
    Ok(())
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn referencias() {
        let r = Referencia::interpretar("nginx").unwrap();
        assert_eq!(
            (
                r.registro.as_str(),
                r.repositorio.as_str(),
                r.etiqueta.as_deref()
            ),
            ("docker.io", "library/nginx", Some("latest"))
        );
        let r = Referencia::interpretar("docker://ghcr.io/org/app:1.2").unwrap();
        assert_eq!(r.texto(), "ghcr.io/org/app:1.2");
        let r = Referencia::interpretar("localhost:5000/tienda").unwrap();
        assert_eq!(r.registro, "localhost:5000");
        assert!(r.servidor_api(false).unwrap().seguro);
        assert!(!r.servidor_api(true).unwrap().seguro);
        assert!(
            Referencia::interpretar("ghcr.io/a/b")
                .unwrap()
                .servidor_api(false)
                .unwrap()
                .seguro
        );
        let d = format!("sha256:{}", "a".repeat(64));
        let r = Referencia::interpretar(&format!("quay.io/x/y@{d}")).unwrap();
        assert_eq!((r.etiqueta, r.resumen), (None, Some(d)));
        assert!(Referencia::interpretar("Mayusculas/no").is_err());
        assert!(Referencia::interpretar("a@md5:abc").is_err());
    }

    #[test]
    fn desafios() {
        let (e, p) = interpretar_desafio(
            r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/nginx:pull""#,
        );
        assert_eq!(e, "bearer");
        assert_eq!(
            p[0],
            ("realm".into(), "https://auth.docker.io/token".into())
        );
        assert_eq!(p[2].1, "repository:library/nginx:pull");
        assert_eq!(
            codificar("repository:a/b:pull"),
            "repository%3Aa%2Fb%3Apull"
        );
    }

    #[test]
    fn urls() {
        let (s, r) = dividir_url("https://cdn.ejemplo.mx/capas/x?firma=1").unwrap();
        assert_eq!(
            (s.host.as_str(), s.puerto, r.as_str()),
            ("cdn.ejemplo.mx", 443, "/capas/x?firma=1")
        );
        let (s, r) = dividir_url("http://127.0.0.1:8080?a=b").unwrap();
        assert_eq!((s.puerto, r.as_str()), (8080, "/?a=b"));
    }
}

#[cfg(test)]
mod auditoria_regresion_localhost {
    use super::*;
    #[test]
    fn sec004_dominios_no_son_loopback() {
        assert!(es_local("127.0.0.1"));
        assert!(es_local("::1"));
        assert!(es_local("localhost"));
        assert!(!es_local("127.audit.invalid"));
        assert!(!es_local("127.0.0.1.audit.invalid"));
    }
}

#[cfg(test)]
mod politica_registros {
    use super::*;
    #[test]
    fn dominios_con_prefijos_ip_no_autorizan_http() {
        for n in 0..256 {
            assert!(!es_local(&format!("127.{n}.example.invalid")));
        }
        for h in ["128.0.0.1", "0.0.0.0", "localhost.evil", "::ffff:192.0.2.1"] {
            assert!(!es_local(h));
        }
        for h in ["127.0.0.2", "[::1]", "LOCALHOST"] {
            assert!(es_local(h));
        }
    }
    #[test]
    fn realm_no_autorizado_se_rechaza_antes_de_conectar() {
        let mut sesion = Sesion {
            api: Servidor::interpretar("https://registry.invalid").unwrap(),
            basica: Some(Basica {
                usuario: "test".into(),
                clave: "synthetic".into(),
            }),
            autorizacion: None,
            confianza: ConfianzaTls::default(),
            tiempo: Duration::from_millis(1),
            repositorio: "test".into(),
            origenes_token: Vec::new(),
            permitir_http_local: false,
        };
        let error = sesion
            .autenticar("Bearer realm=\"https://untrusted.invalid/token\"")
            .unwrap_err();
        assert!(error.contains("no autorizado"));
    }
}
