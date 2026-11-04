//! Cliente HTTP/1.1 mínimo, solo de lectura (GET), para la API de Kubernetes
//! y los registros de imágenes OCI.
//!
//! Se escribe a mano para no añadir dependencias: Suaya solo necesita GET
//! con `Connection: close`, cuerpo con `Content-Length` o fragmentado
//! (`chunked`), leído como flujo, y TLS con verificación estricta del
//! servidor.

use std::io::{BufRead, BufReader, Cursor, Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};

/// Tope de respuesta: la lista de Secrets de un clúster grande cabe holgada.
const MAXIMO_RESPUESTA: usize = 256 * 1024 * 1024;
/// Tope de la cabecera de una respuesta.
const MAXIMO_CABECERA: usize = 64 * 1024;

/// Credenciales para el servidor.
#[derive(Clone, Default)]
pub struct Credenciales {
    pub token: Option<String>,
    /// Certificado de cliente y llave privada, en PEM.
    pub certificado_cliente: Option<(Vec<u8>, Vec<u8>)>,
}

/// Configuración de TLS del servidor.
#[derive(Clone, Default)]
pub struct ConfianzaTls {
    /// Certificados de la autoridad del servidor, en PEM.
    pub autoridad_pem: Option<Vec<u8>>,
    /// Desactiva la verificación (`insecure-skip-tls-verify` del kubeconfig).
    pub sin_verificar: bool,
    /// Nombre esperado en el certificado (`tls-server-name`).
    pub nombre_servidor: Option<String>,
    /// Confía además en el almacén de autoridades del sistema operativo.
    pub raices_sistema: bool,
}

/// Servidor base: `https://host:puerto` o `http://host:puerto`.
#[derive(Clone)]
pub struct Servidor {
    pub seguro: bool,
    pub host: String,
    pub puerto: u16,
    /// Prefijo de ruta (algunos servidores publican la API bajo una ruta).
    pub prefijo: String,
}

impl Servidor {
    pub fn interpretar(url: &str) -> Result<Self, String> {
        let (seguro, resto) = if let Some(r) = url.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = url.strip_prefix("http://") {
            (false, r)
        } else {
            return Err(format!("URL de servidor no soportada: {url}"));
        };
        let (autoridad, prefijo) = match resto.find('/') {
            Some(i) => (&resto[..i], resto[i..].trim_end_matches('/').to_string()),
            None => (resto, String::new()),
        };
        let (host, puerto) = if let Some(r) = autoridad.strip_prefix('[') {
            let (h, p) = r.split_once(']').ok_or("IPv6 sin corchete de cierre")?;
            (h.to_string(), p.strip_prefix(':').map(str::to_string))
        } else {
            match autoridad.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), Some(p.to_string())),
                None => (autoridad.to_string(), None),
            }
        };
        let puerto = match puerto {
            Some(p) => p.parse().map_err(|_| format!("puerto inválido en {url}"))?,
            None if seguro => 443,
            None => 80,
        };
        Ok(Self {
            seguro,
            host,
            puerto,
            prefijo,
        })
    }
}

/// Respuesta HTTP.
pub struct Respuesta {
    pub estado: u16,
    pub cuerpo: Vec<u8>,
}

trait Flujo: Read + Write {}
impl<T: Read + Write> Flujo for T {}

fn configuracion_tls(
    confianza: &ConfianzaTls,
    cred: &Credenciales,
) -> Result<rustls::ClientConfig, String> {
    let proveedor = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let base = rustls::ClientConfig::builder_with_provider(proveedor.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?;
    if confianza.sin_verificar {
        return Err(
            "TLS sin verificación no está permitido en conexiones HTTP con datos o credenciales"
                .into(),
        );
    }
    let con_verificador = {
        let mut raices = rustls::RootCertStore::empty();
        if confianza.raices_sistema {
            for c in rustls_native_certs::load_native_certs().certs {
                // Una autoridad del sistema que rustls no acepta se ignora.
                let _ = raices.add(c);
            }
        }
        if let Some(pem) = &confianza.autoridad_pem {
            for c in CertificateDer::pem_slice_iter(pem) {
                raices
                    .add(c.map_err(|e| format!("autoridad inválida: {e:?}"))?)
                    .map_err(|e| e.to_string())?;
            }
        }
        if raices.is_empty() {
            return Err(if confianza.raices_sistema {
                "no se encontró ninguna autoridad certificadora en el sistema".into()
            } else {
                "el servidor no declara su autoridad certificadora (certificate-authority); no se puede verificar".into()
            });
        }
        let verificador = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(raices),
            proveedor,
        )
        .build()
        .map_err(|e| e.to_string())?;
        base.with_webpki_verifier(verificador)
    };
    match &cred.certificado_cliente {
        Some((cert, llave)) => {
            let cadena: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert)
                .collect::<Result<_, _>>()
                .map_err(|e| format!("certificado de cliente inválido: {e:?}"))?;
            let llave = PrivateKeyDer::from_pem_slice(llave)
                .map_err(|e| format!("llave de cliente inválida: {e:?}"))?;
            con_verificador
                .with_client_auth_cert(cadena, llave)
                .map_err(|e| e.to_string())
        }
        None => Ok(con_verificador.with_no_client_auth()),
    }
}

/// Respuesta cuyo cuerpo se lee como flujo (por ejemplo, una capa de imagen
/// de varios gigabytes).
pub struct RespuestaFlujo {
    pub estado: u16,
    pub encabezados: Vec<(String, String)>,
    pub cuerpo: Box<dyn Read>,
}

impl RespuestaFlujo {
    /// Valor del primer encabezado con ese nombre (sin distinguir mayúsculas).
    pub fn encabezado(&self, nombre: &str) -> Option<&str> {
        self.encabezados
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(nombre))
            .map(|(_, v)| v.as_str())
    }

    /// Lee el cuerpo completo, con un tope.
    pub fn leer_todo(self, maximo: usize) -> Result<Vec<u8>, String> {
        let mut cuerpo = Vec::new();
        self.cuerpo
            .take(maximo as u64 + 1)
            .read_to_end(&mut cuerpo)
            .map_err(|e| format!("error al leer la respuesta: {e}"))?;
        if cuerpo.len() > maximo {
            return Err("respuesta demasiado grande".into());
        }
        Ok(cuerpo)
    }
}

/// Algunos servidores cierran TLS sin `close_notify` tras «Connection: close»:
/// cuando el cuerpo se delimita por el cierre, eso equivale al fin del flujo.
struct CierreTolerante<R>(R);

impl<R: Read> Read for CierreTolerante<R> {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        match self.0.read(b) {
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(0),
            r => r,
        }
    }
}

/// Cuerpo con `Content-Length`: falla si el servidor corta antes.
struct Exacto<R> {
    interior: R,
    restante: u64,
}

impl<R: Read> Read for Exacto<R> {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        if self.restante == 0 || b.is_empty() {
            return Ok(0);
        }
        let n = b.len().min(self.restante.min(usize::MAX as u64) as usize);
        let leidos = self.interior.read(&mut b[..n])?;
        if leidos == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "cuerpo HTTP truncado",
            ));
        }
        self.restante -= leidos as u64;
        Ok(leidos)
    }
}

/// Cuerpo fragmentado (`Transfer-Encoding: chunked`).
struct Fragmentado<R> {
    interior: R,
    restante: u64,
    terminado: bool,
}

fn error_fragmento(texto: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, texto.to_string())
}

fn leer_linea(r: &mut impl BufRead) -> std::io::Result<String> {
    let mut linea = Vec::new();
    r.take(8 * 1024).read_until(b'\n', &mut linea)?;
    if !linea.ends_with(b"\n") {
        return Err(error_fragmento("fragmento HTTP incompleto"));
    }
    Ok(String::from_utf8_lossy(&linea).trim_end().to_string())
}

impl<R: BufRead> Read for Fragmentado<R> {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        if self.terminado || b.is_empty() {
            return Ok(0);
        }
        if self.restante == 0 {
            let linea = leer_linea(&mut self.interior)?;
            let tamano = u64::from_str_radix(linea.split(';').next().unwrap_or("").trim(), 16)
                .map_err(|_| error_fragmento("tamaño de fragmento inválido"))?;
            if tamano == 0 {
                // Encabezados finales, hasta la línea vacía.
                while !leer_linea(&mut self.interior)?.is_empty() {}
                self.terminado = true;
                return Ok(0);
            }
            self.restante = tamano;
        }
        let n = b.len().min(self.restante.min(usize::MAX as u64) as usize);
        let leidos = self.interior.read(&mut b[..n])?;
        if leidos == 0 {
            return Err(error_fragmento("fragmento HTTP truncado"));
        }
        self.restante -= leidos as u64;
        if self.restante == 0 && !leer_linea(&mut self.interior)?.is_empty() {
            return Err(error_fragmento("fragmento HTTP mal terminado"));
        }
        Ok(leidos)
    }
}

/// Lee estado y encabezados y prepara el cuerpo como flujo.
fn leer_respuesta(mut r: Box<dyn BufRead>) -> Result<RespuestaFlujo, String> {
    let mut cabecera = Vec::new();
    loop {
        let antes = cabecera.len();
        (&mut r)
            .take((MAXIMO_CABECERA - antes.min(MAXIMO_CABECERA)) as u64)
            .read_until(b'\n', &mut cabecera)
            .map_err(|e| format!("error al leer la respuesta: {e}"))?;
        if cabecera.len() == antes {
            return Err("respuesta HTTP incompleta".into());
        }
        if cabecera.ends_with(b"\r\n\r\n") || cabecera.ends_with(b"\n\n") {
            break;
        }
        if cabecera.len() >= MAXIMO_CABECERA {
            return Err("cabecera HTTP demasiado grande".into());
        }
    }
    let texto = String::from_utf8_lossy(&cabecera);
    let mut lineas = texto.lines();
    let estado: u16 = lineas
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or("línea de estado HTTP inválida")?;
    let encabezados: Vec<(String, String)> = lineas
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let valor = |n: &str| {
        encabezados
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(n))
            .map(|(_, v)| v.as_str())
    };
    let cuerpo: Box<dyn Read> =
        if valor("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
            Box::new(Fragmentado {
                interior: r,
                restante: 0,
                terminado: false,
            })
        } else if let Some(n) = valor("content-length").and_then(|v| v.parse::<u64>().ok()) {
            Box::new(Exacto {
                interior: r,
                restante: n,
            })
        } else {
            Box::new(r)
        };
    Ok(RespuestaFlujo {
        estado,
        encabezados,
        cuerpo,
    })
}

/// Proxy HTTP para conexiones TLS, tomado de `HTTPS_PROXY` y `NO_PROXY`
/// como hacen curl, Docker y kubectl.
struct Proxy {
    host: String,
    puerto: u16,
    autorizacion: Option<String>,
}

/// ¿El host coincide con una entrada de `NO_PROXY`? Admite `*`, dominios
/// (`.ejemplo.mx`, `*.ejemplo.mx`), direcciones y bloques CIDR.
fn excluido_del_proxy(host: &str, entrada: &str) -> bool {
    if entrada == "*" {
        return true;
    }
    if let Some((red, bits)) = entrada.split_once('/') {
        let (Ok(red), Ok(bits), Ok(ip)) = (
            red.parse::<IpAddr>(),
            bits.parse::<u32>(),
            host.parse::<IpAddr>(),
        ) else {
            return false;
        };
        return match (red, ip) {
            (IpAddr::V4(r), IpAddr::V4(i)) if bits <= 32 => {
                let mascara = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
                u32::from(r) & mascara == u32::from(i) & mascara
            }
            (IpAddr::V6(r), IpAddr::V6(i)) if bits <= 128 => {
                let mascara = u128::MAX.checked_shl(128 - bits).unwrap_or(0);
                u128::from(r) & mascara == u128::from(i) & mascara
            }
            _ => false,
        };
    }
    let e = if entrada.parse::<IpAddr>().is_ok() {
        entrada
    } else {
        entrada.split(':').next().unwrap_or("")
    };
    let e = e.trim_start_matches("*.").trim_start_matches('.');
    !e.is_empty() && (host == e || host.ends_with(&format!(".{e}")))
}

fn proxy_para(host: &str) -> Result<Option<Proxy>, String> {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    if h.eq_ignore_ascii_case("localhost")
        || h.parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
    {
        return Ok(None);
    }
    let variable = |n: &str| {
        std::env::var(n)
            .ok()
            .or_else(|| std::env::var(n.to_lowercase()).ok())
            .filter(|v| !v.trim().is_empty())
    };
    let Some(url) = variable("HTTPS_PROXY") else {
        return Ok(None);
    };
    if let Some(excluidos) = variable("NO_PROXY") {
        let h = h.to_ascii_lowercase();
        for e in excluidos.split(',').map(|e| e.trim().to_ascii_lowercase()) {
            if excluido_del_proxy(&h, &e) {
                return Ok(None);
            }
        }
    }
    let resto = url
        .strip_prefix("http://")
        .or_else(|| (!url.contains("://")).then_some(url.as_str()))
        .ok_or("solo se admiten proxies http:// en HTTPS_PROXY")?;
    let resto = resto.split('/').next().unwrap_or("");
    let (credenciales, direccion) = match resto.rsplit_once('@') {
        Some((c, d)) => (Some(c), d),
        None => (None, resto),
    };
    let s = Servidor::interpretar(&format!("http://{direccion}"))?;
    let autorizacion = credenciales.map(|c| {
        use base64::Engine;
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(c)
        )
    });
    Ok(Some(Proxy {
        host: s.host,
        puerto: s.puerto,
        autorizacion,
    }))
}

fn tcp(host: &str, puerto: u16, tiempo: Duration) -> Result<TcpStream, String> {
    let direccion = (host, puerto)
        .to_socket_addrs()
        .map_err(|e| format!("no se pudo resolver {host}: {e}"))?
        .next()
        .ok_or("sin direcciones")?;
    if host.eq_ignore_ascii_case("localhost") && !direccion.ip().is_loopback() {
        return Err("localhost resolvió fuera de loopback".into());
    }
    let socket = TcpStream::connect_timeout(&direccion, tiempo)
        .map_err(|e| format!("no se pudo conectar a {host}: {e}"))?;
    socket.set_read_timeout(Some(tiempo * 6)).ok();
    socket.set_write_timeout(Some(tiempo)).ok();
    Ok(socket)
}

/// Conexión TCP al servidor, directa o por un túnel `CONNECT` del proxy.
fn conectar(servidor: &Servidor, tiempo: Duration) -> Result<TcpStream, String> {
    let proxy = if servidor.seguro {
        proxy_para(&servidor.host)?
    } else {
        None
    };
    let Some(p) = proxy else {
        return tcp(&servidor.host, servidor.puerto, tiempo);
    };
    let mut socket = tcp(&p.host, p.puerto, tiempo)?;
    let destino = if servidor.host.contains(':') {
        format!("[{}]:{}", servidor.host, servidor.puerto)
    } else {
        format!("{}:{}", servidor.host, servidor.puerto)
    };
    let mut solicitud = format!("CONNECT {destino} HTTP/1.1\r\nHost: {destino}\r\n");
    if let Some(a) = &p.autorizacion {
        solicitud.push_str(&format!("Proxy-Authorization: {a}\r\n"));
    }
    solicitud.push_str("\r\n");
    socket
        .write_all(solicitud.as_bytes())
        .map_err(|e| format!("proxy: {e}"))?;
    // Se lee byte a byte para no consumir nada del túnel.
    let mut cabecera = Vec::new();
    let mut byte = [0u8; 1];
    while !cabecera.ends_with(b"\r\n\r\n") {
        let n = socket.read(&mut byte).map_err(|e| format!("proxy: {e}"))?;
        if n == 0 || cabecera.len() > MAXIMO_CABECERA {
            return Err("el proxy cerró la conexión".into());
        }
        cabecera.push(byte[0]);
    }
    let estado = String::from_utf8_lossy(&cabecera)
        .split_whitespace()
        .nth(1)
        .unwrap_or("")
        .to_string();
    if estado != "200" {
        return Err(format!(
            "el proxy rechazó el túnel hacia {destino} (estado {estado})"
        ));
    }
    Ok(socket)
}

/// Abre un GET y devuelve la respuesta con el cuerpo como flujo.
pub fn abrir(
    servidor: &Servidor,
    ruta: &str,
    encabezados: &[(&str, &str)],
    cred: &Credenciales,
    confianza: &ConfianzaTls,
    tiempo: Duration,
) -> Result<RespuestaFlujo, String> {
    let socket = conectar(servidor, tiempo)?;

    let mut flujo: Box<dyn Flujo> = if servidor.seguro {
        let nombre_texto = confianza
            .nombre_servidor
            .clone()
            .unwrap_or_else(|| servidor.host.clone());
        let nombre = match nombre_texto.parse::<IpAddr>() {
            Ok(ip) => ServerName::IpAddress(ip.into()),
            Err(_) => ServerName::try_from(nombre_texto).map_err(|e| e.to_string())?,
        };
        let conexion =
            rustls::ClientConnection::new(Arc::new(configuracion_tls(confianza, cred)?), nombre)
                .map_err(|e| e.to_string())?;
        Box::new(rustls::StreamOwned::new(conexion, socket))
    } else {
        Box::new(socket)
    };

    let host = if servidor.host.contains(':') {
        format!("[{}]", servidor.host)
    } else {
        servidor.host.clone()
    };
    let predeterminado = if servidor.seguro { 443 } else { 80 };
    let host = if servidor.puerto == predeterminado {
        host
    } else {
        format!("{host}:{}", servidor.puerto)
    };
    let mut solicitud = format!(
        "GET {}{ruta} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: suaya/{}\r\nConnection: close\r\n",
        servidor.prefijo,
        suaya_core::VERSION
    );
    if !encabezados
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("accept"))
    {
        solicitud.push_str("Accept: application/json\r\n");
    }
    for (k, v) in encabezados {
        if k.contains(['\r', '\n']) || v.contains(['\r', '\n']) {
            return Err("encabezado HTTP inválido".into());
        }
        solicitud.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Some(t) = &cred.token {
        if t.contains(['\r', '\n']) {
            return Err("token inválido".into());
        }
        solicitud.push_str(&format!("Authorization: Bearer {t}\r\n"));
    }
    solicitud.push_str("\r\n");
    flujo
        .write_all(solicitud.as_bytes())
        .map_err(|e| e.to_string())?;
    leer_respuesta(Box::new(BufReader::with_capacity(
        64 * 1024,
        CierreTolerante(flujo),
    )))
}

/// Realiza un GET y devuelve el estado y el cuerpo completo.
pub fn get(
    servidor: &Servidor,
    ruta: &str,
    cred: &Credenciales,
    confianza: &ConfianzaTls,
    tiempo: Duration,
) -> Result<Respuesta, String> {
    let r = abrir(servidor, ruta, &[], cred, confianza, tiempo)?;
    let estado = r.estado;
    let cuerpo = r.leer_todo(MAXIMO_RESPUESTA)?;
    Ok(Respuesta { estado, cuerpo })
}

/// Separa estado, encabezados y cuerpo de una respuesta ya recibida.
pub fn interpretar_respuesta(bruto: &[u8]) -> Result<Respuesta, String> {
    let r = leer_respuesta(Box::new(Cursor::new(bruto.to_vec())))?;
    let estado = r.estado;
    let cuerpo = r.leer_todo(MAXIMO_RESPUESTA)?;
    Ok(Respuesta { estado, cuerpo })
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn fragmentado_y_longitud() {
        let r = interpretar_respuesta(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nhola\r\n6\r\n mundo\r\n0\r\n\r\n").unwrap();
        assert_eq!(
            (r.estado, r.cuerpo.as_slice()),
            (200, b"hola mundo".as_slice())
        );
        let r = interpretar_respuesta(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\nnoXX")
            .unwrap();
        assert_eq!((r.estado, r.cuerpo.as_slice()), (403, b"no".as_slice()));
        assert!(
            interpretar_respuesta(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\ncorto").is_err()
        );
        assert!(
            interpretar_respuesta(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nA\r\ncorto"
            )
            .is_err()
        );
        let r = interpretar_respuesta(b"HTTP/1.1 200 OK\r\n\r\nhasta el cierre").unwrap();
        assert_eq!(r.cuerpo, b"hasta el cierre");
    }

    #[test]
    fn exclusiones_del_proxy() {
        assert!(excluido_del_proxy("10.2.3.4", "10.0.0.0/8"));
        assert!(!excluido_del_proxy("11.2.3.4", "10.0.0.0/8"));
        assert!(excluido_del_proxy(
            "api.svc.cluster.local",
            "*.svc.cluster.local"
        ));
        assert!(excluido_del_proxy("registro.ejemplo.mx", ".ejemplo.mx"));
        assert!(excluido_del_proxy("ejemplo.mx", "ejemplo.mx:443"));
        assert!(!excluido_del_proxy("otroejemplo.mx", "ejemplo.mx"));
        assert!(excluido_del_proxy("fd00::1", "fd00::/8"));
        assert!(excluido_del_proxy("cualquiera", "*"));
    }

    #[test]
    fn servidores() {
        let s = Servidor::interpretar("https://10.0.0.1:6443").unwrap();
        assert!(s.seguro && s.host == "10.0.0.1" && s.puerto == 6443);
        let s = Servidor::interpretar("http://127.0.0.1:8001/k8s/").unwrap();
        assert!(!s.seguro && s.prefijo == "/k8s");
        let s = Servidor::interpretar("https://[fd00::1]").unwrap();
        assert_eq!((s.host.as_str(), s.puerto), ("fd00::1", 443));
        assert!(Servidor::interpretar("ftp://x").is_err());
    }
}
