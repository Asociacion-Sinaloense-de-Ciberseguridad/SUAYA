//! Diagnóstico de conectividad y de intercambio de llaves y certificados.
//!
//! El sondeo ([`crate::sondear`]) inventaría qué ofrece un servicio. El
//! diagnóstico responde a otra pregunta: qué obtiene realmente un cliente al
//! conectarse.
//!
//! - **Conectividad**: resolución del nombre, cada dirección IPv4 e IPv6 con
//!   su resultado TCP y su latencia, el preámbulo STARTTLS y el tiempo del
//!   saludo.
//! - **Intercambio de llaves**: dos saludos TLS completos, uno de un cliente
//!   moderno (ofrece X25519MLKEM768 primero) y otro de un cliente que solo
//!   conoce grupos clásicos. Registra la versión, la suite, el grupo
//!   negociado, si hizo falta un `HelloRetryRequest` y el esquema de firma
//!   del `CertificateVerify`. En SSH, el `KEXINIT` con sus extensiones.
//! - **Intercambio de certificados**: valida la cadena como lo haría un
//!   cliente estándar (autoridades del sistema y, opcionalmente, una propia),
//!   comprueba el nombre, el orden, la vigencia, las llaves y las firmas, el
//!   engrapado OCSP y el tamaño de la cadena.
//!
//! Suaya no envía datos de aplicación: completa el saludo, lee y cierra.
//! Cada objetivo TLS recibe una conexión por dirección más dos saludos.

use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use serde::Serialize;
use suaya_core::{Conocimiento, Riesgo};
use suaya_escaneo::api::resumen_certificado;

use crate::{Objetivo, Opciones, Protocolo, ssh, starttls};

/// Direcciones que se prueban como máximo por objetivo.
const MAXIMO_DIRECCIONES: usize = 8;
/// Un saludo más lento que esto se señala.
const SALUDO_LENTO_MS: u64 = 1000;
/// Una cadena más grande que esto se señala (crecerá con certificados ML-DSA).
const CADENA_GRANDE: usize = 10 * 1024;

// ---------------------------------------------------------------------------
// Resultado
// ---------------------------------------------------------------------------

/// Gravedad de un hallazgo del diagnóstico.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Nivel {
    Critico,
    Alto,
    Medio,
    Bajo,
    Info,
}

impl Nivel {
    pub fn interpretar(t: &str) -> Option<Self> {
        match t.trim().to_lowercase().as_str() {
            "critico" | "crítico" | "critical" => Some(Self::Critico),
            "alto" | "high" => Some(Self::Alto),
            "medio" | "medium" => Some(Self::Medio),
            "bajo" | "low" => Some(Self::Bajo),
            "info" => Some(Self::Info),
            _ => None,
        }
    }

    pub fn como_texto(self) -> &'static str {
        match self {
            Self::Critico => "critico",
            Self::Alto => "alto",
            Self::Medio => "medio",
            Self::Bajo => "bajo",
            Self::Info => "info",
        }
    }

    pub fn etiqueta(self) -> &'static str {
        use suaya_core::idioma::tx;
        match self {
            Self::Critico => tx("CRÍTICO", "CRITICAL"),
            Self::Alto => tx("ALTO", "HIGH"),
            Self::Medio => tx("MEDIO", "MEDIUM"),
            Self::Bajo => tx("BAJO", "LOW"),
            Self::Info => tx("INFO", "INFO"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Hallazgo {
    pub nivel: Nivel,
    /// Identificador estable (p. ej. `CERT-VENCE`), útil para filtrar.
    pub codigo: &'static str,
    pub mensaje: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EstadoTcp {
    Abierto,
    Rechazado,
    TiempoAgotado,
    Inalcanzable,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Direccion {
    pub ip: String,
    /// `ipv4` o `ipv6`.
    pub familia: &'static str,
    pub estado: EstadoTcp,
    pub milisegundos: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Conectividad {
    pub resolucion_ms: Option<u64>,
    pub error_resolucion: Option<String>,
    pub direcciones: Vec<Direccion>,
    /// Dirección usada para los saludos.
    pub direccion_usada: Option<String>,
    /// Resultado del preámbulo STARTTLS, si aplica.
    pub starttls: Option<String>,
    /// Duración del saludo TLS (cliente moderno) o de la lectura del `KEXINIT`.
    pub saludo_ms: Option<u64>,
}

impl Conectividad {
    pub fn alcanzable(&self) -> bool {
        self.direcciones
            .iter()
            .any(|d| d.estado == EstadoTcp::Abierto)
    }
}

/// Un saludo TLS completo con un perfil de cliente.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SaludoTls {
    /// `moderno` (ofrece híbridos poscuánticos) o `clasico`.
    pub cliente: &'static str,
    pub exito: bool,
    pub error: Option<String>,
    pub version: Option<String>,
    pub suite: Option<String>,
    pub grupo: Option<String>,
    pub riesgo_grupo: Option<Riesgo>,
    /// El servidor pidió otro `key_share` con un `HelloRetryRequest`.
    pub reintento: bool,
    pub alpn: Option<String>,
    /// Esquema de firma del `CertificateVerify` (o del `ServerKeyExchange`).
    pub esquema_firma: Option<String>,
    pub firma_verificada: Option<bool>,
    pub milisegundos: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IntercambioTls {
    pub moderno: SaludoTls,
    pub clasico: SaludoTls,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CertificadoDiag {
    pub nombre: String,
    pub sujeto: String,
    pub emisor: String,
    pub nombres_alternativos: Vec<String>,
    pub no_antes: String,
    pub no_despues: String,
    pub dias_restantes: i64,
    pub es_ca: bool,
    pub autofirmado: bool,
    pub algoritmo_llave: String,
    pub tamano_llave: Option<u32>,
    pub riesgo_llave: Riesgo,
    pub algoritmo_firma: String,
    pub riesgo_firma: Riesgo,
    pub huella_sha256: String,
    pub bytes: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CadenaCertificados {
    /// `None` si la cadena es válida para un cliente estándar.
    pub error_validacion: Option<String>,
    /// `None` si el certificado ampara el nombre solicitado.
    pub error_nombre: Option<String>,
    pub ocsp_engrapado: bool,
    pub bytes: usize,
    pub orden_correcto: bool,
    pub incluye_raiz: bool,
    pub certificados: Vec<CertificadoDiag>,
}

impl CadenaCertificados {
    pub fn valida(&self) -> bool {
        self.error_validacion.is_none() && self.error_nombre.is_none()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct IntercambioSsh {
    pub identificacion: String,
    pub kex: Vec<String>,
    /// Intercambios híbridos o poscuánticos según la base de conocimiento.
    pub kex_poscuanticos: Vec<String>,
    pub llaves_host: Vec<String>,
    pub cifrados: Vec<String>,
    pub macs: Vec<String>,
    pub extensiones: Vec<String>,
    /// Anuncia `kex-strict-s-v00@openssh.com` (mitigación de Terrapin).
    pub kex_estricto: bool,
}

/// Diagnóstico de un objetivo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Diagnostico {
    pub objetivo: String,
    /// `tls` o `ssh`.
    pub protocolo: &'static str,
    pub conectividad: Conectividad,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<IntercambioTls>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificados: Option<CadenaCertificados>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh: Option<IntercambioSsh>,
    pub hallazgos: Vec<Hallazgo>,
}

impl Diagnostico {
    fn nuevo(o: &Objetivo) -> Self {
        Self {
            objetivo: o.ubicacion(),
            protocolo: match o.protocolo {
                Protocolo::Tls => "tls",
                Protocolo::Ssh => "ssh",
            },
            conectividad: Conectividad::default(),
            tls: None,
            certificados: None,
            ssh: None,
            hallazgos: Vec::new(),
        }
    }

    /// El hallazgo más grave, si hay alguno.
    pub fn peor(&self) -> Option<Nivel> {
        self.hallazgos.iter().map(|h| h.nivel).min()
    }

    fn hallar(&mut self, nivel: Nivel, codigo: &'static str, mensaje: impl Into<String>) {
        self.hallazgos.push(Hallazgo {
            nivel,
            codigo,
            mensaje: mensaje.into(),
        });
    }
}

// ---------------------------------------------------------------------------
// Diagnóstico
// ---------------------------------------------------------------------------

/// Diagnostica cada objetivo en orden.
pub fn diagnosticar(objetivos: &[Objetivo], c: &Conocimiento, op: &Opciones) -> Vec<Diagnostico> {
    let verificador = verificador_estandar(op);
    objetivos
        .iter()
        .map(|o| diagnosticar_uno(o, c, op, verificador.as_ref()))
        .collect()
}

pub(crate) fn diagnosticar_uno(
    o: &Objetivo,
    c: &Conocimiento,
    op: &Opciones,
    verificador: Option<&Arc<WebPkiServerVerifier>>,
) -> Diagnostico {
    let mut d = Diagnostico::nuevo(o);
    let Some(direccion) = conectividad(o, op, &mut d.conectividad) else {
        evaluar(&mut d, o);
        return d;
    };
    d.conectividad.direccion_usada = Some(direccion.ip().to_string());
    match o.protocolo {
        Protocolo::Ssh => {
            let inicio = Instant::now();
            match conectar(direccion, op).and_then(|mut s| ssh::observar(&mut s)) {
                Ok((identificacion, k)) => {
                    d.conectividad.saludo_ms = Some(ms(inicio));
                    let kex_poscuanticos = k
                        .kex
                        .iter()
                        .filter(|n| {
                            c.por_alias("ssh-kex", n).is_some_and(|x| {
                                matches!(x.riesgo, Riesgo::HibridoPq | Riesgo::ResistenteCuantico)
                            })
                        })
                        .cloned()
                        .collect();
                    d.ssh = Some(IntercambioSsh {
                        identificacion,
                        kex_estricto: k.extensiones.iter().any(|e| e.starts_with("kex-strict-s")),
                        kex: k.kex,
                        kex_poscuanticos,
                        llaves_host: k.llaves_host,
                        cifrados: k.cifrados,
                        macs: k.macs,
                        extensiones: k.extensiones,
                    });
                }
                Err(e) => d.hallar(
                    Nivel::Critico,
                    "SSH-SALUDO",
                    format!("No se obtuvo el KEXINIT del servidor: {e}."),
                ),
            }
        }
        Protocolo::Tls => {
            if let Some(st) = o.starttls {
                match conectar(direccion, op).and_then(|mut s| st.preambulo(&mut s)) {
                    Ok(()) => {
                        d.conectividad.starttls =
                            Some(format!("{}: STARTTLS aceptado", st.nombre()))
                    }
                    Err(e) => {
                        let texto = e.strip_prefix(starttls::PREFIJO_SIN_TLS).unwrap_or(&e);
                        d.conectividad.starttls = Some(format!("{}: {texto}", st.nombre()));
                        d.hallar(
                            Nivel::Critico,
                            "CON-STARTTLS",
                            format!("El preámbulo STARTTLS falló: {texto}."),
                        );
                        evaluar(&mut d, o);
                        return d;
                    }
                }
            }
            let mut moderno = saludo_tls(o, direccion, op, c, verificador, false);
            let clasico = saludo_tls(o, direccion, op, c, verificador, true).0;
            // Un reinicio aislado de la conexión no demuestra intolerancia a los
            // saludos híbridos (más grandes): se confirma con un segundo intento.
            if !moderno.0.exito && clasico.exito {
                moderno = saludo_tls(o, direccion, op, c, verificador, false);
            }
            d.conectividad.saludo_ms = moderno.0.milisegundos;
            let captura = if moderno.0.exito {
                moderno.1
            } else {
                saludo_tls(o, direccion, op, c, verificador, true).1
            };
            if !captura.cadena.is_empty() {
                d.certificados = Some(cadena(&captura, c));
            }
            d.tls = Some(IntercambioTls {
                moderno: moderno.0,
                clasico,
            });
        }
    }
    evaluar(&mut d, o);
    d
}

fn ms(desde: Instant) -> u64 {
    desde.elapsed().as_millis().min(u64::MAX as u128) as u64
}

fn conectar(direccion: SocketAddr, op: &Opciones) -> Result<TcpStream, String> {
    let s = TcpStream::connect_timeout(&direccion, op.tiempo_limite)
        .map_err(|e| format!("no se pudo conectar a {direccion}: {e}"))?;
    s.set_read_timeout(Some(op.tiempo_limite)).ok();
    s.set_write_timeout(Some(op.tiempo_limite)).ok();
    Ok(s)
}

/// Resuelve el nombre y prueba cada dirección. Devuelve la primera abierta.
fn conectividad(o: &Objetivo, op: &Opciones, k: &mut Conectividad) -> Option<SocketAddr> {
    let inicio = Instant::now();
    let direcciones: Vec<SocketAddr> = match (o.host.as_str(), o.puerto).to_socket_addrs() {
        Ok(v) => {
            k.resolucion_ms = Some(ms(inicio));
            let mut unicas: Vec<SocketAddr> = Vec::new();
            for d in v {
                if !unicas.contains(&d) {
                    unicas.push(d);
                }
            }
            unicas.truncate(MAXIMO_DIRECCIONES);
            unicas
        }
        Err(e) => {
            k.error_resolucion = Some(e.to_string());
            return None;
        }
    };
    let mut primera = None;
    for d in direcciones {
        let inicio = Instant::now();
        let (estado, milisegundos, error) = match TcpStream::connect_timeout(&d, op.tiempo_limite) {
            Ok(_) => {
                primera.get_or_insert(d);
                (EstadoTcp::Abierto, Some(ms(inicio)), None)
            }
            Err(e) => {
                use std::io::ErrorKind::*;
                let estado = match e.kind() {
                    ConnectionRefused => EstadoTcp::Rechazado,
                    TimedOut | WouldBlock => EstadoTcp::TiempoAgotado,
                    HostUnreachable | NetworkUnreachable | AddrNotAvailable => {
                        EstadoTcp::Inalcanzable
                    }
                    _ => EstadoTcp::Error,
                };
                (estado, None, Some(e.to_string()))
            }
        };
        k.direcciones.push(Direccion {
            ip: d.ip().to_string(),
            familia: if d.is_ipv4() { "ipv4" } else { "ipv6" },
            estado,
            milisegundos,
            error,
        });
    }
    primera
}

// ---------------------------------------------------------------------------
// Saludo TLS con captura de lo que el servidor presenta
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
struct Captura {
    cadena: Vec<Vec<u8>>,
    validacion: Option<Result<(), String>>,
    nombre: Option<Result<(), String>>,
    ocsp: bool,
    esquema: Option<rustls::SignatureScheme>,
    firma: Option<Result<(), String>>,
}

/// Verificador que **registra** el resultado de la validación estándar en
/// lugar de abortar el saludo. Suaya no envía datos por esta conexión.
#[derive(Debug)]
struct Observador {
    estandar: Option<Arc<WebPkiServerVerifier>>,
    proveedor: Arc<CryptoProvider>,
    captura: Arc<Mutex<Captura>>,
}

impl Observador {
    fn con<R>(&self, f: impl FnOnce(&mut Captura) -> R) -> R {
        let mut g = self.captura.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut g)
    }
}

impl ServerCertVerifier for Observador {
    fn verify_server_cert(
        &self,
        hoja: &CertificateDer<'_>,
        intermedios: &[CertificateDer<'_>],
        nombre: &ServerName<'_>,
        ocsp: &[u8],
        ahora: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let validacion = match &self.estandar {
            Some(v) => v
                .verify_server_cert(hoja, intermedios, nombre, ocsp, ahora)
                .map(|_| ())
                .map_err(describir),
            None => Err("no hay autoridades de confianza disponibles en este equipo".into()),
        };
        let nombre = rustls::server::ParsedCertificate::try_from(hoja)
            .and_then(|p| rustls::client::verify_server_name(&p, nombre))
            .map_err(describir);
        self.con(|c| {
            c.cadena = std::iter::once(hoja)
                .chain(intermedios)
                .map(|x| x.as_ref().to_vec())
                .collect();
            c.ocsp = !ocsp.is_empty();
            c.validacion = Some(validacion);
            c.nombre = Some(nombre);
        });
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        mensaje: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let r = rustls::crypto::verify_tls12_signature(
            mensaje,
            cert,
            dss,
            &self.proveedor.signature_verification_algorithms,
        );
        self.con(|c| {
            c.esquema = Some(dss.scheme);
            c.firma = Some(r.map(|_| ()).map_err(describir));
        });
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        mensaje: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let r = rustls::crypto::verify_tls13_signature(
            mensaje,
            cert,
            dss,
            &self.proveedor.signature_verification_algorithms,
        );
        self.con(|c| {
            c.esquema = Some(dss.scheme);
            c.firma = Some(r.map(|_| ()).map_err(describir));
        });
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        crate::tls::SinVerificar(self.proveedor.clone()).supported_verify_schemes()
    }
}

/// Verificador estándar con las autoridades del sistema y la autoridad
/// adicional de las opciones. `None` si no hay ninguna autoridad utilizable.
pub(crate) fn verificador_estandar(op: &Opciones) -> Option<Arc<WebPkiServerVerifier>> {
    let mut raices = rustls::RootCertStore::empty();
    for c in rustls_native_certs::load_native_certs().certs {
        // Una autoridad del sistema que rustls no acepta se ignora.
        let _ = raices.add(c);
    }
    if let Some(pem) = &op.autoridad_pem {
        use rustls::pki_types::pem::PemObject;
        for c in CertificateDer::pem_slice_iter(pem).flatten() {
            let _ = raices.add(c);
        }
    }
    if raices.is_empty() {
        return None;
    }
    WebPkiServerVerifier::builder_with_provider(
        Arc::new(raices),
        Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
    )
    .build()
    .ok()
}

/// Describe en español los errores de verificación más comunes.
fn describir(e: rustls::Error) -> String {
    use rustls::CertificateError as C;
    match &e {
        rustls::Error::InvalidCertificate(ce) => match ce {
            C::Expired | C::ExpiredContext { .. } => "certificado vencido".into(),
            C::NotValidYet | C::NotValidYetContext { .. } => "certificado aún no vigente".into(),
            C::UnknownIssuer => {
                "emisor desconocido: la cadena no llega a una autoridad de confianza".into()
            }
            C::BadSignature => "firma inválida en la cadena".into(),
            C::NotValidForName | C::NotValidForNameContext { .. } => {
                "el certificado no ampara el nombre solicitado".into()
            }
            C::Revoked => "certificado revocado".into(),
            C::InvalidPurpose | C::InvalidPurposeContext { .. } => {
                "el certificado no está autorizado para autenticar servidores".into()
            }
            C::UnsupportedSignatureAlgorithmContext { .. }
            | C::UnsupportedSignatureAlgorithmForPublicKeyContext { .. } => {
                "algoritmo de firma no soportado por el verificador".into()
            }
            otro => format!("certificado inválido ({otro:?})"),
        },
        rustls::Error::PeerMisbehaved(_) | rustls::Error::PeerIncompatible(_) => {
            format!("incompatibilidad con el servidor ({e})")
        }
        rustls::Error::AlertReceived(a) => format!("el servidor respondió con la alerta {a:?}"),
        _ => e.to_string(),
    }
}

fn texto_version(v: rustls::ProtocolVersion) -> String {
    match v {
        rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3".into(),
        rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2".into(),
        otra => format!("{otra:?}"),
    }
}

/// Un saludo completo. `clasico` limita los grupos a los vulnerables a
/// cómputo cuántico, como un cliente sin soporte poscuántico.
fn saludo_tls(
    o: &Objetivo,
    direccion: SocketAddr,
    op: &Opciones,
    c: &Conocimiento,
    estandar: Option<&Arc<WebPkiServerVerifier>>,
    clasico: bool,
) -> (SaludoTls, Captura) {
    let mut r = SaludoTls {
        cliente: if clasico { "clasico" } else { "moderno" },
        ..SaludoTls::default()
    };
    let captura = Arc::new(Mutex::new(Captura::default()));
    let resultado = (|| -> Result<(), String> {
        let mut proveedor = rustls::crypto::aws_lc_rs::default_provider();
        if clasico {
            proveedor
                .kx_groups
                .retain(|g: &&'static dyn SupportedKxGroup| {
                    c.por_codigo_tls(u16::from(g.name()))
                        .is_some_and(|d| d.riesgo == Riesgo::VulnerableCuantico)
                });
        }
        let proveedor = Arc::new(proveedor);
        let mut config = rustls::ClientConfig::builder_with_provider(proveedor.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Observador {
                estandar: estandar.cloned(),
                proveedor,
                captura: captura.clone(),
            }))
            .with_no_client_auth();
        config.resumption = rustls::client::Resumption::disabled();
        // ALPN solo en puertos HTTPS: otros servicios pueden rechazar el saludo
        // con no_application_protocol si reciben protocolos que no conocen.
        if o.starttls.is_none() && matches!(o.puerto, 443 | 8443) {
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        }
        let nombre = ServerName::try_from(o.host.clone()).map_err(|e| e.to_string())?;
        let mut conexion =
            rustls::ClientConnection::new(Arc::new(config), nombre).map_err(describir)?;
        let mut socket = conectar(direccion, op)?;
        if let Some(st) = o.starttls {
            st.preambulo(&mut socket)?;
        }
        let inicio = Instant::now();
        while conexion.is_handshaking() {
            conexion.complete_io(&mut socket).map_err(|e| {
                match e.get_ref().and_then(|x| x.downcast_ref::<rustls::Error>()) {
                    Some(t) => describir(t.clone()),
                    None if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                    {
                        "el servidor no respondió a tiempo".into()
                    }
                    None => e.to_string(),
                }
            })?;
        }
        r.milisegundos = Some(ms(inicio));
        r.version = conexion.protocol_version().map(texto_version);
        r.suite = conexion
            .negotiated_cipher_suite()
            .map(|s| format!("{:?}", s.suite()));
        if let Some(g) = conexion.negotiated_key_exchange_group() {
            let codigo = u16::from(g.name());
            match c.por_codigo_tls(codigo) {
                Some(def) => {
                    r.grupo = Some(crate::tls::nombre_grupo(codigo, def));
                    r.riesgo_grupo = Some(def.riesgo);
                }
                None => r.grupo = Some(format!("0x{codigo:04x}")),
            }
        }
        r.reintento =
            conexion.handshake_kind() == Some(rustls::HandshakeKind::FullWithHelloRetryRequest);
        r.alpn = conexion
            .alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).into_owned());
        conexion.send_close_notify();
        let _ = conexion.complete_io(&mut socket);
        Ok(())
    })();
    let captura = captura.lock().unwrap_or_else(|e| e.into_inner()).clone();
    match resultado {
        Ok(()) => r.exito = true,
        Err(e) => r.error = Some(e),
    }
    r.esquema_firma = captura.esquema.map(|e| format!("{e:?}"));
    r.firma_verificada = captura.firma.as_ref().map(Result::is_ok);
    (r, captura)
}

fn cadena(captura: &Captura, c: &Conocimiento) -> CadenaCertificados {
    let resumenes: Vec<_> = captura
        .cadena
        .iter()
        .filter_map(|der| resumen_certificado(der, c).ok())
        .collect();
    let orden_correcto = resumenes
        .windows(2)
        .all(|par| par[0].emisor_der == par[1].sujeto_der);
    CadenaCertificados {
        error_validacion: captura.validacion.clone().and_then(Result::err),
        error_nombre: captura.nombre.clone().and_then(Result::err),
        ocsp_engrapado: captura.ocsp,
        bytes: captura.cadena.iter().map(Vec::len).sum(),
        orden_correcto,
        incluye_raiz: resumenes.len() > 1
            && resumenes.last().is_some_and(|r| r.autofirmado && r.es_ca),
        certificados: resumenes
            .into_iter()
            .map(|r| CertificadoDiag {
                nombre: r.nombre,
                sujeto: r.sujeto,
                emisor: r.emisor,
                nombres_alternativos: r.nombres_alternativos,
                no_antes: r.no_antes,
                no_despues: r.no_despues,
                dias_restantes: r.dias_restantes,
                es_ca: r.es_ca,
                autofirmado: r.autofirmado,
                algoritmo_llave: r.algoritmo_llave,
                tamano_llave: r.tamano_llave,
                riesgo_llave: r.riesgo_llave,
                algoritmo_firma: r.algoritmo_firma,
                riesgo_firma: r.riesgo_firma,
                huella_sha256: r.huella_sha256,
                bytes: r.tamano_der,
            })
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// Hallazgos
// ---------------------------------------------------------------------------

fn es_pq(r: Option<Riesgo>) -> bool {
    matches!(r, Some(Riesgo::HibridoPq | Riesgo::ResistenteCuantico))
}

/// Deriva los hallazgos de lo observado. No hace conexiones.
pub(crate) fn evaluar(d: &mut Diagnostico, o: &Objetivo) {
    evaluar_conectividad(d, o);
    if let Some(t) = d.tls.clone() {
        evaluar_tls(d, &t);
    }
    if let Some(k) = d.certificados.clone() {
        evaluar_certificados(d, &k, o);
    }
    if let Some(s) = d.ssh.clone() {
        evaluar_ssh(d, &s);
    }
    d.hallazgos.sort_by_key(|h| h.nivel);
}

fn evaluar_conectividad(d: &mut Diagnostico, o: &Objetivo) {
    let k = d.conectividad.clone();
    if let Some(e) = &k.error_resolucion {
        d.hallar(
            Nivel::Critico,
            "CON-DNS",
            format!("No se pudo resolver {}: {e}.", o.host),
        );
        return;
    }
    let cerradas = k
        .direcciones
        .iter()
        .filter(|x| x.estado != EstadoTcp::Abierto)
        .count();
    if !k.alcanzable() {
        d.hallar(
            Nivel::Critico,
            "CON-TCP",
            format!(
                "Ninguna dirección aceptó la conexión en el puerto {}.",
                o.puerto
            ),
        );
        return;
    }
    let solo_ipv6 = k
        .direcciones
        .iter()
        .filter(|x| x.estado != EstadoTcp::Abierto)
        .all(|x| x.familia == "ipv6")
        && k.direcciones
            .iter()
            .any(|x| x.familia == "ipv4" && x.estado == EstadoTcp::Abierto);
    if cerradas > 0 && solo_ipv6 {
        // Sin ruta IPv6 en el equipo que diagnostica, todas las IPv6 fallan
        // igual: no se puede atribuir al servicio con certeza.
        d.hallar(
            Nivel::Bajo,
            "CON-IPV6-FALLA",
            format!(
                "{cerradas} direcciones IPv6 no aceptaron la conexión y las IPv4 sí: revisar el servicio en IPv6, salvo que este equipo no tenga conectividad IPv6."
            ),
        );
    } else if cerradas > 0 {
        d.hallar(
            Nivel::Medio,
            "CON-TCP-PARCIAL",
            format!(
                "{cerradas} de {} direcciones no aceptaron la conexión: los clientes pueden fallar de forma intermitente.",
                k.direcciones.len()
            ),
        );
    }
    if o.host.parse::<IpAddr>().is_err() && k.direcciones.iter().all(|x| x.familia == "ipv4") {
        d.hallar(
            Nivel::Info,
            "CON-IPV6",
            "El nombre no publica direcciones IPv6.",
        );
    }
    if let Some(t) = k.saludo_ms.filter(|t| *t > SALUDO_LENTO_MS) {
        d.hallar(Nivel::Bajo, "CON-LENTO", format!("El saludo tardó {t} ms."));
    }
}

fn evaluar_tls(d: &mut Diagnostico, t: &IntercambioTls) {
    let m = &t.moderno;
    if !m.exito {
        let error = m.error.clone().unwrap_or_default();
        if t.clasico.exito {
            d.hallar(
                Nivel::Alto,
                "KEX-SALUDO",
                format!("El saludo de un cliente moderno falló ({error}), pero el de un cliente clásico funcionó."),
            );
        } else {
            d.hallar(
                Nivel::Alto,
                "KEX-SALUDO",
                format!("Ningún saludo TLS 1.2 o 1.3 completo funcionó: {error}."),
            );
        }
        return;
    }
    let grupo = m
        .grupo
        .clone()
        .unwrap_or_else(|| "un grupo desconocido".into());
    if m.version.as_deref() == Some("TLSv1.2") {
        d.hallar(
            Nivel::Alto,
            "KEX-TLS12",
            "Con un cliente moderno negocia TLS 1.2: no hay intercambio de llaves híbrido poscuántico.",
        );
    } else if es_pq(m.riesgo_grupo) {
        d.hallar(
            Nivel::Info,
            "KEX-PQ",
            format!("Negocia {grupo} con un cliente moderno: protegido contra «capturar ahora, descifrar después»."),
        );
    } else {
        d.hallar(
            Nivel::Alto,
            "KEX-CLASICO",
            format!("Negocia {grupo} aunque el cliente ofrece X25519MLKEM768: el tráfico queda expuesto a «capturar ahora, descifrar después»."),
        );
    }
    if m.reintento {
        d.hallar(
            Nivel::Bajo,
            "KEX-HRR",
            format!("El servidor pidió un HelloRetryRequest para negociar {grupo}: un viaje de ida y vuelta adicional por conexión."),
        );
    }
    if let Some(esquema) = &m.esquema_firma {
        if esquema.starts_with("ML_DSA") {
            d.hallar(
                Nivel::Info,
                "KEX-FIRMA-PQ",
                format!("El servidor firma el saludo con {esquema}: autenticación poscuántica."),
            );
        } else if m.firma_verificada == Some(false) {
            d.hallar(
                Nivel::Alto,
                "KEX-FIRMA",
                format!("La firma del saludo ({esquema}) no se pudo verificar con la llave del certificado."),
            );
        }
    }
    if !t.clasico.exito {
        d.hallar(
            Nivel::Medio,
            "KEX-COMPAT",
            format!(
                "Rechaza a los clientes que solo ofrecen grupos clásicos ({}): verificar la compatibilidad con clientes antiguos.",
                t.clasico.error.clone().unwrap_or_default()
            ),
        );
    }
}

fn evaluar_certificados(d: &mut Diagnostico, k: &CadenaCertificados, o: &Objetivo) {
    if k.error_nombre.is_some() {
        let nombres = k
            .certificados
            .first()
            .map(|h| h.nombres_alternativos.join(", "))
            .unwrap_or_default();
        d.hallar(
            Nivel::Critico,
            "CERT-NOMBRE",
            if nombres.is_empty() {
                format!("El certificado no ampara el nombre {}.", o.host)
            } else {
                format!(
                    "El certificado no ampara el nombre {} (ampara: {nombres}).",
                    o.host
                )
            },
        );
    }
    // Un vencimiento ya se informa certificado por certificado.
    let vencimiento_informado = k.certificados.iter().any(|x| x.dias_restantes < 0);
    if let Some(e) = &k.error_validacion
        && Some(e) != k.error_nombre.as_ref()
        && !(e == "certificado vencido" && vencimiento_informado)
    {
        d.hallar(
            Nivel::Critico,
            "CERT-CADENA",
            format!("La cadena no es válida para un cliente estándar: {e}."),
        );
        if e.starts_with("emisor desconocido")
            && let Some(ultimo) = k.certificados.last()
            && !ultimo.autofirmado
        {
            d.hallar(
                Nivel::Medio,
                "CERT-INCOMPLETA",
                format!(
                    "La cadena termina en «{}» sin llegar a una raíz: puede faltar un certificado intermedio.",
                    ultimo.nombre
                ),
            );
        }
    }
    let Some(hoja) = k.certificados.first() else {
        return;
    };
    match hoja.dias_restantes {
        n if n < 0 => d.hallar(
            Nivel::Critico,
            "CERT-VENCIDO",
            format!("El certificado del servidor venció el {}.", hoja.no_despues),
        ),
        n if n <= 14 => d.hallar(
            Nivel::Alto,
            "CERT-VENCE",
            format!("El certificado del servidor vence en {n} días."),
        ),
        n if n <= 30 => d.hallar(
            Nivel::Medio,
            "CERT-VENCE",
            format!("El certificado del servidor vence en {n} días."),
        ),
        _ => {}
    }
    if hoja.autofirmado {
        d.hallar(
            Nivel::Alto,
            "CERT-AUTOFIRMADO",
            "El servidor presenta un certificado autofirmado.",
        );
    }
    let llave = match hoja.tamano_llave {
        Some(t) => format!("{} de {t} bits", hoja.algoritmo_llave),
        None => hoja.algoritmo_llave.clone(),
    };
    match hoja.riesgo_llave {
        Riesgo::RotoClasico | Riesgo::Obsoleto => d.hallar(
            Nivel::Critico,
            "CERT-LLAVE",
            format!("La llave del certificado ({llave}) es insegura hoy."),
        ),
        Riesgo::VulnerableCuantico => d.hallar(
            Nivel::Medio,
            "CERT-LLAVE-CUANTICA",
            format!("La llave del certificado ({llave}) es vulnerable a cómputo cuántico: planear la migración a ML-DSA o a certificados compuestos."),
        ),
        _ => {}
    }
    for (i, x) in k.certificados.iter().enumerate() {
        // La firma propia de una raíz no aporta seguridad.
        if x.autofirmado && x.es_ca {
            continue;
        }
        if matches!(x.riesgo_firma, Riesgo::RotoClasico) {
            d.hallar(
                Nivel::Alto,
                "CERT-FIRMA",
                format!(
                    "«{}» está firmado con {}, roto hoy.",
                    x.nombre, x.algoritmo_firma
                ),
            );
        }
        if i > 0 && x.dias_restantes < 0 {
            d.hallar(
                Nivel::Alto,
                "CERT-INTERMEDIO-VENCIDO",
                format!("«{}» de la cadena venció el {}.", x.nombre, x.no_despues),
            );
        }
    }
    if !k.orden_correcto {
        d.hallar(
            Nivel::Bajo,
            "CERT-ORDEN",
            "La cadena no está en orden: cada certificado debe ir seguido de su emisor.",
        );
    }
    if k.incluye_raiz {
        d.hallar(
            Nivel::Info,
            "CERT-RAIZ",
            "La cadena incluye la raíz autofirmada: el cliente ya la tiene y se envía en cada saludo.",
        );
    }
    if k.bytes > CADENA_GRANDE {
        d.hallar(
            Nivel::Info,
            "CERT-TAMANO",
            format!("La cadena ocupa {} bytes: con certificados ML-DSA crecerá, conviene enviar solo los intermedios necesarios.", k.bytes),
        );
    }
    if !k.ocsp_engrapado {
        d.hallar(
            Nivel::Info,
            "CERT-OCSP",
            "El servidor no engrapa la respuesta OCSP.",
        );
    }
}

fn evaluar_ssh(d: &mut Diagnostico, s: &IntercambioSsh) {
    let version = s.identificacion.split('-').nth(1).unwrap_or("");
    if version.starts_with('1') && version != "1.99" {
        d.hallar(
            Nivel::Critico,
            "SSH-V1",
            format!("El servidor anuncia el protocolo SSH {version}; SSH-1 está roto."),
        );
    }
    if s.kex_poscuanticos.is_empty() {
        d.hallar(
            Nivel::Alto,
            "SSH-KEX-CLASICO",
            "No ofrece intercambio de llaves poscuántico (mlkem768x25519-sha256 o sntrup761x25519-sha512).",
        );
    } else {
        d.hallar(
            Nivel::Info,
            "SSH-KEX-PQ",
            format!(
                "Ofrece intercambio de llaves híbrido poscuántico: {}.",
                s.kex_poscuanticos.join(", ")
            ),
        );
    }
    let afectado_terrapin = s
        .cifrados
        .iter()
        .any(|x| x.starts_with("chacha20-poly1305"))
        || s.macs.iter().any(|x| x.contains("-etm@"));
    if afectado_terrapin && !s.kex_estricto {
        d.hallar(
            Nivel::Medio,
            "SSH-TERRAPIN",
            "Ofrece ChaCha20-Poly1305 o MAC «etm» sin anunciar «strict KEX»: expuesto a Terrapin (CVE-2023-48795).",
        );
    }
    if !s.llaves_host.is_empty()
        && s.llaves_host
            .iter()
            .all(|x| matches!(x.as_str(), "ssh-rsa" | "ssh-dss"))
    {
        d.hallar(
            Nivel::Alto,
            "SSH-LLAVE-HOST",
            format!(
                "Las llaves de host solo se anuncian con firmas SHA-1 o DSA: {}.",
                s.llaves_host.join(", ")
            ),
        );
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn objetivo(t: &str) -> Objetivo {
        Objetivo::interpretar(t).unwrap()
    }

    /// Diagnóstico con una dirección abierta, para evaluar solo lo demás.
    fn alcanzado(o: &Objetivo) -> Diagnostico {
        let mut d = Diagnostico::nuevo(o);
        d.conectividad.direcciones.push(Direccion {
            ip: "192.0.2.1".into(),
            familia: "ipv6",
            estado: EstadoTcp::Abierto,
            milisegundos: Some(1),
            error: None,
        });
        d
    }

    fn codigos(d: &Diagnostico) -> Vec<&'static str> {
        d.hallazgos.iter().map(|h| h.codigo).collect()
    }

    fn certificado(dias: i64) -> CertificadoDiag {
        CertificadoDiag {
            nombre: "srv".into(),
            sujeto: "CN=srv".into(),
            emisor: "CN=CA".into(),
            nombres_alternativos: vec!["srv.ejemplo.mx".into()],
            no_antes: "2026-01-01T00:00:00Z".into(),
            no_despues: "2027-01-01T00:00:00Z".into(),
            dias_restantes: dias,
            es_ca: false,
            autofirmado: false,
            algoritmo_llave: "ECDSA P-256".into(),
            tamano_llave: Some(256),
            riesgo_llave: Riesgo::VulnerableCuantico,
            algoritmo_firma: "ECDSA con SHA-256".into(),
            riesgo_firma: Riesgo::VulnerableCuantico,
            huella_sha256: "00".into(),
            bytes: 800,
        }
    }

    #[test]
    fn niveles_ordenados_e_interpretados() {
        assert!(Nivel::Critico < Nivel::Alto && Nivel::Bajo < Nivel::Info);
        assert_eq!(Nivel::interpretar("crítico"), Some(Nivel::Critico));
        assert_eq!(Nivel::interpretar("HIGH"), Some(Nivel::Alto));
        assert_eq!(Nivel::interpretar("x"), None);
    }

    #[test]
    fn sin_resolucion_es_critico_y_detiene_la_evaluacion() {
        let o = objetivo("tls://no-existe.invalid:443");
        let mut d = Diagnostico::nuevo(&o);
        d.conectividad.error_resolucion = Some("nombre desconocido".into());
        evaluar(&mut d, &o);
        assert_eq!(codigos(&d), vec!["CON-DNS"]);
        assert_eq!(d.peor(), Some(Nivel::Critico));
    }

    #[test]
    fn direcciones_parciales_y_sin_ipv6() {
        let o = objetivo("tls://srv.ejemplo.mx:443");
        let mut d = Diagnostico::nuevo(&o);
        for (ip, estado) in [
            ("192.0.2.1", EstadoTcp::Abierto),
            ("192.0.2.2", EstadoTcp::TiempoAgotado),
        ] {
            d.conectividad.direcciones.push(Direccion {
                ip: ip.into(),
                familia: "ipv4",
                estado,
                milisegundos: None,
                error: None,
            });
        }
        d.conectividad.saludo_ms = Some(1500);
        evaluar(&mut d, &o);
        let c = codigos(&d);
        assert!(c.contains(&"CON-TCP-PARCIAL"));
        assert!(c.contains(&"CON-IPV6"));
        assert!(c.contains(&"CON-LENTO"));
    }

    #[test]
    fn fallas_solo_en_ipv6_no_se_atribuyen_al_servicio() {
        let o = objetivo("tls://srv.ejemplo.mx:443");
        let mut d = Diagnostico::nuevo(&o);
        for (ip, familia, estado) in [
            ("192.0.2.1", "ipv4", EstadoTcp::Abierto),
            ("2001:db8::1", "ipv6", EstadoTcp::TiempoAgotado),
        ] {
            d.conectividad.direcciones.push(Direccion {
                ip: ip.into(),
                familia,
                estado,
                milisegundos: None,
                error: None,
            });
        }
        evaluar(&mut d, &o);
        let c = codigos(&d);
        assert!(c.contains(&"CON-IPV6-FALLA"));
        assert!(!c.contains(&"CON-TCP-PARCIAL") && !c.contains(&"CON-IPV6"));
    }

    #[test]
    fn intercambio_clasico_con_reintento() {
        let o = objetivo("tls://127.0.0.1:443");
        let mut d = alcanzado(&o);
        d.tls = Some(IntercambioTls {
            moderno: SaludoTls {
                cliente: "moderno",
                exito: true,
                version: Some("TLSv1.3".into()),
                grupo: Some("secp256r1".into()),
                riesgo_grupo: Some(Riesgo::VulnerableCuantico),
                reintento: true,
                ..SaludoTls::default()
            },
            clasico: SaludoTls {
                cliente: "clasico",
                exito: true,
                ..SaludoTls::default()
            },
        });
        evaluar(&mut d, &o);
        let c = codigos(&d);
        assert!(c.contains(&"KEX-CLASICO") && c.contains(&"KEX-HRR"));
        assert!(!c.contains(&"KEX-COMPAT"));
    }

    #[test]
    fn certificados_por_vencer_y_cadena_incompleta() {
        let o = objetivo("tls://srv.ejemplo.mx:443");
        let mut d = alcanzado(&o);
        let mut intermedio = certificado(400);
        intermedio.es_ca = true;
        intermedio.nombre = "Intermedia".into();
        d.certificados = Some(CadenaCertificados {
            error_validacion: Some(
                "emisor desconocido: la cadena no llega a una autoridad de confianza".into(),
            ),
            error_nombre: None,
            ocsp_engrapado: true,
            bytes: 1600,
            orden_correcto: true,
            incluye_raiz: false,
            certificados: vec![certificado(10), intermedio],
        });
        evaluar(&mut d, &o);
        let c = codigos(&d);
        for esperado in [
            "CERT-CADENA",
            "CERT-INCOMPLETA",
            "CERT-VENCE",
            "CERT-LLAVE-CUANTICA",
        ] {
            assert!(c.contains(&esperado), "{esperado}: {c:?}");
        }
        assert!(!c.contains(&"CERT-OCSP"));
        let vence = d
            .hallazgos
            .iter()
            .find(|h| h.codigo == "CERT-VENCE")
            .unwrap();
        assert_eq!(vence.nivel, Nivel::Alto);
    }

    #[test]
    fn nombre_incorrecto_no_se_duplica_como_cadena() {
        let o = objetivo("tls://otro.ejemplo.mx:443");
        let mut d = alcanzado(&o);
        let error = "el certificado no ampara el nombre solicitado".to_string();
        d.certificados = Some(CadenaCertificados {
            error_validacion: Some(error.clone()),
            error_nombre: Some(error),
            ocsp_engrapado: true,
            orden_correcto: true,
            certificados: vec![certificado(200)],
            ..CadenaCertificados::default()
        });
        evaluar(&mut d, &o);
        let c = codigos(&d);
        assert!(c.contains(&"CERT-NOMBRE"));
        assert!(!c.contains(&"CERT-CADENA"));
    }

    #[test]
    fn ssh_sin_poscuantico_ni_strict_kex() {
        let o = objetivo("ssh://bastion:22");
        let mut d = alcanzado(&o);
        d.ssh = Some(IntercambioSsh {
            identificacion: "SSH-2.0-OpenSSH_8.2".into(),
            kex: vec!["curve25519-sha256".into()],
            llaves_host: vec!["ssh-rsa".into()],
            cifrados: vec!["chacha20-poly1305@openssh.com".into()],
            macs: vec!["hmac-sha2-256".into()],
            ..IntercambioSsh::default()
        });
        evaluar(&mut d, &o);
        let c = codigos(&d);
        for esperado in ["SSH-KEX-CLASICO", "SSH-TERRAPIN", "SSH-LLAVE-HOST"] {
            assert!(c.contains(&esperado), "{esperado}: {c:?}");
        }
        assert_eq!(d.hallazgos[0].nivel, Nivel::Alto);
    }
}
