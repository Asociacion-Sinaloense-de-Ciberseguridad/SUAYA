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
//!   engrapado OCSP, el tamaño de la cadena y la vigencia máxima que fija el
//!   CA/Browser Forum.
//! - **DNS** (`dns://`): DNSSEC, delegación, firmas, CAA, TLSA y DKIM.
//! - **Identidad federada** (`oidc://`, `saml://`): algoritmos anunciados,
//!   llaves JWKS y certificados de los metadatos.
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
/// Vigencia máxima, en días, de los certificados TLS de autoridades públicas
/// según su fecha de emisión (CA/Browser Forum, boleta SC-081v3, abril de
/// 2025): 398 días antes del 15 de marzo de 2026 y después 200, 100 y 47.
const VIGENCIA_MAXIMA: [(&str, i64); 4] = [
    ("0000-01-01", 398),
    ("2026-03-15", 200),
    ("2027-03-15", 100),
    ("2029-03-15", 47),
];

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

/// Receta de corrección para hallazgos del diagnóstico (`remediacion.toml`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecetaDiag {
    pub id: String,
    pub titulo: String,
    pub pasos: Vec<String>,
    /// Hallazgos que corrige.
    pub hallazgos: Vec<&'static str>,
}

/// Lo publicado en el DNS de un dominio.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct IntercambioDns {
    pub resolvedor: String,
    /// El resolvedor validó la cadena DNSSEC (bit AD).
    pub validada: bool,
    pub llaves: Vec<String>,
    pub delegaciones: Vec<String>,
    pub firmas: Vec<String>,
    pub caa: Vec<String>,
    pub tlsa: Vec<String>,
    pub dkim: Vec<String>,
}

/// Lo publicado por un proveedor de identidad (OpenID Connect o SAML).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct IntercambioIdentidad {
    pub documento: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emisor: Option<String>,
    /// Algoritmos anunciados por uso, o métodos de los metadatos SAML.
    pub algoritmos: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<String>,
    pub llaves: Vec<String>,
    pub certificados: Vec<String>,
}

/// Lo observado en un servidor IKEv2.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct IntercambioIke {
    pub grupos: Vec<String>,
    pub preferido: Option<String>,
    pub elegidas: Vec<String>,
    pub mlkem: Option<String>,
    pub acepta_3des: bool,
    pub acepta_sha1: bool,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ike: Option<IntercambioIke>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<IntercambioDns>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identidad: Option<IntercambioIdentidad>,
    pub hallazgos: Vec<Hallazgo>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub recetas: Vec<RecetaDiag>,
}

impl Diagnostico {
    fn nuevo(o: &Objetivo) -> Self {
        Self {
            objetivo: o.ubicacion(),
            protocolo: match o.protocolo {
                Protocolo::Tls => "tls",
                Protocolo::Ssh => "ssh",
                Protocolo::Ike => "ike",
                Protocolo::Dns => "dns",
                Protocolo::Oidc => "oidc",
                Protocolo::Saml => "saml",
            },
            conectividad: Conectividad::default(),
            tls: None,
            certificados: None,
            ssh: None,
            ike: None,
            dns: None,
            identidad: None,
            hallazgos: Vec::new(),
            recetas: Vec::new(),
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
// Métricas
// ---------------------------------------------------------------------------

/// Valor de etiqueta en el formato de texto de Prometheus.
fn etiqueta_prometheus(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

impl Diagnostico {
    /// Ofrece o negocia un intercambio o una firma híbrida o poscuántica.
    pub fn poscuantico(&self) -> bool {
        self.tls.as_ref().is_some_and(|t| {
            matches!(
                t.moderno.riesgo_grupo,
                Some(Riesgo::HibridoPq | Riesgo::ResistenteCuantico)
            )
        }) || self.hallazgos.iter().any(|h| h.codigo.ends_with("-PQ"))
    }
}

/// Diagnósticos en el formato de texto de Prometheus, p. ej. para el
/// recolector de archivos de texto de node_exporter.
pub fn metricas_prometheus(diagnosticos: &[Diagnostico]) -> String {
    let mut s = String::new();
    let mut metrica = |nombre: &str,
                       ayuda_es: &'static str,
                       ayuda_en: &'static str,
                       filas: Vec<(String, String)>| {
        if filas.is_empty() {
            return;
        }
        let ayuda = suaya_core::idioma::tx(ayuda_es, ayuda_en);
        s.push_str(&format!("# HELP {nombre} {ayuda}\n# TYPE {nombre} gauge\n"));
        for (etiquetas, valor) in filas {
            s.push_str(&format!("{nombre}{{{etiquetas}}} {valor}\n"));
        }
    };
    let obj = |d: &Diagnostico| format!("objetivo=\"{}\"", etiqueta_prometheus(&d.objetivo));
    metrica(
        "suaya_diagnostico_info",
        "Objetivo diagnosticado por Suaya.",
        "Target diagnosed by Suaya.",
        diagnosticos
            .iter()
            .map(|d| {
                (
                    format!(
                        "{},protocolo=\"{}\",version=\"{}\"",
                        obj(d),
                        d.protocolo,
                        suaya_core::VERSION
                    ),
                    "1".into(),
                )
            })
            .collect(),
    );
    metrica(
        "suaya_diagnostico_alcanzable",
        "1 si el objetivo respondió.",
        "1 if the target answered.",
        diagnosticos
            .iter()
            .map(|d| {
                let alcanzable = d.conectividad.alcanzable() || d.conectividad.saludo_ms.is_some();
                (obj(d), u8::from(alcanzable).to_string())
            })
            .collect(),
    );
    metrica(
        "suaya_diagnostico_hallazgos",
        "Hallazgos del diagnóstico por nivel.",
        "Diagnosis findings by level.",
        diagnosticos
            .iter()
            .flat_map(|d| {
                [
                    Nivel::Critico,
                    Nivel::Alto,
                    Nivel::Medio,
                    Nivel::Bajo,
                    Nivel::Info,
                ]
                .map(|n| {
                    (
                        format!("{},nivel=\"{}\"", obj(d), n.como_texto()),
                        d.hallazgos
                            .iter()
                            .filter(|h| h.nivel == n)
                            .count()
                            .to_string(),
                    )
                })
            })
            .collect(),
    );
    metrica(
        "suaya_diagnostico_poscuantico",
        "1 si el servicio ofrece o negocia criptografía híbrida o poscuántica.",
        "1 if the service offers or negotiates hybrid or post-quantum cryptography.",
        diagnosticos
            .iter()
            .map(|d| (obj(d), u8::from(d.poscuantico()).to_string()))
            .collect(),
    );
    metrica(
        "suaya_diagnostico_saludo_segundos",
        "Duración del saludo o de la lectura del documento.",
        "Duration of the handshake or of the document read.",
        diagnosticos
            .iter()
            .filter_map(|d| {
                d.conectividad
                    .saludo_ms
                    .map(|ms| (obj(d), format!("{:.3}", ms as f64 / 1000.0)))
            })
            .collect(),
    );
    metrica(
        "suaya_diagnostico_certificado_dias_restantes",
        "Días hasta que vence el certificado del servidor.",
        "Days until the server certificate expires.",
        diagnosticos
            .iter()
            .filter_map(|d| {
                let hoja = d.certificados.as_ref()?.certificados.first()?;
                Some((obj(d), hoja.dias_restantes.to_string()))
            })
            .collect(),
    );
    metrica(
        "suaya_diagnostico_cadena_valida",
        "1 si la cadena de certificados es válida para un cliente estándar.",
        "1 if the certificate chain is valid for a standard client.",
        diagnosticos
            .iter()
            .filter_map(|d| {
                Some((
                    obj(d),
                    u8::from(d.certificados.as_ref()?.valida()).to_string(),
                ))
            })
            .collect(),
    );
    s
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
    let mut d = diagnosticar_sin_recetas(o, c, op, verificador);
    asignar_recetas(&mut d, c);
    d
}

/// Agrega las recetas de corrección de los hallazgos, sin repetir.
fn asignar_recetas(d: &mut Diagnostico, c: &Conocimiento) {
    for h in &d.hallazgos {
        let Some(r) = c.receta_de_hallazgo(h.codigo) else {
            continue;
        };
        match d.recetas.iter_mut().find(|x| x.id == r.id) {
            Some(x) => {
                if !x.hallazgos.contains(&h.codigo) {
                    x.hallazgos.push(h.codigo);
                }
            }
            None => d.recetas.push(RecetaDiag {
                id: r.id.clone(),
                titulo: r.titulo().to_string(),
                pasos: r.pasos().to_vec(),
                hallazgos: vec![h.codigo],
            }),
        }
    }
}

fn diagnosticar_sin_recetas(
    o: &Objetivo,
    c: &Conocimiento,
    op: &Opciones,
    verificador: Option<&Arc<WebPkiServerVerifier>>,
) -> Diagnostico {
    let mut d = Diagnostico::nuevo(o);
    // IKE (UDP) y DNS no tienen una conexión TCP que medir.
    match o.protocolo {
        Protocolo::Ike => diagnosticar_ike(o, op, &mut d),
        Protocolo::Dns => diagnosticar_dns(o, c, op, &mut d),
        _ => {}
    }
    if matches!(o.protocolo, Protocolo::Ike | Protocolo::Dns) {
        d.hallazgos.sort_by_key(|h| h.nivel);
        return d;
    }
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
        Protocolo::Oidc | Protocolo::Saml => diagnosticar_identidad(o, c, op, &mut d),
        Protocolo::Ike | Protocolo::Dns => {}
        Protocolo::Tls => {
            if let Some(st) = o.starttls {
                match conectar(direccion, op).and_then(|mut s| st.preambulo_para(&mut s, &o.host)) {
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

/// IKEv2 viaja por UDP: no hay conexión que medir, solo la respuesta.
fn diagnosticar_ike(o: &Objetivo, op: &Opciones, d: &mut Diagnostico) {
    let inicio = Instant::now();
    match (o.host.as_str(), o.puerto).to_socket_addrs() {
        Ok(v) => {
            d.conectividad.resolucion_ms = Some(ms(inicio));
            d.conectividad.direcciones = v
                .take(MAXIMO_DIRECCIONES)
                .map(|x| Direccion {
                    ip: x.ip().to_string(),
                    familia: if x.is_ipv4() { "ipv4" } else { "ipv6" },
                    estado: EstadoTcp::Abierto,
                    milisegundos: None,
                    error: Some("UDP: sin conexión que medir".into()),
                })
                .collect();
        }
        Err(e) => {
            d.conectividad.error_resolucion = Some(e.to_string());
            d.hallar(
                Nivel::Critico,
                "CON-DNS",
                format!("No se pudo resolver {}: {e}.", o.host),
            );
            return;
        }
    }
    let inicio = Instant::now();
    match crate::ike::observar(o, op) {
        Ok(obs) => {
            d.conectividad.saludo_ms = Some(ms(inicio));
            let nombre = |g: u16| crate::ike::nombre_grupo(g);
            let i = IntercambioIke {
                grupos: obs.grupos.iter().map(|g| nombre(*g)).collect(),
                preferido: obs.preferido.map(nombre),
                elegidas: obs
                    .elegidas
                    .iter()
                    .filter_map(crate::ike::nombre_transformacion)
                    .collect(),
                mlkem: obs.mlkem.map(nombre),
                acepta_3des: obs.acepta_3des,
                acepta_sha1: obs.acepta_sha1,
            };
            match &i.mlkem {
                Some(m) => d.hallar(Nivel::Info, "IKE-PQ", format!("Acepta {m} como intercambio adicional (RFC 9370): la VPN puede ser híbrida poscuántica.")),
                None => d.hallar(Nivel::Alto, "IKE-CLASICO", "No acepta ML-KEM como intercambio adicional (RFC 9370): el tráfico de la VPN queda expuesto a «capturar ahora, descifrar después»."),
            }
            let rotos: Vec<&String> = i
                .grupos
                .iter()
                .filter(|g| matches!(g.as_str(), "modp1024" | "modp1536"))
                .collect();
            if !rotos.is_empty() {
                d.hallar(
                    Nivel::Critico,
                    "IKE-DH-ROTO",
                    format!(
                        "Acepta grupos Diffie-Hellman rotos: {}.",
                        rotos
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                );
            }
            if i.acepta_3des {
                d.hallar(Nivel::Alto, "IKE-3DES", "Acepta 3DES para la SA de IKE.");
            }
            if i.acepta_sha1 {
                d.hallar(
                    Nivel::Medio,
                    "IKE-SHA1",
                    "Acepta SHA-1 como función pseudoaleatoria e integridad de IKE.",
                );
            }
            d.ike = Some(i);
        }
        Err(e) => d.hallar(
            Nivel::Critico,
            "CON-UDP",
            format!("El servidor IKEv2 no respondió por UDP: {e}."),
        ),
    }
}

/// Consulta el DNS del dominio y evalúa DNSSEC, CAA, TLSA y DKIM.
fn diagnosticar_dns(o: &Objetivo, c: &Conocimiento, op: &Opciones, d: &mut Diagnostico) {
    let inicio = Instant::now();
    let obs = match crate::dns::observar(o, op) {
        Ok(x) => x,
        Err(e) => {
            d.hallar(
                Nivel::Critico,
                "CON-DNS",
                format!("No se pudo consultar el DNS de {}: {e}.", o.host),
            );
            return;
        }
    };
    d.conectividad.resolucion_ms = Some(ms(inicio));
    evaluar_dns(o, c, &obs, d);
}

/// Hallazgos de lo que publicó el DNS (separado de la consulta para probarlo).
pub(crate) fn evaluar_dns(
    o: &Objetivo,
    c: &Conocimiento,
    obs: &crate::dns::ObservacionDns,
    d: &mut Diagnostico,
) {
    use crate::dns::{describir_tlsa, fecha, llave_dkim, mnemonico, nombre_digestion};
    if let Ok(r) = obs.resolvedor.parse::<SocketAddr>() {
        d.conectividad.direcciones.push(Direccion {
            ip: r.ip().to_string(),
            familia: if r.is_ipv4() { "ipv4" } else { "ipv6" },
            estado: EstadoTcp::Abierto,
            milisegundos: Some(obs.latencia_ms),
            error: None,
        });
        d.conectividad.direccion_usada = Some(r.ip().to_string());
    }
    let riesgo_alg = |a: u8| c.por_alias("dnssec-alg", &a.to_string()).map(|x| x.riesgo);
    if obs.consulto_dnssec {
        if obs.llaves.is_empty() {
            d.hallar(
                Nivel::Medio,
                "DNS-SIN-DNSSEC",
                format!("{} no firma sus respuestas con DNSSEC: un atacante en la ruta puede suplantarlas.", o.host),
            );
        } else {
            if obs.rechazada {
                d.hallar(Nivel::Critico, "DNSSEC-ROTO", "El resolvedor rechaza la zona (SERVFAIL) y solo responde con la validación desactivada: la cadena DNSSEC está rota y los clientes que validan no resuelven el dominio.");
            } else if obs.validada {
                d.hallar(
                    Nivel::Info,
                    "DNSSEC-VALIDADO",
                    "El resolvedor validó la cadena DNSSEC (bit AD).",
                );
            } else if obs.firmas.is_empty() {
                d.hallar(Nivel::Info, "DNS-RESOLVEDOR", format!("El resolvedor {} no devolvió firmas RRSIG ni validó la respuesta: no admite DNSSEC. Para revisar las firmas indique un resolvedor validador con SUAYA_DNS (p. ej. SUAYA_DNS=1.1.1.1).", obs.resolvedor));
            }
            for f in obs.firmas.iter().filter(|f| f.expiracion < obs.ahora) {
                d.hallar(
                    Nivel::Critico,
                    "DNSSEC-RRSIG-VENCIDA",
                    format!(
                        "La firma RRSIG del conjunto DNSKEY (etiqueta {}) venció el {}.",
                        f.etiqueta,
                        fecha(f.expiracion)
                    ),
                );
            }
            if obs.delegaciones.is_empty() {
                d.hallar(Nivel::Medio, "DNSSEC-SIN-DS", "Hay llaves DNSKEY pero la zona padre no publica DS: la cadena de confianza no llega al dominio.");
            }
            if obs.delegaciones.iter().any(|x| x.digestion == 1) {
                d.hallar(
                    Nivel::Medio,
                    "DNSSEC-DS-SHA1",
                    "La delegación publica DS con SHA-1, que ya no debe usarse (RFC 9905).",
                );
            }
            let mut algoritmos: Vec<u8> = obs.llaves.iter().map(|k| k.algoritmo).collect();
            algoritmos.dedup();
            for a in &algoritmos {
                match riesgo_alg(*a) {
                    Some(Riesgo::RotoClasico) => d.hallar(
                        Nivel::Critico,
                        "DNSSEC-ALGORITMO",
                        format!("Firma con {}, inseguro hoy.", mnemonico(*a)),
                    ),
                    Some(Riesgo::Obsoleto) => d.hallar(
                        Nivel::Alto,
                        "DNSSEC-ALGORITMO",
                        format!("Firma con {}, obsoleto.", mnemonico(*a)),
                    ),
                    _ => {}
                }
            }
            for k in &obs.llaves {
                if let Some(b) = k.bits
                    && c.por_id("rsa")
                        .is_some_and(|r| r.riesgo_para_tamano(Some(b)) == Riesgo::RotoClasico)
                {
                    d.hallar(
                        Nivel::Alto,
                        "DNSSEC-RSA-CORTA",
                        format!("La llave {} {} es RSA de {b} bits.", k.rol(), k.etiqueta),
                    );
                }
            }
            let nombres: Vec<String> = algoritmos.iter().map(|a| mnemonico(*a)).collect();
            if algoritmos.iter().any(|a| {
                matches!(
                    riesgo_alg(*a),
                    Some(Riesgo::HibridoPq | Riesgo::ResistenteCuantico)
                )
            }) {
                d.hallar(
                    Nivel::Info,
                    "DNSSEC-PQ",
                    format!(
                        "Firma la zona con un algoritmo poscuántico ({}).",
                        nombres.join(", ")
                    ),
                );
            } else {
                d.hallar(Nivel::Bajo, "DNSSEC-CLASICO", format!("Las firmas DNSSEC usan solo algoritmos clásicos ({}): una computadora cuántica relevante podría falsificar respuestas.", nombres.join(", ")));
            }
        }
        if obs.caa.is_empty() {
            d.hallar(Nivel::Bajo, "DNS-SIN-CAA", "Sin registro CAA: cualquier autoridad certificadora puede emitir certificados para el dominio.");
        }
        if obs.dkim.is_empty() {
            d.hallar(
                Nivel::Info,
                "DKIM-NO-HALLADO",
                format!("No se halló DKIM en los selectores consultados ({}); indíquelos con dns://{}/selector1,selector2.", obs.selectores.join(", "), o.host),
            );
        }
    }
    let mut dkim = Vec::new();
    for k in &obs.dkim {
        let (id, nombre, bits) = llave_dkim(k, c);
        dkim.push(match bits {
            Some(b) => format!("{}: {nombre}, {b} bits", k.selector),
            None => format!("{}: {nombre}", k.selector),
        });
        if id.as_deref() == Some("rsa")
            && let Some(b) = bits
        {
            if b < 1024 {
                d.hallar(Nivel::Critico, "DKIM-RSA-CORTA", format!("La llave DKIM {} es RSA de {b} bits: RFC 8301 exige al menos 1024 y los verificadores la rechazan.", k.selector));
            } else if b < 2048 {
                d.hallar(
                    Nivel::Alto,
                    "DKIM-RSA-CORTA",
                    format!(
                        "La llave DKIM {} es RSA de {b} bits: use al menos 2048.",
                        k.selector
                    ),
                );
            }
        }
        if k.digestiones.iter().any(|h| h == "sha1") {
            d.hallar(
                Nivel::Medio,
                "DKIM-SHA1",
                format!(
                    "La llave DKIM {} acepta rsa-sha1, que RFC 8301 prohíbe.",
                    k.selector
                ),
            );
        }
        if k.pruebas {
            d.hallar(
                Nivel::Bajo,
                "DKIM-PRUEBAS",
                format!("La llave DKIM {} está en modo de prueba (t=y).", k.selector),
            );
        }
    }
    for t in &obs.tlsa {
        d.hallar(
            Nivel::Info,
            "DNS-TLSA",
            format!("Publica TLSA en {} ({}).", t.nombre, describir_tlsa(t)),
        );
    }
    for e in &obs.errores {
        d.hallar(
            Nivel::Bajo,
            "DNS-CONSULTA",
            format!("Consulta fallida: {e}."),
        );
    }
    d.dns = Some(IntercambioDns {
        resolvedor: obs.resolvedor.clone(),
        validada: obs.validada,
        llaves: obs
            .llaves
            .iter()
            .map(|k| match k.bits {
                Some(b) => format!(
                    "{} {} {} ({b} bits)",
                    k.rol(),
                    k.etiqueta,
                    mnemonico(k.algoritmo)
                ),
                None => format!("{} {} {}", k.rol(), k.etiqueta, mnemonico(k.algoritmo)),
            })
            .collect(),
        delegaciones: obs
            .delegaciones
            .iter()
            .map(|x| {
                format!(
                    "DS {} {} {}",
                    x.etiqueta,
                    mnemonico(x.algoritmo),
                    nombre_digestion(x.digestion)
                )
            })
            .collect(),
        firmas: obs
            .firmas
            .iter()
            .map(|f| {
                format!(
                    "RRSIG {} {} {} → {}",
                    f.etiqueta,
                    mnemonico(f.algoritmo),
                    fecha(f.inicio),
                    fecha(f.expiracion)
                )
            })
            .collect(),
        caa: obs.caa.clone(),
        tlsa: obs
            .tlsa
            .iter()
            .map(|t| format!("{}: {}", t.nombre, describir_tlsa(t)))
            .collect(),
        dkim,
    });
}

/// Lee el documento del proveedor de identidad y evalúa sus algoritmos.
fn diagnosticar_identidad(o: &Objetivo, c: &Conocimiento, op: &Opciones, d: &mut Diagnostico) {
    let inicio = Instant::now();
    let obs = match crate::identidad::observar(o, op) {
        Ok(x) => x,
        Err(e) => {
            d.hallar(
                Nivel::Critico,
                "IDP-DOCUMENTO",
                format!("No se pudo leer el documento del proveedor de identidad: {e}."),
            );
            return;
        }
    };
    d.conectividad.saludo_ms = Some(ms(inicio));
    evaluar_identidad(c, &obs, d);
}

/// Hallazgos de lo que publica un proveedor de identidad.
pub(crate) fn evaluar_identidad(
    c: &Conocimiento,
    obs: &crate::identidad::ObservacionIdentidad,
    d: &mut Diagnostico,
) {
    let mut firmas: Vec<(String, Riesgo)> = Vec::new();
    let mut algoritmos = Vec::new();
    for a in &obs.anuncios {
        algoritmos.push(format!("{}: {}", a.uso, a.algoritmos.join(", ")));
        for alg in &a.algoritmos {
            if alg.eq_ignore_ascii_case("none") {
                if a.uso.starts_with("id_token") || a.uso.starts_with("userinfo") {
                    d.hallar(
                        Nivel::Critico,
                        "IDP-ALG-NONE",
                        format!("{} acepta «none»: tokens de identidad sin firma.", a.uso),
                    );
                }
                continue;
            }
            if alg.eq_ignore_ascii_case("RSA1_5") {
                d.hallar(
                    Nivel::Alto,
                    "IDP-RSA15",
                    format!(
                        "{} anuncia RSA1_5 (PKCS #1 v1.5), expuesto a ataques de oráculo.",
                        a.uso
                    ),
                );
            }
            if let Some(def) = c.por_alias("jose", alg) {
                if a.confidencialidad {
                    if def.riesgo == Riesgo::VulnerableCuantico {
                        d.hallar(Nivel::Medio, "IDP-CIFRADO-CLASICO", format!("{} usa {alg}: los tokens cifrados quedan expuestos a «capturar ahora, descifrar después».", a.uso));
                    }
                } else {
                    firmas.push((alg.clone(), def.riesgo));
                }
            }
        }
    }
    let mut llaves = Vec::new();
    for k in &obs.llaves {
        let mut texto = format!("{}: {}", k.kid.as_deref().unwrap_or("-"), k.kty);
        if let Some(p) = &k.parametro {
            texto.push_str(&format!(" {p}"));
        }
        match &k.alg {
            Some(a) => {
                texto.push_str(&format!(", {a}"));
                if let Some(def) = c.por_alias("jose", a) {
                    firmas.push((a.clone(), def.riesgo));
                }
            }
            // Sin «alg», el tipo de llave basta para saber que la firma es clásica.
            None if matches!(k.kty.as_str(), "RSA" | "EC" | "OKP") => {
                firmas.push((k.kty.clone(), Riesgo::VulnerableCuantico));
            }
            None => {}
        }
        if k.kty.eq_ignore_ascii_case("RSA") && k.bits.is_some_and(|b| b < 2048) {
            d.hallar(
                Nivel::Alto,
                "IDP-RSA-CORTA",
                format!(
                    "La llave {} del JWKS es RSA de {} bits.",
                    k.kid.as_deref().unwrap_or("sin kid"),
                    k.bits.unwrap_or(0)
                ),
            );
        }
        llaves.push(texto);
    }
    for (elemento, uri) in &obs.metodos {
        algoritmos.push(format!("{elemento}: {uri}"));
        let Some(def) = c.por_alias("xmldsig", uri) else {
            continue;
        };
        if uri.ends_with("#rsa-1_5") {
            d.hallar(
                Nivel::Alto,
                "IDP-RSA15",
                "Los metadatos anuncian cifrado RSA PKCS #1 v1.5, expuesto a ataques de oráculo.",
            );
        }
        if matches!(def.riesgo, Riesgo::RotoClasico | Riesgo::Obsoleto) {
            d.hallar(
                Nivel::Alto,
                "IDP-ALGORITMO",
                format!("{elemento} usa {}, inseguro hoy.", def.nombre),
            );
        }
        if elemento != "DigestMethod" && elemento != "EncryptionMethod" {
            firmas.push((def.nombre.clone(), def.riesgo));
        }
    }
    let mut certificados = Vec::new();
    for x in &obs.certificados {
        let Ok(r) = resumen_certificado(&x.der, c) else {
            continue;
        };
        let uso = x.uso.as_deref().unwrap_or("-");
        let llave = match r.tamano_llave {
            Some(t) if !r.algoritmo_llave.contains(&t.to_string()) => {
                format!("{} {t}", r.algoritmo_llave)
            }
            _ => r.algoritmo_llave.clone(),
        };
        certificados.push(format!(
            "({uso}) {} · {llave} · → {}",
            r.nombre,
            r.no_despues.get(..10).unwrap_or(&r.no_despues)
        ));
        if r.dias_restantes < 0 {
            d.hallar(
                Nivel::Medio,
                "IDP-CERT-VENCIDO",
                format!(
                    "El certificado {uso} «{}» de los metadatos venció el {}.",
                    r.nombre, r.no_despues
                ),
            );
        }
        firmas.push((r.algoritmo_llave.clone(), r.riesgo_llave));
    }
    let hoy = crate::dns::fecha(crate::dns::ahora());
    if let Some(v) = &obs.vigencia
        && v.get(..10).is_some_and(|f| f < hoy.as_str())
    {
        d.hallar(
            Nivel::Alto,
            "IDP-METADATOS-VENCIDOS",
            format!("Los metadatos vencieron (validUntil {v})."),
        );
    }
    if let Some(externo) = &obs.jwks_externo {
        d.hallar(
            Nivel::Info,
            "IDP-JWKS-EXTERNO",
            format!(
                "jwks_uri apunta fuera del objetivo ({externo}); sondéelo como objetivo explícito."
            ),
        );
    }
    for e in &obs.errores {
        d.hallar(Nivel::Medio, "IDP-JWKS", format!("{e}."));
    }
    let pq = firmas
        .iter()
        .any(|(_, r)| matches!(r, Riesgo::HibridoPq | Riesgo::ResistenteCuantico));
    let mut clasicas: Vec<String> = firmas
        .iter()
        .filter(|(_, r)| *r == Riesgo::VulnerableCuantico)
        .map(|(n, _)| n.clone())
        .collect();
    clasicas.sort();
    clasicas.dedup();
    if pq {
        d.hallar(
            Nivel::Info,
            "IDP-PQ",
            "Anuncia firmas poscuánticas (ML-DSA, RFC 9964).",
        );
    } else if !clasicas.is_empty() {
        d.hallar(Nivel::Bajo, "IDP-CLASICO", format!("Los tokens y aserciones se firman solo con algoritmos clásicos ({}): una computadora cuántica relevante podría falsificarlos.", clasicas.join(", ")));
    }
    d.identidad = Some(IntercambioIdentidad {
        documento: obs.documento.clone(),
        emisor: obs.emisor.clone(),
        algoritmos,
        jwks: obs.jwks.clone(),
        llaves,
        certificados,
    });
}

/// Días desde 1970-01-01 de una fecha «AAAA-MM-DD…» (calendario civil).
fn dias_civiles(fecha: &str) -> Option<i64> {
    let a: i64 = fecha.get(..4)?.parse().ok()?;
    let m: i64 = fecha.get(5..7)?.parse().ok()?;
    let d: i64 = fecha.get(8..10)?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let a = if m <= 2 { a - 1 } else { a };
    let era = a.div_euclid(400);
    let anio_era = a - era * 400;
    let dia_anio = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let dia_era = anio_era * 365 + anio_era / 4 - anio_era / 100 + dia_anio;
    Some(era * 146_097 + dia_era - 719_468)
}

/// Vigencia máxima permitida a un certificado emitido en `emision` y la
/// siguiente etapa del calendario, si la hay.
fn vigencia_maxima(emision: &str) -> (i64, Option<(&'static str, i64)>) {
    let i = VIGENCIA_MAXIMA
        .iter()
        .rposition(|(desde, _)| *desde <= emision)
        .unwrap_or(0);
    (VIGENCIA_MAXIMA[i].1, VIGENCIA_MAXIMA.get(i + 1).copied())
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
            st.preambulo_para(&mut socket, &o.host)?;
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
    // El calendario del CA/Browser Forum solo obliga a autoridades públicas.
    if k.valida()
        && !hoja.autofirmado
        && let (Some(desde), Some(hasta)) =
            (dias_civiles(&hoja.no_antes), dias_civiles(&hoja.no_despues))
    {
        let vigencia = hasta - desde;
        let (maxima, siguiente) = vigencia_maxima(&hoja.no_antes);
        if vigencia > maxima {
            d.hallar(
                Nivel::Medio,
                "CERT-VIGENCIA",
                format!(
                    "El certificado del servidor tiene una vigencia de {vigencia} días, mayor que los {maxima} que el CA/Browser Forum permite a los emitidos en esa fecha: los clientes pueden rechazarlo."
                ),
            );
        } else if let Some((fecha, dias)) = siguiente
            && vigencia > dias
        {
            d.hallar(
                Nivel::Info,
                "CERT-RENOVACION",
                format!(
                    "Vigencia de {vigencia} días: los certificados emitidos desde el {fecha} no podrán durar más de {dias}; automatice la renovación (ACME)."
                ),
            );
        }
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
    fn evaluacion_de_dns() {
        use crate::dns::pruebas::{Zona, opciones, resolvedor_simulado, zona_ejemplo};
        let c = Conocimiento::embebido();
        let ahora = 1_793_000_000u32;
        let o = objetivo("dns://ejemplo.mx");
        let obs = crate::dns::observar_con(
            resolvedor_simulado(zona_ejemplo(ahora)),
            &o,
            &opciones(),
            ahora as i64,
        )
        .unwrap();
        let mut d = Diagnostico::nuevo(&o);
        evaluar_dns(&o, &c, &obs, &mut d);
        let cs = codigos(&d);
        for esperado in [
            "DNSSEC-VALIDADO",
            "DNSSEC-RRSIG-VENCIDA",
            "DNSSEC-DS-SHA1",
            "DNSSEC-CLASICO",
            "DKIM-SHA1",
            "DNS-TLSA",
        ] {
            assert!(cs.contains(&esperado), "{esperado}: {cs:?}");
        }
        assert!(
            !cs.contains(&"DNS-SIN-CAA") && !cs.contains(&"DNSSEC-SIN-DS"),
            "{cs:?}"
        );
        let x = d.dns.as_ref().unwrap();
        assert_eq!(x.llaves.len(), 2);
        assert!(
            x.dkim
                .iter()
                .any(|k| k.starts_with("selector1: RSA") && k.ends_with("2048 bits")),
            "{:?}",
            x.dkim
        );
        assert_eq!(d.conectividad.direcciones.len(), 1);

        // Cadena rota: el resolvedor solo responde con la validación desactivada.
        let mut z = zona_ejemplo(ahora);
        z.rota = true;
        let obs = crate::dns::observar_con(resolvedor_simulado(z), &o, &opciones(), ahora as i64)
            .unwrap();
        let mut d = Diagnostico::nuevo(&o);
        evaluar_dns(&o, &c, &obs, &mut d);
        assert!(codigos(&d).contains(&"DNSSEC-ROTO"));

        // Sin DNSSEC, sin CAA y sin DKIM; un resolvedor que no valida.
        let z = Zona {
            registros: vec![("ejemplo.mx".into(), 16, vec![4, b'h', b'o', b'l', b'a'])],
            rota: false,
            autenticada: false,
        };
        let obs = crate::dns::observar_con(resolvedor_simulado(z), &o, &opciones(), ahora as i64)
            .unwrap();
        let mut d = Diagnostico::nuevo(&o);
        evaluar_dns(&o, &c, &obs, &mut d);
        let cs = codigos(&d);
        for esperado in ["DNS-SIN-DNSSEC", "DNS-SIN-CAA", "DKIM-NO-HALLADO"] {
            assert!(cs.contains(&esperado), "{esperado}: {cs:?}");
        }
    }

    #[test]
    fn evaluacion_de_identidad() {
        use crate::identidad::{Anuncio, CertificadoSaml, LlaveJwk, ObservacionIdentidad};
        let c = Conocimiento::embebido();
        let vencido = {
            let k = rcgen::KeyPair::generate().unwrap();
            let mut p = rcgen::CertificateParams::new(vec!["idp.ejemplo.mx".into()]).unwrap();
            p.not_before = time::OffsetDateTime::from_unix_timestamp(1_500_000_000).unwrap();
            p.not_after = time::OffsetDateTime::from_unix_timestamp(1_600_000_000).unwrap();
            p.self_signed(&k).unwrap().der().to_vec()
        };
        let obs = ObservacionIdentidad {
            documento: "https://login.ejemplo.mx/.well-known/openid-configuration".into(),
            anuncios: vec![
                Anuncio {
                    uso: "id_token (firma)".into(),
                    confidencialidad: false,
                    algoritmos: vec!["RS256".into(), "none".into()],
                },
                Anuncio {
                    uso: "id_token (cifrado de llave)".into(),
                    confidencialidad: true,
                    algoritmos: vec!["RSA1_5".into(), "RSA-OAEP".into()],
                },
            ],
            llaves: vec![LlaveJwk {
                kid: Some("viejo".into()),
                kty: "RSA".into(),
                alg: None,
                parametro: Some("1024 bits".into()),
                bits: Some(1024),
            }],
            certificados: vec![CertificadoSaml {
                uso: Some("signing".into()),
                der: vencido,
            }],
            metodos: vec![(
                "SignatureMethod".into(),
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1".into(),
            )],
            vigencia: Some("2020-01-01T00:00:00Z".into()),
            jwks_externo: Some("https://llaves.otro.example/certs".into()),
            errores: vec!["https://login.ejemplo.mx/certs: estado HTTP 500".into()],
            ..Default::default()
        };
        let mut d = Diagnostico::nuevo(&objetivo("oidc://login.ejemplo.mx"));
        evaluar_identidad(&c, &obs, &mut d);
        let cs = codigos(&d);
        for esperado in [
            "IDP-ALG-NONE",
            "IDP-RSA15",
            "IDP-CIFRADO-CLASICO",
            "IDP-RSA-CORTA",
            "IDP-ALGORITMO",
            "IDP-CERT-VENCIDO",
            "IDP-METADATOS-VENCIDOS",
            "IDP-JWKS-EXTERNO",
            "IDP-JWKS",
            "IDP-CLASICO",
        ] {
            assert!(cs.contains(&esperado), "{esperado}: {cs:?}");
        }
        assert!(!cs.contains(&"IDP-PQ"));
        let x = d.identidad.as_ref().unwrap();
        assert!(
            x.certificados[0].starts_with("(signing) "),
            "{:?}",
            x.certificados
        );

        // Con ML-DSA anunciado, la firma poscuántica sustituye al aviso clásico.
        let obs = ObservacionIdentidad {
            anuncios: vec![Anuncio {
                uso: "id_token (firma)".into(),
                confidencialidad: false,
                algoritmos: vec!["ML-DSA-65".into()],
            }],
            ..Default::default()
        };
        let mut d = Diagnostico::nuevo(&objetivo("oidc://login.ejemplo.mx"));
        evaluar_identidad(&c, &obs, &mut d);
        assert_eq!(codigos(&d), vec!["IDP-PQ"]);
    }

    #[test]
    fn metricas_en_formato_prometheus() {
        let o = objetivo("tls://srv.ejemplo.mx:443");
        let mut d = alcanzado(&o);
        d.objetivo = "tls://a\"b".into();
        d.conectividad.saludo_ms = Some(1250);
        d.hallar(Nivel::Alto, "KEX-TLS12", "x");
        d.hallar(Nivel::Info, "IKE-PQ", "y");
        d.certificados = Some(CadenaCertificados {
            certificados: vec![certificado(42)],
            ..Default::default()
        });
        let m = metricas_prometheus(&[d]);
        assert!(
            m.contains("# TYPE suaya_diagnostico_hallazgos gauge"),
            "{m}"
        );
        assert!(
            m.contains("suaya_diagnostico_hallazgos{objetivo=\"tls://a\\\"b\",nivel=\"alto\"} 1"),
            "{m}"
        );
        assert!(
            m.contains("suaya_diagnostico_saludo_segundos{objetivo=\"tls://a\\\"b\"} 1.250"),
            "{m}"
        );
        assert!(
            m.contains(
                "suaya_diagnostico_certificado_dias_restantes{objetivo=\"tls://a\\\"b\"} 42"
            ),
            "{m}"
        );
        assert!(
            m.contains("suaya_diagnostico_poscuantico{objetivo=\"tls://a\\\"b\"} 1"),
            "{m}"
        );
        assert!(
            m.contains("suaya_diagnostico_cadena_valida{objetivo=\"tls://a\\\"b\"} 1"),
            "{m}"
        );
    }

    #[test]
    fn calendario_de_vigencia_del_ca_b_forum() {
        assert_eq!(dias_civiles("1970-01-01"), Some(0));
        assert_eq!(dias_civiles("2000-03-01T00:00:00Z"), Some(11_017));
        assert_eq!(dias_civiles("2026-13-01"), None);
        assert_eq!(
            vigencia_maxima("2025-06-01T00:00:00Z"),
            (398, Some(("2026-03-15", 200)))
        );
        assert_eq!(
            vigencia_maxima("2026-03-15T00:00:00Z"),
            (200, Some(("2027-03-15", 100)))
        );
        assert_eq!(vigencia_maxima("2029-04-01T00:00:00Z"), (47, None));

        let o = objetivo("tls://srv.ejemplo.mx:443");
        let mut d = alcanzado(&o);
        let mut k = CadenaCertificados {
            ocsp_engrapado: true,
            orden_correcto: true,
            certificados: vec![certificado(200)],
            ..Default::default()
        };
        k.certificados[0].no_antes = "2026-04-01T00:00:00Z".into();
        k.certificados[0].no_despues = "2027-04-01T00:00:00Z".into();
        evaluar_certificados(&mut d, &k, &o);
        assert!(codigos(&d).contains(&"CERT-VIGENCIA"), "{:?}", codigos(&d));

        let mut d = alcanzado(&o);
        k.certificados[0].no_despues = "2026-10-01T00:00:00Z".into();
        evaluar_certificados(&mut d, &k, &o);
        assert!(
            codigos(&d).contains(&"CERT-RENOVACION"),
            "{:?}",
            codigos(&d)
        );
        assert!(!codigos(&d).contains(&"CERT-VIGENCIA"));
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
