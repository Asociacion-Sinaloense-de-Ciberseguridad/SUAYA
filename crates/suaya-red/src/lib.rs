//! # suaya-red
//!
//! Sondeo de red: Suaya se conecta a un servicio y observa la criptografía
//! que realmente ofrece, en lugar de deducirla de archivos de configuración.
//!
//! - **SSH**: lee el `KEXINIT` del servidor, que viaja en claro antes de
//!   cualquier intercambio de llaves. No se autentica ni completa la sesión.
//! - **TLS**: envía mensajes `ClientHello` sin material de llaves para que
//!   el servidor responda con un `HelloRetryRequest` que revela qué grupos
//!   acepta (incluidos los híbridos con ML-KEM) y cuál prefiere. Prueba las
//!   versiones de TLS y obtiene la cadena de certificados.
//!
//! - **Diagnóstico** ([`diagnostico`]): conectividad por dirección y lo que
//!   obtiene realmente un cliente: saludos TLS completos, grupo negociado,
//!   validación estándar de la cadena de certificados y extensiones SSH.
//!
//! - **IKEv2**: `IKE_SA_INIT` por grupo y el intercambio adicional con
//!   ML-KEM (RFC 9370), por UDP.
//! - **DNS** (`dns://`): DNSSEC, DKIM, CAA y TLSA de un dominio indicado.
//! - **Identidad federada** (`oidc://`, `saml://`): documento OpenID
//!   Connect, llaves JWKS y metadatos SAML.
//!
//! Uso responsable: sondee solo sistemas que administre o que tenga
//! autorización expresa para evaluar. Un objetivo TLS recibe entre treinta y
//! setenta conexiones breves y secuenciales; los demás, unas pocas.

pub mod diagnostico;
mod dns;
pub mod http;
mod identidad;
mod ike;
pub mod kubernetes;
pub mod registro;
mod ssh;
pub mod starttls;
mod tls;

use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use suaya_core::{Activo, Conocimiento};

pub use diagnostico::{Diagnostico, Nivel, diagnosticar, metricas_prometheus};

/// Analizadores de respuestas de red expuestos para el *fuzzing*; no forman
/// parte de la API estable.
#[doc(hidden)]
pub mod fuzz {
    /// Interpreta una respuesta IKE, una DNS, un registro DKIM, unos
    /// metadatos SAML y un JWKS a partir de bytes arbitrarios.
    pub fn analizadores(datos: &[u8]) {
        if datos.len() >= 8 {
            let spi: [u8; 8] = datos[..8].try_into().unwrap_or_default();
            let _ = crate::ike::interpretar(datos, &spi);
        }
        if datos.len() >= 2 {
            let _ = crate::dns::interpretar_para_fuzz(datos);
        }
        if let Ok(t) = std::str::from_utf8(datos) {
            let _ = crate::dns::dkim_para_fuzz(t);
            let mut obs = crate::identidad::ObservacionIdentidad::default();
            crate::identidad::interpretar_saml(t, &mut obs);
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(t) {
                let _ = crate::identidad::llaves_para_fuzz(&v);
            }
        }
    }
}
pub use ssh::KexInit;
pub use starttls::Starttls;
pub use tls::{Respuesta, client_hello, leer_respuesta};

/// Protocolo de un objetivo de red.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocolo {
    Tls,
    Ssh,
    /// IKEv2 (VPN IPsec) por UDP.
    Ike,
    /// Registros DNS de un dominio: DNSSEC, DKIM, CAA y TLSA.
    Dns,
    /// Proveedor OpenID Connect: configuración y llaves públicas (JWKS).
    Oidc,
    /// Metadatos SAML de un proveedor de identidad.
    Saml,
}

/// Un servicio a sondear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Objetivo {
    pub protocolo: Protocolo,
    pub host: String,
    pub puerto: u16,
    /// Preámbulo en claro antes de TLS (SMTP, IMAP, POP3, LDAP, PostgreSQL, MySQL).
    pub starttls: Option<Starttls>,
    /// Ruta del recurso en objetivos HTTPS (OIDC y SAML), con «/» inicial.
    pub ruta: String,
}

impl Objetivo {
    /// Interpreta `tls://host:puerto`, `ssh://host:puerto`, `host:puerto` o `host`.
    ///
    /// Sin esquema, los puertos 22 y 2222 se consideran SSH y el resto TLS;
    /// sin puerto, se usa 443.
    pub fn interpretar(texto: &str) -> Result<Self, String> {
        let (esquema, resto) = match texto.split_once("://") {
            Some((e, r)) => (Some(e.to_lowercase()), r),
            None => (None, texto),
        };
        let resto = resto.trim_end_matches('/');
        let (resto, ruta) = match resto.find('/') {
            Some(i) => (&resto[..i], resto[i..].to_string()),
            None => (resto, String::new()),
        };
        let (host, puerto) = if let Some(r) = resto.strip_prefix('[') {
            // IPv6 entre corchetes.
            let (h, p) = r
                .split_once(']')
                .ok_or("dirección IPv6 sin corchete de cierre")?;
            (h.to_string(), p.strip_prefix(':').map(str::to_string))
        } else if resto.matches(':').count() == 1 {
            let (h, p) = resto.split_once(':').expect("hay un ':'");
            (h.to_string(), Some(p.to_string()))
        } else {
            (resto.to_string(), None)
        };
        if host.is_empty() {
            return Err(format!("objetivo sin host: {texto}"));
        }
        let puerto_explicito = match puerto {
            Some(p) => Some(
                p.parse::<u16>()
                    .map_err(|_| format!("puerto inválido en {texto}"))?,
            ),
            None => None,
        };
        let starttls = esquema.as_deref().and_then(Starttls::desde_esquema);
        let protocolo = match esquema.as_deref() {
            _ if starttls.is_some() => Protocolo::Tls,
            Some("tls") | Some("https") => Protocolo::Tls,
            Some("ssh") => Protocolo::Ssh,
            Some("ike") | Some("ikev2") | Some("ipsec") => Protocolo::Ike,
            Some("dns") | Some("dkim") => Protocolo::Dns,
            Some("oidc") => Protocolo::Oidc,
            Some("saml") => Protocolo::Saml,
            Some(otro) => {
                return Err(format!(
                    "esquema no soportado: {otro} (use tls://, ssh://, ike://, dns://, oidc://, saml://, smtp://, imap://, pop3://, ldap://, postgres://, mysql://, ftp://, xmpp:// o rdp://)"
                ));
            }
            None => match puerto_explicito {
                Some(22) | Some(2222) => Protocolo::Ssh,
                _ => Protocolo::Tls,
            },
        };
        let puerto = puerto_explicito.unwrap_or(match (protocolo, starttls) {
            (_, Some(st)) => st.puerto_predeterminado(),
            (Protocolo::Tls, None) => 443,
            (Protocolo::Ssh, None) => 22,
            (Protocolo::Ike, None) => 500,
            (Protocolo::Dns, None) => 53,
            (Protocolo::Oidc, None) | (Protocolo::Saml, None) => 443,
        });
        Ok(Self {
            protocolo,
            host,
            puerto,
            starttls,
            ruta,
        })
    }

    /// Ubicación que se registra en el inventario (`tls://host:puerto`).
    pub fn ubicacion(&self) -> String {
        let esquema = match (self.protocolo, self.starttls) {
            (_, Some(st)) => st.esquema(),
            (Protocolo::Tls, None) => "tls",
            (Protocolo::Ssh, None) => "ssh",
            (Protocolo::Ike, None) => "ike",
            (Protocolo::Dns, None) => return format!("dns://{}", self.host),
            (Protocolo::Oidc, None) => "oidc",
            (Protocolo::Saml, None) => "saml",
        };
        if self.host.contains(':') {
            format!("{esquema}://[{}]:{}{}", self.host, self.puerto, self.ruta)
        } else {
            format!("{esquema}://{}:{}{}", self.host, self.puerto, self.ruta)
        }
    }

    /// Conexión lista para el primer mensaje TLS (tras STARTTLS, si aplica).
    pub(crate) fn conectar_tls(&self, op: &Opciones) -> Result<TcpStream, String> {
        let mut s = self.conectar(op)?;
        if let Some(st) = self.starttls {
            st.preambulo_para(&mut s, &self.host)?;
        }
        Ok(s)
    }

    pub(crate) fn conectar(&self, op: &Opciones) -> Result<TcpStream, String> {
        let direcciones: Vec<SocketAddr> = (self.host.as_str(), self.puerto)
            .to_socket_addrs()
            .map_err(|e| format!("no se pudo resolver {}: {e}", self.host))?
            .collect();
        let mut ultimo = String::from("sin direcciones");
        for d in direcciones {
            match TcpStream::connect_timeout(&d, op.tiempo_limite) {
                Ok(s) => {
                    s.set_read_timeout(Some(op.tiempo_limite)).ok();
                    s.set_write_timeout(Some(op.tiempo_limite)).ok();
                    return Ok(s);
                }
                Err(e) => ultimo = e.to_string(),
            }
        }
        Err(format!(
            "no se pudo conectar a {}:{}: {ultimo}",
            self.host, self.puerto
        ))
    }
}

/// Opciones del sondeo.
#[derive(Debug, Clone)]
pub struct Opciones {
    pub tiempo_limite: Duration,
    /// Capacidad tecnológica a la que se asignan los hallazgos TLS
    /// (por defecto, `servidores-web`).
    pub capacidad_tls: String,
    /// Obtener la cadena de certificados con un saludo TLS completo.
    pub certificados: bool,
    /// Agregar los hallazgos del diagnóstico como advertencias del protocolo.
    pub diagnostico: bool,
    /// Autoridades adicionales (PEM) para validar cadenas en el diagnóstico.
    pub autoridad_pem: Option<Vec<u8>>,
}

impl Default for Opciones {
    fn default() -> Self {
        Self {
            tiempo_limite: Duration::from_secs(5),
            capacidad_tls: "servidores-web".into(),
            certificados: true,
            diagnostico: false,
            autoridad_pem: None,
        }
    }
}

/// Resultado del sondeo de varios objetivos. Los activos no están
/// clasificados: el llamador los combina con otros hallazgos y clasifica.
#[derive(Debug, Default)]
pub struct Resultado {
    pub activos: Vec<Activo>,
    pub avisos: Vec<String>,
}

pub fn sondear(objetivos: &[Objetivo], c: &Conocimiento, op: &Opciones) -> Resultado {
    let mut r = Resultado::default();
    let verificador = op
        .diagnostico
        .then(|| diagnostico::verificador_estandar(op))
        .flatten();
    for o in objetivos {
        // Con STARTTLS, una primera conexión confirma que el servidor ofrece
        // TLS; si responde en claro sin ofrecerlo, eso es el hallazgo.
        if let Some(st) = o.starttls {
            match o
                .conectar(op)
                .and_then(|mut s| st.preambulo_para(&mut s, &o.host))
            {
                Err(e) if e.starts_with(starttls::PREFIJO_SIN_TLS) => {
                    let mut p = Activo::nuevo(
                        format!(
                            "protocolo:tls:{}",
                            suaya_escaneo::api::id_corto(&o.ubicacion())
                        ),
                        format!("{} sin TLS en {}:{}", st.nombre(), o.host, o.puerto),
                        suaya_core::Detalles::Protocolo {
                            tipo_protocolo: "tls".into(),
                            versiones: Vec::new(),
                            grupos: Vec::new(),
                            cifrados: Vec::new(),
                        },
                    )
                    .con_contexto(&op.capacidad_tls, suaya_core::Garantia::Confidencialidad)
                    .con_ubicacion(&o.ubicacion(), None);
                    p.riesgo_fijado = Some(suaya_core::Riesgo::RotoClasico);
                    let texto = &e[starttls::PREFIJO_SIN_TLS.len()..];
                    let mut t = texto.to_string();
                    if let Some(primera) = t.get_mut(0..1) {
                        primera.make_ascii_uppercase();
                    }
                    p.advertir(format!("{t}."));
                    r.activos.push(p);
                    continue;
                }
                Err(e) => {
                    r.avisos.push(format!("{}: {e}", o.ubicacion()));
                    continue;
                }
                Ok(()) => {}
            }
        }
        let salida = match o.protocolo {
            Protocolo::Ssh => ssh::sondear(o, c, op),
            Protocolo::Tls => tls::sondear(o, c, op),
            Protocolo::Ike => ike::sondear(o, c, op),
            Protocolo::Dns => dns::sondear(o, c, op),
            Protocolo::Oidc | Protocolo::Saml => identidad::sondear(o, c, op),
        };
        match salida {
            Ok((mut activos, avisos)) => {
                if op.diagnostico {
                    let d = diagnostico::diagnosticar_uno(o, c, op, verificador.as_ref());
                    if let Some(p) = activos
                        .iter_mut()
                        .find(|a| a.referencia.starts_with("protocolo:"))
                    {
                        for h in d.hallazgos.iter().filter(|h| h.nivel != Nivel::Info) {
                            p.advertir(format!("Diagnóstico ({}): {}", h.codigo, h.mensaje));
                        }
                    }
                }
                r.activos.extend(activos);
                r.avisos.extend(
                    avisos
                        .into_iter()
                        .map(|a| format!("{}: {a}", o.ubicacion())),
                );
            }
            Err(e) => r.avisos.push(format!("{}: {e}", o.ubicacion())),
        }
    }
    r
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn interpretar_objetivos() {
        let o = Objetivo::interpretar("ejemplo.mx").unwrap();
        assert_eq!((o.protocolo, o.puerto), (Protocolo::Tls, 443));
        let o = Objetivo::interpretar("10.0.0.5:22").unwrap();
        assert_eq!((o.protocolo, o.puerto), (Protocolo::Ssh, 22));
        let o = Objetivo::interpretar("smtp://correo.ejemplo.mx").unwrap();
        assert_eq!(
            (o.protocolo, o.puerto, o.starttls),
            (Protocolo::Tls, 25, Some(Starttls::Smtp))
        );
        assert_eq!(o.ubicacion(), "smtp://correo.ejemplo.mx:25");
        let o = Objetivo::interpretar("postgres://db:6432").unwrap();
        assert_eq!((o.puerto, o.starttls), (6432, Some(Starttls::Postgres)));
        let o = Objetivo::interpretar("ssh://bastion:2200").unwrap();
        assert_eq!(
            (o.protocolo, o.host.as_str(), o.puerto),
            (Protocolo::Ssh, "bastion", 2200)
        );
        let o = Objetivo::interpretar("tls://[::1]:8443").unwrap();
        assert_eq!((o.host.as_str(), o.puerto), ("::1", 8443));
        assert_eq!(o.ubicacion(), "tls://[::1]:8443");
        let o = Objetivo::interpretar("ike://vpn.ejemplo.mx").unwrap();
        assert_eq!((o.protocolo, o.puerto), (Protocolo::Ike, 500));
        assert_eq!(o.ubicacion(), "ike://vpn.ejemplo.mx:500");
        let o = Objetivo::interpretar("rdp://escritorio.ejemplo.mx").unwrap();
        assert_eq!(
            (o.protocolo, o.puerto, o.starttls),
            (Protocolo::Tls, 3389, Some(Starttls::Rdp))
        );
        let o = Objetivo::interpretar("oidc://login.ejemplo.mx/realms/clientes").unwrap();
        assert_eq!(
            (o.protocolo, o.puerto, o.ruta.as_str()),
            (Protocolo::Oidc, 443, "/realms/clientes")
        );
        assert_eq!(o.ubicacion(), "oidc://login.ejemplo.mx:443/realms/clientes");
        let o = Objetivo::interpretar("dns://ejemplo.mx").unwrap();
        assert_eq!(o.ubicacion(), "dns://ejemplo.mx");
        assert!(Objetivo::interpretar("gopher://x").is_err());
        assert!(Objetivo::interpretar("x:puerto").is_err());
    }
}
