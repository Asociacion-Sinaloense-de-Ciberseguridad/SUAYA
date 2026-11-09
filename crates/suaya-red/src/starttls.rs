//! Preámbulos en claro que preceden a TLS en protocolos con STARTTLS.
//!
//! Suaya habla lo mínimo de cada protocolo para pedir el cambio a TLS y, en
//! cuanto el servidor lo acepta, entrega el socket al sondeo TLS. No se
//! autentica ni envía datos de aplicación.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;

/// El servidor respondió, pero no ofrece TLS: el protocolo viaja en claro.
pub const PREFIJO_SIN_TLS: &str = "sin TLS: ";

fn sin_tls(t: &str) -> String {
    format!("{PREFIJO_SIN_TLS}{t}")
}

/// Protocolo de aplicación que negocia TLS con STARTTLS (o equivalente).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Starttls {
    Smtp,
    Imap,
    Pop3,
    Ldap,
    Postgres,
    Mysql,
    Ftp,
    Xmpp,
    Rdp,
}

impl Starttls {
    pub fn desde_esquema(esquema: &str) -> Option<Self> {
        Some(match esquema {
            "smtp" | "submission" => Self::Smtp,
            "imap" => Self::Imap,
            "pop3" => Self::Pop3,
            "ldap" => Self::Ldap,
            "postgres" | "postgresql" => Self::Postgres,
            "mysql" => Self::Mysql,
            "ftp" | "ftps" => Self::Ftp,
            "xmpp" => Self::Xmpp,
            "rdp" => Self::Rdp,
            _ => return None,
        })
    }

    pub fn esquema(self) -> &'static str {
        match self {
            Self::Smtp => "smtp",
            Self::Imap => "imap",
            Self::Pop3 => "pop3",
            Self::Ldap => "ldap",
            Self::Postgres => "postgres",
            Self::Mysql => "mysql",
            Self::Ftp => "ftp",
            Self::Xmpp => "xmpp",
            Self::Rdp => "rdp",
        }
    }

    pub fn puerto_predeterminado(self) -> u16 {
        match self {
            Self::Smtp => 25,
            Self::Imap => 143,
            Self::Pop3 => 110,
            Self::Ldap => 389,
            Self::Postgres => 5432,
            Self::Mysql => 3306,
            Self::Ftp => 21,
            Self::Xmpp => 5222,
            Self::Rdp => 3389,
        }
    }

    /// Nombre legible para el inventario.
    pub fn nombre(self) -> &'static str {
        match self {
            Self::Smtp => "SMTP",
            Self::Imap => "IMAP",
            Self::Pop3 => "POP3",
            Self::Ldap => "LDAP",
            Self::Postgres => "PostgreSQL",
            Self::Mysql => "MySQL",
            Self::Ftp => "FTP",
            Self::Xmpp => "XMPP",
            Self::Rdp => "RDP",
        }
    }

    /// Ejecuta el preámbulo; al volver, el siguiente byte es del saludo TLS.
    pub fn preambulo(self, s: &mut TcpStream) -> Result<(), String> {
        self.preambulo_para(s, "")
    }

    /// Como [`Starttls::preambulo`], con el nombre del servidor (XMPP lo exige).
    pub fn preambulo_para(self, s: &mut TcpStream, host: &str) -> Result<(), String> {
        match self {
            Self::Ftp => ftp(s),
            Self::Xmpp => xmpp(s, host),
            Self::Rdp => rdp(s),
            Self::Smtp => smtp(s),
            Self::Imap => linea_a_linea(s, b"a1 STARTTLS\r\n", |l| l.starts_with("a1 "), "a1 OK"),
            Self::Pop3 => linea_a_linea(s, b"STLS\r\n", |_| true, "+OK"),
            Self::Ldap => ldap(s),
            Self::Postgres => postgres(s),
            Self::Mysql => mysql(s),
        }
    }
}

const MAXIMO_LINEA: u64 = 4096;

/// Lee una línea sin consumir bytes posteriores (TLS empieza justo después).
fn leer_linea(s: &mut TcpStream) -> Result<String, String> {
    let mut linea = Vec::new();
    let mut lector = BufReader::with_capacity(1, s);
    (&mut lector)
        .take(MAXIMO_LINEA)
        .read_until(b'\n', &mut linea)
        .map_err(|e| format!("preámbulo: {e}"))?;
    if linea.is_empty() {
        return Err("el servidor cerró la conexión durante el preámbulo".into());
    }
    Ok(String::from_utf8_lossy(&linea).trim_end().to_string())
}

fn smtp(s: &mut TcpStream) -> Result<(), String> {
    // Saludo 220, posiblemente en varias líneas («220-»).
    loop {
        let l = leer_linea(s)?;
        if !l.starts_with("220") {
            return Err(format!("saludo SMTP inesperado: {l}"));
        }
        if l.as_bytes().get(3) != Some(&b'-') {
            break;
        }
    }
    s.write_all(b"EHLO suaya.invalid\r\n")
        .map_err(|e| e.to_string())?;
    let mut anuncia = false;
    loop {
        let l = leer_linea(s)?;
        if !l.starts_with("250") {
            return Err(format!("respuesta EHLO inesperada: {l}"));
        }
        anuncia |= l[4.min(l.len())..].trim().eq_ignore_ascii_case("STARTTLS");
        if l.as_bytes().get(3) != Some(&b'-') {
            break;
        }
    }
    if !anuncia {
        return Err(sin_tls(
            "el servidor SMTP no anuncia STARTTLS: el correo y las credenciales viajan sin cifrar",
        ));
    }
    s.write_all(b"STARTTLS\r\n").map_err(|e| e.to_string())?;
    let l = leer_linea(s)?;
    if l.starts_with("220") {
        Ok(())
    } else {
        Err(format!("el servidor rechazó STARTTLS: {l}"))
    }
}

/// IMAP y POP3: saludo, orden y respuesta afirmativa.
fn linea_a_linea(
    s: &mut TcpStream,
    orden: &[u8],
    es_final: impl Fn(&str) -> bool,
    esperado: &str,
) -> Result<(), String> {
    let saludo = leer_linea(s)?;
    if !(saludo.starts_with("* OK") || saludo.starts_with("+OK")) {
        return Err(format!("saludo inesperado: {saludo}"));
    }
    s.write_all(orden).map_err(|e| e.to_string())?;
    for _ in 0..32 {
        let l = leer_linea(s)?;
        if es_final(&l) {
            return if l.starts_with(esperado) {
                Ok(())
            } else {
                Err(format!("el servidor rechazó STARTTLS: {l}"))
            };
        }
    }
    Err("respuesta STARTTLS demasiado larga".into())
}

fn postgres(s: &mut TcpStream) -> Result<(), String> {
    // SSLRequest: longitud 8 y código 80877103.
    s.write_all(&[0, 0, 0, 8, 0x04, 0xD2, 0x16, 0x2F])
        .map_err(|e| e.to_string())?;
    let mut r = [0u8; 1];
    s.read_exact(&mut r)
        .map_err(|e| format!("preámbulo: {e}"))?;
    match r[0] {
        b'S' => Ok(()),
        b'N' => Err(sin_tls(
            "el servidor PostgreSQL no admite TLS (respondió N al SSLRequest): las consultas viajan sin cifrar",
        )),
        otro => Err(format!("respuesta inesperada al SSLRequest: 0x{otro:02x}")),
    }
}

fn mysql(s: &mut TcpStream) -> Result<(), String> {
    let mut cab = [0u8; 4];
    s.read_exact(&mut cab)
        .map_err(|e| format!("preámbulo: {e}"))?;
    let largo = u32::from_le_bytes([cab[0], cab[1], cab[2], 0]) as usize;
    if !(10..=4096).contains(&largo) {
        return Err("saludo de MySQL inválido".into());
    }
    let mut p = vec![0u8; largo];
    s.read_exact(&mut p)
        .map_err(|e| format!("preámbulo: {e}"))?;
    if p[0] == 0xFF {
        return Err("el servidor MySQL rechazó la conexión".into());
    }
    // Versión de protocolo, versión del servidor (terminada en 0), id de
    // conexión (4), datos de autenticación (8), relleno (1), capacidades (2).
    let fin_version = p[1..]
        .iter()
        .position(|&b| b == 0)
        .ok_or("saludo truncado")?
        + 2;
    let capacidades = p
        .get(fin_version + 13..fin_version + 15)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .ok_or("saludo truncado")?;
    const CLIENT_SSL: u16 = 0x0800;
    if capacidades & CLIENT_SSL == 0 {
        return Err(sin_tls(
            "el servidor MySQL no admite TLS: las consultas y las credenciales viajan sin cifrar",
        ));
    }
    // SSLRequest: capacidades, tamaño máximo de paquete, juego de caracteres y relleno.
    let banderas: u32 = 0x0000_0200 | 0x0000_0800 | 0x0000_8000 | 0x0008_0000;
    let mut carga = banderas.to_le_bytes().to_vec();
    carga.extend_from_slice(&0x0100_0000u32.to_le_bytes());
    carga.push(0x21);
    carga.extend_from_slice(&[0u8; 23]);
    let mut paquete = (carga.len() as u32).to_le_bytes()[..3].to_vec();
    paquete.push(cab[3].wrapping_add(1));
    paquete.extend(carga);
    s.write_all(&paquete).map_err(|e| e.to_string())
}

fn ldap(s: &mut TcpStream) -> Result<(), String> {
    // ExtendedRequest con el OID de StartTLS (RFC 4511, sección 4.14).
    let oid = b"1.3.6.1.4.1.1466.20037";
    let mut peticion = vec![0x30, 0x1D, 0x02, 0x01, 0x01, 0x77, 0x18, 0x80, 0x16];
    peticion.extend_from_slice(oid);
    s.write_all(&peticion).map_err(|e| e.to_string())?;
    let mut cab = [0u8; 2];
    s.read_exact(&mut cab)
        .map_err(|e| format!("preámbulo: {e}"))?;
    if cab[0] != 0x30 {
        return Err("respuesta LDAP inválida".into());
    }
    let largo = if cab[1] & 0x80 == 0 {
        cab[1] as usize
    } else {
        let n = (cab[1] & 0x7F) as usize;
        if n == 0 || n > 3 {
            return Err("longitud LDAP inválida".into());
        }
        let mut b = vec![0u8; n];
        s.read_exact(&mut b).map_err(|e| e.to_string())?;
        b.iter().fold(0usize, |a, &x| (a << 8) | x as usize)
    };
    if largo > 4096 {
        return Err("respuesta LDAP demasiado grande".into());
    }
    let mut cuerpo = vec![0u8; largo];
    s.read_exact(&mut cuerpo).map_err(|e| e.to_string())?;
    // El primer ENUMERATED (0x0A 0x01) es el resultCode.
    match cuerpo.windows(3).find(|w| w[0] == 0x0A && w[1] == 0x01) {
        Some(w) if w[2] == 0 => Ok(()),
        Some(w) => Err(format!(
            "el servidor LDAP rechazó StartTLS (código {})",
            w[2]
        )),
        None => Err("respuesta LDAP sin resultCode".into()),
    }
}

fn ftp(s: &mut TcpStream) -> Result<(), String> {
    loop {
        let l = leer_linea(s)?;
        if !l.starts_with("220") {
            return Err(format!("saludo FTP inesperado: {l}"));
        }
        if l.as_bytes().get(3) != Some(&b'-') {
            break;
        }
    }
    s.write_all(b"AUTH TLS\r\n").map_err(|e| e.to_string())?;
    let l = leer_linea(s)?;
    if l.starts_with("234") {
        Ok(())
    } else {
        Err(sin_tls(
            "el servidor FTP no acepta AUTH TLS: las credenciales y los archivos viajan sin cifrar",
        ))
    }
}

/// Lee bytes uno a uno hasta encontrar `fin` (sin consumir de más).
fn leer_hasta(s: &mut TcpStream, fin: &[&str], limite: usize) -> Result<String, String> {
    let mut v = Vec::new();
    let mut b = [0u8; 1];
    while v.len() < limite {
        match s.read(&mut b) {
            Ok(1) => v.push(b[0]),
            Ok(_) => return Err("el servidor cerró la conexión durante el preámbulo".into()),
            Err(e) => return Err(format!("preámbulo: {e}")),
        }
        let t = String::from_utf8_lossy(&v);
        if fin.iter().any(|f| t.contains(f)) {
            return Ok(t.into_owned());
        }
    }
    Err("respuesta del preámbulo demasiado larga".into())
}

fn xmpp(s: &mut TcpStream, host: &str) -> Result<(), String> {
    let dominio: String = host
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
        .collect();
    s.write_all(
        format!(
            "<?xml version='1.0'?><stream:stream to='{dominio}' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
        )
        .as_bytes(),
    )
    .map_err(|e| e.to_string())?;
    let caracteristicas = leer_hasta(
        s,
        &[
            "</stream:features>",
            "<stream:features/>",
            "</stream:stream>",
        ],
        16384,
    )?;
    if !caracteristicas.contains("<starttls") {
        return Err(sin_tls(
            "el servidor XMPP no ofrece STARTTLS: los mensajes y las credenciales viajan sin cifrar",
        ));
    }
    s.write_all(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
        .map_err(|e| e.to_string())?;
    let r = leer_hasta(s, &["<proceed", "<failure"], 4096)?;
    if r.contains("<failure") {
        return Err("el servidor XMPP rechazó STARTTLS".into());
    }
    // Consumir el resto de «<proceed .../>».
    if !r.trim_end().ends_with("/>") {
        leer_hasta(s, &["/>", "</proceed>"], 512)?;
    }
    Ok(())
}

fn rdp(s: &mut TcpStream) -> Result<(), String> {
    // TPKT + X.224 Connection Request + RDP_NEG_REQ (TLS y CredSSP).
    let solicitud: [u8; 19] = [
        0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00,
        0x03, 0x00, 0x00, 0x00,
    ];
    s.write_all(&solicitud).map_err(|e| e.to_string())?;
    let mut cab = [0u8; 4];
    s.read_exact(&mut cab)
        .map_err(|e| format!("preámbulo RDP: {e}"))?;
    if cab[0] != 3 {
        return Err("el servicio no respondió con RDP".into());
    }
    let largo = (u16::from_be_bytes([cab[2], cab[3]]) as usize).saturating_sub(4);
    if !(7..=256).contains(&largo) {
        return Err("respuesta RDP con longitud inválida".into());
    }
    let mut r = vec![0u8; largo];
    s.read_exact(&mut r)
        .map_err(|e| format!("preámbulo RDP: {e}"))?;
    // X.224 Connection Confirm (7 bytes) y, si la hay, la respuesta de negociación.
    let neg = r.get(7..).unwrap_or(&[]);
    match (neg.first(), neg.get(4..8)) {
        (Some(2), Some(p)) => match u32::from_le_bytes([p[0], p[1], p[2], p[3]]) {
            0 => Err(sin_tls(
                "el servidor RDP eligió la seguridad estándar de RDP (RC4) en lugar de TLS",
            )),
            _ => Ok(()),
        },
        (Some(3), Some(p)) => match u32::from_le_bytes([p[0], p[1], p[2], p[3]]) {
            2 => Err(sin_tls(
                "el servidor RDP no permite TLS (SSL_NOT_ALLOWED_BY_SERVER)",
            )),
            codigo => Err(format!(
                "el servidor RDP rechazó la negociación (código {codigo})"
            )),
        },
        _ => Err(sin_tls(
            "el servidor RDP no negoció un protocolo de seguridad: usa la seguridad estándar de RDP (RC4)",
        )),
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use std::net::TcpListener;
    use std::time::Duration;

    /// Servidor de una sola conexión que escribe `respuesta` y luego lee
    /// hasta que el cliente cierra (así no se pierde nada por un reinicio).
    fn conversar(respuesta: Vec<u8>) -> TcpStream {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let dir = l.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = l.accept() {
                let _ = s.write_all(&respuesta);
                let _ = std::io::copy(&mut s, &mut std::io::sink());
            }
        });
        let s = TcpStream::connect(dir).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s
    }

    fn probar(st: Starttls, respuesta: &[u8]) -> Result<(), String> {
        let mut s = conversar(respuesta.to_vec());
        st.preambulo_para(&mut s, "srv.ejemplo.mx")
    }

    fn sin_tls_es(r: Result<(), String>) -> bool {
        r.is_err_and(|e| e.starts_with(PREFIJO_SIN_TLS))
    }

    #[test]
    fn smtp_imap_y_pop3() {
        let smtp = b"220-srv\r\n220 listo\r\n250-srv\r\n250-PIPELINING\r\n250 STARTTLS\r\n220 adelante\r\n";
        assert!(probar(Starttls::Smtp, smtp).is_ok());
        assert!(sin_tls_es(probar(
            Starttls::Smtp,
            b"220 srv\r\n250 srv\r\n"
        )));
        assert!(probar(Starttls::Smtp, b"554 no\r\n").is_err());
        assert!(
            probar(
                Starttls::Imap,
                b"* OK listo\r\n* algo\r\na1 OK empiece TLS\r\n"
            )
            .is_ok()
        );
        assert!(probar(Starttls::Imap, b"* OK listo\r\na1 NO\r\n").is_err());
        assert!(probar(Starttls::Pop3, b"+OK listo\r\n+OK empiece TLS\r\n").is_ok());
        assert!(probar(Starttls::Pop3, b"-ERR\r\n").is_err());
    }

    #[test]
    fn postgres_mysql_y_ldap() {
        assert!(probar(Starttls::Postgres, b"S").is_ok());
        assert!(sin_tls_es(probar(Starttls::Postgres, b"N")));
        assert!(probar(Starttls::Postgres, b"E").is_err());

        let saludo = |capacidades: u16| {
            let mut p = vec![10];
            p.extend(b"8.4.0\0");
            p.extend([1, 0, 0, 0]);
            p.extend([0u8; 8]);
            p.push(0);
            p.extend(capacidades.to_le_bytes());
            p.extend([0x21, 2, 0, 0, 0]);
            let mut v = (p.len() as u32).to_le_bytes()[..3].to_vec();
            v.push(0);
            v.extend(p);
            v
        };
        assert!(probar(Starttls::Mysql, &saludo(0x0800 | 0x0200)).is_ok());
        assert!(sin_tls_es(probar(Starttls::Mysql, &saludo(0x0200))));
        assert!(probar(Starttls::Mysql, &[1, 0, 0, 0, 0xFF]).is_err());

        // ExtendedResponse con resultCode 0 y con 2 (protocolError).
        let ldap = |codigo: u8| {
            vec![
                0x30, 0x0C, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0A, 0x01, codigo, 0x04, 0x00, 0x04,
                0x00,
            ]
        };
        assert!(probar(Starttls::Ldap, &ldap(0)).is_ok());
        assert!(
            probar(Starttls::Ldap, &ldap(2))
                .unwrap_err()
                .contains("código 2")
        );
        assert!(probar(Starttls::Ldap, &[0x31, 0x00]).is_err());
    }

    #[test]
    fn ftp_y_xmpp() {
        assert!(
            probar(
                Starttls::Ftp,
                b"220-Bienvenido\r\n220 listo\r\n234 AUTH TLS aceptado\r\n"
            )
            .is_ok()
        );
        assert!(sin_tls_es(probar(
            Starttls::Ftp,
            b"220 listo\r\n502 no implementado\r\n"
        )));
        assert!(probar(Starttls::Ftp, b"421 ocupado\r\n").is_err());

        let cabecera = "<?xml version='1.0'?><stream:stream from='srv.ejemplo.mx' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>";
        let con_tls = format!(
            "{cabecera}<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features><proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
        );
        assert!(probar(Starttls::Xmpp, con_tls.as_bytes()).is_ok());
        let sin = format!("{cabecera}<stream:features><mechanisms/></stream:features>");
        assert!(sin_tls_es(probar(Starttls::Xmpp, sin.as_bytes())));
        let rechazo = format!(
            "{cabecera}<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:features><failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
        );
        assert!(
            probar(Starttls::Xmpp, rechazo.as_bytes())
                .unwrap_err()
                .contains("rechazó")
        );
    }

    #[test]
    fn rdp() {
        // TPKT + X.224 Connection Confirm + respuesta (2) o falla (3) de negociación.
        let respuesta = |tipo: u8, valor: u32| {
            let mut v = vec![0x03, 0x00, 0x00, 0x13, 0x0E, 0xD0, 0, 0, 0x12, 0x34, 0];
            v.extend([tipo, 0, 8, 0]);
            v.extend(valor.to_le_bytes());
            v
        };
        assert!(probar(Starttls::Rdp, &respuesta(2, 1)).is_ok());
        assert!(probar(Starttls::Rdp, &respuesta(2, 2)).is_ok());
        assert!(sin_tls_es(probar(Starttls::Rdp, &respuesta(2, 0))));
        assert!(sin_tls_es(probar(Starttls::Rdp, &respuesta(3, 2))));
        assert!(
            probar(Starttls::Rdp, &respuesta(3, 5))
                .unwrap_err()
                .contains("código 5")
        );
        // Sin negociación: seguridad estándar de RDP.
        assert!(sin_tls_es(probar(
            Starttls::Rdp,
            &[0x03, 0, 0, 0x0B, 0x06, 0xD0, 0, 0, 0x12, 0x34, 0]
        )));
        assert!(
            probar(Starttls::Rdp, b"HTTP/1.1 400")
                .unwrap_err()
                .contains("no respondió con RDP")
        );
        assert!(
            probar(Starttls::Rdp, &[0x03, 0, 0, 0x05, 0])
                .unwrap_err()
                .contains("longitud")
        );
    }

    #[test]
    fn esquemas_y_puertos() {
        for (esquema, puerto) in [("ftp", 21), ("xmpp", 5222), ("rdp", 3389), ("smtp", 25)] {
            let st = Starttls::desde_esquema(esquema).unwrap();
            assert_eq!(st.esquema(), esquema);
            assert_eq!(st.puerto_predeterminado(), puerto);
            assert!(!st.nombre().is_empty());
        }
        assert!(Starttls::desde_esquema("gopher").is_none());
    }
}
