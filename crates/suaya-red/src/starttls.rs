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
        }
    }

    /// Ejecuta el preámbulo; al volver, el siguiente byte es del saludo TLS.
    pub fn preambulo(self, s: &mut TcpStream) -> Result<(), String> {
        match self {
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
