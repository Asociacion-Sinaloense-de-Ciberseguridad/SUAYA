//! Sondeo DNS de un dominio indicado: DNSSEC (llaves DNSKEY, delegación DS y
//! firmas RRSIG), llaves DKIM, autoridades autorizadas (CAA) y asociaciones
//! DANE (TLSA).
//!
//! Las consultas van al resolvedor del sistema (`/etc/resolv.conf`), o al
//! que indique la variable `SUAYA_DNS` (`1.1.1.1` o `[2606:4700::1111]:53`),
//! con EDNS0 y el bit DO para recibir las firmas; si la respuesta llega
//! truncada se repite por TCP. Solo se consultan nombres del dominio indicado:
//!
//! - `dns://ejemplo.mx`: DNSKEY, DS y CAA del dominio, TLSA de
//!   `_443._tcp.ejemplo.mx` y DKIM de unos pocos selectores habituales.
//! - `dns://ejemplo.mx/sel1,sel2`: lo mismo, con DKIM solo de esos selectores.
//! - `dns://sel1._domainkey.ejemplo.mx`: solo esa llave DKIM.
//! - `dns://_25._tcp.correo.ejemplo.mx`: solo ese registro TLSA.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use sha2::{Digest, Sha256};
use suaya_core::{Activo, Conocimiento, Detalles, Garantia, Riesgo};
use suaya_escaneo::api::{activo_algoritmo, certificado_en_contexto, id_corto, llave_de_spki};

use crate::{Objetivo, Opciones};

/// Capacidad de los hallazgos DNS (decisión de Suaya, ver `madurez.toml`).
pub(crate) const CAPACIDAD: &str = "infraestructura-dns";

const TXT: u16 = 16;
const DS: u16 = 43;
const RRSIG: u16 = 46;
const DNSKEY: u16 = 48;
const TLSA: u16 = 52;
const CAA: u16 = 257;

/// Respuestas NXDOMAIN y SERVFAIL.
const NXDOMAIN: u8 = 3;
const SERVFAIL: u8 = 2;

/// Selectores DKIM habituales (proveedores de correo y valores por omisión
/// de las herramientas) cuando la ruta no indica ninguno.
const SELECTORES_COMUNES: [&str; 8] = [
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "s1",
    "s2",
    "dkim",
];

/// Llave DNSKEY publicada por la zona.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LlaveDnssec {
    pub banderas: u16,
    pub algoritmo: u8,
    pub etiqueta: u16,
    /// Bits del módulo en llaves RSA.
    pub bits: Option<u32>,
    pub huella: String,
}

impl LlaveDnssec {
    /// KSK (bandera SEP) o ZSK.
    pub fn rol(&self) -> &'static str {
        if self.banderas & 1 == 1 { "KSK" } else { "ZSK" }
    }
}

/// Registro DS de la zona padre.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Delegacion {
    pub etiqueta: u16,
    pub algoritmo: u8,
    pub digestion: u8,
}

/// Firma RRSIG sobre el conjunto DNSKEY.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FirmaDnssec {
    pub algoritmo: u8,
    pub etiqueta: u16,
    /// Segundos desde 1970 (ya resueltos con aritmética de serie, RFC 4034).
    pub inicio: i64,
    pub expiracion: i64,
}

/// Asociación TLSA (RFC 6698).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tlsa {
    pub nombre: String,
    pub uso: u8,
    pub selector: u8,
    pub coincidencia: u8,
    pub datos: Vec<u8>,
}

/// Llave DKIM publicada en `<selector>._domainkey.<dominio>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Dkim {
    pub selector: String,
    /// Etiqueta `k=` en minúsculas (`rsa` por omisión).
    pub tipo_llave: String,
    pub llave: Vec<u8>,
    /// Etiqueta `h=`: digestiones aceptadas, si se restringen.
    pub digestiones: Vec<String>,
    /// `t=y`: el dominio está probando DKIM.
    pub pruebas: bool,
}

/// Lo que respondió el DNS para un objetivo.
#[derive(Debug, Default)]
pub(crate) struct ObservacionDns {
    pub resolvedor: String,
    /// Se consultó DNSSEC (objetivos de dominio completo).
    pub consulto_dnssec: bool,
    pub llaves: Vec<LlaveDnssec>,
    pub delegaciones: Vec<Delegacion>,
    pub firmas: Vec<FirmaDnssec>,
    /// El resolvedor validó la respuesta DNSKEY (bit AD).
    pub validada: bool,
    /// El resolvedor rechazó la zona (SERVFAIL) pero los datos existen con
    /// la validación desactivada (bit CD): la cadena DNSSEC está rota.
    pub rechazada: bool,
    pub caa: Vec<String>,
    pub tlsa: Vec<Tlsa>,
    pub dkim: Vec<Dkim>,
    /// Llaves DKIM revocadas (`p=` vacío), por selector.
    pub dkim_revocadas: Vec<String>,
    pub selectores: Vec<String>,
    pub errores: Vec<String>,
    /// Momento de la observación (segundos desde 1970).
    pub ahora: i64,
    /// Duración de la primera consulta.
    pub latencia_ms: u64,
}

// ---------------------------------------------------------------------------
// Protocolo
// ---------------------------------------------------------------------------

struct Registro {
    tipo: u16,
    datos: Vec<u8>,
}

struct Respuesta {
    rcode: u8,
    autenticada: bool,
    truncada: bool,
    registros: Vec<Registro>,
}

fn consulta(id: u16, nombre: &str, tipo: u16, sin_validar: bool) -> Result<Vec<u8>, String> {
    let mut v = Vec::with_capacity(64);
    v.extend(id.to_be_bytes());
    // RD y AD (RFC 6840: pide que se informe la validación); CD si se
    // quiere ver datos que el resolvedor rechaza.
    v.extend([0x01, if sin_validar { 0x30 } else { 0x20 }]);
    v.extend([0, 1, 0, 0, 0, 0, 0, 1]);
    let nombre = nombre.trim_end_matches('.');
    if nombre.is_empty() || nombre.len() > 253 {
        return Err(format!("nombre DNS inválido: {nombre}"));
    }
    for etiqueta in nombre.split('.') {
        if etiqueta.is_empty() || etiqueta.len() > 63 {
            return Err(format!("nombre DNS inválido: {nombre}"));
        }
        v.push(etiqueta.len() as u8);
        v.extend(etiqueta.as_bytes());
    }
    v.push(0);
    v.extend(tipo.to_be_bytes());
    v.extend(1u16.to_be_bytes());
    // OPT (EDNS0): 1232 bytes de carga UDP y bit DO (DNSSEC OK).
    v.extend([0, 0, 41]);
    v.extend(1232u16.to_be_bytes());
    v.extend([0, 0, 0x80, 0, 0, 0]);
    Ok(v)
}

/// Lee un nombre (con compresión) y devuelve la posición tras él.
fn saltar_nombre(m: &[u8], mut p: usize) -> Result<usize, String> {
    loop {
        let n = *m.get(p).ok_or("nombre DNS truncado")? as usize;
        match n {
            0 => return Ok(p + 1),
            n if n & 0xC0 == 0xC0 => return Ok(p + 2),
            n if n < 64 => p += 1 + n,
            _ => return Err("etiqueta DNS inválida".into()),
        }
    }
}

fn interpretar(m: &[u8], id: u16) -> Result<Respuesta, String> {
    if m.len() < 12 || m[..2] != id.to_be_bytes() {
        return Err("respuesta DNS inválida".into());
    }
    let banderas = u16::from_be_bytes([m[2], m[3]]);
    let preguntas = u16::from_be_bytes([m[4], m[5]]);
    let respuestas = u16::from_be_bytes([m[6], m[7]]);
    let mut p = 12;
    for _ in 0..preguntas {
        p = saltar_nombre(m, p)? + 4;
    }
    let mut registros = Vec::new();
    for _ in 0..respuestas {
        p = saltar_nombre(m, p)?;
        let cabecera = m.get(p..p + 10).ok_or("registro DNS truncado")?;
        let tipo = u16::from_be_bytes([cabecera[0], cabecera[1]]);
        let largo = u16::from_be_bytes([cabecera[8], cabecera[9]]) as usize;
        let datos = m
            .get(p + 10..p + 10 + largo)
            .ok_or("registro DNS truncado")?
            .to_vec();
        registros.push(Registro { tipo, datos });
        p += 10 + largo;
    }
    Ok(Respuesta {
        rcode: (banderas & 0x0F) as u8,
        autenticada: banderas & 0x0020 != 0,
        truncada: banderas & 0x0200 != 0,
        registros,
    })
}

/// Interpreta una respuesta con el identificador de sus dos primeros bytes.
pub(crate) fn interpretar_para_fuzz(m: &[u8]) -> Result<usize, String> {
    let id = u16::from_be_bytes([m[0], m[1]]);
    interpretar(m, id).map(|r| r.registros.len())
}

/// Interpreta un texto como registro DKIM.
pub(crate) fn dkim_para_fuzz(texto: &str) -> bool {
    matches!(dkim("fuzz", texto), Ok(Some(_)))
}

fn por_tcp(servidor: SocketAddr, q: &[u8], tiempo: Duration) -> Result<Vec<u8>, String> {
    let mut s =
        TcpStream::connect_timeout(&servidor, tiempo).map_err(|e| format!("DNS por TCP: {e}"))?;
    s.set_read_timeout(Some(tiempo)).ok();
    s.set_write_timeout(Some(tiempo)).ok();
    let mut v = (q.len() as u16).to_be_bytes().to_vec();
    v.extend(q);
    s.write_all(&v).map_err(|e| format!("DNS por TCP: {e}"))?;
    let mut largo = [0u8; 2];
    s.read_exact(&mut largo)
        .map_err(|e| format!("DNS por TCP: {e}"))?;
    let mut r = vec![0u8; u16::from_be_bytes(largo) as usize];
    s.read_exact(&mut r)
        .map_err(|e| format!("DNS por TCP: {e}"))?;
    Ok(r)
}

fn consultar(
    servidor: SocketAddr,
    nombre: &str,
    tipo: u16,
    sin_validar: bool,
    tiempo: Duration,
) -> Result<Respuesta, String> {
    let azar = crate::ike::aleatorio(2);
    let id = u16::from_be_bytes([azar[0], azar[1]]);
    let q = consulta(id, nombre, tipo, sin_validar)?;
    let local = if servidor.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let s = UdpSocket::bind(local).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(tiempo)).ok();
    s.connect(servidor)
        .map_err(|e| format!("resolvedor {servidor}: {e}"))?;
    let mut b = vec![0u8; 4096];
    let mut bruto = None;
    // Un reenvío ante pérdida; las respuestas ajenas se descartan.
    'envios: for _ in 0..2 {
        s.send(&q)
            .map_err(|e| format!("resolvedor {servidor}: {e}"))?;
        for _ in 0..16 {
            match s.recv(&mut b) {
                Ok(n) if n >= 12 && b[..2] == id.to_be_bytes() => {
                    bruto = Some(b[..n].to_vec());
                    break 'envios;
                }
                Ok(_) => continue,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue 'envios;
                }
                Err(e) => return Err(format!("resolvedor {servidor}: {e}")),
            }
        }
    }
    let bruto = bruto.ok_or_else(|| format!("el resolvedor {servidor} no respondió"))?;
    let r = interpretar(&bruto, id)?;
    if r.truncada {
        return interpretar(&por_tcp(servidor, &q, tiempo)?, id);
    }
    Ok(r)
}

/// Variable con el resolvedor a usar en lugar del del sistema.
pub const VARIABLE_RESOLVEDOR: &str = "SUAYA_DNS";

/// `SUAYA_DNS` o el primer servidor de `/etc/resolv.conf` (IPv4 primero).
fn resolvedor_del_sistema() -> Result<SocketAddr, String> {
    if let Ok(v) = std::env::var(VARIABLE_RESOLVEDOR)
        && !v.trim().is_empty()
    {
        let v = v.trim();
        return v
            .parse::<SocketAddr>()
            .or_else(|_| v.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, 53)))
            .map_err(|_| format!("{VARIABLE_RESOLVEDOR} no es una dirección IP válida: {v}"));
    }
    let texto = std::fs::read_to_string("/etc/resolv.conf")
        .map_err(|e| format!("no se pudo leer /etc/resolv.conf: {e}"))?;
    let mut servidores: Vec<IpAddr> = texto
        .lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .filter_map(|x| x.trim().parse().ok())
        .collect();
    servidores.sort_by_key(|ip| !ip.is_ipv4());
    servidores
        .first()
        .map(|ip| SocketAddr::new(*ip, 53))
        .ok_or_else(|| "no hay servidores DNS en /etc/resolv.conf".into())
}

// ---------------------------------------------------------------------------
// Registros
// ---------------------------------------------------------------------------

/// Etiqueta de llave (RFC 4034, apéndice B).
fn etiqueta_llave(rdata: &[u8]) -> u16 {
    let mut ac: u32 = 0;
    for (i, &b) in rdata.iter().enumerate() {
        ac += if i & 1 == 1 {
            b as u32
        } else {
            (b as u32) << 8
        };
    }
    ac += (ac >> 16) & 0xFFFF;
    (ac & 0xFFFF) as u16
}

fn bits(entero: &[u8]) -> u32 {
    let sin_ceros = match entero.iter().position(|&b| b != 0) {
        Some(i) => &entero[i..],
        None => return 0,
    };
    sin_ceros.len() as u32 * 8 - sin_ceros[0].leading_zeros()
}

/// Bits del módulo de una llave RSA en formato DNSSEC (RFC 3110).
fn bits_rsa_dnssec(llave: &[u8]) -> Option<u32> {
    let (exp, resto) = match *llave.first()? {
        0 => (
            u16::from_be_bytes([*llave.get(1)?, *llave.get(2)?]) as usize,
            &llave[3..],
        ),
        n => (n as usize, &llave[1..]),
    };
    let modulo = resto.get(exp..)?;
    (!modulo.is_empty()).then(|| bits(modulo))
}

fn es_rsa(algoritmo: u8) -> bool {
    matches!(algoritmo, 1 | 5 | 7 | 8 | 10)
}

/// Mnemónico IANA de un algoritmo DNSSEC.
pub(crate) fn mnemonico(algoritmo: u8) -> String {
    match algoritmo {
        1 => "RSAMD5",
        3 => "DSA",
        5 => "RSASHA1",
        6 => "DSA-NSEC3-SHA1",
        7 => "RSASHA1-NSEC3-SHA1",
        8 => "RSASHA256",
        10 => "RSASHA512",
        12 => "ECC-GOST",
        13 => "ECDSAP256SHA256",
        14 => "ECDSAP384SHA384",
        15 => "ED25519",
        16 => "ED448",
        17 => "SM2SM3",
        18 => "MLDSA44",
        23 => "ECC-GOST12",
        n => return format!("algoritmo {n}"),
    }
    .into()
}

/// Nombre de un tipo de digestión DS.
pub(crate) fn nombre_digestion(tipo: u8) -> String {
    match tipo {
        1 => "SHA-1",
        2 => "SHA-256",
        3 => "GOST R 34.11-94",
        4 => "SHA-384",
        5 => "GOST R 34.11-2012",
        6 => "SM3",
        n => return format!("digestión {n}"),
    }
    .into()
}

/// Descripción de un registro TLSA: «DANE-EE, SPKI, SHA-256».
pub(crate) fn describir_tlsa(t: &Tlsa) -> String {
    let uso = match t.uso {
        0 => "PKIX-TA",
        1 => "PKIX-EE",
        2 => "DANE-TA",
        3 => "DANE-EE",
        _ => "uso desconocido",
    };
    let selector = match t.selector {
        0 => "certificado",
        1 => "SPKI",
        _ => "selector desconocido",
    };
    let coincidencia = match t.coincidencia {
        0 => "completo",
        1 => "SHA-256",
        2 => "SHA-512",
        _ => "coincidencia desconocida",
    };
    format!("{uso}, {selector}, {coincidencia}")
}

fn llave_dnskey(rdata: &[u8]) -> Option<LlaveDnssec> {
    let banderas = u16::from_be_bytes([*rdata.first()?, *rdata.get(1)?]);
    let algoritmo = *rdata.get(3)?;
    let llave = rdata.get(4..)?;
    Some(LlaveDnssec {
        banderas,
        algoritmo,
        etiqueta: etiqueta_llave(rdata),
        bits: es_rsa(algoritmo).then(|| bits_rsa_dnssec(llave)).flatten(),
        huella: hex::encode(Sha256::digest(rdata)),
    })
}

/// Lleva un tiempo de 32 bits (aritmética de serie) al más cercano a `ahora`.
fn tiempo_de_serie(valor: u32, ahora: i64) -> i64 {
    ahora + (valor.wrapping_sub(ahora as u32) as i32) as i64
}

fn firma_rrsig(rdata: &[u8], ahora: i64) -> Option<(u16, FirmaDnssec)> {
    let d = rdata.get(..18)?;
    let u32_en = |i: usize| u32::from_be_bytes([d[i], d[i + 1], d[i + 2], d[i + 3]]);
    Some((
        u16::from_be_bytes([d[0], d[1]]),
        FirmaDnssec {
            algoritmo: d[2],
            expiracion: tiempo_de_serie(u32_en(8), ahora),
            inicio: tiempo_de_serie(u32_en(12), ahora),
            etiqueta: u16::from_be_bytes([d[16], d[17]]),
        },
    ))
}

fn texto_caa(rdata: &[u8]) -> Option<String> {
    let largo = *rdata.get(1)? as usize;
    let etiqueta = String::from_utf8_lossy(rdata.get(2..2 + largo)?).to_ascii_lowercase();
    let valor = String::from_utf8_lossy(rdata.get(2 + largo..)?).into_owned();
    Some(format!("{etiqueta} {valor}"))
}

fn texto_txt(rdata: &[u8]) -> String {
    let mut v = Vec::new();
    let mut p = 0;
    while p < rdata.len() {
        let n = rdata[p] as usize;
        v.extend(rdata.get(p + 1..p + 1 + n).unwrap_or(&[]));
        p += 1 + n;
    }
    String::from_utf8_lossy(&v).into_owned()
}

/// Interpreta un registro DKIM (RFC 6376, sección 3.6.1). `Ok(None)` indica
/// una llave revocada (`p=` vacío).
fn dkim(selector: &str, texto: &str) -> Result<Option<Dkim>, ()> {
    let mut tipo_llave = "rsa".to_string();
    let mut llave = None;
    let mut digestiones = Vec::new();
    let mut pruebas = false;
    for parte in texto.split(';') {
        let Some((k, v)) = parte.split_once('=') else {
            continue;
        };
        let v = v.trim();
        match k.trim() {
            "v" if v != "DKIM1" => return Err(()),
            "k" => tipo_llave = v.to_ascii_lowercase(),
            "p" => llave = Some(v.split_whitespace().collect::<String>()),
            "h" => {
                digestiones = v
                    .split(':')
                    .map(|x| x.trim().to_ascii_lowercase())
                    .filter(|x| !x.is_empty())
                    .collect()
            }
            "t" => pruebas = v.split(':').any(|x| x.trim() == "y"),
            _ => {}
        }
    }
    let llave = llave.ok_or(())?;
    if llave.is_empty() {
        return Ok(None);
    }
    let llave = base64::engine::general_purpose::STANDARD
        .decode(&llave)
        .or_else(|_| {
            base64::engine::general_purpose::STANDARD_NO_PAD.decode(llave.trim_end_matches('='))
        })
        .map_err(|_| ())?;
    Ok(Some(Dkim {
        selector: selector.into(),
        tipo_llave,
        llave,
        digestiones,
        pruebas,
    }))
}

// ---------------------------------------------------------------------------
// Observación
// ---------------------------------------------------------------------------

pub(crate) fn ahora() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

pub(crate) fn observar(o: &Objetivo, op: &Opciones) -> Result<ObservacionDns, String> {
    observar_con(resolvedor_del_sistema()?, o, op, ahora())
}

pub(crate) fn observar_con(
    servidor: SocketAddr,
    o: &Objetivo,
    op: &Opciones,
    ahora: i64,
) -> Result<ObservacionDns, String> {
    let t = op.tiempo_limite;
    let inicio = std::time::Instant::now();
    let dominio = o.host.trim_end_matches('.').to_ascii_lowercase();
    let mut obs = ObservacionDns {
        resolvedor: servidor.to_string(),
        ahora,
        ..Default::default()
    };
    let no_existe = |nombre: &str, r: &Respuesta| -> Result<(), String> {
        match r.rcode {
            0 => Ok(()),
            NXDOMAIN => Err(format!("{nombre} no existe (NXDOMAIN)")),
            n => Err(format!(
                "el resolvedor respondió con código {n} para {nombre}"
            )),
        }
    };

    // Objetivos de un solo registro.
    if let Some((selector, _)) = dominio.split_once("._domainkey.") {
        obs.selectores.push(selector.into());
        let r = consultar(servidor, &dominio, TXT, false, t)?;
        obs.latencia_ms = inicio.elapsed().as_millis() as u64;
        no_existe(&dominio, &r)?;
        agregar_dkim(&mut obs, selector, &r);
        return Ok(obs);
    }
    if dominio.starts_with('_') && (dominio.contains("._tcp.") || dominio.contains("._udp.")) {
        let r = consultar(servidor, &dominio, TLSA, false, t)?;
        obs.latencia_ms = inicio.elapsed().as_millis() as u64;
        no_existe(&dominio, &r)?;
        agregar_tlsa(&mut obs, &dominio, &r);
        return Ok(obs);
    }

    obs.consulto_dnssec = true;
    let mut r = consultar(servidor, &dominio, DNSKEY, false, t)?;
    obs.latencia_ms = inicio.elapsed().as_millis() as u64;
    if r.rcode == SERVFAIL
        && let Ok(sin_validar) = consultar(servidor, &dominio, DNSKEY, true, t)
        && sin_validar.rcode == 0
    {
        obs.rechazada = true;
        r = sin_validar;
    }
    no_existe(&dominio, &r)?;
    obs.validada = r.autenticada;
    for x in &r.registros {
        match x.tipo {
            DNSKEY => obs.llaves.extend(llave_dnskey(&x.datos)),
            RRSIG => {
                if let Some((DNSKEY, f)) = firma_rrsig(&x.datos, ahora) {
                    obs.firmas.push(f);
                }
            }
            _ => {}
        }
    }
    let cd = obs.rechazada;
    match consultar(servidor, &dominio, DS, cd, t) {
        Ok(r) => obs
            .delegaciones
            .extend(r.registros.iter().filter(|x| x.tipo == DS).filter_map(|x| {
                let d = x.datos.get(..4)?;
                Some(Delegacion {
                    etiqueta: u16::from_be_bytes([d[0], d[1]]),
                    algoritmo: d[2],
                    digestion: d[3],
                })
            })),
        Err(e) => obs.errores.push(format!("DS: {e}")),
    }
    match consultar(servidor, &dominio, CAA, cd, t) {
        Ok(r) => obs.caa.extend(
            r.registros
                .iter()
                .filter(|x| x.tipo == CAA)
                .filter_map(|x| texto_caa(&x.datos)),
        ),
        Err(e) => obs.errores.push(format!("CAA: {e}")),
    }
    let nombre_tlsa = format!("_443._tcp.{dominio}");
    match consultar(servidor, &nombre_tlsa, TLSA, cd, t) {
        Ok(r) => agregar_tlsa(&mut obs, &nombre_tlsa, &r),
        Err(e) => obs.errores.push(format!("TLSA: {e}")),
    }
    let selectores: Vec<String> = if o.ruta.trim_matches('/').is_empty() {
        SELECTORES_COMUNES.iter().map(|s| s.to_string()).collect()
    } else {
        o.ruta
            .trim_matches('/')
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect()
    };
    for selector in &selectores {
        let nombre = format!("{selector}._domainkey.{dominio}");
        match consultar(servidor, &nombre, TXT, cd, t) {
            Ok(r) => agregar_dkim(&mut obs, selector, &r),
            Err(e) => obs.errores.push(format!("DKIM {selector}: {e}")),
        }
    }
    obs.selectores = selectores;
    Ok(obs)
}

fn agregar_tlsa(obs: &mut ObservacionDns, nombre: &str, r: &Respuesta) {
    obs.tlsa.extend(
        r.registros
            .iter()
            .filter(|x| x.tipo == TLSA)
            .filter_map(|x| {
                let d = &x.datos;
                (d.len() > 3).then(|| Tlsa {
                    nombre: nombre.into(),
                    uso: d[0],
                    selector: d[1],
                    coincidencia: d[2],
                    datos: d[3..].to_vec(),
                })
            }),
    );
}

fn agregar_dkim(obs: &mut ObservacionDns, selector: &str, r: &Respuesta) {
    for x in r.registros.iter().filter(|x| x.tipo == TXT) {
        match dkim(selector, &texto_txt(&x.datos)) {
            Ok(Some(k)) => obs.dkim.push(k),
            Ok(None) => obs.dkim_revocadas.push(selector.into()),
            Err(()) => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Activos
// ---------------------------------------------------------------------------

/// Algoritmo, nombre y bits de una llave DKIM.
pub(crate) fn llave_dkim(k: &Dkim, c: &Conocimiento) -> (Option<String>, String, Option<u32>) {
    match k.tipo_llave.as_str() {
        "rsa" => match llave_de_spki(&k.llave, c) {
            Some(x) => x,
            // Algunos dominios publican RSAPublicKey sin SubjectPublicKeyInfo.
            None => (Some("rsa".into()), "RSA".into(), bits_rsa_publica(&k.llave)),
        },
        "ed25519" => (Some("ed25519".into()), "Ed25519".into(), None),
        otro => (None, format!("DKIM k={otro}"), None),
    }
}

/// Bits del módulo de un `RSAPublicKey` en DER.
fn bits_rsa_publica(der: &[u8]) -> Option<u32> {
    let tlv = |d: &[u8]| -> Option<(u8, usize, usize)> {
        let t = *d.first()?;
        let l = *d.get(1)?;
        let (n, cab) = if l < 0x80 {
            (l as usize, 2)
        } else {
            let k = (l & 0x7F) as usize;
            if k == 0 || k > 4 {
                return None;
            }
            let n = d
                .get(2..2 + k)?
                .iter()
                .fold(0usize, |a, &b| a << 8 | b as usize);
            (n, 2 + k)
        };
        (d.len() >= cab + n).then_some((t, cab, n))
    };
    let (0x30, cab, _) = tlv(der)? else {
        return None;
    };
    let dentro = &der[cab..];
    let (0x02, cab, n) = tlv(dentro)? else {
        return None;
    };
    Some(bits(&dentro[cab..cab + n]))
}

pub(crate) fn activos(o: &Objetivo, obs: &ObservacionDns, c: &Conocimiento) -> Vec<Activo> {
    let ubicacion = o.ubicacion();
    let dominio = o.host.trim_end_matches('.').to_ascii_lowercase();
    let mut todos: Vec<Activo> = Vec::new();
    let mut p = Activo::nuevo(
        format!("protocolo:dnssec:{}", id_corto(&ubicacion)),
        format!("DNS de {dominio}"),
        Detalles::Protocolo {
            tipo_protocolo: "dnssec".into(),
            versiones: Vec::new(),
            grupos: Vec::new(),
            cifrados: Vec::new(),
        },
    )
    .con_contexto(CAPACIDAD, Garantia::Autenticacion)
    .con_ubicacion(&ubicacion, None);
    let algoritmo = |id: Option<&str>, respaldo: &str, tamano: Option<u32>, g: Garantia| {
        activo_algoritmo(
            id.and_then(|i| c.por_id(i)),
            respaldo,
            tamano,
            CAPACIDAD,
            Some(g),
            &ubicacion,
            None,
        )
    };

    // DNSSEC.
    let mut riesgos = Vec::new();
    for k in &obs.llaves {
        let def = c.por_alias("dnssec-alg", &k.algoritmo.to_string());
        if let Some(d) = def {
            riesgos.push(d.riesgo);
        }
        let firma = agregar(
            algoritmo(
                def.map(|d| d.id.as_str()),
                &format!("DNSSEC {}", mnemonico(k.algoritmo)),
                None,
                Garantia::Autenticacion,
            ),
            &mut todos,
        );
        p.relacionar("algorithm", &firma);
        let mut m = Activo::nuevo(
            format!("llave:dnssec:{}", &k.huella[..16]),
            format!(
                "Llave DNSKEY {} {} de {dominio} ({})",
                k.rol(),
                k.etiqueta,
                mnemonico(k.algoritmo)
            ),
            Detalles::Material {
                tipo_material: "public-key".into(),
                tamano: k.bits,
                formato: "DNSKEY".into(),
                protegido_por: None,
                huella_sha256: Some(k.huella.clone()),
                identidad_llave: None,
            },
        )
        .con_contexto(CAPACIDAD, Garantia::Autenticacion)
        .con_ubicacion(&ubicacion, None);
        m.relacionar("algorithm", &firma);
        if let Some(b) = k.bits {
            let rsa = agregar(
                algoritmo(Some("rsa"), "RSA", Some(b), Garantia::Autenticacion),
                &mut todos,
            );
            m.relacionar("algorithm", &rsa);
            p.relacionar("algorithm", &rsa);
        }
        p.relacionar("publicKey", &m.referencia);
        agregar(m, &mut todos);
    }
    for d in &obs.delegaciones {
        let def = c.por_alias("dnssec-ds", &d.digestion.to_string());
        let x = agregar(
            algoritmo(
                def.map(|d| d.id.as_str()),
                &format!("DS {}", nombre_digestion(d.digestion)),
                None,
                Garantia::Integridad,
            ),
            &mut todos,
        );
        p.relacionar("algorithm", &x);
    }
    if obs.consulto_dnssec {
        if obs.llaves.is_empty() {
            p.advertir(format!(
                "{dominio} no publica llaves DNSKEY: sus respuestas DNS no se firman con DNSSEC."
            ));
        } else {
            let llaves: Vec<String> = obs
                .llaves
                .iter()
                .map(|k| format!("{} {} {}", k.rol(), k.etiqueta, mnemonico(k.algoritmo)))
                .collect();
            p.advertir(format!("Llaves DNSKEY: {}.", llaves.join(", ")));
            if obs.delegaciones.is_empty() {
                p.advertir("Sin registro DS en la zona padre: la cadena de confianza DNSSEC no llega al dominio.");
            }
            if obs.rechazada {
                p.advertir("El resolvedor rechazó la zona (SERVFAIL) y solo respondió con la validación desactivada: la cadena DNSSEC está rota.");
            } else if obs.validada {
                p.advertir("El resolvedor validó la cadena DNSSEC (bit AD).");
            } else if obs.firmas.is_empty() {
                p.advertir("El resolvedor no devolvió firmas RRSIG: no admite DNSSEC; indique uno que valide con SUAYA_DNS.");
            }
            for f in obs.firmas.iter().filter(|f| f.expiracion < obs.ahora) {
                p.advertir(format!(
                    "La firma RRSIG de DNSKEY (etiqueta {}) venció el {}.",
                    f.etiqueta,
                    fecha(f.expiracion)
                ));
            }
            if riesgos
                .iter()
                .any(|r| matches!(r, Riesgo::HibridoPq | Riesgo::ResistenteCuantico))
            {
                p.advertir("Firma la zona con un algoritmo poscuántico.");
            } else if !riesgos.is_empty() {
                p.advertir("Las firmas DNSSEC dependen solo de algoritmos clásicos: una computadora cuántica relevante podría falsificar respuestas.");
            }
        }
        if obs.caa.is_empty() {
            p.advertir(
                "Sin registro CAA: cualquier autoridad certificadora puede emitir certificados para el dominio.",
            );
        } else {
            p.advertir(format!("CAA: {}.", obs.caa.join(" | ")));
        }
    }

    // TLSA.
    for t in &obs.tlsa {
        let lugar = format!("dns://{}", t.nombre);
        p.advertir(format!("TLSA en {}: {}.", t.nombre, describir_tlsa(t)));
        match (t.selector, t.coincidencia) {
            (0, 0) => {
                if let Ok(v) = certificado_en_contexto(&t.datos, &lugar, CAPACIDAD, c) {
                    for x in v {
                        if matches!(x.detalles, Detalles::Certificado { .. }) {
                            p.relacionar("certificate", &x.referencia);
                        }
                        agregar(x, &mut todos);
                    }
                }
            }
            (1, 0) => {
                if let Some((id, respaldo, tamano)) = llave_de_spki(&t.datos, c) {
                    let x = agregar(
                        algoritmo(id.as_deref(), &respaldo, tamano, Garantia::Autenticacion),
                        &mut todos,
                    );
                    p.relacionar("algorithm", &x);
                }
            }
            (_, 1) | (_, 2) => {
                let id = if t.coincidencia == 1 {
                    "sha256"
                } else {
                    "sha512"
                };
                let x = agregar(
                    algoritmo(Some(id), id, None, Garantia::Integridad),
                    &mut todos,
                );
                p.relacionar("algorithm", &x);
            }
            _ => {}
        }
    }

    // DKIM.
    for k in &obs.dkim {
        let (id, respaldo, tamano) = llave_dkim(k, c);
        let alg = agregar(
            algoritmo(id.as_deref(), &respaldo, tamano, Garantia::Autenticacion),
            &mut todos,
        );
        let huella = hex::encode(Sha256::digest(&k.llave));
        let mut m = Activo::nuevo(
            format!("llave:dkim:{}", &huella[..16]),
            format!("Llave DKIM {} de {dominio}", k.selector),
            Detalles::Material {
                tipo_material: "public-key".into(),
                tamano,
                formato: "DKIM".into(),
                protegido_por: None,
                huella_sha256: Some(huella),
                identidad_llave: None,
            },
        )
        .con_contexto(CAPACIDAD, Garantia::Autenticacion)
        .con_ubicacion(&format!("dns://{}._domainkey.{dominio}", k.selector), None);
        m.relacionar("algorithm", &alg);
        // El dominio hereda el riesgo de sus llaves DKIM.
        p.relacionar("algorithm", &alg);
        if k.pruebas {
            m.advertir("t=y: el dominio indica que está probando DKIM.");
        }
        if k.digestiones.iter().any(|h| h == "sha1") {
            m.advertir("Acepta rsa-sha1, que RFC 8301 prohíbe para firmar y verificar.");
            let x = agregar(
                algoritmo(Some("sha1"), "sha1", None, Garantia::Integridad),
                &mut todos,
            );
            m.relacionar("algorithm", &x);
        }
        p.relacionar("publicKey", &m.referencia);
        agregar(m, &mut todos);
    }
    if !obs.dkim_revocadas.is_empty() {
        p.advertir(format!(
            "Llaves DKIM revocadas (p= vacío): {}.",
            obs.dkim_revocadas.join(", ")
        ));
    }
    if obs.consulto_dnssec && obs.dkim.is_empty() {
        p.advertir(format!(
            "No se halló DKIM en los selectores consultados ({}); indíquelos con dns://{dominio}/selector1,selector2.",
            obs.selectores.join(", ")
        ));
    }
    p.advertir("Observado en el DNS: refleja lo que el dominio publica realmente.");
    todos.push(p);
    todos
}

/// Agrega un activo (o lo fusiona con uno igual) y devuelve su referencia.
fn agregar(x: Activo, todos: &mut Vec<Activo>) -> String {
    let referencia = x.referencia.clone();
    match todos.iter_mut().find(|y| y.referencia == referencia) {
        Some(y) => y.fusionar(x),
        None => todos.push(x),
    }
    referencia
}

pub(crate) fn fecha(segundos: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(segundos)
        .map(|t| {
            let d = t.date();
            format!("{:04}-{:02}-{:02}", d.year(), u8::from(d.month()), d.day())
        })
        .unwrap_or_else(|_| segundos.to_string())
}

pub(crate) fn sondear(
    o: &Objetivo,
    c: &Conocimiento,
    op: &Opciones,
) -> Result<(Vec<Activo>, Vec<String>), String> {
    let obs = observar(o, op)?;
    Ok((activos(o, &obs, c), obs.errores.clone()))
}

#[cfg(test)]
pub(crate) mod pruebas {
    use super::*;

    /// Codifica un nombre sin compresión.
    fn nombre(n: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for e in n.split('.') {
            v.push(e.len() as u8);
            v.extend(e.as_bytes());
        }
        v.push(0);
        v
    }

    fn txt(texto: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for trozo in texto.as_bytes().chunks(255) {
            v.push(trozo.len() as u8);
            v.extend(trozo);
        }
        v
    }

    /// Llave pública RSA de 2048 bits (SubjectPublicKeyInfo en base64).
    const DKIM_RSA_2048: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyWnq8h4oaXKsMo+SfnuXsHvdAC6fraFM6xLWh/QUYAZoCCcVbq7RXxrd08xN8DWX96bk6x5xD1uI27iq3ZNkyVkxar2WWcz3bd/i2qDpLaYLgG1IUDa24D3z1WAd7kiLujw0cTDanY4gZ3fQZTAXqav8EvRt8Kz/rFBU+LlVIX1JZwLqNhPvKmc0RDEh8HS9QEQC0pTlZjIgKrmVZ+iO7md/5mTNRcB+tfV0tUFBnsxOBL/bsyi3dmoMi7oJcAvXuk7oR7e4wuaOCqdi2p5KmJod41jcu6l0G137DXzDGrlqtY7w1z3XYZLSC/D9Kx79WyKsFhiRRvSDqdmWVuaGHwIDAQAB";

    /// Zona simulada: registros por nombre y tipo.
    pub(crate) struct Zona {
        pub registros: Vec<(String, u16, Vec<u8>)>,
        /// Responder SERVFAIL salvo con el bit CD.
        pub rota: bool,
        pub autenticada: bool,
    }

    /// Responde una consulta como lo haría un resolvedor.
    pub(crate) fn responder(z: &Zona, q: &[u8]) -> Vec<u8> {
        let mut p = 12;
        let mut etiquetas = Vec::new();
        while q[p] != 0 {
            let n = q[p] as usize;
            etiquetas.push(String::from_utf8_lossy(&q[p + 1..p + 1 + n]).into_owned());
            p += 1 + n;
        }
        let consulta_nombre = etiquetas.join(".");
        let tipo = u16::from_be_bytes([q[p + 1], q[p + 2]]);
        let cd = q[3] & 0x10 != 0;
        let fin_pregunta = p + 5;
        let mut r = q[..2].to_vec();
        let mut respuestas: Vec<&(String, u16, Vec<u8>)> = z
            .registros
            .iter()
            .filter(|(n, t, _)| *n == consulta_nombre && (*t == tipo || *t == RRSIG))
            .collect();
        if tipo != DNSKEY {
            respuestas.retain(|(_, t, _)| *t != RRSIG);
        }
        let existe = z.registros.iter().any(|(n, _, _)| *n == consulta_nombre)
            || consulta_nombre.starts_with('_')
            || z.registros
                .iter()
                .any(|(n, _, _)| n.ends_with(&consulta_nombre));
        let rcode = if z.rota && !cd {
            SERVFAIL
        } else if existe {
            0
        } else {
            NXDOMAIN
        };
        if rcode != 0 {
            respuestas.clear();
        }
        r.extend([0x81, (if z.autenticada { 0xA0 } else { 0x80 }) | rcode]);
        r.extend([0, 1]);
        r.extend((respuestas.len() as u16).to_be_bytes());
        r.extend([0, 0, 0, 0]);
        r.extend(&q[12..fin_pregunta]);
        for (_, t, datos) in respuestas {
            r.extend([0xC0, 12]);
            r.extend(t.to_be_bytes());
            r.extend([0, 1, 0, 0, 0x0E, 0x10]);
            r.extend((datos.len() as u16).to_be_bytes());
            r.extend(datos);
        }
        r
    }

    pub(crate) fn resolvedor_simulado(z: Zona) -> SocketAddr {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let direccion = s.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut b = vec![0u8; 4096];
            while let Ok((n, origen)) = s.recv_from(&mut b) {
                let r = responder(&z, &b[..n]);
                let _ = s.send_to(&r, origen);
            }
        });
        direccion
    }

    fn dnskey(banderas: u16, algoritmo: u8, llave: &[u8]) -> Vec<u8> {
        let mut v = banderas.to_be_bytes().to_vec();
        v.extend([3, algoritmo]);
        v.extend(llave);
        v
    }

    fn rrsig(algoritmo: u8, expiracion: u32, inicio: u32) -> Vec<u8> {
        let mut v = DNSKEY.to_be_bytes().to_vec();
        v.extend([algoritmo, 2]);
        v.extend(3600u32.to_be_bytes());
        v.extend(expiracion.to_be_bytes());
        v.extend(inicio.to_be_bytes());
        v.extend(12345u16.to_be_bytes());
        v.extend(nombre("ejemplo.mx"));
        v.extend([0u8; 64]);
        v
    }

    /// Llave RSA de 2048 bits en formato RFC 3110 (exponente 65537).
    fn rsa_dnssec() -> Vec<u8> {
        let mut v = vec![3, 1, 0, 1, 0xC0];
        v.extend([0x11u8; 255]);
        v
    }

    pub(crate) fn zona_ejemplo(ahora: u32) -> Zona {
        let mut caa = vec![0, 5];
        caa.extend(b"issueletsencrypt.org");
        let mut tlsa = vec![3, 1, 1];
        tlsa.extend([0xAB; 32]);
        Zona {
            registros: vec![
                ("ejemplo.mx".into(), DNSKEY, dnskey(257, 13, &[7u8; 64])),
                ("ejemplo.mx".into(), DNSKEY, dnskey(256, 8, &rsa_dnssec())),
                (
                    "ejemplo.mx".into(),
                    RRSIG,
                    rrsig(13, ahora - 60, ahora - 86400),
                ),
                ("ejemplo.mx".into(), DS, vec![0x30, 0x39, 13, 1, 0xAA, 0xBB]),
                ("ejemplo.mx".into(), CAA, caa),
                ("_443._tcp.ejemplo.mx".into(), TLSA, tlsa),
                (
                    "selector1._domainkey.ejemplo.mx".into(),
                    TXT,
                    txt(&format!("v=DKIM1; k=rsa; h=sha1:sha256; p={DKIM_RSA_2048}")),
                ),
                (
                    "google._domainkey.ejemplo.mx".into(),
                    TXT,
                    txt("v=DKIM1; p="),
                ),
                (
                    "s1._domainkey.ejemplo.mx".into(),
                    TXT,
                    txt("v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="),
                ),
            ],
            rota: false,
            autenticada: true,
        }
    }

    pub(crate) fn opciones() -> Opciones {
        Opciones {
            tiempo_limite: Duration::from_secs(3),
            capacidad_tls: "servidores-web".into(),
            certificados: false,
            diagnostico: false,
            autoridad_pem: None,
        }
    }

    #[test]
    fn dominio_completo() {
        let ahora = 1_793_000_000u32;
        let servidor = resolvedor_simulado(zona_ejemplo(ahora));
        let o = Objetivo::interpretar("dns://ejemplo.mx").unwrap();
        let obs = observar_con(servidor, &o, &opciones(), ahora as i64).unwrap();
        assert!(obs.validada);
        assert_eq!(obs.llaves.len(), 2);
        assert_eq!(obs.llaves[0].rol(), "KSK");
        assert_eq!(obs.llaves[1].bits, Some(2048));
        assert_eq!(
            obs.delegaciones,
            vec![Delegacion {
                etiqueta: 12345,
                algoritmo: 13,
                digestion: 1
            }]
        );
        assert_eq!(obs.firmas.len(), 1);
        assert!(obs.firmas[0].expiracion < ahora as i64);
        assert_eq!(obs.caa, vec!["issue letsencrypt.org".to_string()]);
        assert_eq!(obs.tlsa.len(), 1);
        assert_eq!(describir_tlsa(&obs.tlsa[0]), "DANE-EE, SPKI, SHA-256");
        assert_eq!(obs.dkim.len(), 2);
        assert_eq!(obs.dkim_revocadas, vec!["google".to_string()]);

        let c = Conocimiento::embebido();
        let v = activos(&o, &obs, &c);
        let refs: Vec<&str> = v.iter().map(|a| a.referencia.as_str()).collect();
        assert!(refs.contains(&"algoritmo:ecdsa-sha256"), "{refs:?}");
        assert!(refs.contains(&"algoritmo:rsassa-pkcs1-sha256"), "{refs:?}");
        assert!(refs.contains(&"algoritmo:rsa-2048"), "{refs:?}");
        assert!(refs.contains(&"algoritmo:sha1"), "{refs:?}");
        assert!(refs.contains(&"algoritmo:ed25519"), "{refs:?}");
        assert!(refs.contains(&"algoritmo:sha256"), "{refs:?}");
        let p = v
            .iter()
            .find(|a| a.referencia.starts_with("protocolo:dnssec:"))
            .unwrap();
        let avisos = p.advertencias.join("\n");
        assert!(avisos.contains("venció"), "{avisos}");
        assert!(avisos.contains("validó"), "{avisos}");
        assert!(avisos.contains("letsencrypt.org"), "{avisos}");
        assert!(avisos.contains("revocadas"), "{avisos}");
        let dkim = v
            .iter()
            .find(|a| a.nombre.starts_with("Llave DKIM selector1"))
            .unwrap();
        assert!(dkim.advertencias.iter().any(|x| x.contains("RFC 8301")));
        assert!(matches!(
            dkim.detalles,
            Detalles::Material {
                tamano: Some(2048),
                ..
            }
        ));
    }

    #[test]
    fn cadena_rota_y_objetivos_puntuales() {
        let ahora = 1_793_000_000u32;
        let mut z = zona_ejemplo(ahora);
        z.rota = true;
        z.autenticada = false;
        let servidor = resolvedor_simulado(z);
        let o = Objetivo::interpretar("dns://ejemplo.mx/selector1").unwrap();
        let obs = observar_con(servidor, &o, &opciones(), ahora as i64).unwrap();
        assert!(obs.rechazada);
        assert!(!obs.validada);
        assert_eq!(obs.selectores, vec!["selector1".to_string()]);
        assert_eq!(obs.dkim.len(), 1);

        let z = zona_ejemplo(ahora);
        let servidor = resolvedor_simulado(z);
        let o = Objetivo::interpretar("dns://s1._domainkey.ejemplo.mx").unwrap();
        let obs = observar_con(servidor, &o, &opciones(), ahora as i64).unwrap();
        assert!(!obs.consulto_dnssec);
        assert_eq!(obs.dkim[0].tipo_llave, "ed25519");
        let o = Objetivo::interpretar("dns://_443._tcp.ejemplo.mx").unwrap();
        let obs = observar_con(servidor, &o, &opciones(), ahora as i64).unwrap();
        assert_eq!(obs.tlsa.len(), 1);
        let o = Objetivo::interpretar("dns://noexiste.mx").unwrap();
        assert!(
            observar_con(servidor, &o, &opciones(), ahora as i64)
                .unwrap_err()
                .contains("NXDOMAIN")
        );
    }

    #[test]
    fn piezas_del_formato() {
        // RFC 4034, apéndice B: etiqueta de llave.
        assert_eq!(
            etiqueta_llave(&[1, 1, 3, 8, 3, 1, 0, 1]),
            0x0101 + 0x0308 + 0x0301 + 0x0001
        );
        assert_eq!(bits_rsa_dnssec(&rsa_dnssec()), Some(2048));
        assert_eq!(
            tiempo_de_serie(10, (1u64 << 32) as i64 + 5),
            (1u64 << 32) as i64 + 10
        );
        assert_eq!(mnemonico(18), "MLDSA44");
        assert_eq!(nombre_digestion(2), "SHA-256");
        assert!(dkim("x", "v=spf1 -all").is_err());
        assert_eq!(dkim("x", "v=DKIM1; p=").unwrap(), None);
        // RSAPublicKey sin SubjectPublicKeyInfo.
        let mut der = vec![0x30, 0x82, 0x01, 0x0A, 0x02, 0x82, 0x01, 0x01, 0x00, 0xC0];
        der.extend([0x11u8; 255]);
        der.extend([0x02, 0x03, 1, 0, 1]);
        assert_eq!(bits_rsa_publica(&der), Some(2048));
        assert!(consulta(1, "a..b", TXT, false).is_err());
        assert_eq!(fecha(0), "1970-01-01");
    }
}
