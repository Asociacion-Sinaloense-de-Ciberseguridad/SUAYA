//! Sondeo de IKEv2 (VPN IPsec) por UDP.
//!
//! Suaya envía mensajes `IKE_SA_INIT` y lee la respuesta, sin autenticarse ni
//! crear una asociación de seguridad:
//!
//! - Por cada grupo de intercambio candidato ofrece una propuesta con solo
//!   ese grupo: una SA en la respuesta significa que lo acepta;
//!   `NO_PROPOSAL_CHOSEN`, que no.
//! - Una propuesta adicional con ML-KEM como intercambio adicional (RFC 9370)
//!   revela si el servidor ofrece el híbrido poscuántico.
//! - Dos sondas más comprueban si todavía acepta 3DES o SHA-1.
//!
//! Los valores públicos que se envían son válidos sin generar llaves: bytes
//! aleatorios en Curve25519 y Curve448, el punto generador en P-256 y P-384, y
//! g = 2 en los grupos MODP.

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};

use suaya_core::{Activo, Conocimiento, Detalles, Garantia, Riesgo};
use suaya_escaneo::api::{id_corto, por_alias};

use crate::{Objetivo, Opciones};

const CAPACIDAD: &str = "vpn-cifrado-red";
const SA: u8 = 33;
const KE: u8 = 34;
const NONCE: u8 = 40;
const NOTIFY: u8 = 41;
const NO_PROPOSAL_CHOSEN: u16 = 14;
const INVALID_KE_PAYLOAD: u16 = 17;
const COOKIE: u16 = 16390;
const INTERMEDIATE_EXCHANGE_SUPPORTED: u16 = 16438;

/// Grupos que se prueban: (id IANA, alias de ipsec).
const GRUPOS: &[(u16, &str)] = &[
    (31, "curve25519"),
    (32, "curve448"),
    (19, "ecp256"),
    (20, "ecp384"),
    (14, "modp2048"),
    (15, "modp3072"),
    (16, "modp4096"),
    (5, "modp1536"),
    (2, "modp1024"),
];
const MLKEM: &[(u16, &str)] = &[(36, "mlkem768"), (37, "mlkem1024"), (35, "mlkem512")];

const P256_G: [u8; 64] = [
    0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
    0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
    0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
    0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5,
];
const P384_G: [u8; 96] = [
    0xAA, 0x87, 0xCA, 0x22, 0xBE, 0x8B, 0x05, 0x37, 0x8E, 0xB1, 0xC7, 0x1E, 0xF3, 0x20, 0xAD, 0x74,
    0x6E, 0x1D, 0x3B, 0x62, 0x8B, 0xA7, 0x9B, 0x98, 0x59, 0xF7, 0x41, 0xE0, 0x82, 0x54, 0x2A, 0x38,
    0x55, 0x02, 0xF2, 0x5D, 0xBF, 0x55, 0x29, 0x6C, 0x3A, 0x54, 0x5E, 0x38, 0x72, 0x76, 0x0A, 0xB7,
    0x36, 0x17, 0xDE, 0x4A, 0x96, 0x26, 0x2C, 0x6F, 0x5D, 0x9E, 0x98, 0xBF, 0x92, 0x92, 0xDC, 0x29,
    0xF8, 0xF4, 0x1D, 0xBD, 0x28, 0x9A, 0x14, 0x7C, 0xE9, 0xDA, 0x31, 0x13, 0xB5, 0xF0, 0xB8, 0xC0,
    0x0A, 0x60, 0xB1, 0xCE, 0x1D, 0x7E, 0x81, 0x9D, 0x7A, 0x43, 0x1D, 0x7C, 0x90, 0xEA, 0x0E, 0x5F,
];

pub(crate) fn aleatorio(n: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(n);
    while v.len() < n {
        v.extend(uuid::Uuid::new_v4().as_bytes());
    }
    v.truncate(n);
    v
}

/// Valor público válido para un grupo.
fn valor_ke(grupo: u16) -> Vec<u8> {
    let modp = |bytes: usize| {
        let mut v = vec![0u8; bytes];
        v[bytes - 1] = 2;
        v
    };
    match grupo {
        31 => aleatorio(32),
        32 => aleatorio(56),
        19 => P256_G.to_vec(),
        20 => P384_G.to_vec(),
        2 => modp(128),
        5 => modp(192),
        14 => modp(256),
        15 => modp(384),
        16 => modp(512),
        _ => Vec::new(),
    }
}

/// Transformación: (tipo, id, largo de llave en bits).
pub(crate) type Transformacion = (u8, u16, Option<u16>);

fn transformacion(t: &Transformacion, ultima: bool) -> Vec<u8> {
    let (tipo, id, largo) = *t;
    let mut v = vec![if ultima { 0 } else { 3 }, 0, 0, 0, tipo, 0];
    v.extend(id.to_be_bytes());
    if let Some(l) = largo {
        v.extend([0x80, 0x0E]);
        v.extend(l.to_be_bytes());
    }
    let n = v.len() as u16;
    v[2..4].copy_from_slice(&n.to_be_bytes());
    v
}

fn propuesta(numero: u8, ts: &[Transformacion], ultima: bool) -> Vec<u8> {
    let mut v = vec![
        if ultima { 0 } else { 2 },
        0,
        0,
        0,
        numero,
        1,
        0,
        ts.len() as u8,
    ];
    for (i, t) in ts.iter().enumerate() {
        v.extend(transformacion(t, i + 1 == ts.len()));
    }
    let n = v.len() as u16;
    v[2..4].copy_from_slice(&n.to_be_bytes());
    v
}

fn carga(siguiente: u8, cuerpo: &[u8]) -> Vec<u8> {
    let mut v = vec![siguiente, 0];
    v.extend(((cuerpo.len() + 4) as u16).to_be_bytes());
    v.extend_from_slice(cuerpo);
    v
}

/// Transformaciones de cifrado autenticado (AEAD) y de cifrado con integridad.
fn transformaciones(
    grupo: u16,
    adicional: &[u16],
    debil: Option<&str>,
) -> Vec<Vec<Transformacion>> {
    let prf: Vec<Transformacion> = match debil {
        Some("sha1") => vec![(2, 2, None)],
        _ => vec![(2, 5, None), (2, 6, None), (2, 7, None), (2, 2, None)],
    };
    let dh: Transformacion = (4, grupo, None);
    let extra: Vec<Transformacion> = adicional.iter().map(|id| (6u8, *id, None)).collect();
    let mut aead: Vec<Transformacion> = vec![(1, 20, Some(256)), (1, 20, Some(128)), (1, 28, None)];
    let mut cbc: Vec<Transformacion> = vec![(1, 12, Some(256)), (1, 12, Some(128)), (1, 3, None)];
    let mut integ: Vec<Transformacion> =
        vec![(3, 12, None), (3, 13, None), (3, 14, None), (3, 2, None)];
    match debil {
        Some("3des") => {
            aead.clear();
            cbc = vec![(1, 3, None)];
        }
        Some("sha1") => {
            aead.clear();
            integ = vec![(3, 2, None)];
        }
        _ => {}
    }
    let mut v = Vec::new();
    if !aead.is_empty() {
        v.push([aead, prf.clone(), vec![dh], extra.clone()].concat());
    }
    v.push([cbc, integ, prf, vec![dh], extra].concat());
    v
}

fn mensaje(
    spi: &[u8; 8],
    grupo: u16,
    propuestas: &[Vec<Transformacion>],
    cookie: Option<&[u8]>,
    intermedio: bool,
) -> Vec<u8> {
    let mut sa = Vec::new();
    for (i, p) in propuestas.iter().enumerate() {
        sa.extend(propuesta(i as u8 + 1, p, i + 1 == propuestas.len()));
    }
    let mut ke = grupo.to_be_bytes().to_vec();
    ke.extend([0, 0]);
    ke.extend(valor_ke(grupo));
    let mut cargas = Vec::new();
    let mut primera = SA;
    if let Some(c) = cookie {
        let mut n = vec![0, 0];
        n.extend(COOKIE.to_be_bytes());
        n.extend_from_slice(c);
        cargas.extend(carga(SA, &n));
        primera = NOTIFY;
    }
    cargas.extend(carga(KE, &sa));
    cargas.extend(carga(NONCE, &ke));
    cargas.extend(carga(if intermedio { NOTIFY } else { 0 }, &aleatorio(32)));
    if intermedio {
        let mut n = vec![0, 0];
        n.extend(INTERMEDIATE_EXCHANGE_SUPPORTED.to_be_bytes());
        cargas.extend(carga(0, &n));
    }
    let mut v = spi.to_vec();
    v.extend([0u8; 8]);
    v.extend([primera, 0x20, 34, 0x08, 0, 0, 0, 0]);
    v.extend(((28 + cargas.len()) as u32).to_be_bytes());
    v.extend(cargas);
    v
}

/// Respuesta de un servidor a `IKE_SA_INIT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Respuesta {
    /// Transformaciones elegidas.
    Aceptada(Vec<Transformacion>),
    Rechazada,
    /// INVALID_KE_PAYLOAD con el grupo que prefiere.
    OtroGrupo(u16),
    Cookie(Vec<u8>),
    Otra(String),
}

pub(crate) fn interpretar(b: &[u8], spi: &[u8; 8]) -> Respuesta {
    if b.len() < 28 || b[..8] != spi[..] || b[18] != 34 {
        return Respuesta::Otra("respuesta IKE inesperada".into());
    }
    let mut siguiente = b[16];
    let mut p = 28usize;
    while siguiente != 0 && p + 4 <= b.len() {
        let tipo = siguiente;
        siguiente = b[p];
        let largo = u16::from_be_bytes([b[p + 2], b[p + 3]]) as usize;
        if largo < 4 || p + largo > b.len() {
            break;
        }
        let cuerpo = &b[p + 4..p + largo];
        match tipo {
            NOTIFY if cuerpo.len() >= 4 => {
                let spi_tam = cuerpo[1] as usize;
                let t = u16::from_be_bytes([cuerpo[2], cuerpo[3]]);
                let datos = cuerpo.get(4 + spi_tam..).unwrap_or(&[]);
                match t {
                    NO_PROPOSAL_CHOSEN => return Respuesta::Rechazada,
                    INVALID_KE_PAYLOAD if datos.len() >= 2 => {
                        return Respuesta::OtroGrupo(u16::from_be_bytes([datos[0], datos[1]]));
                    }
                    COOKIE => return Respuesta::Cookie(datos.to_vec()),
                    t if t < 16384 => return Respuesta::Otra(format!("error IKE {t}")),
                    _ => {}
                }
            }
            SA => {
                // Primera propuesta: sus transformaciones.
                let Some(n) = cuerpo.get(7).map(|x| *x as usize) else {
                    break;
                };
                let spi_tam = cuerpo.get(6).copied().unwrap_or(0) as usize;
                let mut q = 8 + spi_tam;
                let mut ts = Vec::new();
                for _ in 0..n {
                    let Some(t) = cuerpo.get(q..q + 8) else { break };
                    let lt = u16::from_be_bytes([t[2], t[3]]) as usize;
                    let largo_llave = cuerpo
                        .get(q + 8..q + 12)
                        .filter(|a| lt >= 12 && a[0] == 0x80 && a[1] == 0x0E)
                        .map(|a| u16::from_be_bytes([a[2], a[3]]));
                    ts.push((t[4], u16::from_be_bytes([t[6], t[7]]), largo_llave));
                    if lt < 8 {
                        break;
                    }
                    q += lt;
                }
                return Respuesta::Aceptada(ts);
            }
            _ => {}
        }
        p += largo;
    }
    Respuesta::Otra("respuesta IKE sin SA ni notificación".into())
}

fn preguntar(
    sock: &UdpSocket,
    grupo: u16,
    propuestas: &[Vec<Transformacion>],
    intermedio: bool,
) -> Result<Respuesta, String> {
    let mut spi = [0u8; 8];
    spi.copy_from_slice(&aleatorio(8));
    let mut cookie: Option<Vec<u8>> = None;
    for _ in 0..2 {
        sock.send(&mensaje(
            &spi,
            grupo,
            propuestas,
            cookie.as_deref(),
            intermedio,
        ))
        .map_err(|e| e.to_string())?;
        let mut b = vec![0u8; 8192];
        let n = sock.recv(&mut b).map_err(|e| match e.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                "el servidor IKE no respondió a tiempo (UDP)".to_string()
            }
            _ => e.to_string(),
        })?;
        match interpretar(&b[..n], &spi) {
            Respuesta::Cookie(c) if cookie.is_none() => cookie = Some(c),
            r => return Ok(r),
        }
    }
    Ok(Respuesta::Otra(
        "el servidor pidió una cookie dos veces".into(),
    ))
}

/// Lo observado en un servidor IKEv2.
#[derive(Debug, Default, Clone)]
pub(crate) struct ObservacionIke {
    pub grupos: Vec<u16>,
    pub preferido: Option<u16>,
    pub elegidas: Vec<Transformacion>,
    pub mlkem: Option<u16>,
    pub acepta_3des: bool,
    pub acepta_sha1: bool,
}

fn conectar(o: &Objetivo, op: &Opciones) -> Result<UdpSocket, String> {
    let destino: SocketAddr = (o.host.as_str(), o.puerto)
        .to_socket_addrs()
        .map_err(|e| format!("no se pudo resolver {}: {e}", o.host))?
        .next()
        .ok_or("sin direcciones")?;
    let local: SocketAddr = if destino.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()
    .expect("dirección válida");
    let s = UdpSocket::bind(local).map_err(|e| e.to_string())?;
    s.connect(destino).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(op.tiempo_limite)).ok();
    s.set_write_timeout(Some(op.tiempo_limite)).ok();
    Ok(s)
}

pub(crate) fn observar(o: &Objetivo, op: &Opciones) -> Result<ObservacionIke, String> {
    let s = conectar(o, op)?;
    let mut obs = ObservacionIke::default();
    let mut ultimo_error = None;
    for (g, _) in GRUPOS {
        match preguntar(&s, *g, &transformaciones(*g, &[], None), false) {
            Ok(Respuesta::Aceptada(ts)) => {
                obs.grupos.push(*g);
                if obs.elegidas.is_empty() {
                    obs.elegidas = ts;
                    obs.preferido = Some(*g);
                }
            }
            Ok(Respuesta::OtroGrupo(x)) => {
                obs.preferido.get_or_insert(x);
            }
            Ok(Respuesta::Rechazada) => {}
            Ok(Respuesta::Otra(e)) | Err(e) => {
                if obs.grupos.is_empty() && ultimo_error.is_none() {
                    ultimo_error = Some(e.clone());
                }
                // Sin respuesta al primer intento: el servicio no está o filtra UDP.
                if e.contains("no respondió") && obs.grupos.is_empty() && *g == GRUPOS[0].0 {
                    return Err(e);
                }
            }
            Ok(Respuesta::Cookie(_)) => {}
        }
    }
    let Some(&base) = obs.grupos.first() else {
        return Err(ultimo_error
            .unwrap_or_else(|| "el servidor no aceptó ningún grupo de intercambio".into()));
    };
    // ML-KEM como intercambio adicional (RFC 9370), con una propuesta de respaldo sin él.
    let ids: Vec<u16> = MLKEM.iter().map(|(id, _)| *id).collect();
    let mut con_pq = transformaciones(base, &ids, None);
    con_pq.extend(transformaciones(base, &[], None));
    if let Ok(Respuesta::Aceptada(ts)) = preguntar(&s, base, &con_pq, true) {
        obs.mlkem = ts.iter().find(|t| t.0 == 6 && t.1 != 0).map(|t| t.1);
    }
    obs.acepta_3des = matches!(
        preguntar(&s, base, &transformaciones(base, &[], Some("3des")), false),
        Ok(Respuesta::Aceptada(_))
    );
    obs.acepta_sha1 = matches!(
        preguntar(&s, base, &transformaciones(base, &[], Some("sha1")), false),
        Ok(Respuesta::Aceptada(_))
    );
    Ok(obs)
}

pub(crate) fn nombre_transformacion(t: &Transformacion) -> Option<String> {
    let (tipo, id, largo) = *t;
    Some(match (tipo, id) {
        (1, 3) => "3des".into(),
        (1, 12) => format!("aes{}", largo.unwrap_or(128)),
        (1, 20) => format!("aes{}gcm16", largo.unwrap_or(128)),
        (1, 28) => "chacha20poly1305".into(),
        (2, 2) | (3, 2) => "sha1".into(),
        (2, 5) | (3, 12) => "sha256".into(),
        (2, 6) | (3, 13) => "sha384".into(),
        (2, 7) | (3, 14) => "sha512".into(),
        _ => return None,
    })
}

pub(crate) fn nombre_grupo(id: u16) -> String {
    GRUPOS
        .iter()
        .chain(MLKEM)
        .find(|(g, _)| *g == id)
        .map(|(_, n)| n.to_string())
        .unwrap_or_else(|| format!("grupo {id}"))
}

pub(crate) fn activos(o: &Objetivo, obs: &ObservacionIke, c: &Conocimiento) -> Vec<Activo> {
    let ubicacion = o.ubicacion();
    let mut algoritmos: Vec<Activo> = Vec::new();
    let agregar = |nombre: &str, g: Garantia, algoritmos: &mut Vec<Activo>| -> Option<Riesgo> {
        let x = por_alias(c, "ipsec", nombre, CAPACIDAD, Some(g), &ubicacion, None);
        let r = x.algoritmo_id().and_then(|i| c.por_id(i)).map(|d| d.riesgo);
        if !algoritmos.iter().any(|y| y.referencia == x.referencia) {
            algoritmos.push(x);
        }
        r
    };
    let mut riesgos = Vec::new();
    let grupos: Vec<String> = obs.grupos.iter().map(|g| nombre_grupo(*g)).collect();
    for g in &grupos {
        riesgos.extend(agregar(g, Garantia::Confidencialidad, &mut algoritmos));
    }
    if let Some(m) = obs.mlkem {
        agregar(
            &nombre_grupo(m),
            Garantia::Confidencialidad,
            &mut algoritmos,
        );
    }
    let elegidas: Vec<String> = obs
        .elegidas
        .iter()
        .filter_map(nombre_transformacion)
        .collect();
    for t in &elegidas {
        agregar(t, Garantia::Confidencialidad, &mut algoritmos);
    }
    let mut p = Activo::nuevo(
        format!("protocolo:ipsec:{}", id_corto(&ubicacion)),
        format!("IKEv2 en {}:{}", o.host, o.puerto),
        Detalles::Protocolo {
            tipo_protocolo: "ipsec".into(),
            versiones: vec!["IKEv2".into()],
            grupos: grupos.clone(),
            cifrados: elegidas.clone(),
        },
    )
    .con_contexto(CAPACIDAD, Garantia::Confidencialidad)
    .con_ubicacion(&ubicacion, None);
    let mut candidatos = Vec::new();
    match obs.mlkem {
        Some(m) => {
            p.advertir(format!(
                "Acepta {} como intercambio adicional (RFC 9370): la VPN puede protegerse contra «capturar ahora, descifrar después».",
                nombre_grupo(m)
            ));
            candidatos.push(Riesgo::HibridoPq);
        }
        None => {
            p.advertir("No acepta ML-KEM como intercambio adicional (RFC 9370): el tráfico de la VPN queda expuesto a «capturar ahora, descifrar después».");
            candidatos.push(Riesgo::VulnerableCuantico);
        }
    }
    let rotos: Vec<&String> = grupos
        .iter()
        .zip(&riesgos)
        .filter(|(_, r)| matches!(r, Riesgo::RotoClasico))
        .map(|(g, _)| g)
        .collect();
    if !rotos.is_empty() {
        p.advertir(format!(
            "Acepta grupos Diffie-Hellman rotos: {}.",
            rotos
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
        candidatos.push(Riesgo::RotoClasico);
    }
    if obs.acepta_3des {
        p.advertir("Acepta 3DES para la SA de IKE.");
        agregar("3des", Garantia::Confidencialidad, &mut algoritmos);
        candidatos.push(Riesgo::RotoClasico);
    }
    if obs.acepta_sha1 {
        p.advertir("Acepta SHA-1 como función pseudoaleatoria e integridad de IKE.");
        agregar("sha1", Garantia::Integridad, &mut algoritmos);
        candidatos.push(Riesgo::Obsoleto);
    }
    if let Some(g) = obs.preferido {
        p.advertir(format!(
            "Grupo con el que responde primero: {}.",
            nombre_grupo(g)
        ));
    }
    p.advertir("Observado en la red: refleja lo que el servicio ofrece realmente.");
    p.riesgo_fijado = candidatos.into_iter().min_by_key(|r| r.gravedad());
    for x in &algoritmos {
        p.relacionar("algorithm", &x.referencia);
    }
    algoritmos.push(p);
    algoritmos
}

pub(crate) fn sondear(
    o: &Objetivo,
    c: &Conocimiento,
    op: &Opciones,
) -> Result<(Vec<Activo>, Vec<String>), String> {
    let obs = observar(o, op)?;
    Ok((activos(o, &obs, c), Vec::new()))
}

#[cfg(test)]
pub(crate) mod pruebas {
    use super::*;

    /// Responde a IKE_SA_INIT como un servidor con los grupos dados y, si
    /// `pq`, aceptando ML-KEM-768 como intercambio adicional.
    pub(crate) fn respuesta_simulada(peticion: &[u8], grupos: &[u16], pq: bool) -> Vec<u8> {
        let spi = &peticion[..8];
        let mut v = spi.to_vec();
        v.extend(aleatorio(8));
        // Grupo del KE de la petición.
        let mut p = 28usize;
        let mut siguiente = peticion[16];
        let mut grupo = 0u16;
        let mut con_mlkem = false;
        while siguiente != 0 && p + 4 <= peticion.len() {
            let tipo = siguiente;
            siguiente = peticion[p];
            let largo = u16::from_be_bytes([peticion[p + 2], peticion[p + 3]]) as usize;
            if tipo == KE {
                grupo = u16::from_be_bytes([peticion[p + 4], peticion[p + 5]]);
            }
            if tipo == SA {
                con_mlkem = peticion[p..p + largo].windows(2).any(|w| w == [6, 0]);
            }
            p += largo;
        }
        let aceptar = grupos.contains(&grupo);
        let cargas = if aceptar {
            let mut ts: Vec<Transformacion> =
                vec![(1, 20, Some(256)), (2, 5, None), (4, grupo, None)];
            if pq && con_mlkem {
                ts.push((6, 36, None));
            }
            let sa = propuesta(1, &ts, true);
            let mut c = carga(0, &sa);
            c[0] = 0;
            (SA, c)
        } else {
            let mut n = vec![0, 0];
            n.extend(NO_PROPOSAL_CHOSEN.to_be_bytes());
            (NOTIFY, carga(0, &n))
        };
        v.extend([cargas.0, 0x20, 34, 0x20, 0, 0, 0, 0]);
        v.extend(((28 + cargas.1.len()) as u32).to_be_bytes());
        v.extend(cargas.1);
        v
    }

    #[test]
    fn sondeo_contra_servidor_simulado() {
        let servidor = UdpSocket::bind("127.0.0.1:0").unwrap();
        let puerto = servidor.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut b = vec![0u8; 8192];
            while let Ok((n, origen)) = servidor.recv_from(&mut b) {
                let r = respuesta_simulada(&b[..n], &[19, 14, 2], true);
                let _ = servidor.send_to(&r, origen);
            }
        });
        let o = Objetivo::interpretar(&format!("ike://127.0.0.1:{puerto}")).unwrap();
        let op = Opciones {
            tiempo_limite: std::time::Duration::from_secs(2),
            ..Opciones::default()
        };
        let obs = observar(&o, &op).unwrap();
        assert_eq!(obs.grupos, vec![19, 14, 2]);
        assert_eq!(obs.mlkem, Some(36));
        let v = activos(&o, &obs, &Conocimiento::embebido());
        let p = v.last().unwrap();
        assert_eq!(p.riesgo_fijado, Some(Riesgo::RotoClasico));
        assert!(p.advertencias.iter().any(|w| w.contains("modp1024")));
        assert!(v.iter().any(|x| x.algoritmo_id() == Some("ml-kem-768")));
    }

    #[test]
    fn mensaje_bien_formado_e_interpretacion() {
        let spi = [1u8; 8];
        let m = mensaje(&spi, 31, &transformaciones(31, &[36], None), None, true);
        assert_eq!(
            u32::from_be_bytes(m[24..28].try_into().unwrap()) as usize,
            m.len()
        );
        assert_eq!(m[16], SA);
        let r = respuesta_simulada(&m, &[31, 19], true);
        match interpretar(&r, &spi) {
            Respuesta::Aceptada(ts) => {
                assert!(
                    ts.contains(&(4, 31, None))
                        && ts.contains(&(6, 36, None))
                        && ts.contains(&(1, 20, Some(256)))
                );
            }
            otra => panic!("{otra:?}"),
        }
        let m = mensaje(&spi, 2, &transformaciones(2, &[], None), None, false);
        assert_eq!(
            interpretar(&respuesta_simulada(&m, &[31], false), &spi),
            Respuesta::Rechazada
        );
        assert!(matches!(interpretar(&[0u8; 10], &spi), Respuesta::Otra(_)));
    }
}
