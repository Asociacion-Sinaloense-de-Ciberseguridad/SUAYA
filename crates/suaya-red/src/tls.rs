//! Sondeo TLS.
//!
//! Técnica: se envía un `ClientHello` de TLS 1.3 que ofrece grupos en
//! `supported_groups` pero ninguna llave en `key_share`. Un servidor que
//! acepta alguno de esos grupos responde con un `HelloRetryRequest` que
//! indica cuál eligió. Así se detecta el soporte de cada grupo (incluidos
//! los híbridos con ML-KEM) sin generar material criptográfico, y sin que la
//! biblioteca del cliente limite qué grupos se pueden probar.

use std::io::{ErrorKind, Read, Write};
use std::net::IpAddr;
use std::sync::Arc;

use suaya_core::{Activo, AlgoritmoDef, Conocimiento, Detalles, Garantia, Riesgo};
use suaya_escaneo::api::{activo_algoritmo, certificado_en_contexto, id_corto};

use crate::{Objetivo, Opciones};

/// `random` especial que identifica un HelloRetryRequest (RFC 8446, 4.1.3).
const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];
const TLS13: u16 = 0x0304;
const SUITES_13: &[u16] = &[0x1301, 0x1302, 0x1303];
/// Suites de TLS 1.2 e inferiores, amplias a propósito para detectar versiones.
const SUITES_12: &[u16] = &[
    0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC009, 0xC013, 0xC00A, 0xC014, 0x009C, 0x009D,
    0x002F, 0x0035, 0x0033, 0x0039, 0x000A, 0x009E, 0x009F, 0xCCAA, 0xC023, 0xC024, 0xC027, 0xC028,
    0x003C, 0x003D, 0x0067, 0x006B, 0xC012, 0xC008, 0x0016, 0x0005, 0x0004, 0xC011, 0xC007, 0x0041,
    0x0084, 0xC0AC, 0xC0AD, 0x0002, 0x0001,
];
/// Conexiones adicionales como máximo para enumerar las suites de TLS 1.2.
const MAXIMO_ENUMERACION: usize = 40;
/// Esquemas de firma ofrecidos, incluidos ML-DSA (0x0904 a 0x0906).
const FIRMAS: &[u16] = &[
    0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0807, 0x0808, 0x0904,
    0x0905, 0x0906, 0x0201, 0x0203,
];
/// Grupos clásicos para las pruebas de versiones anteriores a TLS 1.3.
const GRUPOS_HEREDADOS: &[u16] = &[0x001D, 0x0017, 0x0018];
const VERSIONES_HEREDADAS: &[(u16, &str)] = &[
    (0x0303, "TLSv1.2"),
    (0x0302, "TLSv1.1"),
    (0x0301, "TLSv1"),
    (0x0300, "SSLv3"),
];
const MAXIMO_REGISTRO: usize = 16384 + 2048;
/// Nombres IANA de las suites ofrecidas para versiones anteriores a TLS 1.3.
const NOMBRES_SUITES: &[(u16, &str)] = &[
    (0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
    (0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
    (0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
    (0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
    (0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"),
    (0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
    (0xC009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"),
    (0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"),
    (0xC00A, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"),
    (0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"),
    (0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256"),
    (0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384"),
    (0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA"),
    (0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"),
    (0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"),
    (0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"),
    (0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
    (0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"),
    (0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"),
    (0xCCAA, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
    (0xC023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"),
    (0xC024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"),
    (0xC027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"),
    (0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"),
    (0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256"),
    (0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256"),
    (0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"),
    (0x006B, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"),
    (0xC012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"),
    (0xC008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"),
    (0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"),
    (0x0005, "TLS_RSA_WITH_RC4_128_SHA"),
    (0x0004, "TLS_RSA_WITH_RC4_128_MD5"),
    (0xC011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA"),
    (0xC007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"),
    (0x0041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"),
    (0x0084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"),
    (0xC0AC, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"),
    (0xC0AD, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM"),
    (0x0002, "TLS_RSA_WITH_NULL_SHA"),
    (0x0001, "TLS_RSA_WITH_NULL_MD5"),
];

fn nombre_suite(codigo: u16) -> String {
    NOMBRES_SUITES
        .iter()
        .find(|(c, _)| *c == codigo)
        .map(|(_, n)| n.to_string())
        .unwrap_or_else(|| format!("0x{codigo:04X}"))
}

// ---------------------------------------------------------------------------
// Construcción del ClientHello
// ---------------------------------------------------------------------------

fn con_largo16(v: &[u8]) -> Vec<u8> {
    let mut b = (v.len() as u16).to_be_bytes().to_vec();
    b.extend_from_slice(v);
    b
}

fn lista16(v: &[u16]) -> Vec<u8> {
    v.iter().flat_map(|x| x.to_be_bytes()).collect()
}

fn extension(tipo: u16, datos: &[u8]) -> Vec<u8> {
    let mut b = tipo.to_be_bytes().to_vec();
    b.extend(con_largo16(datos));
    b
}

fn aleatorio() -> [u8; 32] {
    let mut r = [0u8; 32];
    r[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    r[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    r
}

/// Construye un registro TLS con un `ClientHello`.
///
/// Con `tls13 = true` anuncia solo TLS 1.3 en `supported_versions` y envía
/// `key_share` vacío; con `false` es un saludo clásico de la versión `legado`.
pub fn client_hello(
    sni: Option<&str>,
    legado: u16,
    suites: &[u16],
    grupos: &[u16],
    tls13: bool,
) -> Vec<u8> {
    let mut ext = Vec::new();
    if let Some(nombre) = sni {
        let mut entrada = vec![0u8];
        entrada.extend(con_largo16(nombre.as_bytes()));
        ext.extend(extension(0x0000, &con_largo16(&entrada)));
    }
    ext.extend(extension(0x000A, &con_largo16(&lista16(grupos))));
    ext.extend(extension(0x000B, &[1, 0]));
    ext.extend(extension(0x000D, &con_largo16(&lista16(FIRMAS))));
    if tls13 {
        ext.extend(extension(0x002B, &[2, 0x03, 0x04]));
        ext.extend(extension(0x002D, &[1, 1]));
        ext.extend(extension(0x0033, &con_largo16(&[])));
    }

    let mut cuerpo = legado.to_be_bytes().to_vec();
    cuerpo.extend_from_slice(&aleatorio());
    cuerpo.push(32);
    cuerpo.extend_from_slice(&aleatorio());
    cuerpo.extend(con_largo16(&lista16(suites)));
    cuerpo.extend_from_slice(&[1, 0]);
    cuerpo.extend(con_largo16(&ext));

    let mut saludo = vec![0x01];
    saludo.extend_from_slice(&(cuerpo.len() as u32).to_be_bytes()[1..]);
    saludo.extend(cuerpo);

    let mut registro = vec![0x16, 0x03, 0x01];
    registro.extend(con_largo16(&saludo));
    registro
}

// ---------------------------------------------------------------------------
// Lectura de la respuesta
// ---------------------------------------------------------------------------

/// Lo que respondió el servidor a un `ClientHello`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Respuesta {
    /// `ServerHello` o `HelloRetryRequest` (`reintento`).
    Saludo {
        version: u16,
        suite: u16,
        grupo: Option<u16>,
        reintento: bool,
    },
    /// Alerta TLS con su código de descripción.
    Alerta(u8),
    /// El servidor cerró la conexión sin responder.
    Cerrada,
}

fn leer_exacto(s: &mut impl Read, buf: &mut [u8]) -> Result<bool, String> {
    match s.read_exact(buf) {
        Ok(()) => Ok(true),
        Err(e)
            if matches!(
                e.kind(),
                ErrorKind::UnexpectedEof
                    | ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
            ) =>
        {
            Ok(false)
        }
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
            Err("el servidor no respondió a tiempo".into())
        }
        Err(e) => Err(e.to_string()),
    }
}

/// Lee registros hasta obtener un `ServerHello`, una alerta o el cierre.
pub fn leer_respuesta(s: &mut impl Read) -> Result<Respuesta, String> {
    let mut saludo: Vec<u8> = Vec::new();
    loop {
        let mut cab = [0u8; 5];
        if !leer_exacto(s, &mut cab)? {
            return Ok(Respuesta::Cerrada);
        }
        let largo = u16::from_be_bytes([cab[3], cab[4]]) as usize;
        if largo > MAXIMO_REGISTRO {
            return Err("registro TLS demasiado grande".into());
        }
        let mut datos = vec![0u8; largo];
        if !leer_exacto(s, &mut datos)? {
            return Ok(Respuesta::Cerrada);
        }
        match cab[0] {
            0x15 => return Ok(Respuesta::Alerta(*datos.get(1).unwrap_or(&0))),
            0x16 => {
                saludo.extend_from_slice(&datos);
                if saludo.len() >= 4 {
                    let total =
                        4 + u32::from_be_bytes([0, saludo[1], saludo[2], saludo[3]]) as usize;
                    if saludo.len() >= total {
                        if saludo[0] != 0x02 {
                            return Err("respuesta de saludo inesperada".into());
                        }
                        return interpretar_server_hello(&saludo[4..total]);
                    }
                    if total > MAXIMO_REGISTRO * 4 {
                        return Err("mensaje de saludo demasiado grande".into());
                    }
                }
            }
            _ => return Err("el servicio no respondió con TLS".into()),
        }
    }
}

fn interpretar_server_hello(b: &[u8]) -> Result<Respuesta, String> {
    let err = || "ServerHello truncado".to_string();
    let u16_en = |p: usize| {
        b.get(p..p + 2)
            .map(|x| u16::from_be_bytes([x[0], x[1]]))
            .ok_or_else(err)
    };
    let mut version = u16_en(0)?;
    let reintento = b.get(2..34).ok_or_else(err)? == HRR_RANDOM;
    let largo_sid = *b.get(34).ok_or_else(err)? as usize;
    let mut p = 35 + largo_sid;
    let suite = u16_en(p)?;
    p += 3; // suite + compresión
    let mut grupo = None;
    if let Ok(total) = u16_en(p) {
        p += 2;
        let fin = (p + total as usize).min(b.len());
        while p + 4 <= fin {
            let tipo = u16_en(p)?;
            let largo = u16_en(p + 2)? as usize;
            let datos = b.get(p + 4..p + 4 + largo).ok_or_else(err)?;
            match tipo {
                0x002B if datos.len() >= 2 => version = u16::from_be_bytes([datos[0], datos[1]]),
                0x0033 if datos.len() >= 2 => {
                    grupo = Some(u16::from_be_bytes([datos[0], datos[1]]))
                }
                _ => {}
            }
            p += 4 + largo;
        }
    }
    Ok(Respuesta::Saludo {
        version,
        suite,
        grupo,
        reintento,
    })
}

// ---------------------------------------------------------------------------
// Sondeo
// ---------------------------------------------------------------------------

fn preguntar(o: &Objetivo, op: &Opciones, saludo: &[u8]) -> Result<Respuesta, String> {
    let mut s = o.conectar_tls(op)?;
    s.write_all(saludo).map_err(|e| e.to_string())?;
    leer_respuesta(&mut s)
}

/// Nombre IANA (minúsculas) del grupo, tomado de los alias `tls-grupo`.
pub(crate) fn nombre_grupo(codigo: u16, def: &AlgoritmoDef) -> String {
    let indice = def
        .codigos_tls
        .iter()
        .position(|c| *c == codigo)
        .unwrap_or(0);
    def.alias
        .iter()
        .filter_map(|a| a.strip_prefix("tls-grupo:"))
        .nth(indice)
        .map(str::to_string)
        .unwrap_or_else(|| format!("0x{codigo:04x}"))
}

/// Observaciones crudas de un servicio TLS.
#[derive(Debug, Default, Clone)]
pub(crate) struct Observacion {
    pub tls13: bool,
    /// Grupo elegido cuando se ofrecen todos, clásicos primero.
    pub preferido: Option<u16>,
    /// Grupo elegido cuando se ofrecen todos, poscuánticos primero.
    pub preferido_pq_primero: Option<u16>,
    pub grupos: Vec<u16>,
    /// Versiones anteriores a 1.3 aceptadas, con la suite elegida.
    pub heredadas: Vec<(&'static str, u16)>,
    /// Todas las suites de TLS 1.2 que el servidor aceptó, en orden de elección.
    pub suites_12: Vec<u16>,
    pub certificados: Vec<Vec<u8>>,
}

pub(crate) fn sondear(
    o: &Objetivo,
    c: &Conocimiento,
    op: &Opciones,
) -> Result<(Vec<Activo>, Vec<String>), String> {
    let sni = if o.host.parse::<IpAddr>().is_ok() {
        None
    } else {
        Some(o.host.as_str())
    };
    let mut avisos = Vec::new();
    let mut obs = Observacion::default();

    // Se ofrecen todos los grupos dos veces, en órdenes opuestos. Si el
    // servidor elige siempre el híbrido, lo prioriza; si sigue el orden del
    // cliente, protegerá a los clientes modernos; si elige siempre el clásico,
    // su configuración relega al híbrido.
    let mut todos = c.grupos_tls();
    todos.sort_by_key(|(_, d)| d.riesgo != Riesgo::VulnerableCuantico);
    let clasicos_primero: Vec<u16> = todos.iter().map(|(cod, _)| *cod).collect();
    let mut pq_primero = clasicos_primero.clone();
    pq_primero.sort_by_key(|cod| {
        c.por_codigo_tls(*cod)
            .is_some_and(|d| d.riesgo == Riesgo::VulnerableCuantico)
    });

    if let Respuesta::Saludo {
        version: TLS13,
        grupo,
        ..
    } = preguntar(
        o,
        op,
        &client_hello(sni, 0x0303, SUITES_13, &clasicos_primero, true),
    )? {
        obs.tls13 = true;
        obs.preferido = grupo;
        if let Ok(Respuesta::Saludo {
            version: TLS13,
            grupo,
            ..
        }) = preguntar(
            o,
            op,
            &client_hello(sni, 0x0303, SUITES_13, &pq_primero, true),
        ) {
            obs.preferido_pq_primero = grupo;
        }
    }
    if obs.tls13 {
        for (codigo, _) in &todos {
            if let Ok(Respuesta::Saludo {
                version: TLS13,
                grupo: Some(g),
                ..
            }) = preguntar(
                o,
                op,
                &client_hello(sni, 0x0303, SUITES_13, &[*codigo], true),
            ) && g == *codigo
            {
                obs.grupos.push(*codigo);
            }
        }
    }
    for (version, nombre) in VERSIONES_HEREDADAS {
        match preguntar(
            o,
            op,
            &client_hello(sni, *version, SUITES_12, GRUPOS_HEREDADOS, false),
        ) {
            Ok(Respuesta::Saludo {
                version: v, suite, ..
            }) if v == *version => obs.heredadas.push((nombre, suite)),
            Ok(_) => {}
            Err(e) => avisos.push(format!("prueba de {nombre}: {e}")),
        }
    }
    if !obs.tls13 && obs.heredadas.is_empty() {
        return Err("el servicio no aceptó ninguna versión de TLS ofrecida".into());
    }
    // Enumeración de las suites de TLS 1.2: se retira la elegida y se vuelve a
    // preguntar hasta que el servidor no acepte ninguna de las restantes.
    if let Some((_, primera)) = obs.heredadas.iter().find(|(n, _)| *n == "TLSv1.2") {
        obs.suites_12.push(*primera);
        let mut restantes: Vec<u16> = SUITES_12.iter().copied().filter(|x| x != primera).collect();
        for _ in 0..MAXIMO_ENUMERACION {
            if restantes.is_empty() {
                break;
            }
            match preguntar(
                o,
                op,
                &client_hello(sni, 0x0303, &restantes, GRUPOS_HEREDADOS, false),
            ) {
                Ok(Respuesta::Saludo {
                    version: 0x0303,
                    suite,
                    ..
                }) if restantes.contains(&suite) => {
                    obs.suites_12.push(suite);
                    restantes.retain(|x| *x != suite);
                }
                _ => break,
            }
        }
    }
    if op.certificados {
        match obtener_certificados(o, op) {
            Ok(v) => obs.certificados = v,
            Err(e) => avisos.push(format!("no se obtuvo la cadena de certificados: {e}")),
        }
    }
    Ok((activos(o, &obs, c, op, &mut avisos), avisos))
}

/// Construye los activos de un servicio TLS a partir de lo observado.
pub(crate) fn activos(
    o: &Objetivo,
    obs: &Observacion,
    c: &Conocimiento,
    op: &Opciones,
    avisos: &mut Vec<String>,
) -> Vec<Activo> {
    let ubicacion = o.ubicacion();
    let capacidad = op.capacidad_tls.as_str();
    let mut activos = Vec::new();
    let mut nombres_grupos = Vec::new();
    let mut riesgos_grupos = Vec::new();

    for codigo in &obs.grupos {
        if let Some(def) = c.por_codigo_tls(*codigo) {
            nombres_grupos.push(nombre_grupo(*codigo, def));
            riesgos_grupos.push(def.riesgo);
            activos.push(activo_algoritmo(
                Some(def),
                &def.nombre,
                None,
                capacidad,
                Some(Garantia::Confidencialidad),
                &ubicacion,
                None,
            ));
        }
    }

    let mut versiones: Vec<String> = obs
        .heredadas
        .iter()
        .rev()
        .map(|(n, _)| n.to_string())
        .collect();
    if obs.tls13 {
        versiones.push("TLSv1.3".into());
    }
    let suite_12 = obs
        .heredadas
        .iter()
        .find(|(n, _)| *n == "TLSv1.2")
        .map(|(_, s)| *s);

    let mut protocolo = Activo::nuevo(
        format!("protocolo:tls:{}", id_corto(&ubicacion)),
        match o.starttls {
            Some(st) => format!("{} con STARTTLS en {}:{}", st.nombre(), o.host, o.puerto),
            None => format!("TLS en {}:{}", o.host, o.puerto),
        },
        Detalles::Protocolo {
            tipo_protocolo: "tls".into(),
            versiones: versiones.clone(),
            grupos: nombres_grupos.clone(),
            cifrados: if obs.suites_12.is_empty() {
                suite_12.map(nombre_suite).into_iter().collect()
            } else {
                obs.suites_12.iter().map(|s| nombre_suite(*s)).collect()
            },
        },
    )
    .con_contexto(capacidad, Garantia::Confidencialidad)
    .con_ubicacion(&ubicacion, None);

    // Riesgo por versiones.
    let mut candidatos: Vec<Riesgo> = Vec::new();
    let obsoletas: Vec<&str> = obs
        .heredadas
        .iter()
        .filter(|(n, _)| {
            c.por_alias("tls-protocolo", &n.to_lowercase())
                .is_some_and(|d| matches!(d.riesgo, Riesgo::RotoClasico | Riesgo::Obsoleto))
        })
        .map(|(n, _)| *n)
        .collect();
    for n in &obsoletas {
        if let Some(d) = c.por_alias("tls-protocolo", &n.to_lowercase()) {
            candidatos.push(d.riesgo);
        }
    }
    if !obsoletas.is_empty() {
        protocolo.advertir(format!(
            "Acepta versiones rotas u obsoletas: {}.",
            obsoletas.join(", ")
        ));
    }

    if let Some(suite) = suite_12 {
        let nombre = nombre_suite(suite);
        if nombre.starts_with("TLS_RSA_") {
            protocolo.advertir(format!(
                "En TLS 1.2 elige {nombre}: intercambio de llaves RSA estático, sin secreto perfecto hacia adelante."
            ));
        }
        if nombre.contains("3DES") {
            protocolo.advertir("En TLS 1.2 elige una suite con 3DES (Sweet32).");
            candidatos.push(Riesgo::RotoClasico);
        }
    }
    // Lo que acepta aunque no lo elija primero: un cliente antiguo puede llegar ahí.
    let aceptadas: Vec<String> = obs.suites_12.iter().map(|s| nombre_suite(*s)).collect();
    let con = |f: &dyn Fn(&str) -> bool| {
        aceptadas
            .iter()
            .filter(|n| f(n))
            .cloned()
            .collect::<Vec<_>>()
    };
    let rc4 = con(&|n| n.contains("RC4"));
    let nulas = con(&|n| n.contains("NULL"));
    let triple = con(&|n| n.contains("3DES"));
    let estaticas = con(&|n| n.starts_with("TLS_RSA_"));
    if !rc4.is_empty() || !nulas.is_empty() {
        protocolo.advertir(format!(
            "En TLS 1.2 acepta suites rotas: {}.",
            rc4.iter()
                .chain(&nulas)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ));
        candidatos.push(Riesgo::RotoClasico);
    }
    if !triple.is_empty() && suite_12.is_some_and(|s| !nombre_suite(s).contains("3DES")) {
        protocolo.advertir(format!(
            "En TLS 1.2 también acepta 3DES (Sweet32): {}.",
            triple.join(", ")
        ));
        candidatos.push(Riesgo::RotoClasico);
    }
    if !estaticas.is_empty() && suite_12.is_some_and(|s| !nombre_suite(s).starts_with("TLS_RSA_")) {
        protocolo.advertir(format!(
            "En TLS 1.2 también acepta intercambio RSA estático, sin secreto perfecto hacia adelante: {}.",
            estaticas.join(", ")
        ));
    }
    if obs.suites_12.len() > 1 {
        protocolo.advertir(format!(
            "Acepta {} suites de TLS 1.2 de las {} que Suaya ofrece.",
            obs.suites_12.len(),
            SUITES_12.len()
        ));
    }

    // Riesgo por grupos.
    let hay_pq = riesgos_grupos
        .iter()
        .any(|r| matches!(r, Riesgo::HibridoPq | Riesgo::ResistenteCuantico));
    if !obs.tls13 {
        protocolo.advertir(
            "No ofrece TLS 1.3, por lo que no puede negociar grupos híbridos poscuánticos.",
        );
        candidatos.push(Riesgo::VulnerableCuantico);
    } else if hay_pq {
        candidatos.push(if riesgos_grupos.contains(&Riesgo::HibridoPq) {
            Riesgo::HibridoPq
        } else {
            Riesgo::ResistenteCuantico
        });
        let es_pq = |g: Option<u16>| {
            g.and_then(|x| c.por_codigo_tls(x))
                .is_some_and(|d| matches!(d.riesgo, Riesgo::HibridoPq | Riesgo::ResistenteCuantico))
        };
        let nombre = |g: Option<u16>| {
            g.and_then(|x| c.por_codigo_tls(x).map(|d| nombre_grupo(x, d)))
                .unwrap_or_else(|| "otro grupo".into())
        };
        match (es_pq(obs.preferido), es_pq(obs.preferido_pq_primero)) {
            (true, _) => protocolo.advertir(
                "Prioriza el grupo poscuántico aunque el cliente ofrezca primero grupos clásicos.",
            ),
            (false, true) => protocolo.advertir(format!(
                "Respeta el orden del cliente: los clientes que ofrecen primero un híbrido obtienen protección poscuántica; los que ofrecen primero un grupo clásico negocian {}.",
                nombre(obs.preferido)
            )),
            (false, false) if obs.preferido_pq_primero.is_some() => protocolo.advertir(format!(
                "Aunque el cliente ofrezca primero un grupo híbrido, el servidor elige {}: revisar el orden de grupos en su configuración.",
                nombre(obs.preferido_pq_primero)
            )),
            _ => {}
        }
        if riesgos_grupos.contains(&Riesgo::VulnerableCuantico) {
            protocolo.advertir("También acepta grupos clásicos: los clientes antiguos negociarán sin protección poscuántica.");
        }
        if versiones.iter().any(|v| v == "TLSv1.2") {
            protocolo.advertir(
                "TLS 1.2 sigue habilitado: esas conexiones no pueden usar grupos híbridos.",
            );
        }
    } else {
        candidatos.push(Riesgo::VulnerableCuantico);
    }
    if obs.tls13 && obs.grupos.is_empty() {
        protocolo.advertir(
            "Ofrece TLS 1.3, pero no aceptó ninguno de los grupos de la base de conocimiento.",
        );
    }
    protocolo.riesgo_fijado = candidatos.into_iter().min_by_key(|r| r.gravedad());
    protocolo.advertir("Observado en la red: refleja lo que el servicio ofrece realmente.");

    for a in &activos {
        protocolo.relacionar("algorithm", &a.referencia);
    }

    // Cadena de certificados.
    for (i, der) in obs.certificados.iter().enumerate() {
        match certificado_en_contexto(der, &ubicacion, capacidad, c) {
            Ok(v) => {
                for a in v {
                    if matches!(a.detalles, Detalles::Certificado { .. }) {
                        protocolo.relacionar("certificate", &a.referencia);
                    }
                    activos.push(a);
                }
            }
            Err(e) => avisos.push(format!("certificado {} de la cadena: {e}", i + 1)),
        }
    }

    activos.push(protocolo);
    activos
}

// ---------------------------------------------------------------------------
// Cadena de certificados (saludo completo con rustls)
// ---------------------------------------------------------------------------

/// Verificador que acepta cualquier certificado: Suaya no confía en la
/// conexión ni envía datos por ella; solo lee la cadena para inventariarla.
#[derive(Debug)]
pub(crate) struct SinVerificar(pub(crate) Arc<rustls::crypto::CryptoProvider>);

/// Familias de esquemas de firma para pedir, una a la vez, la cadena que el
/// servidor reserva a cada tipo de cliente (un servidor puede tener un
/// certificado RSA, otro ECDSA y otro ML-DSA).
pub(crate) const FAMILIAS_FIRMA: &[(&str, &[rustls::SignatureScheme])] = &[
    (
        "ECDSA",
        &[
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
        ],
    ),
    (
        "RSA",
        &[
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
        ],
    ),
    (
        "EdDSA",
        &[
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ],
    ),
    (
        "ML-DSA",
        &[
            rustls::SignatureScheme::ML_DSA_44,
            rustls::SignatureScheme::ML_DSA_65,
            rustls::SignatureScheme::ML_DSA_87,
        ],
    ),
];

/// Como [`SinVerificar`], pero anuncia solo una familia de esquemas.
#[derive(Debug)]
pub(crate) struct SoloFamilia(pub(crate) &'static [rustls::SignatureScheme]);

impl rustls::client::danger::ServerCertVerifier for SoloFamilia {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.to_vec()
    }
}

impl rustls::client::danger::ServerCertVerifier for SinVerificar {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        // Además de los esquemas del proveedor, se anuncian ML-DSA para que un
        // servidor con certificado poscuántico complete el saludo y su cadena
        // quede inventariada (este verificador no valida firmas).
        let mut esquemas = self.0.signature_verification_algorithms.supported_schemes();
        for e in [
            rustls::SignatureScheme::ML_DSA_44,
            rustls::SignatureScheme::ML_DSA_65,
            rustls::SignatureScheme::ML_DSA_87,
        ] {
            if !esquemas.contains(&e) {
                esquemas.push(e);
            }
        }
        esquemas
    }
}

fn obtener_certificados(o: &Objetivo, op: &Opciones) -> Result<Vec<Vec<u8>>, String> {
    // aws-lc-rs permite completar saludos con X25519MLKEM768, de modo que la
    // cadena se obtiene también de servidores que solo aceptan híbridos.
    let proveedor = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut cadena = saludo_con_verificador(o, op, Arc::new(SinVerificar(proveedor.clone())))?;
    // Una cadena más por familia de firma, si el servidor tiene otra hoja.
    let mut hojas: Vec<Vec<u8>> = cadena.first().cloned().into_iter().collect();
    for (_, esquemas) in FAMILIAS_FIRMA {
        if let Ok(otra) = saludo_con_verificador(o, op, Arc::new(SoloFamilia(esquemas)))
            && let Some(hoja) = otra.first()
            && !hojas.contains(hoja)
        {
            hojas.push(hoja.clone());
            for der in otra {
                if !cadena.contains(&der) {
                    cadena.push(der);
                }
            }
        }
    }
    Ok(cadena)
}

/// Saludo completo con un verificador dado; devuelve la cadena presentada.
pub(crate) fn saludo_con_verificador(
    o: &Objetivo,
    op: &Opciones,
    verificador: Arc<dyn rustls::client::danger::ServerCertVerifier>,
) -> Result<Vec<Vec<u8>>, String> {
    let proveedor = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(proveedor)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(verificador)
        .with_no_client_auth();
    let nombre =
        rustls::pki_types::ServerName::try_from(o.host.clone()).map_err(|e| e.to_string())?;
    let mut conexion =
        rustls::ClientConnection::new(Arc::new(config), nombre).map_err(|e| e.to_string())?;
    let mut socket = o.conectar_tls(op)?;
    while conexion.is_handshaking() {
        conexion
            .complete_io(&mut socket)
            .map_err(|e| e.to_string())?;
    }
    let cadena = conexion
        .peer_certificates()
        .map(|cs| cs.iter().map(|c| c.as_ref().to_vec()).collect())
        .unwrap_or_default();
    conexion.send_close_notify();
    let _ = conexion.complete_io(&mut socket);
    Ok(cadena)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn client_hello_bien_formado() {
        let h = client_hello(
            Some("ejemplo.mx"),
            0x0303,
            SUITES_13,
            &[0x11EC, 0x001D],
            true,
        );
        assert_eq!(&h[..3], &[0x16, 0x03, 0x01]);
        assert_eq!(u16::from_be_bytes([h[3], h[4]]) as usize, h.len() - 5);
        assert_eq!(h[5], 0x01);
        let largo = u32::from_be_bytes([0, h[6], h[7], h[8]]) as usize;
        assert_eq!(largo, h.len() - 9);
    }

    fn server_hello(version_ext: Option<u16>, grupo: Option<u16>, hrr: bool) -> Vec<u8> {
        let mut cuerpo = vec![0x03, 0x03];
        cuerpo.extend_from_slice(if hrr { &HRR_RANDOM } else { &[7u8; 32] });
        cuerpo.push(0);
        cuerpo.extend_from_slice(&[0x13, 0x01, 0x00]);
        let mut ext = Vec::new();
        if let Some(v) = version_ext {
            ext.extend(extension(0x002B, &v.to_be_bytes()));
        }
        if let Some(g) = grupo {
            ext.extend(extension(0x0033, &g.to_be_bytes()));
        }
        cuerpo.extend(con_largo16(&ext));
        let mut hs = vec![0x02];
        hs.extend_from_slice(&(cuerpo.len() as u32).to_be_bytes()[1..]);
        hs.extend(cuerpo);
        let mut r = vec![0x16, 0x03, 0x03];
        r.extend(con_largo16(&hs));
        r
    }

    #[test]
    fn interpreta_hello_retry_request() {
        let r =
            leer_respuesta(&mut server_hello(Some(TLS13), Some(0x11EC), true).as_slice()).unwrap();
        assert_eq!(
            r,
            Respuesta::Saludo {
                version: TLS13,
                suite: 0x1301,
                grupo: Some(0x11EC),
                reintento: true
            }
        );
    }

    #[test]
    fn interpreta_alerta_y_cierre() {
        assert_eq!(
            leer_respuesta(&mut [0x15u8, 3, 3, 0, 2, 2, 40].as_slice()).unwrap(),
            Respuesta::Alerta(40)
        );
        assert_eq!(
            leer_respuesta(&mut [0u8; 0].as_slice()).unwrap(),
            Respuesta::Cerrada
        );
        assert!(leer_respuesta(&mut b"HTTP/1.1 400 Bad".as_slice()).is_err());
    }

    #[test]
    fn nombres_de_grupo_desde_la_base() {
        let c = Conocimiento::embebido();
        assert_eq!(
            nombre_grupo(0x11EC, c.por_codigo_tls(0x11EC).unwrap()),
            "x25519mlkem768"
        );
        assert_eq!(
            nombre_grupo(0x0101, c.por_codigo_tls(0x0101).unwrap()),
            "ffdhe3072"
        );
        assert_eq!(
            nombre_grupo(0x0017, c.por_codigo_tls(0x0017).unwrap()),
            "secp256r1"
        );
    }
}
