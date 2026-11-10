//! Sondeo SSH: intercambio de versiones y lectura del `KEXINIT` del servidor.

use std::io::{Read, Write};

use suaya_core::{Activo, Conocimiento, Detalles, Garantia, Riesgo};
use suaya_escaneo::api::{id_corto, por_alias, riesgo_kex_ssh};

use crate::{Objetivo, Opciones};

const CAPACIDAD: &str = "vpn-cifrado-red";
const SSH_MSG_KEXINIT: u8 = 20;
/// Nombres de la lista de intercambio que señalan extensiones, no algoritmos.
const PSEUDOALGORITMOS: &[&str] = &["ext-info-", "kex-strict-"];
/// Límite de bytes para la identificación y el primer paquete.
const MAXIMO_PAQUETE: usize = 64 * 1024;

/// Listas de algoritmos anunciadas por el servidor (RFC 4253, sección 7.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KexInit {
    pub kex: Vec<String>,
    pub llaves_host: Vec<String>,
    pub cifrados: Vec<String>,
    pub macs: Vec<String>,
    /// Pseudoalgoritmos de la lista de intercambio (`ext-info-s`,
    /// `kex-strict-s-v00@openssh.com`), que señalan extensiones.
    pub extensiones: Vec<String>,
}

impl KexInit {
    /// Interpreta la carga útil de un paquete `SSH_MSG_KEXINIT`.
    pub fn desde_carga(carga: &[u8]) -> Result<Self, String> {
        if carga.first() != Some(&SSH_MSG_KEXINIT) {
            return Err("el primer paquete no es KEXINIT".into());
        }
        let mut pos = 1 + 16; // tipo + cookie
        let mut listas = Vec::with_capacity(10);
        for _ in 0..10 {
            let largo = carga
                .get(pos..pos + 4)
                .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)
                .ok_or("KEXINIT truncado")?;
            pos += 4;
            let texto = carga.get(pos..pos + largo).ok_or("KEXINIT truncado")?;
            pos += largo;
            let texto = std::str::from_utf8(texto).map_err(|_| "lista de nombres no ASCII")?;
            listas.push(
                texto
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect::<Vec<_>>(),
            );
        }
        Ok(Self {
            kex: listas[0]
                .iter()
                .filter(|k| !PSEUDOALGORITMOS.iter().any(|p| k.starts_with(p)))
                .cloned()
                .collect(),
            llaves_host: listas[1].clone(),
            // Se usan las listas del servidor hacia el cliente.
            cifrados: listas[3].clone(),
            macs: listas[5].clone(),
            extensiones: listas[0]
                .iter()
                .filter(|k| PSEUDOALGORITMOS.iter().any(|p| k.starts_with(p)))
                .cloned()
                .collect(),
        })
    }
}

/// Lee la identificación del servidor (`SSH-2.0-...`), ignorando líneas previas.
fn leer_identificacion(s: &mut impl Read) -> Result<String, String> {
    let mut linea = Vec::new();
    let mut byte = [0u8; 1];
    let mut total = 0;
    loop {
        s.read_exact(&mut byte)
            .map_err(|e| format!("sin identificación SSH: {e}"))?;
        total += 1;
        if total > MAXIMO_PAQUETE {
            return Err("identificación SSH demasiado larga".into());
        }
        if byte[0] == b'\n' {
            let texto = String::from_utf8_lossy(&linea)
                .trim_end_matches('\r')
                .to_string();
            if texto.starts_with("SSH-") {
                return Ok(texto);
            }
            linea.clear();
        } else {
            linea.push(byte[0]);
        }
    }
}

fn leer_paquete(s: &mut impl Read) -> Result<Vec<u8>, String> {
    let mut cab = [0u8; 5];
    s.read_exact(&mut cab)
        .map_err(|e| format!("no se recibió KEXINIT: {e}"))?;
    let largo = u32::from_be_bytes([cab[0], cab[1], cab[2], cab[3]]) as usize;
    let relleno = cab[4] as usize;
    if largo < 1 + relleno || largo > MAXIMO_PAQUETE {
        return Err("paquete SSH con longitud inválida".into());
    }
    let mut resto = vec![0u8; largo - 1];
    s.read_exact(&mut resto)
        .map_err(|e| format!("paquete SSH incompleto: {e}"))?;
    resto.truncate(largo - 1 - relleno);
    Ok(resto)
}

/// Intercambia identificaciones y lee el `KEXINIT` por una conexión abierta.
pub(crate) fn observar(s: &mut (impl Read + Write)) -> Result<(String, KexInit), String> {
    s.write_all(format!("SSH-2.0-Suaya_{}\r\n", suaya_core::VERSION).as_bytes())
        .map_err(|e| e.to_string())?;
    let identificacion = leer_identificacion(s)?;
    let kexinit = KexInit::desde_carga(&leer_paquete(s)?)?;
    Ok((identificacion, kexinit))
}

/// Punto generador de P-256 (llave pública válida de la llave privada 1).
const GENERADOR_P256: [u8; 65] = [
    0x04, 0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40,
    0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2,
    0x96, 0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E,
    0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51,
    0xF5,
];

fn cadena_ssh(v: &mut Vec<u8>, b: &[u8]) {
    v.extend((b.len() as u32).to_be_bytes());
    v.extend_from_slice(b);
}

fn escribir_paquete(s: &mut impl Write, carga: &[u8]) -> Result<(), String> {
    // Relleno de al menos 4 bytes y total múltiplo de 8 (sin cifrado aún).
    let mut relleno = 8 - ((5 + carga.len()) % 8);
    if relleno < 4 {
        relleno += 8;
    }
    let mut p = ((1 + carga.len() + relleno) as u32).to_be_bytes().to_vec();
    p.push(relleno as u8);
    p.extend_from_slice(carga);
    p.extend(std::iter::repeat_n(0u8, relleno));
    s.write_all(&p).map_err(|e| e.to_string())
}

/// Intercambio de llaves mínimo para obtener la llave de host del servidor
/// (K_S en el `KEX_ECDH_REPLY`). No se calcula el secreto ni se continúa:
/// basta con un valor público válido (cualquiera en curve25519, el punto
/// generador en P-256 o g = 2 en Diffie-Hellman).
fn llave_de_host(
    o: &Objetivo,
    op: &Opciones,
    servidor: &KexInit,
    alg_host: &str,
) -> Result<Vec<u8>, String> {
    let ofrece = |k: &str| servidor.kex.iter().any(|x| x == k);
    let (kex, valor): (&str, Vec<u8>) =
        if ofrece("curve25519-sha256") || ofrece("curve25519-sha256@libssh.org") {
            let k = if ofrece("curve25519-sha256") {
                "curve25519-sha256"
            } else {
                "curve25519-sha256@libssh.org"
            };
            let mut q = uuid::Uuid::new_v4().as_bytes().to_vec();
            q.extend(uuid::Uuid::new_v4().as_bytes());
            let mut v = Vec::new();
            cadena_ssh(&mut v, &q);
            (k, v)
        } else if ofrece("ecdh-sha2-nistp256") {
            let mut v = Vec::new();
            cadena_ssh(&mut v, &GENERADOR_P256);
            ("ecdh-sha2-nistp256", v)
        } else if let Some(dh) = servidor.kex.iter().find(|k| {
            k.starts_with("diffie-hellman-group14") || k.starts_with("diffie-hellman-group16")
        }) {
            let mut v = Vec::new();
            cadena_ssh(&mut v, &[2]);
            (dh.as_str(), v)
        } else {
            return Err(
                "el servidor no ofrece un intercambio con el que Suaya lea la llave de host".into(),
            );
        };
    let mut s = o.conectar(op)?;
    let (_, k) = observar(&mut s)?;
    let mut carga = vec![SSH_MSG_KEXINIT];
    carga.extend(uuid::Uuid::new_v4().as_bytes());
    let cifrados = k.cifrados.join(",");
    let macs = k.macs.join(",");
    for lista in [
        kex, alg_host, &cifrados, &cifrados, &macs, &macs, "none", "none", "", "",
    ] {
        cadena_ssh(&mut carga, lista.as_bytes());
    }
    carga.push(0);
    carga.extend([0, 0, 0, 0]);
    escribir_paquete(&mut s, &carga)?;
    let mut init = vec![30u8];
    init.extend(valor);
    escribir_paquete(&mut s, &init)?;
    for _ in 0..8 {
        let p = leer_paquete(&mut s)?;
        match p.first() {
            Some(31) => {
                let n = p
                    .get(1..5)
                    .map(|x| u32::from_be_bytes([x[0], x[1], x[2], x[3]]) as usize);
                return n
                    .and_then(|n| p.get(5..5 + n))
                    .map(<[u8]>::to_vec)
                    .ok_or_else(|| "respuesta de intercambio truncada".to_string());
            }
            Some(1) => return Err("el servidor cerró la sesión durante el intercambio".into()),
            _ => continue,
        }
    }
    Err("el servidor no envió su llave de host".into())
}

/// Algoritmos de llave de host a consultar: uno por tipo de llave.
fn tipos_de_llave(servidor: &KexInit) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    let mut rsa = false;
    for a in &servidor.llaves_host {
        let es_rsa = matches!(a.as_str(), "rsa-sha2-512" | "rsa-sha2-256" | "ssh-rsa");
        if es_rsa {
            if !rsa {
                rsa = true;
                // Se pide la variante más fuerte que el servidor ofrezca.
                let mejor = ["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]
                    .into_iter()
                    .find(|x| servidor.llaves_host.iter().any(|y| y == x))
                    .unwrap_or("ssh-rsa");
                v.push(mejor.to_string());
            }
        } else if !a.starts_with("sk-") && !a.starts_with("webauthn") {
            v.push(a.clone());
        }
        if v.len() >= 5 {
            break;
        }
    }
    v
}

/// Llaves de host del servidor (blob SSH por algoritmo consultado).
pub(crate) fn llaves_de_host(
    o: &Objetivo,
    op: &Opciones,
    servidor: &KexInit,
) -> Vec<(String, Result<Vec<u8>, String>)> {
    tipos_de_llave(servidor)
        .into_iter()
        .map(|alg| {
            let r = llave_de_host(o, op, servidor, &alg);
            (alg, r)
        })
        .collect()
}

pub(crate) fn sondear(
    o: &Objetivo,
    c: &Conocimiento,
    op: &Opciones,
) -> Result<(Vec<Activo>, Vec<String>), String> {
    let (identificacion, kexinit) = observar(&mut o.conectar(op)?)?;
    let mut activos = activos(o, &identificacion, &kexinit, c);
    let ubicacion = o.ubicacion();
    let mut llaves = Vec::new();
    let mut fallas = Vec::new();
    for (alg, r) in llaves_de_host(o, op, &kexinit) {
        match r.and_then(|blob| suaya_escaneo::api::activos_de_llave_ssh(&blob, &ubicacion, c)) {
            Ok(v) => llaves.extend(v),
            Err(e) => fallas.push(format!("No se obtuvo la llave de host {alg}: {e}.")),
        }
    }
    if let Some(p) = activos
        .iter_mut()
        .find(|a| a.referencia.starts_with("protocolo:ssh:"))
    {
        for x in &llaves {
            if matches!(x.detalles, Detalles::Material { .. }) {
                p.relacionar("publicKey", &x.referencia);
            }
        }
        for f in fallas {
            p.advertir(f);
        }
    }
    activos.extend(llaves);
    Ok((activos, Vec::new()))
}

/// Construye los activos de un servicio SSH a partir de lo observado.
pub(crate) fn activos(
    o: &Objetivo,
    identificacion: &str,
    k: &KexInit,
    c: &Conocimiento,
) -> Vec<Activo> {
    let ubicacion = o.ubicacion();
    let software = identificacion
        .splitn(3, '-')
        .nth(2)
        .unwrap_or("")
        .to_string();
    let version = identificacion.split('-').nth(1).unwrap_or("").to_string();

    let mut algoritmos = Vec::new();
    for (lista, espacio, garantia) in [
        (&k.kex, "ssh-kex", Garantia::Confidencialidad),
        (&k.llaves_host, "ssh", Garantia::Autenticacion),
        (&k.cifrados, "ssh-cifrado", Garantia::Confidencialidad),
        (&k.macs, "ssh-mac", Garantia::Integridad),
    ] {
        for nombre in lista {
            algoritmos.push(por_alias(
                c,
                espacio,
                nombre,
                CAPACIDAD,
                Some(garantia),
                &ubicacion,
                None,
            ));
        }
    }

    let mut protocolo = Activo::nuevo(
        format!("protocolo:ssh:{}", id_corto(&ubicacion)),
        if software.is_empty() {
            format!("SSH en {}:{}", o.host, o.puerto)
        } else {
            format!("SSH en {}:{} ({software})", o.host, o.puerto)
        },
        Detalles::Protocolo {
            tipo_protocolo: "ssh".into(),
            versiones: vec![version.clone()],
            grupos: k.kex.clone(),
            cifrados: k.cifrados.clone(),
        },
    )
    .con_contexto(CAPACIDAD, Garantia::Confidencialidad)
    .con_ubicacion(&ubicacion, None);

    let (riesgo, advertencias) = riesgo_kex_ssh(&k.kex, c);
    for a in advertencias {
        protocolo.advertir(a);
    }
    protocolo.riesgo_fijado = Some(if version.starts_with('1') {
        protocolo.advertir(format!(
            "El servidor anuncia el protocolo SSH {version}; SSH-1 está roto."
        ));
        Riesgo::RotoClasico
    } else {
        riesgo
    });
    protocolo.advertir("Observado en la red: refleja lo que el servicio ofrece realmente.");

    for a in &algoritmos {
        protocolo.relacionar("algorithm", &a.referencia);
    }
    algoritmos.push(protocolo);
    algoritmos
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn lista(v: &str) -> Vec<u8> {
        let mut b = (v.len() as u32).to_be_bytes().to_vec();
        b.extend_from_slice(v.as_bytes());
        b
    }

    pub(crate) fn carga_kexinit(kex: &str, host: &str, cifrado: &str, mac: &str) -> Vec<u8> {
        let mut c = vec![SSH_MSG_KEXINIT];
        c.extend_from_slice(&[0u8; 16]);
        for l in [
            kex, host, cifrado, cifrado, mac, mac, "none", "none", "", "",
        ] {
            c.extend(lista(l));
        }
        c.push(0);
        c.extend_from_slice(&[0, 0, 0, 0]);
        c
    }

    #[test]
    fn interpreta_kexinit() {
        let carga = carga_kexinit(
            "mlkem768x25519-sha256,curve25519-sha256,ext-info-s,kex-strict-s-v00@openssh.com",
            "rsa-sha2-512,ssh-ed25519",
            "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
            "hmac-sha2-256-etm@openssh.com",
        );
        let k = KexInit::desde_carga(&carga).unwrap();
        assert_eq!(k.kex, vec!["mlkem768x25519-sha256", "curve25519-sha256"]);
        assert_eq!(
            k.extensiones,
            vec!["ext-info-s", "kex-strict-s-v00@openssh.com"]
        );
        assert_eq!(k.llaves_host.len(), 2);
    }

    #[test]
    fn tipos_de_llave_sin_duplicar_rsa() {
        let k = KexInit {
            llaves_host: [
                "ssh-ed25519",
                "rsa-sha2-512",
                "rsa-sha2-256",
                "ssh-rsa",
                "ecdsa-sha2-nistp256",
                "sk-ssh-ed25519@openssh.com",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            ..KexInit::default()
        };
        assert_eq!(
            tipos_de_llave(&k),
            vec!["ssh-ed25519", "rsa-sha2-512", "ecdsa-sha2-nistp256"]
        );
    }

    #[test]
    fn kexinit_truncado() {
        assert!(KexInit::desde_carga(&[SSH_MSG_KEXINIT, 1, 2]).is_err());
        assert!(KexInit::desde_carga(&[21]).is_err());
    }
}
