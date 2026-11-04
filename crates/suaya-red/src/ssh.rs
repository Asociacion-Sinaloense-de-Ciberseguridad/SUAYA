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

pub(crate) fn sondear(
    o: &Objetivo,
    c: &Conocimiento,
    op: &Opciones,
) -> Result<(Vec<Activo>, Vec<String>), String> {
    let (identificacion, kexinit) = observar(&mut o.conectar(op)?)?;
    Ok((activos(o, &identificacion, &kexinit, c), Vec::new()))
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
    fn kexinit_truncado() {
        assert!(KexInit::desde_carga(&[SSH_MSG_KEXINIT, 1, 2]).is_err());
        assert!(KexInit::desde_carga(&[21]).is_err());
    }
}
