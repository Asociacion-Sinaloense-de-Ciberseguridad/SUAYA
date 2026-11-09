//! Cabeceras LUKS: el cifrador y la derivación de llaves que usa realmente un
//! volumen cifrado (`crypttab` solo dice qué volumen se abre y cómo).
//!
//! Se leen copias de la cabecera (`cryptsetup luksHeaderBackup`) o imágenes
//! de disco que empiezan con ella. Suaya no lee llaves ni las ranuras.

use serde_json::Value;
use suaya_core::{Activo, Conocimiento, Detalles, Garantia, Riesgo};

use crate::Escaner;
use crate::comun::{Archivo, activo_algoritmo, id_corto};

const CAPACIDAD: &str = "cifrado-volumen";
pub(crate) const MAGIA: &[u8] = b"LUKS\xba\xbe";

fn texto_c(b: &[u8]) -> String {
    let fin = b.iter().position(|&x| x == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..fin]).trim().to_string()
}

/// Algoritmo de un cifrador de dm-crypt («aes-xts-plain64» con su tamaño).
fn cifrador(nombre: &str, bytes_llave: u64) -> Option<&'static str> {
    let n = nombre.to_ascii_lowercase();
    let bits = if n.contains("xts") {
        bytes_llave * 4
    } else {
        bytes_llave * 8
    };
    Some(
        match (
            n.split('-').next()?,
            n.contains("xts"),
            n.contains("cbc"),
            n.contains("ecb"),
            bits,
        ) {
            ("aes", true, _, _, 128) => "aes-128-xts",
            ("aes", true, _, _, 256) => "aes-256-xts",
            ("aes", _, true, _, 128) => "aes-128-cbc",
            ("aes", _, true, _, 192) => "aes-192-cbc",
            ("aes", _, true, _, 256) => "aes-256-cbc",
            ("aes", _, _, true, _) => "modo-ecb",
            _ => return None,
        },
    )
}

pub(crate) fn analizar_cabecera(
    a: &Archivo,
    b: &[u8],
    c: &Conocimiento,
) -> Result<Vec<Activo>, String> {
    if !b.starts_with(MAGIA) || b.len() < 512 {
        return Err("no es una cabecera LUKS".into());
    }
    let version = u16::from_be_bytes([b[6], b[7]]);
    let mut activos = Vec::new();
    let mut p = Activo::nuevo(
        format!("protocolo:luks:{}", id_corto(&a.ruta_estable)),
        format!("Volumen LUKS{version} ({})", a.nombre),
        Detalles::Protocolo {
            tipo_protocolo: format!("luks{version}"),
            versiones: vec![format!("LUKS{version}")],
            grupos: Vec::new(),
            cifrados: Vec::new(),
        },
    )
    .con_contexto(CAPACIDAD, Garantia::Confidencialidad)
    .con_ubicacion(a.ruta, None);
    let agregar = |id: Option<&str>, respaldo: &str, p: &mut Activo, activos: &mut Vec<Activo>| {
        let x = activo_algoritmo(
            id.and_then(|i| c.por_id(i)),
            respaldo,
            None,
            CAPACIDAD,
            Some(Garantia::Confidencialidad),
            a.ruta,
            None,
        );
        p.relacionar("algorithm", &x.referencia);
        if !activos
            .iter()
            .any(|y: &Activo| y.referencia == x.referencia)
        {
            activos.push(x);
        }
    };
    match version {
        1 => {
            let nombre = texto_c(&b[8..40]);
            let modo = texto_c(&b[40..72]);
            let hash = texto_c(&b[72..104]);
            let bytes = u32::from_be_bytes(b[108..112].try_into().expect("4 bytes")) as u64;
            let completo = format!("{nombre}-{modo}");
            agregar(cifrador(&completo, bytes), &completo, &mut p, &mut activos);
            agregar(Some("pbkdf2"), "PBKDF2", &mut p, &mut activos);
            let mut minimo = u32::MAX;
            for ranura in 0..8 {
                let o = 208 + ranura * 48;
                let activa = u32::from_be_bytes(b[o..o + 4].try_into().expect("4 bytes"));
                if activa == 0x00AC_71F3 {
                    minimo = minimo.min(u32::from_be_bytes(
                        b[o + 4..o + 8].try_into().expect("4 bytes"),
                    ));
                }
            }
            if let Detalles::Protocolo { cifrados, .. } = &mut p.detalles {
                cifrados.push(format!("{completo} ({} bits), PBKDF2-{hash}", bytes * 8));
            }
            p.advertir("LUKS1 deriva las llaves con PBKDF2, que resiste poco los ataques con GPU: convierta a LUKS2 con Argon2id (cryptsetup convert --type luks2 y luksConvertKey --pbkdf argon2id).");
            if hash.eq_ignore_ascii_case("sha1") {
                p.advertir(
                    "La cabecera usa SHA-1 para PBKDF2 y para la digestión de la llave maestra.",
                );
            }
            if minimo != u32::MAX && minimo < 100_000 {
                p.advertir(format!(
                    "Una ranura activa usa solo {minimo} iteraciones de PBKDF2."
                ));
            }
            p.riesgo_fijado = Some(Riesgo::Obsoleto);
        }
        2 => {
            let tam = u64::from_be_bytes(b[8..16].try_into().expect("8 bytes")) as usize;
            let fin = tam.min(b.len()).max(4096);
            let json = texto_c(b.get(4096..fin).unwrap_or(&[]));
            let v: Value = serde_json::from_str(&json)
                .map_err(|e| format!("metadatos LUKS2 inválidos: {e}"))?;
            if let Some(segmentos) = v.get("segments").and_then(Value::as_object) {
                for s in segmentos.values() {
                    if let Some(enc) = s.get("encryption").and_then(Value::as_str) {
                        // El tamaño de llave del segmento se declara en el digest o en las ranuras.
                        let bytes = v
                            .get("keyslots")
                            .and_then(Value::as_object)
                            .and_then(|k| {
                                k.values()
                                    .find_map(|x| x.get("key_size").and_then(Value::as_u64))
                            })
                            .unwrap_or(64);
                        agregar(cifrador(enc, bytes), enc, &mut p, &mut activos);
                        if let Detalles::Protocolo { cifrados, .. } = &mut p.detalles {
                            cifrados.push(format!("{enc} ({} bits)", bytes * 8));
                        }
                    }
                }
            }
            if let Some(ranuras) = v.get("keyslots").and_then(Value::as_object) {
                for r in ranuras.values() {
                    match r.pointer("/kdf/type").and_then(Value::as_str) {
                        Some(t) if t.starts_with("argon2") => {
                            agregar(Some("argon2"), t, &mut p, &mut activos)
                        }
                        Some("pbkdf2") => {
                            agregar(Some("pbkdf2"), "PBKDF2", &mut p, &mut activos);
                            p.advertir("Una ranura de LUKS2 usa PBKDF2: cámbiela a Argon2id (cryptsetup luksConvertKey --pbkdf argon2id).");
                        }
                        _ => {}
                    }
                }
            }
        }
        otra => return Err(format!("versión de LUKS desconocida: {otra}")),
    }
    activos.push(p);
    Ok(activos)
}

pub struct EscanerLuks;

impl Escaner for EscanerLuks {
    fn nombre(&self) -> &'static str {
        "cabecera LUKS"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        a.contenido.starts_with(MAGIA)
    }

    fn analizar(&self, a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
        analizar_cabecera(a, a.contenido, c)
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn luks1_y_luks2() {
        let c = Conocimiento::embebido();
        let mut b = vec![0u8; 592];
        b[..6].copy_from_slice(MAGIA);
        b[7] = 1;
        b[8..11].copy_from_slice(b"aes");
        b[40..52].copy_from_slice(b"xts-plain64\0");
        b[72..76].copy_from_slice(b"sha1");
        b[108..112].copy_from_slice(&64u32.to_be_bytes());
        b[208..212].copy_from_slice(&0x00AC_71F3u32.to_be_bytes());
        b[212..216].copy_from_slice(&2000u32.to_be_bytes());
        let a = Archivo::nuevo(
            "cabecera.img",
            std::path::Path::new("cabecera.img"),
            &b,
            None,
        );
        let v = analizar_cabecera(&a, &b, &c).unwrap();
        assert!(v.iter().any(|x| x.algoritmo_id() == Some("aes-256-xts")));
        let p = v.last().unwrap();
        assert_eq!(p.riesgo_fijado, Some(Riesgo::Obsoleto));
        assert!(p.advertencias.iter().any(|w| w.contains("2000")));

        let json = br#"{"keyslots":{"0":{"type":"luks2","key_size":64,"kdf":{"type":"argon2id"}}},"segments":{"0":{"type":"crypt","encryption":"aes-xts-plain64"}}}"#;
        let mut b = vec![0u8; 16384];
        b[..6].copy_from_slice(MAGIA);
        b[7] = 2;
        b[8..16].copy_from_slice(&16384u64.to_be_bytes());
        b[4096..4096 + json.len()].copy_from_slice(json);
        let v = analizar_cabecera(&a, &b, &c).unwrap();
        assert!(v.iter().any(|x| x.algoritmo_id() == Some("aes-256-xts")));
        assert!(v.iter().any(|x| x.algoritmo_id() == Some("argon2")));
        assert!(v.last().unwrap().riesgo_fijado.is_none());
    }
}
