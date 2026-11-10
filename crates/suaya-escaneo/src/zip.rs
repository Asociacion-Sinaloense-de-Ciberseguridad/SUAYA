//! Lectura acotada de archivos ZIP (JAR, WAR, EAR, APK, AAR).
//!
//! Solo lo necesario para inventariar: el directorio central (incluido
//! ZIP64) y la lectura de entradas almacenadas o comprimidas con deflate,
//! con límites de tamaño y de proporción para evitar bombas de descompresión.

use std::io::Read;

#[derive(Debug, Clone)]
pub(crate) struct Entrada {
    pub nombre: String,
    pub metodo: u16,
    pub comprimido: u64,
    pub descomprimido: u64,
    pub desplazamiento: u64,
}

pub(crate) struct Zip<'a> {
    pub datos: &'a [u8],
    pub entradas: Vec<Entrada>,
    /// Desplazamiento del directorio central (el bloque de firma de APK va antes).
    pub inicio_directorio: usize,
}

const MAXIMO_ENTRADAS: usize = 100_000;

fn u16_en(b: &[u8], p: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(p..p + 2)?.try_into().ok()?))
}

fn u32_en(b: &[u8], p: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(p..p + 4)?.try_into().ok()?))
}

fn u64_en(b: &[u8], p: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(p..p + 8)?.try_into().ok()?))
}

pub(crate) fn abrir(b: &[u8]) -> Option<Zip<'_>> {
    // Fin del directorio central: en los últimos 64 KiB más 22 bytes.
    let desde = b.len().saturating_sub(65_557);
    let eocd = (desde..b.len().saturating_sub(21))
        .rev()
        .find(|&i| b[i..].starts_with(b"PK\x05\x06"))?;
    let mut total = u16_en(b, eocd + 10)? as u64;
    let mut inicio = u32_en(b, eocd + 16)? as u64;
    if total == 0xFFFF || inicio == 0xFFFF_FFFF {
        // ZIP64: el localizador está 20 bytes antes.
        let loc = eocd.checked_sub(20)?;
        if !b[loc..].starts_with(b"PK\x06\x07") {
            return None;
        }
        let registro = u64_en(b, loc + 8)? as usize;
        if !b.get(registro..)?.starts_with(b"PK\x06\x06") {
            return None;
        }
        total = u64_en(b, registro + 32)?;
        inicio = u64_en(b, registro + 48)?;
    }
    let mut entradas = Vec::new();
    let mut p = usize::try_from(inicio).ok()?;
    let inicio_directorio = p;
    for _ in 0..total.min(MAXIMO_ENTRADAS as u64) {
        if !b.get(p..)?.starts_with(b"PK\x01\x02") {
            break;
        }
        let metodo = u16_en(b, p + 10)?;
        let mut comprimido = u32_en(b, p + 20)? as u64;
        let mut descomprimido = u32_en(b, p + 24)? as u64;
        let n = u16_en(b, p + 28)? as usize;
        let e = u16_en(b, p + 30)? as usize;
        let k = u16_en(b, p + 32)? as usize;
        let mut desplazamiento = u32_en(b, p + 42)? as u64;
        let nombre = String::from_utf8_lossy(b.get(p + 46..p + 46 + n)?).into_owned();
        // Campo extra ZIP64 (id 1) con los valores que no caben en 32 bits.
        let mut x = p + 46 + n;
        let fin_extra = x + e;
        while x + 4 <= fin_extra {
            let id = u16_en(b, x)?;
            let largo = u16_en(b, x + 2)? as usize;
            if id == 1 {
                let mut q = x + 4;
                if descomprimido == 0xFFFF_FFFF {
                    descomprimido = u64_en(b, q)?;
                    q += 8;
                }
                if comprimido == 0xFFFF_FFFF {
                    comprimido = u64_en(b, q)?;
                    q += 8;
                }
                if desplazamiento == 0xFFFF_FFFF {
                    desplazamiento = u64_en(b, q)?;
                }
            }
            x += 4 + largo;
        }
        entradas.push(Entrada {
            nombre,
            metodo,
            comprimido,
            descomprimido,
            desplazamiento,
        });
        p += 46 + n + e + k;
    }
    Some(Zip {
        datos: b,
        entradas,
        inicio_directorio,
    })
}

/// Contenido de una entrada, si no supera `limite` bytes ni una proporción
/// de compresión sospechosa.
pub(crate) fn leer(z: &Zip<'_>, e: &Entrada, limite: usize) -> Option<Vec<u8>> {
    if e.descomprimido > limite as u64
        || e.descomprimido > e.comprimido.saturating_mul(200).saturating_add(1 << 20)
    {
        return None;
    }
    let p = usize::try_from(e.desplazamiento).ok()?;
    if !z.datos.get(p..)?.starts_with(b"PK\x03\x04") {
        return None;
    }
    let n = u16_en(z.datos, p + 26)? as usize;
    let x = u16_en(z.datos, p + 28)? as usize;
    let inicio = p + 30 + n + x;
    let fin = inicio.checked_add(usize::try_from(e.comprimido).ok()?)?;
    let crudo = z.datos.get(inicio..fin)?;
    match e.metodo {
        0 => Some(crudo.to_vec()),
        8 => {
            let mut v = Vec::new();
            flate2::read::DeflateDecoder::new(crudo)
                .take(limite as u64 + 1)
                .read_to_end(&mut v)
                .ok()?;
            (v.len() <= limite).then_some(v)
        }
        _ => None,
    }
}

#[cfg(test)]
pub(crate) mod pruebas {
    use super::*;

    /// ZIP mínimo con entradas almacenadas, para pruebas.
    pub(crate) fn zip_almacenado(entradas: &[(&str, &[u8])]) -> Vec<u8> {
        let mut b = Vec::new();
        let mut central = Vec::new();
        for (nombre, datos) in entradas {
            let desplazamiento = b.len() as u32;
            b.extend(b"PK\x03\x04");
            b.extend([20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            b.extend((datos.len() as u32).to_le_bytes());
            b.extend((datos.len() as u32).to_le_bytes());
            b.extend((nombre.len() as u16).to_le_bytes());
            b.extend([0, 0]);
            b.extend(nombre.as_bytes());
            b.extend(*datos);
            central.extend(b"PK\x01\x02");
            central.extend([20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            central.extend((datos.len() as u32).to_le_bytes());
            central.extend((datos.len() as u32).to_le_bytes());
            central.extend((nombre.len() as u16).to_le_bytes());
            central.extend([0u8; 12]);
            central.extend(desplazamiento.to_le_bytes());
            central.extend(nombre.as_bytes());
        }
        let inicio = b.len() as u32;
        let largo = central.len() as u32;
        b.extend(&central);
        b.extend(b"PK\x05\x06");
        b.extend([0, 0, 0, 0]);
        b.extend((entradas.len() as u16).to_le_bytes());
        b.extend((entradas.len() as u16).to_le_bytes());
        b.extend(largo.to_le_bytes());
        b.extend(inicio.to_le_bytes());
        b.extend([0, 0]);
        b
    }

    #[test]
    fn lee_entradas_y_rechaza_bombas() {
        let b = zip_almacenado(&[
            ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
            ("a/B.class", b"xyz"),
        ]);
        let z = abrir(&b).unwrap();
        assert_eq!(z.entradas.len(), 2);
        assert_eq!(leer(&z, &z.entradas[1], 100).as_deref(), Some(&b"xyz"[..]));
        let mut bomba = z.entradas[1].clone();
        bomba.descomprimido = 1 << 40;
        assert!(leer(&z, &bomba, 1 << 20).is_none());
        assert!(abrir(b"PK\x03\x04 no es un zip").is_none());
    }
}
