//! Lectura mínima y acotada de DER/BER y de mensajes CMS (PKCS #7).
//!
//! Lo comparten las firmas de código (Authenticode, macOS, JAR y APK) y los
//! contenedores PKCS #12. Solo lee: nunca verifica ni descifra firmas.

/// Un elemento TLV.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Tlv<'a> {
    pub etiqueta: u8,
    pub contenido: &'a [u8],
    /// Codificación completa (etiqueta, largo y contenido).
    pub completo: &'a [u8],
}

const PROFUNDIDAD_MAXIMA: usize = 32;

/// Lee un elemento y devuelve el resto. Admite largo indefinido (BER) en
/// elementos construidos.
pub(crate) fn tlv(b: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    tlv_con_profundidad(b, 0)
}

fn tlv_con_profundidad(b: &[u8], profundidad: usize) -> Option<(Tlv<'_>, &[u8])> {
    if profundidad > PROFUNDIDAD_MAXIMA {
        return None;
    }
    let etiqueta = *b.first()?;
    if etiqueta & 0x1f == 0x1f {
        return None; // Etiquetas de varios bytes: no aparecen en estos formatos.
    }
    let l0 = *b.get(1)?;
    if l0 == 0x80 {
        // Largo indefinido: hijos hasta el marcador 00 00.
        if etiqueta & 0x20 == 0 {
            return None;
        }
        let mut resto = &b[2..];
        loop {
            if resto.starts_with(&[0, 0]) {
                let fin = b.len() - resto.len();
                return Some((
                    Tlv {
                        etiqueta,
                        contenido: &b[2..fin],
                        completo: &b[..fin + 2],
                    },
                    &resto[2..],
                ));
            }
            let (_, r) = tlv_con_profundidad(resto, profundidad + 1)?;
            resto = r;
        }
    }
    let (largo, cabecera) = if l0 < 0x80 {
        (l0 as usize, 2usize)
    } else {
        let n = (l0 & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut v = 0usize;
        for i in 0..n {
            v = (v << 8) | *b.get(2 + i)? as usize;
        }
        (v, 2 + n)
    };
    let fin = cabecera.checked_add(largo)?;
    if fin > b.len() {
        return None;
    }
    Some((
        Tlv {
            etiqueta,
            contenido: &b[cabecera..fin],
            completo: &b[..fin],
        },
        &b[fin..],
    ))
}

/// Hijos de un elemento construido (como máximo 4096).
pub(crate) fn hijos(contenido: &[u8]) -> Vec<Tlv<'_>> {
    let mut v = Vec::new();
    let mut resto = contenido;
    while !resto.is_empty() && !resto.starts_with(&[0, 0]) && v.len() < 4096 {
        match tlv(resto) {
            Some((t, r)) => {
                v.push(t);
                resto = r;
            }
            None => break,
        }
    }
    v
}

/// Contenido de un elemento construido BER: concatena los segmentos de una
/// cadena de octetos construida.
pub(crate) fn octetos(t: &Tlv<'_>) -> Vec<u8> {
    if t.etiqueta & 0x20 == 0 {
        return t.contenido.to_vec();
    }
    hijos(t.contenido).iter().flat_map(|h| octetos(h)).collect()
}

/// Texto de un OID («1.2.840.113549.1.7.2») a partir de su contenido DER.
pub(crate) fn oid(contenido: &[u8]) -> Option<String> {
    let (&primero, resto) = contenido.split_first()?;
    let mut partes = vec![
        (primero / 40).min(2) as u64,
        (primero as u64).saturating_sub(40 * (primero / 40).min(2) as u64),
    ];
    let mut actual: u64 = 0;
    for &b in resto {
        if actual > (u64::MAX >> 8) {
            return None;
        }
        actual = (actual << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            partes.push(actual);
            actual = 0;
        }
    }
    Some(
        partes
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join("."),
    )
}

/// OID del primer hijo de un AlgorithmIdentifier.
pub(crate) fn oid_de_algoritmo(t: &Tlv<'_>) -> Option<String> {
    let h = hijos(t.contenido);
    h.first()
        .filter(|x| x.etiqueta == 0x06)
        .and_then(|x| oid(x.contenido))
}

/// Entero sin signo pequeño (hasta 8 bytes).
pub(crate) fn entero(contenido: &[u8]) -> Option<u64> {
    if contenido.is_empty() || contenido.len() > 9 {
        return None;
    }
    Some(contenido.iter().fold(0u64, |v, b| (v << 8) | *b as u64))
}

/// Lo que interesa de un mensaje CMS SignedData.
#[derive(Debug, Default, Clone)]
pub(crate) struct Cms {
    pub certificados: Vec<Vec<u8>>,
    /// OID de los algoritmos de digestión declarados y de los firmantes.
    pub digestiones: Vec<String>,
    /// OID de los algoritmos de firma de los firmantes.
    pub firmas: Vec<String>,
    /// Tipo del contenido firmado.
    pub tipo_contenido: Option<String>,
    /// En Authenticode: OID del hash del archivo (SpcIndirectDataContent).
    pub hash_contenido: Option<String>,
}

pub(crate) const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
pub(crate) const OID_SPC_INDIRECT: &str = "1.3.6.1.4.1.311.2.1.4";

/// Interpreta un ContentInfo con SignedData.
pub(crate) fn cms(der: &[u8]) -> Option<Cms> {
    let (ci, _) = tlv(der)?;
    if ci.etiqueta != 0x30 {
        return None;
    }
    let partes = hijos(ci.contenido);
    if partes.first().and_then(|x| oid(x.contenido)).as_deref() != Some(OID_SIGNED_DATA) {
        return None;
    }
    let explicito = partes.get(1).filter(|x| x.etiqueta == 0xA0)?;
    let sd = hijos(explicito.contenido).into_iter().next()?;
    let campos = hijos(sd.contenido);
    let mut r = Cms::default();
    for (i, c) in campos.iter().enumerate() {
        match (i, c.etiqueta) {
            (1, 0x31) => {
                r.digestiones
                    .extend(hijos(c.contenido).iter().filter_map(oid_de_algoritmo));
            }
            (2, 0x30) => {
                let encap = hijos(c.contenido);
                r.tipo_contenido = encap.first().and_then(|x| oid(x.contenido));
                if r.tipo_contenido.as_deref() == Some(OID_SPC_INDIRECT)
                    && let Some(e) = encap.get(1)
                    && let Some(spc) = hijos(e.contenido).into_iter().next()
                {
                    // SpcIndirectDataContent { data, messageDigest DigestInfo }.
                    r.hash_contenido = hijos(spc.contenido)
                        .get(1)
                        .and_then(|di| hijos(di.contenido).into_iter().next())
                        .and_then(|alg| oid_de_algoritmo(&alg));
                }
            }
            (_, 0xA0) => {
                for cert in hijos(c.contenido).into_iter().take(64) {
                    if cert.etiqueta == 0x30 {
                        r.certificados.push(cert.completo.to_vec());
                    }
                }
            }
            (_, 0x31) if i >= 3 => {
                for firmante in hijos(c.contenido).into_iter().take(16) {
                    let f = hijos(firmante.contenido);
                    // version, sid, digestAlgorithm, [0] signedAttrs?, signatureAlgorithm, ...
                    if let Some(d) = f.get(2).and_then(oid_de_algoritmo) {
                        r.digestiones.push(d);
                    }
                    if let Some(s) = f
                        .iter()
                        .skip(3)
                        .find(|x| x.etiqueta == 0x30)
                        .and_then(oid_de_algoritmo)
                    {
                        r.firmas.push(s);
                    }
                }
            }
            _ => {}
        }
    }
    r.digestiones.sort();
    r.digestiones.dedup();
    r.firmas.sort();
    r.firmas.dedup();
    Some(r)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn oid_y_tlv() {
        // 1.2.840.113549.1.7.2
        let c = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
        assert_eq!(oid(&c).as_deref(), Some(OID_SIGNED_DATA));
        let b = [0x30, 0x03, 0x02, 0x01, 0x05, 0xFF];
        let (t, r) = tlv(&b).unwrap();
        assert_eq!((t.etiqueta, t.contenido.len(), r.len()), (0x30, 3, 1));
        assert_eq!(entero(hijos(t.contenido)[0].contenido), Some(5));
        // Largo indefinido.
        let b = [0x30, 0x80, 0x02, 0x01, 0x07, 0x00, 0x00, 0x01];
        let (t, r) = tlv(&b).unwrap();
        assert_eq!((hijos(t.contenido).len(), r), (1, &[0x01][..]));
        // Largo que excede los datos.
        assert!(tlv(&[0x30, 0x05, 0x01]).is_none());
        assert!(tlv(&[0x30, 0x85, 1, 1, 1, 1, 1]).is_none());
    }
}
