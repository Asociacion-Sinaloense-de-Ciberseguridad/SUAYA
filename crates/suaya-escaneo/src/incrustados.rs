//! Certificados y llaves PEM incrustados en base64 dentro de otros archivos.
//!
//! Es el formato de los `Secret` de Kubernetes (`tls.crt`, `tls.key`), de
//! `kubeconfig` (`client-key-data`, `certificate-authority-data`), de valores
//! de Helm, del estado de Terraform y de muchas variables de CI. En lugar de
//! interpretar cada formato, se busca la firma base64 de `-----BEGIN`.

use base64::Engine;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use suaya_core::{Activo, Conocimiento};

use crate::Escaner;
use crate::comun::{Archivo, linea_de};
use crate::pem::analizar_texto_pem;

/// `-----BEGIN` codificado en base64 (los primeros 14 caracteres).
const MARCA: &[u8] = b"LS0tLS1CRUdJTi";
const MINIMO: usize = 60;

const TOLERANTE: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

pub struct EscanerIncrustados;

fn es_base64(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='
}

/// Describe de forma legible en qué tipo de archivo está el secreto.
fn origen(a: &Archivo, texto: &str, campo: &str) -> String {
    let tipo = if texto.contains("kind: Secret") || texto.contains("\"kind\": \"Secret\"") {
        "un Secret de Kubernetes"
    } else if texto.contains("clusters:") && texto.contains("users:") {
        "un archivo kubeconfig"
    } else if a.extension == "tfstate" {
        "el estado de Terraform"
    } else {
        "un archivo de texto (codificado en base64)"
    };
    if campo.is_empty() {
        tipo.to_string()
    } else {
        format!("{tipo} (campo «{campo}»)")
    }
}

/// Nombre del campo YAML o JSON que precede al valor en la misma línea.
fn campo_en(linea: &str) -> String {
    linea
        .split(':')
        .next()
        .unwrap_or("")
        .trim()
        .trim_start_matches('-')
        .trim()
        .trim_matches('"')
        .chars()
        .take(60)
        .collect()
}

impl Escaner for EscanerIncrustados {
    fn nombre(&self) -> &'static str {
        "secretos incrustados"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        a.contiene(MARCA)
    }

    fn analizar(&self, a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
        let datos = a.contenido;
        let texto = String::from_utf8_lossy(datos);
        let mut activos = Vec::new();
        let mut errores = Vec::new();
        let mut i = 0usize;

        while let Some(p) = datos[i..].windows(MARCA.len()).position(|w| w == MARCA) {
            let inicio = i + p;
            let fin = inicio
                + datos[inicio..]
                    .iter()
                    .take_while(|&&b| es_base64(b))
                    .count();
            i = fin.max(inicio + 1);
            if fin - inicio < MINIMO {
                continue;
            }
            let Ok(decodificado) = TOLERANTE.decode(&datos[inicio..fin]) else {
                continue;
            };
            let Ok(pem) = String::from_utf8(decodificado) else {
                continue;
            };
            let linea = linea_de(datos, inicio);
            let inicio_linea = datos[..inicio]
                .iter()
                .rposition(|&b| b == b'\n')
                .map(|x| x + 1)
                .unwrap_or(0);
            let campo = campo_en(&String::from_utf8_lossy(&datos[inicio_linea..inicio]));

            let mut interno =
                Archivo::nuevo(a.ruta, std::path::Path::new(a.ruta), pem.as_bytes(), a.modo);
            interno.ruta_estable = format!("{}#{linea}", a.ruta_estable);
            interno.incrustado_en = Some(origen(a, &texto, &campo));
            let (mut v, mut e) = analizar_texto_pem(&pem, &interno, Some(linea), c);
            activos.append(&mut v);
            errores.append(&mut e);
        }

        if activos.is_empty() && !errores.is_empty() {
            return Err(errores.join("; "));
        }
        Ok(activos)
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn campo_de_la_linea() {
        assert_eq!(campo_en("  tls.key: "), "tls.key");
        assert_eq!(campo_en("    \"client-key-data\": \""), "client-key-data");
        assert_eq!(
            campo_en("- certificate-authority-data: "),
            "certificate-authority-data"
        );
    }
}
