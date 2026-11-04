//! Escáner de la política criptográfica de Java (`java.security`).
//!
//! El JDK prohíbe algoritmos con tres listas: `jdk.tls.disabledAlgorithms`
//! (TLS), `jdk.certpath.disabledAlgorithms` (validación de certificados) y
//! `jdk.jar.disabledAlgorithms` (firma de JAR). Las listas predeterminadas de
//! las versiones actuales ya excluyen lo roto; el riesgo aparece cuando una
//! instalación las recorta para «compatibilidad». Suaya revisa qué quedó
//! habilitado de nuevo.

use std::collections::BTreeMap;

use suaya_core::{Activo, Conocimiento, Detalles, Garantia, Riesgo};

use crate::Escaner;
use crate::comun::{Archivo, id_corto, linea_de};
use crate::config_tls::evaluar_tls;

/// Decisión de Suaya: la política de Java gobierna el TLS de servidores y
/// clientes de aplicaciones; se evalúa con la madurez de `servidores-web`.
const CAPACIDAD: &str = "servidores-web";
const VERSIONES: [&str; 5] = ["SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"];
const SIN_GRUPOS: &str = "Java elige los grupos de TLS con la propiedad del sistema jdk.tls.namedGroups, fuera de java.security. Verifique si su versión del JDK ofrece grupos híbridos con ML-KEM y si las aplicaciones fijan esa propiedad.";

/// Entradas que deben seguir en `jdk.tls.disabledAlgorithms`.
const TLS_PROHIBIDOS: [&str; 6] = ["RC4", "DES", "3DES_EDE_CBC", "NULL", "anon", "MD5withRSA"];
/// Entradas que deben seguir en `jdk.certpath.disabledAlgorithms`.
const RUTA_PROHIBIDOS: [&str; 3] = ["MD2", "MD5", "SHA1"];
/// Entradas que deben seguir en `jdk.jar.disabledAlgorithms`.
const JAR_PROHIBIDOS: [&str; 2] = ["MD2", "MD5"];

pub struct EscanerConfigJava;

/// Primeras palabras de cada entrada de una lista (`DH keySize < 1024` -> `DH`).
fn nombres(lista: &str) -> Vec<String> {
    lista
        .split(',')
        .filter_map(|e| e.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

/// ¿La lista restringe el tamaño de llave RSA a 1024 bits o más?
fn restringe_rsa(lista: &str) -> bool {
    lista.split(',').any(|e| {
        let partes: Vec<&str> = e.split_whitespace().collect();
        partes.first() == Some(&"RSA")
            && partes.contains(&"keySize")
            && partes
                .last()
                .and_then(|n| n.parse::<u32>().ok())
                .is_some_and(|n| n >= 1024)
    })
}

impl Escaner for EscanerConfigJava {
    fn nombre(&self) -> &'static str {
        "política criptográfica de Java"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        a.nombre == "java.security" || a.contiene(b"jdk.tls.disabledAlgorithms")
    }

    fn analizar(&self, a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
        let texto = a.texto().ok_or("el archivo no es texto UTF-8")?;
        // Propiedades de Java: «clave=valor» con continuación por «\» al final.
        let mut valores: BTreeMap<String, (String, u32)> = BTreeMap::new();
        let mut pendiente: Option<(String, String, u32)> = None;
        let mut desplazamiento = 0usize;
        for linea in texto.split_inclusive('\n') {
            let numero = linea_de(a.contenido, desplazamiento);
            desplazamiento += linea.len();
            let l = linea.trim();
            if let Some((k, mut v, n)) = pendiente.take() {
                let continua = l.ends_with('\\');
                v.push(' ');
                v.push_str(l.trim_end_matches('\\').trim());
                if continua {
                    pendiente = Some((k, v, n));
                } else {
                    valores.insert(k, (v, n));
                }
                continue;
            }
            if l.is_empty() || l.starts_with('#') || l.starts_with('!') {
                continue;
            }
            let Some((k, v)) = l.split_once(['=', ':']) else {
                continue;
            };
            let k = k.trim().to_string();
            let v = v.trim();
            if v.ends_with('\\') {
                pendiente = Some((k, v.trim_end_matches('\\').trim().to_string(), numero));
            } else {
                valores.insert(k, (v.to_string(), numero));
            }
        }
        if let Some((k, v, n)) = pendiente {
            valores.insert(k, (v, n));
        }
        let Some((tls, linea_tls)) = valores.get("jdk.tls.disabledAlgorithms").cloned() else {
            return Ok(Vec::new());
        };

        let prohibidos = nombres(&tls);
        let esta = |lista: &[String], n: &str| lista.iter().any(|x| x.eq_ignore_ascii_case(n));
        let versiones: Vec<String> = VERSIONES
            .iter()
            .filter(|v| !esta(&prohibidos, v))
            .map(|v| v.to_string())
            .collect();

        let mut protocolo = Activo::nuevo(
            format!("protocolo:tls:{}", id_corto(&a.ruta_estable)),
            format!("Java ({})", a.nombre),
            Detalles::Protocolo {
                tipo_protocolo: "tls".into(),
                versiones: versiones.clone(),
                grupos: Vec::new(),
                cifrados: Vec::new(),
            },
        )
        .con_contexto(CAPACIDAD, Garantia::Confidencialidad)
        .con_ubicacion(a.ruta, Some(linea_tls));
        evaluar_tls(
            &mut protocolo,
            &versiones,
            None,
            SIN_GRUPOS,
            Riesgo::Desconocido,
            c,
        );

        let mut agravantes: Vec<Riesgo> = Vec::new();
        let faltan: Vec<&str> = TLS_PROHIBIDOS
            .iter()
            .copied()
            .filter(|n| !esta(&prohibidos, n))
            .collect();
        if !faltan.is_empty() {
            agravantes.push(Riesgo::RotoClasico);
            protocolo.advertir(format!(
                "jdk.tls.disabledAlgorithms ya no excluye {}: Java puede negociar cifrados rotos. Restaure la lista predeterminada del JDK.",
                faltan.join(", ")
            ));
        }

        if let Some((ruta, _)) = valores.get("jdk.certpath.disabledAlgorithms") {
            let p = nombres(ruta);
            let faltan: Vec<&str> = RUTA_PROHIBIDOS
                .iter()
                .copied()
                .filter(|n| !esta(&p, n))
                .collect();
            if !faltan.is_empty() {
                agravantes.push(Riesgo::Obsoleto);
                protocolo.advertir(format!(
                    "jdk.certpath.disabledAlgorithms ya no excluye {}: se aceptan certificados firmados con resúmenes rotos.",
                    faltan.join(", ")
                ));
            }
            if !restringe_rsa(ruta) {
                agravantes.push(Riesgo::Obsoleto);
                protocolo.advertir(
                    "jdk.certpath.disabledAlgorithms no limita el tamaño de RSA (se espera «RSA keySize < 1024» o más): se aceptan certificados con llaves RSA débiles.",
                );
            }
        }
        if let Some((jar, _)) = valores.get("jdk.jar.disabledAlgorithms") {
            let p = nombres(jar);
            let faltan: Vec<&str> = JAR_PROHIBIDOS
                .iter()
                .copied()
                .filter(|n| !esta(&p, n))
                .collect();
            if !faltan.is_empty() {
                agravantes.push(Riesgo::Obsoleto);
                protocolo.advertir(format!(
                    "jdk.jar.disabledAlgorithms ya no excluye {}: se aceptan JAR firmados con resúmenes rotos (capacidad de firma de código).",
                    faltan.join(", ")
                ));
            }
        }
        if valores
            .get("keystore.type")
            .is_some_and(|(v, _)| v.eq_ignore_ascii_case("jks") || v.eq_ignore_ascii_case("jceks"))
        {
            protocolo.advertir(
                "keystore.type usa el formato heredado JKS/JCEKS, que protege las llaves con algoritmos propietarios débiles. Use PKCS12.",
            );
        }
        if let Some(r) = agravantes.into_iter().min_by_key(|r| r.gravedad()) {
            let actual = protocolo.riesgo_fijado.unwrap_or(Riesgo::Desconocido);
            if r.gravedad() < actual.gravedad() {
                protocolo.riesgo_fijado = Some(r);
            }
        }
        Ok(vec![protocolo])
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn listas() {
        assert_eq!(
            nombres("SSLv3, TLSv1, DH keySize < 1024, include jdk.disabled.namedCurves"),
            ["SSLv3", "TLSv1", "DH", "include"]
        );
        assert!(restringe_rsa("MD2, RSA keySize < 1024, DSA keySize < 1024"));
        assert!(!restringe_rsa("MD2, RSA keySize < 512"));
    }
}
