//! Enlace entre llaves privadas, llaves públicas y certificados.
//!
//! Los escáneres calculan la identidad de cada llave pública (ver
//! [`crate::modelo::Detalles`]). Aquí se usa esa identidad para:
//!
//! - relacionar cada llave privada con su certificado y su llave pública;
//! - heredar a la llave el contexto de uso del certificado (una llave suelta
//!   pasa de «sin clasificar» a, por ejemplo, «servidores web»);
//! - advertir cuando la misma llave privada aparece en varias ubicaciones.

use std::collections::BTreeMap;

use crate::modelo::{Contexto, Detalles, Inventario};

fn identidad(d: &Detalles) -> Option<&str> {
    match d {
        Detalles::Certificado {
            identidad_llave, ..
        }
        | Detalles::Material {
            identidad_llave, ..
        } => identidad_llave.as_deref(),
        _ => None,
    }
}

fn es_privada(d: &Detalles) -> bool {
    matches!(d, Detalles::Material { tipo_material, .. } if tipo_material == "private-key")
}

/// Enlaza los activos que comparten identidad de llave. Es idempotente.
pub fn enlazar_llaves(inv: &mut Inventario) {
    let mut grupos: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, a) in inv.activos.iter().enumerate() {
        if let Some(id) = identidad(&a.detalles) {
            grupos.entry(id.to_string()).or_default().push(i);
        }
    }

    for indices in grupos.values() {
        if indices.len() < 2 {
            continue;
        }
        let certificados: Vec<usize> = indices
            .iter()
            .copied()
            .filter(|&i| matches!(inv.activos[i].detalles, Detalles::Certificado { .. }))
            .collect();
        let privadas: Vec<usize> = indices
            .iter()
            .copied()
            .filter(|&i| es_privada(&inv.activos[i].detalles))
            .collect();
        let publicas: Vec<usize> = indices
            .iter()
            .copied()
            .filter(|&i| !certificados.contains(&i) && !privadas.contains(&i))
            .collect();

        // Contextos de los certificados, para heredarlos.
        let contextos: Vec<Contexto> = certificados
            .iter()
            .flat_map(|&i| inv.activos[i].contextos.clone())
            .filter(|c| c.capacidad != "sin-clasificar")
            .collect();

        let refs = |v: &[usize], inv: &Inventario| -> Vec<String> {
            v.iter()
                .map(|&i| inv.activos[i].referencia.clone())
                .collect()
        };
        let refs_cert = refs(&certificados, inv);
        let refs_priv = refs(&privadas, inv);
        let refs_pub = refs(&publicas, inv);

        for &i in &privadas {
            let a = &mut inv.activos[i];
            for r in &refs_cert {
                a.relacionar("certificate", r);
            }
            for r in &refs_pub {
                a.relacionar("publicKey", r);
            }
            if !contextos.is_empty() {
                a.contextos.retain(|c| c.capacidad != "sin-clasificar");
                for c in &contextos {
                    a.agregar_contexto(&c.capacidad, c.garantia);
                }
            }
        }
        for &i in &certificados {
            let a = &mut inv.activos[i];
            for r in &refs_priv {
                a.relacionar("privateKey", r);
            }
        }
        for &i in &publicas {
            let a = &mut inv.activos[i];
            for r in &refs_cert {
                a.relacionar("certificate", r);
            }
            for r in &refs_priv {
                a.relacionar("privateKey", r);
            }
            if !contextos.is_empty() {
                a.contextos.retain(|c| c.capacidad != "sin-clasificar");
                for c in &contextos {
                    a.agregar_contexto(&c.capacidad, c.garantia);
                }
            }
        }

        if privadas.len() > 1 {
            let mut lugares: Vec<String> = privadas
                .iter()
                .filter_map(|&i| inv.activos[i].ubicaciones.first().map(|u| u.ruta.clone()))
                .collect();
            lugares.sort();
            let texto = format!(
                "La misma llave privada aparece en {} ubicaciones ({}). Cada copia amplía la superficie de exposición; conserve solo las necesarias.",
                privadas.len(),
                lugares.join(", ")
            );
            for &i in &privadas {
                inv.activos[i].advertir(texto.clone());
            }
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::modelo::{Activo, Garantia};

    fn llave(r: &str, tipo: &str, id: &str, ruta: &str) -> Activo {
        Activo::nuevo(
            r,
            r,
            Detalles::Material {
                tipo_material: tipo.into(),
                tamano: None,
                formato: "PEM".into(),
                protegido_por: None,
                huella_sha256: None,
                identidad_llave: Some(id.into()),
            },
        )
        .con_contexto("sin-clasificar", Garantia::Autenticacion)
        .con_ubicacion(ruta, None)
    }

    #[test]
    fn enlaza_y_hereda_contexto() {
        let mut inv = Inventario::default();
        inv.agregar(
            Activo::nuevo(
                "certificado:a",
                "a",
                Detalles::Certificado {
                    sujeto: String::new(),
                    emisor: String::new(),
                    serie: String::new(),
                    no_antes: String::new(),
                    no_despues: String::new(),
                    huella_sha256: String::new(),
                    extension_archivo: None,
                    vencido: false,
                    identidad_llave: Some("x".into()),
                },
            )
            .con_contexto("servidores-web", Garantia::Autenticacion),
        );
        inv.agregar(llave("llave:1", "private-key", "x", "/a.key"));
        inv.agregar(llave("llave:2", "private-key", "x", "/copia/a.key"));
        inv.agregar(llave("llave:3", "private-key", "y", "/otra.key"));
        enlazar_llaves(&mut inv);
        enlazar_llaves(&mut inv);

        let k1 = &inv.activos[1];
        assert!(
            k1.relaciones
                .iter()
                .any(|r| r.tipo == "certificate" && r.referencia == "certificado:a")
        );
        assert_eq!(k1.contextos.len(), 1);
        assert_eq!(k1.contextos[0].capacidad, "servidores-web");
        assert_eq!(k1.advertencias.len(), 1);
        assert!(k1.advertencias[0].contains("2 ubicaciones"));
        assert_eq!(inv.activos[0].relaciones.len(), 2);
        assert!(inv.activos[3].relaciones.is_empty());
        assert_eq!(inv.activos[3].contextos[0].capacidad, "sin-clasificar");
    }
}
