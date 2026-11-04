//! Recursos `Certificate` de cert-manager en manifiestos de Kubernetes.
//!
//! El algoritmo de la llave que cert-manager generará se declara en
//! `spec.privateKey` (por omisión, RSA de 2048 bits). Inventariarlo permite
//! saber qué se emitirá en cada renovación, no solo lo que ya existe.

use suaya_core::{Activo, Conocimiento, Detalles, Garantia};

use crate::Escaner;
use crate::comun::{Archivo, activo_algoritmo, id_corto};

/// Las llaves de cert-manager suelen servir TLS de cargas de trabajo.
const CAPACIDAD: &str = "servidores-web";

pub struct EscanerCertManager;

fn indentacion(l: &str) -> usize {
    l.len() - l.trim_start().len()
}

fn valor(l: &str) -> String {
    l.split_once(':')
        .map(|(_, v)| v.trim().trim_matches('"').trim_matches('\'').to_string())
        .unwrap_or_default()
}

/// Datos de un recurso `Certificate`.
struct Recurso {
    linea: u32,
    nombre: String,
    espacio: String,
    algoritmo: String,
    tamano: Option<u32>,
    rotacion: Option<String>,
}

fn recursos(texto: &str) -> Vec<Recurso> {
    let mut salida = Vec::new();
    let lineas: Vec<&str> = texto.lines().collect();
    let mut inicio = 0usize;
    while inicio < lineas.len() {
        let fin = lineas[inicio..]
            .iter()
            .position(|l| l.trim_start().starts_with("---"))
            .map(|p| if p == 0 { inicio + 1 } else { inicio + p })
            .unwrap_or(lineas.len());
        let doc = &lineas[inicio..fin];
        inicio = if fin == inicio { inicio + 1 } else { fin };

        let es_certificado = doc.iter().any(|l| l.trim() == "kind: Certificate")
            && doc.iter().any(|l| l.contains("cert-manager.io/"));
        if !es_certificado {
            continue;
        }
        let mut r = Recurso {
            linea: (inicio_doc(doc, &lineas) + 1) as u32,
            nombre: String::new(),
            espacio: "default".into(),
            algoritmo: "RSA".into(),
            tamano: None,
            rotacion: None,
        };
        let mut en_metadata = false;
        let mut en_llave: Option<usize> = None;
        for l in doc {
            let t = l.trim();
            if t.starts_with('#') || t.is_empty() {
                continue;
            }
            if indentacion(l) == 0 {
                en_metadata = t == "metadata:";
            }
            if en_metadata && r.nombre.is_empty() && t.starts_with("name:") {
                r.nombre = valor(t);
            }
            if en_metadata && t.starts_with("namespace:") {
                r.espacio = valor(t);
            }
            if let Some(ind) = en_llave {
                if indentacion(l) <= ind {
                    en_llave = None;
                } else if t.starts_with("algorithm:") {
                    r.algoritmo = valor(t);
                } else if t.starts_with("size:") {
                    r.tamano = valor(t).parse().ok();
                } else if t.starts_with("rotationPolicy:") {
                    r.rotacion = Some(valor(t));
                }
            }
            if t == "privateKey:" {
                en_llave = Some(indentacion(l));
            }
        }
        salida.push(r);
    }
    salida
}

fn inicio_doc(doc: &[&str], todas: &[&str]) -> usize {
    let primero = doc.first().map(|l| l.as_ptr()).unwrap_or(std::ptr::null());
    todas
        .iter()
        .position(|l| l.as_ptr() == primero)
        .unwrap_or(0)
}

impl Escaner for EscanerCertManager {
    fn nombre(&self) -> &'static str {
        "cert-manager"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        matches!(a.extension.as_str(), "yaml" | "yml")
            && a.contiene(b"cert-manager.io/")
            && a.contiene(b"Certificate")
    }

    fn analizar(&self, a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
        let texto = a.texto().ok_or("el archivo no es texto UTF-8")?;
        let mut activos = Vec::new();
        for r in recursos(texto) {
            activos.extend(activos_certificado(
                &r.espacio,
                &r.nombre,
                &r.algoritmo,
                r.tamano,
                r.rotacion.as_deref(),
                a.ruta,
                Some(r.linea),
                &a.ruta_estable,
                c,
            ));
        }
        Ok(activos)
    }
}

/// Activos de un `Certificate` de cert-manager (algoritmo y llave futura).
/// Lo usan el escáner de manifiestos y la lectura de clústeres en vivo.
#[allow(clippy::too_many_arguments)]
pub fn activos_certificado(
    espacio: &str,
    nombre: &str,
    algoritmo: &str,
    tamano_declarado: Option<u32>,
    rotacion: Option<&str>,
    ruta: &str,
    linea: Option<u32>,
    ruta_estable: &str,
    c: &Conocimiento,
) -> Vec<Activo> {
    let (def, tamano) = match algoritmo.to_uppercase().as_str() {
        "ECDSA" => (
            c.por_id(match tamano_declarado.unwrap_or(256) {
                384 => "ec-p384",
                521 => "ec-p521",
                _ => "ec-p256",
            }),
            None,
        ),
        "ED25519" => (c.por_id("ed25519"), None),
        "RSA" | "" => (c.por_id("rsa"), Some(tamano_declarado.unwrap_or(2048))),
        _ => (None, tamano_declarado),
    };
    let alg = activo_algoritmo(
        def,
        algoritmo,
        tamano,
        CAPACIDAD,
        Some(Garantia::Autenticacion),
        ruta,
        linea,
    );
    let mut llave = Activo::nuevo(
        format!(
            "llave:cert-manager:{}",
            id_corto(&format!("{ruta_estable}#{espacio}/{nombre}"))
        ),
        format!("Llave de cert-manager {espacio}/{nombre} ({})", alg.nombre),
        Detalles::Material {
            tipo_material: "private-key".into(),
            tamano,
            formato: "cert-manager (spec.privateKey)".into(),
            protegido_por: Some("Secret de Kubernetes".into()),
            huella_sha256: None,
            identidad_llave: None,
        },
    )
    .con_contexto(CAPACIDAD, Garantia::Autenticacion)
    .con_ubicacion(ruta, linea);
    llave.relacionar("algorithm", &alg.referencia);
    llave.advertir(
        "cert-manager generará llaves con este algoritmo en cada renovación. Para migrar, cambie spec.privateKey.algorithm cuando su versión de cert-manager y su emisor admitan un algoritmo poscuántico.",
    );
    if rotacion != Some("Always") {
        llave.advertir(
            "spec.privateKey.rotationPolicy no es «Always»: la llave se reutiliza en las renovaciones, lo que alarga su exposición y retrasa la migración.",
        );
    }
    vec![alg, llave]
}

#[cfg(test)]
mod pruebas {
    use super::recursos;

    #[test]
    fn lee_privatekey() {
        let t = "apiVersion: cert-manager.io/v1\nkind: Certificate\nmetadata:\n  name: web\n  namespace: prod\nspec:\n  privateKey:\n    algorithm: ECDSA\n    size: 384\n    rotationPolicy: Always\n  dnsNames: [a]\n---\napiVersion: cert-manager.io/v1\nkind: Certificate\nmetadata:\n  name: api\nspec:\n  secretName: x\n";
        let r = recursos(t);
        assert_eq!(r.len(), 2);
        assert_eq!(
            (
                r[0].nombre.as_str(),
                r[0].espacio.as_str(),
                r[0].algoritmo.as_str(),
                r[0].tamano
            ),
            ("web", "prod", "ECDSA", Some(384))
        );
        assert_eq!(r[0].rotacion.as_deref(), Some("Always"));
        assert_eq!(
            (r[1].nombre.as_str(), r[1].algoritmo.as_str(), r[1].tamano),
            ("api", "RSA", None)
        );
        assert_eq!(r[1].linea, 13);
    }
}
