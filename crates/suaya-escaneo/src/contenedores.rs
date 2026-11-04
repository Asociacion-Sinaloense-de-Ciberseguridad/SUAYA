//! Contenedores de llaves protegidos por contraseña (PKCS#12, Java KeyStore).
//!
//! Suaya no intenta abrirlos ni adivinar contraseñas: los registra para que
//! no queden fuera del inventario y recomienda cómo inspeccionarlos.

use suaya_core::{Activo, Conocimiento, Detalles, Garantia, Riesgo};

use crate::Escaner;
use crate::comun::{Archivo, id_corto};

const EXTENSIONES: &[(&str, &str)] = &[
    ("p12", "PKCS#12"),
    ("pfx", "PKCS#12"),
    ("jks", "Java KeyStore"),
    ("jceks", "Java JCEKS"),
    ("bcfks", "BouncyCastle FIPS KeyStore"),
    ("keystore", "Java KeyStore"),
];

pub struct EscanerContenedores;

impl Escaner for EscanerContenedores {
    fn nombre(&self) -> &'static str {
        "contenedores de llaves"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        EXTENSIONES.iter().any(|(e, _)| *e == a.extension)
    }

    fn analizar(&self, a: &Archivo, _c: &Conocimiento) -> Result<Vec<Activo>, String> {
        let formato = EXTENSIONES
            .iter()
            .find(|(e, _)| *e == a.extension)
            .map(|(_, f)| *f)
            .unwrap_or("desconocido");
        let herramienta = if formato == "PKCS#12" {
            "openssl pkcs12 -info -nokeys"
        } else {
            "keytool -list -v"
        };
        let mut activo = Activo::nuevo(
            format!("llave:contenedor:{}", id_corto(&a.ruta_estable)),
            format!("Contenedor {formato}"),
            Detalles::Material {
                tipo_material: "key".into(),
                tamano: None,
                formato: formato.into(),
                protegido_por: Some("contraseña".into()),
                huella_sha256: None,
                identidad_llave: None,
            },
        )
        .con_contexto("sin-clasificar", Garantia::Autenticacion)
        .con_ubicacion(a.ruta, None);
        activo.riesgo_fijado = Some(Riesgo::Desconocido);
        activo.advertir(format!(
            "Contenedor protegido por contraseña: Suaya no lo abre. Inventaríe su contenido con «{herramienta}»."
        ));
        Ok(vec![activo])
    }
}
