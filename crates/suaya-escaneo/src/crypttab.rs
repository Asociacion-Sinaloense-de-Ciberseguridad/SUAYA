//! Escáner de `/etc/crypttab` (cifrado de volúmenes con dm-crypt/LUKS).
//!
//! El cifrado del volumen es simétrico (AES-XTS) y resiste a Grover con
//! llaves de 256 bits. El riesgo cuántico aparece en el desbloqueo: TPM2,
//! FIDO2 y PKCS#11 dependen de criptografía asimétrica.

use suaya_core::{Activo, Conocimiento, Detalles, Garantia};

use crate::Escaner;
use crate::comun::{Archivo, activo_algoritmo, id_corto, linea_de};

const CAPACIDAD: &str = "cifrado-volumen";

pub struct EscanerCrypttab;

impl Escaner for EscanerCrypttab {
    fn nombre(&self) -> &'static str {
        "cifrado de volumen"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        a.nombre == "crypttab"
    }

    fn analizar(&self, a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
        let texto = a.texto().ok_or("el archivo no es texto UTF-8")?;
        let mut activos = Vec::new();
        let mut desplazamiento = 0usize;

        for linea in texto.split_inclusive('\n') {
            let numero = Some(linea_de(a.contenido, desplazamiento));
            desplazamiento += linea.len();
            let l = linea.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            let campos: Vec<&str> = l.split_whitespace().collect();
            let nombre_volumen = campos[0];
            let opciones: Vec<&str> = campos
                .get(3)
                .map(|o| o.split(',').collect())
                .unwrap_or_default();
            let opcion = |clave: &str| {
                opciones
                    .iter()
                    .find_map(|o| o.strip_prefix(clave).and_then(|v| v.strip_prefix('=')))
            };

            let es_luks = opciones.contains(&"luks") || opcion("cipher").is_none();
            let cifrado = opcion("cipher").unwrap_or("aes-xts-plain64");
            let tamano: u32 = opcion("size").and_then(|s| s.parse().ok()).unwrap_or(512);

            // En XTS la llave se divide en dos: 512 bits equivalen a AES-256.
            let def = if cifrado.starts_with("aes-xts") {
                c.por_id(if tamano >= 512 {
                    "aes-256-xts"
                } else {
                    "aes-128-xts"
                })
            } else {
                c.por_alias("volumen", cifrado)
            };
            let alg = activo_algoritmo(
                def,
                cifrado,
                None,
                CAPACIDAD,
                Some(Garantia::Confidencialidad),
                a.ruta,
                numero,
            );

            let mut volumen = Activo::nuevo(
                format!(
                    "llave:volumen:{}",
                    id_corto(&format!("{}#{}", a.ruta_estable, nombre_volumen))
                ),
                format!("Llave del volumen {nombre_volumen}"),
                Detalles::Material {
                    tipo_material: "secret-key".into(),
                    tamano: Some(tamano),
                    formato: if es_luks {
                        "LUKS".into()
                    } else {
                        "dm-crypt plain".into()
                    },
                    protegido_por: campos
                        .get(2)
                        .filter(|k| **k != "none" && **k != "-")
                        .map(|k| format!("archivo de llave {k}")),
                    huella_sha256: None,
                    identidad_llave: None,
                },
            )
            .con_contexto(CAPACIDAD, Garantia::Confidencialidad)
            .con_ubicacion(a.ruta, numero);
            volumen.relacionar("algorithm", &alg.referencia);

            if es_luks && opcion("cipher").is_none() {
                volumen.advertir(
                    "El cifrador se define en la cabecera LUKS; se asume el predeterminado de LUKS2 (aes-xts-plain64, 512 bits). Confirmar con «cryptsetup luksDump».",
                );
            }
            if opciones.iter().any(|o| o.starts_with("tpm2-device")) {
                volumen.agregar_contexto(CAPACIDAD, Garantia::Autenticacion);
                volumen.advertir(
                    "Se desbloquea con TPM2, que usa criptografía asimétrica clásica; aún no hay TPM de hardware con PQC disponibles comercialmente.",
                );
            }
            if opciones.iter().any(|o| o.starts_with("fido2-device")) {
                volumen.agregar_contexto(CAPACIDAD, Garantia::Autenticacion);
                volumen.advertir("Se desbloquea con un token FIDO2 basado en curvas elípticas (vulnerable a Shor).");
            }
            if opciones.iter().any(|o| o.starts_with("pkcs11-uri")) {
                volumen.agregar_contexto(CAPACIDAD, Garantia::Autenticacion);
                volumen.advertir("Se desbloquea con un token PKCS#11; revisar el algoritmo de la llave del token.");
            }

            activos.push(alg);
            activos.push(volumen);
        }
        Ok(activos)
    }
}
