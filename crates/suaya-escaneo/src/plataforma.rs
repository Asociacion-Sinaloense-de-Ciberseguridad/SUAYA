//! Aseguramiento de plataforma: la criptografía que decide qué código arranca.
//!
//! - **Arranque seguro UEFI**: variables `PK`, `KEK`, `db`, `dbx` y `MokList`
//!   (archivos de `/sys/firmware/efi/efivars`, listas `.esl` y `.auth`):
//!   certificados X.509 y revocaciones por hash.
//! - **Firma de módulos del kernel de Linux**: `CONFIG_MODULE_SIG_*` en la
//!   configuración del kernel (`/boot/config-*`).
//! - **Llaves de MOK, IMA y EVM** guardadas como certificados DER.

use suaya_core::{Activo, Conocimiento, Detalles, Garantia, Riesgo};

use crate::Escaner;
use crate::comun::{Archivo, activo_algoritmo, id_corto, linea_de};
use crate::pem::certificado_en_contexto;

const CAPACIDAD: &str = "aseguramiento-plataforma";

/// EFI_CERT_X509_GUID (a5c059a1-94e4-4aa7-87b5-ab155c2bf072) en bytes.
const GUID_X509: [u8; 16] = [
    0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a, 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72,
];
/// EFI_CERT_SHA256_GUID (c1c41626-504c-4092-aca9-41f936934328) en bytes.
const GUID_SHA256: [u8; 16] = [
    0x26, 0x16, 0xc4, 0xc1, 0x4c, 0x50, 0x92, 0x40, 0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28,
];

/// Variable de arranque seguro según el nombre del archivo.
fn variable(nombre: &str) -> Option<&'static str> {
    let n = nombre.to_ascii_lowercase();
    let base = n.split(['-', '.']).next().unwrap_or("");
    Some(match base {
        "pk" => "PK",
        "kek" => "KEK",
        "db" => "db",
        "dbx" => "dbx",
        "moklist" | "moklistrt" => "MokList",
        _ => return None,
    })
}

/// Lista de firmas EFI: certificados y número de hashes SHA-256.
fn listas_de_firmas(mut b: &[u8]) -> (Vec<Vec<u8>>, usize) {
    let mut certificados = Vec::new();
    let mut hashes = 0usize;
    let mut vueltas = 0;
    while b.len() >= 28 && vueltas < 4096 {
        vueltas += 1;
        let tipo: [u8; 16] = b[..16].try_into().expect("16 bytes");
        let u = |p: usize| u32::from_le_bytes(b[p..p + 4].try_into().expect("4 bytes")) as usize;
        let (lista, cabecera, tam) = (u(16), u(20), u(24));
        if lista < 28 || lista > b.len() || tam < 16 || 28 + cabecera > lista {
            break;
        }
        let mut p = 28 + cabecera;
        while p + tam <= lista {
            let datos = &b[p + 16..p + tam];
            if tipo == GUID_X509 && datos.first() == Some(&0x30) {
                certificados.push(datos.to_vec());
            } else if tipo == GUID_SHA256 {
                hashes += 1;
            }
            p += tam;
        }
        b = &b[lista..];
    }
    (certificados, hashes)
}

/// Quita la cabecera de un archivo de efivars (4 bytes de atributos) o de una
/// variable autenticada `.auth` (marca de tiempo y WIN_CERTIFICATE).
fn cuerpo_de_variable<'a>(a: &Archivo<'a>) -> &'a [u8] {
    let b = a.contenido;
    if a.extension == "auth" && b.len() > 24 {
        let largo = u32::from_le_bytes(b[16..20].try_into().expect("4 bytes")) as usize;
        return b.get(16 + largo..).unwrap_or(&[]);
    }
    if a.extension == "esl" {
        return b;
    }
    // efivars: «db-d719b2cb-...» con 4 bytes de atributos al inicio.
    if a.nombre.matches('-').count() >= 5 && b.len() > 4 {
        return &b[4..];
    }
    b
}

pub struct EscanerArranqueSeguro;

impl Escaner for EscanerArranqueSeguro {
    fn nombre(&self) -> &'static str {
        "arranque seguro UEFI"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        let r = a.ruta.replace('\\', "/").to_ascii_lowercase();
        variable(&a.nombre).is_some()
            && (matches!(a.extension.as_str(), "esl" | "auth")
                || r.contains("efivars")
                || a.nombre.matches('-').count() >= 5)
    }

    fn analizar(&self, a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
        let var = variable(&a.nombre).unwrap_or("db");
        let (certificados, hashes) = listas_de_firmas(cuerpo_de_variable(a));
        let mut v = Activo::nuevo(
            format!("protocolo:arranque-seguro:{}", id_corto(&a.ruta_estable)),
            format!("Arranque seguro UEFI: variable {var}"),
            Detalles::Protocolo {
                tipo_protocolo: "uefi-secure-boot".into(),
                versiones: Vec::new(),
                grupos: Vec::new(),
                cifrados: Vec::new(),
            },
        )
        .con_contexto(CAPACIDAD, Garantia::Autenticacion)
        .con_ubicacion(a.ruta, None);
        let mut activos = Vec::new();
        let mut ms2011 = false;
        for der in &certificados {
            match certificado_en_contexto(der, a.ruta, CAPACIDAD, c) {
                Ok(xs) => {
                    for x in xs {
                        if let Detalles::Certificado { sujeto, .. } = &x.detalles {
                            v.relacionar("certificate", &x.referencia);
                            if sujeto.contains("Microsoft") && sujeto.contains("2011") {
                                ms2011 = true;
                            }
                        }
                        activos.push(x);
                    }
                }
                Err(e) => v.advertir(format!("Certificado ilegible en {var}: {e}.")),
            }
        }
        v.advertir(format!(
            "{var}: {} certificados y {hashes} hashes SHA-256.",
            certificados.len()
        ));
        if var == "dbx" {
            v.advertir("dbx lista binarios y certificados revocados: manténgala al día con las actualizaciones del fabricante.");
        }
        if ms2011 {
            v.advertir("Incluye autoridades de Microsoft de 2011, que vencen en 2026: sin las autoridades de 2023 en KEK y db, el equipo dejará de recibir componentes de arranque firmados nuevos.");
        }
        if certificados.is_empty() && hashes == 0 {
            v.advertir("La variable está vacía o no se pudo interpretar.");
            v.riesgo_fijado = Some(Riesgo::Desconocido);
        }
        activos.push(v);
        Ok(activos)
    }
}

pub struct EscanerConfigKernel;

impl Escaner for EscanerConfigKernel {
    fn nombre(&self) -> &'static str {
        "configuración del kernel"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        (a.nombre.starts_with("config-") || a.nombre == ".config" || a.nombre == "config")
            && a.contiene(b"CONFIG_MODULE_SIG")
    }

    fn analizar(&self, a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
        let texto = a.texto().ok_or("el archivo no es texto UTF-8")?;
        let mut p = Activo::nuevo(
            format!("protocolo:firma-modulos:{}", id_corto(&a.ruta_estable)),
            format!("Firma de módulos del kernel ({})", a.nombre),
            Detalles::Protocolo {
                tipo_protocolo: "linux-module-signing".into(),
                versiones: Vec::new(),
                grupos: Vec::new(),
                cifrados: Vec::new(),
            },
        )
        .con_contexto(CAPACIDAD, Garantia::Autenticacion)
        .con_ubicacion(a.ruta, None);
        let mut activos = Vec::new();
        let mut firma = false;
        let mut forzada = false;
        let mut desplazamiento = 0usize;
        for linea in texto.split_inclusive('\n') {
            let numero = Some(linea_de(a.contenido, desplazamiento));
            desplazamiento += linea.len();
            let l = linea.trim();
            match l {
                "CONFIG_MODULE_SIG=y" => firma = true,
                "CONFIG_MODULE_SIG_FORCE=y" => forzada = true,
                "CONFIG_MODULE_SIG_KEY_TYPE_RSA=y" => activos.push(activo_algoritmo(
                    c.por_id("rsa"),
                    "RSA",
                    None,
                    CAPACIDAD,
                    Some(Garantia::Autenticacion),
                    a.ruta,
                    numero,
                )),
                "CONFIG_MODULE_SIG_KEY_TYPE_ECDSA=y" => activos.push(activo_algoritmo(
                    c.por_id("ec"),
                    "ECDSA",
                    None,
                    CAPACIDAD,
                    Some(Garantia::Autenticacion),
                    a.ruta,
                    numero,
                )),
                _ => {}
            }
            if let Some(h) = l.strip_prefix("CONFIG_MODULE_SIG_HASH=") {
                let h = h.trim_matches('"').to_ascii_lowercase().replace('_', "-");
                let def = c.codigo.traducir("codigo", &h).and_then(|id| c.por_id(id));
                activos.push(activo_algoritmo(
                    def,
                    &h,
                    None,
                    CAPACIDAD,
                    Some(Garantia::Integridad),
                    a.ruta,
                    numero,
                ));
            }
        }
        if !firma {
            p.advertir("El kernel no exige ni verifica firmas de módulos (CONFIG_MODULE_SIG no está activo).");
            p.riesgo_fijado = Some(Riesgo::RotoClasico);
        } else if !forzada {
            p.advertir("CONFIG_MODULE_SIG_FORCE no está activo: el kernel carga módulos sin firma (con una advertencia) salvo que el modo lockdown lo impida.");
        }
        for x in &activos {
            p.relacionar("algorithm", &x.referencia);
        }
        activos.push(p);
        Ok(activos)
    }
}

pub struct EscanerLlavesPlataforma;

impl Escaner for EscanerLlavesPlataforma {
    fn nombre(&self) -> &'static str {
        "llaves de MOK, IMA y EVM"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        let r = a.ruta.replace('\\', "/").to_ascii_lowercase();
        matches!(a.extension.as_str(), "der" | "cer" | "crt")
            && a.contenido.first() == Some(&0x30)
            && (a.nombre.starts_with("mok")
                || a.nombre.starts_with("x509_ima")
                || a.nombre.starts_with("x509_evm")
                || r.contains("/etc/keys/")
                || r.contains("secureboot")
                || r.contains("/efi/"))
    }

    fn analizar(&self, a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
        certificado_en_contexto(a.contenido, a.ruta, CAPACIDAD, c)
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn lista_de_firmas_con_hashes() {
        let mut b = Vec::new();
        b.extend_from_slice(&GUID_SHA256);
        let tam = 16 + 32;
        b.extend((28u32 + 2 * tam as u32).to_le_bytes());
        b.extend(0u32.to_le_bytes());
        b.extend((tam as u32).to_le_bytes());
        b.extend(vec![0u8; 2 * tam]);
        let (certs, hashes) = listas_de_firmas(&b);
        assert_eq!((certs.len(), hashes), (0, 2));
        let mut ef = vec![7u8, 0, 0, 0];
        ef.extend(&b);
        let a = Archivo::nuevo(
            "efivars/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
            std::path::Path::new("dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f"),
            &ef,
            None,
        );
        assert!(EscanerArranqueSeguro.aplica(&a));
        let v = EscanerArranqueSeguro
            .analizar(&a, &Conocimiento::embebido())
            .unwrap();
        assert!(v[0].advertencias.iter().any(|w| w.contains("2 hashes")));
        // Una lista corrupta no hace fallar.
        assert_eq!(listas_de_firmas(&[0xFF; 40]).0.len(), 0);
    }

    #[test]
    fn kernel_sin_firma_forzada() {
        let t = b"CONFIG_MODULES=y\nCONFIG_MODULE_SIG=y\n# CONFIG_MODULE_SIG_FORCE is not set\nCONFIG_MODULE_SIG_SHA1=y\nCONFIG_MODULE_SIG_HASH=\"sha1\"\nCONFIG_MODULE_SIG_KEY_TYPE_RSA=y\n";
        let a = Archivo::nuevo(
            "boot/config-6.1.0",
            std::path::Path::new("config-6.1.0"),
            t,
            None,
        );
        assert!(EscanerConfigKernel.aplica(&a));
        let v = EscanerConfigKernel
            .analizar(&a, &Conocimiento::embebido())
            .unwrap();
        assert!(v.iter().any(|x| x.algoritmo_id() == Some("sha1")));
        assert!(
            v.last()
                .unwrap()
                .advertencias
                .iter()
                .any(|w| w.contains("FORCE"))
        );
    }
}
