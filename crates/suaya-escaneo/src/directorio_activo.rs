//! Active Directory a partir de exportaciones LDIF (`ldifde -f salida.ldf`).
//!
//! - **Plantillas de certificados de AD CS** (`pKICertificateTemplate`):
//!   algoritmo y tamaño mínimo de llave, vigencia, usos y la opción de que
//!   quien solicita elija el sujeto.
//! - **Tipos de cifrado de Kerberos** de cuentas de usuario y de equipo
//!   (`msDS-SupportedEncryptionTypes`, `userAccountControl`).
//!
//! Sin conectarse al dominio: se lee el archivo exportado.

use std::collections::BTreeMap;

use base64::Engine;
use suaya_core::{Activo, Conocimiento, Detalles, Garantia, Riesgo};

use crate::Escaner;
use crate::comun::{Archivo, activo_algoritmo, id_corto};

/// Registros de un LDIF: atributos (en minúsculas) con sus valores y la línea
/// donde empieza cada registro.
fn registros(texto: &str) -> Vec<(BTreeMap<String, Vec<String>>, u32)> {
    let mut v = Vec::new();
    let mut actual: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut inicio = 1u32;
    let mut previo: Option<(String, String)> = None;
    let cerrar = |actual: &mut BTreeMap<String, Vec<String>>,
                  previo: &mut Option<(String, String)>| {
        if let Some((k, val)) = previo.take() {
            actual.entry(k).or_default().push(val);
        }
    };
    for (i, linea) in texto.lines().enumerate() {
        if v.len() >= 200_000 {
            break;
        }
        if let Some(cont) = linea.strip_prefix(' ') {
            if let Some((_, val)) = &mut previo {
                val.push_str(cont);
            }
            continue;
        }
        cerrar(&mut actual, &mut previo);
        if linea.trim().is_empty() {
            if !actual.is_empty() {
                v.push((std::mem::take(&mut actual), inicio));
            }
            inicio = i as u32 + 2;
            continue;
        }
        if linea.starts_with('#') {
            continue;
        }
        if let Some((k, val)) = linea.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            let val = if let Some(b64) = val.strip_prefix(':') {
                // «atributo:: base64»: se conserva marcado para decodificarlo después.
                format!("\u{0}{}", b64.trim())
            } else {
                val.trim().to_string()
            };
            previo = Some((k, val));
        }
    }
    cerrar(&mut actual, &mut previo);
    if !actual.is_empty() {
        v.push((actual, inicio));
    }
    v
}

fn valor<'a>(r: &'a BTreeMap<String, Vec<String>>, k: &str) -> Option<&'a str> {
    r.get(k).and_then(|v| v.first()).map(String::as_str)
}

fn binario(v: &str) -> Option<Vec<u8>> {
    v.strip_prefix('\u{0}')
        .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
}

fn numero(v: Option<&str>) -> Option<i64> {
    let v = v?;
    match binario(v) {
        Some(b) => String::from_utf8(b).ok()?.trim().parse().ok(),
        None => v.trim().parse().ok(),
    }
}

/// Días de un intervalo FILETIME negativo (pKIExpirationPeriod).
fn dias_filetime(b: &[u8]) -> Option<i64> {
    let x = i64::from_le_bytes(b.try_into().ok()?);
    Some(-x / 864_000_000_000)
}

pub struct EscanerDirectorioActivo;

impl Escaner for EscanerDirectorioActivo {
    fn nombre(&self) -> &'static str {
        "Active Directory (LDIF)"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        matches!(a.extension.as_str(), "ldf" | "ldif")
            && (a.contiene(b"pKICertificateTemplate")
                || a.contiene(b"msDS-SupportedEncryptionTypes")
                || a.contiene(b"msds-supportedencryptiontypes"))
    }

    fn analizar(&self, a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
        let texto = a.texto().ok_or("el archivo no es texto UTF-8")?;
        let mut activos = Vec::new();
        let (mut cuentas, mut rc4, mut des, mut solo_des) = (0usize, 0usize, 0usize, 0usize);
        for (r, linea) in registros(texto) {
            let clases: Vec<String> = r
                .get("objectclass")
                .map(|v| v.iter().map(|x| x.to_ascii_lowercase()).collect())
                .unwrap_or_default();
            if clases.iter().any(|x| x == "pkicertificatetemplate") {
                activos.extend(plantilla(a, c, &r, linea));
                continue;
            }
            if let Some(tipos) = numero(valor(&r, "msds-supportedencryptiontypes")) {
                cuentas += 1;
                if tipos & 0x4 != 0 {
                    rc4 += 1;
                }
                if tipos & 0x3 != 0 {
                    des += 1;
                }
            }
            if numero(valor(&r, "useraccountcontrol")).is_some_and(|u| u & 0x0020_0000 != 0) {
                solo_des += 1;
            }
        }
        if cuentas > 0 || solo_des > 0 {
            let mut p = Activo::nuevo(
                format!("protocolo:kerberos:{}", id_corto(&format!("{}#ad", a.ruta_estable))),
                format!("Kerberos en Active Directory ({cuentas} cuentas con tipos de cifrado declarados)"),
                Detalles::Protocolo {
                    tipo_protocolo: "kerberos".into(),
                    versiones: Vec::new(),
                    grupos: Vec::new(),
                    cifrados: Vec::new(),
                },
            )
            .con_contexto("sin-clasificar", Garantia::Confidencialidad)
            .con_ubicacion(a.ruta, None);
            if rc4 > 0 {
                p.advertir(format!("{rc4} cuentas admiten RC4 en Kerberos: sus tickets se pueden descifrar fuera de línea (Kerberoasting)."));
                let x = activo_algoritmo(
                    c.por_id("rc4"),
                    "RC4",
                    None,
                    "sin-clasificar",
                    Some(Garantia::Confidencialidad),
                    a.ruta,
                    None,
                );
                p.relacionar("algorithm", &x.referencia);
                activos.push(x);
            }
            if des > 0 || solo_des > 0 {
                p.advertir(format!(
                    "{} cuentas admiten DES en Kerberos{}.",
                    des.max(solo_des),
                    if solo_des > 0 {
                        format!(" ({solo_des} con USE_DES_KEY_ONLY)")
                    } else {
                        String::new()
                    }
                ));
                let x = activo_algoritmo(
                    c.por_id("des"),
                    "DES",
                    None,
                    "sin-clasificar",
                    Some(Garantia::Confidencialidad),
                    a.ruta,
                    None,
                );
                p.relacionar("algorithm", &x.referencia);
                activos.push(x);
            }
            p.riesgo_fijado = Some(if rc4 > 0 || des > 0 || solo_des > 0 {
                Riesgo::RotoClasico
            } else {
                Riesgo::DebilitadoGrover
            });
            activos.push(p);
        }
        Ok(activos)
    }
}

fn plantilla(
    a: &Archivo,
    c: &Conocimiento,
    r: &BTreeMap<String, Vec<String>>,
    linea: u32,
) -> Vec<Activo> {
    let nombre = valor(r, "displayname")
        .or(valor(r, "cn"))
        .unwrap_or("sin nombre")
        .to_string();
    let usos: Vec<&str> = r
        .get("pkiextendedkeyusage")
        .map(|v| v.iter().map(String::as_str).collect())
        .unwrap_or_default();
    let capacidad = if usos.contains(&"1.3.6.1.5.5.7.3.3") {
        "firma-codigo"
    } else if usos.contains(&"1.3.6.1.5.5.7.3.1") {
        "servidores-web"
    } else {
        "pki-ca"
    };
    // Plantillas de versión 3 o 4 pueden declarar un algoritmo CNG.
    let politicas = r
        .get("mspki-ra-application-policies")
        .map(|v| v.join(" "))
        .unwrap_or_default()
        .to_ascii_uppercase();
    let tamano = numero(valor(r, "mspki-minimal-key-size")).map(|x| x as u32);
    let (id, tamano) = if politicas.contains("ECDH_P384") || politicas.contains("ECDSA_P384") {
        ("ec-p384", None)
    } else if politicas.contains("ECDH_P521") || politicas.contains("ECDSA_P521") {
        ("ec-p521", None)
    } else if politicas.contains("ECDH_P256") || politicas.contains("ECDSA_P256") {
        ("ec-p256", None)
    } else {
        ("rsa", tamano)
    };
    let alg = activo_algoritmo(
        c.por_id(id),
        id,
        tamano,
        capacidad,
        Some(Garantia::Autenticacion),
        a.ruta,
        Some(linea),
    );
    let mut m = Activo::nuevo(
        format!(
            "llave:plantilla-adcs:{}",
            id_corto(&format!("{}#{nombre}", a.ruta_estable))
        ),
        format!("Plantilla de certificado AD CS «{nombre}»"),
        Detalles::Material {
            tipo_material: "private-key".into(),
            tamano,
            formato: "plantilla de AD CS".into(),
            protegido_por: None,
            huella_sha256: None,
            identidad_llave: None,
        },
    )
    .con_contexto(capacidad, Garantia::Autenticacion)
    .con_ubicacion(a.ruta, Some(linea));
    m.relacionar("algorithm", &alg.referencia);
    m.advertir("Plantilla que emitirá llaves con este algoritmo en cada inscripción o renovación.");
    if let Some(dias) = valor(r, "pkiexpirationperiod")
        .and_then(binario)
        .and_then(|b| dias_filetime(&b))
    {
        m.advertir(format!("Vigencia de los certificados: {dias} días."));
        if capacidad == "servidores-web" && dias > 398 {
            m.advertir("La vigencia supera la de los certificados públicos (200 días desde marzo de 2026): planifique renovaciones automáticas.");
        }
    }
    let autenticacion_cliente = usos.contains(&"1.3.6.1.5.5.7.3.2")
        || usos.contains(&"1.3.6.1.4.1.311.20.2.2")
        || usos.contains(&"2.5.29.37.0");
    if numero(valor(r, "mspki-certificate-name-flag")).is_some_and(|f| f & 1 != 0)
        && autenticacion_cliente
    {
        m.advertir("Quien solicita elige el sujeto y el certificado sirve para autenticar clientes: si usuarios sin privilegios pueden inscribirse, permite suplantar cuentas (ESC1). Revise los permisos de inscripción.");
        m.riesgo_fijado = Some(Riesgo::Desconocido);
    }
    vec![alg, m]
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn plantillas_y_kerberos() {
        let periodo = base64::engine::general_purpose::STANDARD
            .encode((-(730i64 * 864_000_000_000)).to_le_bytes());
        let t = format!(
            "dn: CN=WebServer,CN=Certificate Templates,DC=ejemplo,DC=mx\nobjectClass: top\nobjectClass: pKICertificateTemplate\ncn: WebServer\ndisplayName: Servidor web\nmsPKI-Minimal-Key-Size: 1024\npKIExtendedKeyUsage: 1.3.6.1.5.5.7.3.1\npKIExpirationPeriod:: {periodo}\n\ndn: CN=Usuario,CN=Certificate Templates,DC=ejemplo,DC=mx\nobjectClass: pKICertificateTemplate\ncn: Usuario\nmsPKI-Minimal-Key-Size: 2048\nmsPKI-Certificate-Name-Flag: 1\npKIExtendedKeyUsage: 1.3.6.1.5.5.7.3.2\n\ndn: CN=srv01,OU=Equipos,DC=ejemplo,DC=mx\nobjectClass: computer\nmsDS-SupportedEncryptionTypes: 28\n\ndn: CN=legado,OU=Usuarios,DC=ejemplo,DC=mx\nobjectClass: user\nuserAccountControl: 2163200\n"
        );
        let a = Archivo::nuevo("ad.ldf", std::path::Path::new("ad.ldf"), t.as_bytes(), None);
        assert!(EscanerDirectorioActivo.aplica(&a));
        let v = EscanerDirectorioActivo
            .analizar(&a, &Conocimiento::embebido())
            .unwrap();
        assert!(v.iter().any(|x| x.referencia == "algoritmo:rsa-1024"));
        let web = v
            .iter()
            .find(|x| x.nombre.contains("Servidor web"))
            .unwrap();
        assert!(web.advertencias.iter().any(|w| w.contains("730 días")));
        let usuario = v.iter().find(|x| x.nombre.contains("Usuario")).unwrap();
        assert!(usuario.advertencias.iter().any(|w| w.contains("ESC1")));
        let k = v
            .iter()
            .find(|x| x.referencia.starts_with("protocolo:kerberos"))
            .unwrap();
        assert_eq!(k.riesgo_fijado, Some(Riesgo::RotoClasico));
        assert!(
            k.advertencias
                .iter()
                .any(|w| w.contains("1 cuentas admiten RC4"))
        );
        assert!(
            k.advertencias
                .iter()
                .any(|w| w.contains("USE_DES_KEY_ONLY"))
        );
    }
}
