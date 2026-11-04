//! Importación de CBOM CycloneDX generados por otras herramientas (por
//! ejemplo, CBOMkit) o por versiones anteriores de Suaya.
//!
//! Cada componente se reconstruye como activo de Suaya y se vuelve a
//! clasificar con la base de conocimiento vigente, de modo que inventarios de
//! fuentes distintas se comparan con el mismo criterio. Los algoritmos se
//! reconocen por OID o por nombre; lo que no se reconoce entra como
//! desconocido, nunca se descarta.

use std::collections::HashMap;

use serde_json::Value;
use suaya_core::{Activo, Conocimiento, Detalles, Garantia};

use crate::codigo::CAPACIDAD as CAPACIDAD_CODIGO;
use crate::comun::{activo_algoritmo, id_corto};

/// Resultado de importar un CBOM.
#[derive(Debug, Default)]
pub struct Importado {
    pub activos: Vec<Activo>,
    pub avisos: Vec<String>,
    /// Herramienta que generó el CBOM, si lo declara.
    pub herramienta: String,
}

fn normalizar(t: &str) -> String {
    t.trim().to_lowercase().replace(['_', '.', ' '], "-")
}

/// Reconoce un algoritmo por su nombre: id de Suaya, tablas de nombres del
/// código, y como último recurso separando un tamaño final («RSA-2048»).
fn por_nombre<'a>(
    c: &'a Conocimiento,
    nombre: &str,
) -> (Option<&'a suaya_core::AlgoritmoDef>, Option<u32>) {
    let n = normalizar(nombre);
    let buscar = |x: &str| {
        c.por_id(x)
            .or_else(|| c.codigo.traducir("codigo", x).and_then(|id| c.por_id(id)))
            .or_else(|| {
                c.codigo
                    .traducir("java-cifrado", x)
                    .and_then(|id| c.por_id(id))
            })
            .or_else(|| c.codigo.traducir("tls", x).and_then(|id| c.por_id(id)))
            .or_else(|| c.algoritmos.iter().find(|d| normalizar(&d.nombre) == x))
    };
    if let Some(d) = buscar(&n) {
        return (Some(d), None);
    }
    if let Some((base, t)) = n.rsplit_once('-')
        && let Ok(t) = t.parse::<u32>()
        && let Some(d) = buscar(base)
    {
        return (Some(d), Some(t));
    }
    // «AES-256-GCM» y similares ya están en la base; «AES256-GCM» no.
    let sin_guiones = n.replace('-', "");
    (
        c.algoritmos
            .iter()
            .find(|d| d.id.replace('-', "") == sin_guiones),
        None,
    )
}

fn texto<'a>(v: &'a Value, puntero: &str) -> Option<&'a str> {
    v.pointer(puntero).and_then(Value::as_str)
}

/// Interpreta un purl sencillo: `pkg:<tipo>/<nombre>@<versión>`.
fn interpretar_purl(purl: &str) -> Option<(String, String, Option<String>)> {
    let resto = purl.strip_prefix("pkg:")?;
    let (tipo, resto) = resto.split_once('/')?;
    let resto = resto.split(['?', '#']).next().unwrap_or(resto);
    let (nombre, version) = match resto.rsplit_once('@') {
        Some((n, v)) => (n, Some(v.to_string())),
        None => (resto, None),
    };
    let nombre = nombre.replace("%40", "@");
    let nombre = if tipo == "maven" {
        nombre.replacen('/', ":", 1)
    } else {
        nombre
    };
    Some((tipo.to_string(), nombre, version))
}

/// Importa el texto JSON de un CBOM. `origen` identifica el archivo.
pub fn importar_cbom(
    texto_json: &str,
    origen: &str,
    c: &Conocimiento,
) -> Result<Importado, String> {
    let v: Value = serde_json::from_str(texto_json).map_err(|e| format!("JSON inválido: {e}"))?;
    if v.get("bomFormat").and_then(Value::as_str) != Some("CycloneDX") {
        return Err("el archivo no es un BOM CycloneDX".into());
    }
    let herramienta = v
        .pointer("/metadata/tools/components/0/name")
        .or_else(|| v.pointer("/metadata/tools/0/name"))
        .and_then(Value::as_str)
        .unwrap_or("herramienta no declarada")
        .to_string();
    let procedencia = format!("Importado del CBOM {origen} (generado por {herramienta}).");
    let componentes = v
        .get("components")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut resultado = Importado {
        herramienta: herramienta.clone(),
        ..Importado::default()
    };
    // Referencia original -> referencia de Suaya.
    let mut equivalentes: HashMap<String, String> = HashMap::new();
    let mut pendientes: Vec<(Activo, Vec<(String, String)>)> = Vec::new();

    for comp in &componentes {
        let original = comp.get("bom-ref").and_then(Value::as_str).unwrap_or("");
        let nombre = comp
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("sin nombre");
        let ubicaciones: Vec<(String, Option<u32>)> = comp
            .pointer("/evidence/occurrences")
            .and_then(Value::as_array)
            .map(|os| {
                os.iter()
                    .filter_map(|o| {
                        Some((
                            o.get("location")?.as_str()?.to_string(),
                            o.get("line").and_then(Value::as_u64).map(|l| l as u32),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let ubicaciones = if ubicaciones.is_empty() {
            vec![(format!("importado:{origen}"), None)]
        } else {
            ubicaciones
        };
        let tipo = comp.get("type").and_then(Value::as_str).unwrap_or("");
        let cp = comp.get("cryptoProperties").cloned().unwrap_or(Value::Null);
        let relaciones: Vec<(String, String)> = cp
            .as_object()
            .map(|o| {
                o.values()
                    .filter_map(|x| {
                        x.get("relatedCryptographicAssets")
                            .and_then(Value::as_array)
                    })
                    .flatten()
                    .filter_map(|r| {
                        Some((
                            r.get("type")?.as_str()?.to_string(),
                            r.get("ref")?.as_str()?.to_string(),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let capacidad = comp
            .get("properties")
            .and_then(Value::as_array)
            .and_then(|ps| {
                ps.iter()
                    .find(|p| p["name"] == "suaya:capacidad")
                    .and_then(|p| p["value"].as_str())
            })
            .filter(|cap| c.capacidad(cap).is_some())
            .unwrap_or("sin-clasificar")
            .to_string();

        let activo = if tipo == "library" {
            let Some((eco, paquete, version)) = comp
                .get("purl")
                .and_then(Value::as_str)
                .and_then(interpretar_purl)
            else {
                continue;
            };
            let eco = if eco == "generic" {
                "binario".to_string()
            } else {
                eco
            };
            let Some(def) = c.por_paquete(&eco, &paquete) else {
                continue;
            };
            let version = version.or_else(|| {
                comp.get("version")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            });
            let evaluacion = def.evaluar(version.as_deref(), &crate::bibliotecas::hoy());
            let mut a = Activo::nuevo(
                format!(
                    "biblioteca:{}:{}",
                    def.id,
                    version.as_deref().unwrap_or("sin-version")
                ),
                match &version {
                    Some(ver) => format!("{} {ver}", def.nombre),
                    None => def.nombre.clone(),
                },
                Detalles::Biblioteca {
                    biblioteca_id: def.id.clone(),
                    version,
                    purl: comp.get("purl").and_then(Value::as_str).map(str::to_string),
                },
            )
            .con_contexto(CAPACIDAD_CODIGO, Garantia::Confidencialidad);
            a.riesgo_fijado = Some(evaluacion.riesgo);
            for adv in evaluacion.advertencias {
                a.advertir(adv);
            }
            a
        } else if tipo == "cryptographic-asset" {
            match texto(&cp, "/assetType").unwrap_or("") {
                "algorithm" => {
                    let (def, tamano) = match texto(&cp, "/oid").and_then(|o| c.por_oid(o)) {
                        Some(d) => (Some(d), None),
                        None => por_nombre(c, nombre),
                    };
                    let tamano = tamano.or_else(|| {
                        texto(&cp, "/algorithmProperties/parameterSetIdentifier")
                            .and_then(|p| p.parse().ok())
                    });
                    let (ruta, linea) = ubicaciones[0].clone();
                    activo_algoritmo(def, nombre, tamano, &capacidad, None, &ruta, linea)
                }
                "certificate" => {
                    let p = &cp["certificateProperties"];
                    let s = |k: &str| p.get(k).and_then(Value::as_str).unwrap_or("").to_string();
                    let huella = p
                        .pointer("/fingerprint/content")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                        .unwrap_or_else(|| id_corto(&format!("{origen}{original}{nombre}")));
                    let no_despues = s("notValidAfter");
                    let vencido = !no_despues.is_empty()
                        && no_despues.as_str() < crate::bibliotecas::hoy().as_str();
                    Activo::nuevo(
                        format!("certificado:{}", &huella[..huella.len().min(16)]),
                        nombre,
                        Detalles::Certificado {
                            sujeto: s("subjectName"),
                            emisor: s("issuerName"),
                            serie: s("serialNumber"),
                            no_antes: s("notValidBefore"),
                            no_despues,
                            huella_sha256: huella,
                            extension_archivo: None,
                            vencido,
                            identidad_llave: None,
                        },
                    )
                    .con_contexto(&capacidad, Garantia::Autenticacion)
                }
                "related-crypto-material" => {
                    let p = &cp["relatedCryptoMaterialProperties"];
                    Activo::nuevo(
                        format!(
                            "llave:importada:{}",
                            id_corto(&format!("{origen}{original}{nombre}"))
                        ),
                        nombre,
                        Detalles::Material {
                            tipo_material: p
                                .get("type")
                                .and_then(Value::as_str)
                                .unwrap_or("unknown")
                                .to_string(),
                            tamano: p.get("size").and_then(Value::as_u64).map(|t| t as u32),
                            formato: p
                                .get("format")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_string(),
                            protegido_por: p
                                .pointer("/securedBy/mechanism")
                                .and_then(Value::as_str)
                                .map(str::to_string),
                            huella_sha256: None,
                            identidad_llave: None,
                        },
                    )
                    .con_contexto(&capacidad, Garantia::Autenticacion)
                }
                "protocol" => {
                    let p = &cp["protocolProperties"];
                    let versiones: Vec<String> = p
                        .get("version")
                        .and_then(Value::as_str)
                        .map(|v| v.split(',').map(|x| x.trim().to_string()).collect())
                        .unwrap_or_default();
                    let suites = p.get("cipherSuites").and_then(Value::as_array);
                    let cifrados: Vec<String> = suites
                        .map(|ss| {
                            ss.iter()
                                .filter_map(|x| x.get("name").and_then(Value::as_str))
                                .map(str::to_string)
                                .collect()
                        })
                        .unwrap_or_default();
                    let grupos: Vec<String> = suites
                        .map(|ss| {
                            ss.iter()
                                .filter_map(|x| x.get("tlsGroups").and_then(Value::as_array))
                                .flatten()
                                .filter_map(Value::as_str)
                                .map(str::to_string)
                                .collect()
                        })
                        .unwrap_or_default();
                    let tipo_protocolo = p
                        .get("type")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                        .to_string();
                    // «1.2» y «TLSv1.2» son la misma versión.
                    let versiones: Vec<String> = versiones
                        .into_iter()
                        .map(|v| {
                            if tipo_protocolo == "tls"
                                && v.starts_with(|ch: char| ch.is_ascii_digit())
                            {
                                format!("TLSv{v}")
                            } else {
                                v
                            }
                        })
                        .collect();
                    let mut protocolo = Activo::nuevo(
                        format!(
                            "protocolo:importado:{}",
                            id_corto(&format!("{origen}{original}{nombre}"))
                        ),
                        nombre,
                        Detalles::Protocolo {
                            tipo_protocolo: tipo_protocolo.clone(),
                            versiones: versiones.clone(),
                            grupos: grupos.clone(),
                            cifrados,
                        },
                    )
                    .con_contexto(&capacidad, Garantia::Confidencialidad);
                    if tipo_protocolo == "tls" && !versiones.is_empty() {
                        crate::config_tls::evaluar_tls(
                            &mut protocolo,
                            &versiones,
                            (!grupos.is_empty()).then_some(grupos.as_slice()),
                            "El CBOM importado no declara los grupos de intercambio de llaves: verifique el servicio.",
                            suaya_core::Riesgo::Desconocido,
                            c,
                        );
                    }
                    protocolo
                }
                otro => {
                    resultado.avisos.push(format!(
                        "{origen}: componente «{nombre}» con assetType no soportado ({otro})"
                    ));
                    continue;
                }
            }
        } else {
            continue;
        };
        let mut activo = activo;
        activo.ubicaciones.clear();
        for (ruta, linea) in &ubicaciones {
            activo.agregar_ubicacion(ruta, *linea);
        }
        activo.advertir(procedencia.clone());
        if !original.is_empty() {
            equivalentes.insert(original.to_string(), activo.referencia.clone());
        }
        pendientes.push((activo, relaciones));
    }

    for (mut activo, relaciones) in pendientes {
        for (tipo, original) in relaciones {
            if let Some(nuevo) = equivalentes.get(&original) {
                activo.relacionar(&tipo, nuevo);
            }
        }
        resultado.activos.push(activo);
    }
    Ok(resultado)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn purl_y_nombres() {
        assert_eq!(
            interpretar_purl("pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78?type=jar"),
            Some((
                "maven".into(),
                "org.bouncycastle:bcprov-jdk18on".into(),
                Some("1.78".into())
            ))
        );
        let c = Conocimiento::embebido();
        let (d, t) = por_nombre(&c, "RSA-2048");
        assert_eq!((d.map(|x| x.id.as_str()), t), (Some("rsa"), Some(2048)));
        assert_eq!(
            por_nombre(&c, "SHA256withRSA").0.unwrap().id,
            "rsassa-pkcs1-sha256"
        );
        assert_eq!(por_nombre(&c, "AES256-GCM").0.unwrap().id, "aes-256-gcm");
        assert_eq!(por_nombre(&c, "ML-KEM-768").0.unwrap().id, "ml-kem-768");
        assert!(por_nombre(&c, "Algoritmo inventado").0.is_none());
    }
}
