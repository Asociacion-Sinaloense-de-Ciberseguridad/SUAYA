//! Exportación a CBOM CycloneDX 1.7.

use serde_json::{Map, Value, json};
use suaya_core::idioma::traducir;
use suaya_core::{Activo, Conocimiento, Detalles, Inventario, etiqueta_prioridad};

use crate::VERSION_CYCLONEDX;

/// Modos válidos en el enum `mode` de CycloneDX 1.7.
const MODOS: &[&str] = &["cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr"];

/// Valores de `protocolProperties.type` en CycloneDX 1.7. Los demás
/// protocolos (Kerberos, NTLM, DNSSEC, OpenID Connect...) se exportan como
/// `other` y conservan su tipo en la propiedad `suaya:tipo-protocolo`.
const TIPOS_PROTOCOLO: &[&str] = &[
    "tls",
    "ssh",
    "ipsec",
    "ike",
    "sstp",
    "wpa",
    "dtls",
    "quic",
    "eap-aka",
    "eap-aka-prime",
    "prins",
    "5g-aka",
    "other",
    "unknown",
];

#[derive(Debug, Clone, Default)]
pub struct OpcionesCbom {
    /// Nombre del sistema escaneado (componente principal del CBOM).
    pub nombre_sistema: Option<String>,
    /// Rutas que se escanearon.
    pub raices: Vec<String>,
    /// Perfil de política evaluado: (nombre, referencia).
    pub perfil: Option<(String, String)>,
    /// Perfil y año para declarar el cumplimiento como atestación CycloneDX
    /// (CDXA: `definitions.standards` y `declarations`).
    pub declaraciones: Option<(suaya_core::Perfil, i32)>,
}

/// Genera el documento CBOM.
pub fn generar(inv: &Inventario, c: &Conocimiento, op: &OpcionesCbom) -> Value {
    let ahora = time::OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    let marca = ahora
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();

    let componentes: Vec<Value> = inv.activos.iter().map(|a| componente(a, c)).collect();
    let dependencias: Vec<Value> = inv
        .activos
        .iter()
        .filter(|a| !a.relaciones.is_empty())
        .map(|a| {
            let mut refs: Vec<&str> = a.relaciones.iter().map(|r| r.referencia.as_str()).collect();
            refs.sort();
            refs.dedup();
            json!({ "ref": a.referencia, "dependsOn": refs })
        })
        .collect();

    let mut propiedades = vec![
        prop("suaya:base-conocimiento", &traducir(&c.procedencia())),
        prop("suaya:version-algoritmos", &c.meta_algoritmos.version),
        prop("suaya:version-madurez", &c.meta_madurez.version),
        prop("suaya:idioma", suaya_core::idioma::actual().codigo()),
    ];
    if let Some(f) = &c.meta_madurez.fuente {
        propiedades.push(prop("suaya:fuente-madurez", f));
    }
    for r in &op.raices {
        propiedades.push(prop("suaya:ruta-escaneada", r));
    }
    if let Some((nombre, referencia)) = &op.perfil {
        propiedades.push(prop("suaya:perfil-politica", &traducir(nombre)));
        propiedades.push(prop("suaya:perfil-referencia", &traducir(referencia)));
    }

    let mut documento = json!({
        "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": VERSION_CYCLONEDX,
        "serialNumber": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "version": 1,
        "metadata": {
            "timestamp": marca,
            "lifecycles": [{ "phase": "operations" }],
            "tools": {
                "components": [{
                    "type": "application",
                    "name": "Suaya",
                    "version": suaya_core::VERSION,
                    "description": "Inventario criptográfico abierto con evaluación de preparación poscuántica",
                    "licenses": [{ "license": { "id": "Apache-2.0" } }]
                }]
            },
            "component": {
                "type": "application",
                "bom-ref": "sistema",
                "name": op.nombre_sistema.clone().unwrap_or_else(|| "Sistema escaneado".into())
            },
            "properties": propiedades
        },
        "components": componentes,
        "dependencies": dependencias
    });
    if let Some((perfil, anio)) = &op.declaraciones {
        let (definiciones, declaraciones) = declaraciones(inv, perfil, *anio, &marca);
        documento["definitions"] = definiciones;
        documento["declarations"] = declaraciones;
    }
    documento
}

/// Atestación del cumplimiento con un perfil (CycloneDX Attestations, CDXA).
///
/// Cada regla del perfil es un requisito del estándar. Para cada una, una
/// afirmación sobre el sistema cita como evidencia los activos que la regla
/// alcanzó; la conformidad es la fracción de esos activos que la cumple.
fn declaraciones(
    inv: &Inventario,
    perfil: &suaya_core::Perfil,
    anio: i32,
    marca: &str,
) -> (Value, Value) {
    use suaya_core::EstadoCumplimiento as E;
    let id = &perfil.perfil.id;
    let mut requisitos = Vec::new();
    let mut afirmaciones = Vec::new();
    let mut evidencias = Vec::new();
    let mut mapa = Vec::new();
    for (i, regla) in perfil.reglas.iter().enumerate() {
        let n = i + 1;
        let alcanzados: Vec<&suaya_core::Activo> = inv
            .activos
            .iter()
            .filter(|a| a.cumplimiento.as_ref().is_some_and(|c| c.regla == Some(i)))
            .collect();
        let cumplen = alcanzados
            .iter()
            .filter(|a| {
                a.cumplimiento
                    .as_ref()
                    .is_some_and(|c| c.estado == regla.estado || regla.estado == E::NoConforme)
            })
            .count();
        let total = alcanzados.len();
        // Una regla que prohíbe se cumple cuando no alcanza ningún activo.
        let puntaje = match (regla.estado, total) {
            (_, 0) => 1.0,
            (E::NoConforme, _) => 0.0,
            _ => cumplen as f64 / total as f64,
        };
        let descripcion = regla.describir();
        let titulo = regla
            .nota
            .clone()
            .map(|n| suaya_core::idioma::traducir(&n).into_owned())
            .unwrap_or_else(|| descripcion.clone());
        let ref_requisito = format!("requisito-{id}-{n}");
        let ref_afirmacion = format!("afirmacion-{id}-{n}");
        let ref_evidencia = format!("evidencia-{id}-{n}");
        requisitos.push(json!({
            "bom-ref": ref_requisito,
            "identifier": format!("R{n}"),
            "title": titulo,
            "text": descripcion,
        }));
        let estado = regla.estado.etiqueta();
        afirmaciones.push(json!({
            "bom-ref": ref_afirmacion,
            "target": "sistema",
            "predicate": suaya_core::t!(
                "La regla R{n} alcanza {total} activos del sistema; {cumplen} quedan en el estado «{estado}».",
                "Rule R{n} covers {total} assets of the system; {cumplen} end up in the \"{estado}\" status."
            ),
            "evidence": [ref_evidencia],
        }));
        let referencias: Vec<&str> = alcanzados.iter().map(|a| a.referencia.as_str()).collect();
        evidencias.push(json!({
            "bom-ref": ref_evidencia,
            "propertyName": "suaya:cumplimiento",
            "description": suaya_core::t!(
                "Activos del CBOM alcanzados por la regla R{n}.",
                "CBOM assets covered by rule R{n}."
            ),
            "data": [{
                "name": "activos",
                "contents": { "attachment": {
                    "contentType": "application/json",
                    "content": serde_json::to_string(&referencias).unwrap_or_default()
                }}
            }],
            "created": marca,
        }));
        mapa.push(json!({
            "requirement": ref_requisito,
            "claims": [ref_afirmacion],
            "conformance": {
                "score": (puntaje * 1000.0).round() / 1000.0,
                "rationale": if total == 0 {
                    suaya_core::t!("Ningún activo del inventario cae en esta regla.", "No inventoried asset falls under this rule.")
                } else {
                    suaya_core::t!("{cumplen} de {total} activos cumplen lo que exige la regla.", "{cumplen} of {total} assets meet what the rule requires.")
                },
                "mitigationStrategies": []
            },
            "confidence": {
                "score": 0.8,
                "rationale": suaya_core::t!(
                    "Inventario automático: refleja lo que Suaya observó en archivos, código y servicios, no lo que no pudo alcanzar.",
                    "Automated inventory: it reflects what Suaya observed in files, code and services, not what it could not reach."
                )
            }
        }));
    }
    let definiciones = json!({
        "standards": [{
            "bom-ref": format!("estandar-{id}"),
            "name": perfil.perfil.nombre,
            "version": anio.to_string(),
            "description": suaya_core::t!(
                "Perfil de política de Suaya basado en: {}",
                "Suaya policy profile based on: {}",
                perfil.perfil.referencia
            ),
            "requirements": requisitos,
        }]
    });
    let declaraciones = json!({
        "assessors": [{
            "bom-ref": "evaluador-suaya",
            "thirdParty": false,
            "organization": { "name": suaya_core::t!("Suaya (evaluación automatizada)", "Suaya (automated assessment)") }
        }],
        "attestations": [{
            "summary": suaya_core::t!(
                "Evaluación automática del cumplimiento con {} para {anio}.",
                "Automated assessment of compliance with {} for {anio}.",
                perfil.perfil.nombre
            ),
            "assessor": "evaluador-suaya",
            "map": mapa,
        }],
        "claims": afirmaciones,
        "evidence": evidencias,
    });
    (definiciones, declaraciones)
}

fn prop(nombre: &str, valor: &str) -> Value {
    json!({ "name": nombre, "value": valor })
}

fn componente(a: &Activo, c: &Conocimiento) -> Value {
    let mut comp = Map::new();
    if let Detalles::Biblioteca { version, purl, .. } = &a.detalles {
        // Una biblioteca es un componente de software, no un activo
        // criptográfico: CycloneDX la describe con su versión y su purl.
        comp.insert("type".into(), json!("library"));
        comp.insert("bom-ref".into(), json!(a.referencia));
        comp.insert("name".into(), json!(traducir(&a.nombre)));
        if let Some(v) = version {
            comp.insert("version".into(), json!(v));
        }
        if let Some(p) = purl {
            comp.insert("purl".into(), json!(p));
        }
    } else {
        comp.insert("type".into(), json!("cryptographic-asset"));
        comp.insert("bom-ref".into(), json!(a.referencia));
        comp.insert("name".into(), json!(traducir(&a.nombre)));
        comp.insert("cryptoProperties".into(), propiedades_cripto(a, c));
    }

    if !a.ubicaciones.is_empty() {
        let ocurrencias: Vec<Value> = a
            .ubicaciones
            .iter()
            .map(|u| {
                let mut o = Map::new();
                o.insert("location".into(), json!(u.ruta));
                if let Some(l) = u.linea {
                    o.insert("line".into(), json!(l));
                }
                Value::Object(o)
            })
            .collect();
        comp.insert("evidence".into(), json!({ "occurrences": ocurrencias }));
    }

    let mut props = Vec::new();
    if let Some(cl) = &a.clasificacion {
        props.push(prop("suaya:riesgo", cl.riesgo.como_texto()));
        props.push(prop("suaya:accion", cl.accion.como_texto()));
        props.push(prop("suaya:prioridad", &cl.prioridad.to_string()));
        props.push(prop(
            "suaya:prioridad-etiqueta",
            etiqueta_prioridad(cl.prioridad),
        ));
        props.push(prop("suaya:capacidad", &cl.capacidad));
        props.push(prop("suaya:garantia", cl.garantia.como_texto()));
        props.push(prop("suaya:madurez-ecosistema", cl.madurez.como_texto()));
        props.push(prop("suaya:justificacion", &traducir(&cl.justificacion)));
    }
    if let Detalles::Biblioteca { biblioteca_id, .. } = &a.detalles {
        props.push(prop("suaya:biblioteca", biblioteca_id));
    }
    if let Detalles::Protocolo { tipo_protocolo, .. } = &a.detalles
        && !TIPOS_PROTOCOLO.contains(&tipo_protocolo.as_str())
    {
        props.push(prop("suaya:tipo-protocolo", tipo_protocolo));
    }
    if let Detalles::Certificado {
        identidad_llave: Some(id),
        ..
    }
    | Detalles::Material {
        identidad_llave: Some(id),
        ..
    } = &a.detalles
    {
        props.push(prop("suaya:identidad-llave", id));
    }
    for ctx in &a.contextos {
        props.push(prop(
            "suaya:contexto",
            &format!("{}/{}", ctx.capacidad, ctx.garantia.como_texto()),
        ));
    }
    for adv in &a.advertencias {
        props.push(prop("suaya:advertencia", &traducir(adv)));
    }
    if let Some(def) = a.algoritmo_id().and_then(|id| c.por_id(id))
        && let Some(n) = &def.nota
    {
        props.push(prop("suaya:nota", &traducir(n)));
    }
    if let Some(cu) = &a.cumplimiento {
        props.push(prop("suaya:perfil", &cu.perfil));
        props.push(prop("suaya:cumplimiento", cu.estado.como_texto()));
        if let Some(p) = cu.prohibicion {
            props.push(prop("suaya:plazo", &p.to_string()));
        }
        if let Some(r) = cu.retiro {
            props.push(prop("suaya:retiro", &r.to_string()));
        }
        if !cu.nota.is_empty() {
            props.push(prop("suaya:cumplimiento-nota", &traducir(&cu.nota)));
        }
    }
    if let Some(o) = &a.organizacion {
        for x in &o.sistemas {
            props.push(prop("suaya:sistema", x));
        }
        for x in &o.responsables {
            props.push(prop("suaya:responsable", x));
        }
        if let Some(x) = o.criticidad {
            props.push(prop("suaya:criticidad", x.como_texto()));
        }
        if let Some(x) = o.exposicion {
            props.push(prop("suaya:exposicion", x.como_texto()));
        }
        if let Some(m) = &o.mosca {
            props.push(prop("suaya:mosca-vida-datos", &m.vida_datos.to_string()));
            props.push(prop("suaya:mosca-migracion", &m.migracion.to_string()));
            props.push(prop("suaya:mosca-horizonte", &m.horizonte.to_string()));
            props.push(prop("suaya:mosca-holgura", &m.holgura.to_string()));
        }
        if let Some(e) = &o.excepcion {
            props.push(prop("suaya:excepcion", &e.id));
            props.push(prop("suaya:excepcion-vence", &e.vence));
            props.push(prop(
                "suaya:excepcion-vigente",
                if e.vigente { "true" } else { "false" },
            ));
            props.push(prop("suaya:excepcion-justificacion", &e.justificacion));
            if let Some(x) = &e.aprobada_por {
                props.push(prop("suaya:excepcion-aprobada-por", x));
            }
        }
    }
    if !props.is_empty() {
        comp.insert("properties".into(), Value::Array(props));
    }
    Value::Object(comp)
}

fn relacionados(a: &Activo) -> Value {
    Value::Array(
        a.relaciones
            .iter()
            .map(|r| json!({ "type": r.tipo, "ref": r.referencia }))
            .collect(),
    )
}

/// Seguridad clásica aproximada de RSA según NIST SP 800-57.
fn seguridad_clasica_rsa(bits: u32) -> u32 {
    match bits {
        0..=1023 => 0,
        1024..=2047 => 80,
        2048..=3071 => 112,
        3072..=7679 => 128,
        7680..=15359 => 192,
        _ => 256,
    }
}

fn propiedades_cripto(a: &Activo, c: &Conocimiento) -> Value {
    match &a.detalles {
        Detalles::Algoritmo {
            algoritmo_id,
            tamano_llave,
        } => {
            let def = algoritmo_id.as_deref().and_then(|id| c.por_id(id));
            let mut p = Map::new();
            match def {
                Some(d) => {
                    p.insert("primitive".into(), json!(d.primitiva));
                    if let Some(f) = &d.familia {
                        p.insert("algorithmFamily".into(), json!(f));
                    }
                    let conjunto = d
                        .conjunto_parametros
                        .clone()
                        .or_else(|| tamano_llave.map(|t| t.to_string()));
                    if let Some(cp) = conjunto {
                        p.insert("parameterSetIdentifier".into(), json!(cp));
                    }
                    if let Some(cv) = &d.curva {
                        p.insert("ellipticCurve".into(), json!(cv));
                    }
                    if let Some(m) = d.modo.as_deref().filter(|m| MODOS.contains(m)) {
                        p.insert("mode".into(), json!(m));
                    }
                    if !d.funciones.is_empty() {
                        p.insert("cryptoFunctions".into(), json!(d.funciones));
                    }
                    let clasica = match (d.id.as_str(), tamano_llave) {
                        ("rsa", Some(t)) => Some(seguridad_clasica_rsa(*t)),
                        _ => d.nivel_clasico,
                    };
                    if let Some(n) = clasica {
                        p.insert("classicalSecurityLevel".into(), json!(n));
                    }
                    if let Some(n) = d.nivel_nist_cuantico {
                        p.insert("nistQuantumSecurityLevel".into(), json!(n));
                    }
                }
                None => {
                    p.insert("primitive".into(), json!("unknown"));
                    if let Some(t) = tamano_llave {
                        p.insert("parameterSetIdentifier".into(), json!(t.to_string()));
                    }
                }
            }
            p.insert("executionEnvironment".into(), json!("unknown"));
            p.insert("implementationPlatform".into(), json!("unknown"));

            let mut cp = Map::new();
            cp.insert("assetType".into(), json!("algorithm"));
            cp.insert("algorithmProperties".into(), Value::Object(p));
            if let Some(oid) = def.and_then(|d| d.oids.first()) {
                cp.insert("oid".into(), json!(oid));
            }
            Value::Object(cp)
        }
        Detalles::Certificado {
            sujeto,
            emisor,
            serie,
            no_antes,
            no_despues,
            huella_sha256,
            extension_archivo,
            ..
        } => {
            let mut p = Map::new();
            p.insert("serialNumber".into(), json!(serie));
            p.insert("subjectName".into(), json!(sujeto));
            p.insert("issuerName".into(), json!(emisor));
            p.insert("notValidBefore".into(), json!(no_antes));
            p.insert("notValidAfter".into(), json!(no_despues));
            p.insert("certificateFormat".into(), json!("X.509"));
            if let Some(e) = extension_archivo {
                p.insert("certificateFileExtension".into(), json!(e));
            }
            p.insert(
                "fingerprint".into(),
                json!({ "alg": "SHA-256", "content": huella_sha256 }),
            );
            p.insert("relatedCryptographicAssets".into(), relacionados(a));
            json!({ "assetType": "certificate", "certificateProperties": p })
        }
        Detalles::Material {
            tipo_material,
            tamano,
            formato,
            protegido_por,
            huella_sha256,
            ..
        } => {
            let mut p = Map::new();
            p.insert("type".into(), json!(tipo_material));
            if let Some(t) = tamano {
                p.insert("size".into(), json!(t));
            }
            p.insert("format".into(), json!(formato));
            if let Some(h) = huella_sha256 {
                p.insert(
                    "fingerprint".into(),
                    json!({ "alg": "SHA-256", "content": h }),
                );
            }
            if let Some(pp) = protegido_por {
                p.insert("securedBy".into(), json!({ "mechanism": pp }));
            }
            p.insert("relatedCryptographicAssets".into(), relacionados(a));
            json!({ "assetType": "related-crypto-material", "relatedCryptoMaterialProperties": p })
        }
        Detalles::Protocolo {
            tipo_protocolo,
            versiones,
            grupos,
            cifrados,
        } => {
            let mut p = Map::new();
            let tipo = if TIPOS_PROTOCOLO.contains(&tipo_protocolo.as_str()) {
                tipo_protocolo.as_str()
            } else {
                "other"
            };
            p.insert("type".into(), json!(tipo));
            if !versiones.is_empty() {
                p.insert("version".into(), json!(versiones.join(", ")));
            }
            let mut suites: Vec<Value> = Vec::new();
            if tipo_protocolo == "tls" {
                let mut s = Map::new();
                s.insert(
                    "name".into(),
                    json!(if cifrados.is_empty() {
                        "predeterminados de la biblioteca TLS".to_string()
                    } else {
                        cifrados.join(" ")
                    }),
                );
                if !grupos.is_empty() {
                    s.insert("tlsGroups".into(), json!(grupos));
                }
                suites.push(Value::Object(s));
            } else {
                suites.extend(cifrados.iter().map(|x| json!({ "name": x })));
            }
            if !suites.is_empty() {
                p.insert("cipherSuites".into(), Value::Array(suites));
            }
            p.insert("relatedCryptographicAssets".into(), relacionados(a));
            json!({ "assetType": "protocol", "protocolProperties": p })
        }
        // Las bibliotecas no llevan cryptoProperties (ver `componente`).
        Detalles::Biblioteca { .. } => json!({ "assetType": "other" }),
    }
}
