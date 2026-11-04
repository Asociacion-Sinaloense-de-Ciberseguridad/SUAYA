//! Inventario de un clúster de Kubernetes en vivo, por su API y solo con
//! lecturas (GET): Secrets, Ingress y, si existe, Certificates de cert-manager.
//!
//! La conexión se toma del kubeconfig (contexto actual o el indicado), con
//! token, certificado de cliente o un complemento `exec` (EKS, GKE, AKS), o
//! de la cuenta de servicio cuando Suaya corre dentro del clúster. El
//! contenido de los Secrets solo se decodifica en memoria para analizarlo.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine;
use serde_json::Value;
use suaya_core::{Activo, Conocimiento, Detalles, Garantia};
use suaya_escaneo::Archivo;
use suaya_escaneo::api::{activos_certificado, analizar_texto_pem};
use yaml_rust2::{Yaml, YamlLoader};

use crate::http::{ConfianzaTls, Credenciales, Servidor, get};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const CUENTA_DE_SERVICIO: &str = "/var/run/secrets/kubernetes.io/serviceaccount";

/// Conexión resuelta a un clúster.
#[derive(Clone)]
pub struct Conexion {
    pub contexto: String,
    pub servidor: Servidor,
    pub credenciales: Credenciales,
    pub confianza: ConfianzaTls,
}

/// Ruta del kubeconfig: la indicada, la primera de `$KUBECONFIG` o `~/.kube/config`.
pub fn ruta_kubeconfig(indicada: Option<&Path>) -> Option<PathBuf> {
    if let Some(r) = indicada {
        return Some(r.to_path_buf());
    }
    if let Ok(v) = std::env::var("KUBECONFIG") {
        let separador = if cfg!(windows) { ';' } else { ':' };
        if let Some(primera) = v.split(separador).find(|s| !s.is_empty()) {
            return Some(PathBuf::from(primera));
        }
    }
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".kube").join("config"))
}

fn texto(y: &Yaml) -> Option<String> {
    y.as_str().map(str::to_string)
}

fn buscar_por_nombre<'a>(lista: &'a Yaml, nombre: &str, campo: &str) -> Option<&'a Yaml> {
    lista
        .as_vec()?
        .iter()
        .find(|e| e["name"].as_str() == Some(nombre))
        .map(|e| &e[campo])
}

/// Lee un dato `*-data` (base64) o un archivo relativo al kubeconfig.
fn dato_o_archivo(nodo: &Yaml, clave: &str, base: &Path) -> Result<Option<Vec<u8>>, String> {
    if let Some(d) = nodo[format!("{clave}-data").as_str()].as_str() {
        return B64
            .decode(d.trim())
            .map(Some)
            .map_err(|e| format!("{clave}-data inválido: {e}"));
    }
    if let Some(r) = nodo[clave].as_str() {
        let ruta = if Path::new(r).is_absolute() {
            PathBuf::from(r)
        } else {
            base.join(r)
        };
        return std::fs::read(&ruta)
            .map(Some)
            .map_err(|e| format!("no se pudo leer {}: {e}", ruta.display()));
    }
    Ok(None)
}

/// Ejecuta el complemento `exec` del kubeconfig y devuelve sus credenciales.
fn credenciales_exec(exec: &Yaml) -> Result<Credenciales, String> {
    let comando = exec["command"].as_str().ok_or("exec sin command")?;
    let mut proceso = std::process::Command::new(comando);
    if let Some(args) = exec["args"].as_vec() {
        proceso.args(args.iter().filter_map(|a| a.as_str()));
    }
    if let Some(env) = exec["env"].as_vec() {
        for e in env {
            if let (Some(k), Some(v)) = (e["name"].as_str(), e["value"].as_str()) {
                proceso.env(k, v);
            }
        }
    }
    let version = exec["apiVersion"]
        .as_str()
        .unwrap_or("client.authentication.k8s.io/v1");
    proceso.env(
        "KUBERNETES_EXEC_INFO",
        format!(
            r#"{{"apiVersion":"{version}","kind":"ExecCredential","spec":{{"interactive":false}}}}"#
        ),
    );
    let salida = proceso
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| {
            format!("no se pudo ejecutar el complemento de autenticación «{comando}»: {e}")
        })?;
    if !salida.status.success() {
        return Err(format!(
            "el complemento de autenticación «{comando}» falló: {}",
            String::from_utf8_lossy(&salida.stderr).trim()
        ));
    }
    let v: Value = serde_json::from_slice(&salida.stdout)
        .map_err(|e| format!("respuesta de exec inválida: {e}"))?;
    let estado = &v["status"];
    Ok(Credenciales {
        token: estado["token"].as_str().map(str::to_string),
        certificado_cliente: match (
            estado["clientCertificateData"].as_str(),
            estado["clientKeyData"].as_str(),
        ) {
            (Some(c), Some(k)) => Some((c.as_bytes().to_vec(), k.as_bytes().to_vec())),
            _ => None,
        },
    })
}

/// Resuelve la conexión desde un kubeconfig.
pub fn desde_kubeconfig(ruta: &Path, contexto: Option<&str>) -> Result<Conexion, String> {
    let texto_config = std::fs::read_to_string(ruta)
        .map_err(|e| format!("no se pudo leer {}: {e}", ruta.display()))?;
    let docs = YamlLoader::load_from_str(&texto_config)
        .map_err(|e| format!("kubeconfig inválido: {e}"))?;
    let doc = docs.first().ok_or("kubeconfig vacío")?;
    let base = ruta.parent().unwrap_or(Path::new("."));

    let nombre_contexto = match contexto {
        Some(c) => c.to_string(),
        None => texto(&doc["current-context"])
            .ok_or("el kubeconfig no tiene current-context; indique --contexto")?,
    };
    let ctx = buscar_por_nombre(&doc["contexts"], &nombre_contexto, "context")
        .ok_or_else(|| format!("no existe el contexto «{nombre_contexto}»"))?;
    let nombre_cluster = ctx["cluster"]
        .as_str()
        .ok_or("el contexto no indica cluster")?;
    let nombre_usuario = ctx["user"].as_str().unwrap_or("");
    let cluster = buscar_por_nombre(&doc["clusters"], nombre_cluster, "cluster")
        .ok_or_else(|| format!("no existe el cluster «{nombre_cluster}»"))?;
    let usuario = buscar_por_nombre(&doc["users"], nombre_usuario, "user");

    let servidor = Servidor::interpretar(
        cluster["server"]
            .as_str()
            .ok_or("el cluster no tiene server")?,
    )?;
    let autoridad_pem = dato_o_archivo(cluster, "certificate-authority", base)?;
    let confianza = ConfianzaTls {
        // Como kubectl: sin autoridad declarada se usa la del sistema.
        raices_sistema: autoridad_pem.is_none(),
        autoridad_pem,
        sin_verificar: cluster["insecure-skip-tls-verify"]
            .as_bool()
            .unwrap_or(false),
        nombre_servidor: texto(&cluster["tls-server-name"]),
    };

    let credenciales = match usuario {
        None => Credenciales::default(),
        Some(u) if !u["exec"].is_badvalue() => credenciales_exec(&u["exec"])?,
        Some(u) if !u["auth-provider"].is_badvalue() => {
            return Err("el kubeconfig usa auth-provider, retirado por Kubernetes; actualice a un complemento exec".into());
        }
        Some(u) => {
            let token = match (texto(&u["token"]), texto(&u["tokenFile"])) {
                (Some(t), _) => Some(t),
                (None, Some(f)) => Some(
                    std::fs::read_to_string(base.join(&f))
                        .map_err(|e| format!("no se pudo leer tokenFile: {e}"))?
                        .trim()
                        .to_string(),
                ),
                _ => None,
            };
            let certificado = dato_o_archivo(u, "client-certificate", base)?;
            let llave = dato_o_archivo(u, "client-key", base)?;
            Credenciales {
                token,
                certificado_cliente: certificado.zip(llave),
            }
        }
    };
    Ok(Conexion {
        contexto: nombre_contexto,
        servidor,
        credenciales,
        confianza,
    })
}

/// Conexión con la cuenta de servicio, si Suaya corre dentro de un clúster.
pub fn dentro_del_cluster() -> Option<Result<Conexion, String>> {
    let host = std::env::var("KUBERNETES_SERVICE_HOST").ok()?;
    let puerto = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".into());
    Some((|| {
        let token = std::fs::read_to_string(format!("{CUENTA_DE_SERVICIO}/token"))
            .map_err(|e| e.to_string())?;
        let ca =
            std::fs::read(format!("{CUENTA_DE_SERVICIO}/ca.crt")).map_err(|e| e.to_string())?;
        let anfitrion = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.clone()
        };
        Ok(Conexion {
            contexto: "dentro-del-cluster".into(),
            servidor: Servidor::interpretar(&format!("https://{anfitrion}:{puerto}"))?,
            credenciales: Credenciales {
                token: Some(token.trim().into()),
                certificado_cliente: None,
            },
            confianza: ConfianzaTls {
                autoridad_pem: Some(ca),
                sin_verificar: false,
                nombre_servidor: None,
                raices_sistema: false,
            },
        })
    })())
}

/// Opciones de lectura del clúster.
#[derive(Clone)]
pub struct Opciones {
    /// Espacios de nombres a leer; vacío significa todos.
    pub espacios: Vec<String>,
    pub tiempo: Duration,
}

impl Default for Opciones {
    fn default() -> Self {
        Self {
            espacios: Vec::new(),
            tiempo: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, Default)]
pub struct Resultado {
    /// Activos sin clasificar.
    pub activos: Vec<Activo>,
    pub avisos: Vec<String>,
    /// Hosts publicados por los Ingress con TLS, para sondearlos si se desea.
    pub hosts_ingress: Vec<String>,
    pub secretos_revisados: usize,
}

fn codificar_url(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Lista todos los objetos de una colección, con paginación.
fn listar(con: &Conexion, ruta: &str, op: &Opciones) -> Result<Option<Vec<Value>>, String> {
    let mut items = Vec::new();
    let mut continuar: Option<String> = None;
    let inicio = std::time::Instant::now();
    let mut paginas = 0;
    let mut bytes = 0usize;
    let mut vistos = std::collections::HashSet::new();
    loop {
        paginas += 1;
        if paginas > 100 || inicio.elapsed() > Duration::from_secs(120) {
            return Err("colección Kubernetes excede presupuesto de páginas/tiempo".into());
        }
        let mut url = format!("{ruta}?limit=250");
        if let Some(c) = &continuar {
            url.push_str(&format!("&continue={}", codificar_url(c)));
        }
        let r = get(
            &con.servidor,
            &url,
            &con.credenciales,
            &con.confianza,
            op.tiempo,
        )?;
        match r.estado {
            200 => {}
            404 => return Ok(None),
            401 => return Err("credenciales rechazadas por el clúster (401)".into()),
            403 => {
                return Err(format!(
                    "sin permiso para leer {ruta} (403); se requiere «list» en ese recurso"
                ));
            }
            otro => return Err(format!("{ruta}: respuesta HTTP {otro}")),
        }
        bytes = bytes.saturating_add(r.cuerpo.len());
        if bytes > 64 * 1024 * 1024 {
            return Err("colección Kubernetes excede 64 MiB".into());
        }
        let v: Value =
            serde_json::from_slice(&r.cuerpo).map_err(|e| format!("{ruta}: JSON inválido: {e}"))?;
        if let Some(lista) = v["items"].as_array() {
            if items.len() + lista.len() > 25_000 {
                return Err("demasiados objetos Kubernetes".into());
            }
            items.extend(lista.iter().cloned());
        }
        continuar = v["metadata"]["continue"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        if let Some(token) = &continuar
            && !vistos.insert(token.clone())
        {
            return Err("paginación Kubernetes repetida".into());
        }
        if continuar.is_none() {
            return Ok(Some(items));
        }
    }
}

/// Rutas de una colección para todos los espacios o para los indicados.
fn rutas(op: &Opciones, grupo: &str, recurso: &str) -> Vec<String> {
    if op.espacios.is_empty() {
        vec![format!("{grupo}/{recurso}")]
    } else {
        op.espacios
            .iter()
            .map(|ns| format!("{grupo}/namespaces/{ns}/{recurso}"))
            .collect()
    }
}

fn metadatos(item: &Value) -> (String, String) {
    (
        item["metadata"]["namespace"]
            .as_str()
            .unwrap_or("default")
            .to_string(),
        item["metadata"]["name"].as_str().unwrap_or("").to_string(),
    )
}

/// Lee el clúster y produce activos.
pub fn inventariar(con: &Conexion, c: &Conocimiento, op: &Opciones) -> Result<Resultado, String> {
    let mut r = Resultado::default();
    let ctx = &con.contexto;
    // (espacio, Secret) -> referencias de certificados hallados en él.
    let mut certificados_de: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();

    // Secrets.
    for ruta in rutas(op, "/api/v1", "secrets") {
        let Some(items) = listar(con, &ruta, op)? else {
            continue;
        };
        for item in items {
            r.secretos_revisados += 1;
            let (ns, nombre) = metadatos(&item);
            let Some(datos) = item["data"].as_object() else {
                continue;
            };
            for (clave, valor) in datos {
                let Some(b64) = valor.as_str() else { continue };
                let Ok(bytes) = B64.decode(b64) else { continue };
                if !bytes.windows(11).any(|w| w == b"-----BEGIN ") {
                    continue;
                }
                let texto_pem = String::from_utf8_lossy(&bytes).to_string();
                let ubicacion = format!("k8s://{ctx}/{ns}/secret/{nombre}#{clave}");
                let a = Archivo::nuevo(&ubicacion, Path::new(&ubicacion), &bytes, None);
                let (activos, errores) = analizar_texto_pem(&texto_pem, &a, None, c);
                r.avisos
                    .extend(errores.into_iter().map(|e| format!("{ubicacion}: {e}")));
                for mut x in activos {
                    match &x.detalles {
                        Detalles::Certificado { .. } => {
                            certificados_de
                                .entry((ns.clone(), nombre.clone()))
                                .or_default()
                                .push(x.referencia.clone());
                        }
                        Detalles::Material { tipo_material, .. }
                            if tipo_material == "private-key" =>
                        {
                            x.advertir(
                                "Llave privada en un Secret de Kubernetes: los Secrets solo están codificados en base64. Verifique que etcd tenga cifrado en reposo y que el RBAC limite quién puede leerlos.",
                            );
                        }
                        _ => {}
                    }
                    r.activos.push(x);
                }
            }
        }
    }

    // Ingress: qué certificados se publican y para qué hosts.
    for ruta in rutas(op, "/apis/networking.k8s.io/v1", "ingresses") {
        let items = match listar(con, &ruta, op) {
            Ok(Some(i)) => i,
            Ok(None) => continue,
            Err(e) => {
                r.avisos.push(e);
                continue;
            }
        };
        for item in items {
            let (ns, nombre) = metadatos(&item);
            for tls in item["spec"]["tls"].as_array().into_iter().flatten() {
                let hosts: Vec<String> = tls["hosts"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|h| h.as_str().map(str::to_string))
                    .collect();
                for h in &hosts {
                    if !r.hosts_ingress.contains(h) && !h.starts_with('*') {
                        r.hosts_ingress.push(h.clone());
                    }
                }
                let Some(secreto) = tls["secretName"].as_str() else {
                    continue;
                };
                match certificados_de.get(&(ns.clone(), secreto.to_string())) {
                    Some(refs) => {
                        for a in r.activos.iter_mut().filter(|a| refs.contains(&a.referencia)) {
                            a.agregar_contexto("servidores-web", Garantia::Autenticacion);
                            a.advertir(format!(
                                "Lo publica el Ingress {ns}/{nombre} para: {}.",
                                if hosts.is_empty() { "todos los hosts".to_string() } else { hosts.join(", ") }
                            ));
                        }
                    }
                    None => r.avisos.push(format!(
                        "el Ingress {ns}/{nombre} usa el Secret «{secreto}», que no se encontró o no contiene un certificado"
                    )),
                }
            }
        }
    }

    // Certificates de cert-manager, si el CRD existe.
    for ruta in rutas(op, "/apis/cert-manager.io/v1", "certificates") {
        let items = match listar(con, &ruta, op) {
            Ok(Some(i)) => i,
            Ok(None) => break,
            Err(e) => {
                r.avisos.push(e);
                continue;
            }
        };
        for item in items {
            let (ns, nombre) = metadatos(&item);
            let llave = &item["spec"]["privateKey"];
            let ubicacion = format!("k8s://{ctx}/{ns}/certificate/{nombre}");
            r.activos.extend(activos_certificado(
                &ns,
                &nombre,
                llave["algorithm"].as_str().unwrap_or("RSA"),
                llave["size"].as_u64().map(|s| s as u32),
                llave["rotationPolicy"].as_str(),
                &ubicacion,
                None,
                &ubicacion,
                c,
            ));
        }
    }
    Ok(r)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn kubeconfig_con_token_y_archivos_relativos() {
        let dir = std::env::temp_dir().join(format!("suaya-kc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("ca.pem"),
            b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let kc = dir.join("config");
        std::fs::write(
            &kc,
            "apiVersion: v1\nkind: Config\ncurrent-context: prod\ncontexts:\n- name: prod\n  context: {cluster: c1, user: u1}\n- name: lab\n  context: {cluster: c2, user: u2}\nclusters:\n- name: c1\n  cluster: {server: 'https://10.0.0.1:6443', certificate-authority: ca.pem}\n- name: c2\n  cluster: {server: 'http://127.0.0.1:8001'}\nusers:\n- name: u1\n  user: {token: abc}\n- name: u2\n  user: {}\n",
        )
        .unwrap();
        let c = desde_kubeconfig(&kc, None).unwrap();
        assert_eq!(c.contexto, "prod");
        assert_eq!(c.servidor.puerto, 6443);
        assert_eq!(c.credenciales.token.as_deref(), Some("abc"));
        assert!(c.confianza.autoridad_pem.is_some());
        let c = desde_kubeconfig(&kc, Some("lab")).unwrap();
        assert!(!c.servidor.seguro && c.credenciales.token.is_none());
        assert!(desde_kubeconfig(&kc, Some("inexistente")).is_err());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn url_y_rutas() {
        assert_eq!(codificar_url("a+b/c="), "a%2Bb%2Fc%3D");
        let op = Opciones {
            espacios: vec!["prod".into()],
            ..Opciones::default()
        };
        assert_eq!(
            rutas(&op, "/api/v1", "secrets"),
            vec!["/api/v1/namespaces/prod/secrets"]
        );
    }
}
