//! Prueba de la lectura de Kubernetes contra un servidor de API simulado
//! sobre TLS real: autoridad propia, verificación estricta y token.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use base64::Engine;
use rcgen::{CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use suaya_core::{Conocimiento, Detalles, Inventario, clasificar};
use suaya_red::kubernetes::{Opciones, desde_kubeconfig, inventariar};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const TOKEN: &str = "token-de-prueba";

struct Pki {
    ca_pem: String,
    servidor: (Vec<u8>, Vec<u8>),
    tienda_cert: String,
    tienda_llave: String,
}

fn pki() -> Pki {
    let ca_llave = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    ca.distinguished_name
        .push(DnType::CommonName, "CA de prueba");
    let ca_cert = ca.self_signed(&ca_llave).unwrap();
    let emisor = rcgen::Issuer::new(ca, ca_llave);

    let srv_llave = KeyPair::generate().unwrap();
    let srv = CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap();
    let srv_cert = srv.signed_by(&srv_llave, &emisor).unwrap();

    let t_llave = KeyPair::generate().unwrap();
    let mut t = CertificateParams::new(vec!["tienda.ejemplo.mx".to_string()]).unwrap();
    t.distinguished_name
        .push(DnType::CommonName, "tienda.ejemplo.mx");
    let t_cert = t.signed_by(&t_llave, &emisor).unwrap();

    Pki {
        ca_pem: ca_cert.pem(),
        servidor: (srv_cert.der().to_vec(), srv_llave.serialize_der()),
        tienda_cert: t_cert.pem(),
        tienda_llave: t_llave.serialize_pem(),
    }
}

fn respuesta(estado: &str, cuerpo: &str, fragmentada: bool) -> Vec<u8> {
    if fragmentada {
        let mitad = cuerpo.len() / 2;
        format!(
            "HTTP/1.1 {estado}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n{:x}\r\n{}\r\n0\r\n\r\n",
            mitad,
            &cuerpo[..mitad],
            cuerpo.len() - mitad,
            &cuerpo[mitad..]
        )
        .into_bytes()
    } else {
        format!(
            "HTTP/1.1 {estado}\r\nContent-Length: {}\r\n\r\n{cuerpo}",
            cuerpo.len()
        )
        .into_bytes()
    }
}

fn servidor_api(p: &Pki, con_cert_manager: bool) -> u16 {
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![p.servidor.0.clone().into()],
        rustls::pki_types::PrivateKeyDer::Pkcs8(p.servidor.1.clone().into()),
    )
    .unwrap();
    let config = Arc::new(config);
    let tls = serde_json::json!({
        "metadata": {"name": "tienda-tls", "namespace": "tienda"},
        "type": "kubernetes.io/tls",
        "data": {"tls.crt": B64.encode(&p.tienda_cert), "tls.key": B64.encode(&p.tienda_llave)}
    });
    let opaco = serde_json::json!({"metadata": {"name": "app", "namespace": "tienda"}, "data": {"clave": B64.encode("hola")}});
    let pagina1 =
        serde_json::json!({"items": [tls], "metadata": {"continue": "tok+/="}}).to_string();
    let pagina2 = serde_json::json!({"items": [opaco], "metadata": {}}).to_string();
    let ingress = serde_json::json!({"items": [{
        "metadata": {"name": "web", "namespace": "tienda"},
        "spec": {"tls": [{"hosts": ["tienda.ejemplo.mx"], "secretName": "tienda-tls"}]}
    }]})
    .to_string();
    let certificados = serde_json::json!({"items": [{
        "metadata": {"name": "tienda", "namespace": "tienda"},
        "spec": {"privateKey": {"algorithm": "ECDSA", "size": 384}}
    }]})
    .to_string();

    let escucha = TcpListener::bind("127.0.0.1:0").unwrap();
    let puerto = escucha.local_addr().unwrap().port();
    thread::spawn(move || {
        for s in escucha.incoming().flatten() {
            let conexion = rustls::ServerConnection::new(config.clone()).unwrap();
            let mut flujo = rustls::StreamOwned::new(conexion, s);
            let mut solicitud = Vec::new();
            let mut b = [0u8; 4096];
            while !solicitud.windows(4).any(|w| w == b"\r\n\r\n") {
                match flujo.read(&mut b) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => solicitud.extend_from_slice(&b[..n]),
                }
            }
            let texto = String::from_utf8_lossy(&solicitud).to_string();
            let ruta = texto.split_whitespace().nth(1).unwrap_or("").to_string();
            let r = if !texto.contains(&format!("Authorization: Bearer {TOKEN}")) {
                respuesta("401 Unauthorized", "{}", false)
            } else if ruta.starts_with("/api/v1/secrets") && ruta.contains("continue=tok%2B%2F%3D")
            {
                respuesta("200 OK", &pagina2, true)
            } else if ruta.starts_with("/api/v1/secrets") {
                respuesta("200 OK", &pagina1, true)
            } else if ruta.starts_with("/apis/networking.k8s.io/v1/ingresses") {
                respuesta("200 OK", &ingress, false)
            } else if ruta.starts_with("/apis/cert-manager.io/v1/certificates") && con_cert_manager
            {
                respuesta("200 OK", &certificados, false)
            } else {
                respuesta("404 Not Found", "{}", false)
            };
            let _ = flujo.write_all(&r);
            flujo.conn.send_close_notify();
            let _ = flujo.flush();
        }
    });
    puerto
}

fn kubeconfig(puerto: u16, ca_pem: &str, token: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("suaya-k8s-{}-{puerto}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ruta = dir.join("config");
    std::fs::write(
        &ruta,
        format!(
            "apiVersion: v1\nkind: Config\ncurrent-context: prueba\ncontexts:\n- name: prueba\n  context:\n    cluster: local\n    user: lector\nclusters:\n- name: local\n  cluster:\n    server: https://127.0.0.1:{puerto}\n    certificate-authority-data: {}\nusers:\n- name: lector\n  user:\n    token: {token}\n",
            B64.encode(ca_pem)
        ),
    )
    .unwrap();
    ruta
}

#[test]
fn inventario_de_un_cluster_simulado() {
    let p = pki();
    let puerto = servidor_api(&p, true);
    let con = desde_kubeconfig(&kubeconfig(puerto, &p.ca_pem, TOKEN), None).unwrap();
    let c = Conocimiento::embebido();
    let r = inventariar(&con, &c, &Opciones::default()).unwrap();
    assert!(r.avisos.is_empty(), "{:?}", r.avisos);
    assert_eq!(r.secretos_revisados, 2, "falló la paginación");
    assert_eq!(r.hosts_ingress, vec!["tienda.ejemplo.mx"]);

    let mut inv = Inventario::default();
    inv.extender(r.activos);
    clasificar(&mut inv, &c);
    let cert = inv
        .activos
        .iter()
        .find(|a| matches!(a.detalles, Detalles::Certificado { .. }))
        .expect("certificado del Secret");
    assert!(
        cert.ubicaciones[0]
            .ruta
            .starts_with("k8s://prueba/tienda/secret/tienda-tls#tls.crt")
    );
    assert!(
        cert.advertencias
            .iter()
            .any(|w| w.contains("Ingress tienda/web"))
    );
    assert!(
        cert.contextos
            .iter()
            .any(|x| x.capacidad == "servidores-web")
    );
    let llave = inv
        .activos
        .iter()
        .find(|a| matches!(&a.detalles, Detalles::Material { tipo_material, .. } if tipo_material == "private-key" && a.nombre.starts_with("Llave privada")))
        .expect("llave del Secret");
    assert!(llave.advertencias.iter().any(|w| w.contains("etcd")));
    assert!(
        llave.relaciones.iter().any(|x| x.tipo == "certificate"),
        "llave sin enlazar"
    );
    assert!(
        inv.activos
            .iter()
            .any(|a| a.nombre.contains("Llave de cert-manager tienda/tienda")
                && a.nombre.contains("P-384"))
    );
}

#[test]
fn rechaza_un_servidor_con_otra_autoridad() {
    let p = pki();
    let otra = pki();
    let puerto = servidor_api(&p, false);
    let con = desde_kubeconfig(&kubeconfig(puerto, &otra.ca_pem, TOKEN), None).unwrap();
    let e = inventariar(&con, &Conocimiento::embebido(), &Opciones::default()).unwrap_err();
    assert!(
        e.to_lowercase().contains("certific") || e.contains("UnknownIssuer"),
        "{e}"
    );
}

#[test]
fn informa_credenciales_rechazadas() {
    let p = pki();
    let puerto = servidor_api(&p, false);
    let con = desde_kubeconfig(&kubeconfig(puerto, &p.ca_pem, "otro"), None).unwrap();
    let e = inventariar(&con, &Conocimiento::embebido(), &Opciones::default()).unwrap_err();
    assert!(e.contains("401"), "{e}");
}
