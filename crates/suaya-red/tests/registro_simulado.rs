//! Registro OCI simulado: desafío Bearer, token con credenciales de
//! `config.json`, índice multiplataforma, redirección de una capa a otro
//! servidor (sin la autorización) y verificación de resúmenes.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

use base64::Engine;
use sha2::{Digest, Sha256};
use suaya_core::{Conocimiento, Detalles};
use suaya_escaneo::{Opciones as OpcionesEscaneo, Resultado, escaneres_predeterminados};
use suaya_red::registro::{Opciones, inventariar_imagen};

fn capas_fixture() -> Vec<Vec<u8>> {
    let ruta = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../pruebas/fixtures/imagenes/tienda-docker.tar"
    );
    let mut archivo = tar::Archive::new(std::fs::File::open(ruta).unwrap());
    let mut capas = vec![Vec::new(), Vec::new()];
    for e in archivo.entries().unwrap() {
        let mut e = e.unwrap();
        let nombre = e.path().unwrap().to_string_lossy().to_string();
        let i = match nombre.as_str() {
            "capa1.tar.gz" => 0,
            "capa2.tar" => 1,
            _ => continue,
        };
        e.read_to_end(&mut capas[i]).unwrap();
    }
    capas
}

fn resumen(b: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(b)))
}

/// Solicitud recibida: ruta y encabezado Authorization.
type Registro = Arc<Mutex<Vec<(String, Option<String>)>>>;

fn servidor(
    escucha: TcpListener,
    manejar: impl Fn(&str, Option<&str>) -> Vec<u8> + Send + 'static,
) -> Registro {
    let registro: Registro = Arc::default();
    let r = registro.clone();
    thread::spawn(move || {
        for conexion in escucha.incoming() {
            let Ok(mut conexion) = conexion else { break };
            let mut lector = BufReader::new(conexion.try_clone().unwrap());
            let mut primera = String::new();
            lector.read_line(&mut primera).unwrap();
            let ruta = primera.split_whitespace().nth(1).unwrap_or("").to_string();
            let mut autorizacion = None;
            loop {
                let mut l = String::new();
                lector.read_line(&mut l).unwrap();
                if l.trim().is_empty() {
                    break;
                }
                if let Some((_, v)) = l
                    .split_once(':')
                    .filter(|(k, _)| k.eq_ignore_ascii_case("authorization"))
                {
                    autorizacion = Some(v.trim().to_string());
                }
            }
            r.lock().unwrap().push((ruta.clone(), autorizacion.clone()));
            let respuesta = manejar(&ruta, autorizacion.as_deref());
            let _ = conexion.write_all(&respuesta);
        }
    });
    registro
}

fn escuchar() -> (TcpListener, u16) {
    let escucha = TcpListener::bind("127.0.0.1:0").unwrap();
    let puerto = escucha.local_addr().unwrap().port();
    (escucha, puerto)
}

fn respuesta(estado: &str, extra: &str, cuerpo: &[u8]) -> Vec<u8> {
    let mut r = format!(
        "HTTP/1.1 {estado}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",
        cuerpo.len()
    )
    .into_bytes();
    r.extend_from_slice(cuerpo);
    r
}

fn fragmentada(cuerpo: &[u8]) -> Vec<u8> {
    let mut r =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
    for trozo in cuerpo.chunks(1000) {
        r.extend_from_slice(format!("{:x}\r\n", trozo.len()).as_bytes());
        r.extend_from_slice(trozo);
        r.extend_from_slice(b"\r\n");
    }
    r.extend_from_slice(b"0\r\n\r\n");
    r
}

struct Escenario {
    puerto: u16,
    registro: Registro,
    cdn: Registro,
    config: std::path::PathBuf,
}

/// Levanta registro y CDN. Con `alterar`, la capa 2 llega modificada.
fn escenario(alterar: bool, clave: &str) -> Escenario {
    let capas = capas_fixture();
    let (d1, d2) = (resumen(&capas[0]), resumen(&capas[1]));
    let manifiesto = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": resumen(b"{}"), "size": 2},
        "layers": [
            {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": d1, "size": capas[0].len()},
            {"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": d2, "size": capas[1].len()},
        ]
    })
    .to_string()
    .into_bytes();
    let dm = resumen(&manifiesto);
    let indice = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": resumen(b"otra"), "size": 4, "platform": {"os": "linux", "architecture": "arm64"}},
            {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": dm, "size": manifiesto.len(), "platform": {"os": "linux", "architecture": "amd64"}},
        ]
    })
    .to_string()
    .into_bytes();

    let capa1 = capas[0].clone();
    let (escucha_cdn, puerto_cdn) = escuchar();
    let cdn = servidor(escucha_cdn, move |ruta, _| {
        if ruta.starts_with("/cdn/") {
            fragmentada(&capa1)
        } else {
            respuesta("404 Not Found", "", b"")
        }
    });

    let (escucha, puerto) = escuchar();
    let basica = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("ana:clave")
    );
    let mut capa2 = capas[1].clone();
    if alterar {
        let n = capa2.len();
        capa2[n / 2] ^= 0xFF;
    }
    let (d1c, d2c, dmc) = (d1.clone(), d2.clone(), dm.clone());
    let registro = servidor(escucha, move |ruta: &str, auth: Option<&str>| -> Vec<u8> {
        if ruta.starts_with("/token?") {
            if auth == Some(basica.as_str())
                && ruta.contains("service=prueba")
                && ruta.contains("scope=repository%3Ademo%2Ftienda%3Apull")
            {
                return respuesta("200 OK", "", br#"{"token":"secreto"}"#);
            }
            return respuesta("401 Unauthorized", "", b"{}");
        }
        if auth != Some("Bearer secreto") {
            let desafio = format!(
                "WWW-Authenticate: Bearer realm=\"http://127.0.0.1:{puerto}/token\",service=\"prueba\",scope=\"repository:demo/tienda:pull\"\r\n"
            );
            return respuesta("401 Unauthorized", &desafio, b"");
        }
        match ruta {
            "/v2/demo/tienda/manifests/1.0" => respuesta(
                "200 OK",
                "Content-Type: application/vnd.oci.image.index.v1+json\r\n",
                &indice,
            ),
            r if r == format!("/v2/demo/tienda/manifests/{dmc}") => respuesta(
                "200 OK",
                "Content-Type: application/vnd.oci.image.manifest.v1+json\r\n",
                &manifiesto,
            ),
            r if r == format!("/v2/demo/tienda/blobs/{d1c}") => respuesta(
                "307 Temporary Redirect",
                &format!("Location: http://127.0.0.1:{puerto_cdn}/cdn/{d1c}?firma=1\r\n"),
                b"",
            ),
            r if r == format!("/v2/demo/tienda/blobs/{d2c}") => respuesta("200 OK", "", &capa2),
            _ => respuesta("404 Not Found", "", b""),
        }
    });

    let dir = std::env::temp_dir().join(format!("suaya-registro-{puerto}"));
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("config.json");
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("ana:{clave}"));
    std::fs::write(
        &config,
        format!(r#"{{"auths":{{"127.0.0.1:{puerto}":{{"auth":"{auth}"}}}}}}"#),
    )
    .unwrap();
    Escenario {
        puerto,
        registro,
        cdn,
        config,
    }
}

fn opciones(e: &Escenario) -> Opciones {
    Opciones {
        plataforma: "linux/amd64".into(),
        permitir_http_local: true,
        config_docker: Some(e.config.clone()),
        ..Opciones::default()
    }
}

#[test]
fn descarga_verificada_con_token_y_redireccion() {
    let e = escenario(false, "clave");
    let c = Conocimiento::embebido();
    let mut r = Resultado::default();
    let referencia = format!("docker://127.0.0.1:{}/demo/tienda:1.0", e.puerto);
    inventariar_imagen(
        &referencia,
        &escaneres_predeterminados(),
        &c,
        &OpcionesEscaneo::default(),
        &opciones(&e),
        &mut r,
    )
    .unwrap();

    let llave = r
        .inventario
        .activos
        .iter()
        .find(|a| matches!(&a.detalles, Detalles::Material { tipo_material, .. } if tipo_material == "private-key"))
        .expect("la llave de la capa 1");
    assert!(llave.advertencias.iter().any(|x| x.contains("Se borró")));
    assert!(
        llave.ubicaciones[0]
            .ruta
            .starts_with(&format!("127.0.0.1:{}/demo/tienda:1.0@capa1:", e.puerto))
    );
    assert!(r.inventario.activos.iter().any(|a| {
        a.nombre.contains("X25519MLKEM768")
            || a.ubicaciones
                .iter()
                .any(|u| u.ruta.ends_with("tienda.conf"))
    }));
    assert!(r.avisos.iter().any(|a| a.contains("2 capas verificadas")));

    // La autorización nunca viaja a la CDN.
    let cdn = e.cdn.lock().unwrap();
    assert_eq!(cdn.len(), 1);
    assert!(cdn[0].1.is_none(), "la CDN no debe recibir credenciales");
    // Al registro solo se le envió el token, nunca la clave (salvo al servicio de tokens).
    let reg = e.registro.lock().unwrap();
    assert!(
        reg.iter()
            .filter(|(ruta, _)| ruta.starts_with("/v2/"))
            .all(|(_, a)| a.as_deref().is_none_or(|a| a == "Bearer secreto"))
    );
}

#[test]
fn capa_alterada_descarta_la_imagen() {
    let e = escenario(true, "clave");
    let c = Conocimiento::embebido();
    let mut r = Resultado::default();
    let error = inventariar_imagen(
        &format!("127.0.0.1:{}/demo/tienda:1.0", e.puerto),
        &escaneres_predeterminados(),
        &c,
        &OpcionesEscaneo::default(),
        &opciones(&e),
        &mut r,
    )
    .unwrap_err();
    assert!(error.contains("no coincide"), "{error}");
    assert!(r.inventario.activos.is_empty(), "sin hallazgos parciales");
}

#[test]
fn credenciales_incorrectas() {
    let e = escenario(false, "otra");
    let c = Conocimiento::embebido();
    let mut r = Resultado::default();
    let error = inventariar_imagen(
        &format!("127.0.0.1:{}/demo/tienda:1.0", e.puerto),
        &escaneres_predeterminados(),
        &c,
        &OpcionesEscaneo::default(),
        &opciones(&e),
        &mut r,
    )
    .unwrap_err();
    assert!(error.contains("credenciales"), "{error}");
    let _ = e.registro;
}
