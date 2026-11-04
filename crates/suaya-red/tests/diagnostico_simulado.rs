//! Diagnóstico de conectividad e intercambio de llaves y certificados contra
//! servidores TLS reales (rustls) y un SSH simulado en `127.0.0.1`.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use rcgen::{CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use suaya_core::{Conocimiento, Riesgo};
use suaya_red::diagnostico::{EstadoTcp, Nivel};
use suaya_red::{Diagnostico, Objetivo, Opciones, diagnosticar, sondear};

struct Pki {
    ca_pem: String,
    hoja: Vec<u8>,
    llave: Vec<u8>,
}

fn pki(dias: i64) -> Pki {
    let ca_llave = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    ca.distinguished_name
        .push(DnType::CommonName, "CA de diagnóstico");
    let ca_cert = ca.self_signed(&ca_llave).unwrap();
    let emisor = rcgen::Issuer::new(ca, ca_llave);

    let llave = KeyPair::generate().unwrap();
    let mut srv = CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap();
    srv.distinguished_name
        .push(DnType::CommonName, "servidor de prueba");
    let ahora = time::OffsetDateTime::now_utc();
    srv.not_before = ahora - time::Duration::days(1);
    srv.not_after = ahora + time::Duration::days(dias);
    let hoja = srv.signed_by(&llave, &emisor).unwrap();
    Pki {
        ca_pem: ca_cert.pem(),
        hoja: hoja.der().to_vec(),
        llave: llave.serialize_der(),
    }
}

/// Servidor TLS con rustls. `grupos` filtra los grupos del proveedor por nombre.
fn servidor(p: &Pki, grupos: fn(&str) -> bool) -> u16 {
    let mut proveedor = rustls::crypto::aws_lc_rs::default_provider();
    proveedor
        .kx_groups
        .retain(|g| grupos(&format!("{:?}", g.name())));
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(proveedor))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![p.hoja.clone().into()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(p.llave.clone().into()),
        )
        .unwrap();
    let config = Arc::new(config);
    let escucha = TcpListener::bind("127.0.0.1:0").unwrap();
    let puerto = escucha.local_addr().unwrap().port();
    thread::spawn(move || {
        for s in escucha.incoming().flatten() {
            let config = config.clone();
            thread::spawn(move || {
                let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(3)));
                let conexion = rustls::ServerConnection::new(config).unwrap();
                let mut flujo = rustls::StreamOwned::new(conexion, s);
                let mut b = [0u8; 64];
                // Completa el saludo y espera el cierre del cliente.
                while matches!(flujo.read(&mut b), Ok(n) if n > 0) {}
            });
        }
    });
    puerto
}

fn todos(_: &str) -> bool {
    true
}

fn clasicos(n: &str) -> bool {
    !n.contains("MLKEM")
}

fn solo_hibrido(n: &str) -> bool {
    n == "X25519MLKEM768"
}

fn opciones(ca: Option<&str>) -> Opciones {
    Opciones {
        tiempo_limite: std::time::Duration::from_secs(3),
        autoridad_pem: ca.map(|c| c.as_bytes().to_vec()),
        ..Opciones::default()
    }
}

fn diagnostico(objetivo: &str, op: &Opciones) -> Diagnostico {
    let c = Conocimiento::embebido();
    diagnosticar(&[Objetivo::interpretar(objetivo).unwrap()], &c, op)
        .pop()
        .unwrap()
}

fn tiene(d: &Diagnostico, codigo: &str) -> bool {
    d.hallazgos.iter().any(|h| h.codigo == codigo)
}

#[test]
fn servidor_hibrido_con_cadena_valida() {
    let p = pki(365);
    let puerto = servidor(&p, todos);
    let d = diagnostico(
        &format!("tls://127.0.0.1:{puerto}"),
        &opciones(Some(&p.ca_pem)),
    );

    assert!(d.conectividad.alcanzable());
    assert_eq!(d.conectividad.direcciones[0].estado, EstadoTcp::Abierto);
    assert!(d.conectividad.saludo_ms.is_some());

    let t = d.tls.as_ref().expect("intercambio TLS");
    assert!(t.moderno.exito, "{:?}", t.moderno.error);
    assert_eq!(t.moderno.version.as_deref(), Some("TLSv1.3"));
    assert_eq!(t.moderno.grupo.as_deref(), Some("x25519mlkem768"));
    assert_eq!(t.moderno.riesgo_grupo, Some(Riesgo::HibridoPq));
    assert!(!t.moderno.reintento);
    assert_eq!(t.moderno.firma_verificada, Some(true));
    assert!(t.moderno.esquema_firma.is_some());
    assert!(t.clasico.exito);
    assert_eq!(t.clasico.riesgo_grupo, Some(Riesgo::VulnerableCuantico));

    let k = d.certificados.as_ref().expect("cadena");
    assert!(k.valida(), "{:?} {:?}", k.error_validacion, k.error_nombre);
    assert_eq!(k.certificados.len(), 1);
    assert!(
        k.certificados[0]
            .nombres_alternativos
            .contains(&"127.0.0.1".to_string())
    );
    assert!(k.certificados[0].dias_restantes >= 363);

    assert!(tiene(&d, "KEX-PQ"));
    assert!(tiene(&d, "CERT-LLAVE-CUANTICA"));
    assert!(tiene(&d, "CERT-OCSP"));
    assert!(!tiene(&d, "CERT-CADENA") && !tiene(&d, "KEX-COMPAT"));
    assert_eq!(d.peor(), Some(Nivel::Medio));

    // El JSON del diagnóstico es estable para otras herramientas.
    let j = serde_json::to_value(&d).unwrap();
    assert_eq!(j["protocolo"], "tls");
    assert_eq!(j["tls"]["moderno"]["grupo"], "x25519mlkem768");
    assert_eq!(j["hallazgos"][0]["nivel"], "medio");
}

#[test]
fn servidor_clasico_sin_autoridad_y_por_vencer() {
    let p = pki(10);
    let puerto = servidor(&p, clasicos);
    let d = diagnostico(&format!("tls://127.0.0.1:{puerto}"), &opciones(None));
    let t = d.tls.as_ref().unwrap();
    assert!(t.moderno.exito);
    assert_eq!(t.moderno.riesgo_grupo, Some(Riesgo::VulnerableCuantico));
    assert!(tiene(&d, "KEX-CLASICO"));
    assert!(tiene(&d, "CERT-CADENA"));
    assert!(tiene(&d, "CERT-VENCE"));
    assert_eq!(d.peor(), Some(Nivel::Critico));
}

#[test]
fn servidor_solo_hibrido_rechaza_clientes_clasicos() {
    let p = pki(200);
    let puerto = servidor(&p, solo_hibrido);
    let d = diagnostico(
        &format!("tls://127.0.0.1:{puerto}"),
        &opciones(Some(&p.ca_pem)),
    );
    let t = d.tls.as_ref().unwrap();
    assert!(t.moderno.exito);
    assert!(!t.clasico.exito);
    assert!(tiene(&d, "KEX-PQ"));
    assert!(tiene(&d, "KEX-COMPAT"));
}

#[test]
fn puerto_cerrado_es_critico() {
    let puerto = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let d = diagnostico(&format!("tls://127.0.0.1:{puerto}"), &opciones(None));
    assert!(!d.conectividad.alcanzable());
    assert_eq!(d.conectividad.direcciones[0].estado, EstadoTcp::Rechazado);
    assert!(tiene(&d, "CON-TCP"));
    assert!(d.tls.is_none());
}

fn lista(v: &str) -> Vec<u8> {
    let mut b = (v.len() as u32).to_be_bytes().to_vec();
    b.extend_from_slice(v.as_bytes());
    b
}

fn servidor_ssh(kex: &'static str, cifrado: &'static str) -> u16 {
    let escucha = TcpListener::bind("127.0.0.1:0").unwrap();
    let puerto = escucha.local_addr().unwrap().port();
    thread::spawn(move || {
        for mut s in escucha.incoming().flatten() {
            let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(2)));
            let mut byte = [0u8];
            for _ in 0..256 {
                if s.read_exact(&mut byte).is_err() || byte[0] == b'\n' {
                    break;
                }
            }
            let _ = s.write_all(b"SSH-2.0-OpenSSH_9.9 Simulado\r\n");
            let mut carga = vec![20u8];
            carga.extend_from_slice(&[0u8; 16]);
            for l in [
                kex,
                "ssh-ed25519",
                cifrado,
                cifrado,
                "hmac-sha2-256",
                "hmac-sha2-256",
                "none",
                "none",
                "",
                "",
            ] {
                carga.extend(lista(l));
            }
            carga.extend_from_slice(&[0, 0, 0, 0, 0]);
            let mut paquete = ((carga.len() + 5) as u32).to_be_bytes().to_vec();
            paquete.push(4);
            paquete.extend(carga);
            paquete.extend_from_slice(&[0u8; 4]);
            let _ = s.write_all(&paquete);
        }
    });
    puerto
}

#[test]
fn ssh_hibrido_con_strict_kex() {
    let puerto = servidor_ssh(
        "mlkem768x25519-sha256,curve25519-sha256,ext-info-s,kex-strict-s-v00@openssh.com",
        "chacha20-poly1305@openssh.com",
    );
    let d = diagnostico(&format!("ssh://127.0.0.1:{puerto}"), &opciones(None));
    let s = d.ssh.as_ref().expect("KEXINIT");
    assert!(s.kex_estricto);
    assert_eq!(s.kex_poscuanticos, vec!["mlkem768x25519-sha256"]);
    assert!(tiene(&d, "SSH-KEX-PQ"));
    assert!(!tiene(&d, "SSH-TERRAPIN"));
}

#[test]
fn ssh_clasico_expuesto_a_terrapin() {
    let puerto = servidor_ssh("curve25519-sha256", "chacha20-poly1305@openssh.com");
    let d = diagnostico(&format!("ssh://127.0.0.1:{puerto}"), &opciones(None));
    assert!(tiene(&d, "SSH-KEX-CLASICO"));
    assert!(tiene(&d, "SSH-TERRAPIN"));
}

#[test]
fn sondear_con_diagnostico_agrega_advertencias() {
    let p = pki(5);
    let puerto = servidor(&p, clasicos);
    let c = Conocimiento::embebido();
    let op = Opciones {
        diagnostico: true,
        ..opciones(Some(&p.ca_pem))
    };
    let r = sondear(
        &[Objetivo::interpretar(&format!("tls://127.0.0.1:{puerto}")).unwrap()],
        &c,
        &op,
    );
    let protocolo = r
        .activos
        .iter()
        .find(|a| a.referencia.starts_with("protocolo:tls"))
        .expect("protocolo");
    assert!(
        protocolo
            .advertencias
            .iter()
            .any(|w| w.starts_with("Diagnóstico (CERT-VENCE)")),
        "{:?}",
        protocolo.advertencias
    );
    assert!(
        !protocolo
            .advertencias
            .iter()
            .any(|w| w.contains("(CERT-OCSP)")),
        "los hallazgos informativos no se agregan al CBOM"
    );
}
