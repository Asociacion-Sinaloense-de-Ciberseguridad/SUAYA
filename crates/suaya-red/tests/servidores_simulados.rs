//! Pruebas del sondeo contra servidores simulados en `127.0.0.1`.
//!
//! Los servidores implementan lo justo del protocolo para responder a los
//! sondeos: un servidor SSH que envía su `KEXINIT` y un servidor TLS que
//! responde con `HelloRetryRequest`, `ServerHello` o alertas según su
//! configuración. Así se prueban escenarios (como grupos híbridos) que las
//! bibliotecas instaladas no siempre ofrecen.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use suaya_core::{Conocimiento, Detalles, Inventario, Riesgo, clasificar};
use suaya_red::{Objetivo, Opciones, sondear};

// ---------------------------------------------------------------------------
// Servidor SSH simulado
// ---------------------------------------------------------------------------

fn lista(v: &str) -> Vec<u8> {
    let mut b = (v.len() as u32).to_be_bytes().to_vec();
    b.extend_from_slice(v.as_bytes());
    b
}

fn servidor_ssh(kex: &'static str) -> u16 {
    let escucha = TcpListener::bind("127.0.0.1:0").unwrap();
    let puerto = escucha.local_addr().unwrap().port();
    thread::spawn(move || {
        for s in escucha.incoming().flatten() {
            let mut s = s;
            let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(2)));
            // Consumir la identificación evita un RST al cerrar con datos sin leer en macOS.
            let mut byte = [0u8];
            for _ in 0..256 {
                if s.read_exact(&mut byte).is_err() || byte[0] == b'\n' {
                    break;
                }
            }
            let _ = s.write_all(b"SSH-2.0-OpenSSH_10.0 Simulado\r\n");
            let mut carga = vec![20u8];
            carga.extend_from_slice(&[0u8; 16]);
            for l in [
                kex,
                "ssh-ed25519,rsa-sha2-512",
                "aes256-gcm@openssh.com",
                "aes256-gcm@openssh.com",
                "hmac-sha2-256-etm@openssh.com",
                "hmac-sha2-256-etm@openssh.com",
                "none",
                "none",
                "",
                "",
            ] {
                carga.extend(lista(l));
            }
            carga.extend_from_slice(&[0, 0, 0, 0, 0]);
            let relleno = 4u8;
            let mut paquete = ((carga.len() + 1 + relleno as usize) as u32)
                .to_be_bytes()
                .to_vec();
            paquete.push(relleno);
            paquete.extend(carga);
            paquete.extend_from_slice(&[0u8; 4]);
            let _ = s.write_all(&paquete);
        }
    });
    puerto
}

// ---------------------------------------------------------------------------
// Servidor TLS simulado
// ---------------------------------------------------------------------------

struct ConfigTls {
    /// Grupos aceptados en orden de preferencia del servidor.
    grupos: &'static [u16],
    /// Versiones aceptadas sin `supported_versions` (0x0303 = TLS 1.2).
    heredadas: &'static [u16],
    tls13: bool,
    /// Elegir según el orden del cliente en lugar del propio.
    orden_cliente: bool,
}

struct Saludo {
    legado: u16,
    versiones: Vec<u16>,
    grupos: Vec<u16>,
}

fn leer_client_hello(s: &mut TcpStream) -> Option<Saludo> {
    let mut cab = [0u8; 5];
    s.read_exact(&mut cab).ok()?;
    let mut d = vec![0u8; u16::from_be_bytes([cab[3], cab[4]]) as usize];
    s.read_exact(&mut d).ok()?;
    let u16_en = |p: usize| u16::from_be_bytes([d[p], d[p + 1]]);
    let legado = u16_en(4);
    let mut p = 4 + 2 + 32;
    p += 1 + d[p] as usize;
    p += 2 + u16_en(p) as usize;
    p += 1 + d[p] as usize;
    let fin = p + 2 + u16_en(p) as usize;
    p += 2;
    let (mut versiones, mut grupos) = (Vec::new(), Vec::new());
    while p + 4 <= fin {
        let (tipo, largo) = (u16_en(p), u16_en(p + 2) as usize);
        let datos = &d[p + 4..p + 4 + largo];
        match tipo {
            0x000A => {
                grupos = datos[2..]
                    .chunks(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect()
            }
            0x002B => {
                versiones = datos[1..]
                    .chunks(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect()
            }
            _ => {}
        }
        p += 4 + largo;
    }
    Some(Saludo {
        legado,
        versiones,
        grupos,
    })
}

fn server_hello(version: u16, grupo: Option<u16>, hrr: bool) -> Vec<u8> {
    const HRR: [u8; 32] = [
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8,
        0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8,
        0x33, 0x9C,
    ];
    let mut cuerpo = if hrr {
        vec![0x03, 0x03]
    } else {
        version.to_be_bytes().to_vec()
    };
    cuerpo.extend_from_slice(if hrr { &HRR } else { &[9u8; 32] });
    cuerpo.push(0);
    cuerpo.extend_from_slice(if hrr {
        &[0x13, 0x01, 0]
    } else {
        &[0xC0, 0x2F, 0]
    });
    let mut ext = Vec::new();
    if hrr {
        ext.extend_from_slice(&[0x00, 0x2B, 0, 2, 0x03, 0x04]);
        if let Some(g) = grupo {
            ext.extend_from_slice(&[0x00, 0x33, 0, 2]);
            ext.extend_from_slice(&g.to_be_bytes());
        }
    }
    cuerpo.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    cuerpo.extend(ext);
    let mut hs = vec![0x02];
    hs.extend_from_slice(&(cuerpo.len() as u32).to_be_bytes()[1..]);
    hs.extend(cuerpo);
    let mut r = vec![0x16, 0x03, 0x03];
    r.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    r.extend(hs);
    r
}

fn servidor_tls(cfg: ConfigTls) -> u16 {
    servidor_tls_con(cfg, |_| true)
}

/// Lee una línea del cliente, byte a byte.
fn linea(s: &mut TcpStream) -> String {
    let mut l = Vec::new();
    let mut b = [0u8; 1];
    while s.read(&mut b).unwrap_or(0) == 1 {
        l.push(b[0]);
        if b[0] == b'\n' {
            break;
        }
    }
    String::from_utf8_lossy(&l).to_string()
}

fn preambulo_smtp(s: &mut TcpStream) -> bool {
    let _ = s.write_all(b"220-correo.ejemplo.mx ESMTP\r\n220 listo\r\n");
    if !linea(s).starts_with("EHLO") {
        return false;
    }
    let _ = s.write_all(b"250-correo.ejemplo.mx\r\n250-PIPELINING\r\n250 STARTTLS\r\n");
    if !linea(s).starts_with("STARTTLS") {
        return false;
    }
    s.write_all(b"220 2.0.0 Ready to start TLS\r\n").is_ok()
}

fn preambulo_smtp_sin_tls(s: &mut TcpStream) -> bool {
    let _ = s.write_all(b"220 viejo.ejemplo.mx ESMTP\r\n");
    let _ = linea(s);
    let _ = s.write_all(b"250-viejo.ejemplo.mx\r\n250 8BITMIME\r\n");
    false
}

fn preambulo_postgres(s: &mut TcpStream) -> bool {
    let mut b = [0u8; 8];
    s.read_exact(&mut b).is_ok()
        && b == [0, 0, 0, 8, 0x04, 0xD2, 0x16, 0x2F]
        && s.write_all(b"S").is_ok()
}

fn servidor_tls_con(cfg: ConfigTls, preambulo: fn(&mut TcpStream) -> bool) -> u16 {
    let escucha = TcpListener::bind("127.0.0.1:0").unwrap();
    let puerto = escucha.local_addr().unwrap().port();
    thread::spawn(move || {
        for s in escucha.incoming().flatten() {
            let mut s = s;
            if !preambulo(&mut s) {
                continue;
            }
            let Some(h) = leer_client_hello(&mut s) else {
                continue;
            };
            let respuesta = if h.versiones.contains(&0x0304) {
                let elegido = if cfg.orden_cliente {
                    h.grupos.iter().find(|g| cfg.grupos.contains(g))
                } else {
                    cfg.grupos.iter().find(|g| h.grupos.contains(g))
                };
                match elegido {
                    Some(g) if cfg.tls13 => server_hello(0x0304, Some(*g), true),
                    _ => vec![0x15, 3, 3, 0, 2, 2, 40],
                }
            } else if cfg.heredadas.contains(&h.legado) {
                server_hello(h.legado, None, false)
            } else {
                vec![0x15, 3, 3, 0, 2, 2, 70]
            };
            let _ = s.write_all(&respuesta);
        }
    });
    puerto
}

fn opciones() -> Opciones {
    Opciones {
        certificados: false,
        ..Opciones::default()
    }
}

fn sondear_clasificado(objetivo: &str) -> Inventario {
    let c = Conocimiento::embebido();
    let r = sondear(&[Objetivo::interpretar(objetivo).unwrap()], &c, &opciones());
    assert!(r.avisos.is_empty(), "avisos: {:?}", r.avisos);
    let mut inv = Inventario::default();
    inv.extender(r.activos);
    clasificar(&mut inv, &c);
    inv
}

fn protocolo(inv: &Inventario) -> &suaya_core::Activo {
    inv.activos
        .iter()
        .find(|a| a.referencia.starts_with("protocolo:"))
        .expect("protocolo")
}

// ---------------------------------------------------------------------------
// Pruebas
// ---------------------------------------------------------------------------

#[test]
fn ssh_con_hibrido() {
    let puerto = servidor_ssh("mlkem768x25519-sha256,curve25519-sha256,ext-info-s");
    let inv = sondear_clasificado(&format!("ssh://127.0.0.1:{puerto}"));
    let p = protocolo(&inv);
    assert_eq!(p.clasificacion.as_ref().unwrap().riesgo, Riesgo::HibridoPq);
    assert!(p.nombre.contains("OpenSSH_10.0"));
    assert!(
        inv.activos
            .iter()
            .any(|a| a.algoritmo_id() == Some("x25519-mlkem768"))
    );
    assert!(!inv.activos.iter().any(|a| a.nombre.contains("ext-info")));
}

#[test]
fn ssh_heredado_es_critico() {
    let puerto = servidor_ssh("curve25519-sha256,diffie-hellman-group1-sha1");
    let inv = sondear_clasificado(&format!("ssh://127.0.0.1:{puerto}"));
    assert_eq!(
        protocolo(&inv).clasificacion.as_ref().unwrap().riesgo,
        Riesgo::RotoClasico
    );
}

#[test]
fn tls_que_prefiere_hibrido() {
    let puerto = servidor_tls(ConfigTls {
        grupos: &[0x11EC, 0x001D, 0x0017],
        heredadas: &[],
        tls13: true,
        orden_cliente: false,
    });
    let inv = sondear_clasificado(&format!("tls://127.0.0.1:{puerto}"));
    let p = protocolo(&inv);
    assert_eq!(p.clasificacion.as_ref().unwrap().riesgo, Riesgo::HibridoPq);
    match &p.detalles {
        Detalles::Protocolo {
            versiones, grupos, ..
        } => {
            assert_eq!(versiones, &vec!["TLSv1.3".to_string()]);
            assert!(grupos.contains(&"x25519mlkem768".to_string()));
            assert_eq!(grupos.len(), 3);
        }
        _ => unreachable!(),
    }
    assert!(
        p.advertencias
            .iter()
            .any(|a| a.contains("Prioriza el grupo poscuántico"))
    );
}

#[test]
fn tls_que_acepta_pero_no_prefiere_hibrido() {
    let puerto = servidor_tls(ConfigTls {
        grupos: &[0x001D, 0x11EC],
        heredadas: &[0x0303],
        tls13: true,
        orden_cliente: false,
    });
    let inv = sondear_clasificado(&format!("tls://127.0.0.1:{puerto}"));
    let p = protocolo(&inv);
    assert_eq!(p.clasificacion.as_ref().unwrap().riesgo, Riesgo::HibridoPq);
    assert!(
        p.advertencias
            .iter()
            .any(|a| a.contains("el servidor elige x25519"))
    );
    assert!(
        p.advertencias
            .iter()
            .any(|a| a.contains("TLS 1.2 sigue habilitado"))
    );
}

#[test]
fn tls_heredado_obsoleto() {
    let puerto = servidor_tls(ConfigTls {
        grupos: &[],
        heredadas: &[0x0303, 0x0302, 0x0301],
        tls13: false,
        orden_cliente: false,
    });
    let inv = sondear_clasificado(&format!("tls://127.0.0.1:{puerto}"));
    let p = protocolo(&inv);
    let cl = p.clasificacion.as_ref().unwrap();
    assert_eq!(cl.riesgo, Riesgo::Obsoleto);
    assert!(
        p.advertencias
            .iter()
            .any(|a| a.contains("No ofrece TLS 1.3"))
    );
}

#[test]
fn servicio_inexistente_produce_aviso() {
    let libre = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let c = Conocimiento::embebido();
    let r = sondear(
        &[Objetivo::interpretar(&format!("tls://127.0.0.1:{libre}")).unwrap()],
        &c,
        &opciones(),
    );
    assert!(r.activos.is_empty());
    assert_eq!(r.avisos.len(), 1);
}

#[test]
fn tls_que_respeta_el_orden_del_cliente() {
    let puerto = servidor_tls(ConfigTls {
        grupos: &[0x001D, 0x11EC],
        heredadas: &[],
        tls13: true,
        orden_cliente: true,
    });
    let inv = sondear_clasificado(&format!("tls://127.0.0.1:{puerto}"));
    let p = protocolo(&inv);
    assert!(
        p.advertencias
            .iter()
            .any(|a| a.contains("Respeta el orden del cliente"))
    );
}

#[test]
fn tls_con_suite_3des_es_critico() {
    let puerto = servidor_tls_con_suite();
    let inv = sondear_clasificado(&format!("tls://127.0.0.1:{puerto}"));
    assert_eq!(
        protocolo(&inv).clasificacion.as_ref().unwrap().riesgo,
        Riesgo::RotoClasico
    );
}

/// Servidor TLS 1.2 que elige TLS_RSA_WITH_3DES_EDE_CBC_SHA.
fn servidor_tls_con_suite() -> u16 {
    let escucha = TcpListener::bind("127.0.0.1:0").unwrap();
    let puerto = escucha.local_addr().unwrap().port();
    thread::spawn(move || {
        for s in escucha.incoming().flatten() {
            let mut s = s;
            let Some(h) = leer_client_hello(&mut s) else {
                continue;
            };
            let r = if h.versiones.is_empty() && h.legado == 0x0303 {
                let mut r = server_hello(0x0303, None, false);
                // La suite está en: 5 (registro) + 4 (saludo) + 2 + 32 + 1 = 44.
                r[44] = 0x00;
                r[45] = 0x0A;
                r
            } else {
                vec![0x15, 3, 3, 0, 2, 2, 70]
            };
            let _ = s.write_all(&r);
        }
    });
    puerto
}

#[test]
fn starttls_smtp_y_postgres() {
    let cfg = || ConfigTls {
        grupos: &[0x11EC, 0x001D],
        heredadas: &[],
        tls13: true,
        orden_cliente: false,
    };
    let smtp = servidor_tls_con(cfg(), preambulo_smtp);
    let inv = sondear_clasificado(&format!("smtp://127.0.0.1:{smtp}"));
    let p = inv
        .activos
        .iter()
        .find(|a| a.nombre.starts_with("SMTP con STARTTLS"))
        .expect("protocolo SMTP");
    assert_eq!(p.clasificacion.as_ref().unwrap().riesgo, Riesgo::HibridoPq);
    assert!(p.ubicaciones[0].ruta.starts_with("smtp://"));

    let pg = servidor_tls_con(cfg(), preambulo_postgres);
    let inv = sondear_clasificado(&format!("postgres://127.0.0.1:{pg}"));
    assert!(
        inv.activos
            .iter()
            .any(|a| a.nombre.starts_with("PostgreSQL con STARTTLS"))
    );

    let viejo = servidor_tls_con(cfg(), preambulo_smtp_sin_tls);
    let inv = sondear_clasificado(&format!("smtp://127.0.0.1:{viejo}"));
    let p = inv
        .activos
        .iter()
        .find(|a| a.nombre.starts_with("SMTP sin TLS"))
        .expect("SMTP sin TLS");
    assert_eq!(
        p.clasificacion.as_ref().unwrap().riesgo,
        Riesgo::RotoClasico
    );
    assert!(p.advertencias.iter().any(|w| w.contains("sin cifrar")));
}
