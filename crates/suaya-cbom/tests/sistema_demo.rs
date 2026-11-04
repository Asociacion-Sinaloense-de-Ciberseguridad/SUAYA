//! Prueba de extremo a extremo sobre el sistema de demostración
//! (`pruebas/fixtures/sistema-demo`, generado por `pruebas/generar-fixtures.sh`).

use std::path::PathBuf;

use suaya_cbom::{OpcionesCbom, comparar, generar, leer, reporte_markdown};
use suaya_core::{Accion, Activo, Conocimiento, Detalles, Riesgo};
use suaya_escaneo::{Opciones, Resultado, escanear};

fn demo() -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../pruebas/fixtures/sistema-demo"
    ))
}

fn escanear_demo() -> (Resultado, Conocimiento) {
    let c = Conocimiento::embebido();
    let r = escanear(&[demo()], &c, &Opciones::default());
    (r, c)
}

fn buscar(r: &Resultado, f: impl Fn(&Activo) -> bool) -> Vec<&Activo> {
    r.inventario.activos.iter().filter(|a| f(a)).collect()
}

fn en(a: &Activo, fragmento: &str) -> bool {
    a.ubicaciones.iter().any(|u| u.ruta.ends_with(fragmento))
}

fn riesgo(a: &Activo) -> Riesgo {
    a.clasificacion.as_ref().unwrap().riesgo
}

#[test]
fn escaneo_sin_avisos() {
    let (r, _) = escanear_demo();
    assert!(r.avisos.is_empty(), "avisos inesperados: {:?}", r.avisos);
    assert!(r.inventario.activos.len() >= 40);
}

#[test]
fn certificado_heredado_es_critico() {
    let (r, _) = escanear_demo();
    let cert = buscar(&r, |a| {
        matches!(a.detalles, Detalles::Certificado { .. }) && en(a, "legado/legado.crt")
    });
    assert_eq!(cert.len(), 1);
    let cl = cert[0].clasificacion.as_ref().unwrap();
    assert_eq!(cl.riesgo, Riesgo::RotoClasico);
    assert_eq!(cl.accion, Accion::CorregirYa);
    assert_eq!(cl.prioridad, 1);
}

#[test]
fn nginx_hibrido_y_certificado_enlazado() {
    let (r, _) = escanear_demo();
    let tls = buscar(&r, |a| {
        a.referencia.starts_with("protocolo:tls") && en(a, "nginx/nginx.conf")
    });
    assert_eq!(riesgo(tls[0]), Riesgo::HibridoPq);
    let cert_ref = tls[0]
        .relaciones
        .iter()
        .find(|x| x.tipo == "certificate")
        .expect("certificado enlazado");
    let cert = r
        .inventario
        .activos
        .iter()
        .find(|a| a.referencia == cert_ref.referencia)
        .unwrap();
    assert!(
        cert.contextos
            .iter()
            .any(|c| c.capacidad == "servidores-web")
    );
    assert!(
        cert.advertencias
            .iter()
            .any(|w| w.contains("Vigente hasta"))
    );
}

#[test]
fn apache_obsoleto() {
    let (r, _) = escanear_demo();
    let tls = buscar(&r, |a| {
        a.referencia.starts_with("protocolo:tls") && en(a, "apache2/ssl.conf")
    });
    assert_eq!(riesgo(tls[0]), Riesgo::Obsoleto);
    assert!(
        tls[0]
            .advertencias
            .iter()
            .any(|w| w.contains("no se encontró"))
    );
}

#[test]
fn ssh_moderno_y_heredado() {
    let (r, _) = escanear_demo();
    let moderno = buscar(&r, |a| {
        a.referencia.starts_with("protocolo:ssh") && en(a, "etc/ssh/sshd_config")
    });
    let heredado = buscar(&r, |a| {
        a.referencia.starts_with("protocolo:ssh") && en(a, "legado/ssh/sshd_config")
    });
    assert_eq!(riesgo(moderno[0]), Riesgo::HibridoPq);
    assert_eq!(riesgo(heredado[0]), Riesgo::RotoClasico);
}

#[test]
fn llaves() {
    let (r, _) = escanear_demo();
    let mldsa = buscar(&r, |a| {
        matches!(a.detalles, Detalles::Material { .. }) && en(a, "firma-mldsa65.pub.pem")
    });
    assert_eq!(riesgo(mldsa[0]), Riesgo::ResistenteCuantico);

    let cifrada = buscar(&r, |a| {
        matches!(a.detalles, Detalles::Material { .. }) && en(a, "srv/app-cifrada.key")
    });
    assert_eq!(riesgo(cifrada[0]), Riesgo::Desconocido);

    let ssh = buscar(&r, |a| {
        matches!(a.detalles, Detalles::Material { .. }) && en(a, ".ssh/id_rsa")
    });
    match &ssh[0].detalles {
        Detalles::Material {
            tamano,
            protegido_por,
            ..
        } => {
            assert_eq!(*tamano, Some(3072));
            assert!(protegido_por.is_some());
        }
        _ => unreachable!(),
    }
}

#[cfg(unix)]
#[test]
fn permisos_laxos() {
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("suaya-permisos-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    let key = root.join("app.key");
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../pruebas/fixtures/sistema-demo/srv/app.key");
    std::fs::copy(source, &key).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    let c = Conocimiento::embebido();
    let r = suaya_escaneo::escanear(std::slice::from_ref(&root), &c, &Default::default());
    std::fs::remove_dir_all(root).unwrap();
    let laxa = buscar(&r, |a| {
        matches!(a.detalles, Detalles::Material { .. }) && en(a, "app.key")
    });
    assert!(laxa[0].advertencias.iter().any(|w| w.contains("permisos")));
}

#[test]
fn volumenes() {
    let (r, _) = escanear_demo();
    let aes128 = buscar(&r, |a| a.algoritmo_id() == Some("aes-128-xts"));
    let aes256 = buscar(&r, |a| a.algoritmo_id() == Some("aes-256-xts"));
    assert_eq!(aes128.len(), 1);
    assert_eq!(aes256.len(), 1);
    let raiz = buscar(&r, |a| a.nombre == "Llave del volumen raiz");
    assert!(raiz[0].advertencias.iter().any(|w| w.contains("TPM2")));
}

/// Fragmentos secretos de todo el sistema de demostración: el cuerpo de cada
/// bloque PEM de llave privada, las llaves privadas de WireGuard y los campos
/// `tls.key` de los Secret de Kubernetes.
fn secretos(dir: &std::path::Path, v: &mut Vec<(String, String)>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            secretos(&p, v);
            continue;
        }
        let Ok(texto) = std::fs::read_to_string(&p) else {
            continue;
        };
        let nombre = p.display().to_string();
        let mut en_llave = false;
        for linea in texto.lines() {
            let l = linea.trim();
            if l.starts_with("-----BEGIN") {
                en_llave = l.contains("PRIVATE KEY");
            } else if l.starts_with("-----END") {
                en_llave = false;
            } else if en_llave && l.len() > 20 && !l.contains(':') {
                v.push((nombre.clone(), l.to_string()));
            }
            for prefijo in ["PrivateKey = ", "tls.key: ", "client-key-data: "] {
                if let Some(x) = l.strip_prefix(prefijo)
                    && x.len() > 20
                {
                    v.push((nombre.clone(), x.trim_matches('"').to_string()));
                }
            }
        }
    }
}

#[test]
fn el_cbom_y_los_reportes_no_contienen_material_secreto() {
    let (r, c) = escanear_demo();
    let mut fragmentos = Vec::new();
    secretos(&demo(), &mut fragmentos);
    assert!(
        fragmentos.len() > 50,
        "solo {} fragmentos",
        fragmentos.len()
    );
    let perfil = suaya_core::Perfil::cargar("nist-ir-8547").unwrap();
    for idioma in [
        suaya_core::idioma::Idioma::Es,
        suaya_core::idioma::Idioma::En,
    ] {
        suaya_core::idioma::con_idioma(idioma, || {
            let doc = generar(
                &r.inventario,
                &c,
                &OpcionesCbom {
                    nombre_sistema: Some("Demo".into()),
                    raices: vec![],
                    perfil: Some((
                        perfil.perfil.nombre.clone(),
                        perfil.perfil.referencia.clone(),
                    )),
                    declaraciones: Some((perfil.clone(), 2026)),
                },
            );
            let json = serde_json::to_string(&doc).unwrap();
            let leido = leer(&json).unwrap();
            let salidas = [
                json.clone(),
                reporte_markdown(&leido, &c),
                suaya_cbom::reporte_html(&leido, &c),
                format!("{:?}", r.avisos),
            ];
            for (archivo, f) in &fragmentos {
                for s in &salidas {
                    assert!(
                        !s.contains(f.as_str()),
                        "una salida contiene material de {archivo}"
                    );
                }
            }
        });
    }
}

#[test]
fn ida_y_vuelta_reporte_y_comparacion() {
    let (r, c) = escanear_demo();
    let doc = generar(
        &r.inventario,
        &c,
        &OpcionesCbom {
            nombre_sistema: Some("Demo".into()),
            raices: vec![],
            perfil: None,
            declaraciones: None,
        },
    );
    assert_eq!(doc["specVersion"], "1.7");
    let texto = serde_json::to_string(&doc).unwrap();
    let leido = leer(&texto).unwrap();
    assert_eq!(leido.registros.len(), r.inventario.activos.len());

    let md = reporte_markdown(&leido, &c);
    assert!(md.contains("Qué se puede migrar hoy"));
    assert!(!md.contains('\u{2014}'), "el reporte no debe usar raya");

    let d = comparar(&leido, &leido);
    assert!(d.nuevos.is_empty() && d.eliminados.is_empty() && d.cambiados.is_empty());
    assert!(!d.hay_regresion());
}

#[test]
fn llaves_enlazadas_con_su_certificado_en_todos_los_formatos() {
    let (r, _) = escanear_demo();
    let privada = |ruta: &str| {
        buscar(&r, |a| {
            matches!(&a.detalles, Detalles::Material { tipo_material, .. } if tipo_material == "private-key")
                && en(a, ruta)
        })
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("sin llave en {ruta}"))
    };
    // PKCS#8 EC, Ed25519 y RSA con su certificado; heredan el contexto.
    for (ruta, capacidad) in [
        ("etc/nginx/www.key", "servidores-web"),
        ("etc/pki/ca.key", "pki-ca"),
        ("legado/legado.key", "pki-ca"),
    ] {
        let k = privada(ruta);
        assert!(
            k.relaciones.iter().any(|x| x.tipo == "certificate"),
            "{ruta} sin certificado"
        );
        assert!(
            k.contextos.iter().all(|c| c.capacidad == capacidad),
            "{ruta}: {:?}",
            k.contextos
        );
    }
    // OpenSSH cifrada: su parte pública es visible y se enlaza con authorized_keys.
    assert!(
        privada(".ssh/id_rsa")
            .relaciones
            .iter()
            .any(|x| x.tipo == "publicKey")
    );
    // PKCS#8 y PKCS#1 de la misma llave: se detecta la copia.
    for ruta in ["srv/app.key", "legado/app-pkcs1.key"] {
        assert!(
            privada(ruta)
                .advertencias
                .iter()
                .any(|w| w.contains("misma llave privada"))
        );
    }
}

#[test]
fn haproxy_por_bind() {
    let (r, _) = escanear_demo();
    let bind = |nombre: &str| {
        buscar(&r, |a| {
            a.nombre.starts_with(&format!("HAProxy bind {nombre} "))
        })
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("sin bind {nombre}"))
    };
    let moderno = bind(":443");
    assert_eq!(riesgo(moderno), Riesgo::HibridoPq);
    assert!(
        moderno.relaciones.iter().any(|x| x.tipo == "certificate"),
        "crt de directorio sin enlazar"
    );
    assert_eq!(riesgo(bind(":8443")), Riesgo::Obsoleto);
}

#[test]
fn postgresql_con_y_sin_tls() {
    let (r, _) = escanear_demo();
    let pg = |ruta: &str| {
        buscar(&r, |a| a.nombre.starts_with("PostgreSQL") && en(a, ruta))
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("sin PostgreSQL en {ruta}"))
    };
    let moderno = pg("var/lib/pgsql/data/postgresql.conf");
    assert_eq!(riesgo(moderno), Riesgo::HibridoPq);
    assert!(moderno.relaciones.iter().any(|x| x.tipo == "certificate"));
    let sin_tls = pg("legado/pgsql/postgresql.conf");
    assert_eq!(riesgo(sin_tls), Riesgo::RotoClasico);
    assert!(
        sin_tls
            .advertencias
            .iter()
            .any(|w| w.contains("sin cifrar"))
    );
}

fn protocolo_llamado<'a>(r: &'a Resultado, prefijo: &str, ruta: &str) -> &'a Activo {
    buscar(r, |a| a.nombre.starts_with(prefijo) && en(a, ruta))
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("sin {prefijo} en {ruta}"))
}

#[test]
fn secretos_de_kubernetes_y_kubeconfig() {
    let (r, _) = escanear_demo();
    let llave_secret = buscar(&r, |a| {
        matches!(&a.detalles, Detalles::Material { tipo_material, .. } if tipo_material == "private-key")
            && en(a, "k8s/secret-tienda.yaml")
    });
    assert_eq!(llave_secret.len(), 1);
    assert!(
        llave_secret[0]
            .advertencias
            .iter()
            .any(|w| w.contains("Secret de Kubernetes (campo «tls.key»)"))
    );
    assert!(
        llave_secret[0]
            .relaciones
            .iter()
            .any(|x| x.tipo == "certificate")
    );

    let llave_kube = buscar(&r, |a| {
        matches!(&a.detalles, Detalles::Material { tipo_material, .. } if tipo_material == "private-key")
            && en(a, ".kube/config")
    });
    assert!(
        llave_kube[0]
            .advertencias
            .iter()
            .any(|w| w.contains("kubeconfig"))
    );
}

#[test]
fn cert_manager_declara_el_algoritmo_futuro() {
    let (r, _) = escanear_demo();
    let intranet = buscar(&r, |a| {
        a.nombre
            .starts_with("Llave de cert-manager interno/intranet")
    });
    assert_eq!(intranet.len(), 1, "falta el Certificate sin privateKey");
    assert!(
        intranet[0].nombre.contains("RSA-2048"),
        "{}",
        intranet[0].nombre
    );
    assert!(
        intranet[0]
            .advertencias
            .iter()
            .any(|w| w.contains("rotationPolicy"))
    );
    let tienda = buscar(&r, |a| {
        a.nombre.starts_with("Llave de cert-manager tienda/tienda")
    });
    assert!(tienda[0].nombre.contains("P-256"));
}

#[test]
fn vpn() {
    let (r, _) = escanear_demo();
    let wg = protocolo_llamado(&r, "WireGuard", "etc/wireguard/wg0.conf");
    assert_eq!(riesgo(wg), Riesgo::VulnerableCuantico);
    assert!(wg.advertencias.iter().any(|w| w.contains("1 de 2 pares")));
    assert_eq!(
        riesgo(protocolo_llamado(&r, "OpenVPN", "etc/openvpn/server.conf")),
        Riesgo::HibridoPq
    );
    assert_eq!(
        riesgo(protocolo_llamado(&r, "OpenVPN", "legado/vpn/cliente.ovpn")),
        Riesgo::RotoClasico
    );
    assert_eq!(
        riesgo(protocolo_llamado(
            &r,
            "strongSwan",
            "etc/swanctl/swanctl.conf"
        )),
        Riesgo::HibridoPq
    );
    let ikev1 = protocolo_llamado(&r, "strongSwan", "legado/vpn/ipsec.conf");
    assert_eq!(riesgo(ikev1), Riesgo::RotoClasico);
    assert!(ikev1.advertencias.iter().any(|w| w.contains("IKEv1")));
}

#[test]
fn imagen_de_contenedor_con_secreto_borrado() {
    let c = Conocimiento::embebido();
    let imagen = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../pruebas/fixtures/imagenes/tienda-docker.tar"
    ));
    let r = suaya_escaneo::escanear_con_imagenes(&[], &[imagen], &c, &Opciones::default());
    let llave = buscar(
        &r,
        |a| matches!(&a.detalles, Detalles::Material { tipo_material, .. } if tipo_material == "private-key"),
    );
    assert_eq!(llave.len(), 1);
    assert!(
        llave[0].ubicaciones[0]
            .ruta
            .contains("@capa1:/etc/ssl/private/tienda.key")
    );
    assert!(
        llave[0]
            .advertencias
            .iter()
            .any(|w| w.contains("sigue dentro de la imagen (capa 1)"))
    );
    // La configuración de nginx de la capa 2 se enlaza con el certificado de la capa 1.
    let tls = buscar(&r, |a| a.referencia.starts_with("protocolo:tls"));
    assert_eq!(riesgo(tls[0]), Riesgo::HibridoPq);
    assert!(tls[0].relaciones.iter().any(|x| x.tipo == "certificate"));
}

#[test]
fn perfiles_de_politica() {
    use suaya_core::{EstadoCumplimiento, Perfil};
    let estado = |r: &Resultado, nombre: &str| {
        r.inventario
            .activos
            .iter()
            .find(|a| a.nombre == nombre)
            .and_then(|a| a.cumplimiento.as_ref())
            .unwrap_or_else(|| panic!("sin cumplimiento para {nombre}"))
            .clone()
    };

    // NIST IR 8547: lo vulnerable al cuántico entra en transición.
    let (mut r, c) = escanear_demo();
    let nist = Perfil::cargar("nist-ir-8547").unwrap();
    nist.evaluar(&mut r.inventario, &c, 2026);
    assert!(
        r.inventario
            .activos
            .iter()
            .all(|a| a.cumplimiento.is_some())
    );
    assert_eq!(
        estado(&r, "RSA-1024").estado,
        EstadoCumplimiento::NoConforme
    );
    let x = estado(&r, "X25519");
    assert_eq!(x.estado, EstadoCumplimiento::Transicion);
    assert_eq!((x.retiro, x.prohibicion), (Some(2030), Some(2035)));

    // CNSA 2.0: X25519 no forma parte de la suite; P-384 sí está en transición.
    let (mut r, c) = escanear_demo();
    let cnsa = Perfil::cargar("cnsa-2.0").unwrap();
    cnsa.evaluar(&mut r.inventario, &c, 2026);
    assert_eq!(estado(&r, "X25519").estado, EstadoCumplimiento::NoConforme);
    assert_eq!(
        estado(&r, "Curva NIST P-384").estado,
        EstadoCumplimiento::Transicion
    );

    // El cumplimiento viaja en el CBOM y llega al reporte.
    let doc = generar(
        &r.inventario,
        &c,
        &OpcionesCbom {
            nombre_sistema: None,
            raices: vec![],
            perfil: Some((cnsa.perfil.nombre.clone(), cnsa.perfil.referencia.clone())),
            declaraciones: Some((cnsa.clone(), 2026)),
        },
    );
    // Atestación CDXA: un requisito por regla, con afirmación y evidencia.
    let requisitos = doc["definitions"]["standards"][0]["requirements"]
        .as_array()
        .unwrap();
    assert_eq!(requisitos.len(), cnsa.reglas.len());
    let mapa = doc["declarations"]["attestations"][0]["map"]
        .as_array()
        .unwrap();
    assert_eq!(mapa.len(), requisitos.len());
    // La regla de lo roto u obsoleto alcanza activos: su conformidad es 0.
    assert_eq!(mapa[0]["conformance"]["score"], 0.0);
    let leido = leer(&serde_json::to_string(&doc).unwrap()).unwrap();
    assert!(leido.perfil.is_some());
    let md = reporte_markdown(&leido, &c);
    assert!(md.contains("## Cumplimiento con CNSA 2.0"));
    assert!(md.contains("Calendario de migración"));

    // Un perfil propio en TOML se carga desde archivo; uno inexistente falla.
    assert!(Perfil::cargar("no-existe").is_err());
    assert_eq!(Perfil::incluidos().len(), 3);
}

#[test]
fn mysql_y_postfix() {
    let (r, _) = escanear_demo();
    let tiene = |a: &Activo, t: &str| a.advertencias.iter().any(|w| w.contains(t));

    let mysql = protocolo_llamado(&r, "MySQL", "etc/mysql/mysql.conf.d/mysqld.cnf");
    // Sin grupos declarados el riesgo depende de OpenSSL: se pide verificar.
    assert_eq!(riesgo(mysql), Riesgo::Desconocido);
    assert!(mysql.relaciones.iter().any(|x| x.tipo == "certificate"));
    assert!(!tiene(mysql, "require_secure_transport"));
    let mysql_viejo = protocolo_llamado(&r, "MySQL", "legado/mysql/my.cnf");
    assert_eq!(riesgo(mysql_viejo), Riesgo::Obsoleto);
    assert!(tiene(mysql_viejo, "require_secure_transport"));
    assert!(tiene(mysql_viejo, "autofirmado"));

    let postfix = protocolo_llamado(&r, "Postfix", "etc/postfix/main.cf");
    assert_eq!(riesgo(postfix), Riesgo::HibridoPq);
    assert!(tiene(postfix, "oportunista"));
    assert!(!tiene(postfix, "envío saliente"));
    assert!(postfix.relaciones.iter().any(|x| x.tipo == "certificate"));
    let postfix_viejo = protocolo_llamado(&r, "Postfix", "legado/postfix/main.cf");
    assert_eq!(riesgo(postfix_viejo), Riesgo::RotoClasico);
    assert!(tiene(postfix_viejo, "STARTTLS"));
}

#[test]
fn politica_de_java() {
    let (r, _) = escanear_demo();
    let tiene = |a: &Activo, t: &str| a.advertencias.iter().any(|w| w.contains(t));
    let actual = protocolo_llamado(&r, "Java", "etc/java-21-openjdk/security/java.security");
    assert_eq!(riesgo(actual), Riesgo::Desconocido);
    assert!(!tiene(actual, "ya no excluye"));
    let recortada = protocolo_llamado(&r, "Java", "legado/java/java.security");
    assert_eq!(riesgo(recortada), Riesgo::RotoClasico);
    assert!(tiene(recortada, "3DES_EDE_CBC"));
    assert!(tiene(recortada, "JKS"));
}

#[test]
fn codigo_fuente() {
    let (r, _) = escanear_demo();
    let alg = |nombre: &str| {
        buscar(&r, |a| a.nombre == nombre)
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("sin {nombre}"))
    };
    let lineas = |a: &Activo, archivo: &str| -> Vec<u32> {
        a.ubicaciones
            .iter()
            .filter(|u| u.ruta.ends_with(archivo))
            .filter_map(|u| u.linea)
            .collect()
    };
    // Lo que aparece solo en comentarios no cuenta.
    assert!(lineas(alg("MD5"), "pagos.py") == vec![7]);
    assert!(
        !alg("MD5")
            .ubicaciones
            .iter()
            .any(|u| u.ruta.ends_with("main.go"))
    );
    assert!(lineas(alg("SHA-1"), "pagos.py").is_empty());
    assert_eq!(riesgo(alg("RSA-1024")), Riesgo::RotoClasico);
    // «AES» sin modo en Java es ECB.
    assert!(!lineas(alg("Modo de operación ECB"), "Firma.java").is_empty());
    // RSA con tamaño desplaza al genérico del mismo archivo.
    assert!(!lineas(alg("RSA-2048"), "Firma.java").is_empty());
    assert!(
        buscar(&r, |a| a.nombre == "RSA" && en(a, "Firma.java")).is_empty(),
        "el RSA sin tamaño sobra"
    );
    for archivo in ["main.go", "Cifrado.cs", "firma.rs", "Firma.java"] {
        assert!(!lineas(alg("ML-KEM-768"), archivo).is_empty(), "{archivo}");
    }
    assert_eq!(riesgo(alg("X25519MLKEM768 (híbrido)")), Riesgo::HibridoPq);
    let tls = protocolo_llamado(&r, "TLS en código", "srv/app/cliente.ts");
    assert_eq!(riesgo(tls), Riesgo::RotoClasico);
    assert!(
        tls.advertencias
            .iter()
            .any(|w| w.contains("rejectUnauthorized"))
    );
    assert!(
        alg("MD5")
            .contextos
            .iter()
            .any(|x| x.capacidad == "codigo-aplicacion")
    );
}

#[test]
fn bibliotecas_criptograficas() {
    let (r, _) = escanear_demo();
    let biblioteca = |nombre: &str| {
        buscar(&r, |a| a.nombre == nombre)
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("sin {nombre}"))
    };
    // Fin de soporte en el pasado: no depende de la fecha del escaneo.
    let vieja = biblioteca("OpenSSL 1.1.1w");
    assert_eq!(riesgo(vieja), Riesgo::Obsoleto);
    assert!(en(vieja, "srv/bin/herramienta"));
    assert_eq!(riesgo(biblioteca("OpenSSL 3.3.1")), Riesgo::Obsoleto);
    assert_eq!(riesgo(biblioteca("PyCrypto 2.6.1")), Riesgo::Obsoleto);
    assert_eq!(
        riesgo(biblioteca("Bouncy Castle (Java) 1.78.1")),
        Riesgo::VulnerableCuantico
    );
    assert_eq!(
        riesgo(biblioteca("Go (biblioteca estándar) 1.22")),
        Riesgo::Obsoleto
    );
    assert_eq!(
        riesgo(biblioteca("@noble/post-quantum 0.4.1")),
        Riesgo::ResistenteCuantico
    );
    match &biblioteca("Bouncy Castle (Java) 1.80").detalles {
        Detalles::Biblioteca { purl, .. } => assert_eq!(
            purl.as_deref(),
            Some("pkg:maven/org.bouncycastle/bcprov-jdk18on@1.80")
        ),
        otro => panic!("{otro:?}"),
    }
    // Las bibliotecas viajan en el CBOM como componentes «library».
    let c = Conocimiento::embebido();
    let doc = generar(&r.inventario, &c, &OpcionesCbom::default());
    let bibliotecas = doc["components"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| x["type"] == "library")
        .count();
    assert!(bibliotecas >= 10, "{bibliotecas}");
    let leido = leer(&serde_json::to_string(&doc).unwrap()).unwrap();
    assert!(leido.registros.iter().any(|x| x.tipo_activo == "library"));
}

#[test]
fn importacion_de_cbom_externo_y_propio() {
    let c = Conocimiento::embebido();
    let texto = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../pruebas/fixtures/cbom-externo/cbomkit.json"
    ))
    .unwrap();
    let r = suaya_escaneo::importar_cbom(&texto, "cbomkit.json", &c).unwrap();
    assert_eq!(r.herramienta, "CBOMkit");
    let mut inv = suaya_core::Inventario::default();
    inv.extender(r.activos);
    suaya_core::clasificar(&mut inv, &c);
    let riesgo_de = |n: &str| {
        inv.activos
            .iter()
            .find(|a| a.nombre == n)
            .unwrap_or_else(|| panic!("sin {n}"))
            .clasificacion
            .as_ref()
            .unwrap()
            .riesgo
    };
    assert_eq!(riesgo_de("RSA-2048"), Riesgo::VulnerableCuantico);
    assert_eq!(riesgo_de("AES-128-GCM"), Riesgo::DebilitadoGrover);
    assert_eq!(riesgo_de("SHA-1"), Riesgo::Obsoleto);
    assert_eq!(riesgo_de("TLSv1.2"), Riesgo::VulnerableCuantico);
    assert_eq!(riesgo_de("Rabbit"), Riesgo::Desconocido);
    assert_eq!(
        riesgo_de("Bouncy Castle (Java) 1.77"),
        Riesgo::VulnerableCuantico
    );
    let tls = inv.activos.iter().find(|a| a.nombre == "TLSv1.2").unwrap();
    assert!(
        tls.relaciones
            .iter()
            .any(|x| x.referencia == "algoritmo:aes-128-gcm")
    );
    assert!(tls.advertencias.iter().any(|w| w.contains("CBOMkit")));

    // El CBOM de Suaya también se reimporta sin perder algoritmos.
    let (demo, _) = escanear_demo();
    let doc = generar(&demo.inventario, &c, &OpcionesCbom::default());
    let r = suaya_escaneo::importar_cbom(&doc.to_string(), "propio.json", &c).unwrap();
    let algoritmos = |v: &[Activo]| -> std::collections::BTreeSet<String> {
        v.iter()
            .filter(|a| a.referencia.starts_with("algoritmo:"))
            .map(|a| a.referencia.clone())
            .collect()
    };
    assert_eq!(algoritmos(&r.activos), algoritmos(&demo.inventario.activos));
}

#[test]
fn reporte_y_cbom_en_ingles() {
    use suaya_core::idioma::{Idioma, con_idioma};
    let (mut r, c) = escanear_demo();
    let perfil = suaya_core::Perfil::cargar("nist-ir-8547").unwrap();
    perfil.evaluar(&mut r.inventario, &c, 2026);
    let doc = con_idioma(Idioma::En, || {
        generar(
            &r.inventario,
            &c,
            &OpcionesCbom {
                nombre_sistema: Some("Demo".into()),
                raices: vec![],
                perfil: Some((
                    perfil.perfil.nombre.clone(),
                    perfil.perfil.referencia.clone(),
                )),
                declaraciones: Some((perfil.clone(), 2026)),
            },
        )
    });
    // Ningún texto de hallazgo queda en español.
    let espanol = |t: &str| {
        t.chars().any(|ch| "áéíóúñ¿¡«»".contains(ch))
            || [
                " el ", " la ", " los ", " las ", " del ", " con ", " para ", " que ",
            ]
            .iter()
            .any(|p| format!(" {t} ").contains(p))
    };
    let mut pendientes = Vec::new();
    for comp in doc["components"].as_array().unwrap() {
        let mut textos = vec![comp["name"].as_str().unwrap_or("").to_string()];
        for p in comp["properties"].as_array().into_iter().flatten() {
            if matches!(
                p["name"].as_str(),
                Some(
                    "suaya:advertencia"
                        | "suaya:justificacion"
                        | "suaya:nota"
                        | "suaya:cumplimiento-nota"
                )
            ) {
                textos.push(p["value"].as_str().unwrap_or("").to_string());
            }
        }
        for t in textos {
            if espanol(&t) {
                pendientes.push(t);
            }
        }
    }
    pendientes.sort();
    pendientes.dedup();
    assert!(
        pendientes.is_empty(),
        "sin traducir:\n{}",
        pendientes.join("\n")
    );

    let leido = leer(&doc.to_string()).unwrap();
    let html = con_idioma(Idioma::En, || suaya_cbom::reporte_html(&leido, &c));
    assert!(html.contains(r#"<html lang="en">"#) && html.contains("Executive summary"));
    let md = con_idioma(Idioma::En, || reporte_markdown(&leido, &c));
    assert!(md.contains("## Findings that require action"));
    let lineas: Vec<&str> = md.lines().filter(|l| espanol(l)).collect();
    assert!(
        lineas.is_empty(),
        "el reporte en inglés tiene español:\n{}",
        lineas.join("\n")
    );
}

#[test]
fn el_resultado_no_depende_del_numero_de_hilos() {
    let c = Conocimiento::embebido();
    let con = |hilos| {
        let r = escanear(
            &[demo()],
            &c,
            &Opciones {
                hilos,
                ..Opciones::default()
            },
        );
        (
            serde_json::to_string(&r.inventario.activos).unwrap(),
            r.avisos,
            r.archivos_revisados,
        )
    };
    let uno = con(1);
    assert_eq!(uno, con(4));
    assert_eq!(uno, con(0));
}
