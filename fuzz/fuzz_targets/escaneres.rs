//! Cada escáner de Suaya ante contenido arbitrario. El primer byte elige el
//! nombre del archivo, de modo que el fuzzer explore todos los escáneres.
#![no_main]

use std::path::Path;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use suaya_core::Conocimiento;
use suaya_escaneo::{Archivo, Escaner, escaneres_predeterminados};

const NOMBRES: &[&str] = &[
    "a.pem", "id_ed25519.pub", "sshd_config", "nginx.conf", "haproxy.cfg", "postgresql.conf",
    "my.cnf", "main.cf", "java.security", "crypttab", "wg0.conf", "x.ovpn", "swanctl.conf",
    "x.p12", "secret.yaml", "x.py", "X.java", "x.go", "x.ts", "x.cs", "x.rs", "x.c", "go.mod",
    "Cargo.lock", "package-lock.json", "pom.xml", "requirements.txt", "release", "x.der",
    // 1.7
    "openssl.cnf", "krb5.conf", "x.reg", "main.tf", "plantilla.json", "x.bicep", "x.asc",
    "pubring.kbx", "x.jks", "x.jceks", "db.esl", "PK.auth", ".config", "x.ldif", "x.efi",
    "x.jar", "x.apk", "X.class", "server.properties", "application.yml", "server.xml",
    "mongod.conf", "redis.conf", "elasticsearch.yml", "rabbitmq.conf", "mosquitto.conf",
    "vault.hcl", "traefik.yml", "Caddyfile", "ldap.conf", "grafana.ini", "sqlnet.ora",
    "dovecot.conf", "Info.plist", "application.ini", "x.php", "x.rb", "x.swift", "x.dart",
    "x.ps1", "x.sh", "Dockerfile", "policies.json", "x.cbom.json",
];

struct Estado {
    c: Conocimiento,
    escaneres: Vec<Box<dyn Escaner>>,
}

fn estado() -> &'static Estado {
    static E: OnceLock<Estado> = OnceLock::new();
    E.get_or_init(|| Estado {
        c: Conocimiento::embebido(),
        escaneres: escaneres_predeterminados(),
    })
}

fuzz_target!(|datos: &[u8]| {
    let Some((&n, resto)) = datos.split_first() else {
        return;
    };
    let nombre = NOMBRES[n as usize % NOMBRES.len()];
    let e = estado();
    let a = Archivo::nuevo(nombre, Path::new(nombre), resto, Some(0o644));
    for s in &e.escaneres {
        if s.aplica(&a) {
            let _ = s.analizar(&a, &e.c);
        }
    }
});
