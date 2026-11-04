//! Robustez de los escáneres ante entradas dañadas o maliciosas.
//!
//! Toma cada archivo del sistema de demostración, lo muta de muchas formas
//! (bytes cambiados, cortes, marcas insertadas, basura aleatoria) y exige
//! que ningún escáner entre en pánico. Es un complemento estable de los
//! objetivos de `fuzz/`, que requieren el compilador nightly. Con
//! `SUAYA_RONDAS` se aumenta el número de mutaciones por archivo.

use std::path::{Path, PathBuf};

use suaya_core::Conocimiento;
use suaya_escaneo::{Archivo, escaneres_predeterminados};

/// Generador determinista (xorshift64*), para que un fallo sea reproducible.
struct Azar(u64);

impl Azar {
    fn siguiente(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn hasta(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.siguiente() % n as u64) as usize
        }
    }
}

const MARCAS: &[&[u8]] = &[
    b"-----BEGIN CERTIFICATE-----\n",
    b"-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n",
    b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjE=\n",
    b"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t",
    b"ssl_protocols TLSv1 TLSv1.3;\nssl_ecdh_curve X25519MLKEM768;\n",
    b"[Interface]\nPrivateKey = \n[Peer]\n",
    b"\x7fELF\x02\x01OpenSSL 3.0.13 30 Jan 2024\x00",
    b"\xff Go buildinf:\x08\x02go1.22\x00dep\tgolang.org/x/crypto\tv0.1.0\n",
    b"kind: Certificate\napiVersion: cert-manager.io/v1\n",
    b"jdk.tls.disabledAlgorithms=SSLv3, \\\n",
    b"[mysqld]\ntls_version=\n",
    b"hashlib.md5( Cipher.getInstance(\"AES/ECB\") rsa.GenerateKey(r, 1024)",
    b"\"\"\"",
    b"/*",
    b"r#\"",
    b"'",
    b"`",
    b"\\",
];

fn mutar(r: &mut Azar, base: &[u8]) -> Vec<u8> {
    let mut v = base.to_vec();
    for _ in 0..1 + r.hasta(6) {
        match r.hasta(6) {
            0 if !v.is_empty() => {
                let i = r.hasta(v.len());
                v[i] = r.siguiente() as u8;
            }
            1 if !v.is_empty() => {
                let i = r.hasta(v.len());
                v.truncate(i);
            }
            2 => {
                let i = r.hasta(v.len() + 1);
                let m = MARCAS[r.hasta(MARCAS.len())];
                v.splice(i..i, m.iter().copied());
            }
            3 if v.len() > 2 => {
                let a = r.hasta(v.len());
                let b = r.hasta(v.len());
                v.drain(a.min(b)..a.max(b));
            }
            4 => {
                for _ in 0..r.hasta(64) {
                    v.push(r.siguiente() as u8);
                }
            }
            _ => {
                let i = r.hasta(v.len() + 1);
                let n = r.hasta(40);
                v.splice(i..i, std::iter::repeat_n(b'=', n));
            }
        }
    }
    v
}

fn archivos(dir: &Path, v: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            archivos(&p, v);
        } else if p.metadata().map(|m| m.len() < 512 * 1024).unwrap_or(false) {
            v.push(p);
        }
    }
}

fn rondas() -> usize {
    std::env::var("SUAYA_RONDAS")
        .ok()
        .and_then(|x| x.parse().ok())
        .unwrap_or(12)
}

#[test]
fn ningun_escaner_entra_en_panico() {
    let c = Conocimiento::embebido();
    let escaneres = escaneres_predeterminados();
    let mut rutas = Vec::new();
    archivos(
        Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../pruebas/fixtures/sistema-demo"
        )),
        &mut rutas,
    );
    rutas.sort();
    assert!(rutas.len() > 40);
    let mut r = Azar(0x5EED_5AFE_C0DE_2026);
    for ruta in &rutas {
        let base = std::fs::read(ruta).unwrap();
        let texto = ruta.display().to_string();
        for _ in 0..rondas() {
            let mutado = mutar(&mut r, &base);
            let a = Archivo::nuevo(&texto, ruta, &mutado, Some(0o644));
            for e in &escaneres {
                if e.aplica(&a) {
                    let _ = e.analizar(&a, &c);
                }
            }
        }
    }
    // Basura con nombres que activan cada escáner.
    for nombre in [
        "a.pem",
        "id_ed25519.pub",
        "sshd_config",
        "nginx.conf",
        "haproxy.cfg",
        "postgresql.conf",
        "my.cnf",
        "main.cf",
        "java.security",
        "crypttab",
        "wg0.conf",
        "x.ovpn",
        "swanctl.conf",
        "x.p12",
        "secret.yaml",
        "x.py",
        "X.java",
        "x.go",
        "x.ts",
        "x.cs",
        "x.rs",
        "x.c",
        "go.mod",
        "Cargo.lock",
        "package-lock.json",
        "pom.xml",
        "requirements.txt",
        "release",
        "bcprov-jdk18on-1.78.jar",
    ] {
        for _ in 0..rondas() * 4 {
            let n = r.hasta(2048);
            let mut b: Vec<u8> = (0..n).map(|_| r.siguiente() as u8).collect();
            if r.hasta(2) == 0 {
                let m = MARCAS[r.hasta(MARCAS.len())];
                let i = r.hasta(b.len() + 1);
                b.splice(i..i, m.iter().copied());
            }
            let a = Archivo::nuevo(nombre, Path::new(nombre), &b, None);
            for e in &escaneres {
                if e.aplica(&a) {
                    let _ = e.analizar(&a, &c);
                }
            }
        }
    }
}

#[test]
fn importar_cbom_danado_no_entra_en_panico() {
    let c = Conocimiento::embebido();
    let base = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../pruebas/fixtures/cbom-externo/cbomkit.json"
    ))
    .unwrap();
    let mut r = Azar(42);
    for _ in 0..rondas() * 50 {
        let m = mutar(&mut r, &base);
        let _ = suaya_escaneo::importar_cbom(&String::from_utf8_lossy(&m), "x.json", &c);
    }
}
