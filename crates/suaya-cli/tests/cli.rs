//! Pruebas de extremo a extremo del binario `suaya`: órdenes, archivos que
//! produce y códigos de salida, que forman parte del contrato de estabilidad
//! (docs/estabilidad.md).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn suaya() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_suaya"));
    c.env_remove("SUAYA_IDIOMA")
        .env_remove("SUAYA_CLAVE_FIRMA")
        .env("SUAYA_FECHA", "2026-10-16");
    c
}

fn demo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../pruebas/fixtures/sistema-demo")
}

fn directorio(nombre: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("suaya-cli-{}-{nombre}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn correr(c: &mut Command) -> Output {
    let s = c.output().expect("no se pudo ejecutar suaya");
    if !s.status.success() && s.status.code() == Some(1) {
        eprintln!("{}", String::from_utf8_lossy(&s.stderr));
    }
    s
}

#[test]
fn escanear_reportar_y_comparar() {
    let d = directorio("escanear");
    let cbom = d.join("demo.cbom.json");
    let s = correr(
        suaya()
            .arg("escanear")
            .arg(demo())
            .args(["-n", "Demo", "--perfil", "nist-ir-8547", "--anio", "2026"])
            .arg("-o")
            .arg(&cbom)
            .arg("-r")
            .arg(d.join("reporte.html")),
    );
    assert_eq!(s.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&cbom).unwrap()).unwrap();
    assert_eq!(v["bomFormat"], "CycloneDX");
    assert_eq!(v["specVersion"], "1.7");
    assert!(v["declarations"].is_object(), "falta la atestación CDXA");
    let html = std::fs::read_to_string(d.join("reporte.html")).unwrap();
    assert!(html.starts_with("<!doctype html>"));
    assert!(!html.contains("<script"));

    // Reporte desde el CBOM, en pantalla y en Markdown.
    let s = correr(suaya().arg("reporte").arg(&cbom));
    assert_eq!(s.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&s.stdout).contains("# "));

    // El sistema de demostración tiene hallazgos críticos: --fallar-en 1 da 2.
    let s = correr(
        suaya()
            .arg("escanear")
            .arg(demo())
            .arg("-o")
            .arg(d.join("otra.json"))
            .args(["--fallar-en", "1"]),
    );
    assert_eq!(s.status.code(), Some(2));

    // Comparar un CBOM consigo mismo no muestra regresión.
    let s = correr(
        suaya()
            .arg("comparar")
            .arg(&cbom)
            .arg(&cbom)
            .arg("--fallar-si-empeora"),
    );
    assert_ne!(s.status.code(), Some(1));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn llaves_firmar_y_verificar() {
    let d = directorio("firma");
    let cbom = d.join("x.cbom.json");
    let prefijo = d.join("prueba");
    let s = correr(
        suaya()
            .arg("escanear")
            .arg(demo().join("etc/pki"))
            .arg("-o")
            .arg(&cbom),
    );
    assert_eq!(s.status.code(), Some(0));
    let s = correr(
        suaya()
            .env("PRUEBA_CLAVE", "una frase de paso de prueba")
            .arg("llaves")
            .arg(&prefijo)
            .args(["--clave-env", "PRUEBA_CLAVE"]),
    );
    assert_eq!(s.status.code(), Some(0));
    let privada = d.join("prueba.privada.json");
    let publica = d.join("prueba.publica.json");
    let texto = std::fs::read_to_string(&privada).unwrap();
    assert!(
        texto.contains("\"cifrado\"") && !texto.contains("\"secreto\""),
        "la llave privada no quedó cifrada"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let modo = std::fs::metadata(&privada).unwrap().permissions().mode();
        assert_eq!(modo & 0o077, 0, "la llave privada es legible por otros");
    }
    // Sin la frase de paso no se puede firmar.
    let s = correr(
        suaya()
            .arg("firmar")
            .arg(&cbom)
            .arg("--llave")
            .arg(&privada),
    );
    assert_eq!(s.status.code(), Some(1));
    let s = correr(
        suaya()
            .env("SUAYA_CLAVE_FIRMA", "una frase de paso de prueba")
            .arg("firmar")
            .arg(&cbom)
            .arg("--llave")
            .arg(&privada),
    );
    assert_eq!(s.status.code(), Some(0));
    let s = correr(
        suaya()
            .arg("verificar")
            .arg(&cbom)
            .arg("--llave-publica")
            .arg(&publica),
    );
    assert_eq!(s.status.code(), Some(0));
    // Un solo byte cambiado invalida la firma: código 3.
    let mut b = std::fs::read(&cbom).unwrap();
    let i = b.len() / 2;
    b[i] ^= 1;
    std::fs::write(&cbom, &b).unwrap();
    let s = correr(
        suaya()
            .arg("verificar")
            .arg(&cbom)
            .arg("--llave-publica")
            .arg(&publica),
    );
    assert_eq!(s.status.code(), Some(3));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn ingles_y_ordenes_auxiliares() {
    let s = correr(suaya().args(["--idioma", "en", "--help"]));
    assert_eq!(s.status.code(), Some(0));
    let ayuda = String::from_utf8_lossy(&s.stdout);
    assert!(ayuda.contains("Usage:") && ayuda.contains("Exit codes"));

    let s = correr(suaya().env("SUAYA_IDIOMA", "en").arg("perfiles"));
    assert_eq!(s.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&s.stdout).contains("nist-ir-8547"));

    let s = correr(suaya().arg("conocimiento"));
    assert_eq!(s.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&s.stdout).contains("Algoritmos registrados"));

    let s = correr(suaya().arg("manual"));
    assert_eq!(s.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&s.stdout).contains(".TH"));

    for interprete in ["bash", "zsh", "fish", "powershell"] {
        let s = correr(suaya().args(["completado", interprete]));
        assert_eq!(s.status.code(), Some(0), "{interprete}");
        assert!(String::from_utf8_lossy(&s.stdout).contains("escanear"));
    }

    // Orden desconocida: error de uso (código 1, el 2 es del umbral).
    let s = correr(suaya().arg("no-existe"));
    assert_eq!(s.status.code(), Some(1));
    // Ruta inexistente: error controlado.
    let s = correr(suaya().args(["reporte", "/no/existe.json"]));
    assert_eq!(s.status.code(), Some(1));
}

#[test]
fn diagnosticar_puerto_cerrado_json_y_umbral() {
    let d = directorio("diagnosticar");
    let puerto = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let json = d.join("diagnostico.json");
    let objetivo = format!("tls://127.0.0.1:{puerto}");

    // Sin umbral, un hallazgo crítico no cambia el código de salida.
    let s = correr(suaya().args(["diagnosticar", &objetivo]));
    assert_eq!(s.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&s.stdout).contains("CON-TCP"));

    let s = correr(
        suaya()
            .args(["diagnose", &objetivo, "--fallar-en", "critico", "--json"])
            .arg(&json),
    );
    assert_eq!(s.status.code(), Some(2));
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&json).unwrap()).unwrap();
    let diag = &v["diagnosticos"][0];
    assert_eq!(diag["objetivo"], objetivo);
    assert_eq!(
        diag["conectividad"]["direcciones"][0]["estado"],
        "rechazado"
    );
    assert_eq!(diag["hallazgos"][0]["codigo"], "CON-TCP");
    assert_eq!(diag["hallazgos"][0]["nivel"], "critico");

    // Un nivel inválido es un error de uso.
    let s = correr(suaya().args(["diagnosticar", &objetivo, "--fallar-en", "grave"]));
    assert_eq!(s.status.code(), Some(1));
}
