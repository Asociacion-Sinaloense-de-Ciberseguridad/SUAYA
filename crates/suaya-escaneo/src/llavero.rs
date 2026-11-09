//! Certificados del llavero de macOS (`suaya escanear --llavero`): las raíces
//! del sistema y la lista de búsqueda del usuario (llavero de sesión y del
//! sistema).
//!
//! Se leen con `/usr/bin/security find-certificate -a -p`, que entrega solo
//! certificados públicos en PEM: Suaya no pide ni lee llaves privadas, y la
//! orden no pide la contraseña del llavero.

use suaya_core::{Activo, Conocimiento};

/// Tope de la salida de `security` por llavero.
#[cfg(target_os = "macos")]
const MAXIMO: u64 = 64 * 1024 * 1024;

/// (ubicación en el inventario, llavero; `None` es la lista de búsqueda).
#[cfg(target_os = "macos")]
const LLAVEROS: [(&str, Option<&str>); 2] = [
    (
        "llavero:raices-del-sistema",
        Some("/System/Library/Keychains/SystemRootCertificates.keychain"),
    ),
    ("llavero:usuario-y-sistema", None),
];

/// Certificados del llavero y avisos de lo que no se pudo leer.
#[cfg(target_os = "macos")]
pub fn escanear_llavero(c: &Conocimiento) -> (Vec<Activo>, Vec<String>) {
    use std::io::Read;
    use std::process::{Command, Stdio};

    let mut activos = Vec::new();
    let mut avisos = Vec::new();
    for (ubicacion, llavero) in LLAVEROS {
        let mut orden = Command::new("/usr/bin/security");
        orden.args(["find-certificate", "-a", "-p"]);
        if let Some(l) = llavero {
            orden.arg(l);
        }
        let mut hijo = match orden
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(h) => h,
            Err(e) => {
                avisos.push(format!("{ubicacion}: no se pudo ejecutar security: {e}"));
                continue;
            }
        };
        let mut salida = Vec::new();
        let leido = hijo
            .stdout
            .take()
            .map(|s| s.take(MAXIMO + 1).read_to_end(&mut salida));
        if salida.len() as u64 > MAXIMO {
            let _ = hijo.kill();
            avisos.push(format!("{ubicacion}: la salida de security excede 64 MiB"));
        }
        let _ = hijo.wait();
        if let Some(Err(e)) = leido {
            avisos.push(format!("{ubicacion}: {e}"));
            continue;
        }
        let texto = String::from_utf8_lossy(&salida);
        let a =
            crate::comun::Archivo::nuevo(ubicacion, std::path::Path::new(ubicacion), &salida, None);
        let (v, errores) = crate::pem::analizar_texto_pem(&texto, &a, None, c);
        activos.extend(v);
        avisos.extend(errores.into_iter().map(|e| format!("{ubicacion}: {e}")));
    }
    (activos, avisos)
}

/// Fuera de macOS no hay llavero que leer.
#[cfg(not(target_os = "macos"))]
pub fn escanear_llavero(_: &Conocimiento) -> (Vec<Activo>, Vec<String>) {
    (
        Vec::new(),
        vec!["--llavero: el llavero de certificados solo existe en macOS".into()],
    )
}
