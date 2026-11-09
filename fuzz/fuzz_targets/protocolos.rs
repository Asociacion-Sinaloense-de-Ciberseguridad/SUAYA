//! Respuestas de red arbitrarias: HTTP, saludos TLS, KEXINIT de SSH, IKEv2,
//! DNS, DKIM, metadatos SAML y JWKS.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|datos: &[u8]| {
    let _ = suaya_red::http::interpretar_respuesta(datos);
    let _ = suaya_red::leer_respuesta(&mut std::io::Cursor::new(datos));
    let _ = suaya_red::KexInit::desde_carga(datos);
    suaya_red::fuzz::analizadores(datos);
    if let Ok(t) = std::str::from_utf8(datos) {
        let _ = suaya_red::Objetivo::interpretar(t);
        let _ = suaya_red::registro::Referencia::interpretar(t);
    }
});
