//! Importación de CBOM CycloneDX arbitrarios.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use suaya_core::Conocimiento;

fuzz_target!(|datos: &[u8]| {
    static C: OnceLock<Conocimiento> = OnceLock::new();
    let c = C.get_or_init(Conocimiento::embebido);
    if let Ok(t) = std::str::from_utf8(datos) {
        let _ = suaya_escaneo::importar_cbom(t, "fuzz.json", c);
    }
});
