# Fuzzing de Suaya

Objetivos para [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (requiere el compilador nightly):

| Objetivo | Qué ejercita |
|---|---|
| `escaneres` | Todos los escáneres de archivos con contenido arbitrario; el primer byte elige el nombre del archivo |
| `importar_cbom` | La importación de CBOM CycloneDX de otras herramientas |
| `protocolos` | Respuestas HTTP, saludos TLS, `KEXINIT` de SSH, objetivos y referencias de imagen |

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run escaneres -- -max_total_time=600
```

Como complemento estable, `cargo test` ejecuta pruebas de robustez con mutaciones deterministas de los archivos del sistema de demostración (`crates/*/tests/robustez.rs`); `SUAYA_RONDAS=400 cargo test --release --test robustez` amplía la búsqueda.
