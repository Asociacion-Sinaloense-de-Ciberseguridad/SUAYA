# SUAYA 1.5.0

Inventario criptográfico real, CBOM CycloneDX 1.7, evaluación poscuántica y firma híbrida ML-DSA-65 + Ed25519. Interfaz nativa macOS, CLI y API autenticada con SQLite.

Esta versión corrige los cinco hallazgos de la auditoría 1.4 e incorpora límites, trazabilidad y gates adicionales. Consulte [cierre 1.5](docs/cierre-1.5.md) y [operación 1.5](docs/operacion-1.5.md) para cambios de compatibilidad y validación. Los informes 1.3/1.4 se conservan como antecedentes; no describen el estado actual.

## Compilar y verificar

Rust 1.99.1 es el toolchain utilizado para validar esta entrega. En macOS se requieren las herramientas de Xcode. La GUI requiere macOS 13 o posterior; compilar en el sistema destino.

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --release --workspace --locked
python3 pruebas/test_release.py
```

## Interfaz macOS

Abra `build/SUAYA.app`. Seleccione un archivo o carpeta, ejecute el escaneo y exporte CBOM o HTML. Los resultados provienen del motor incluido en la aplicación. Cancelar o limpiar impide que una tarea antigua repueble el inventario.

```sh
./empaquetado/build-macos.sh
SUAYA_DMG=1 ./empaquetado/build-macos.sh
```

El paquete local tiene firma ad-hoc; la publicación pública requiere Developer ID y notarización del propietario. El build aborta ante cualquier error y nunca crea un stub.

## CLI

La entrega incluye `bin/suaya` y `bin/suaya-api` listos para macOS arm64. Las rutas `target/release/` de los ejemplos se usan al compilar desde fuentes; puede sustituirlas por `bin/`.

```sh
./target/release/suaya escanear pruebas/fixtures/sistema-demo -o inventario.json -r reporte.html
./target/release/suaya escanear /ruta/autorizada --fallar-si-incompleto --fallar-en 1 -o inventario.json
./target/release/suaya --help
```

Consulte `--help` para los valores concretos de `--fallar-en` y las órdenes `sondear`, `kubernetes`, `importar`, `reporte`, `comparar`, `llaves`, `firmar`, `verificar`, `perfiles` y `conocimiento`.

Los resultados parciales llevan `suaya:estado=partial`; sus reportes muestran una advertencia. `--fallar-si-incompleto` devuelve 4 si hay avisos o archivos omitidos. Los archivos de salida se reemplazan atómicamente con permisos privados. Los límites de recursos pueden producir un inventario parcial y no deben omitirse de la evaluación.

## API local con persistencia

```sh
python3 scripts/configurar-api.py --directory /ruta/privada/suaya-data --target demo=/ruta/autorizada --user administrador:admin --user analista:analyst
./target/release/suaya-api --config /ruta/privada/suaya-data/config.json --database /ruta/privada/suaya-data/scans.db
```

`configurar-api.py` genera tokens aleatorios de 48 bytes, almacena solo sus hashes en config.json y entrega los tokens en tokens.json (0600). El directorio requiere 0700. No incluya esos archivos en Git. Los tokens expiran, por defecto, a los 30 días. Para rotar o revocar, actualice los hashes/expiraciones y reinicie el proceso; no hay JWT ni cookies de sesión.

La API escucha únicamente en loopback (`127.0.0.1:8787`). Para acceso remoto necesita un proxy TLS, límites de conexiones y control de acceso propios. No habilite un proxy público sin configurar esos controles.

| Método/ruta | Función |
|---|---|
| GET /api/v1/health | Salud pública, sin datos del inventario |
| POST /api/v1/scan | JSON `{"target":"demo"}`; solo alias autorizados en config |
| GET /api/v1/scans | Resultados del propietario; admin puede ver todos |
| GET /api/v1/scan/{id} | CBOM del propietario o admin |
| DELETE /api/v1/scan/{id} | Borrado del propietario o admin |
| GET /api/v1/config | Alias y límites; solo admin; nunca hashes/tokens/rutas |

Todas las rutas salvo health requieren `Authorization: Bearer TOKEN`. Configuración inmutable desde HTTP. El usuario analista puede escanear cualquiera de los alias que el administrador configuró para esa instancia; separe instancias si los usuarios necesitan conjuntos de objetivos distintos. Límites: 4 KiB por request, 2 escaneos simultáneos, 60 requests/min por identidad, 600/min globales y 1000 resultados por usuario. La falta de acceso a un resultado ajeno devuelve 404.

## Automatización

```sh
python3 scripts/automatizar.py --binary ./target/release/suaya --target /ruta/autorizada --output /ruta/privada/resultados --interval 3600 --timeout 1800
```

Usa subprocess sin shell, sin ejecuciones solapadas, resultados separados y timeout. `--once` ejecuta una vez para launchd/systemd/CI. Los eventos distinguen completed, partial, failed y timeout. Configure rotación/retención de resultados según su política; el runner no elimina evidencia automáticamente.

## Alcance funcional real

Incluye escaneo de certificados, llaves, configuración TLS/SSH/VPN, código, bibliotecas, imágenes Docker/OCI, sondeos explícitos TLS/SSH/STARTTLS, Kubernetes y CBOM externos. El modelo conserva las prioridades críticas y las muestra en el resumen. RSA/ECC/DH no se consideran resistentes a ataques cuánticos por aumentar su tamaño.

No se ofrecen como funciones operativas PDF/Excel, auditoría IAM de nubes, HSM, timestamping confiable, actualizaciones automáticas, notificaciones Slack/email/Discord o un asistente LLM: las pantallas/stubs de 1.3 no implementaban esas capacidades. Esta entrega elimina tales promesas y no comunica éxito ficticio. La fecha firmada es una declaración del firmante, no una autoridad de tiempo.

Vea [cierre de correcciones](docs/cierre-1.4.md), [seguridad](SECURITY.md), [arquitectura](docs/arquitectura.md) y [manual CLI](docs/manual-cli.md).
