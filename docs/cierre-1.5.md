# Cierre de correcciones SUAYA 1.5.0

Fecha: 20 de octubre de 2026, America/Mazatlan. Entrega local macOS Apple Silicon basada en v1.4. Las versiones anteriores se conservan intactas. El usuario autorizó aplicar el plan de la auditoría 1.4. Este cierre acredita cambios y pruebas locales; no es una certificación ni una nueva auditoría independiente.

## Matriz de cierre

| ID de auditoría 1.4 | Cambio aplicado | Validación |
|---|---|---|
| SEC-001 | Rechazo de 401 tras redirección a otro origen; realms externos autorizados por registro; scope pull; autorización incorporada Docker Hub | Regresión de tres orígenes, rechazo de realm directo no autorizado y aceptación de allowlist explícita; registro simulado existente |
| SEC-004 | IpAddr::is_loopback en registro y selección de proxy; TLS por defecto; HTTP local explícito; localhost resuelto solo a loopback; sin downgrade TLS | Test unitario original y matriz de 256 dominios con prefijo 127; pruebas de registros |
| SEC-002 | Buckets tipados e independientes para anónimos e identidades; conteo saturado y cardinalidad acotada por credenciales | 650 solicitudes anónimas no bloquean usuarios válidos; cuotas individuales y cabeceras |
| SEC-003 | Verificación de presencia y duplicados de capas; tipos válidos; digests SHA-256 de manifiestos y capas OCI y tamaños de capas; descriptor regular y límites | Regresión de capa ausente; cuatro pruebas adicionales con subcasos Docker/OCI válidos, duplicados, tipos inválidos, capa ausente y digest manipulado |
| SEC-005 | Directorio temporal 0700 sin ACL heredada, archivo 0600 y rename atómico; no se copian metadatos públicos del destino | Bloque real Swift extraído del producto: overwrite 0644 en directorio con ACL pública heredable termina 0600 y sin ACL pública |
| CAL-001 | cargo-deb separado por paquete; metadata deb/rpm API; generación e inspección de paquetes en workflow | YAML revisado y parseado; requiere runner Linux para validar paquetes completos |
| OBS-001 | Log JSON de solicitudes admitidas/rechazadas, request_id, identidad validada, plantilla de ruta, UUID, estado y duración; recarga y retención registradas | Regresión verifica 401, 429, request_id y ausencia del token sintético |
| RES-001 | Lectura de binarios con O_NOFOLLOW/O_NONBLOCK y metadata de descriptor, límite real de bytes; metadatos de imagen y descompresión acotados; paginación Kubernetes limitada y rechazo de continuación repetida | Suite Rust, escenarios de imagen, Clippy y límites documentados; sin ensayo destructivo de carga |
| OPS-001 | Recarga atómica de credenciales por SIGHUP; scopes de alias; cuotas de filas/bytes/documento, límite físico SQLite, retención horaria; DB en spawn_blocking | Pruebas de revocación, restricción por alias y purga sin nuevos escaneos; guía de operación y backups cifrados |
| QA-001 | Nuevas regresiones en CI, pruebas de tokens duplicados reales, 7 reglas Semgrep, medición LLVM y fuzzing instrumentado sancov con corpus | 118 tests Rust; 10 tests Python; prueba Swift; informes de cobertura y fuzzing |
| PKG-001 | Limpieza de atributos antes de firmar; copia sin atributos al staging DMG; verificación del bundle copiado y checksum de DMG | Firma ad-hoc válida en staging y app; hdiutil verify válido |
| SUP-001 | Snapshot de apt; bases y acciones por digest/commit; dependencias SAST transitivas por versión; Trivy fijado por versión y SHA-256; manifest de build con dependencias/hashes; attestation y gates en publicación | cargo-deny, manifest local y reproducibilidad CLI/API; contenedor y attestation remota requieren runner |
| DOC-001 | Corrige recuento histórico a 110 Rust y explica contratos, límites y cambios de compatibilidad | README, CHANGELOG, operación 1.5 y este cierre |

## Resultados locales

- 118 pruebas Rust aprobadas, sin fallos (`validacion/tests.log`).
- 2 pruebas Python de configuración/empaquetado, 4 regresiones de seguridad y 4 pruebas de imágenes aprobadas; estas últimas incluyen múltiples subcasos (`python.log`, `regresiones.log`, `imagenes.log`).
- Exportación Swift: modo 0600 y ausencia de ACL pública heredada (`gui-regresion.log`). Es una prueba del bloque real de escritura, no un recorrido interactivo completo de NSSavePanel.
- Cobertura de líneas de fuentes propios Rust: **84.21 %**, 12125 líneas contabilizadas, 1914 no cubiertas. Incluye tests internos en módulos src; excluye archivos de tests de integración y código generado de dependencias. La tabla LLVM completa conserva su total más amplio de 84.44 %. No confundir ninguno con cobertura de ramas o ausencia de vulnerabilidades (`coverage-source.json`, `coverage.txt`).
- Clippy sin warnings y formato Rust comprobado.
- Semgrep: 7 reglas, 59 archivos, cero findings; Gitleaks cero hallazgos con exclusiones documentadas; cargo-deny aprueba advisories, bans, licenses y sources.
- CBOM de demostración: cero errores contra esquema CycloneDX 1.7 (`schema.log`).
- Fuzzing de tres targets con instrumentación sancov, 30 segundos solicitados por target, límite RSS 1024 MiB y timeout 10 s por caso; sin crash observado. Se realizaron 610690, 682556 y 440416 ejecuciones, respectivamente. Los logs y el corpus completo se incluyen en validacion/fuzz-corpus.zip; se conservan semillas legibles en fuzz/corpus. Es una campaña corta, no una prueba prolongada con ASAN/Miri.
- CLI y API compiladas dos veces en rutas distintas con hashes idénticos (`reproducibilidad.log`). La reproducibilidad se aplica a estos binarios con las banderas del script, no a la GUI/DMG.
- App macOS arm64 y DMG creados; firma local y checksum verificados (`package.log`).

## Límites y tareas externas

Los cinco hallazgos de seguridad tienen corrección y regresión local aprobada. No se declara producción universalmente aprobada: Linux/Windows, el contenedor y los workflows se han actualizado, pero necesitan ejecución en sus plataformas. La notarización y Developer ID requieren la cuenta del propietario; no se publicaron artefactos ni se crearon attestations remotas.

SQLite no implementa cifrado de aplicación. Se prescribe cifrado de volumen y backups cifrados; habilitarlo en el despliegue corresponde al operador. No se configura un SIEM, proxy, SLO o retención de logs inexistente. Los límites cooperativos no interrumpen instantáneamente syscalls bloqueados: para un SLO estricto se requiere supervisión de procesos y recursos. Esas condiciones operativas se describen en `operacion-1.5.md`; no se presentan como controles de infraestructura ya desplegados.

Los catálogos criptográficos completos y todas las dependencias no se han auditado manualmente. No se atribuyen certificaciones FIPS/ISO a esta aplicación. Los hashes acreditan integridad, no identidad del editor. La auditoría y la corrección fueron realizadas por el mismo asistente, por lo que se recomienda revisión independiente antes de una distribución sensible.

## Reproducción

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --release --workspace --locked
python3 pruebas/test_release.py
SUAYA_BIN="$PWD/target/release/suaya" SUAYA_API="$PWD/target/release/suaya-api" python3 pruebas/regresiones.py
SUAYA_BIN="$PWD/target/release/suaya" python3 pruebas/imagenes_seguridad.py
python3 pruebas/regresion_gui.py
rustup component add llvm-tools-preview
python3 scripts/cobertura.py
bash scripts/fuzz.sh
SUAYA_DMG=1 bash empaquetado/build-macos.sh
```

Las pruebas usan datos sintéticos, archivos temporales y listeners loopback. Los binarios incluidos están en `bin/`; la GUI incluye su propio motor `suaya-engine`. El manifiesto final SHA256SUMS cubre los archivos entregados salvo el propio manifiesto.
