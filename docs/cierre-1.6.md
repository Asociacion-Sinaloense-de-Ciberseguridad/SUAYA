# Cierre SUAYA 1.6.0

Fecha: 30 de octubre de 2026, America/Mazatlan. Entrega local macOS Apple Silicon basada en v1.5, que se conserva intacta. Este cierre acredita cambios y pruebas locales; no es una certificación ni una auditoría independiente.

## Alcance

| Área | Cambio | Validación |
|---|---|---|
| Diagnóstico de red | Orden `diagnosticar` (`diagnose`): conectividad por dirección IPv4/IPv6, STARTTLS, saludos TLS completos de un cliente moderno (X25519MLKEM768) y uno clásico, validación estándar de la cadena, análisis del `KEXINIT` SSH; texto, `--json` y `--fallar-en` | 8 pruebas unitarias de evaluación, 7 de integración con servidores rustls reales y SSH simulado en loopback, 1 de extremo a extremo de la CLI; ejecución contra servicios públicos (Google, Cloudflare, SMTP de Gmail, GitHub SSH, badssl) |
| Sondeo | `--diagnostico` y `--ca` en `sondear`, `escanear --objetivo` y `kubernetes --sondear-ingress`; hallazgos no informativos como `suaya:advertencia` | Prueba de integración y CBOM de un servicio real |
| API | `POST /api/v1/diagnose` sobre alias de `network_targets`; validación al arrancar, alcance por credencial, semáforo compartido, sin persistencia; `configurar-api.py --network-target` | 2 pruebas nuevas en `security.rs` y llamada real con el binario a un servicio público |
| macOS | Pestaña «Diagnóstico de red»; los objetivos se pasan tras `--`; exportación JSON con la escritura privada compartida | Compilación sin advertencias, decodificación del JSON real con los tipos Swift, regresión de exportación 0600 sin ACL heredada |
| Dependencias | `rustls-webpki` 0.103.16 (RUSTSEC-2026-0382) y `tokio` 1.54.1 (RUSTSEC-2026-0384), avisos publicados después del cierre 1.5 | cargo-deny: advisories, bans, licenses y sources aprobados |

## Resultados locales

- 136 pruebas Rust aprobadas, sin fallos (`validacion/tests.log`); 118 heredadas y 18 nuevas.
- Clippy con `-D warnings` y formato sin observaciones (`clippy.log`, `fmt.log`).
- Python: 2 pruebas de empaquetado, 4 regresiones de seguridad y 4 de imágenes aprobadas; regresión real de exportación de la GUI aprobada.
- CBOM de demostración: 0 errores contra CycloneDX 1.7 (`schema.log`).
- Semgrep: 7 reglas, 61 archivos, 0 hallazgos. Gitleaks: 0 hallazgos; se documentó en `.gitleaksignore` un falso positivo (hash SHA-256 en el manifiesto archivado de 1.5).
- Cobertura de líneas de fuentes propios: **84.20 %** (13438 líneas, 2123 no cubiertas; `coverage-source.json`). `diagnostico.rs`: 80.38 %. No es cobertura de ramas.
- Fuzzing sancov de tres objetivos, 30 s cada uno: 610154, 676777 y 435907 ejecuciones, sin fallos. Corpus completo en `fuzz-corpus.zip`; en `fuzz/corpus` quedan las semillas legibles.
- Compilación reproducible de CLI y API en dos rutas distintas con hashes idénticos (`reproducibilidad.log`).
- App y DMG arm64 con firma ad-hoc verificada; `hdiutil verify` válido (`package.log`, `dmg.sha256`).
- Las evidencias de 1.5 están en `validacion/heredado-1.5/` y no describen esta entrega.

## Límites

- El diagnóstico observa desde el equipo que lo ejecuta: las fallas solo en IPv6 se informan con nivel bajo porque pueden deberse a esa red (el equipo de esta validación no tiene salida IPv6 por su módem).
- La validación de cadenas usa las autoridades del sistema y no consulta revocación (OCSP/CRL); solo informa si el servidor engrapa OCSP.
- El JSON del diagnóstico y sus códigos de hallazgo solo crecen; los textos de los mensajes pueden cambiar.
- La pestaña de la GUI no se recorrió de forma interactiva automatizada; se verificaron compilación, decodificación y escritura.
- Linux, Windows, el contenedor y los workflows no se ejecutaron en sus plataformas. Notarización y Developer ID requieren la cuenta del propietario. No se publicaron artefactos.
- Implementación y verificación por el mismo asistente: se recomienda revisión independiente antes de una distribución sensible.

## Reproducción

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo deny --locked check
SUAYA_BIN="$PWD/bin/suaya" SUAYA_API="$PWD/bin/suaya-api" python3 pruebas/regresiones.py
python3 pruebas/regresion_gui.py
python3 scripts/cobertura.py
bash scripts/fuzz.sh
bash scripts/compilacion-reproducible.sh
SUAYA_BUILD_DIR=/private/tmp/suaya-build SUAYA_DMG=1 bash empaquetado/build-macos.sh
```
