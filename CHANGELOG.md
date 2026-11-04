# Cambios

## [1.6.0] - 2026-10-30

- Nueva orden `suaya diagnosticar` (`diagnose`): análisis de conectividad e intercambio de llaves y certificados de servicios TLS, STARTTLS y SSH, con salida para personas, `--json` y `--fallar-en critico|alto|medio|bajo` (código 2).
- Conectividad: resolución del nombre, cada dirección IPv4 e IPv6 con estado TCP y latencia, preámbulo STARTTLS y tiempo del saludo.
- Intercambio de llaves TLS: dos saludos completos (cliente moderno con X25519MLKEM768 y cliente solo clásico) con versión, suite, grupo negociado, `HelloRetryRequest`, ALPN y verificación de la firma del `CertificateVerify`.
- Intercambio de certificados: validación estándar con las autoridades del sistema (y `--ca` propia), nombre, vigencia, orden, raíz enviada, llaves, firmas, tamaño de la cadena y engrapado OCSP.
- SSH: intercambios poscuánticos ofrecidos, «strict KEX» (Terrapin, CVE-2023-48795) y llaves de host solo SHA-1/DSA.
- `sondear`, `escanear --objetivo` y `kubernetes --sondear-ingress` aceptan `--diagnostico` (y `--ca`) para agregar esos hallazgos al CBOM como `suaya:advertencia`.
- API: `POST /api/v1/diagnose` sobre alias preconfigurados (`network_targets`, `configurar-api.py --network-target`), con alcance por credencial y sin persistencia.
- macOS: pestaña «Diagnóstico de red» con autoridad propia opcional, hallazgos por nivel y exportación JSON privada; la escritura privada se comparte con el inventario.
- El saludo del cliente moderno se repite una vez antes de concluir que el servidor lo rechaza.
- Catálogo en inglés ampliado; 136 pruebas Rust (18 nuevas, incluidos servidores rustls reales en loopback).

## [1.5.0] - 2026-10-20

- Corrige desafíos de autenticación entre orígenes; autorización explícita de realms por registro y TLS predeterminado.
- Separa cuotas API anónimas/usuarios, añade logs estructurados, revocación por SIGHUP y scopes de alias.
- Valida capas Docker/OCI, digests y tamaños; acota metadatos, paginación Kubernetes y lecturas reales de binarios.
- Exportación macOS privada y atómica, incluidos destinos con ACL heredadas.
- Cuotas SQLite por bytes, retención, operaciones fuera del executor async, gates de regresión/cobertura y empaquetado corregido.

# Cambios

## [1.4.0] - 2026-10-19

- Núcleo de escaneo, CBOM, políticas y red restaurado desde la copia completa 1.0.
- API Axum autenticada: expiración de tokens opacos, roles, ownership, consultas parametrizadas, límites y SQLite.
- GUI SwiftUI conectada al motor real con cancelación y exportación privada.
- Firma híbrida versión 2 liga también la fecha; no acepta pseudo-firmas de 1.3.
- Derivación de llaves con parámetros acotados y validación de algoritmos/sal.
- HTML con escape y CSP; Markdown neutraliza HTML crudo; conteo crítico restaurado.
- Estados completed/partial, gate de cobertura y runner periódico real.
- Lecturas acotadas, O_NOFOLLOW para archivos normales y salidas atómicas 0600.
- HTTP con validación TLS obligatoria; sondeo TLS sin credenciales conserva su propósito de observación.
- Build macOS fail-closed, arquitectura correcta, firma local ad-hoc y pruebas de release.
- Regresiones de seguridad y CI con análisis, SCA y revisión de secretos.

Las versiones 1.0 y 1.3 se conservan fuera de esta carpeta; consulte la procedencia de la reconstrucción en docs/procedencia.json.
