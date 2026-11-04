# Cierre de correcciones SUAYA 1.4.0

Entrega local para macOS Apple Silicon. Este documento describe la corrección del árbol auditado 1.3; no es una certificación normativa ni una garantía de ausencia de vulnerabilidades.

## Decisión de implementación

La copia 1.3 carecía de fuentes esenciales y contenía contratos incompatibles y funciones simuladas. Se recuperó el núcleo completo de la copia local 1.0, se actualizó a 1.4.0 y se integraron una API real con SQLite y una interfaz SwiftUI conectada al motor. Las versiones anteriores permanecen intactas. `procedencia.json` identifica por SHA-256 los archivos fuente de origen y las diferencias de esta entrega. No se atribuye a esos archivos un origen remoto verificado.

## Matriz de cierre del informe 1.3

| Hallazgo | Corrección aplicada | Evidencia |
|---|---|---|
| SEC-001: pseudo-firmas | Firma híbrida real ML-DSA-65 + Ed25519; ambas verificaciones obligatorias; fecha incluida en el mensaje autenticado; formato `suaya-firma-2`; validación de parámetros KDF | Pruebas de round-trip, contenido alterado, fecha alterada y firmas inválidas |
| SEC-002: HTML activo | Escape contextual del reporte, CSP restrictiva, neutralización de HTML en Markdown | Pruebas con cargas hostiles y reporte generado |
| SEC-003: autenticación ineficaz | Tokens opacos aleatorios, hashes, comparación constante, expiración, roles y autorización por propietario; todas las rutas de datos protegidas | Seis pruebas API y prueba HTTP con proceso real |
| CAL-001: fuentes/manifiestos incompletos | Workspace de seis crates coherentes, lockfile actualizado, núcleo recuperado, API nueva | Build release, 110 pruebas Rust (recuento corregido en auditoría 1.4), Clippy |
| CAL-002: resultados fabricados | GUI ejecuta el motor incluido; exporta sus bytes reales JSON/HTML | Build nativo, inicio, escaneo gráfico con 115 activos/20 críticos y exportación JSON/HTML verificados |
| CAL-003: Critical omitido | Prioridad 1 contabilizada y umbrales correctos; resumen gráfico con críticos | Regresión Critical y pruebas del modelo |
| CAL-004: éxito vacío | Stubs retirados del producto; estado `completed`/`partial` y errores reales; flag CLI para fallar por cobertura incompleta | Prueba de CLI y de escaneo API; reportes con advertencia |
| CAL-005: empaquetar tras error | Build aborta si falla Rust o Swift; sin binario sustituto | Prueba que fuerza fallo de swiftc; firma y verificación locales |
| CAL-006: arquitectura incorrecta | Paquete arm64 identificado desde host y binario inspeccionado | `file`, versión 1.4.0 y DMG arm64 |
| BP-001: cadena de entrega | Imágenes Docker por digest, acciones por commit, CI/release con gates y toolchain fijo | Manifiestos y workflows incluidos; ejecución local documentada |
| BP-002: proveedor en conflicto | AWS-LC en el grafo activo, política deny preservada | cargo-deny: advisories, bans, licenses y sources aprobados |
| BP-003: carreras GUI | MainActor, tarea única, cancelación con bloqueo y token de generación; limpiar invalida resultados anteriores | Typecheck, revisión del flujo y prueba gráfica de escaneo/exportación |
| BP-004: cron ambiguo | Runner secuencial con intervalo validado, timeout y subprocess sin shell; `--once` para scheduler externo | Prueba de ejecución con CLI real |
| BP-005: CVE ficticias | Retirados los prototipos que atribuían CVE por puerto; no se anuncian diagnósticos inexistentes | Revisión del alcance y de fuentes |

## Endurecimiento adicional

- Lecturas CLI acotadas a 256 MiB; recorrido limitado a 100000 entradas; lectura de archivos con comprobación de archivo regular y `O_NOFOLLOW` en Unix por defecto.
- Salidas CLI atómicas y privadas; configuración API 0600, directorio SQLite 0700 y base 0600 en Unix.
- API en loopback, cuerpo máximo 4 KiB, 2 escaneos simultáneos, 60 solicitudes/min por usuario y 600/min globales; hasta 1000 resultados por identidad.
- La API solo acepta alias de objetivos administrados, sin rutas o URLs arbitrarias; parámetros SQL enlazados; sin edición de configuración desde HTTP.
- HTTP con datos/credenciales rechaza desactivar validación TLS. Los sondeos explícitos de certificados siguen separados de ese cliente.
- Logs API omiten cuerpos, tokens y consultas. Tokens de ejemplo no se incluyen en la entrega.
- Nombres distintos `SUAYA` y `suaya-engine` evitan la colisión de ejecutables en sistemas de archivos macOS que no distinguen mayúsculas.

## Validación

Los registros ejecutados se conservan en `../validacion/`. Consulte `resultados.json` para el resultado final de cada comprobación. Se verificaron pruebas Rust, Python, Clippy, formato, esquema CycloneDX, Semgrep con cinco reglas locales sobre 59 archivos Rust, Gitleaks y cargo-deny. Las excepciones de secretos se limitan a fixtures públicos sintéticos, cabeceras PEM sin material de llave y productos de compilación. Se documentan también falsos positivos sobre hashes del manifiesto de procedencia y una línea de prosa del informe original; no se ocultan archivos de configuración del producto.

La GUI se abrió y se inspeccionó visualmente; exportó JSON válido contra el esquema y HTML con CSP, ambos 0600.

Dos builds de la CLI para aarch64-apple-darwin en rutas distintas produjeron SHA-256 `4565798e372d7fe871656b18381c446dd651ffa9fecf0e8f8d2935f00f0f47af`, usando las banderas normalizadas de `scripts/compilacion-reproducible.sh`. Esta prueba no afirma reproducibilidad byte a byte del bundle Swift, del DMG ni del build sin esas banderas. La imagen DMG pasó `hdiutil verify`.

Los harnesses de fuzzing compilan; esto no equivale a una campaña prolongada de fuzzing. Semgrep usa reglas específicas para las regresiones auditadas, no un conjunto exhaustivo de vulnerabilidades. La prueba HTTP real confirma autenticación, inventario, lectura y persistencia después de reiniciar el servidor. La API no fue desplegada en Internet ni se ejecutaron ataques contra servicios externos.

## Operación y límites

1. GUI local, CLI y API están implementadas. PDF/Excel, HSM, auditoría IAM de nubes, asistente LLM, autoactualizaciones y notificaciones externas quedan explícitamente fuera de esta versión; las simulaciones previas no se conservan como funciones exitosas.
2. Los tokens se rotan/revocan editando la configuración y reiniciando. Todos los analistas pueden escanear todos los alias de su instancia. Use instancias separadas para conjuntos de objetivos distintos.
3. Ejecute el servicio con una cuenta dedicada y directorios bajo su control. Los límites no sustituyen cuotas de disco, límites del sistema operativo, proxy TLS, monitoreo ni una política de retención. SQLite no cifra los inventarios en reposo; proteja el volumen y las copias de respaldo.
4. No use kubeconfig de terceros sin revisarlo: sus plugins `exec` ejecutan programas con la identidad del operador. Sondeos e imágenes remotas requieren objetivos autorizados explícitos.
5. La firma ad-hoc permite comprobar la integridad local del paquete; no es Developer ID ni notarización Apple. No se publicó un release remoto. La fórmula Homebrew `.rb.in` es una plantilla pendiente de URL pública y hash de publicación; no se anuncia como instalación disponible.
6. La fecha firmada es una declaración autenticada del firmante, no un sello de una autoridad de tiempo. El formato v2 requiere generar nuevas firmas; las pseudo-firmas de 1.3 no son compatibles ni confiables.
7. Linux/Windows, la imagen Docker y los workflows remotos no se ejecutaron en este Mac. La compatibilidad del código fuente no demuestra un paquete validado para esas plataformas.
8. Los archivos escaneados pueden contener secretos: el inventario evita incorporar llaves privadas, pero nombres, rutas y metadatos siguen siendo sensibles. Trate resultados y logs como información interna.
