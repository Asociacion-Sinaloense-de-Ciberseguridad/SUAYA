# Revisión técnica y de seguridad de SUAYA v1.3

Fecha: 19 de octubre de 2026. Objetivo: `/Users/enriquerangel/Documents/Quantum/SUAYA/suaya v1.3`.

Revisión estática de la copia entregada, desde las perspectivas de arquitectura, AppSec y auditoría. No constituye certificación ISO ni evaluación completa de conformidad ASVS. No se modificó el proyecto ni se ejecutaron escaneos de red. Este informe se guarda fuera del repositorio.

## 1. Resumen ejecutivo

**Dictamen: no apto para producción en el estado de esta copia. Calificación global de calidad: 1.6/5.** La nota es el promedio simple de las nueve dimensiones de la sección 3, redondeado. No es una puntuación de seguridad ni de conformidad normativa.

El problema principal es la distancia entre las capacidades documentadas y la implementación disponible. El workspace contiene manifiestos sin fuentes, contratos incompatibles, interfaces simuladas y controles de seguridad incompletos. Un parser TOML confirmó que el manifiesto raíz es inválido por una clave duplicada. No fue posible ejecutar Cargo porque no está instalado/disponible en PATH. Estos son impedimentos diferentes: instalar Rust no corrige el código entregado.

Los cinco riesgos prioritarios son:

1. **Integridad de resultados:** el verificador acepta cualquier texto con prefijo `sig_`; el firmador calcula un hash público e ignora la llave privada. No proporciona autenticidad.
2. **Ejecución de contenido en reportes:** el generador HTML interpola datos sin escape contextual. La explotación depende de que datos controlados por un tercero lleguen al reporte y este se abra en un navegador.
3. **Futura exposición de la API sin controles efectivos:** no se instala autenticación en el router y el supuesto middleware solo reconoce un prefijo. Los handlers actuales son stubs y no existe un servidor demostrado; no se afirma acceso remoto a datos reales.
4. **Decisiones basadas en evidencia incorrecta:** la GUI fabrica elementos y vulnerabilidades; varios scanners retornan éxito vacío; el resumen omite severidad Critical. Esto invalida su uso actual como evidencia de auditoría.
5. **Distribución sin evidencia reproducible:** lockfile de versión anterior, manifiestos incompletos, ausencia de workflows en esta copia y empaquetado que reemplaza una compilación fallida por un stub y continúa.

No se encontró evidencia suficiente para afirmar CVE explotables, filtración de secretos reales, IDOR sobre objetos reales, SSRF en un cliente HTTP operativo o compromiso del binario distribuido. Ausencia de evidencia no significa ausencia de riesgo.

Aspectos positivos verificables: separación nominal por crates; estructuras de hallazgos sin campos de llave privada; uso de serialización JSON en lugar de eval; Docker final con usuario nonroot; `deny.toml` con política de orígenes, licencias y avisos sin excepciones; modelos de amenazas y objetivos de fuzzing presentes. La existencia de estas políticas no demuestra su ejecución ni que los controles descritos estén implementados.

## 2. Fase 0: mapa del sistema y superficie de ataque

### Contexto inferido y supuestos

SUAYA pretende inventariar criptografía, producir CBOM y evaluar preparación poscuántica. En esta copia coexisten Rust con `edition = "2021"`, `rust-version = "1.89"` y GUI SwiftUI/Cocoa. La documentación antigua menciona Rust 2024 y cinco crates, pero no describe fielmente esta versión.

Los manifiestos declaran versiones de dependencias; no son versiones resueltas verificadas del sistema actual. Propósito empresarial, roles, despliegue real, normas legales aplicables y fecha de salida no fueron proporcionados. No se presume que LFPDPPP o PCI DSS apliquen. Los datos previstos incluyen metadatos de llaves/certificados, inventarios y posiblemente credenciales de acceso; los flujos implementados observados se reducen en gran parte a estructuras en memoria y datos simulados.

### Módulos

| Módulo/ruta relativa a la raíz objetivo | Responsabilidad observada | Estado |
|---|---|---|
| `crates/suaya-core/src` | Finding, Severity, ScanOptions, ScanResult, errores, trait Scanner | Dos definiciones incompatibles de ScanResult; faltan conversiones y dependencias utilizadas |
| `crates/suaya-cli/src/main.rs` | Declaración Clap de Scan/Manage/Report/Config/Version | Sin función main; no orquesta operaciones |
| `crates/suaya-gui/src/main.rs` | Pantallas de TUI | Texto de demostración; defectos sintácticos y de API visibles |
| `crates/suaya-gui/src/swift` | Pantallas nativas, ScannerManager y preferencias | Escaneo simulado; exportación imprime un mensaje |
| `crates/suaya-api/src` | Router, modelos, supuesto middleware | Axum en código frente a Actix en manifiesto; endpoints devuelven textos constantes |
| `crates/suaya-db/src` | Guardar/obtener/borrar escaneos y configuración | HashMap en memoria, no persistencia SQLite implementada |
| `crates/suaya-signature/src` | Firma/verificación | Hash sin llave y validación de prefijo |
| `crates/suaya-reports/src` | JSON/Markdown/HTML y conteos | HTML sin escape; Critical no contabilizado por categoría |
| `crates/suaya-validate/src` | Reglas sobre resultados | Reglas registradas opcionalmente; umbral High ignora Critical |
| `crates/suaya-automate/src` | Cron, payload de webhook y notificaciones | No hay envío operativo; send devuelve Ok |
| `crates/suaya-scanner-cloud/src` | Interfaces AWS/Azure/GCP | Métodos vacíos o ramas con comentarios |
| `crates/suaya-scanner-{code,container,secret,network}` | Prototipos adicionales | Fuera de lista members; no conectados desde crates revisados del workspace; defectos de compilación propios |
| `crates/suaya-{escaneo,cbom,red}` | Núcleo de escaneo, CBOM y protocolos documentado | Solo Cargo.toml; cero archivos Rust |
| `crates/suaya-scanner-{docker,k8s,db,api}` | Escáneres adicionales declarados | Solo Cargo.toml; cero archivos Rust |
| `crates/suaya-cli-interact`, `suaya-i18n`, `suaya-docs` | Menús, traducciones, documentación | Implementación parcial; escritura de Markdown en docs |
| `conocimiento/` | Algoritmos, madurez, bibliotecas, perfiles y traducciones | Datos presentes; no se demostró un consumidor funcional |
| `fuzz/`, `pruebas/` | Harnesses y fixtures | Harnesses hacen referencia a APIs ausentes; fixtures no equivalen a pruebas ejecutables |
| `empaquetado/`, `scripts/` | App/DMG, Docker, Homebrew, reproducibilidad | Inconsistencias entre fuente, plataformas y empaquetado |
| `build/` | App y DMG existentes | No ejecutados ni vinculados criptográficamente con estas fuentes |

### Entradas y límites de confianza

- API declarada: POST `/api/v1/scan`, GET/DELETE `/api/v1/scan/:id`, GET `/api/v1/scans`, GET/PUT `/api/v1/config`, GET `/api/v1/health`. Ubicación: `crates/suaya-api/src/routes.rs:9`. No se encontró listener de servidor ni conexión de esos handlers con almacenamiento o scanners.
- CLI: `Scan`, `Interactive`, `Manage`, `Report`, `Config`, `Version`. Son definiciones de argumentos; no ejecución demostrada.
- GUI: botones de escaneo, exportación y preferencias. `ScannerManager.startScan` solo espera y agrega cadenas fabricadas. No cruza a un scanner Rust ni a una API.
- Scheduler: calcula tiempos y genera textos cron/systemd. No se encontró un ejecutor de tareas ni consumidor de cola.
- Prototipo de red: `port_scan.rs` conecta a direcciones IP/puertos, con timeout por conexión. No se probó ni activó. El scanner principal propone 1..1024 por defecto; contradice la ausencia de descubrimiento descrita en el modelo de amenazas.
- Flujo HTML concreto a nivel de librería: `ScanResult.target/findings` → `ReportGenerator::convert_to_report_data` → `HtmlFormat::generate` → documento HTML. El límite texto/datos → código interpretado no tiene escape.
- Flujo de firma: resultado → JSON → SHA-256 → base64 → `sig_`; verificador separado → comprobación de prefijo. No se usa identidad criptográfica.
- Flujo previsto de secretos de archivos/red → inventario → CBOM no es verificable porque faltan las implementaciones centrales. No se atribuyen a esta copia los controles descritos en documentación anterior.

### Dependencias

Se inspeccionaron los 24 manifiestos de crates; 20 están listados como members. Dependencias relevantes declaradas: Rustls/AWS-LC, x509-parser, ssh-key, tar/flate2/ruzstd, serde/serde_json/TOML/YAML, Tokio, Actix/JWT/Argon2, rusqlite, Tera/Handlebars y Cursive/Ratatui. Su presencia no prueba uso efectivo.

`Cargo.lock` contiene 180 registros y solo cinco paquetes Suaya, todos 1.0.0: `suaya`, `suaya-core`, `suaya-escaneo`, `suaya-cbom`, `suaya-red`. No resuelve el workspace 1.3 actual. Incluye `aws-lc-rs 1.18.2`, `rustls 0.23.46` y `ring 0.17.14`; esto último entra en conflicto con la política de prohibir ring. No puede presentarse como inventario transitivo final.

**Cierre fase 0:** la copia y sus límites quedaron identificados; se puede revisar estáticamente lo presente. Compilación, ejecución, SCA vigente e historial quedan pendientes de un árbol completo y un entorno Rust. No se recuperaron archivos desde v1.0 ni se mezclaron versiones.

## 3. Fase 1: evaluación de calidad

Escala: 1 deficiente, 3 aceptable con deuda, 5 sólida. Rendimiento es valoración de diseño, no benchmark.

| Dimensión | Nota | Evidencia y justificación |
|---|---:|---|
| Arquitectura y separación | 2 | Crates separados, pero API usa Axum sin declararlo; núcleo faltante y contratos duplicados (`core/src/types.rs`, `result.rs`, `api/Cargo.toml`) |
| Legibilidad | 3 | Funciones cortas y nombres claros; comentarios y nombres prometen capacidades que el cuerpo no implementa (`signature/src/signer.rs:27`, `automate/src/notification.rs`) |
| Complejidad | 2 | Poca complejidad local, en gran parte por stubs; no permite concluir que el producto completo sea simple o correcto |
| Duplicación | 2 | Dos ScanResult en core, otro en db; conteos repetidos en reports/docs/core y detectores de secretos duplicados |
| Manejo de errores | 1 | Fallos Swift se convierten en stub (`build-macos.sh:43`); notificaciones/scanners comunican éxito sin trabajo; `try? Task.sleep` ignora cancelación |
| Pruebas y cobertura | 1 | Búsqueda de atributos test en crates no encontró pruebas; fuzz depende de APIs ausentes. Cobertura no medida; no se afirma 0% medido |
| Rendimiento | 1 | No hay ruta de escaneo central ejecutable para medir; prototipo de puertos secuencial con timeout de 5 s por puerto (`port_scan.rs:24`) |
| Mantenibilidad | 1 | Manifiesto inválido, versiones internas incompatibles y lock antiguo; falta main en CLI y fuentes en siete miembros |
| Documentación | 1 | Hay documentación extensa, pero afirma controles/pruebas/componentes que no están; README_GUI y docs/auditoria describen otras versiones |

Bloqueos verificados o estáticamente demostrables:

- `Cargo.toml:89` repite `workspace.dependencies.serde_json`, ya declarada antes. Python 3.13 `tomllib` devolvió `Cannot overwrite a value (at line 89, column 23)`.
- `workspace.dependencies` pide versiones internas 1.1.0, frente a `workspace.package.version = 1.3.0`. Resolver requiere conciliarlas.
- Siete miembros carecen de `src/lib.rs`, `src/main.rs` o targets explícitos utilizables.
- Core usa `chrono` sin dependencia; `scanner.rs` usa `Result<ScanResult>` sin importar el alias propio. Los tipos exportados no derivan Serialize/Deserialize pese a consumidores que lo requieren.
- API importa Axum no declarado y `ApiModels` inexistente; su middleware invoca `req.into_response()` sin implementación presente.
- Signature importa base64 no declarado. Reports importa `crate::ReportData` sin reexportarlo. DB referencia `ScanSummary` ausente y `query.rs` no importa HashMap.
- GUI Swift declara `struct ScannerManager: ObservableObject` con `@Published`; requiere rediseñar como clase observable. `SuayaApp.swift` importa Cocoa, pero utiliza App/Scene/WindowGroup de SwiftUI sin importarlo en ese archivo.

Lo anterior no es una salida de `cargo check`: es inspección estática y validación TOML. No se afirma haber compilado ni enumerado todos los errores.

## 4. Fase 2: hallazgos de seguridad

### Criterio de severidad

Se separa defecto de código, escenario de uso y exposición real. No hay despliegue ni artefacto compilado demostrado a partir del árbol. **Ningún hallazgo se presenta como explotación end-to-end confirmada en producción.** Los CVSS-B v4.0 siguientes describen escenarios explícitos de integración/uso; no son mediciones del entorno real. Valores calculados con `cvss==3.6` en un directorio temporal, con vectores publicados para reproducibilidad. Deben contrastarse con el calculador de FIRST antes de registro formal. Prioridad empresarial puede ser inmediata aunque el CVSS de ese escenario sea medio.

| ID | Hallazgo | Confianza en defecto / explotación | CVSS-B del escenario | Prioridad |
|---|---|---|---:|---|
| SEC-001 | Firma y verificación no autentican resultados | Confirmado estáticamente / requiere integración | 6.8, media | Inmediata |
| SEC-002 | Inyección HTML/script en reportes | Confirmado el sink sin escape / probable si hay entrada de tercero | 4.8, media | Inmediata antes de compartir reportes |
| SEC-003 | API sin autenticación efectiva | Confirmada ausencia local / requiere verificación de servidor/capa externa | No aplicable al stub actual; 6.9 media para escenario futuro descrito | Bloquear exposición |

### SEC-001. Cualquier tercero puede fabricar resultados aceptados como firmados

**CWE:** CWE-347, Improper Verification of Cryptographic Signature; CWE-345 para la autenticidad no proporcionada por el firmador.

**Ubicación:** `crates/suaya-signature/src/verifier.rs:21` y `:23`; `signer.rs:23` y `:28`. La llave pública y privada se guardan pero no participan en las operaciones.

Evidencia mínima:

```rust
// verifier.rs:23
Ok(signature.starts_with("sig_"))
// signer.rs:24-28
let data = serde_json::to_string(result)?;
let hash = self.compute_hash(&data);
let signature = format!("sig_{}", hash);
```

Mitigación buscada: no hay llamada a un verificador criptográfico en esos métodos ni requisito de llave. `ResultSigner::verify` recomputa el hash, pero cualquiera puede recomputarlo también. No hay implementación de la firma híbrida documentada en el crate cbom, porque sus fuentes faltan. `verify_chain([],...)=true` además acepta una cadena vacía por vacuidad lógica; su impacto depende del contrato consumidor.

Escenario no destructivo:

1. Un consumidor integra `ResultVerifier` para validar un resultado recibido como archivo.
2. Un tercero cambia el target/hallazgos del resultado y proporciona `sig_cualquier_cosa`.
3. El consumidor invoca verify: la expresión retorna true para cualquier resultado.
4. Aun usando `ResultSigner::verify`, el tercero puede calcular SHA-256(base JSON) y construir el texto esperado sin conocer una llave.

Impacto: integridad alta sobre el inventario que el consumidor confíe como auténtico; confidencialidad/disponibilidad no demostradas. No hay ruptura de SHA-256: falta autenticación.

Vector: `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N` = **6.8**. Modelo: archivo entregado, aceptación por una persona/consumidor, alteración del resultado. Una API remota tendría otro vector y no está demostrada.

Corrección inmediata segura propuesta, mientras se implementa criptografía real:

```rust
// Sustituir el cuerpo de ResultSigner::sign.
pub fn sign(&self, _result: &ScanResult) -> Result<String> {
    Err(suaya_core::Error::InternalError {
        message: "Firma criptográfica no disponible".into(),
    })
}
// Sustituir ambos verificadores y verify_chain: no aceptar nada todavía.
pub fn verify(&self, _result: &ScanResult, _signature: &str) -> Result<bool> {
    Ok(false)
}
pub fn verify_chain(&self, _results: &[ScanResult], _signature: &str) -> Result<bool> {
    Ok(false)
}
```

Este fail-closed retira la función, no implementa una firma. Solución final: proveedor validado, llave pública confiable distribuida fuera del documento, sobre versionado, bytes canónicos, separación de dominio y binding de todos los campos; si se mantiene la promesa híbrida, exigir ML-DSA-65 **y** Ed25519 sobre el mismo mensaje y rechazar resultados parciales. No aceptar la llave pública suministrada por un atacante como raíz de confianza. Firmar una lista debe vincular longitud y orden, no verificar una misma cadena contra elementos inconexos.

Esfuerzo: bajo para desactivar; alto para implementar y validar el ciclo completo de llaves, formato y migración. Confianza: defecto confirmado por inspección; uso y alcance requieren verificación.

### SEC-002. Datos del reporte se interpretan como HTML activo

**CWE:** CWE-79. Ubicación: `crates/suaya-reports/src/formats.rs:64`, `:66-68`, `:76-78`; flujo desde `generator.rs:35-50`.

```rust
output.push_str(&format!("<p><strong>Target:</strong> {}</p>", data.target));
output.push_str(&format!("<p>{}</p>", finding.description));
```

No hay Tera/Handlebars ni autoescape en esta ruta: declarar dependencias de plantillas no mitiga concatenación de strings. El título también puede cerrar `</title>` y cambiar el documento.

Escenario:

1. Un tercero logra que `target` o un texto Finding contenga HTML, por importación o por un consumidor que usa la librería; esa entrada todavía no está conectada en la CLI de esta copia.
2. Se genera el reporte con HtmlFormat.
3. Un analista abre el archivo. Una carga inocua como `<script>document.title='SUAYA_TEST'</script>` se vuelve un nodo ejecutable si el navegador lo permite.
4. En un reporte alojado bajo un origen web, el alcance dependería de ese origen y sus políticas; no se presume acceso a cookies, archivos locales ni otras sesiones.

Impacto del modelo: confidencialidad e integridad bajas dentro del contexto del reporte; disponibilidad no demostrada. Confirmado el sink; explotación probable al conectar entrada de terceros. Vector para archivo local: `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N` = **4.8**. No se ejecutó código en un navegador durante la revisión.

Corrección propuesta para estos contextos de texto HTML:

```rust
fn html_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}
// Usar en TODAS las interpolaciones de texto de HtmlFormat:
output.push_str(&html_text(&data.title)); // dentro de <title>
output.push_str(&format!("<h1>{}</h1>", html_text(&data.title)));
output.push_str(&format!("<p><strong>Target:</strong> {}</p>", html_text(&data.target)));
output.push_str(&format!("<p><strong>Date:</strong> {}</p>", html_text(&data.scan_date)));
// Dentro del loop:
output.push_str(&format!("<h3>{}</h3>", html_text(&finding.title)));
output.push_str(&format!("<p>{}</p>", html_text(&finding.description)));
output.push_str(&format!("<p><strong>Remediation:</strong> {}</p>", html_text(&finding.remediation)));
```

Una plantilla con autoescape activado es una alternativa. No reutilizar este helper para URLs, JavaScript o CSS: requieren otras validaciones. Añadir CSP restrictiva como defensa adicional, sin sustituir escape. Markdown requiere su propio contrato: deshabilitar HTML crudo y validar esquemas URL al renderizarlo.

Esfuerzo: bajo para HTML; medio si se extiende a todos los formatos y consumidores. Aceptación: todas las cadenas hostiles se muestran como texto; el DOM no contiene nodos script/eventos provenientes de datos.

### SEC-003. Router sin protección y middleware que no valida credenciales

**CWE:** CWE-306; CWE-287 en la lógica del supuesto middleware.

Ubicación: `crates/suaya-api/src/routes.rs:9-15`, `middleware.rs:18-23`.

```rust
Router::new()
    .route("/api/v1/scan", post(handle_scan))
    .route("/api/v1/config", get(handle_get_config).put(handle_update_config))
// No layer/route_layer de autenticación en create_router.
if token_str.starts_with("Bearer ") {
    return Ok(req.into_response());
}
```

El segundo fragmento no es un middleware Axum funcional y contiene un error de compilación. No se presenta como bypass HTTP ejecutado. No hay validación de firma, algoritmo, issuer, audience, expiración, identidad, scopes ni autorización sobre objetos. No se encontró un servidor/proxy externo en el árbol que permita verificar otra mitigación. La preferencia Swift `authentication` solo se almacena en SettingsView; no implementa protección del backend.

Escenario condicionado:

1. Se arreglan dependencias y compilación y se expone el router sin añadir controles.
2. Un cliente envía GET `/api/v1/scans` o PUT `/api/v1/config` sin token.
3. El router actual ejecutaría handlers que solo devuelven textos constantes; no hay acceso real a escaneos/configuración demostrado.
4. Al sustituir los stubs por operaciones reales, esa misma estructura expondría operaciones sin autenticar, salvo que otra capa lo impida.

**Impacto actual sobre datos: no demostrado. CVSS actual: no aplicable.** Como escenario futuro mínimo de API de configuración realmente modificable sin autenticación: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N` = **6.9**. No corresponde afirmar 9.8/10.0 ni IDOR remoto sobre este código incompleto.

Contención concreta propuesta mientras no exista autenticación:

```rust
// Mantener únicamente el endpoint público de salud.
pub fn create_router() -> Router {
    Router::new().route("/api/v1/health", get(handle_health))
}
```

Eso deshabilita funciones; no implementa IAM. Para habilitarlas: elegir Axum o Actix y alinear el manifiesto; instalar middleware antes de publicar rutas; JWT con algoritmo fijo, llave configurada, exp/iss/aud obligatorios; principal tipado; autorización por operación y propietario; separación admin/analista; 401 sin identidad y 403 por privilegios insuficientes. No se propone un helper JWT aparentemente completo sin conocer el proveedor, formato de tokens ni modelo de roles.

Esfuerzo: bajo para retirar rutas; medio/alto para IAM completo. Confianza: ausencia local confirmada; exposición e impacto requieren topología y backend funcional.

### Defectos de producto y recomendaciones, separados de vulnerabilidades explotables

| ID | Evidencia | Consecuencia y acción |
|---|---|---|
| CAL-001 | `Cargo.toml:89`; siete miembros sin fuentes | Árbol no compilable. Restaurar fuentes de procedencia comprobada y unificar contratos/versiones |
| CAL-002 | `gui/src/swift/ContentView.swift:107-121` | Se generan elementos y vulnerabilidades tras dormir, sin inspección. Separar modo demo explícito del resultado real; no exportar evidencia de demo como real |
| CAL-003 | `reports/src/generator.rs:41-49`, `docs/src/generator.rs` y `validate/src/rules.rs:10-14` | Critical se omite de categorías/umbral. Añadir contador Critical y regla independiente; no asumir que el umbral >10 era una política de release aprobada |
| CAL-004 | `scanner-cloud/src/{scanner,aws,azure,gcp}.rs`; prototipos scanner-code/container/secret | Éxito vacío sin evaluación. Usar estado Unsupported/NotRun/Failed y distinguirlo de Completed sin hallazgos |
| CAL-005 | `empaquetado/build-macos.sh:43-49` | Error de compilación produce un ejecutable stub y sigue empaquetando. Salir con error y verificar binario/arquitectura antes de empaquetar |
| CAL-006 | mismo script `:11`, `:34`; Dockerfile y scripts | Nombre x86_64 frente a target arm64; Cargo package `suaya` frente a llamadas build `-p suaya` que sí corresponden al package CLI; no confundir directorio suaya-cli con nombre del paquete. Corregir plataforma y verificar targets |
| BP-001 | Dockerfile usa tags; no hay `.github/workflows` en esta copia | Fijar imágenes por digest, acciones por commit y toolchain. No afirmar que workflows remotos no existan |
| BP-002 | `signature/Cargo.toml` declara ring; `deny.toml` lo prohíbe | Resolver política frente a proveedor. No basta cambiar el comentario ni suprimir el gate |
| BP-003 | ScannerManager permite varias Task, ignora cancelación; clearData no cancela | Posible repoblación tras limpiar y progreso incoherente, no fuga confirmada. Clase @MainActor, tarea única, cancelación y token de generación |
| BP-004 | `automate/src/scheduler.rs::set_interval` genera cinco campos y oculta error | Validar sintaxis del crate cron elegido, devolver Result y distinguir formatos cron/systemd. No se ejecutaron estas rutas |
| BP-005 | `scanner-network/src/port_scan.rs` usa identificadores CVE ficticios | Eliminar `CVE-2021-XXXX/YYYY/ZZZZ`. Un puerto abierto no demuestra una CVE; reportarlo como observación de servicio |

### Cobertura de las 14 áreas solicitadas

1. **AuthN/AuthZ:** SEC-003. IDOR/escalamiento horizontal/vertical no demostrables sin objetos, principal y roles reales. Control cliente Swift no es autorización backend.
2. **Inyección/entrada:** SEC-002. No hay SQL ejecutado: QueryBuilder produce parámetros de texto y DB usa HashMap; no se etiqueta como SQLi. No se encontraron sinks operativos para NoSQL, LDAP, SSTI, XXE o comandos remotos. Doc generator recibe output_dir del llamador; no se demuestra path traversal de tercero sin fuente no confiable.
3. **Deserialización/SSRF:** serde_json convierte estructuras/Value; sin carga de objetos ejecutables observada. WebhookConfig contiene URL pero no realiza envío. La funcionalidad registry/HTTP documentada falta. SSRF no confirmada.
4. **Tokens/sesiones:** no hay emisión/validación JWT operativa ni cookies implementadas; declaración de jsonwebtoken no mitiga SEC-003. Revocación y rotación pendientes.
5. **Criptografía/PQC:** uso real observado SHA-256/base64 en pseudo-firma; SEC-001. No se demostró generación aleatoria, AES, PBKDF2, protección de llave ni ML-DSA en esta copia. RSA/ECC son mencionados como objetos inventariados y en dependencias, no usos reales mapeables para migración. La GUI presenta umbrales RSA<3072/ECC<256 que no delimitan resistencia cuántica: aumentar esos tamaños no convierte RSA/ECC en PQC. ML-KEM corresponde a establecimiento de secretos; ML-DSA a firma, no son intercambiables.
6. **Secretos:** no se ejecutó detector especializado; no se imprimieron ni validaron credenciales. Fixtures contienen material de demostración y requieren tratamiento separado. No se afirma que sean secretos productivos. Sin `.git` no se puede revisar historial.
7. **Dependencias:** lock analizado pero incoherente con árbol actual. CVE, abandono y typosquatting requieren SCA y comprobación de identidad/mantenedores; no se inventa una lista. Licencias declaradas y allowlist presentes, conformidad transitiva no verificada.
8. **Configuración:** sin servidor operativo, no se puede verificar CORS, TLS, headers ni debug real. HTML sin CSP propuesta como defensa adicional. Docker nonroot es positivo; tags mutables son mejora de cadena de suministro.
9. **Logs/monitoreo:** no hay auditoría de operaciones sensibles implementada; print de acciones simuladas no prueba trazabilidad. No se demostró fuga de secreto en logs.
10. **Errores:** varios errores se propagan con texto original y otros se ocultan; no se comprobó exposición de stack trace en HTTP. Empaquetado fail-open: CAL-005.
11. **Concurrencia:** BP-003 y estado Task; no se afirma race de memoria explotable. DB utiliza &mut para mutación local; sin transacciones persistentes implementadas no se puede auditar concurrencia multiusuario.
12. **Negocio:** CAL-002/003/004; firma sin identidad SEC-001. Definir evidencia mínima y estados de ejecución antes de usar como control de aprobación.
13. **Supply chain:** lock incoherente, política ring contradictoria y empaquetado tolera fallos. Sin historial, CI ni atestaciones verificables de build; no se atribuyen SLSA o reproducibilidad por documentación.
14. **LLM:** no se encontró cliente de modelo, prompts, herramientas de agente ni contexto de LLM. ScanAssistant es un formulario guiado, no IA. OWASP LLM Top 10 queda no aplicable al alcance observado, sujeto a módulos no entregados.

## 5. Fase 3: plan de mejoras para aprobación

No se aplicó ninguna acción. Los plazos son horizontes de prioridad, no compromisos de entrega; recuperar el núcleo puede requerir más tiempo si las fuentes no existen.

| Acción | Horizonte / qué y por qué | Cómo | Criterio de aceptación | Dependencias |
|---|---|---|---|---|
| A1 | Inmediato 0–7 días: impedir distribución como producto funcional | Desactivar publicación; mostrar demo explícita; retirar pseudo-firma y rutas sensibles | Fallo de build bloquea paquete; no hay firma aceptada sin criptografía; demo no genera evidencia real | Ninguna; contención posible antes de recuperar todo |
| A2 | Inmediato: recuperar build verificable | Fuentes originales, TOML sin duplicados, versiones internas consistentes, un ScanResult, imports/errores/serde/dependencias completos; escoger framework HTTP | `cargo metadata --locked`, `cargo check --workspace --all-targets --locked` y build Swift exitosos; sin stub; lock regenerado con revisión de diff | Procedencia y disponibilidad de fuentes; toolchain Rust |
| A3 | Inmediato: cerrar HTML y conteos | Escape final de todos los textos; Critical explícito en resumen, docs y política | Prueba XSS sin nodos activos; fixture con un Critical produce contador 1 y decisión de policy esperada | A2 para ejecutar regresiones; escape se puede diseñar antes |
| A4 | Corto 2–4 semanas: firma auténtica | Proveedor validado, confianza de llave, formato versionado/canónico y firma híbrida si se mantiene requisito | Firma válida pasa; mensaje/llave/algoritmo/firma alterados fallan; ambas mitades requeridas; rechazo de legacy sig_ | A2, decisión sobre proveedor y formato |
| A5 | Corto: AuthN/AuthZ antes de publicar API | Middleware del framework elegido y policy por operación/objeto; TLS y configuración de issuer/audience | Matriz 401/403/200; usuario A no lee/borra B; token expirado, firma inválida, alg incorrecto y replay revocado rechazados | A2, proveedor de identidad y roles definidos |
| A6 | Corto: escáneres y datos reales | Conectar backend; estado Completed/Failed/Unsupported, eliminar éxitos simulados; persistencia real si se ofrece | Fixture vulnerable detectado, fixture limpio sin hallazgos, falta de permisos devuelve Failed; exportación produce archivo validable | A2, alcance funcional aprobado |
| A7 | Corto: gates de cadena de suministro | Lock consistente, SCA, secretos, reglas SAST y tests; política de licencias y proveedor conciliada | Merge bloqueado por controles de sección 6; cero secretos reales; dependencias con identidad/procedencia documentadas | A2 y repositorio Git/CI |
| A8 | Mediano 1–3 meses: hardening de entradas/red | Límites de tamaño/tiempo/memoria, cancelación, validación TLS y redirecciones, aislamiento de parsers | Corpus hostil sin panic/hang; consumo acotado medido; no forwarding de credenciales entre orígenes | A6, implementación central completa |
| A9 | Mediano: observabilidad y procesos | Logging estructurado sin material secreto, IDs de operación, retención/acceso, revisiones AppSec y SBOM/procedencia | Reconstrucción de operación sensible; fixture secreto ausente de todas las salidas; release reproducible y artefacto firmado verificado | A4–A8; política de datos/despliegue |
| A10 | Mediano: inventario PQC y documentación fiel | Inventario de usos reales, dependencias y vida útil; migración específica por función; actualizar docs/pruebas | Cada promesa referencia control y test ejecutado; RSA/ECC no se clasifica PQ-safe por tamaño | Núcleo real y A4/A6 |

Estimación cualitativa: A1/A3 baja-media; A2/A4/A5/A6 alta por implementación faltante; A7 media; A8–A10 media-alta. No se recomienda invertir primero en pruebas de carga o rediseño cosmético antes de A1/A2.

## 6. Fase 4: diseño y código de pruebas, sin aplicación al repositorio

Estado: **pruebas propuestas, no ejecutadas**. La fase 3 está redactada para aprobación; estos bloques documentan cómo se comprobaría, sin crear ni modificar archivos del proyecto. No se ha demostrado todavía la secuencia rojo→verde. Los errores de compilación son blockers de ejecución y no pruebas que confirmen vulnerabilidades. Tras aprobación: reproducir en baseline compilable sin corregir el defecto, aplicar corrección y repetir.

### T-SEC-001: rechazar firmas inventadas y firma sin llave

Ubicación propuesta: `crates/suaya-signature/tests/regresion.rs`. APIs existentes; requiere primero reparar contratos y dependencias de compilación. La primera prueba falla con la expresión actual para `sig_inventada`; pasa con contención fail-closed y con verificación criptográfica real. La segunda demuestra el requisito de no firmar sin una llave válida.

```rust
use suaya_core::ScanResult;
use suaya_signature::{ResultSigner, ResultVerifier};

#[test]
fn rechaza_firma_inventada_para_cualquier_resultado() {
    let verifier = ResultVerifier::new();
    for target in ["fixture-a", "fixture-b"] {
        let result = ScanResult::new(target);
        for signature in ["sig_", "sig_inventada", "", "otra"] {
            assert!(!verifier.verify(&result, signature).unwrap_or(false));
        }
    }
}

#[test]
fn no_firma_sin_llave() {
    let result = ScanResult::new("fixture-local");
    assert!(ResultSigner::new().sign(&result).is_err());
}

#[test]
fn no_acepta_cadena_vacia_como_evidencia() {
    assert!(!ResultVerifier::new()
        .verify_chain(&[], "sig_inventada")
        .unwrap_or(false));
}
```

Para habilitar firma real añadir pruebas positivas de round-trip, rechazo de llave incorrecta, modificación individual de cada campo, truncamiento, longitudes grandes, cambio de versión/algoritmo, orden/longitud de cadena y rechazo de una sola mitad válida de firma híbrida. No se inventa API de generación de llaves que aún no existe.

### T-SEC-002: datos hostiles en cada campo del HTML

Ubicación propuesta: `crates/suaya-reports/tests/regresion.rs`. Importar ReportData desde `formats`; corregir previamente los imports internos del crate y serde del núcleo.

```rust
use suaya_core::{Finding, Severity};
use suaya_reports::formats::{HtmlFormat, ReportData, ReportFormat};

#[test]
fn html_escapa_todos_los_campos_de_texto() {
    let payload = "</title><script>document.title='SUAYA_TEST'</script><b>marca</b>&";
    let data = ReportData {
        title: payload.into(), target: payload.into(), scan_date: payload.into(),
        findings_count: 1, high_severity: 1, medium_severity: 0, low_severity: 0,
        findings: vec![Finding {
            id: "TEST".into(), severity: Severity::High,
            title: payload.into(), description: payload.into(), remediation: payload.into(),
        }],
    };
    let html = HtmlFormat.generate(&data).expect("generar HTML");
    assert!(!html.contains("<script>"));
    assert!(!html.contains("<b>marca</b>"));
    assert_eq!(html.matches("&lt;script&gt;").count(), 7);
}
```

Son siete inserciones: title aparece dos veces, target, date y tres campos Finding. Esta prueba falla en el generador actual. Complementar con prueba DOM en navegador local aislado, sin red: script no ejecutado, ningún atributo de evento originado por datos, texto visible preservado tras decode HTML. Incluir `&`, comillas, Unicode, etiquetas mal cerradas y `</title>`. La comprobación DOM es más fuerte que buscar substrings; no dar esta prueba unitaria por garantía universal de XSS.

### T-SEC-003: rutas sensibles no permiten acceso anónimo

Ubicación propuesta: `crates/suaya-api/tests/auth.rs`. Solo aplicable si se elige Axum. Requiere `tower` con feature `util` como dev-dependency y versión HTTP compatible con Axum seleccionado. No introducirlo si se opta por Actix; usar entonces su test harness.

```rust
use axum::{body::Body, http::Request};
use tower::ServiceExt;
use suaya_api::create_router;

#[tokio::test]
async fn rutas_sensibles_no_admiten_anonimos_ni_bearer_inventado() {
    let cases = [
        ("GET", "/api/v1/scans"),
        ("GET", "/api/v1/scan/fixture"),
        ("DELETE", "/api/v1/scan/fixture"),
        ("POST", "/api/v1/scan"),
        ("GET", "/api/v1/config"),
        ("PUT", "/api/v1/config"),
    ];
    for (method, path) in cases {
        for token in [None, Some("Bearer inventado")] {
            let mut request = Request::builder().method(method).uri(path);
            if let Some(value) = token {
                request = request.header("Authorization", value);
            }
            let response = create_router().oneshot(
                request.body(Body::empty()).unwrap()
            ).await.unwrap();
            let status = response.status().as_u16();
            // 404 solo es aceptable mientras la función está deshabilitada.
            assert!(matches!(status, 401 | 403 | 404));
        }
    }
}
```

Con router actual compilable los stubs responderían 200: falla. Con contención de retirar rutas devuelve 404: pasa, pero no certifica IAM. Al habilitar funciones, sustituir por 401 obligatorio para falta/invalidez de credencial, 403 para usuario autenticado sin permiso, y pruebas positivas con tokens válidos 200/201. No permitir que 404 perpetuo satisfaga la aceptación final.

### Pruebas de defectos de producto

- CAL-001: parser TOML y metadata con `--locked` deben pasar; todos los members tienen target; no lock desactualizado. Ya se ejecutó validación TOML y falló en línea 89.
- CAL-002/004: backend fake inyectable con resultado conocido; solo su respuesta alimenta inventario; Unsupported/Failed nunca se muestra como Completed limpio. Fixture real con material de test conocido, sin secretos de producción.
- CAL-003: un Finding Critical debe aparecer explícitamente en resumen y policy; probar 0, 1 y múltiples Critical junto con High. Documentar qué umbral se desea antes de codificar el gate.
- CAL-005: en entorno temporal, reemplazar `swiftc` por programa de prueba que termina con 1; el empaquetador debe terminar no cero y no llamar hdiutil ni producir app/DMG. No ejecutar ese script actual contra build real.
- BP-003: iniciar, cancelar/limpiar y esperar; estado permanece vacío, sin tareas antiguas que repueblen; dos inicios no producen ejecuciones simultáneas no autorizadas.

### Property tests y fuzzing

Ejemplo de property test propuesto para `suaya-reports/src/formats.rs`, dentro de módulo tests con acceso al helper, después de añadir `proptest` como dev-dependency revisada:

```rust
proptest::proptest! {
    #[test]
    fn texto_html_no_contiene_delimitadores_activos(s in ".{0,4096}") {
        let escaped = html_text(&s);
        proptest::prop_assert!(!escaped.contains('<'));
        proptest::prop_assert!(!escaped.contains('>'));
    }
}
```

Agregar propiedad de round-trip `decode_entities(html_text(s)) == s` con parser independiente. Firma: toda modificación de bytes cubiertos invalida firma; ninguna cadena aleatoria sin llave válida se acepta. Tokens: encabezados/claims/longitudes arbitrarios producen rechazo sin panic. Parsers de archivos y protocolos: aprovechar tres harnesses existentes solo después de restaurar sus APIs, acotar entrada por caso y exigir límites de memoria/tiempo. Propuesta de CI: corpus de regresión en cada PR y fuzzing nocturno de 10 minutos por target, con RSS limitado a 1 GiB y timeout de 10 s por caso; calibrar esos valores con el núcleo real. No afirmar que hay fuzzing operativo actualmente.

### SAST, SCA, secretos y DAST

Semgrep: reglas locales iniciales, precisas para los fragmentos observados. Son propuestas no validadas con el parser de Semgrep; antes de bloquear merge ejecutar `semgrep validate` y pruebas positivas/negativas de las reglas. No suponer que una regla genérica detecta IAM o una firma falsa por sí sola.

```yaml
rules:
  - id: suaya-prefix-is-not-signature-verification
    languages: [rust]
    message: No autenticar una firma mediante un prefijo
    severity: ERROR
    paths:
      include: [crates/suaya-signature/src/verifier.rs]
    pattern: Ok($SIG.starts_with("sig_"))
  - id: suaya-public-hash-is-not-signature
    languages: [rust]
    message: Hash público utilizado como firma
    severity: ERROR
    paths:
      include: [crates/suaya-signature/src/signer.rs]
    pattern: format!("sig_{}", $HASH)
  - id: suaya-unescaped-html-field
    languages: [rust]
    message: Campo de texto de reporte insertado sin escape HTML
    severity: ERROR
    paths:
      include: [crates/suaya-reports/src/formats.rs]
    pattern-either:
      - pattern: $OUT.push_str(&$DATA.title)
      - pattern: $OUT.push_str(&format!("<p><strong>Target:</strong> {}</p>", $DATA.target))
      - pattern: $OUT.push_str(&format!("<p>{}</p>", $FINDING.description))
  - id: suaya-bearer-prefix-only
    languages: [rust]
    message: Reconocer Bearer no valida identidad ni token
    severity: ERROR
    paths:
      include: [crates/suaya-api/src/middleware.rs]
    pattern: |
      if $TOKEN.starts_with("Bearer ") {
        return Ok($REQ.into_response());
      }
```

Estas reglas cubren el código concreto, no todas las variantes ni la ausencia de layers en router: para eso son necesarias T-SEC-003 y revisión de autorización. Registrar estas limitaciones evita confianza excesiva en SAST.

Configuración propuesta del job de verificación, tras restaurar fuentes e instalar herramientas con versiones/digests fijados:

```sh
cargo metadata --locked --format-version 1
cargo check --workspace --all-targets --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo deny check advisories bans licenses sources
semgrep validate --config security/semgrep.yml
semgrep scan --config security/semgrep.yml --error --strict --metrics off .
gitleaks dir . --redact --exit-code 1
# Solo al disponer del repositorio Git completo:
gitleaks git . --redact --exit-code 1
```

Los archivos security/semgrep.yml y tests mencionados son destinos propuestos, no archivos creados. Clippy no sustituye SAST. Cargo-deny proporciona SCA de RustSec/licencias/origen; refrescar la base de avisos y registrar fecha. Cargo.lock viejo no permite dictamen del grafo final. Revisar además la identidad, propietarios y mantenimiento de dependencias agregadas; no bloquear solo por una antigüedad arbitraria. Resolver primero la prohibición local de ring.

CodeQL es opción complementaria con soporte documentado para Rust y Swift: usar suites de seguridad compatibles con la versión fijada y build macOS para Swift cuando corresponda. No prometer una query estándar que detecte automáticamente los tres defectos de negocio. Trivy, si se distribuye Docker, debe revisar imagen final y configuración para vulnerabilidades y secretos; incorporar digest y SBOM de cada release.

DAST: OWASP ZAP baseline contra **staging propio/autorizado**, con contexto y lista de rutas aprobados. Usar OpenAPI cuando exista para cubrir API; baseline por sí solo no demuestra autorización. Reglas relevantes: 40012 XSS reflejado y 40014 XSS persistente requieren escaneo activo y una superficie web correspondiente; no detectarán por sí mismas la inyección de un archivo HTML local generado offline. Para ese caso usar la prueba DOM local. Missing CSP, regla pasiva 10038, es defensa adicional y no reemplaza SEC-002. No se ejecutó ZAP ni escaneo activo.

Gates propuestos: build/test fallido bloquea; todo ERROR de reglas locales bloquea; cualquier secreto real nuevo bloquea; avisos RustSec no exceptuados, orígenes/licencias/proveedores prohibidos bloquean conforme a deny.toml; hallazgos SAST/SCA/DAST altos o críticos confirmados bloquean merge; SEC-001/002/003 bloquean habilitar sus funciones aunque la puntuación contextual sea media. Excepciones con responsable, justificación, mitigación y vencimiento, nunca supresiones globales. Pruebas y packaging deben ser required status checks; `permissions: contents: read` por defecto, privilegios de publicación en job separado protegido, sin secretos para PR de forks, acciones fijadas por commit real verificado. No se insertan hashes inventados de actions en un workflow supuestamente listo para usar.

## 7. Cobertura, supuestos y limitaciones

- Se enumeraron 60 archivos Rust y 8 Swift bajo crates; enumerar no equivale a revisar completamente cada línea. Lectura detallada: core; CLI; API; firma; almacenamiento/consultas/migración; reportes; validación; automatización; ScannerManager, reportes/PQC/settings/app Swift; prototipos de scanners cloud, code, container, secret y network; documentación de arquitectura/amenazas/auditoría; manifiestos, lock, deny y empaquetado. TUI e internacionalización se inspeccionaron como soporte, sin auditoría exhaustiva de UI.
- No se validó exhaustivamente cada regla de conocimiento ni su correspondencia con normas. No se revisaron internamente AWS-LC/rustls, parsers de dependencias, binarios empaquetados, DMG ni sus firmas. No se ejecutó el binario ni se intentó inferir su procedencia a partir del nombre.
- `git rev-parse --show-toplevel` falló: esta carpeta no es repositorio Git. No hay base para auditar historia, branches, remotos o secretos eliminados.
- `cargo metadata --locked --offline --no-deps --format-version 1` no arrancó: `cargo` no está en PATH. No hay resultados de cargo test/check/deny, SAST, DAST ni cobertura dinámica. No se instaló toolchain ni se ejecutaron builds del proyecto.
- Se ejecutaron inventario de archivos, lecturas y validación TOML/lock con Python; cálculo de vectores CVSS en /tmp. Se descargó exclusivamente calculadora cvss==3.6 a directorio temporal; no se enviaron fuentes ni secretos a ese paquete ni a servicios externos.
- Datos legales, roles, perímetro y prioridad de negocio siguen sin especificarse. No se presume un servidor público. El backend incompleto impide confirmar exploits remotos y emitir una certificación.
- Para cerrar revisión: fuentes completas con commit verificable, toolchain y build reproducible, CI real, diagrama de despliegue/IAM, política de datos/retención, matriz de roles, formato de firma y raíces de confianza, SBOM/grafo de dependencias resuelto y entorno autorizado de pruebas.

## 8. Matriz de trazabilidad y marcos de referencia

Los enlaces a ASVS corresponden al catálogo 5.0.0 consultado. La matriz es de correspondencia técnica, no declaración de cumplimiento completo. ISO se mapea a controles de Anexo A de ISO/IEC 27001:2022; ISO/IEC 27002:2022 proporciona orientación. Validar contra la copia normativa licenciada y la Statement of Applicability de la organización. No se reprodujo el texto normativo de ISO.

| Elemento | CWE | ASVS 5.0.0 | ISO Anexo A (correspondencia) | SSDF SP 800-218 | Evidencia/prueba |
|---|---|---|---|---|---|
| SEC-001 | 347, 345 | 11.2.1 (implementación criptográfica validada); 11.1.1 (ciclo de llaves); 11.1.4 (migración) como relacionados, no requisito específico de formato de firma | 8.24, 8.28, 8.29 | PW.5, PW.7, PW.8 | T-SEC-001 y round-trip/tamper/hybrid pendientes |
| SEC-002 | 79 | 1.1.2, 1.2.1 (escape final y contextual) | 8.28, 8.29 | PW.5, PW.7, PW.8 | T-SEC-002, property test y DOM |
| SEC-003 | 306, 287 | 8.3.1 (enforcement en capa confiable); 6.8.2 solo si se adopta JWT/assertions de IdP | 8.3, 8.5, 8.28, 8.29 | PW.1, PW.5, PW.8 | T-SEC-003; matriz de rol/objeto y JWT pendiente |
| CAL-002/004 | No se asigna CWE sin contrato operativo | 2.1.3/2.3.2 como expectativas de negocio relacionadas | 8.25, 8.28, 8.29 | PO.1, PW.1, PW.8 | Fixtures, estados de ejecución y no-demo |
| CAL-003 | No se fuerza clasificación CWE | Política de negocio a definir; 2.3.2 relacionado | 8.28, 8.29 | PW.5, PW.8 | Fixture Critical |
| CAL-001/005, BP-001/002 | No son CVE ni vulnerabilidad remota demostrada | No equivalencia directa de build con requisito web ASVS | 8.25, 8.29, 8.32 | PO.3, PO.4, PS.2, PS.3, PW.4 | Metadata/build, SCA, packaging fail-closed, procedencia |

CWE Top 25 se usa como taxonomía complementaria, no como lista exhaustiva de controles. Los CWE asignados no se presentan como miembros de una edición concreta del Top 25 sin comprobar esa edición. OWASP Top 10 vigente consultado es 2025: SEC-002 corresponde a Injection; SEC-003 a Authentication Failures/Broken Access Control; SEC-001 a fallas criptográficas/integridad según la función afectada. OWASP LLM Top 10 2025 no aplica a código LLM inexistente en este alcance.

### Fuentes primarias consultadas

- [OWASP ASVS 5.0.0, catálogo de requisitos](https://raw.githubusercontent.com/OWASP/ASVS/master/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.flat.json): numeración usada en la matriz. No se citan controles de ASVS 4.x como si fueran 5.0.
- [OWASP Top 10:2025](https://top10.owasp.org/2025/): edición vigente consultada y categorías de riesgo.
- [OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/): alcance de riesgos de aplicaciones con modelos; no se presume que el asistente de formularios use un modelo.
- [FIRST CVSS v4.0](https://www.first.org/cvss/v4.0/specification-document) y [calculador](https://www.first.org/cvss/calculator/v4.0): significado de vectores y evaluación contextual. Puntuaciones reproducidas con calculadora local, no certificadas por FIRST.
- [NIST SSDF SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final): organización de prácticas de desarrollo seguro, revisión y pruebas.
- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) y [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final): ML-KEM para KEM y ML-DSA para firmas. No se recomienda reemplazar una firma por ML-KEM.
- [ISO/IEC 27002:2022](https://www.iso.org/standard/75652.html): referencia de orientación de controles; mapeo no equivale a certificación.
- [CodeQL: lenguajes y frameworks soportados](https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks/): soporte de Rust y Swift para análisis complementario.
- [Semgrep CLI](https://docs.semgrep.dev/cli-reference): configuración local, validación y modo de fallo con findings.
- [cargo-deny checks](https://embarkstudios.github.io/cargo-deny/checks/index.html): advisories, bans, licencias y fuentes.
- [Gitleaks](https://github.com/gitleaks/gitleaks): análisis de directorio y Git con salida redactada.
- [ZAP baseline](https://www.zaproxy.org/docs/docker/baseline-scan/): alcance pasivo y limitaciones; no reemplaza pruebas autenticadas ni DOM offline.

**Decisión pendiente:** aprobar A1–A3 para contención y recuperación de build, junto con el alcance funcional/IAM/criptografía de A4–A6. Hasta esa aprobación no se aplican cambios al repositorio. El dictamen se limita a esta copia y debe reevaluarse después de restaurar las fuentes y ejecutar las pruebas.
