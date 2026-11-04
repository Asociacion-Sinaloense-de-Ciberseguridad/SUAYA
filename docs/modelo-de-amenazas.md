# Actualización 1.4

El alcance y los controles de API, GUI, persistencia, tokens y límites nuevos se detallan en [cierre 1.4](cierre-1.4.md). El cliente HTTP ya no permite `sin_verificar` para transferencias; kubeconfig y sus plugins exec requieren confianza del operador. Las rutas y directorios deben estar bajo control de la cuenta del servicio.

# Modelo de amenazas

Suaya lee lo que otros escribieron: archivos de configuración, llaves, certificados, binarios, imágenes de contenedor, respuestas de servidores y CBOM de otras herramientas. Todo eso puede estar dañado o haber sido preparado por un atacante. Este documento describe qué protege Suaya, de quién y cómo, para orientar a quien lo use, lo revise o lo audite.

## Activos que se protegen

1. **El material secreto del sistema inventariado.** Llaves privadas, contraseñas y frases de paso que Suaya encuentra al escanear. Es el activo más valioso y la razón por la que existe la primera regla del proyecto.
2. **El equipo donde corre Suaya.** Suele correr con privilegios amplios de lectura (para ver `/etc` completo) y a veces en servidores de producción.
3. **La integridad del inventario.** Un CBOM que esconde un activo vulnerable o lo marca como conforme lleva a decisiones equivocadas.
4. **La llave de firma de Suaya** de quien firma sus CBOM.
5. **La cadena de suministro de Suaya**: que el binario que se descarga sea el que se compiló desde este código.

## Adversarios

| Adversario | Qué controla | Qué busca |
|---|---|---|
| A1. Contenido malicioso en el sistema escaneado | Archivos, imágenes de contenedor, manifiestos | Ejecutar código, leer fuera de las rutas pedidas, bloquear el escaneo, esconder activos |
| A2. Servidor o red hostil | Las respuestas de un servicio sondeado, un registro o una API de Kubernetes | Lo mismo que A1, más obtener credenciales |
| A3. CBOM de terceros | Un JSON que se importa con `importar` | Inyectar activos falsos o hacer fallar el proceso |
| A4. Lector del CBOM o del reporte | Acceso a los archivos generados | Obtener secretos del sistema inventariado |
| A5. Atacante de la cadena de suministro | Una dependencia, el sistema de compilación o la descarga | Distribuir un binario alterado |

## Controles

### Material secreto (contra A4)

- Suaya nunca copia el contenido de una llave privada, una contraseña o un secreto: registra tipo, tamaño, formato, protección, ubicación y la identidad de la llave pública derivada. Una prueba automática (`crates/suaya-cbom/tests/sistema_demo.rs`) busca cada secreto del sistema de demostración en el CBOM y falla si aparece.
- La misma prueba cubre los reportes en Markdown y HTML, en español y en inglés, y los avisos del escaneo, con los fragmentos de cada llave privada, llave de WireGuard y Secret de Kubernetes del sistema de demostración.
- La llave privada de firma se escribe con permisos `0600`, sin sobrescribir un archivo existente, y cifrada con PBKDF2-HMAC-SHA256 (600 000 iteraciones) y AES-256-GCM si se da una frase de paso. La frase de paso solo se lee de una variable de entorno, nunca de un argumento (que quedaría en el historial y en la lista de procesos).

### Entradas hostiles (contra A1, A2 y A3)

- Rust sin `unsafe` en todo el código propio (`unsafe_code = "forbid"`). Los errores de memoria quedan limitados a las dependencias.
- Ningún escáner ejecuta, interpreta ni carga lo que lee: no hay evaluación de plantillas, de YAML con etiquetas, de clases Java ni de scripts.
- Límites de recursos: tamaño máximo de archivo (5 MiB por omisión), lectura por bloques de binarios grandes con memoria acotada, límites de tamaño en respuestas de red, en capas de imagen y en documentos de la API de Kubernetes, y tiempo límite por conexión.
- No sigue enlaces simbólicos salvo que se pida (`--seguir-enlaces`), y al extraer imágenes de contenedor no escribe en disco ni resuelve rutas fuera de la capa.
- Un archivo malformado produce un aviso y el escaneo continúa. Las pruebas de robustez (`tests/robustez.rs` en cada crate) mutan cada archivo del sistema de demostración y exigen que ningún escáner entre en pánico; los objetivos de `fuzz/` hacen lo mismo de forma guiada por cobertura.
- Las descargas de registros verifican el resumen SHA-256 de cada manifiesto y capa antes de usarlos.
- Un CBOM importado no se toma como verdad: cada activo se reclasifica con el criterio de Suaya y registra su procedencia (archivo y herramienta de origen).

### Red (contra A2)

- Solo se usa la red cuando se pide de forma explícita, y solo contra los objetivos que la persona nombra: Suaya no recorre rangos de direcciones ni descubre puertos.
- El sondeo TLS y SSH no envía datos de aplicación ni credenciales. Para inventariar lo que el servidor ofrece acepta cualquier certificado, pero nunca continúa la conexión después del saludo.
- Las conexiones a registros y a la API de Kubernetes sí verifican el certificado contra las raíces del sistema o la autoridad configurada, y nunca envían credenciales a un servidor cuyo certificado no se verificó. Las credenciales de un registro solo se envían al registro al que pertenecen.
- La orden `kubernetes` solo hace lecturas (`GET`).

### Integridad del inventario (contra A1 y A3)

- La clasificación vive en datos versionados (`conocimiento/`) que se revisan como código; cada CBOM registra la versión de cada base.
- Lo que no se reconoce no se marca como conforme: un algoritmo desconocido se clasifica con riesgo «desconocido», nunca como seguro, y un activo que ninguna regla del perfil alcanza queda «sin evaluar», no como cumplido.
- La firma híbrida (`suaya firmar`) permite comprobar que un CBOM no cambió después de generarse. `verificar` exige que las dos firmas, ML-DSA-65 y Ed25519, sean válidas sobre un mensaje con separación de dominio, de modo que romper un solo algoritmo no basta para falsificarla.

### Cadena de suministro (contra A5)

- Dependencias al mínimo, con `Cargo.lock` versionado y `--locked` en toda compilación.
- `cargo-deny` revisa en cada cambio los avisos de seguridad de RustSec, las licencias y que todo provenga de crates.io; también impide que entre un segundo proveedor criptográfico (solo AWS-LC).
- Las acciones de GitHub se fijan por su *commit*, no por etiqueta.
- Las compilaciones son reproducibles y se verifican en la integración continua; cada paquete publicado lleva procedencia SLSA firmada con Sigstore y la lista `SHA256SUMS` puede llevar además la firma híbrida de Suaya. Ver [publicacion.md](publicacion.md).

## Fuera de alcance

- **Un sistema ya comprometido** en el que el atacante controla el núcleo, el sistema de archivos o el propio binario de Suaya. Un inventario no detecta un *rootkit*.
- **Material ofuscado a propósito.** Una llave cifrada con un esquema propio, partida en varios archivos o generada en tiempo de ejecución no se detectará. Suaya inventaría lo que un sistema expone de forma ordinaria.
- **Exactitud absoluta del análisis de código.** El escáner de código fuente es léxico: reconoce llamadas a API criptográficas conocidas, no sigue el flujo de datos. Puede haber falsos positivos y falsos negativos; el CBOM indica la línea para revisarla.
- **Denegación de servicio por volumen.** Escanear un directorio enorme tarda en proporción a su tamaño; los límites evitan que un solo archivo agote la memoria, no que el escaneo completo sea largo.
- **Fallas de AWS-LC o de otras dependencias.** Se mitigan manteniéndolas al día y con el aviso de RustSec, no se eliminan.

## Supuestos

- Quien ejecuta Suaya tiene derecho a leer lo que escanea y a sondear los servicios que nombra.
- El CBOM y los reportes se guardan con el mismo cuidado que cualquier inventario de seguridad: no contienen secretos, pero sí describen dónde están las llaves y qué tan débiles son.
