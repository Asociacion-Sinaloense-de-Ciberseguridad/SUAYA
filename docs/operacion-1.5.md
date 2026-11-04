# Operación SUAYA 1.5

## Registros OCI y compatibilidad

TLS es obligatorio por defecto, incluso para loopback. Para desarrollo local usar `--registro-http-local`; solo admite IP loopback real o localhost resuelto a loopback. Se rechaza cualquier downgrade HTTPS a HTTP. No autorizar HTTP para un registro de producción.

Los desafíos 401 de otro origen tras una redirección se rechazan. Un realm externo necesita `--registro-token-origen REGISTRO=https://auth.example`; la regla solo vale para ese registro, esquema, host y puerto. No derive esta lista del desafío recibido. Docker Hub incluye la relación conocida docker.io -> https://auth.docker.io. Un token se solicita únicamente con alcance pull del repositorio analizado. Redirecciones de contenido no reciben Authorization.

## API: identidad, revocación y acceso

Ejecutar con cuenta de servicio dedicada; directorio de datos 0700 y config/base 0600. La API permanece en loopback. Para acceso remoto, el proxy debe autenticar/TLS, limitar conexiones y solicitudes por cliente, y rotar sus logs. La API no confía en X-Forwarded-For. Las solicitudes anónimas comparten un bucket limitado; las válidas tienen 60 solicitudes por identidad/minuto y dos escaneos simultáneos. Esto evita que el tráfico anónimo consuma la cuota válida; no sustituye límites de conexión del sistema operativo.

Una credencial acepta `"targets":["alias1","alias2"]`. Lista vacía impide escanear; campo ausente conserva acceso a todos los alias para compatibilidad. Administradores tienen todos los alias. Los reportes siguen restringidos por propietario salvo administrador.

Para revocar/rotar, editar los hashes y expiración en config.json y enviar `kill -HUP PID` en Unix. La validación es atómica: configuración inválida conserva la política previa y registra success=false. Los alias deben permanecer iguales; cambiarlos requiere reinicio. Las solicitudes ya admitidas pueden terminar. En Windows se requiere reiniciar. No publicar tokens.json. Rotación recomendada máxima de 90 días; revocar inmediatamente ante incidente.

Los logs JSON incluyen evento, request_id generado internamente, usuario validado o null, método, plantilla de ruta, UUID de objeto, status, duración y fecha. No incluyen tokens, cuerpos ni queries. Los errores internos devuelven respuestas genéricas; correlacionar el status 500 con request_id en el log de solicitud. Configurar rotación por tamaño/retención en el supervisor y exportación a un destino protegido; la app escribe stderr, no administra un SIEM.

## Persistencia y recursos

SQLite tiene cuotas de 1000 filas por propietario, 16 MiB por documento, 128 MiB por propietario y 512 MiB total de documentos; max_page_count limita crecimiento físico a unas 576 MiB con páginas de 4096 bytes. El journal DELETE puede requerir espacio adicional. Monitorizar espacio libre y reservar al menos 1 GiB. Retención de 30 días aplicada antes de nuevas inserciones y por mantenimiento al inicio y cada hora, incluso sin nuevos escaneos. El margen de purga por fecha es de hasta una hora mientras el servicio permanece activo. secure_delete borra contenido de páginas liberadas, pero no copias previas, snapshots o backups.

SQLite no incorpora cifrado de aplicación: usar FileVault/LUKS/BitLocker y respaldos cifrados con llaves fuera de la carpeta. Realizar backups mediante SQLite backup API o con el servicio detenido, con permisos 0600 en directorio 0700. Probar restauración periódicamente. No copiar una base activa con operaciones de escritura sin mecanismo consistente.

Límites: binario individual 512 MiB leídos, imágenes externas 64 GiB, metadatos candidatos agregados 32 MiB, 1000 capas y 100000 entradas de imagen, 16 GiB descomprimidos y 120 s cooperativos por analizador. Kubernetes: 100 páginas, 25000 objetos, 64 MiB y 120 s cooperativos por colección; tokens repetidos abortan. Límites de tiempo entre operaciones no interrumpen instantáneamente un syscall bloqueado. Un proceso supervisado con límites de memoria/tiempo es necesario para un SLO estricto; el runner de automatización tiene timeout de proceso.

Ausencias, duplicados, errores y límites producen error o estado parcial. `--fallar-si-incompleto` debe usarse para gates. Un Docker archive carece de digests criptográficos obligatorios para sus capas; se valida estructura/presencia, sin afirmar autenticidad. OCI valida SHA-256 de manifiestos y capas con sus tamaños. El soporte multiplataforma selecciona la primera imagen en archivo OCI local; para registro remoto usar --plataforma.

## macOS y distribución

La exportación usa un directorio temporal privado sin ACL heredadas y rename atómico en el mismo filesystem, sin preservar los metadatos públicos del destino previo. La prueba usa un destino 0644 y una ACL pública heredable. Archivos y directorios deben estar en un filesystem con semántica Unix compatible.

El build limpia atributos extendidos antes de firmar y verifica también la copia del bundle usada para el DMG. Verificar nuevamente después de mover al sistema de distribución: Finder/file-provider pueden añadir atributos. La firma local es ad-hoc. Developer ID, notarización y attestation remota requieren credenciales/ejecución del propietario; no se simulan ni se declaran realizados.

## CI y cadena de suministro

Clippy con deny warnings, cargo test, regresiones dinámicas, privacidad Swift, esquema CBOM, Semgrep (7 reglas), cargo-deny y Gitleaks son gates. CI mide cobertura LLVM y conserva el informe; no se fija un porcentaje arbitrario sin línea base estable. Fuzzing acotado aporta casos adicionales; campañas largas deben ejecutarse en workers aislados. La lista SAST fija dependencias transitivas por versión. Trivy 0.76.0 se verifica por SHA-256 oficial antes de analizar la imagen; altos/críticos bloquean el job. Snapshot Debian y bases por digest requieren mantenimiento periódico, aunque sean reproducibles.

El manifest de build registra herramientas, dependencias y hashes; no prueba autoría por sí solo. El workflow de publicación conserva attestation de procedencia y crea borradores tras gates. Linux, Windows, contenedor y CI remoto requieren sus runners para validación de extremo a extremo.
