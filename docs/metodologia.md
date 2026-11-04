# Metodología de clasificación

## Los cuatro ejes

### 1. Riesgo

| Riesgo | Significado | Ejemplos |
|---|---|---|
| Roto (clásico) | Inseguro hoy, sin computadora cuántica | MD5 o SHA-1 en firmas, RSA menor a 2048 bits, 3DES, SSL 3.0 |
| Obsoleto | No está roto, pero los estándares lo retiraron | TLS 1.0 y 1.1 (RFC 8996), DSA (FIPS 186-5), HMAC-SHA-1 |
| Vulnerable a cómputo cuántico | Roto por el algoritmo de Shor | RSA, ECDSA, EdDSA, ECDH, X25519, Diffie-Hellman |
| Debilitado por Grover | Margen reducido; aceptable para NIST, no para CNSA 2.0 | AES-128 |
| Híbrido | Clásico combinado con poscuántico | X25519MLKEM768, mlkem768x25519-sha256 |
| Resistente | Resiste los ataques cuánticos conocidos | ML-KEM, ML-DSA, SLH-DSA, AES-256, SHA-384 |
| Desconocido | Información insuficiente | Llave cifrada, configuración implícita |

El riesgo de RSA depende del tamaño: por debajo de 2048 bits se considera roto. Este umbral, como todos, está en `conocimiento/algoritmos.toml` (`tamano_minimo_clasico`).

### 2. Garantía

Confidencialidad y autenticación se evalúan por separado, porque el ecosistema avanza a ritmos distintos en cada una. En casi todas las capacidades, la confidencialidad (intercambio de llaves) está más madura que la autenticación (firmas y certificados). La integridad (hash, MAC) no requiere migración por Shor.

### 3. Capacidad tecnológica

Cada hallazgo se asocia a una capacidad según su contexto:

| Contexto | Capacidad |
|---|---|
| Configuración de nginx, Apache, HAProxy, PostgreSQL, MySQL o MariaDB, Postfix o Java (`java.security`); certificado con uso `serverAuth` | Servidores web (todos salvo nginx y Apache por decisión de Suaya, editable: terminan TLS como un servidor y comparten bibliotecas y madurez) |
| Configuración y llaves SSH | VPN y cifrado de red (decisión de Suaya, editable) |
| Certificado de autoridad (`CA:TRUE`) | PKI y autoridades certificadoras |
| Certificado con uso `codeSigning` | Firma de código |
| `crypttab` | Cifrado de volumen |
| Código fuente y bibliotecas criptográficas | Código de aplicaciones (decisión de Suaya, editable) |
| Sin contexto suficiente | Sin clasificar |

### 4. Madurez del ecosistema

Escala de siete niveles: No aplica, Bloqueado, Habilitado, Componentes disponibles, Integración preliminar, Integración e Integración validada (con módulo FIPS 140-3). Los niveles por capacidad provienen del *Post-Quantum Cryptography (PQC) Capability Development Report* de MITRE, edición de septiembre de 2026, con evidencia de julio de 2026.

## De los ejes a la acción

```
si riesgo = roto                 → Corregir de inmediato   (prioridad 1)
si riesgo = obsoleto             → Reemplazar              (prioridad 2)
si riesgo = vulnerable:
    madurez ≥ Integración        → Migrar ahora            (2 confidencialidad, 3 autenticación)
    madurez ≥ Componentes        → Planificar y piloto     (3 confidencialidad, 4 autenticación)
    en otro caso                 → Monitorear              (4)
si riesgo = desconocido          → Verificar               (3)
si riesgo = debilitado (Grover)  → Revisar parámetros      (4)
si riesgo = híbrido o resistente → Conforme                (5)
```

Cuando un activo tiene varios contextos (por ejemplo, la misma curva en un servidor web y en una llave suelta), se reporta el contexto más urgente.

## Enlace entre llaves

Una llave privada que comparte identidad con un certificado hereda los contextos de uso del certificado y deja de estar «sin clasificar». Si la misma llave privada aparece en varias ubicaciones, cada copia recibe una advertencia.

## Advertencias adicionales

- **Vigencia larga**: un certificado con algoritmo vulnerable que vence después de 2030 recibe una advertencia basada en las fechas de transición de NIST IR 8547 (borrador inicial, noviembre de 2024). Las fechas están en `[politica]` de `algoritmos.toml`.
- **Permisos**: una llave privada sin cifrar legible por grupo u otros.
- **Configuración implícita**: cuando nginx, Apache u OpenSSH no declaran los grupos o el intercambio de llaves, el resultado depende de la versión instalada (OpenSSL 3.5 y OpenSSH 10.0 ya prefieren híbridos con ML-KEM) y se marca para verificación.
- **Compatibilidad hacia atrás**: un servidor que ofrece un híbrido pero también acepta grupos clásicos o TLS 1.2 se reporta como conforme con advertencia, porque los clientes antiguos negociarán sin protección poscuántica.

## Hallazgos de red

En la red, el riesgo de un servicio TLS combina:

- **Versiones**: aceptar SSL 3.0, TLS 1.0 o 1.1 lo hace roto u obsoleto. Sin TLS 1.3 no puede negociar híbridos.
- **Grupos**: si acepta al menos un grupo híbrido o ML-KEM, se considera híbrido; si no, vulnerable.
- **Preferencia**: Suaya ofrece todos los grupos dos veces, clásicos primero y poscuánticos primero. Informa si el servidor prioriza el híbrido, si sigue el orden del cliente (los navegadores modernos ofrecen primero `X25519MLKEM768`) o si elige el clásico aun cuando el cliente ofrece primero el híbrido; este último caso se advierte como un problema de configuración.
- **TLS 1.2**: una suite con 3DES es crítica; un intercambio RSA estático se advierte por falta de secreto perfecto hacia adelante.

En SSH, el riesgo se calcula sobre el `KEXINIT` con las mismas reglas que para `sshd_config`.

## Imágenes de contenedor

Cada capa se lee en orden. Si una capa agrega una llave privada y una capa posterior la borra (archivo `.wh.`) o la reemplaza, el contenedor en ejecución ya no la ve, pero la capa original sigue dentro de la imagen: cualquiera que descargue la imagen puede extraerla. Suaya lo advierte en la llave afectada y recomienda reconstruir la imagen y revocar la llave. Toda llave privada dentro de una imagen se advierte, porque viaja a cada registro y equipo donde se copia la imagen.

## Imágenes desde un registro

Una imagen descargada (`docker://`) se analiza igual que un archivo tar, con dos garantías adicionales: el manifiesto y cada capa se comparan con su resumen SHA-256, y los hallazgos solo se agregan al inventario cuando todas las capas se verificaron. Una imagen alterada en tránsito o en el registro se descarta completa, sin hallazgos parciales.

## Bases de datos, correo y Java

- **MySQL y MariaDB**: MySQL cifra por omisión desde 5.7 (TLS 1.2 y 1.3 en las versiones actuales); MariaDB solo desde 11.4, así que sin opciones de TLS su estado se marca para verificar. Ninguno fija los grupos de intercambio de llaves en la configuración: dependen de la versión de OpenSSL enlazada (desde 3.5 incluyen X25519MLKEM768), por lo que el resultado es «verificar» salvo que algo lo agrave. Se advierte cuando no se exige transporte cifrado y cuando MySQL usa el certificado autofirmado que genera por sí mismo.
- **Postfix**: sin STARTTLS (`none`) el correo viaja en claro y el riesgo es inmediato. El TLS oportunista (`may`) es lo habitual para recibir correo de Internet, pero un atacante en la red puede suprimirlo; se advierte y se sugiere `encrypt`, DANE o MTA-STS. Las curvas de `tls_eecdh_auto_curves` se evalúan como los grupos de cualquier servidor TLS.
- **Java**: las listas predeterminadas de `java.security` ya excluyen lo roto. Suaya revisa qué se retiró de ellas: una versión de TLS que vuelve a habilitarse o un cifrador roto que deja de excluirse domina el riesgo, y un resumen roto aceptado en certificados o en JAR firmados lo agrava a obsoleto.

## Código fuente

El código se analiza en dos pasos. Primero, un analizador léxico de cada lenguaje sustituye los comentarios por espacios sin mover el resto del texto (las cadenas se conservan, porque ahí suelen ir los nombres de algoritmo), así que un algoritmo mencionado en un comentario no cuenta y las líneas reportadas coinciden con el archivo. Después se aplican las reglas de `conocimiento/codigo.toml`: expresiones regulares por lenguaje que capturan el nombre del algoritmo y, cuando el código lo fija, el tamaño de llave. No es un análisis de flujo de datos: si el algoritmo llega por una variable, Suaya registra la llamada sin el detalle.

Algunas decisiones que conviene conocer:

- En Java, `Cipher.getInstance("AES")` equivale a AES en modo ECB y se reporta así.
- Un algoritmo genérico (RSA sin tamaño, AES sin tamaño, una curva no determinada) se descarta si el mismo archivo ya fija la variante.
- Desactivar la verificación de certificados (`verify=False`, `InsecureSkipVerify`, `rejectUnauthorized: false`, un `TrustManager` vacío, `SSL_VERIFY_NONE`) se reporta como un protocolo TLS roto en ese archivo.
- Todo hallazgo de código usa la capacidad «Código de aplicaciones», una decisión de Suaya documentada en `madurez.toml`: las bibliotecas generales ya ofrecen ML-KEM y ML-DSA, y el inventario de bibliotecas dice si la versión concreta lo permite.

## Bibliotecas criptográficas

Una biblioteca se reconoce por su paquete, por la cadena de versión de un binario o por la información de compilación de Go, y se evalúa con `conocimiento/bibliotecas.toml`:

- si su rama ya no recibe correcciones de seguridad, el riesgo es obsoleto (reemplazar);
- si la versión es anterior a la primera con PQC, es vulnerable al cómputo cuántico;
- si ya ofrece PQC y la usa por omisión (por ejemplo, OpenSSL 3.5 con X25519MLKEM768 entre sus grupos predeterminados), se considera híbrida;
- si ofrece PQC pero no por omisión, o si no hay datos, queda para verificar.

Cuando una rama termina su soporte en menos de seis meses se advierte. La versión mínima que declara un manifiesto (`go 1.22` en `go.mod`, `>=` en `requirements.txt`) se marca como tal, porque la instalada puede ser mayor. Los binarios grandes solo se revisan con `--binarios`; las bibliotecas `libssl` y `libcrypto` y los JAR de Bouncy Castle se revisan siempre.

## Firmas compuestas

Las firmas compuestas ML-DSA (draft-ietf-lamps-pq-composite-sigs) combinan ML-DSA con RSA, ECDSA, Ed25519 o Ed448, y se clasifican como híbridas. Suaya las reconoce por los OID que IANA asignó de forma anticipada en octubre de 2025; el documento todavía no es RFC, por lo que la base de conocimiento se actualizará si cambian. Cada una advierte que el validador debe exigir ambas firmas: aceptar solo la clásica anula la protección (ataque de despojo).

## CBOM importados

Un CBOM de otra herramienta se reconstruye como inventario de Suaya y se vuelve a clasificar con la base vigente: los algoritmos se reconocen por OID o por nombre («RSA-2048», «SHA256withRSA», «AES128-GCM»), los protocolos TLS por su versión y las bibliotecas por su purl. Lo que no se reconoce entra como desconocido y cada activo indica de qué CBOM y de qué herramienta proviene.

## Firma del CBOM

La firma de Suaya es compuesta: ML-DSA-65 protege contra un adversario cuántico y Ed25519 conserva la confianza en un algoritmo clásico maduro mientras ML-DSA acumula años de análisis. Ambas firman el mismo mensaje: la etiqueta `suaya-firma-cbom-v1`, el nombre del algoritmo compuesto, la huella de la llave pública y el SHA-512 del CBOM. Verificar exige las dos firmas, de modo que quitar una (ataque de despojo) invalida el conjunto, y la etiqueta impide reutilizar la firma Ed25519 fuera de este contexto.

## Atestación de cumplimiento (CDXA)

Cuando se evalúa un perfil, cada regla se convierte en un requisito y recibe una afirmación cuya evidencia son las referencias de los activos que la regla alcanzó. La conformidad se calcula así: una regla que declara no conformes ciertos algoritmos se cumple (1) si no alcanza ningún activo y no se cumple (0) si alcanza alguno; una regla de transición o de conformidad vale la fracción de activos que mantienen ese estado (los que vencieron su plazo bajan el puntaje). La confianza se declara en 0.8: el inventario es automático y no incluye lo que Suaya no pudo observar.

## Perfiles de política

La clasificación de Suaya responde «qué hacer»; un perfil responde «qué exige este marco y para cuándo». Cada regla del perfil se aplica por algoritmo, familia, riesgo, capacidad o tamaño mínimo, en orden, y la primera que coincide decide el estado. Un estado «en transición» lleva su fecha límite, tomada de la regla o del plazo de la capacidad; si el año de evaluación (`--anio`, por omisión el actual) ya la alcanzó, el activo pasa a «no conforme».

Certificados, llaves y protocolos toman el peor estado de sus algoritmos. Su propio riesgo cuenta cuando lo agrava (un protocolo que habilita TLS 1.0) o cuando no hay algoritmos relacionados; lo que no tiene algoritmo identificado queda «sin evaluar», nunca «conforme» por omisión.

Los perfiles incluidos resumen documentos públicos y no sustituyen su lectura: `nist-ir-8547` sigue el borrador inicial de NIST IR 8547 (noviembre de 2024) y `cnsa-2.0` la suite CNSA 2.0 de la NSA. Ninguno está avalado por esas instituciones.

## Kubernetes en vivo

Cada certificado de un Secret toma el uso de los Ingress que lo publican («servidores web») y registra para qué hosts. Las llaves privadas de los Secrets se advierten para recordar que solo están codificadas en base64: su protección depende del cifrado en reposo de etcd y del RBAC. Los Certificates de cert-manager se evalúan igual que en los manifiestos: por el algoritmo que se emitirá en cada renovación.

## VPN

- **WireGuard** usa una suite fija y clásica. `PresharedKey` agrega una capa simétrica con resistencia poscuántica a la confidencialidad; si todos los pares la usan, el túnel se considera híbrido, con la advertencia de que esa llave debe distribuirse por un canal seguro. La autenticación sigue basada en X25519.
- **OpenVPN** se evalúa en dos canales: el de control (TLS, con las mismas reglas que un servidor web) y el de datos (cifradores y `auth`). Un cifrador roto en cualquiera de los dos domina el riesgo.
- **strongSwan**: una propuesta IKE es poscuántica si incluye ML-KEM, ya sea como intercambio adicional (`ke1_mlkem768`, RFC 9370) o como grupo. Como el par elige entre las propuestas aceptadas, se advierte cuando también se aceptan propuestas sin ML-KEM. IKEv1 se considera obsoleto (RFC 9395).

## Límites conocidos

- El escaneo de archivos no observa el tráfico; el sondeo de red ve lo que un servicio ofrece, no lo que negocia cada cliente real.
- El sondeo TLS no detecta aún si el servidor firma con ML-DSA en el saludo.
- No abre contenedores protegidos por contraseña ni llaves cifradas.
- Las llaves privadas cifradas en formato PKCS#8 o en el formato heredado de OpenSSL no revelan su llave pública, por lo que no se pueden enlazar (las llaves OpenSSH cifradas sí).
