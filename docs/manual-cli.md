# Manual del núcleo recuperado (referencia de CLI)

Las diferencias vigentes de 1.4 se documentan en README.md y docs/cierre-1.4.md.

# Suaya

**Suaya: protege lo que sostiene tu criptografía.**

Suaya es una herramienta libre y abierta, hecha en español, que inventaría los activos criptográficos de un sistema (algoritmos, llaves, certificados, protocolos y configuraciones), los exporta como **CBOM** (*Cryptographic Bill of Materials*) en el estándar **CycloneDX 1.7** y evalúa qué tan preparado está ese sistema para la migración a criptografía poscuántica (NIST FIPS 203, 204 y 205).

Suaya no solo responde *qué es vulnerable*. Responde también **qué se puede migrar hoy y qué todavía no**, porque cruza cada hallazgo con la madurez real del ecosistema tecnológico.

> Estado: versión 1.0, estable. Proyecto personal de José Enrique Rangel Ramírez, abierto a contribuciones. Qué promete la versión estable y qué no: [contrato de estabilidad](docs/estabilidad.md).

---

## Instalación

Cada [publicación](https://github.com/[OWNER]/suaya/releases) trae binarios para Linux (x86_64 y aarch64), macOS (arm64) y Windows (x86_64), paquetes `.deb` y `.rpm`, la página de manual y el autocompletado. Cada archivo lleva procedencia SLSA firmada con Sigstore; cómo verificarla está en [docs/publicacion.md](docs/publicacion.md).

```bash
# Desde la fuente (requiere Rust 1.89 o posterior)
cargo install --locked --path crates/suaya-cli

# Contenedor mínimo, sin privilegios
docker build -f empaquetado/contenedor/Dockerfile -t suaya .
```

Las compilaciones son reproducibles: `./scripts/compilacion-reproducible.sh` compila dos veces en rutas distintas y comprueba que el binario sea idéntico.

## Uso rápido

```bash

# Escanear un sistema y generar el CBOM y el reporte ejecutivo
suaya escanear /etc /home /srv -n "Servidor de producción" -o inventario.cbom.json -r reporte.md

# Regenerar el reporte desde un CBOM existente
suaya reporte inventario.cbom.json -o reporte.md

# Comparar dos escaneos para medir el avance de la migración
suaya comparar inventario-enero.cbom.json inventario-junio.cbom.json

# Sondear servicios en la red: lo que negocian realmente
suaya sondear tls://www.ejemplo.mx ssh://bastion.ejemplo.mx:22 -r reporte-red.md

# ... incluidos servicios con STARTTLS
suaya sondear smtp://correo.ejemplo.mx postgres://db.ejemplo.mx:5432

# Unir el CBOM de otra herramienta (por ejemplo, CBOMkit) y reclasificarlo
suaya importar cbomkit.json -r reporte.md
suaya escanear ./mi-app --importar cbomkit.json

# Escanear una imagen de contenedor (docker save, podman save u OCI)
docker save mi-app:1.0 -o mi-app.tar
suaya escanear --imagen mi-app.tar -r reporte-imagen.md

# ... o descargarla directamente del registro, verificando cada capa
suaya escanear --imagen docker://ghcr.io/mi-org/mi-app:1.0 --plataforma linux/arm64

# Evaluar el cumplimiento con un perfil de política (reporte HTML imprimible a PDF)
suaya escanear /etc --perfil nist-ir-8547 -r reporte.html
suaya perfiles

# Interfaz y reportes en inglés
suaya --idioma en scan /etc -r report.html

# Firmar el CBOM con ML-DSA-65 y Ed25519, y verificarlo
suaya llaves equipo-seguridad
suaya escanear /etc -o inventario.cbom.json --firmar-con equipo-seguridad.privada.json
suaya verificar inventario.cbom.json --llave-publica equipo-seguridad.publica.json

# Inventariar un clúster de Kubernetes en vivo (solo lecturas)
suaya kubernetes --contexto produccion -r reporte-k8s.md

# Combinar archivos y red en un solo inventario
suaya escanear /etc --objetivo tls://localhost:443 --objetivo ssh://localhost:22

# Consultar la base de conocimiento y la tabla de madurez
suaya conocimiento
```

Las órdenes también aceptan alias en inglés (`scan`, `probe`, `k8s`, `import`, `report`, `diff`, `profiles`, `keygen`, `sign`, `verify`, `knowledge`). Con `--idioma en` (o `SUAYA_IDIOMA=en`) la ayuda, los mensajes, el CBOM y los reportes salen en inglés; los nombres de las opciones se mantienen en español.

### En integración continua

```bash
# Falla (código 2) si hay hallazgos críticos o altos
suaya escanear ./despliegue --fallar-en 2

# Falla si la migración retrocede respecto del último escaneo aprobado
suaya comparar base.cbom.json actual.cbom.json --fallar-si-empeora
```

Códigos de salida: 0 éxito, 1 error, 2 umbral alcanzado (`--fallar-en`, `--fallar-si-empeora`), 3 firma no válida.

### Rendimiento

Suaya analiza los archivos en paralelo (`--hilos`, por omisión todos los núcleos) y detecta todas sus marcas en una sola pasada por archivo. El CBOM es idéntico byte a byte con cualquier número de hilos. Con dos núcleos, `/usr/share` de una distribución Linux (1.1 GB, 43 000 archivos) se inventaría en unos 1.4 segundos con 31 MiB de memoria, y `/usr/lib` con `--binarios` en alrededor de un segundo. Los binarios grandes se leen por bloques, así que la memoria no crece con el tamaño del archivo.

Puede probarlo sobre el sistema de demostración incluido:

```bash
cargo run -p suaya -- escanear pruebas/fixtures/sistema-demo -r reporte-demo.md
```

El resultado se parece a este [reporte de ejemplo](docs/ejemplo-reporte.md).

---

## Qué inventaría hoy

| Escáner | Qué encuentra |
|---|---|
| Certificados y llaves | Certificados X.509 (PEM y DER), llaves públicas y privadas en PKCS#8, PKCS#8 cifrado, PKCS#1, SEC1, DSA y OpenSSH |
| Llaves SSH | `*.pub`, `authorized_keys` y `known_hosts` |
| Configuración SSH | `sshd_config`, `ssh_config` y fragmentos `*.d/*.conf`: intercambio de llaves, cifradores, MAC y algoritmos de llave de host |
| Configuración TLS | nginx y Apache httpd: versiones de TLS, grupos de intercambio de llaves (incluido `X25519MLKEM768`) y certificados referenciados |
| Configuración de HAProxy | Cada `bind ... ssl`: versiones habilitadas (`ssl-min-ver`, `no-tlsv1x`), curvas y certificados, combinados con los valores de `global` |
| Configuración de PostgreSQL | `ssl`, versiones mínima y máxima, `ssl_groups` o `ssl_ecdh_curve`, certificado; advierte si escucha en la red sin TLS |
| Configuración de MySQL y MariaDB | `tls_version`, `require_secure_transport`, `ssl-cert` y TLS deshabilitado; advierte el certificado autofirmado que MySQL genera si no se declara uno |
| Configuración de Postfix | `smtpd_tls_security_level` (sin TLS, oportunista u obligatorio), protocolos, `tls_eecdh_auto_curves`, certificados y TLS del envío saliente |
| Política de Java | `java.security`: versiones de TLS que siguen habilitadas, algoritmos que se retiraron de `jdk.tls`, `jdk.certpath` y `jdk.jar.disabledAlgorithms`, y almacenes JKS |
| Secretos incrustados | Certificados y llaves en base64 dentro de `Secret` de Kubernetes, `kubeconfig`, valores de Helm, estado de Terraform o cualquier YAML/JSON; advierte cada llave privada guardada en un archivo de configuración |
| cert-manager | `spec.privateKey` de cada `Certificate`: el algoritmo que se emitirá en cada renovación (RSA 2048 si no se declara) y su política de rotación |
| Imágenes de contenedor | Archivos de cada capa de una imagen `docker save`, `podman save` u OCI, o descargada de un registro (`docker://`), sin extraerlos a disco; detecta **secretos borrados en una capa posterior que siguen dentro de la imagen** |
| WireGuard | Suite fija (X25519, ChaCha20-Poly1305, BLAKE2s), pares sin `PresharedKey` y permisos de la llave privada |
| OpenVPN | Cifradores del canal de datos (incluido el antiguo BF-CBC), `auth`, versión mínima de TLS, `tls-groups`, `tls-crypt` y certificados |
| strongSwan | Propuestas IKE y ESP de `swanctl.conf` e `ipsec.conf`, incluidos los intercambios adicionales con ML-KEM (RFC 9370, por ejemplo `ke1_mlkem768`) y el uso de IKEv1 |
| **Kubernetes en vivo** (API) | Secrets con certificados o llaves, qué Ingress publica cada certificado y para qué hosts, y los Certificates de cert-manager. Solo lecturas; el contenido de los Secrets se analiza en memoria |
| Cifrado de volumen | `/etc/crypttab`: cifrador, tamaño de llave y desbloqueo por TPM2, FIDO2 o PKCS#11 |
| Contenedores de llaves | PKCS#12 y Java KeyStore (se registran sin abrirse) |
| Código fuente | Python, Java (y Kotlin), Go, JavaScript y TypeScript, C#, Rust y C/C++: llamadas a APIs criptográficas (hashlib, JCA, crypto/*, node:crypto, Web Crypto, System.Security.Cryptography, RustCrypto, OpenSSL), con nombre de algoritmo y tamaño de llave cuando el código los fija; desactivar la verificación de certificados TLS. Los comentarios no cuentan |
| Bibliotecas criptográficas | Versión de OpenSSL o LibreSSL incrustada en binarios, compilador y módulos de Go, JDK, paquetes de Python instalados, JAR de Bouncy Castle y manifiestos (`go.mod`, `Cargo.lock`, `requirements.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `package-lock.json`, `pom.xml`, `build.gradle`, `*.csproj`): fin de soporte y si la versión ya ofrece PQC |
| **Sondeo TLS** (red) | Versiones de SSL/TLS aceptadas, cada grupo de intercambio de llaves aceptado (incluidos X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024 y ML-KEM puro), si el servidor prioriza el híbrido, la suite que elige en TLS 1.2 y la cadena de certificados |
| **Sondeo SSH** (red) | Identificación del servidor y su `KEXINIT`: intercambio de llaves (incluido `mlkem768x25519-sha256`), llaves de host, cifradores y MAC |

También reconoce las firmas compuestas ML-DSA (con RSA, ECDSA, Ed25519 o Ed448) por los identificadores que IANA asignó de forma anticipada al borrador de IETF, e importa CBOM CycloneDX de otras herramientas. La [hoja de ruta](docs/hoja-de-ruta.md) describe lo que sigue.

### Cómo sondea la red

Para TLS, Suaya envía saludos `ClientHello` de TLS 1.3 que ofrecen grupos pero ninguna llave. El servidor responde con un `HelloRetryRequest` que indica qué grupo acepta, sin que se genere material criptográfico. Así detecta cada grupo híbrido aunque la biblioteca TLS local no lo implemente, y averigua si el servidor prioriza el híbrido, sigue el orden del cliente o lo relega. Los grupos que se prueban salen de la base de conocimiento: para sondear uno nuevo basta con agregar su código IANA en `algoritmos.toml`.

Para SSH, lee el `KEXINIT` que el servidor envía en claro antes de cualquier intercambio de llaves. No se autentica ni abre sesión.

Con `smtp://`, `imap://`, `pop3://`, `ldap://`, `postgres://` o `mysql://`, Suaya habla lo mínimo de ese protocolo para pedir el cambio a TLS (`STARTTLS`, `STLS`, la operación extendida StartTLS de LDAP o el `SSLRequest` de PostgreSQL y MySQL) y después sondea igual que un servicio TLS directo. Si el servidor responde pero no ofrece TLS, eso queda en el inventario como protocolo en claro.

> **Uso responsable.** Suaya sondea únicamente los servicios que usted indica de forma explícita, uno por uno; no descubre ni recorre rangos de red. Sondee solo sistemas que administre o que tenga autorización expresa para evaluar. Cada objetivo recibe unas veinte conexiones breves.

### Kubernetes en vivo

`suaya kubernetes` usa el kubeconfig (contexto actual o `--contexto`), con token, certificado de cliente o un complemento `exec`, o la cuenta de servicio cuando corre dentro del clúster. Verifica el certificado del servidor de la API contra la autoridad del kubeconfig y se niega a continuar si no puede hacerlo, salvo que el propio kubeconfig declare `insecure-skip-tls-verify` (en cuyo caso lo advierte). Requiere permiso `list` sobre `secrets` e `ingresses`; con `--espacio` se limita a espacios de nombres concretos. `--sondear-ingress` sondea además por TLS los hosts que publican los Ingress del propio clúster.

### Imágenes desde un registro

`--imagen docker://registro/repositorio:etiqueta` (o `@sha256:...`) descarga solo la imagen indicada mediante la API de distribución OCI y la analiza en flujo, sin escribirla a disco. De un índice multiplataforma toma la plataforma de este equipo o la de `--plataforma`. Verifica el resumen SHA-256 de cada manifiesto y de cada capa, y descarta la imagen completa si alguno no coincide.

Las credenciales salen de `SUAYA_REGISTRO_USUARIO` y `SUAYA_REGISTRO_CLAVE` o de `~/.docker/config.json` (`auths`, `credHelpers` y `credsStore`, como Docker). Suaya pide al registro un token de solo lectura (`pull`); nunca envía la clave por HTTP sin cifrar (salvo a `localhost`) ni la reenvía a otro servidor cuando el registro redirige la descarga de una capa. Respeta `HTTPS_PROXY` y `NO_PROXY`, y `--ca-registro` agrega la autoridad de un registro privado.

---

### Perfiles de política

Además de la clasificación propia, Suaya evalúa cada activo contra un perfil de política (`--perfil`): **conforme**, **en transición** (con su fecha límite), **no conforme** o **sin evaluar**. Certificados, llaves y protocolos toman el peor estado de sus algoritmos. El reporte agrega una sección de cumplimiento con un calendario de migración por año.

| Perfil | Fuente |
|---|---|
| `nist-ir-8547` | NIST IR 8547 (borrador inicial): lo vulnerable al cómputo cuántico entra en retiro después de 2030 y se prohíbe después de 2035 |
| `cnsa-2.0` | NSA CNSA 2.0: ML-KEM-1024, ML-DSA-87, AES-256 y SHA-384 o superior, con las fechas de uso exclusivo por capacidad; CNSA 1.0 (P-384, RSA de 3072 bits o más) queda en transición |

Los perfiles son archivos TOML en [`conocimiento/perfiles/`](conocimiento/perfiles/). Para un marco nacional, sectorial o institucional, copie `plantilla.toml`, ajuste sus reglas y páselo con `--perfil mi-marco.toml`.

---

### Enlace entre llaves y certificados

Suaya calcula la identidad de cada llave pública de forma canónica, sin importar el formato (certificado X.509, PKCS#8, PKCS#1, SEC1 u OpenSSH). Con ella:

- relaciona cada llave privada con su certificado y su llave pública, incluso entre formatos (una llave OpenSSH cifrada se enlaza con su línea de `authorized_keys`);
- hereda a la llave el uso del certificado, de modo que una llave suelta pasa de «sin clasificar» a, por ejemplo, «servidores web»;
- detecta la **misma llave privada copiada en varias ubicaciones**, un hallazgo de exposición por sí mismo;
- presenta en el reporte cada llave junto a su certificado, en lugar de duplicar filas.

## Cómo decide

Cada activo se evalúa en cuatro ejes:

1. **Riesgo**: roto hoy, obsoleto, vulnerable al algoritmo de Shor, debilitado por Grover, híbrido o resistente.
2. **Garantía**: confidencialidad, autenticación o integridad, evaluadas por separado.
3. **Capacidad tecnológica**: navegadores, servidores web, VPN y cifrado de red, aseguramiento de plataforma, firma de código, PKI, cifrado de volumen y conectividad a la nube.
4. **Madurez del ecosistema**: en una escala de siete niveles, desde *Bloqueado* hasta *Integración validada* (FIPS 140-3).

El cruce produce una acción y una prioridad:

| Acción | Cuándo | Prioridad |
|---|---|---|
| Corregir de inmediato | Inseguro hoy (MD5, SHA-1 en firmas, RSA menor a 2048, 3DES) | Crítica |
| Reemplazar | Retirado por los estándares (TLS 1.0/1.1, DSA) | Alta |
| Migrar ahora | Vulnerable y el ecosistema ya ofrece PQC en versión general | Alta (confidencialidad) o media (autenticación) |
| Planificar y hacer piloto | Vulnerable; solo hay componentes o versiones preliminares | Media o baja |
| Monitorear | Vulnerable; aún no hay vía de migración madura | Baja |
| Revisar parámetros | Margen reducido por Grover (p. ej. AES-128) | Baja |
| Verificar | Información insuficiente (llave cifrada, configuración implícita) | Media |
| Conforme | Híbrido o resistente | Informativa |

La confidencialidad se prioriza sobre la autenticación porque los datos cifrados hoy pueden capturarse y descifrarse cuando exista una computadora cuántica capaz.

Los niveles de madurez provienen, con atribución, del *Post-Quantum Cryptography (PQC) Capability Development Report* de MITRE (septiembre de 2026). Más detalle en [docs/metodologia.md](docs/metodologia.md).

---

## Criptoagilidad

Suaya aplica a sí misma lo que recomienda:

- **El criterio es dato, no código.** Algoritmos, OIDs, riesgos, niveles de madurez y fechas de transición viven en [`conocimiento/`](conocimiento/) como archivos TOML versionados. Cuando cambia un estándar o sale una nueva edición del reporte de madurez, se actualiza el archivo; el programa no cambia.
- **Base de conocimiento sustituible en ejecución**: `--base-conocimiento <directorio>` permite usar criterios propios de una organización o un regulador.
- **Procedencia en cada CBOM**: el inventario registra qué versión de la base de conocimiento produjo cada clasificación.
- **Lo desconocido no se oculta**: un algoritmo que Suaya no reconoce aparece en el inventario como desconocido, con su OID o nombre, para que alguien lo revise.

---

## Formato de salida

El CBOM es un JSON CycloneDX 1.7 válido contra el esquema oficial. La clasificación de Suaya viaja dentro del propio CBOM como propiedades con prefijo `suaya:` (`suaya:riesgo`, `suaya:accion`, `suaya:prioridad`, `suaya:capacidad`, `suaya:madurez-ecosistema`, `suaya:justificacion`, `suaya:advertencia`). Así el CBOM es autosuficiente: cualquier herramienta CycloneDX puede leerlo, y Suaya puede regenerar el reporte o comparar escaneos sin volver a escanear.

Las referencias (`bom-ref`) son deterministas: el mismo activo conserva su referencia entre escaneos, lo que permite seguir la migración en el tiempo.

Además:

- Las bibliotecas criptográficas son componentes `library` con su versión y su purl.
- Con `--perfil`, el CBOM incluye una **atestación CycloneDX (CDXA)**: el perfil como estándar (`definitions.standards`, un requisito por regla) y, en `declarations`, una afirmación por requisito con los activos que alcanza como evidencia y un puntaje de conformidad.
- El reporte se genera en Markdown o en HTML autocontenido (sin red ni JavaScript), con gráficas, modo oscuro y estilos de impresión para guardarlo como PDF desde el navegador.

### Firma del CBOM

`suaya llaves` genera un par compuesto ML-DSA-65 (FIPS 204) y Ed25519; con la variable `SUAYA_CLAVE_FIRMA` la llave privada se guarda cifrada (PBKDF2-HMAC-SHA256 y AES-256-GCM). `suaya firmar` o `--firmar-con` crean `<cbom>.firma` y `suaya verificar` exige que **ambas** firmas sean válidas: ambas cubren un mensaje con etiqueta de dominio, algoritmo y huella de la llave, así que una firma clásica separada de su pareja no sirve. La firma va en un archivo aparte porque el formato de firma incrustada de CycloneDX (JSF) no contempla ML-DSA. La criptografía es de AWS-LC.

---

## Seguridad de la herramienta

- **Nunca copia material secreto.** De una llave privada registra tipo, tamaño, formato, protección y ubicación; jamás su contenido. Una prueba automática lo verifica.
- Escrito en Rust, con `unsafe` prohibido en todo el proyecto.
- No sigue enlaces simbólicos por defecto, omite archivos grandes y nunca se detiene por un archivo malformado.
- No abre contenedores protegidos ni intenta adivinar contraseñas.
- Solo usa la red cuando se le pide (`sondear`, `--objetivo`, `kubernetes` o una imagen `docker://`). El sondeo no envía datos de aplicación ni credenciales; las descargas de registro y las lecturas de Kubernetes verifican el certificado del servidor y no escriben nada.
- Pruebas de mutación y objetivos de *fuzzing* para cada analizador; `cargo-deny` revisa en cada cambio los avisos de seguridad, las licencias y el origen de las dependencias.
- Compilaciones reproducibles y procedencia SLSA de cada publicación.

El [modelo de amenazas](docs/modelo-de-amenazas.md) detalla qué protege Suaya y de quién. Suaya todavía no ha pasado por una auditoría de seguridad externa; [docs/auditoria.md](docs/auditoria.md) define su alcance. Para reportar una vulnerabilidad, consulte [SECURITY.md](SECURITY.md).

---

## Arquitectura

```
crates/
├── suaya-core      modelo de datos, base de conocimiento y motor de clasificación
├── suaya-escaneo   escáneres (un rasgo `Escaner` por tipo de fuente)
├── suaya-cbom      exportación CycloneDX 1.7, lectura, reporte y comparación
├── suaya-red       sondeo TLS y SSH, Kubernetes en vivo y registros de imágenes
└── suaya-cli       interfaz de línea de comandos (binario `suaya`)
conocimiento/       algoritmos.toml, madurez.toml y perfiles de política
pruebas/            sistema de demostración y su generador
```

Detalle en [docs/arquitectura.md](docs/arquitectura.md). Otros documentos: [metodología](docs/metodologia.md), [hoja de ruta](docs/hoja-de-ruta.md), [registro de cambios](CHANGELOG.md), [publicación y verificación](docs/publicacion.md) y [gobernanza](GOBERNANZA.md).

---

## Origen del nombre

*Suaya* es una palabra del **yoremnokki**, la lengua del pueblo yoreme mayo, única lengua originaria viva de Sinaloa (familia cahíta, tronco yuto-azteca). En los diccionarios español-mayo significa **cuidar, proteger**, y se distingue de *ujü*, que expresa cuidar en el sentido de atender.

El nombre describe la función del proyecto: un CBOM no guarda secretos, sino que inventaría, describe y vigila los activos que protegen la información. Elegirlo es también una forma de reconocer y dar visibilidad a la lengua y a la comunidad yoreme mayo en un ámbito técnico global.

La grafía y el significado están en proceso de validación con hablantes de la lengua. Agradecemos a la comunidad yoreme mayo, a quien pertenece esta palabra.

---

## Contribuir

Las contribuciones son bienvenidas, en español o en inglés. Lea [CONTRIBUTING.md](CONTRIBUTING.md) y el [código de conducta](CODE_OF_CONDUCT.md). Las formas más sencillas de empezar:

- Agregar un algoritmo o corregir un riesgo en `conocimiento/algoritmos.toml`.
- Escribir un escáner nuevo implementando el rasgo `Escaner`.
- Probar Suaya en sistemas reales y reportar falsos positivos o negativos.

---

## Licencia y atribuciones

Suaya se distribuye bajo la [Licencia Apache 2.0](LICENSE). Consulte [NOTICE](NOTICE) para las atribuciones.

- CycloneDX es un estándar de OWASP publicado por Ecma International como ECMA-424.
- La tabla de madurez se deriva del *Post-Quantum Cryptography (PQC) Capability Development Report* de MITRE, © 2026 MITRE, aprobado para difusión pública (caso 26-2150). Suaya usa sus niveles con atribución y no reproduce su texto. La inclusión de estos datos no implica respaldo de MITRE a Suaya.
