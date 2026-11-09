# Manual de uso · SUAYA 1.7

Suaya inventaría la criptografía de un sistema, la clasifica según su exposición a la computación cuántica y entrega un CBOM (Cryptographic Bill of Materials) CycloneDX 1.7, un reporte ejecutivo y, en esta versión, los pasos para corregir lo que encuentra. «Suaya» significa cuidar, proteger, en yoremnokki, la lengua yoreme mayo de Sinaloa.

Este manual explica cómo usarla. La referencia detallada de cada escáner está en [docs/manual-cli.md](docs/manual-cli.md), las integraciones en [docs/integraciones.md](docs/integraciones.md) y lo que cambió en esta versión en el [registro de cambios](CHANGELOG.md).

---

## 1. Qué hace Suaya

1. **Encuentra criptografía**: en archivos (certificados, llaves, configuraciones, código, bibliotecas, ejecutables, imágenes de contenedor), en servicios de red que usted indica (TLS, SSH, VPN IKEv2, DNS, proveedores de identidad), en clústeres de Kubernetes y en el llavero de macOS.
2. **La clasifica** en cuatro ejes: **riesgo** (roto hoy, obsoleto, vulnerable al algoritmo de Shor, debilitado por Grover, híbrido o resistente), **garantía** (confidencialidad, autenticación o integridad), **capacidad tecnológica** (servidores web, VPN, PKI, firma de código...) y **madurez del ecosistema** para migrar (según el reporte de MITRE de septiembre de 2026).
3. **Asigna una prioridad** del 1 (crítica: corregir de inmediato) al 5 (informativa: ya protegido), y una acción: corregir ya, reemplazar, migrar ahora, planificar piloto, monitorear, revisar parámetros o verificar.
4. **Evalúa el cumplimiento** con un perfil de política (NIST, CNSA 2.0, UE, Reino Unido, Canadá, PCI DSS o uno propio) y, si se le da, con el **contexto de su organización**: qué sistema es, quién responde, cuánto tiempo deben protegerse sus datos.
5. **Dice cómo corregir**: cada hallazgo trae una receta con pasos concretos.

Suaya **nunca** recorre rangos de red (solo sondea los servicios que usted nombra), **nunca** copia material secreto al inventario, **nunca** adivina contraseñas y solo lee: no modifica los sistemas que analiza.

---

## 2. Instalación

### Binarios incluidos (macOS Apple Silicon)

La carpeta de la entrega trae:

- `bin/suaya` (línea de órdenes) y `bin/suaya-api` (API local).
- `build/SUAYA-1.7.0-macos-arm64.dmg` con la aplicación de macOS (arrastre `SUAYA.app` a Aplicaciones).

```sh
cp bin/suaya /usr/local/bin/
suaya --version          # suaya 1.7.0
```

La app tiene firma local ad hoc; la primera vez puede pedirle que la abra con clic derecho > Abrir. Una distribución pública requiere Developer ID y notarización.

### Desde la fuente

Requiere Rust 1.89 o posterior (esta entrega se validó con 1.99.1) y, en macOS, las herramientas de línea de órdenes de Xcode.

```sh
cargo build --release --locked -p suaya -p suaya-api
# binarios en target/release/
```

Si la carpeta está sincronizada con iCloud Drive, compile fuera de ella (`CARGO_TARGET_DIR=/private/tmp/suaya-target`) para no subir gigabytes de compilación, y construya la app con `SUAYA_BUILD_DIR=/private/tmp/suaya-build SUAYA_DMG=1 bash empaquetado/build-macos.sh`.

---

## 3. Primeros pasos

Pruebe con el sistema de demostración incluido:

```sh
suaya escanear pruebas/fixtures/sistema-demo -o inventario.json -r reporte.html
```

En pantalla verá cuántos activos hay por prioridad y lo más urgente. Abra `reporte.html` en el navegador: tiene el resumen ejecutivo, qué se puede migrar hoy, los hallazgos por prioridad, **cómo corregir** cada tipo de hallazgo y la metodología. Para guardarlo como PDF, use Imprimir.

Tres órdenes cubren casi todo:

| Quiero... | Orden |
|---|---|
| Inventariar archivos y directorios | `suaya escanear RUTAS` |
| Inventariar lo que ofrecen servicios de red | `suaya sondear OBJETIVOS` |
| Saber qué obtiene un cliente al conectarse y qué falla | `suaya diagnosticar OBJETIVOS` |

Todas las órdenes aceptan `--ayuda` y tienen alias en inglés (`scan`, `probe`, `diagnose`, `k8s`, `report`, `trends`, `diff`, `import`, `profiles`, `keygen`, `sign`, `verify`, `knowledge`).

---

## 4. Escanear archivos (`escanear`)

```sh
suaya escanear /etc /srv /opt/app -n "Servidor de pagos" -o inventario.json -r reporte.html
```

Qué encuentra, en resumen:

- **Certificados y llaves** en PEM, DER, PKCS#8, PKCS#1, SEC1, OpenSSH, OpenPGP, PKCS#12, JKS y JCEKS (con `SUAYA_CLAVE_ALMACEN` también lee los PKCS#12 cifrados con AES).
- **Configuración**: SSH, nginx, Apache, HAProxy, PostgreSQL, MySQL, Postfix, Java, WireGuard, OpenVPN, strongSwan, OpenSSL, crypto-policies, GnuTLS, Kerberos, políticas de navegador, registro de Windows (`.reg`) y veinte servicios más descritos como datos (Kafka, MongoDB, Redis, Vault, Traefik, Envoy, Grafana, Oracle Net...).
- **Nube e infraestructura como código**: Terraform, CloudFormation, ARM, Bicep, exportaciones de las CLI de AWS, Azure y Google, JWKS y cfssl.
- **Plataforma**: UEFI Secure Boot, firma de módulos del kernel, llaves MOK/IMA/EVM, cabeceras LUKS y exportaciones LDIF de Active Directory.
- **Código**: Python, Java, Kotlin, Go, JavaScript, TypeScript, C#, Rust, C/C++, PHP, Ruby, Swift, Dart, PowerShell y scripts de shell (incluidas órdenes como `openssl`, `ssh-keygen` o `curl -k`).
- **Bibliotecas** y su versión (OpenSSL, Bouncy Castle, navegadores, paquetes de Python, Go, Node, Java, .NET...), con fin de soporte y si ya ofrecen PQC.

Opciones útiles:

| Opción | Efecto |
|---|---|
| `--binarios` | Revisa también ejecutables y firmware (firmas Authenticode y de macOS, funciones importadas, JAR y APK) |
| `--llavero` | Agrega los certificados del llavero de macOS (nunca llaves privadas); puede usarse sin rutas |
| `--imagen ARCHIVO.tar` o `--imagen docker://registro/imagen:etiqueta` | Analiza una imagen de contenedor capa por capa |
| `--objetivo tls://host:443` | Sondea además un servicio de red (repetible) |
| `--importar otro.cbom.json` | Une el CBOM de otra herramienta (por ejemplo, CBOMkit) |
| `--perfil cnsa-2.0` | Evalúa el cumplimiento con un perfil (sección 9) |
| `--organizacion org.toml` | Aplica el contexto de su organización (sección 8) |
| `--sarif archivo.sarif`, `--csv archivo.csv` | Salidas adicionales (sección 10) |
| `--fallar-en 1` | Termina con código 2 si hay hallazgos críticos (1) o de la prioridad indicada |
| `--fallar-si-incompleto` | Termina con código 4 si el resultado es parcial |
| `--hilos`, `--tamano-maximo`, `--seguir-enlaces` | Rendimiento y alcance del recorrido |

---

## 5. Sondear servicios de red (`sondear`)

```sh
suaya sondear tls://www.ejemplo.mx ssh://bastion.ejemplo.mx:22 ike://vpn.ejemplo.mx -r reporte-red.html
```

| Objetivo | Qué observa |
|---|---|
| `tls://host:puerto` (o `host:puerto`) | Versiones de TLS, cada grupo de intercambio de llaves (incluidos los híbridos con ML-KEM), si prioriza el híbrido, suites de TLS 1.2 y la cadena de certificados por familia de firma |
| `smtp://`, `imap://`, `pop3://`, `ldap://`, `postgres://`, `mysql://`, `ftp://`, `xmpp://`, `rdp://` | Lo mismo tras negociar TLS con el protocolo; si el servidor no ofrece TLS, queda como protocolo en claro |
| `ssh://host:22` | Intercambio de llaves (incluido `mlkem768x25519-sha256`), cifradores, MAC y llaves de host |
| `ike://host` | Grupos de la VPN IKEv2 y si acepta ML-KEM como intercambio adicional (RFC 9370) |
| `dns://dominio` | DNSSEC (llaves, delegación, firmas), CAA, TLSA y DKIM; `dns://dominio/sel1,sel2` indica los selectores DKIM |
| `oidc://host/ruta` | Algoritmos de firma de tokens que anuncia un proveedor OpenID Connect y sus llaves JWKS |
| `saml://host/ruta/metadata.xml` | Certificados y algoritmos de unos metadatos SAML |

Con `dns://` se usa el resolvedor del sistema; si no valida DNSSEC (muchos módems no lo hacen), indique otro: `SUAYA_DNS=1.1.1.1 suaya sondear dns://ejemplo.mx`.

> **Uso responsable.** Sondee solo sistemas que administre o que tenga autorización expresa para evaluar. Un objetivo TLS recibe entre treinta y setenta conexiones breves y secuenciales; los demás, unas pocas. Suaya no descubre equipos ni recorre rangos.

---

## 6. Diagnosticar (`diagnosticar`)

El sondeo inventaría lo que un servicio ofrece; el diagnóstico responde qué obtiene un cliente real y qué está mal:

```sh
suaya diagnosticar www.ejemplo.mx ssh://bastion.ejemplo.mx dns://ejemplo.mx -d
```

Incluye conectividad por dirección IPv4 e IPv6, dos saludos TLS completos (un cliente moderno con X25519MLKEM768 y uno solo clásico), la validación de la cadena como lo haría un navegador, la vigencia máxima de los certificados públicos según el CA/Browser Forum (200 días desde el 15 de marzo de 2026, 100 desde 2027 y 47 desde 2029), el `KEXINIT` de SSH, la VPN IKEv2, DNS e identidad federada.

Cada hallazgo tiene un **nivel** (crítico, alto, medio, bajo, info) y un **código estable** (`CERT-VENCE`, `KEX-CLASICO`, `SSH-TERRAPIN`, `DNSSEC-CLASICO`, `DKIM-RSA-CORTA`, `IDP-ALG-NONE`...). Debajo aparece **Cómo corregir**: el título de la receta y, con `-d`, sus pasos.

| Opción | Efecto |
|---|---|
| `--json diagnostico.json` | Diagnóstico completo para automatizar |
| `--metricas suaya.prom` | Métricas para Prometheus (sección 11) |
| `--fallar-en alto` | Código 2 si hay hallazgos altos o más graves |
| `--ca autoridad.pem` | Autoridad propia para validar cadenas internas |

---

## 7. Kubernetes (`kubernetes`)

```sh
suaya kubernetes --contexto produccion --espacio pagos -r reporte-k8s.html
```

Lee por la API del clúster, solo con lecturas, los Secrets con certificados o llaves, los Ingress y los Certificates de cert-manager. Usa el kubeconfig (o la cuenta de servicio dentro del clúster) y verifica el certificado del servidor de la API. `--sondear-ingress` sondea además los hosts publicados.

---

## 8. Contexto de su organización (`--organizacion`)

El inventario dice qué criptografía hay; el contexto dice qué importa más. Copie y adapte [docs/ejemplos/suaya-organizacion.toml](docs/ejemplos/suaya-organizacion.toml):

```toml
[organizacion]
horizonte_cuantico = 2035        # año supuesto de una computadora cuántica relevante

[[sistema]]
nombre = "Portal de clientes"
responsable = "equipo-web@ejemplo.mx"
criticidad = "alta"              # alta | media | baja
exposicion = "internet"          # internet | interna
vida_datos = 10                  # años que los datos deben seguir confidenciales
migracion = 3                    # años que tardará migrar
rutas = ["srv/portal/**", "etc/nginx/**"]
objetivos = ["tls://portal.ejemplo.mx:443"]

[[excepcion]]
id = "EXC-2026-014"
justificacion = "Equipo heredado; se reemplaza en 2027."
aprobada_por = "Comité de riesgos"
vence = "2027-06-30"
rutas = ["srv/legado/**"]
```

- **Desigualdad de Mosca** (x + y > z): si los datos deben protegerse más años (x) de los que faltan para el horizonte (z), menos lo que tarda la migración (y), lo que hoy se captura cifrado podrá descifrarse mientras siga siendo valioso. Esos activos suben a prioridad alta.
- **Excepciones**: riesgos aceptados con vencimiento. No cambian la clasificación ni ocultan el activo, pero no cuentan para `--fallar-en` mientras estén vigentes. Vencidas, vuelven a contar.
- El reporte agrega la sección «Contexto de la organización» con cada sistema, los activos expuestos según Mosca y el estado de cada excepción.

---

## 9. Perfiles de política (`--perfil`)

```sh
suaya perfiles
suaya escanear /etc --perfil cnsa-2.0 -r reporte.html
```

| Perfil | Marco |
|---|---|
| `nist-ir-8547` | NIST IR 8547: retiro de RSA y ECC en 2030 y prohibición en 2035 |
| `cnsa-2.0` | NSA CNSA 2.0 (LMS y XMSS para firma de software y firmware) |
| `ue-hoja-de-ruta` | Hoja de ruta coordinada de la Unión Europea |
| `ncsc-reino-unido` | Calendario del NCSC del Reino Unido |
| `canada-cccs` | Hoja de ruta del CCCS de Canadá |
| `pci-dss-4` | PCI DSS v4.0.1, criptografía robusta |

Para un marco propio, copie `conocimiento/perfiles/plantilla.toml` y páselo con `--perfil mi-marco.toml`. El reporte muestra el estado de cumplimiento, el calendario de migración y, en el CBOM, una atestación CycloneDX.

---

## 10. Reportes, formatos y seguimiento

### Desde cualquier CBOM

```sh
suaya reporte inventario.json -o reporte.html                    # HTML (o .md)
suaya reporte inventario.json --formato pci -o inventario-pci.md # PCI DSS 12.3.3 y 4.2.1.1
suaya reporte inventario.json --formato sarif -o hallazgos.sarif # análisis de código
suaya reporte inventario.json --formato csv -o inventario.csv    # hoja de cálculo
suaya reporte inventario.json --formato jsonl -o inventario.jsonl
suaya reporte inventario.json --formato tickets -o tickets.json  # un ticket por activo crítico a medio
```

- **SARIF 2.1.0**: una regla por receta de corrección, un resultado por ubicación; GitHub y GitLab lo muestran en el análisis de código.
- **CSV**: un activo por fila con sistema, responsable, excepción y receta; las celdas peligrosas para Excel se neutralizan.
- **Tickets**: título, prioridad, responsables, etiquetas y una descripción con ubicaciones y pasos de corrección.

### Medir el avance

```sh
suaya comparar enero.json junio.json                  # qué es nuevo, qué se eliminó, qué empeoró
suaya tendencias escaneos/*.json --formato md        # evolución de muchos escaneos
```

`--fallar-si-empeora` devuelve el código 2 si la situación retrocede.

---

## 11. Integración continua y monitoreo

- **GitHub**: la acción `action.yml` compila Suaya, escanea, publica el SARIF y aplica el umbral.
- **GitLab**: incluya `integraciones/gitlab/suaya.gitlab-ci.yml`.
- **pre-commit**: ganchos `suaya` y `suaya-estricto` (`.pre-commit-hooks.yaml`).
- **Prometheus**: `suaya diagnosticar ... --metricas /ruta/textfile/suaya.prom` para el recolector de node_exporter; métricas `suaya_diagnostico_hallazgos`, `..._poscuantico`, `..._certificado_dias_restantes`, `..._cadena_valida`, `..._saludo_segundos` y `..._alcanzable`.
- **Ejecución periódica**: `scripts/automatizar.py` escanea y diagnostica sin intérprete de shell, con tiempo límite.

Ejemplos completos en [docs/integraciones.md](docs/integraciones.md).

---

## 12. Firmar el CBOM

```sh
suaya llaves equipo-seguridad                      # crea .privada.json y .publica.json
suaya firmar inventario.json --llave equipo-seguridad.privada.json
suaya verificar inventario.json --llave-publica equipo-seguridad.publica.json
```

La firma es híbrida: ML-DSA-65 (poscuántica) y Ed25519; ambas deben ser válidas. Para cifrar la llave privada con una frase de paso, defina la variable `SUAYA_CLAVE_FIRMA` (u otra con `--clave-env`). `--firmar-con` firma al generar el CBOM.

---

## 13. Aplicación de macOS

Abra **SUAYA.app**:

- **Inventario**: elija un archivo o carpeta (o solo active **Incluir el llavero de macOS**), opcionalmente un **perfil** y un archivo de **organización**, y pulse **Escanear**. Exporte CBOM, HTML, CSV o SARIF; los archivos se guardan con permisos privados.
- **Diagnóstico de red**: escriba uno o más servicios (`www.ejemplo.mx`, `ssh://bastion:22`, `ike://vpn.ejemplo.mx`, `dns://ejemplo.mx`, `oidc://login.ejemplo.mx`); opcionalmente elija una autoridad propia. Cada servicio muestra conectividad, intercambio de llaves, certificados, DNS o identidad, hallazgos por nivel y cómo corregirlos. Exporte el JSON.

La app usa el mismo motor que la línea de órdenes, incluido dentro del paquete.

---

## 14. API local y panel web

```sh
python3 scripts/configurar-api.py --directory /ruta/privada/suaya-data \
  --target demo=/ruta/autorizada --network-target web=tls://www.ejemplo.mx:443 \
  --organization org.toml --user admin:admin --user analista:analyst
bin/suaya-api --config /ruta/privada/suaya-data/config.json --database /ruta/privada/suaya-data/scans.db
```

- Escucha solo en `127.0.0.1:8787`. Para acceso remoto ponga delante un proxy TLS con sus propios controles.
- El cliente **nunca** envía rutas ni URLs: escanea alias configurados por el operador y elige perfiles solo entre los incluidos.
- **Panel**: abra `http://127.0.0.1:8787/panel`, pegue su token (se guarda solo en esa pestaña) y escanee, descargue reportes en cualquier formato, compare, vea tendencias y diagnostique servicios configurados.
- Descripción OpenAPI 3.1 en `/api/v1/openapi.json`. Lista de rutas en el [README](README.md#api-local-con-persistencia).

---

## 15. Idiomas

```sh
suaya --idioma en escanear /etc -r report.html     # inglés
suaya --idioma pt escanear /etc -r relatorio.html  # portugués
```

También con `SUAYA_IDIOMA=en` o `pt`. En inglés se traduce todo; en portugués, el reporte, las etiquetas, las justificaciones y el resumen (la ayuda, las recetas y los mensajes detallados quedan en español). Los nombres de las opciones siempre están en español.

---

## 16. Base de conocimiento

Todo el criterio de Suaya vive como datos en `conocimiento/`, no en el código:

| Archivo | Contenido |
|---|---|
| `algoritmos.toml` | Algoritmos, OID, alias por protocolo y riesgo |
| `madurez.toml` | Capacidades tecnológicas y madurez del ecosistema (MITRE) |
| `codigo.toml`, `bibliotecas.toml`, `servicios.toml` | Reglas de código, bibliotecas y servicios |
| `remediacion.toml` | Recetas de corrección |
| `perfiles/` | Perfiles de política |
| `traducciones/` | Catálogos de inglés y portugués |

`suaya conocimiento` muestra lo cargado. Para usar una base propia (por ejemplo, con un algoritmo nuevo o un criterio distinto), copie la carpeta, edítela y pásela con `--base-conocimiento DIRECTORIO`; Suaya valida su coherencia al cargarla. Cada CBOM registra la versión de cada archivo usado.

---

## 17. Referencia rápida

### Códigos de salida

| Código | Significado |
|---|---|
| 0 | Éxito |
| 1 | Error de uso, archivo ilegible, conexión fallida |
| 2 | Umbral alcanzado (`--fallar-en`, `--fallar-si-empeora`) |
| 3 | `verificar`: firma no válida |
| 4 | Resultado parcial con `--fallar-si-incompleto` |

### Variables de entorno

| Variable | Uso |
|---|---|
| `SUAYA_IDIOMA` | `es`, `en` o `pt` |
| `SUAYA_CLAVE_FIRMA` | Frase de paso de la llave de firma |
| `SUAYA_CLAVE_ALMACEN` | Contraseña para descifrar contenedores PKCS#12 (la proporciona usted; Suaya nunca adivina) |
| `SUAYA_DNS` | Resolvedor para `dns://` (por ejemplo, `1.1.1.1`) |
| `SUAYA_REGISTRO_USUARIO`, `SUAYA_REGISTRO_CLAVE` | Credenciales de un registro de imágenes |
| `SUAYA_FECHA` | Fecha fija (AAAA-MM-DD) para resultados reproducibles |
| `KUBECONFIG`, `HTTPS_PROXY` | Kubeconfig y proxy, como en otras herramientas |

### Prioridades

| Prioridad | Significado | Acción típica |
|---|---|---|
| 1 Crítica | Roto hoy, sin necesidad de una computadora cuántica | Corregir de inmediato |
| 2 Alta | Obsoleto; o vulnerable a Shor en confidencialidad con migración disponible; o expuesto según Mosca | Reemplazar o migrar ahora |
| 3 Media | Vulnerable en autenticación con migración disponible; en confidencialidad con solo pilotos; o algoritmo no identificado | Migrar, planificar o verificar |
| 4 Baja | Vulnerable en autenticación con solo pilotos o sin vía madura; o debilitado por Grover | Planificar, monitorear o revisar parámetros |
| 5 Informativa | Híbrido o resistente | Conforme |

---

## 18. Solución de problemas

| Síntoma | Causa y solución |
|---|---|
| `esquema no soportado` | Revise el prefijo del objetivo (`tls://`, `ssh://`, `dns://`...); la lista completa aparece en el propio mensaje |
| El diagnóstico DNS dice que el resolvedor no devolvió firmas RRSIG | El resolvedor local no valida DNSSEC: use `SUAYA_DNS=1.1.1.1` |
| `jwks_uri apunta fuera del objetivo` | El proveedor publica sus llaves en otro dominio; sondéelo explícitamente con el `oidc://` que sugiere el mensaje |
| Muchos avisos de PKCS#12 cifrados | Defina `SUAYA_CLAVE_ALMACEN` con la contraseña si desea inventariar su contenido |
| Fallan solo las direcciones IPv6 | Puede ser la red del equipo que diagnostica; se informa con nivel bajo |
| `codesign` falla al construir la app | La carpeta está en iCloud: construya con `SUAYA_BUILD_DIR` fuera de ella |
| Error al cargar `--organizacion` | El mensaje indica el campo: fechas `AAAA-MM-DD`, sistemas con rutas u objetivos, excepciones con alcance acotado |
| Resultado `partial` | Hubo archivos omitidos o avisos; revise con `-d` antes de concluir que no hay riesgo |

---

## 19. Límites conocidos

- Suaya ve lo que está declarado o lo que el servicio ofrece; no observa el tráfico real. Si una configuración no declara un parámetro, el resultado depende de la versión instalada y se marca para verificación.
- La validación de certificados no consulta revocación (OCSP/CRL); solo informa si el servidor engrapa OCSP.
- Las recetas citan versiones y directivas vigentes al cierre de 1.7: contrástelas con la documentación de su producto.
- La clasificación cambia cuando cambia el conocimiento (un estándar nuevo, un algoritmo que se debilita); cada CBOM registra con qué versión de la base se clasificó.

Más detalle: [manual de la CLI](docs/manual-cli.md), [integraciones](docs/integraciones.md), [contrato de estabilidad](docs/estabilidad.md), [metodología](docs/metodologia.md), [modelo de amenazas](docs/modelo-de-amenazas.md) y [cierre 1.7](docs/cierre-1.7.md).
