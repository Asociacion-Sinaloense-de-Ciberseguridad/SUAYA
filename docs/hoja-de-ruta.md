# Hoja de ruta

## 1.7 (actual): cobertura, contexto e integraciones

- Base de conocimiento ampliada (firmas basadas en hash, KEM alternativos y compuestos, algoritmos nacionales, JOSE, XML Signature) y recetas de corrección como datos.
- Escáneres de servicios declarados como datos, configuración del sistema, registro de Windows, nube e infraestructura como código, OpenPGP, almacenes Java, plataforma (Secure Boot, kernel, LUKS), Active Directory, ejecutables y aplicaciones Java y Android, y el llavero de macOS.
- Red: suites de TLS 1.2, cadenas por familia de firma, llaves de host SSH, IKEv2 con ML-KEM, DNS (DNSSEC, DKIM, CAA, TLSA) e identidad federada (OIDC y SAML).
- Contexto de la organización (Mosca y excepciones), SARIF, CSV, JSON Lines, tickets, inventario PCI DSS, tendencias, métricas para Prometheus, integraciones de CI, panel web y portugués.

## 1.6: diagnóstico de conectividad e intercambio de llaves y certificados

- Orden `diagnosticar` (`diagnose`) con conectividad por dirección, saludos TLS completos de un cliente moderno y uno clásico, validación estándar de la cadena y análisis del `KEXINIT` de SSH, en texto y JSON, con umbral `--fallar-en`.
- `--diagnostico` en el sondeo para llevar los hallazgos al CBOM.
- Diagnóstico en la API (`POST /api/v1/diagnose`, alias preconfigurados) y en la interfaz macOS (pestaña «Diagnóstico de red»).

## 1.0: estable

- Contrato de estabilidad para órdenes, opciones, códigos de salida, propiedades `suaya:` del CBOM, formato de firma y esquema de la base de conocimiento ([estabilidad.md](estabilidad.md)).
- Rendimiento: análisis en paralelo determinista, detección de marcas en una sola pasada (Aho-Corasick) y lectura por bloques de binarios grandes.
- Pruebas de mutación y objetivos de *fuzzing* para todos los analizadores.
- Compilaciones reproducibles, procedencia SLSA, `SHA256SUMS` con firma híbrida opcional y política de dependencias con cargo-deny.
- Paquetes `.deb` y `.rpm`, fórmula de Homebrew, imagen de contenedor, página de manual y autocompletado.
- Modelo de amenazas, guía de publicación, alcance de auditoría y gobernanza.

## 0.8

- Reporte HTML autocontenido con gráficas, modo oscuro e impresión a PDF (`-r reporte.html`, `suaya reporte --formato html`).
- Interfaz, CBOM y reportes también en inglés (`--idioma en`), con el texto de los hallazgos traducido desde un catálogo como datos (`conocimiento/traducciones/en.toml`).
- Firma híbrida del CBOM con ML-DSA-65 y Ed25519 (`suaya llaves`, `firmar`, `verificar`, `--firmar-con`).
- Atestaciones CycloneDX (CDXA) del cumplimiento con el perfil de política.

## 0.7

- Uso criptográfico en código fuente: Python, Java (y Kotlin), Go, JavaScript y TypeScript, C#, Rust y C/C++, con analizador léxico que descarta comentarios y reglas como datos (`conocimiento/codigo.toml`).
- Bibliotecas criptográficas y su versión en binarios, paquetes instalados y manifiestos, con fin de soporte y disponibilidad de PQC (`conocimiento/bibliotecas.toml`), exportadas como componentes `library` con purl.
- STARTTLS en el sondeo: SMTP, IMAP, POP3, LDAP, PostgreSQL y MySQL.
- Importación de CBOM CycloneDX de otras herramientas (`suaya importar`, `--importar`).
- Firmas compuestas ML-DSA reconocidas por sus OID de asignación anticipada.

## 0.6

- Perfiles de política intercambiables (`--perfil`): NIST IR 8547 y CNSA 2.0 incluidos, más una plantilla para marcos nacionales, sectoriales o institucionales. Estado de cumplimiento, fecha límite y calendario de migración en el CBOM y en el reporte.
- Imágenes de contenedor directamente desde un registro OCI (`--imagen docker://...`), con verificación SHA-256 de manifiestos y capas, credenciales de Docker y soporte de proxy.
- Escáneres de MySQL y MariaDB, Postfix y la política criptográfica de Java (`java.security`).
- Kubernetes: sin autoridad declarada en el kubeconfig se usan las del sistema, como kubectl.

## 0.5

- Inventario de clústeres de Kubernetes en vivo (`suaya kubernetes`): Secrets, Ingress y Certificates de cert-manager, solo con lecturas y verificación TLS estricta del servidor de la API.
- Autenticación con token, certificado de cliente, complementos `exec` (EKS, GKE, AKS) y cuenta de servicio dentro del clúster.
- Sondeo opcional de los hosts publicados por los Ingress.
- El sondeo TLS anuncia esquemas ML-DSA para inventariar certificados poscuánticos.

## 0.4

- Secretos incrustados en base64 (Kubernetes, kubeconfig, Helm, Terraform) y advertencia de llaves privadas en archivos de configuración.
- Recursos `Certificate` de cert-manager.
- Imágenes de contenedor `docker save`, `podman save` y OCI, con detección de secretos borrados en capas posteriores.
- WireGuard, OpenVPN y strongSwan (incluido ML-KEM en IKEv2 según RFC 9370).

## 0.3

- Identidad canónica de llaves públicas y enlace entre llaves privadas, públicas y certificados en todos los formatos.
- Detección de llaves privadas copiadas en varias ubicaciones.
- Reporte que agrupa cada llave con su certificado.
- Escáneres de HAProxy y PostgreSQL; certificados referenciados por directorio.

## 0.2

- **Sondeo de red** TLS y SSH (`suaya sondear` y `--objetivo`): versiones aceptadas, cada grupo de intercambio de llaves, preferencia por híbridos, suite de TLS 1.2, cadena de certificados y `KEXINIT` de SSH.
- Códigos IANA de grupos TLS en la base de conocimiento.

## 0.1

- Modelo de datos, base de conocimiento como datos y motor de clasificación en cuatro ejes.
- Escáneres de archivos: certificados, llaves (PKCS#8, PKCS#1, SEC1, OpenSSH), llaves SSH, configuración SSH, nginx, Apache, `crypttab` y contenedores PKCS#12/JKS.
- CBOM CycloneDX 1.7 validado contra el esquema oficial, reporte ejecutivo en español y comparación entre escaneos.

## Después de la 1.7

- Revocación: consultar OCSP y CRL (hoy se informa el engrapado OCSP).
- Firmas Sigstore y cosign de imágenes y artefactos; cadenas `#US` de ensamblados .NET; configuración de IIS.
- Consultas en vivo a las API de nube (KMS, balanceadores) con credenciales de solo lectura; PKCS#11 y HashiCorp Vault.
- Cifrado de bases de datos (TDE de SQL Server y Oracle).
- Recetas de corrección y mensajes de hallazgos también en portugués.

## Después de la 1.0

- **Auditoría de seguridad externa** con el alcance de [auditoria.md](auditoria.md).
- **Perfiles latinoamericanos**: marcos nacionales y sectoriales de México y de la región, construidos con la plantilla de perfiles y revisados por especialistas de cada país.
- **Firmas compuestas**: actualizar los identificadores de ML-DSA compuesto cuando el borrador de IETF se publique como RFC.
- Verificación de la compilación reproducible también en macOS y Windows.
- Pruebas contra registros de imágenes públicos y clústeres de Kubernetes reales en la integración continua.
- Traslado a una organización neutral cuando haya un grupo de mantenimiento ([GOBERNANZA.md](../GOBERNANZA.md)).
