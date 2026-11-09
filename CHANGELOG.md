# Cambios

## [1.7.0] - 2026-11-06

### Conocimiento
- Algoritmos nuevos: HSS/LMS, XMSS y XMSS^MT; FN-DSA, HQC, FrodoKEM, Classic McEliece y X-Wing; los doce ML-KEM compuestos; curvas brainpool; SM2, SM3 y SM4; GOST R 34.10-2012, Streebog, Kuznyechik y Magma; Camellia, ARIA y SEED; AES-KW, AES-CCM, AES-GCM-SIV, CMAC, HKDF, SHAKE; Argon2, bcrypt, yescrypt y las variantes de crypt; MD4, ElGamal, tipos de cifrado de Kerberos y P-224.
- Alias como datos para DNSSEC (incluido ML-DSA-44, algoritmo 18 de IANA), digestiones DS, Kerberos, AWS KMS, Google Cloud KMS, contraseñas, Oracle, JOSE (RS256, ES256, ML-DSA-44... de RFC 7518 y RFC 9964) y XML Signature/Encryption.
- Perfiles nuevos: hoja de ruta de la Unión Europea, NCSC del Reino Unido, CCCS de Canadá y PCI DSS v4.0.1; las reglas de un perfil pueden depender de la criticidad del sistema.
- Recetas de corrección como datos (`conocimiento/remediacion.toml`): pasos concretos (nginx, Apache, HAProxy, OpenSSH, strongSwan, OpenSSL, DKIM...) en el reporte, el diagnóstico, SARIF y los tickets.
- Capacidades nuevas: infraestructura DNS e identidad federada (decisiones de Suaya, editables).
- Reglas de código para PHP, Ruby, Swift, Dart, PowerShell y scripts de shell, incluidas órdenes como `openssl`, `ssh-keygen`, `keytool`, `certbot`, `step`, `gpg` y `wg`, y hallazgos como `curl -k`.
- Navegadores (Chrome, Edge, Firefox, Safari) como bibliotecas con la versión desde la que negocian ML-KEM.

### Escaneo de archivos
- Servicios descritos como datos (`conocimiento/servicios.toml`): Kafka, Spring Boot, Tomcat, WildFly, Dovecot, Exim, MongoDB, Redis, Elasticsearch, RabbitMQ, Mosquitto, Vault/Consul/Nomad, Traefik, Envoy, ingress-nginx, componentes de Kubernetes, Caddy, OpenLDAP, Grafana y Oracle Net.
- Configuración del sistema: OpenSSL, crypto-policies, GnuTLS, Kerberos y políticas de navegador; registro de Windows (`.reg`: SChannel, Kerberos, BitLocker, .NET, NTLM, almacenes de certificados).
- Infraestructura como código y nube: Terraform, CloudFormation, ARM, Bicep, salidas de las CLI de AWS, Azure y Google, JWKS (llaves ML-DSA `AKP` y cadenas `x5c`) y cfssl.
- OpenPGP; contenedores JKS, JCEKS y PKCS#12 (con `SUAYA_CLAVE_ALMACEN` para descifrar PBES2/AES); UEFI Secure Boot, firma de módulos del kernel y llaves MOK/IMA/EVM; cabeceras LUKS; plantillas de AD CS y cuentas de Kerberos en LDIF; certificados SSH.
- Ejecutables PE, ELF y Mach-O (firmas Authenticode y de código de macOS, funciones importadas, constantes de implementación) y aplicaciones Java y Android (firmas de JAR y APK v2/v3, literales de bytecode y DEX) con `--binarios`.
- `escanear --llavero` inventaría los certificados del llavero de macOS (nunca lee llaves privadas).

### Red y diagnóstico
- TLS: enumeración de las suites de TLS 1.2 aceptadas y cadena de certificados por familia de firma (ECDSA, RSA, EdDSA, ML-DSA).
- SSH: llaves de host como material en el CBOM. IKEv2 (`ike://`) con grupos aceptados e intercambio adicional ML-KEM (RFC 9370). STARTTLS de FTP, XMPP y RDP.
- `dns://dominio`: DNSSEC (llaves, delegación, firmas y validación), CAA, TLSA y DKIM, con `SUAYA_DNS` para elegir el resolvedor.
- `oidc://` y `saml://`: algoritmos anunciados, llaves JWKS y certificados y métodos de los metadatos SAML; `jwks_uri` solo se sigue dentro del dominio del objetivo.
- El diagnóstico aplica la vigencia máxima del CA/Browser Forum (SC-081v3), agrega recetas de corrección y exporta métricas para Prometheus (`--metricas`).

### Contexto, salidas e integraciones
- `--organizacion` (TOML): sistemas, responsables, criticidad, exposición, desigualdad de Mosca y excepciones con vencimiento; las excepciones vigentes no cuentan para `--fallar-en`.
- Salidas `--sarif` (SARIF 2.1.0) y `--csv`; `suaya reporte --formato pci|sarif|csv|jsonl|tickets`; orden nueva `suaya tendencias` (`trends`).
- Acción de GitHub (`action.yml`), plantilla de GitLab CI, ganchos de pre-commit y modo de diagnóstico en `scripts/automatizar.py`.
- API: perfiles incluidos y contexto de la organización en los escaneos, reportes en todos los formatos, resumen, comparación, tendencias, OpenAPI 3.1 y un panel web en `/panel`.
- macOS: perfil, archivo de organización, llavero y exportación CSV y SARIF; el diagnóstico muestra IKE, DNS, identidad y recetas.
- Interfaz y reporte en portugués (`--idioma pt`); catálogo en inglés para todos los textos nuevos.

### Seguridad
- `rusqlite` 0.41.1 y `libsqlite3-sys` 0.39.1 (SQLite 3.54.1) en la API, por RUSTSEC-2026-0459 (CVE-2026-119375): memoria de la caché de páginas sin inicializar al abrir una base con un `-wal` manipulado.

### Correcciones
- Los protocolos fuera del vocabulario de CycloneDX 1.7 (Kerberos, NTLM, DNSSEC...) se exportan como `other` con `suaya:tipo-protocolo`, y el CBOM vuelve a validar contra el esquema.
- El aviso de cobertura parcial del reporte ya se traduce.

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
