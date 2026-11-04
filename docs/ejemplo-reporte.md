# Reporte de preparación poscuántica (ejemplo)

> Generado por Suaya sobre `pruebas/fixtures/sistema-demo` y la imagen `pruebas/fixtures/imagenes/tienda-docker.tar`, con el perfil `nist-ir-8547` evaluado para 2026. Todas las llaves son de prueba. También disponible en [HTML](ejemplo-reporte.html) y, en inglés, en [HTML](example-report.html).

| | |
|---|---|
| **Sistema** | Sistema de demostración |
| **Fecha del escaneo** | 2026-10-17T04:19:03Z |
| **Herramienta** | Suaya 1.0.0 |
| **Base de conocimiento** | algoritmos 2026.10.0 · código 2026.10.0 · bibliotecas 2026.10.0 · madurez 2026.09.0 (MITRE, Post-Quantum Cryptography (PQC) Capability Development Report, edición 2026-09) |

## Resumen ejecutivo

Suaya inventarió **117 activos criptográficos**. **20** requieren corrección inmediata porque ya son inseguros hoy, sin necesidad de una computadora cuántica. **15** son vulnerables a cómputo cuántico y **pueden migrarse ya**, porque el ecosistema de su capacidad ofrece soluciones generales con PQC. **25** deben planificarse con pilotos, porque solo existen componentes o versiones preliminares. **26** ya son conformes: resistentes a cómputo cuántico o protegidos con un esquema híbrido.

| Prioridad | Activos |
|---|---:|
| Crítica | 20 |
| Alta | 20 |
| Media | 16 |
| Baja | 35 |
| Informativa | 26 |

Las 10 llaves privadas que tienen certificado se presentan junto a él, en las observaciones de cada prioridad.

## Qué se puede migrar hoy y qué no

La madurez del ecosistema indica si ya existen productos para migrar cada tipo de garantía en cada capacidad tecnológica.

| Capacidad | Madurez: confidencialidad | Madurez: autenticación | Activos | Migrar ahora | Planificar | Monitorear |
|---|---|---|---:|---:|---:|---:|
| Servidores web | Integración | Componentes disponibles | 35 | 2 | 19 | 0 |
| VPN y cifrado de red | Integración | Componentes disponibles | 34 | 3 | 6 | 0 |
| Gestión de PKI y autoridades certificadoras | Integración | Integración | 9 | 6 | 0 | 0 |
| Cifrado de volumen | Componentes disponibles | Componentes disponibles | 4 | 0 | 0 | 0 |
| Código de aplicaciones | Integración | Integración | 25 | 4 | 0 | 0 |
| Sin clasificar | Habilitado | Habilitado | 10 | 0 | 0 | 6 |

## Hallazgos que requieren acción

### Prioridad crítica (19)

| Activo | Tipo | Riesgo | Acción | Capacidad | Ubicación |
|---|---|---|---|---|---|
| Triple DES (CBC) | Algoritmo | Roto (clásico) | Corregir de inmediato | VPN y cifrado de red | `pruebas/fixtures/sistema-demo/legado/ssh/sshd_config:2 (y 4 más)` |
| Blowfish (CBC) | Algoritmo | Roto (clásico) | Corregir de inmediato | VPN y cifrado de red | `pruebas/fixtures/sistema-demo/legado/vpn/cliente.ovpn:4` |
| Diffie-Hellman de 1024 o 1536 bits | Algoritmo | Roto (clásico) | Corregir de inmediato | VPN y cifrado de red | `pruebas/fixtures/sistema-demo/legado/vpn/ipsec.conf:3` |
| Diffie-Hellman con SHA-1 | Algoritmo | Roto (clásico) | Corregir de inmediato | VPN y cifrado de red | `pruebas/fixtures/sistema-demo/legado/ssh/sshd_config:1` |
| HMAC-MD5 | Algoritmo | Roto (clásico) | Corregir de inmediato | VPN y cifrado de red | `pruebas/fixtures/sistema-demo/legado/vpn/ipsec.conf:3 (y 1 más)` |
| MD5 | Algoritmo | Roto (clásico) | Corregir de inmediato | Código de aplicaciones | `pruebas/fixtures/sistema-demo/srv/app/pagos.py:7` |
| RSA-1024 | Algoritmo | Roto (clásico) | Corregir de inmediato | Gestión de PKI y autoridades certificadoras | `pruebas/fixtures/sistema-demo/legado/legado.crt:1 (y 2 más)` |
| RSASSA-PKCS1-v1_5 con SHA-1 | Algoritmo | Roto (clásico) | Corregir de inmediato | VPN y cifrado de red | `pruebas/fixtures/sistema-demo/legado/ssh/sshd_config:4` |
| SSL 3.0 | Algoritmo | Roto (clásico) | Corregir de inmediato | Código de aplicaciones | `pruebas/fixtures/sistema-demo/srv/app/legado.c:6` |
| legado.ejemplo.mx | Certificado | Roto (clásico) | Corregir de inmediato | Gestión de PKI y autoridades certificadoras | `pruebas/fixtures/sistema-demo/legado/legado.crt:1` |
| strongSwan (ipsec.conf) | Protocolo | Roto (clásico) | Corregir de inmediato | VPN y cifrado de red | `pruebas/fixtures/sistema-demo/legado/vpn/ipsec.conf` |
| Configuración SSH (sshd_config) | Protocolo | Roto (clásico) | Corregir de inmediato | VPN y cifrado de red | `pruebas/fixtures/sistema-demo/legado/ssh/sshd_config` |
| Java (java.security) | Protocolo | Roto (clásico) | Corregir de inmediato | Servidores web | `pruebas/fixtures/sistema-demo/legado/java/java.security:4` |
| OpenVPN (cliente.ovpn) | Protocolo | Roto (clásico) | Corregir de inmediato | VPN y cifrado de red | `pruebas/fixtures/sistema-demo/legado/vpn/cliente.ovpn` |
| Postfix SMTP (main.cf) | Protocolo | Roto (clásico) | Corregir de inmediato | Servidores web | `pruebas/fixtures/sistema-demo/legado/postfix/main.cf:3` |
| PostgreSQL (postgresql.conf) | Protocolo | Roto (clásico) | Corregir de inmediato | Servidores web | `pruebas/fixtures/sistema-demo/legado/pgsql/postgresql.conf:2` |
| TLS en código (pagos.py) | Protocolo | Roto (clásico) | Corregir de inmediato | Código de aplicaciones | `pruebas/fixtures/sistema-demo/srv/app/pagos.py:13` |
| TLS en código (cliente.ts) | Protocolo | Roto (clásico) | Corregir de inmediato | Código de aplicaciones | `pruebas/fixtures/sistema-demo/srv/app/cliente.ts:7` |
| TLS en código (legado.c) | Protocolo | Roto (clásico) | Corregir de inmediato | Código de aplicaciones | `pruebas/fixtures/sistema-demo/srv/app/legado.c:7` |

**Observaciones**

- **legado.ejemplo.mx**: Raíz autofirmada con RSASSA-PKCS1-v1_5 con SHA-1: la firma propia de un ancla de confianza no afecta la seguridad; lo relevante es su llave pública.
- **legado.ejemplo.mx**: llave privada asociada en `pruebas/fixtures/sistema-demo/legado/legado.key:1`.
- **strongSwan (ipsec.conf)**: Ninguna propuesta IKE incluye ML-KEM. strongSwan 6 admite intercambios adicionales (RFC 9370), por ejemplo «aes256gcm16-sha384-x25519-ke1_mlkem768».
- **strongSwan (ipsec.conf)**: Las propuestas incluyen algoritmos rotos u obsoletos (3DES, MD5, SHA-1 o grupos DH menores a 2048 bits).
- **strongSwan (ipsec.conf)**: Usa IKEv1, retirado por RFC 9395; migre a IKEv2, que además admite intercambios adicionales con ML-KEM.
- **Configuración SSH (sshd_config)**: El intercambio de llaves acepta algoritmos rotos; deshabilitarlos.
- **Java (java.security)**: Habilita versiones de SSL/TLS rotas u obsoletas (RFC 8996).
- **Java (java.security)**: Java elige los grupos de TLS con la propiedad del sistema jdk.tls.namedGroups, fuera de java.security. Verifique si su versión del JDK ofrece grupos híbridos con ML-KEM y si las aplicaciones fijan esa propiedad.
- **Java (java.security)**: jdk.tls.disabledAlgorithms ya no excluye 3DES_EDE_CBC: Java puede negociar cifrados rotos. Restaure la lista predeterminada del JDK.
- **Java (java.security)**: jdk.certpath.disabledAlgorithms ya no excluye MD5, SHA1: se aceptan certificados firmados con resúmenes rotos.
- **Java (java.security)**: keystore.type usa el formato heredado JKS/JCEKS, que protege las llaves con algoritmos propietarios débiles. Use PKCS12.
- **OpenVPN (cliente.ovpn)**: Habilita versiones de SSL/TLS rotas u obsoletas (RFC 8996).
- **OpenVPN (cliente.ovpn)**: No declara tls-groups: OpenVPN usa los grupos predeterminados de OpenSSL (con OpenSSL 3.5 o posterior incluyen X25519MLKEM768). Verificar la versión o sondear el servicio.
- **OpenVPN (cliente.ovpn)**: El canal de datos acepta cifradores o MAC rotos u obsoletos.
- **Postfix SMTP (main.cf)**: El servidor SMTP no ofrece STARTTLS (smtpd_tls_security_level=none): el correo y las credenciales SMTP AUTH viajan sin cifrar.
- **PostgreSQL (postgresql.conf)**: SSL deshabilitado y escucha en «0.0.0.0»: las conexiones a la base de datos viajan sin cifrar.
- **TLS en código (pagos.py)**: Desactiva la verificación del certificado TLS (verify=False): cualquiera en la red puede suplantar al servidor. [línea 13]
- **TLS en código (cliente.ts)**: Desactiva la verificación del certificado TLS (rejectUnauthorized: false o NODE_TLS_REJECT_UNAUTHORIZED=0). [línea 7]
- **TLS en código (legado.c)**: SSL_VERIFY_NONE desactiva la verificación del certificado del par TLS. [línea 7]

### Prioridad alta (20)

| Activo | Tipo | Riesgo | Acción | Capacidad | Ubicación |
|---|---|---|---|---|---|
| DSA | Algoritmo | Obsoleto | Reemplazar | VPN y cifrado de red | `pruebas/fixtures/sistema-demo/legado/ssh/sshd_config:4` |
| ECDH sobre P-256 | Algoritmo | Vulnerable a cómputo cuántico | Migrar ahora | Servidores web | `pruebas/fixtures/sistema-demo/etc/haproxy/haproxy.cfg:6 (y 3 más)` |
| ECDH sobre P-384 | Algoritmo | Vulnerable a cómputo cuántico | Migrar ahora | VPN y cifrado de red | `pruebas/fixtures/sistema-demo/etc/swanctl/swanctl.conf:7` |
| Diffie-Hellman de campo finito | Algoritmo | Vulnerable a cómputo cuántico | Migrar ahora | VPN y cifrado de red | `pruebas/fixtures/sistema-demo/etc/swanctl/swanctl.conf:4` |
| HMAC-SHA-1 | Algoritmo | Obsoleto | Reemplazar | VPN y cifrado de red | `pruebas/fixtures/sistema-demo/legado/ssh/sshd_config:3 (y 1 más)` |
| Modo de operación ECB | Algoritmo | Obsoleto | Reemplazar | Código de aplicaciones | `pruebas/fixtures/sistema-demo/srv/app/Firma.java:10` |
| SHA-1 | Algoritmo | Obsoleto | Reemplazar | Código de aplicaciones | `pruebas/fixtures/sistema-demo/srv/app/Cifrado.cs:5 (y 1 más)` |
| TLS 1.2 | Algoritmo | Vulnerable a cómputo cuántico | Migrar ahora | Código de aplicaciones | `pruebas/fixtures/sistema-demo/srv/app/Cifrado.cs:8` |
| X25519 | Algoritmo | Vulnerable a cómputo cuántico | Migrar ahora | Servidores web | `pruebas/fixtures/sistema-demo/etc/haproxy/haproxy.cfg:6 (y 10 más)` |
| Bouncy Castle (Java, artefacto jdk15on) 1.70 | Biblioteca | Obsoleto | Reemplazar | Código de aplicaciones | `pruebas/fixtures/sistema-demo/srv/app/pom.xml:11` |
| Bouncy Castle (Java) 1.78.1 | Biblioteca | Vulnerable a cómputo cuántico | Migrar ahora | Código de aplicaciones | `pruebas/fixtures/sistema-demo/srv/app/lib/bcprov-jdk18on-1.78.1.jar` |
| crypto-js 4.2.0 | Biblioteca | Obsoleto | Reemplazar | Código de aplicaciones | `pruebas/fixtures/sistema-demo/srv/app/package-lock.json:1` |
| Go (biblioteca estándar) 1.22 | Biblioteca | Obsoleto | Reemplazar | Código de aplicaciones | `pruebas/fixtures/sistema-demo/srv/app/go.mod:3` |
| OpenSSL 1.1.1w | Biblioteca | Obsoleto | Reemplazar | Código de aplicaciones | `pruebas/fixtures/sistema-demo/srv/bin/herramienta` |
| OpenSSL 3.3.1 | Biblioteca | Obsoleto | Reemplazar | Código de aplicaciones | `pruebas/fixtures/sistema-demo/srv/app/Cargo.lock:4` |
| PyCrypto 2.6.1 | Biblioteca | Obsoleto | Reemplazar | Código de aplicaciones | `pruebas/fixtures/sistema-demo/srv/app/requirements.txt:2` |
| WireGuard (wg0.conf) | Protocolo | Vulnerable a cómputo cuántico | Migrar ahora | VPN y cifrado de red | `pruebas/fixtures/sistema-demo/etc/wireguard/wg0.conf` |
| Configuración TLS (ssl.conf) | Protocolo | Obsoleto | Reemplazar | Servidores web | `pruebas/fixtures/sistema-demo/etc/apache2/ssl.conf` |
| HAProxy bind :8443 (haproxy.cfg) | Protocolo | Obsoleto | Reemplazar | Servidores web | `pruebas/fixtures/sistema-demo/etc/haproxy/haproxy.cfg:10` |
| MySQL/MariaDB (my.cnf) | Protocolo | Obsoleto | Reemplazar | Servidores web | `pruebas/fixtures/sistema-demo/legado/mysql/my.cnf:6` |

**Observaciones**

- **Bouncy Castle (Java, artefacto jdk15on) 1.70**: El artefacto bcprov-jdk15on dejó de publicarse en la versión 1.70: migre a bcprov-jdk18on.
- **Bouncy Castle (Java) 1.78.1**: La versión 1.78.1 no ofrece criptografía poscuántica: actualice al menos a 1.79.
- **crypto-js 4.2.0**: Su desarrollo se descontinuó: use node:crypto o Web Crypto.
- **Go (biblioteca estándar) 1.22**: La versión 1.22 no ofrece criptografía poscuántica: actualice al menos a 1.24.
- **Go (biblioteca estándar) 1.22**: La rama 1.22 de Go (biblioteca estándar) dejó de recibir correcciones de seguridad el 2025-02-11.
- **Go (biblioteca estándar) 1.22**: Versión mínima declarada en go.mod: la versión con la que se compila puede ser mayor.
- **OpenSSL 1.1.1w**: La versión 1.1.1w no ofrece criptografía poscuántica: actualice al menos a 3.5.0.
- **OpenSSL 1.1.1w**: La rama 1.1.1 de OpenSSL dejó de recibir correcciones de seguridad el 2023-09-11.
- **OpenSSL 3.3.1**: La versión 3.3.1 no ofrece criptografía poscuántica: actualice al menos a 3.5.0.
- **OpenSSL 3.3.1**: La rama 3.3 de OpenSSL dejó de recibir correcciones de seguridad el 2026-04-09.
- **PyCrypto 2.6.1**: Sin mantenimiento desde 2013 y con vulnerabilidades conocidas: migre a cryptography o PyCryptodome.
- **WireGuard (wg0.conf)**: 1 de 2 pares no usan PresharedKey: su tráfico depende solo de X25519 y puede guardarse para descifrarse en el futuro.
- **WireGuard (wg0.conf)**: La autenticación de los pares sigue basada en X25519. Para un intercambio poscuántico completo, considere Rosenpass, que renueva la PresharedKey con ML-KEM y Classic McEliece.
- **Configuración TLS (ssl.conf)**: Habilita versiones de SSL/TLS rotas u obsoletas (RFC 8996).
- **Configuración TLS (ssl.conf)**: No declara grupos de intercambio de llaves: con OpenSSL 3.5 o posterior el predeterminado incluye X25519MLKEM768; con versiones anteriores solo hay grupos clásicos. Verificar la versión de OpenSSL o sondear el servicio con «suaya sondear».
- **Configuración TLS (ssl.conf)**: Certificado referenciado que no se encontró en el escaneo: /etc/ssl/certs/intranet.crt. Inclúyalo para evaluarlo.
- **HAProxy bind :8443 (haproxy.cfg)**: Habilita versiones de SSL/TLS rotas u obsoletas (RFC 8996).
- **MySQL/MariaDB (my.cnf)**: Habilita versiones de SSL/TLS rotas u obsoletas (RFC 8996).
- **MySQL/MariaDB (my.cnf)**: Sin TLS 1.3 no es posible negociar grupos híbridos poscuánticos.
- **MySQL/MariaDB (my.cnf)**: No exige transporte cifrado (require_secure_transport=ON): un cliente puede conectarse sin TLS y exponer sus credenciales.
- **MySQL/MariaDB (my.cnf)**: Sin ssl_cert, MySQL usa el certificado autofirmado que genera en su directorio de datos (RSA de 2048 bits): los clientes no pueden verificar la identidad del servidor.

### Prioridad media (14)

| Activo | Tipo | Riesgo | Acción | Capacidad | Ubicación |
|---|---|---|---|---|---|
| Ed25519 | Algoritmo | Vulnerable a cómputo cuántico | Migrar ahora | Gestión de PKI y autoridades certificadoras | `pruebas/fixtures/sistema-demo/etc/pki/ca.der (y 6 más)` |
| RSA-2048 | Algoritmo | Vulnerable a cómputo cuántico | Migrar ahora | Gestión de PKI y autoridades certificadoras | `pruebas/fixtures/sistema-demo/etc/haproxy/certs/api.pem:1 (y 6 más)` |
| RSA-3072 | Algoritmo | Vulnerable a cómputo cuántico | Migrar ahora | Código de aplicaciones | `pruebas/fixtures/sistema-demo/etc/mysql/server-cert.pem:1 (y 8 más)` |
| RSASSA-PKCS1-v1_5 con SHA-256 | Algoritmo | Vulnerable a cómputo cuántico | Migrar ahora | Código de aplicaciones | `pruebas/fixtures/sistema-demo/etc/haproxy/certs/api.pem:1 (y 2 más)` |
| Bouncy Castle (Java) 1.80 | Biblioteca | Desconocido | Verificar manualmente | Código de aplicaciones | `pruebas/fixtures/sistema-demo/srv/app/pom.xml:6` |
| CIRCL (Cloudflare) v1.3.7 | Biblioteca | Desconocido | Verificar manualmente | Código de aplicaciones | `pruebas/fixtures/sistema-demo/srv/app/go.mod:7` |
| golang.org/x/crypto v0.21.0 | Biblioteca | Desconocido | Verificar manualmente | Código de aplicaciones | `pruebas/fixtures/sistema-demo/srv/app/go.mod:6` |
| cryptography (Python) 41.0.7 | Biblioteca | Desconocido | Verificar manualmente | Código de aplicaciones | `pruebas/fixtures/sistema-demo/srv/app/requirements.txt:1` |
| CA Demo Suaya | Certificado | Vulnerable a cómputo cuántico | Migrar ahora | Gestión de PKI y autoridades certificadoras | `pruebas/fixtures/sistema-demo/etc/pki/ca.der` |
| ana | Certificado | Vulnerable a cómputo cuántico | Migrar ahora | Gestión de PKI y autoridades certificadoras | `pruebas/fixtures/sistema-demo/home/ana/.kube/config:10` |
| Llave privada cifrada (algoritmo no visible) | Llave o material | Desconocido | Verificar manualmente | Sin clasificar | `pruebas/fixtures/sistema-demo/srv/app-cifrada.key:1` |
| Contenedor PKCS#12 | Llave o material | Desconocido | Verificar manualmente | Sin clasificar | `pruebas/fixtures/sistema-demo/srv/almacen.p12` |
| Java (java.security) | Protocolo | Desconocido | Verificar manualmente | Servidores web | `pruebas/fixtures/sistema-demo/etc/java-21-openjdk/security/java.security:7` |
| MySQL/MariaDB (mysqld.cnf) | Protocolo | Desconocido | Verificar manualmente | Servidores web | `pruebas/fixtures/sistema-demo/etc/mysql/mysql.conf.d/mysqld.cnf:5` |

**Observaciones**

- **Bouncy Castle (Java) 1.80**: La versión 1.80 ofrece PQC: verifique que la aplicación la use. Desde 1.79 implementa ML-KEM, ML-DSA y SLH-DSA según FIPS 203, 204 y 205.
- **CA Demo Suaya**: Raíz autofirmada con Ed25519: la firma propia de un ancla de confianza no afecta la seguridad; lo relevante es su llave pública.
- **CA Demo Suaya**: Vigente hasta 2036 con un algoritmo vulnerable; NIST prevé retirar RSA y ECC de 112 bits después de 2030 y prohibirlos después de 2035 (NIST IR 8547, Transition to Post-Quantum Cryptography Standards (borrador inicial, noviembre de 2024)).
- **CA Demo Suaya**: llave privada asociada en `pruebas/fixtures/sistema-demo/etc/pki/ca.key:1`.
- **ana**: Raíz autofirmada con RSASSA-PKCS1-v1_5 con SHA-256: la firma propia de un ancla de confianza no afecta la seguridad; lo relevante es su llave pública.
- **ana**: llave privada asociada en `pruebas/fixtures/sistema-demo/home/ana/.kube/config:11`.
  - Llave privada incrustada en un archivo kubeconfig (campo «client-key-data»): quien tenga acceso a este archivo, o a su historial en control de versiones, tiene la llave. Use un gestor de secretos (por ejemplo, Sealed Secrets, External Secrets o SOPS).
  - Llave privada sin cifrar con permisos de lectura para grupo u otros (644). Restringir a 600.
- **Llave privada cifrada (algoritmo no visible)**: Llave cifrada: su algoritmo no es visible sin la contraseña. Inventaríe el certificado o la llave pública que la acompaña.
- **Contenedor PKCS#12**: Contenedor protegido por contraseña: Suaya no lo abre. Inventaríe su contenido con «openssl pkcs12 -info -nokeys».
- **Java (java.security)**: Java elige los grupos de TLS con la propiedad del sistema jdk.tls.namedGroups, fuera de java.security. Verifique si su versión del JDK ofrece grupos híbridos con ML-KEM y si las aplicaciones fijan esa propiedad.
- **MySQL/MariaDB (mysqld.cnf)**: La configuración no fija los grupos de intercambio de llaves de TLS: el servidor usa los predeterminados de su biblioteca OpenSSL (desde OpenSSL 3.5 incluyen X25519MLKEM768; antes solo hay grupos clásicos). Verifique la versión de OpenSSL enlazada.

### Prioridad baja (28)

| Activo | Tipo | Riesgo | Acción | Capacidad | Ubicación |
|---|---|---|---|---|---|
| AES-128-CTR | Algoritmo | Debilitado por Grover | Revisar parámetros | VPN y cifrado de red | `pruebas/fixtures/sistema-demo/legado/ssh/sshd_config:2` |
| AES-128-GCM | Algoritmo | Debilitado por Grover | Revisar parámetros | VPN y cifrado de red | `pruebas/fixtures/sistema-demo/etc/ssh/sshd_config:4` |
| AES-128-XTS | Algoritmo | Debilitado por Grover | Revisar parámetros | Cifrado de volumen | `pruebas/fixtures/sistema-demo/etc/crypttab:3` |
| Curva NIST P-256 | Algoritmo | Vulnerable a cómputo cuántico | Planificar y hacer piloto | Servidores web | `pruebas/fixtures/sistema-demo/etc/nginx/www.crt:1 (y 8 más)` |
| Curva NIST P-384 | Algoritmo | Vulnerable a cómputo cuántico | Planificar y hacer piloto | Servidores web | `pruebas/fixtures/sistema-demo/legado/ec384-sec1.key:1 (y 2 más)` |
| ECDSA con SHA-256 | Algoritmo | Vulnerable a cómputo cuántico | Planificar y hacer piloto | Servidores web | `pruebas/fixtures/sistema-demo/etc/nginx/www.crt:1 (y 3 más)` |
| ECDSA con SHA-384 | Algoritmo | Vulnerable a cómputo cuántico | Planificar y hacer piloto | Servidores web | `pruebas/fixtures/sistema-demo/var/lib/pgsql/data/server.crt:1` |
| RSA | Algoritmo | Vulnerable a cómputo cuántico | Monitorear el ecosistema | Sin clasificar | `pruebas/fixtures/sistema-demo/legado/app-pkcs1-cifrada.key:1` |
| RSASSA-PKCS1-v1_5 con SHA-512 | Algoritmo | Vulnerable a cómputo cuántico | Planificar y hacer piloto | VPN y cifrado de red | `pruebas/fixtures/sistema-demo/etc/ssh/sshd_config:6` |
| correo.ejemplo.mx | Certificado | Vulnerable a cómputo cuántico | Planificar y hacer piloto | Servidores web | `pruebas/fixtures/sistema-demo/etc/postfix/correo.pem:6` |
| mysql.ejemplo.mx | Certificado | Vulnerable a cómputo cuántico | Planificar y hacer piloto | Servidores web | `pruebas/fixtures/sistema-demo/etc/mysql/server-cert.pem:1` |
| api.ejemplo.mx | Certificado | Vulnerable a cómputo cuántico | Planificar y hacer piloto | Servidores web | `pruebas/fixtures/sistema-demo/etc/haproxy/certs/api.pem:1` |
| tienda.ejemplo.mx | Certificado | Vulnerable a cómputo cuántico | Planificar y hacer piloto | Servidores web | `pruebas/fixtures/sistema-demo/k8s/secret-tienda.yaml:8 (y 1 más)` |
| www.ejemplo.mx | Certificado | Vulnerable a cómputo cuántico | Planificar y hacer piloto | Servidores web | `pruebas/fixtures/sistema-demo/etc/nginx/www.crt:1` |
| db.ejemplo.mx | Certificado | Vulnerable a cómputo cuántico | Planificar y hacer piloto | Servidores web | `pruebas/fixtures/sistema-demo/var/lib/pgsql/data/server.crt:1` |
| Llave pública Ed25519 (ana@demo) | Llave o material | Vulnerable a cómputo cuántico | Planificar y hacer piloto | VPN y cifrado de red | `pruebas/fixtures/sistema-demo/home/ana/.ssh/authorized_keys:3 (y 2 más)` |
| Llave pública RSA-3072 (ana-rsa@demo) | Llave o material | Vulnerable a cómputo cuántico | Planificar y hacer piloto | VPN y cifrado de red | `pruebas/fixtures/sistema-demo/home/ana/.ssh/authorized_keys:2 (y 1 más)` |
| Llave privada Curva NIST P-384 | Llave o material | Vulnerable a cómputo cuántico | Monitorear el ecosistema | Sin clasificar | `pruebas/fixtures/sistema-demo/legado/ec384-sec1.key:1` |
| Llave privada Ed25519 | Llave o material | Vulnerable a cómputo cuántico | Planificar y hacer piloto | VPN y cifrado de red | `pruebas/fixtures/sistema-demo/home/ana/.ssh/id_ed25519:1` |
| Llave privada RSA | Llave o material | Vulnerable a cómputo cuántico | Monitorear el ecosistema | Sin clasificar | `pruebas/fixtures/sistema-demo/legado/app-pkcs1-cifrada.key:1` |
| Llave privada WireGuard (X25519) | Llave o material | Vulnerable a cómputo cuántico | Planificar y hacer piloto | VPN y cifrado de red | `pruebas/fixtures/sistema-demo/etc/wireguard/wg0.conf:4` |
| Llave privada RSA-3072 | Llave o material | Vulnerable a cómputo cuántico | Monitorear el ecosistema | Sin clasificar | `pruebas/fixtures/sistema-demo/legado/app-pkcs1.key:1` |
| Llave privada RSA-3072 | Llave o material | Vulnerable a cómputo cuántico | Planificar y hacer piloto | VPN y cifrado de red | `pruebas/fixtures/sistema-demo/home/ana/.ssh/id_rsa:1` |
| Llave de cert-manager tienda/tienda (Curva NIST P-256) | Llave o material | Vulnerable a cómputo cuántico | Planificar y hacer piloto | Servidores web | `pruebas/fixtures/sistema-demo/k8s/certificados.yaml:1` |
| Llave de cert-manager interno/intranet (RSA-2048) | Llave o material | Vulnerable a cómputo cuántico | Planificar y hacer piloto | Servidores web | `pruebas/fixtures/sistema-demo/k8s/certificados.yaml:14` |
| Llave privada RSA-3072 | Llave o material | Vulnerable a cómputo cuántico | Monitorear el ecosistema | Sin clasificar | `pruebas/fixtures/sistema-demo/srv/app.key:1` |
| Llave pública RSA-3072 | Llave o material | Vulnerable a cómputo cuántico | Monitorear el ecosistema | Sin clasificar | `pruebas/fixtures/sistema-demo/srv/app.pub.pem:1` |
| Llave del volumen datos | Llave o material | Debilitado por Grover | Revisar parámetros | Cifrado de volumen | `pruebas/fixtures/sistema-demo/etc/crypttab:3` |

**Observaciones**

- **correo.ejemplo.mx**: llave privada asociada en `pruebas/fixtures/sistema-demo/etc/postfix/correo.pem:1`.
- **mysql.ejemplo.mx**: llave privada asociada en `pruebas/fixtures/sistema-demo/etc/mysql/server-key.pem:1`.
- **api.ejemplo.mx**: llave privada asociada en `pruebas/fixtures/sistema-demo/etc/haproxy/certs/api.pem:20`.
- **tienda.ejemplo.mx**: llave privada asociada en `tienda-docker.tar@capa1:/etc/ssl/private/tienda.key:1`.
  - Se borró en una capa posterior, pero sigue dentro de la imagen (capa 1) y cualquiera que la descargue puede extraerla. Reconstruya la imagen sin el secreto y revóquelo.
  - Llave privada dentro de la imagen de contenedor «demo/tienda:1.0»: queda expuesta en cada registro y equipo donde se copie la imagen. Móntela en tiempo de ejecución desde un gestor de secretos.
  - La misma llave privada aparece en 2 ubicaciones (pruebas/fixtures/sistema-demo/k8s/secret-tienda.yaml, tienda-docker.tar@capa1:/etc/ssl/private/tienda.key). Cada copia amplía la superficie de exposición; conserve solo las necesarias.
- **tienda.ejemplo.mx**: llave privada asociada en `pruebas/fixtures/sistema-demo/k8s/secret-tienda.yaml:9`.
  - Llave privada incrustada en un Secret de Kubernetes (campo «tls.key»): quien tenga acceso a este archivo, o a su historial en control de versiones, tiene la llave. Use un gestor de secretos (por ejemplo, Sealed Secrets, External Secrets o SOPS).
  - Llave privada sin cifrar con permisos de lectura para grupo u otros (644). Restringir a 600.
  - La misma llave privada aparece en 2 ubicaciones (pruebas/fixtures/sistema-demo/k8s/secret-tienda.yaml, tienda-docker.tar@capa1:/etc/ssl/private/tienda.key). Cada copia amplía la superficie de exposición; conserve solo las necesarias.
- **www.ejemplo.mx**: Vigente hasta 2040 con un algoritmo vulnerable; NIST prevé retirar RSA y ECC de 112 bits después de 2030 y prohibirlos después de 2035 (NIST IR 8547, Transition to Post-Quantum Cryptography Standards (borrador inicial, noviembre de 2024)).
- **www.ejemplo.mx**: llave privada asociada en `pruebas/fixtures/sistema-demo/etc/nginx/www.key:1`.
- **db.ejemplo.mx**: llave privada asociada en `pruebas/fixtures/sistema-demo/var/lib/pgsql/data/server.key:1`.
- **Llave privada RSA**: Formato de cifrado heredado de OpenSSL; preferir PKCS#8 con PBES2 o scrypt.
- **Llave privada RSA-3072**: La misma llave privada aparece en 2 ubicaciones (pruebas/fixtures/sistema-demo/legado/app-pkcs1.key, pruebas/fixtures/sistema-demo/srv/app.key). Cada copia amplía la superficie de exposición; conserve solo las necesarias.
- **Llave de cert-manager tienda/tienda (Curva NIST P-256)**: cert-manager generará llaves con este algoritmo en cada renovación. Para migrar, cambie spec.privateKey.algorithm cuando su versión de cert-manager y su emisor admitan un algoritmo poscuántico.
- **Llave de cert-manager interno/intranet (RSA-2048)**: cert-manager generará llaves con este algoritmo en cada renovación. Para migrar, cambie spec.privateKey.algorithm cuando su versión de cert-manager y su emisor admitan un algoritmo poscuántico.
- **Llave de cert-manager interno/intranet (RSA-2048)**: spec.privateKey.rotationPolicy no es «Always»: la llave se reutiliza en las renovaciones, lo que alarga su exposición y retrasa la migración.
- **Llave privada RSA-3072**: Llave privada sin cifrar con permisos de lectura para grupo u otros (644). Restringir a 600.
- **Llave privada RSA-3072**: La misma llave privada aparece en 2 ubicaciones (pruebas/fixtures/sistema-demo/legado/app-pkcs1.key, pruebas/fixtures/sistema-demo/srv/app.key). Cada copia amplía la superficie de exposición; conserve solo las necesarias.

## Cumplimiento con NIST IR 8547 (transición a criptografía poscuántica)

Referencia: NIST IR 8547, Transition to Post-Quantum Cryptography Standards, borrador inicial (noviembre de 2024).

| Estado | Activos |
|---|---:|
| No conforme | 32 |
| En transición | 53 |
| Conforme | 21 |
| Sin evaluar | 11 |

**Calendario de migración**

| Fecha límite | Activos | Ejemplos |
|---|---:|---|
| 2035 | 53 | Bouncy Castle (Java) 1.78.1, CA Demo Suaya, Configuración SSH (sshd_config), Configuración TLS (nginx.conf) y 40 más |

**Activos no conformes**

| Activo | Tipo | Motivo |
|---|---|---|
| Blowfish (CBC) | Algoritmo | Inseguro o retirado por los estándares vigentes. |
| Configuración SSH (sshd_config) | Protocolo | Inseguro o retirado por los estándares vigentes. |
| Diffie-Hellman con SHA-1 | Algoritmo | Inseguro o retirado por los estándares vigentes. |
| Diffie-Hellman de 1024 o 1536 bits | Algoritmo | Inseguro o retirado por los estándares vigentes. |
| HMAC-MD5 | Algoritmo | Inseguro o retirado por los estándares vigentes. |
| Java (java.security) | Protocolo | Inseguro o retirado por los estándares vigentes. |
| Llave privada RSA-1024 | Llave o material | Inseguro o retirado por los estándares vigentes. |
| MD5 | Algoritmo | Inseguro o retirado por los estándares vigentes. |
| OpenVPN (cliente.ovpn) | Protocolo | Inseguro o retirado por los estándares vigentes. |
| Postfix SMTP (main.cf) | Protocolo | Inseguro o retirado por los estándares vigentes. |
| PostgreSQL (postgresql.conf) | Protocolo | Inseguro o retirado por los estándares vigentes. |
| RSA-1024 | Algoritmo | Inseguro o retirado por los estándares vigentes. |
| RSASSA-PKCS1-v1_5 con SHA-1 | Algoritmo | Inseguro o retirado por los estándares vigentes. |
| TLS en código (cliente.ts) | Protocolo | Inseguro o retirado por los estándares vigentes. |
| TLS en código (legado.c) | Protocolo | Inseguro o retirado por los estándares vigentes. |
| TLS en código (pagos.py) | Protocolo | Inseguro o retirado por los estándares vigentes. |
| Triple DES (CBC) | Algoritmo | Inseguro o retirado por los estándares vigentes. |
| legado.ejemplo.mx | Certificado | Inseguro o retirado por los estándares vigentes. |
| strongSwan (ipsec.conf) | Protocolo | Inseguro o retirado por los estándares vigentes. |
| Bouncy Castle (Java, artefacto jdk15on) 1.70 | Biblioteca | Inseguro o retirado por los estándares vigentes. |
| Configuración TLS (ssl.conf) | Protocolo | Inseguro o retirado por los estándares vigentes. |
| DSA | Algoritmo | Inseguro o retirado por los estándares vigentes. |
| Go (biblioteca estándar) 1.22 | Biblioteca | Inseguro o retirado por los estándares vigentes. |
| HAProxy bind :8443 (haproxy.cfg) | Protocolo | Inseguro o retirado por los estándares vigentes. |
| HMAC-SHA-1 | Algoritmo | Inseguro o retirado por los estándares vigentes. |
| ... y 7 más | | |

## Activos conformes (26)

AES-256-CBC, AES-256-GCM, AES-256-XTS, BLAKE2s, ChaCha20-Poly1305, HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512, ML-DSA-65, ML-KEM-768, SHA-256, sntrup761x25519 (híbrido no NIST), TLS 1.3, X25519MLKEM768 (híbrido), @noble/post-quantum 0.4.1, ml-kem (RustCrypto) 0.2.1, Llave pública ML-DSA-65, Llave del volumen raiz, strongSwan (swanctl.conf), Configuración SSH (sshd_config), Postfix SMTP (main.cf), Configuración TLS (tienda.conf), PostgreSQL (postgresql.conf), OpenVPN (server.conf), HAProxy bind :443 (haproxy.cfg), Configuración TLS (nginx.conf).

**Observaciones**

- **Llave del volumen raiz**: El cifrador se define en la cabecera LUKS; se asume el predeterminado de LUKS2 (aes-xts-plain64, 512 bits). Confirmar con «cryptsetup luksDump».
- **Llave del volumen raiz**: Se desbloquea con TPM2, que usa criptografía asimétrica clásica; aún no hay TPM de hardware con PQC disponibles comercialmente.
- **strongSwan (swanctl.conf)**: También acepta propuestas IKE sin ML-KEM: los pares antiguos negociarán sin protección poscuántica.
- **Configuración SSH (sshd_config)**: También acepta intercambios clásicos: los clientes antiguos negociarán sin protección poscuántica.
- **Postfix SMTP (main.cf)**: También acepta grupos clásicos: los clientes antiguos negociarán sin protección poscuántica.
- **Postfix SMTP (main.cf)**: TLS 1.2 sigue habilitado: esas conexiones no pueden usar grupos híbridos.
- **Postfix SMTP (main.cf)**: TLS oportunista (smtpd_tls_security_level=may): un atacante en la red puede suprimir STARTTLS y forzar texto claro. Para el intercambio entre sistemas propios exija TLS (encrypt) o publique DANE o MTA-STS.
- **Configuración TLS (tienda.conf)**: También acepta grupos clásicos: los clientes antiguos negociarán sin protección poscuántica.
- **PostgreSQL (postgresql.conf)**: También acepta grupos clásicos: los clientes antiguos negociarán sin protección poscuántica.
- **OpenVPN (server.conf)**: También acepta grupos clásicos: los clientes antiguos negociarán sin protección poscuántica.
- **OpenVPN (server.conf)**: TLS 1.2 sigue habilitado: esas conexiones no pueden usar grupos híbridos.
- **OpenVPN (server.conf)**: tls-crypt cifra el canal de control con una llave simétrica compartida: si esa llave no se expone, dificulta capturar el intercambio de llaves para descifrarlo en el futuro.
- **OpenVPN (server.conf)**: Certificado referenciado que no se encontró en el escaneo: /etc/openvpn/ca.crt. Inclúyalo para evaluarlo.
- **OpenVPN (server.conf)**: Certificado referenciado que no se encontró en el escaneo: /etc/openvpn/server.crt. Inclúyalo para evaluarlo.
- **HAProxy bind :443 (haproxy.cfg)**: También acepta grupos clásicos: los clientes antiguos negociarán sin protección poscuántica.
- **HAProxy bind :443 (haproxy.cfg)**: TLS 1.2 sigue habilitado: esas conexiones no pueden usar grupos híbridos.
- **Configuración TLS (nginx.conf)**: También acepta grupos clásicos: los clientes antiguos negociarán sin protección poscuántica.
- **Configuración TLS (nginx.conf)**: TLS 1.2 sigue habilitado: esas conexiones no pueden usar grupos híbridos.

## Metodología

Cada activo se evalúa en cuatro ejes: **riesgo** (roto, obsoleto, vulnerable al algoritmo de Shor, debilitado por Grover, híbrido o resistente), **garantía** (confidencialidad, autenticación o integridad), **capacidad tecnológica** y **madurez del ecosistema** para adoptar PQC. La confidencialidad se prioriza porque los datos cifrados hoy pueden almacenarse y descifrarse en el futuro.

Los niveles de madurez provienen de: MITRE, Post-Quantum Cryptography (PQC) Capability Development Report, edición 2026-09, con evidencia de 2026-07. © MITRE, aprobado para difusión pública (caso 26-2150). Suaya usa sus niveles con atribución y no reproduce su texto.

**Alcance.** Suaya inspecciona archivos, configuraciones, código y los servicios que se le indican; no observa el tráfico real. Cuando una configuración no declara un parámetro, el resultado depende de la versión instalada del software y se marca para verificación. Suaya nunca copia material secreto al inventario.
