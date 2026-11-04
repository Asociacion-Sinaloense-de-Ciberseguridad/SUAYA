# Alcance para una auditoría de seguridad externa

Suaya 1.0 no ha pasado todavía por una auditoría de seguridad independiente. Este documento prepara esa revisión: qué revisar primero, dónde está cada parte y qué evidencia ya existe, para que el tiempo del equipo auditor se dedique a lo que más importa.

## Contexto

- Rust 2024, unos 16 000 renglones de código propio en cinco crates (sin contar pruebas), `unsafe` prohibido.
- Lee entradas no confiables (archivos, imágenes de contenedor, CBOM, respuestas de red) y suele correr con permisos amplios de lectura.
- Un único proveedor criptográfico: AWS-LC, mediante `aws-lc-rs` (y `rustls` sobre él).
- Modelo de amenazas: [modelo-de-amenazas.md](modelo-de-amenazas.md).

## Prioridades

### 1. Que nunca salga material secreto

El requisito más importante. Revisar que ningún camino copie a la salida (CBOM, reportes, avisos, mensajes de error) el contenido de una llave privada, una contraseña o un secreto.

- Escáneres que tocan secretos: `crates/suaya-escaneo/src/pem.rs`, `llaves_ssh.rs`, `contenedores.rs` (PKCS#12, JKS), `incrustados.rs` (base64 en YAML, kubeconfig, Terraform), `vpn.rs` (WireGuard, OpenVPN, strongSwan), `config_*.rs`.
- Kubernetes en vivo: `crates/suaya-red/src/kubernetes.rs` (lee Secrets).
- Evidencia existente: `el_cbom_y_los_reportes_no_contienen_material_secreto` en `crates/suaya-cbom/tests/sistema_demo.rs`.
- Preguntas: ¿puede un mensaje de error de un analizador incluir parte de la entrada? ¿Puede una justificación citar una línea de configuración con un secreto?

### 2. Análisis de entradas hostiles

- Analizadores: PEM, PKCS#8, PKCS#1 y SEC1 (`pem.rs`, `identidad.rs`, sobre `x509-parser`), JKS (`contenedores.rs`), tar e imágenes OCI (`imagen.rs`), el analizador léxico de código (`codigo.rs`), los formatos de configuración (`config_*.rs`), manifiestos y binarios (`bibliotecas.rs`), importación de CBOM (`importar.rs`).
- Protocolos de red: SSH `KEXINIT` (`suaya-red/src/ssh.rs`), preámbulos STARTTLS (`starttls.rs`), cliente HTTP propio con cuerpos fragmentados y túnel por proxy (`http.rs`).
- Buscar: pánicos alcanzables (índices, `unwrap`, desbordamientos aritméticos en compilación de depuración), consumo de memoria o tiempo no acotado, lectura fuera de las rutas indicadas, seguimiento de enlaces simbólicos.
- Evidencia: `tests/robustez.rs` en cada crate y los objetivos de `fuzz/` (`cargo +nightly fuzz run escaneres`).

### 3. Red

- Que el sondeo no envíe credenciales ni datos de aplicación.
- Que el cliente de registros y el de Kubernetes verifiquen siempre el certificado del servidor y no envíen credenciales a otro origen tras una redirección (`registro.rs`, `Sesion::abrir`).
- Manejo de `HTTPS_PROXY` y `NO_PROXY` (`http.rs`, `excluido_del_proxy`).
- Complementos `exec` del kubeconfig: Suaya ejecuta el programa que el kubeconfig indica, igual que kubectl. Revisar que no se ejecute nada que el kubeconfig no pida.

### 4. Firma híbrida

- `crates/suaya-cbom/src/firma.rs`: construcción del mensaje con separación de dominio, verificación de ambas firmas, comparación de huellas, cifrado de la llave privada (PBKDF2-HMAC-SHA256 con 600 000 iteraciones, AES-256-GCM, sal y nonce aleatorios), permisos del archivo.
- Preguntas: ¿hay algún camino en que una sola firma válida baste? ¿Se puede sustituir la llave pública sin que cambie la huella?

### 5. Corrección de la clasificación

Un falso «conforme» es una falla de seguridad para quien confía en el inventario.

- Datos: `conocimiento/*.toml`. Lógica: `crates/suaya-core/src/clasificacion.rs`, `politica.rs`, `conocimiento.rs`.
- Revisar contra NIST IR 8547, CNSA 2.0, FIPS 203, 204 y 205, y los RFC de TLS y SSH citados.

### 6. Cadena de suministro

- `Cargo.lock`, `deny.toml`, `.github/workflows/*.yml` (acciones fijadas por *commit*, permisos mínimos por trabajo), `scripts/compilacion-reproducible.sh`.

## Fuera de alcance sugerido

- La implementación de AWS-LC y de `rustls`, auditadas por separado.
- Los perfiles de política como interpretación jurídica de cada marco.

## Cómo preparar el entorno

```bash
cargo test --locked                 # pruebas, incluidas las de robustez
SUAYA_RONDAS=400 cargo test --release --locked --test robustez
cargo deny check
./pruebas/generar-fixtures.sh       # regenera el sistema de demostración
./scripts/compilacion-reproducible.sh
```

## Entregables esperados

Un reporte con cada hallazgo clasificado por gravedad, pasos para reproducirlo y, si es posible, una prueba que lo demuestre. Los hallazgos se coordinan según [SECURITY.md](../SECURITY.md) y se publican junto con la corrección.
