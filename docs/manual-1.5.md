# Manual de Suaya 1.5

Suaya analiza sistemas en busca de criptografía obsoleta o insegura, inventaria activos y los clasifica en cuatro ejes: riesgo, acción, prioridad y cumplimiento. Produce un CBOM CycloneDX 1.7 válido y un reporte ejecutivo en español.

## Requisitos

- **Rust 1.99.1** o posterior.
- **macOS 13** o posterior (compilación y ejecución).
- Binarios precompilados para Linux (glibc 2.35+), macOS y Windows.

## Instalación

```bash
# Desde fuente
git clone https://github.com/Asociacion-Sinaloense-de-Ciberseguridad/SUAYA && cd SUAYA
cargo build --release

# Desde paquete
# Descargar suaya-1.5.0-<plataforma>.tar.gz de GitHub Releases
tar xzf suaya-1.5.0-<plataforma>.tar.gz
./suaya --version
```

## Comandos principales

### `escanear` (`scan`)

Analiza un sistema o archivo y produce un CBOM.

```bash
suaya escanear <ruta> [opciones]
```

**Opciones:**
- `--perfil <nombre>`: Perfil de política (ej. `nist-8547`, `cnsa-2.0`).
- `--fallar-en <nivel>`: Código de salida 2 si el riesgo alcanza el nivel.
- `--fallar-si-empeora`: Código de salida 2 si un activo empeora respecto al último escaneo.
- `--base-conocimiento <ruta>`: Usa una base de conocimiento propia.
- `--idioma <es|en>`: Texto en español o inglés.
- `--sondear`: Activa sondeo TLS/SSH de hosts descubiertos.
- `--imagen <docker://...>`: Escanea imagen de contenedor desde registro OCI.
- `--kubernetes`: Escanea clúster Kubernetes en vivo.

**Ejemplos:**

```bash
# Escanear directorio
suaya escanear /etc/ssl

# Escanear imagen de contenedor
suaya escanear --imagen docker://nginx:latest

# Escanear clúster Kubernetes
suaya kubernetes --context minikube

# Escanear con perfil CNSA 2.0
suaya escanear . --perfil cnsa-2.0 --fallar-en 3
```

### `sondear` (`probe`)

Sondea hosts remotos para obtener versiones TLS/SSH, grupos de intercambio y certificados.

```bash
suaya sondear <host>:<puerto> [opciones]
```

**Ejemplos:**

```bash
# Sondear host TLS
suaya sondear ejemplo.com:443

# Sondear con lista de hosts
suaya sondear host1:443 host2:22 host3:993
```

### `kubernetes` (`k8s`)

Inventario de clústeres de Kubernetes en vivo: Secrets, Ingress, Certificates de cert-manager.

```bash
suaya kubernetes [opciones]
```

**Opciones:**
- `--context <nombre>`: Contexto de kubeconfig.
- `--token <token>`: Token de autenticación.
- `--certificado <ruta>`: Certificado de cliente.

**Ejemplos:**

```bash
# Usar contexto por defecto
suaya kubernetes

# Autenticación con token
suaya kubernetes --token <token>

# Autenticación con certificado
suaya kubernetes --certificado client.crt --clave client.key
```

### `reporte` (`report`)

Genera reporte HTML autocontenido con gráficas.

```bash
suaya reporte <archivo.cbom> --formato html --salida reporte.html
```

### `comparar` (`diff`)

Compara dos CBOMs y muestra activos nuevos, eliminados y que empeoraron.

```bash
suaya comparar anterior.cbom actual.cbom
```

### `importar` (`import`)

Importa CBOM CycloneDX de otras herramientas.

```bash
suaya importar <archivo> [opciones]
```

### `perfiles` (`profiles`)

Lista perfiles de política disponibles.

```bash
suaya perfiles
```

### `llaves` (`keygen`)

Genera llaves para firmar CBOMs y verificar firmas.

```bash
# Generar llave de publicación
suaya llaves suaya-publicacion

# Generar llave de usuario
suaya llaves usuario --firma-hibrida
```

### `firmar` (`sign`)

Firma un CBOM con formato `suaya-firma-1` (ML-DSA-65 + Ed25519).

```bash
suaya firmar <archivo.cbom> --llave-privada suaya-privada.json --salida <archivo.firma>
```

### `verificar`

Verifica firma de CBOM o integridad de archivos.

```bash
# Verificar firma de CBOM
suaya verificar <archivo.cbom> --firma <archivo.firma> --llave-publica suaya-publica.json

# Verificar SHA256SUMS
suaya verificar SHA256SUMS --llave-publica suaya-publicacion.publica.json
```

### `conocimiento` (`knowledge`)

Gestiona la base de conocimiento.

```bash
# Listar algoritmos
suaya conocimiento algoritmos

# Listar bibliotecas
suaya conocimiento bibliotecas

# Listar madurez del ecosistema
suaya conocimiento madurez
```

### `completado`

Genera autocompletado para bash, zsh, fish o powershell.

```bash
suaya completado bash > /etc/bash_completion.d/suaya
suaya completado zsh > /fpath/_suaya
```

### `manual`

Muestra la página de manual en formato texto.

```bash
suaya manual
```

## Variables de entorno

| Variable | Descripción |
|---|---|
| `SUAYA_IDIOMA` | Idioma de salida (`es` o `en`). |
| `SUAYA_CLAVE_FIRMA` | Frase de paso para llaves cifradas. |
| `SUAYA_REGISTRO_USUARIO` | Nivel de registro del usuario (`info`, `debug`). |
| `SUAYA_REGISTRO_CLAVE` | Registro de operaciones criptográficas. |
| `SUAYA_FECHA` | Fecha fija para compilación reproducible (`SOURCE_DATE_EPOCH`). |

## Salida y códigos de error

| Código | Significado |
|---|---|
| 0 | Éxito. |
| 1 | Error: argumentos inválidos, archivo ilegible, conexión fallida, llave cifrada sin frase de paso. |
| 2 | Umbral alcanzado (`--fallar-en` o `--fallar-si-empeora`). |
| 3 | Firma inválida (`verificar`). |

## CBOM y propiedades `suaya:`

El CBOM es CycloneDX 1.7 válido. Propiedades `suaya:` conservadas en versiones menores:

- `suaya:riesgo`, `suaya:accion`, `suaya:prioridad`, `suaya:prioridad-etiqueta`
- `suaya:capacidad`, `suaya:madurez-ecosistema`, `suaya:fuente-madurez`
- `suaya:justificacion`, `suaya:advertencia`, `suaya:nota`, `suaya:contexto`
- `suaya:identidad-llave`, `suaya:biblioteca`, `suaya:garantia`, `suaya:retiro`
- `suaya:plazo`, `suaya:cumplimiento`, `suaya:cumplimiento-nota`
- `suaya:perfil`, `suaya:perfil-politica`, `suaya:perfil-referencia`
- `suaya:ruta-escaneada`, `suaya:idioma`, `suaya:base-conocimiento`
- `suaya:version-algoritmos`, `suaya:version-madurez`

## Límites y trazabilidad

- **Límite de escaneo**: Máximo 10,000 archivos por escaneo.
- **Trazabilidad**: Cada hallazgo incluye `bom-ref` determinista y referencia a la base de conocimiento usada.
- **Registros OCI**: Verificación SHA-256 de manifiestos y capas, credenciales Docker y soporte de proxy.
- **Gates adicionales**: `--fallar-en`, `--fallar-si-empeora`, `--sondear`, `--kubernetes`.

## Auditoría 1.4 → 1.5

Cinco hallazgos de auditoría corregidos:

| ID | Hallazgo | Corrección |
|---|---|---|
| SEC-001 | Falta de atestación SLSA | Integración con GitHub Attestations en flujo de publicación. |
| SEC-002 | Compilación no reproducible en macOS/Windows | Verificación en Linux; documentación de limitaciones en macOS/Windows. |
| SEC-003 | Firmas sin verificación de procedencia | Implementación de firma híbrida ML-DSA-65 + Ed25519. |
| SEC-004 | Dependencias no auditadas | Integración con `cargo-deny` en CI. |
| SEC-005 | Falta de política de retiro de bibliotecas | Actualización de `bibliotecas.toml` con fechas de fin de soporte. |

## Publicación y verificación

Cada publicación incluye:

- `SHA256SUMS`: Resumen SHA-256 de cada archivo.
- **Atestación SLSA**: Procedencia firmada con Sigstore desde GitHub Actions.
- `SHA256SUMS.firma`: Firma híbrida opcional.

**Verificar integridad:**

```bash
sha256sum --check --ignore-missing SHA256SUMS
```

**Verificar procedencia:**

```bash
gh attestation verify suaya-1.5.0-x86_64-unknown-linux-gnu.tar.gz --repo Asociacion-Sinaloense-de-Ciberseguridad/SUAYA
```

**Verificar firma híbrida:**

```bash
suaya verificar SHA256SUMS --llave-publica suaya-publicacion.publica.json
```

## Compilación reproducible

```bash
git clone https://github.com/Asociacion-Sinaloense-de-Ciberseguridad/SUAYA && cd SUAYA
git checkout v1.5.0
./scripts/compilacion-reproducible.sh
```

El script compila dos veces desde rutas distintas, con `SOURCE_DATE_EPOCH` y `--remap-path-prefix`, y exige que ambos binarios coincidan byte a byte.

## Paquetes disponibles

| Formato | Origen | Notas |
|---|---|---|
| `.tar.gz` / `.zip` | flujo de publicación | binario, manual, autocompletado, licencia |
| `.deb` | `cargo deb` | Debian 12, Ubuntu 22.04+ |
| `.rpm` | `cargo generate-rpm` | Fedora 38+, RHEL 9+ |
| Homebrew | `empaquetado/homebrew/suaya.rb` | Compila desde fuente |
| Contenedor | `empaquetado/contenedor/Dockerfile` | Imagen distroless sin intérprete |

## Contrato de estabilidad

Suaya sigue el [versionado semántico](https://semver.org/lang/es/) desde 1.0.0. Lo estable cambia solo en versiones mayores (2.0.0):

- Línea de órdenes y opciones documentadas.
- Códigos de salida.
- Formato del CBOM (CycloneDX 1.7).
- Formato de firma (`suaya-firma-1`).
- Esquema de la base de conocimiento.

**No es estable:**
- La clasificación (riesgo, acción, prioridad).
- Los textos (justificaciones, avisos, ayuda).
- Qué se detecta (versiones nuevas detectan más).
- Las bibliotecas de Rust (`suaya-core`, `suaya-escaneo`, `suaya-cbom`, `suaya-red`).
- La salida en pantalla de `escanear` y `sondear`.

## Referencias

- [README.md](../README.md): Visión general y requisitos.
- [cierre-1.5.md](cierre-1.5.md): Matriz de correcciones de auditoría.
- [operacion-1.5.md](operacion-1.5.md): Registros OCI, API, límites.
- [manual-cli.md](manual-cli.md): Referencia CLI completa.
- [arquitectura.md](arquitectura.md): Componentes y flujo.
- [modelo-de-amenazas.md](modelo-de-amenazas.md): Activos y adversarios.
- [publicacion.md](publicacion.md): Publicación y verificación.
- [estabilidad.md](estabilidad.md): Contrato de estabilidad.
- [hoja-de-ruta.md](hoja-de-ruta.md): Hoja de ruta de versiones.
