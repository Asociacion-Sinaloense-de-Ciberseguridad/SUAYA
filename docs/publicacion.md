# Publicación y verificación

Cómo se publica una versión de Suaya y cómo comprobar que el binario que descargó es el que se compiló desde este código.

## Verificar una descarga

Cada publicación incluye, junto a los paquetes:

- `SHA256SUMS`: el resumen SHA-256 de cada archivo.
- Una **atestación de procedencia SLSA** por paquete, firmada con Sigstore desde el flujo de GitHub Actions que lo compiló. Dice qué repositorio, qué *commit* y qué flujo produjeron el archivo.
- Opcionalmente, `SHA256SUMS.firma`: la firma híbrida de Suaya (ML-DSA-65 y Ed25519) sobre `SHA256SUMS`.

### 1. Integridad

```bash
sha256sum --check --ignore-missing SHA256SUMS
```

### 2. Procedencia

Con la CLI de GitHub:

```bash
gh attestation verify suaya-1.0.0-x86_64-unknown-linux-gnu.tar.gz --repo Asociacion-Sinaloense-de-Ciberseguridad/SUAYA
```

La verificación falla si el archivo no se compiló en el flujo de publicación de ese repositorio.

### 3. Firma híbrida (si se publicó)

Con una copia de Suaya en la que ya confíe y la llave pública del proyecto, publicada en el repositorio y en la página de la versión:

```bash
suaya verificar SHA256SUMS --llave-publica suaya-publicacion.publica.json
```

Compare la huella que imprime con la que el proyecto publica por un canal distinto.

## Compilación reproducible

Cualquiera puede recompilar una versión y obtener el mismo binario:

```bash
git clone https://github.com/Asociacion-Sinaloense-de-Ciberseguridad/SUAYA && cd SUAYA
git checkout v1.0.0
./scripts/compilacion-reproducible.sh
```

El script compila dos veces desde copias del repositorio en rutas distintas, con la fecha fija del último *commit* (`SOURCE_DATE_EPOCH`) y las rutas de compilación reescritas (`--remap-path-prefix` para Rust y `-ffile-prefix-map` para el código C de AWS-LC), y exige que ambos binarios coincidan byte a byte. La integración continua lo ejecuta en cada cambio.

Para comparar contra el binario publicado, use la misma versión de Rust que el flujo de publicación (la estable del día, registrada en la atestación) y el mismo objetivo. Diferencias conocidas:

- El binario depende de la versión exacta de `rustc` y del compilador de C del sistema. Con versiones distintas el resultado es funcionalmente igual pero no idéntico.
- En macOS y Windows la reproducibilidad no se verifica todavía en la integración continua; en Linux sí.

## Publicar una versión

Solo quien mantiene el proyecto.

1. Actualice la versión en `Cargo.toml` (`[workspace.package]` y las dependencias internas) y en el README.
2. Mueva las notas de la sección en curso de [CHANGELOG.md](../CHANGELOG.md) a una sección `## [X.Y.Z] - AAAA-MM-DD`. El flujo de publicación toma de ahí las notas.
3. Verifique localmente: `cargo fmt --all --check`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked`, `cargo deny check` y `python3 pruebas/sin-rayas.py .`.
4. Cree una etiqueta firmada y empújela:

   ```bash
   git tag -s v1.0.0 -m "Suaya 1.0.0"
   git push origin v1.0.0
   ```

5. El flujo `.github/workflows/publicacion.yml` compila para Linux (x86_64 y aarch64), macOS (arm64) y Windows (x86_64), genera la página de manual, el autocompletado y los paquetes `.deb` y `.rpm`, atestigua cada archivo, calcula `SHA256SUMS`, lo firma si existe el secreto `SUAYA_LLAVE_FIRMA` y crea la publicación como **borrador**.
6. Revise el borrador (archivos, notas, atestaciones) y publíquelo a mano.
7. Actualice la fórmula de Homebrew (`empaquetado/homebrew/suaya.rb`) con el resumen del archivo fuente de la etiqueta.

### Llave de firma de publicaciones

```bash
SUAYA_CLAVE_FIRMA='frase de paso larga' suaya llaves suaya-publicacion
```

- `suaya-publicacion.publica.json` se versiona en el repositorio y se publica su huella en la página del proyecto.
- El contenido de `suaya-publicacion.privada.json` (cifrada) se guarda como secreto `SUAYA_LLAVE_FIRMA` del entorno de publicación, y la frase de paso como `SUAYA_CLAVE_FIRMA`. Conviene restringir ese entorno a la rama principal y a etiquetas, con aprobación manual.
- Una copia de respaldo de la llave privada se guarda fuera de línea.

## Empaquetado

| Formato | Origen | Notas |
|---|---|---|
| `.tar.gz` / `.zip` | flujo de publicación | binario, página de manual, autocompletado, licencia; en Linux requiere glibc 2.35 o posterior (Debian 12, Ubuntu 22.04) |
| `.deb` | `cargo deb` | metadatos en `crates/suaya-cli/Cargo.toml` |
| `.rpm` | `cargo generate-rpm` | metadatos en `crates/suaya-cli/Cargo.toml` |
| Homebrew | `empaquetado/homebrew/suaya.rb` | plantilla para un *tap* propio; compila desde la fuente |
| Contenedor | `empaquetado/contenedor/Dockerfile` | imagen *distroless* sin intérprete de órdenes y sin privilegios |

La página de manual y el autocompletado se generan del propio binario (`suaya manual`, `suaya completado bash|zsh|fish|powershell`) con `empaquetado/generar.sh`, así que nunca se desfasan de la ayuda.
