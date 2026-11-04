# Manual de Uso de Suaya en macOS

Este manual cubre la instalación, configuración y uso de Suaya en macOS 13 (Ventana) o posterior.

## Requisitos de macOS

- **macOS 13** o posterior.
- **Rust 1.99.1** o posterior (para compilación desde fuente).
- **Xcode Command Line Tools** instalados.
- Binarios precompilados para macOS (arm64 para Apple Silicon, x86_64 para Intel).

## Instalación

### Opción 1: Binario precompilado (Recomendado)

1. Descarga el paquete desde GitHub Releases:

```bash
# Para Apple Silicon (arm64)
curl -LO https://github.com/[OWNER]/suaya/releases/download/v1.5.0/suaya-1.5.0-arm64.tar.gz

# Para Intel (x86_64)
curl -LO https://github.com/[OWNER]/suaya/releases/download/v1.5.0/suaya-1.5.0-x86_64.tar.gz
```

2. Extrae y mueve a `/usr/local/bin`:

```bash
tar xzf suaya-1.5.0-*.tar.gz
sudo mv suaya /usr/local/bin/
chmod +x /usr/local/bin/suaya
```

3. Verifica la instalación:

```bash
suaya --version
```

### Opción 2: Instalación con Homebrew

```bash
# Agrega el tap (si está disponible)
brew tap [OWNER]/suaya

# Instala
brew install suaya

# Verifica
suaya --version
```

### Opción 3: Compilación desde fuente

1. Instala Rust:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
rustc --version  # Debe mostrar 1.99.1 o posterior
```

2. Instala Xcode Command Line Tools:

```bash
xcode-select --install
```

3. Compila Suaya:

```bash
git clone https://github.com/[OWNER]/suaya && cd suaya
cargo build --release
```

4. Instala el binario:

```bash
sudo cp target/release/suaya /usr/local/bin/
```

## Configuración inicial

### Generar llaves de usuario

```bash
# Generar llave para firmar CBOMs personales
suaya llaves usuario --firma-hibrida

# Mueve las llaves a un lugar seguro
mkdir -p ~/.suaya/llaves
mv usuario.privada.json usuario.publica.json ~/.suaya/llaves/
chmod 600 ~/.suaya/llaves/usuario.*.json
```

### Configurar variables de entorno

Agrega a `~/.zshrc` (o `~/.bash_profile` si usas bash):

```bash
# Idioma de salida
export SUAYA_IDIOMA=es

# Ruta a llaves de usuario
export SUAYA_REGISTRO_USUARIO=info

# Frase de paso para llaves cifradas (no guardar en el archivo)
# export SUAYA_CLAVE_FIRMA="tu-frase-de-paso"

# Fecha para compilación reproducible (opcional)
# export SUAYA_FECHA=$(git log -1 --format=%ct)
```

Recarga tu shell:

```bash
source ~/.zshrc
```

## Comandos de uso común

### Escanear directorios y archivos

```bash
# Escanear directorio completo
suaya escanear /etc/ssl

# Escanear archivo específico
suaya escanear /etc/ssl/certs/ca-certificates.crt

# Escanear con perfil CNSA 2.0
suaya escanear ~/proyecto --perfil cnsa-2.0

# Escanear y generar reporte HTML
suaya escanear . --reporte-html --salida reporte.html
```

### Sondear hosts remotos

```bash
# Sondear un host
suaya sondear ejemplo.com:443

# Sondear múltiples hosts
suaya sondear host1:443 host2:22 host3:993

# Sondear con lista desde archivo
cat hosts.txt | xargs -I {} suaya sondear {}
```

### Escanear imágenes de contenedor

```bash
# Escanear imagen desde Docker Hub
suaya escanear --imagen docker://nginx:latest

# Escanear con credenciales
suaya escanear --imagen docker://usuario/imagen:tag \
  --registro-credenciales ~/.docker/config.json

# Escanear desde registro OCI privado
suaya escanear --imagen oci://registry.ejemplo.com/app:v1.0
```

### Trabajar con Kubernetes

```bash
# Escanear clúster con contexto por defecto
suaya kubernetes

# Escanear con contexto específico
suaya kubernetes --context minikube

# Autenticación con token
suaya kubernetes --token <token> --context gke_prod

# Autenticación con certificado
suaya kubernetes --certificado client.crt --clave client.key
```

### Gestionar firmas

```bash
# Firmar un CBOM
suaya firmar resultado.cbom \
  --llave-privida ~/.suaya/llaves/usuario.privada.json \
  --salida resultado.firma

# Verificar firma
suaya verificar resultado.cbom \
  --firma resultado.firma \
  --llave-publica ~/.suaya/llaves/usuario.publica.json

# Verificar SHA256SUMS
suaya verificar SHA256SUMS \
  --llave-publica suaya-publicacion.publica.json
```

### Generar reportes

```bash
# Generar reporte HTML
suaya reporte resultado.cbom --formato html --salida reporte.html

# Abrir reporte en navegador
open reporte.html

# Generar reporte en inglés
suaya reporte resultado.cbom --formato html --salida reporte_en.html --idioma en
```

### Comparar escaneos

```bash
# Comparar dos CBOMs
suaya comparar anterior.cbom actual.cbom

# Comparar con umbral de falla
suaya comparar anterior.cbom actual.cbom --fallar-en 3

# Comparar y generar reporte de diferencias
suaya comparar anterior.cbom actual.cbom --reporte-diff diff.html
```

## Integración con CI/CD en macOS

### GitHub Actions para macOS

```yaml
# .github/workflows/suaya.yml
name: Suaya Escaneo

on: [push, pull_request]

jobs:
  escaneo:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Instalar Rust
        uses: dtolnay/rust-toolchain@stable
      
      - name: Instalar Suaya
        run: cargo install --path .
      
      - name: Escanar proyecto
        run: suaya escanear . --perfil cnsa-2.0 --fallar-en 3
      
      - name: Generar reporte
        run: suaya reporte resultado.cbom --formato html --salida reporte.html
      
      - name: Subir reporte
        uses: actions/upload-artifact@v4
        with:
          name: reporte-suaya
          path: reporte.html
```

### Script de validación local

```bash
#!/bin/bash
# scripts/validar-macos.sh

set -e

echo "Validando proyecto con Suaya en macOS..."

# Escanear
suaya escanear . --perfil cnsa-2.0 --salida resultado.cbom

# Verificar que no haya riesgo 4
if suaya comparar resultado.cbom resultado.cbom --fallar-en 4; then
  echo "✅ Validación exitosa"
  exit 0
else
  echo "❌ Se encontraron riesgos críticos"
  suaya reporte resultado.cbom --formato html --salida reporte.html
  open reporte.html
  exit 1
fi
```

## Seguridad en macOS

### Firmar binario con codesign

```bash
# Si desarrollas Suaya desde fuente
codesign --sign "Developer ID Application" \
  --entitlements scripts/entitlements.plist \
  target/release/suaya
```

### Restringir acceso a llaves

```bash
# Las llaves deben tener permisos 600
chmod 600 ~/.suaya/llaves/*.json

# Opcional: cifrar llaves adicionales con Keychain
security add-generic-password -s suaya-llave \
  -w -D "Suaya llave privada"
```

### Usar Keychain para frases de paso

```bash
# Guardar frase de paso en Keychain
security add-generic-password -s suaya-clave \
  -w -D "Frase de paso Suaya"

# Recuperar frase de paso en script
export SUAYA_CLAVE_FIRMA=$(security find-generic-password -s suaya-clave -w)
```

## Solución de problemas

### Error: "command not found: suaya"

```bash
# Verifica que esté en PATH
echo $PATH

# Si no está en /usr/local/bin, muévelo
sudo mv suaya /usr/local/bin/
```

### Error: "cannot open file"

```bash
# Verifica permisos de lectura
ls -la /ruta/al/archivo

# Si es un certificado, verifica que no esté corrupto
openssl x509 -in /ruta/al/archivo -text -noout
```

### Error: "connection refused" al sondear

```bash
# Verifica que el host sea accesible
telnet ejemplo.com 443

# Verifica firewall
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getlogstate
```

### Error: "compilation failed" al compilar desde fuente

```bash
# Instala Xcode Command Line Tools
xcode-select --install

# Actualiza Rust
rustup update stable

# Limpia y vuelve a compilar
cargo clean && cargo build --release
```

## Actualizaciones

### Actualizar desde binario precompilado

```bash
# Descarga la nueva versión
curl -LO https://github.com/[OWNER]/suaya/releases/download/v1.5.1/suaya-1.5.1-arm64.tar.gz

# Extrae y reemplaza
tar xzf suaya-1.5.1-arm64.tar.gz
sudo mv suaya /usr/local/bin/
```

### Actualizar desde Homebrew

```bash
brew update && brew upgrade suaya
```

## Recursos adicionales

- [Manual CLI](manual-1.5.md): Referencia completa de comandos.
- [Publicación y verificación](publicacion.md): Cómo verificar descargas.
- [Contrato de estabilidad](estabilidad.md): Qué cambia entre versiones.
- [Hoja de ruta](hoja-de-ruta.md): Próximas características.

## Soporte

- Issues: https://github.com/[OWNER]/suaya/issues
- Documentación: https://github.com/[OWNER]/suaya/tree/main/docs
- Comunidad: [enlace a Discord/Slack si aplica]
