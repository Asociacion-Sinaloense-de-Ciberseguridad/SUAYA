#!/bin/sh
# Instala SUAYA en macOS o Linux desde el paquete de una publicación.
#
# Descargue en una misma carpeta el paquete de su equipo
# (suaya-<versión>-<arquitectura>-<sistema>.tar.gz), el archivo SHA256SUMS y
# este script, y ejecute:
#
#   sh instalar.sh                          # en /usr/local (pide sudo si hace falta)
#   PREFIJO="$HOME/.local" sh instalar.sh   # en su carpeta personal, sin sudo
#   sh instalar.sh --desinstalar            # quita lo instalado
#
# Verifica la suma SHA-256 del paquete y copia suaya, suaya-api, la página de
# manual y el autocompletado de bash, zsh y fish. En Windows use
# instalar-windows.ps1; en Debian, Ubuntu, Fedora o RHEL también puede usar los
# paquetes .deb o .rpm de la publicación.
set -eu

prefijo=${PREFIJO:-/usr/local}
modo=${1:-instalar}
aqui=$(cd "$(dirname "$0")" && pwd)

case "$(uname -s)" in
    Darwin) sistema=apple-darwin ;;
    Linux) sistema=unknown-linux-gnu ;;
    *) echo "Sistema no soportado: $(uname -s). En Windows use instalar-windows.ps1." >&2; exit 1 ;;
esac
case "$(uname -m)" in
    x86_64 | amd64) arquitectura=x86_64 ;;
    arm64 | aarch64) arquitectura=aarch64 ;;
    *) echo "Arquitectura no soportada: $(uname -m)." >&2; exit 1 ;;
esac
objetivo="$arquitectura-$sistema"

# sudo solo si alguna carpeta de destino no se puede escribir. No crea nada:
# revisa la carpeta existente más cercana a cada destino.
necesita_sudo() {
    carpeta=$1
    while [ ! -d "$carpeta" ]; do
        carpeta=$(dirname "$carpeta")
    done
    [ ! -w "$carpeta" ]
}
como=""
for carpeta_destino in bin share/man/man1 share/bash-completion/completions share/zsh/site-functions share/fish/vendor_completions.d; do
    if necesita_sudo "$prefijo/$carpeta_destino"; then
        como=sudo
    fi
done

archivos="bin/suaya bin/suaya-api share/man/man1/suaya.1 share/bash-completion/completions/suaya share/zsh/site-functions/_suaya share/fish/vendor_completions.d/suaya.fish"

if [ "$modo" = "--desinstalar" ]; then
    for archivo in $archivos; do
        $como rm -f "$prefijo/$archivo"
    done
    echo "SUAYA se desinstaló de $prefijo."
    exit 0
fi

paquete=""
encontrados=0
for candidato in "$aqui"/suaya-*-"$objetivo".tar.gz; do
    if [ -e "$candidato" ]; then
        paquete=$candidato
        encontrados=$((encontrados + 1))
    fi
done
if [ "$encontrados" -eq 0 ]; then
    echo "No se encontró suaya-<versión>-$objetivo.tar.gz junto a este script." >&2
    exit 1
fi
if [ "$encontrados" -gt 1 ]; then
    echo "Hay varios paquetes para $objetivo junto a este script: deje solo el que quiere instalar." >&2
    exit 1
fi
nombre=$(basename "$paquete")

if [ -f "$aqui/SHA256SUMS" ]; then
    esperado=$(awk -v n="$nombre" '{ f = $2; sub(/^\*/, "", f); if (f == n) { print $1; exit } }' "$aqui/SHA256SUMS")
    if [ -z "$esperado" ]; then
        echo "SHA256SUMS no incluye $nombre." >&2
        exit 1
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        real=$(sha256sum "$paquete" | awk '{ print $1 }')
    else
        real=$(shasum -a 256 "$paquete" | awk '{ print $1 }')
    fi
    if [ "$esperado" != "$real" ]; then
        echo "La suma SHA-256 de $nombre no coincide con SHA256SUMS: no se instala." >&2
        exit 1
    fi
    echo "Suma SHA-256 verificada: $nombre"
else
    echo "Aviso: no se encontró SHA256SUMS junto al script; la descarga no se verificó." >&2
fi

temporal=$(mktemp -d)
trap 'rm -rf "$temporal"' EXIT INT TERM
tar -xzf "$paquete" -C "$temporal"
origen=$(find "$temporal" -mindepth 1 -maxdepth 1 -type d | head -n 1)
if [ -z "$origen" ] || [ ! -f "$origen/suaya" ]; then
    echo "El paquete no contiene suaya." >&2
    exit 1
fi

$como mkdir -p "$prefijo/bin" "$prefijo/share/man/man1" \
    "$prefijo/share/bash-completion/completions" \
    "$prefijo/share/zsh/site-functions" \
    "$prefijo/share/fish/vendor_completions.d"
$como install -m 0755 "$origen/suaya" "$prefijo/bin/suaya"
$como install -m 0755 "$origen/suaya-api" "$prefijo/bin/suaya-api"
$como install -m 0644 "$origen/suaya.1" "$prefijo/share/man/man1/suaya.1"
$como install -m 0644 "$origen/completado/suaya.bash" "$prefijo/share/bash-completion/completions/suaya"
$como install -m 0644 "$origen/completado/suaya.zsh" "$prefijo/share/zsh/site-functions/_suaya"
$como install -m 0644 "$origen/completado/suaya.fish" "$prefijo/share/fish/vendor_completions.d/suaya.fish"
if [ "$sistema" = apple-darwin ]; then
    # Sin firma de Developer ID: se quita la cuarentena que agrega el navegador.
    $como xattr -d com.apple.quarantine "$prefijo/bin/suaya" "$prefijo/bin/suaya-api" 2>/dev/null || true
fi

"$prefijo/bin/suaya" --version
echo "SUAYA quedó instalado en $prefijo/bin."
case ":$PATH:" in
    *":$prefijo/bin:"*) ;;
    *) echo "Agregue $prefijo/bin a su PATH para usar suaya sin la ruta completa." ;;
esac