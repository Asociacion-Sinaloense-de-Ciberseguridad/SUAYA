#!/usr/bin/env bash
# Genera la página de manual y el autocompletado a partir del binario.
#   ./empaquetado/generar.sh [ruta/al/binario]
set -euo pipefail
binario=${1:-target/release/suaya}
destino=$(dirname "$0")/generado
mkdir -p "$destino"
"$binario" manual > "$destino/suaya.1"
"$binario" completado bash > "$destino/suaya.bash"
"$binario" completado zsh > "$destino/_suaya"
"$binario" completado fish > "$destino/suaya.fish"
"$binario" completado powershell > "$destino/suaya.ps1"
echo "Generado en $destino"
