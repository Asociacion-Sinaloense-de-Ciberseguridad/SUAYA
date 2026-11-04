#!/usr/bin/env bash
# Verifica que Suaya se compile de forma reproducible: dos compilaciones desde
# copias del repositorio en rutas distintas deben producir el mismo binario.
#
#   ./scripts/compilacion-reproducible.sh [objetivo]
#
# Usa las mismas banderas que el flujo de publicación (.github/workflows/publicacion.yml).
set -euo pipefail

raiz=$(cd "$(dirname "$0")/.." && pwd)
objetivo=${1:-$(rustc -vV | sed -n 's/^host: //p')}
trabajo=$(mktemp -d)
trabajo=$(cd "$trabajo" && pwd -P)
trap 'rm -rf "$trabajo"' EXIT

# Fecha fija de la entrega; se puede indicar SOURCE_DATE_EPOCH.
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1792454400}
export CARGO_INCREMENTAL=0

compilar() {
    local dir=$1
    mkdir -p "$dir"
    (cd "$raiz" && tar --exclude=target --exclude=./build --exclude=./dist --exclude=./bin --exclude=./validacion --exclude=./.git -cf - .) | tar -xf - -C "$dir"
    (
        cd "$dir"
        export CARGO_TARGET_DIR="$dir/target"
        # Las rutas de compilación no deben quedar dentro del binario.
        export RUSTFLAGS="--remap-path-prefix=$dir=/suaya --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"
        if [[ "$objetivo" == *apple-darwin ]]; then
            export RUSTFLAGS="$RUSTFLAGS -C link-arg=-Wl,-no_uuid"
        fi
        export CFLAGS="-ffile-prefix-map=$dir=/suaya -ffile-prefix-map=${CARGO_HOME:-$HOME/.cargo}=/cargo"
        export CXXFLAGS="$CFLAGS"
        cargo build --locked --release --target "$objetivo" -p suaya -p suaya-api >/dev/null 2>&1
    )
    shasum -a 256 "$dir/target/$objetivo/release/suaya" "$dir/target/$objetivo/release/suaya-api" | cut -d' ' -f1
}

a=$(compilar "$trabajo/primera/suaya")
b=$(compilar "$trabajo/una-ruta-distinta/suaya")
echo "primera:  $a"
echo "segunda:  $b"
if [ "$a" = "$b" ]; then
    echo "Compilación reproducible para $objetivo."
else
    echo "Los binarios difieren." >&2
    exit 1
fi
