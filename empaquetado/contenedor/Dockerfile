# Imagen de contenedor de Suaya.
#
#   docker build -f empaquetado/contenedor/Dockerfile -t suaya .
#   docker run --rm --user "$(id -u)" -v /etc:/objetivo/etc:ro -v "$PWD":/salida \
#     suaya escanear /objetivo -o /salida/cbom.json -r /salida/reporte.html
#
# Para una compilación verificable, fije las imágenes base por resumen
# (@sha256:...) en lugar de por etiqueta; las etiquetas se mueven.
FROM docker.io/library/rust:1.99.1-bookworm@sha256:e12566d5abc17a0da741628782cdb504b68b8961f5bfcf677936bf3e8b32de29 AS compilacion
# Snapshot inmutable del índice de paquetes; mantener con revisión de seguridad.
RUN rm -f /etc/apt/sources.list.d/debian.sources && printf '%s\n' \
    'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20261019T000000Z bookworm main' \
    'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/20261019T000000Z bookworm-security main' > /etc/apt/sources.list
RUN apt-get update && apt-get install -y --no-install-recommends cmake clang && rm -rf /var/lib/apt/lists/*
WORKDIR /suaya
COPY . .
ENV CARGO_INCREMENTAL=0 \
    RUSTFLAGS="--remap-path-prefix=/suaya=/suaya --remap-path-prefix=/usr/local/cargo=/cargo"
RUN cargo build --locked --release -p suaya

# Imagen final mínima: sin intérprete de órdenes ni gestor de paquetes, y
# con un usuario sin privilegios.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=compilacion /suaya/target/release/suaya /usr/local/bin/suaya
COPY --from=compilacion /suaya/LICENSE /suaya/NOTICE /usr/share/doc/suaya/
USER nonroot
ENTRYPOINT ["/usr/local/bin/suaya"]
CMD ["--help"]
