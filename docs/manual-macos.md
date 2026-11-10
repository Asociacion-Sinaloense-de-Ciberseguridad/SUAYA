# Suaya en macOS · versión 1.7

Esta guía cubre la aplicación de escritorio y el uso de la línea de órdenes en macOS. El uso general de Suaya está en el [manual de uso](../Manual_SUAYA%20v1.7.md) y la referencia de cada escáner en el [manual de la CLI](manual-cli.md).

## Requisitos

- macOS 13 o posterior. La entrega incluye binarios para Apple Silicon (arm64); en un Mac con Intel, compile desde la fuente.
- Para compilar: Rust 1.89 o posterior (validado con 1.99.1) y las herramientas de línea de órdenes de Xcode (`xcode-select --install`).

## Instalación

### Aplicación

1. Abra `build/SUAYA-1.7.0-macos-arm64.dmg`.
2. Arrastre **SUAYA.app** a **Aplicaciones**.
3. La app tiene firma local ad hoc, sin notarización: la primera vez, haga clic derecho sobre ella y elija **Abrir**.

Para comprobar la integridad, compare el hash del DMG con `validacion/dmg.sha256` o con `SHA256SUMS`:

```sh
shasum -a 256 build/SUAYA-1.7.0-macos-arm64.dmg
```

La aplicación incluye su propio motor (`SUAYA.app/Contents/MacOS/suaya-engine`); no necesita la CLI instalada.

### Línea de órdenes

```sh
sudo cp bin/suaya bin/suaya-api /usr/local/bin/
suaya --version     # suaya 1.7.0
```

### Desde la fuente

```sh
cargo build --release --locked -p suaya -p suaya-api
SUAYA_BUILD_DIR=/private/tmp/suaya-build SUAYA_DMG=1 bash empaquetado/build-macos.sh
```

El script compila el motor y la app, los firma ad hoc, verifica la firma y crea el DMG; ante cualquier error se detiene sin generar un paquete incompleto.

**Si el proyecto está en iCloud Drive**, compile fuera de la carpeta sincronizada:

- `SUAYA_BUILD_DIR` fuera de iCloud, porque iCloud agrega atributos extendidos que hacen fallar `codesign` («resource fork, Finder information, or similar detritus»).
- `CARGO_TARGET_DIR=/private/tmp/suaya-target`, para no sincronizar gigabytes de compilación.

Copie los resultados con `ditto --norsrc --noextattr`. Por la misma razón, una copia de `SUAYA.app` dentro de iCloud puede no pasar `codesign --verify` aunque la del DMG sea válida.

## La aplicación

### Inventario

1. **Elegir archivo o carpeta**: el objetivo del escaneo. **Quitar** lo deja vacío si solo quiere el llavero.
2. **Perfil**: NIST IR 8547, CNSA 2.0, Unión Europea, Reino Unido (NCSC), Canadá (CCCS) o PCI DSS v4.0.1, para evaluar el cumplimiento. Sin perfil, solo se clasifica.
3. **Organización (TOML)…**: el archivo de contexto con sistemas, responsables, desigualdad de Mosca y excepciones (ejemplo en [ejemplos/suaya-organizacion.toml](ejemplos/suaya-organizacion.toml)).
4. **Incluir el llavero de macOS**: agrega los certificados de las raíces del sistema y de los llaveros del sistema y del usuario. Suaya nunca lee llaves privadas ni pide la contraseña del llavero.
5. **Escanear**. El resumen muestra los activos y los críticos; la lista, cada activo.
6. **Exportar CBOM**, **HTML**, **CSV** o **SARIF**. Los archivos se escriben de forma atómica con permisos 0600 y sin heredar las ACL de la carpeta de destino.

**Cancelar** detiene el escaneo y **Limpiar** borra el inventario de la sesión; ninguno de los dos permite que un escaneo anterior vuelva a llenar la pantalla. Si el resultado es parcial (archivos omitidos o avisos), la app lo indica: revise con la CLI antes de concluir que no hay riesgo.

### Diagnóstico de red

1. Escriba uno o más servicios separados por espacios o comas (hasta 20): `www.ejemplo.mx`, `smtp://correo.ejemplo.mx`, `ssh://bastion:22`, `ike://vpn.ejemplo.mx`, `dns://ejemplo.mx`, `oidc://login.ejemplo.mx`, `saml://idp.ejemplo.mx/ruta/metadata.xml`.
2. Opcional: **Autoridad propia (PEM)…** para validar certificados de una PKI interna.
3. **Diagnosticar**. Cada servicio muestra un indicador de su hallazgo más grave y, al desplegarlo:
   - conectividad por dirección;
   - intercambio de llaves TLS, SSH o IKEv2;
   - certificados;
   - DNS (DNSSEC, CAA, TLSA, DKIM) o identidad (algoritmos, JWKS, certificados SAML);
   - hallazgos por nivel;
   - **Cómo corregir**, con los pasos de cada receta.
4. **Exportar JSON** con el diagnóstico completo.

Los servicios se entregan al motor después de `--`, de modo que nada de lo escrito puede interpretarse como una opción. Diagnostique solo sistemas que administre o que tenga autorización expresa para evaluar.

## La línea de órdenes en macOS

Todo lo descrito en el [manual de uso](../Manual_SUAYA%20v1.7.md) funciona igual. Algunos usos propios de macOS:

```sh
# Certificados del llavero, con reporte HTML
suaya escanear --llavero -r llavero.html && open llavero.html

# Aplicaciones y binarios instalados (firmas de código y bibliotecas)
suaya escanear /Applications/MiApp.app --binarios -r app.html

# Reporte en inglés o portugués
suaya --idioma en reporte inventario.json -o report.html
suaya --idioma pt reporte inventario.json -o relatorio.html
```

### Frases de paso en el llavero

Guarde la frase de paso de la llave de firma en el llavero y pásela por la variable que Suaya lee:

```sh
security add-generic-password -s suaya-firma -a "$USER" -w     # la pide sin mostrarla
export SUAYA_CLAVE_FIRMA="$(security find-generic-password -s suaya-firma -a "$USER" -w)"
suaya firmar inventario.json --llave equipo.privada.json
```

Lo mismo sirve para `SUAYA_CLAVE_ALMACEN` (contenedores PKCS#12). Guarde las llaves `.privada.json` con permisos 600.

### Diagnóstico periódico con launchd

`scripts/automatizar.py` ejecuta escaneos o diagnósticos con tiempo límite y sin intérprete de shell; `--once` lo hace apto para launchd:

```sh
python3 scripts/automatizar.py --binary /usr/local/bin/suaya \
  --diagnosticar tls://portal.ejemplo.mx:443 --diagnosticar dns://ejemplo.mx \
  --metricas "$HOME/Library/Application Support/suaya/suaya.prom" \
  --output "$HOME/Library/Application Support/suaya/resultados" --once
```

El directorio de resultados debe ser privado (0700). Programe la ejecución con un `LaunchAgent` (`StartInterval`) que llame a esa orden.

### API local y panel

```sh
python3 scripts/configurar-api.py --directory "$HOME/Library/Application Support/suaya/api" \
  --target proyecto="$HOME/Proyectos/mi-app" --user admin:admin
suaya-api --config "$HOME/Library/Application Support/suaya/api/config.json" \
  --database "$HOME/Library/Application Support/suaya/api/scans.db"
open http://127.0.0.1:8787/panel
```

El token está en `tokens.json` (0600) dentro de ese directorio; péguelo en el panel. La API solo escucha en loopback.

## Solución de problemas

| Síntoma | Solución |
|---|---|
| macOS dice que la app «no se puede abrir» | Clic derecho > **Abrir** la primera vez (firma ad hoc sin notarización) |
| «El paquete no contiene el motor SUAYA» | La app está incompleta: reinstálela desde el DMG |
| El escaneo de la app falla con un código | Repita con la CLI y `-d` para ver el motivo (permisos, archivo de organización inválido...) |
| `command not found: suaya` | Copie `bin/suaya` a `/usr/local/bin` o agregue la carpeta al `PATH` |
| `codesign` falla al construir | Construya fuera de iCloud con `SUAYA_BUILD_DIR` |
| El diagnóstico de `dns://` no muestra firmas | El resolvedor del módem no valida DNSSEC: `SUAYA_DNS=1.1.1.1 suaya diagnosticar dns://...` |
| Fallan solo las direcciones IPv6 | Puede ser la red del Mac (por ejemplo, un módem sin IPv6); se informa con nivel bajo |
| Faltan certificados del llavero | Solo se leen los llaveros de la lista de búsqueda del usuario y las raíces del sistema |
| La carpeta del proyecto ocupa muchos gigabytes | Es `target/`, la caché de compilación: se puede borrar y se regenera |

## Distribución

La firma ad hoc sirve para uso local. Para distribuir la app a otras personas hace falta firmarla con un certificado Developer ID y notarizarla con la cuenta del propietario; vea [publicación](publicacion.md).

## Más información

- [Manual de uso 1.7](../Manual_SUAYA%20v1.7.md) y [manual de la CLI](manual-cli.md)
- [Integraciones](integraciones.md): GitHub, GitLab, pre-commit y Prometheus
- [Contrato de estabilidad](estabilidad.md), [hoja de ruta](hoja-de-ruta.md) y [cierre 1.7](cierre-1.7.md)
