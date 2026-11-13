# Política de seguridad

## Reportar una vulnerabilidad

No abra un *issue* público. Use el reporte privado de vulnerabilidades de GitHub (pestaña **Security**, opción **Report a vulnerability**) o escriba a contacto@ciberseguridadsinaloa.org .

Incluya, si es posible: versión de Suaya, sistema operativo, pasos para reproducir y el impacto que observa. No incluya llaves ni datos reales de una organización.

Nos comprometemos a confirmar la recepción en un máximo de 5 días hábiles y a coordinar con usted la publicación de la corrección.

## Qué consideramos vulnerabilidad

- Que Suaya copie material secreto (llaves privadas, contraseñas) al CBOM, al reporte o a la salida en pantalla.
- Que un archivo manipulado provoque ejecución de código, lectura fuera de las rutas indicadas o un bloqueo del escaneo.
- Que la clasificación marque como conforme un activo que está roto (falso negativo grave).

## Prácticas del proyecto

- `unsafe` está prohibido en todo el código.
- Las dependencias se revisan antes de incorporarse y se mantienen al mínimo.
- La integración continua fija las acciones de GitHub por su *commit*.
- `cargo-deny` revisa en cada cambio los avisos de RustSec, las licencias y el origen de las dependencias.
- Las compilaciones son reproducibles y, cuando el repositorio es público, cada publicación lleva procedencia SLSA firmada con Sigstore; siempre incluye SHA256SUMS y, opcionalmente, la firma híbrida de Suaya (ML-DSA-65 y Ed25519). Ver [docs/publicacion.md](docs/publicacion.md).
- El [modelo de amenazas](docs/modelo-de-amenazas.md) describe qué se protege y de quién; [docs/auditoria.md](docs/auditoria.md), el alcance propuesto para una auditoría externa, que todavía no se ha realizado.

## Versiones con soporte

Se corrigen las vulnerabilidades en la versión menor más reciente de la serie 1.x. Las versiones 0.x no reciben correcciones.
