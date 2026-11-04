# Contrato de estabilidad

Suaya sigue el [versionado semántico](https://semver.org/lang/es/) desde la versión 1.0.0. Este documento dice qué cubre esa promesa, para que se pueda automatizar sobre Suaya (integración continua, tableros, otras herramientas) sin temor a que una actualización menor lo rompa.

## Qué es estable

Lo siguiente solo cambia de forma incompatible en una versión mayor (2.0.0):

### Línea de órdenes

- Los nombres de las órdenes y sus alias en inglés: `escanear` (`scan`), `sondear` (`probe`), `kubernetes` (`k8s`), `reporte` (`report`), `comparar` (`diff`), `importar` (`import`), `perfiles` (`profiles`), `llaves` (`keygen`), `firmar` (`sign`), `verificar` (`verify`), `conocimiento` (`knowledge`), y las órdenes auxiliares `completado` y `manual`.
- Los nombres y el significado de las opciones documentadas en `suaya <orden> --ayuda`. Se pueden agregar opciones nuevas; una opción existente no se elimina ni cambia de significado.
- Las variables de entorno `SUAYA_IDIOMA`, `SUAYA_CLAVE_FIRMA`, `SUAYA_REGISTRO_USUARIO`, `SUAYA_REGISTRO_CLAVE` y `SUAYA_FECHA`.

### Códigos de salida

| Código | Significado |
|---|---|
| 0 | Éxito. |
| 1 | Error: argumentos inválidos, archivo ilegible, conexión fallida, llave cifrada sin frase de paso. |
| 2 | Se alcanzó el umbral pedido con `--fallar-en` o `--fallar-si-empeora`. |
| 3 | `verificar`: la firma no es válida. |

### Formato del CBOM

- El CBOM es CycloneDX 1.7 válido contra el esquema oficial. Una versión menor puede adoptar una versión menor posterior de CycloneDX solo si sigue siendo legible por quien lee 1.7.
- Las propiedades `suaya:` existentes conservan su nombre y el tipo de su valor: `suaya:riesgo`, `suaya:accion`, `suaya:prioridad`, `suaya:prioridad-etiqueta`, `suaya:capacidad`, `suaya:madurez-ecosistema`, `suaya:fuente-madurez`, `suaya:justificacion`, `suaya:advertencia`, `suaya:nota`, `suaya:contexto`, `suaya:identidad-llave`, `suaya:biblioteca`, `suaya:garantia`, `suaya:retiro`, `suaya:plazo`, `suaya:cumplimiento`, `suaya:cumplimiento-nota`, `suaya:perfil`, `suaya:perfil-politica`, `suaya:perfil-referencia`, `suaya:ruta-escaneada`, `suaya:idioma`, `suaya:base-conocimiento`, `suaya:version-algoritmos` y `suaya:version-madurez`. Se pueden agregar propiedades nuevas.
- Los valores con vocabulario cerrado (riesgo, acción, prioridad del 1 al 4, estado de cumplimiento) solo crecen: no se renombra ni se elimina un valor existente.
- Las referencias `bom-ref` son deterministas: el mismo activo en el mismo lugar conserva su referencia entre versiones menores, para que `comparar` funcione entre un escaneo hecho con 1.0 y otro hecho con 1.x.
- Suaya 1.x lee cualquier CBOM producido por Suaya 1.0 o posterior.

### Firma

- El formato `suaya-firma-1` (archivo `.firma`) y el de las llaves (`.privada.json`, `.publica.json`). Una firma hecha con 1.0 se verifica con cualquier 1.x. Si un algoritmo dejara de considerarse seguro, se agregaría un formato nuevo y el anterior seguiría verificándose con una advertencia.

### Base de conocimiento

- El esquema de los archivos de `conocimiento/` (`algoritmos.toml`, `madurez.toml`, `codigo.toml`, `bibliotecas.toml`, los perfiles y el catálogo de traducción). Una base propia escrita para 1.0 se puede pasar con `--base-conocimiento` a cualquier 1.x; los campos nuevos serán opcionales.

## Qué no es estable

- **La clasificación.** El riesgo, la acción o la prioridad de un activo pueden cambiar en una versión menor o de parche cuando cambia el conocimiento: un algoritmo se debilita, sale un estándar, la madurez del ecosistema avanza, una biblioteca llega a su fin de soporte. Ese es el propósito de la herramienta. Cada CBOM registra la versión de cada base (`suaya:version-algoritmos`, `suaya:version-madurez`) para saber con qué criterio se clasificó.
- **Los textos.** Las justificaciones, los avisos, la ayuda y los reportes en Markdown y HTML pueden cambiar de redacción en cualquier versión. No los analice con expresiones regulares: lea las propiedades del CBOM.
- **Qué se detecta.** Las versiones nuevas detectan más cosas; un CBOM puede crecer al actualizar Suaya sin que el sistema haya cambiado. `comparar` distingue los activos nuevos de los que empeoraron.
- **Las bibliotecas de Rust** (`suaya-core`, `suaya-escaneo`, `suaya-cbom`, `suaya-red`). Su API pública es interna del proyecto y puede cambiar en versiones menores hasta que se publique en crates.io con su propio compromiso.
- **La salida en pantalla** de `escanear` y `sondear`, pensada para personas.

## Obsolescencia

Antes de retirar algo estable en una versión mayor, se marca como obsoleto en al menos una versión menor previa: sigue funcionando, muestra un aviso y el [registro de cambios](../CHANGELOG.md) lo anuncia con la alternativa.

## Versión mínima de Rust

Compilar Suaya requiere Rust 1.89 o posterior. Subir esa versión no se considera un cambio incompatible, pero solo se hace en una versión menor y se anuncia en el registro de cambios.
