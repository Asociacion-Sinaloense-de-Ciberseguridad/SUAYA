# Cómo contribuir a Suaya

Gracias por su interés. Suaya es un proyecto abierto y en español; también recibimos contribuciones en inglés.

## Antes de empezar

- Lea el [código de conducta](CODE_OF_CONDUCT.md).
- Para cambios grandes, abra primero un *issue* para conversar el enfoque.
- Nunca incluya llaves, certificados o configuraciones reales de una organización en un *issue*, *pull request* o prueba. Use el generador de `pruebas/` o datos sintéticos.

## Certificado de origen del desarrollador (DCO)

Suaya usa el [Developer Certificate of Origin](https://developercertificate.org/) en lugar de un acuerdo de licencia de contribuyente. Al firmar cada *commit* usted certifica que tiene derecho a aportar ese código bajo la licencia del proyecto:

```bash
git commit -s -m "escaneo: agrega soporte para HAProxy"
```

La opción `-s` agrega la línea `Signed-off-by: Nombre <correo>`. Los *pull requests* sin firma no se pueden aceptar.

Con DCO, cada persona conserva los derechos de autor de su aporte. Esto permite que el proyecto se traslade en el futuro a una organización neutral o a una fundación sin renegociar con cada contribuyente.

## Entorno de desarrollo

```bash
cargo build
cargo test
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo deny check                     # requiere cargo install cargo-deny
python3 pruebas/sin-rayas.py .
```

El sistema de demostración de `pruebas/fixtures/sistema-demo` se regenera con `pruebas/generar-fixtures.sh` (requiere `openssl` y Python con el paquete `cryptography`).

## Tipos de contribución

### 1. Base de conocimiento (no requiere programar)

Para agregar un algoritmo, un alias o corregir un riesgo, edite `conocimiento/algoritmos.toml`. Cada cambio debe citar su fuente (estándar, RFC o publicación de NIST) en la descripción del *pull request*. Las pruebas validan que no haya identificadores, OIDs ni alias duplicados.

Para actualizar la madurez del ecosistema, edite `conocimiento/madurez.toml` e indique la edición de la fuente en la sección `[meta]`.

### 2. Escáneres

Un escáner implementa el rasgo `Escaner` de `crates/suaya-escaneo`:

```rust
pub trait Escaner: Send + Sync {
    fn nombre(&self) -> &'static str;
    fn aplica(&self, archivo: &Archivo) -> bool;
    fn analizar(&self, archivo: &Archivo, conocimiento: &Conocimiento) -> Result<Vec<Activo>, String>;
}
```

Reglas:

- `aplica` debe ser barato: nombre, extensión o `archivo.contiene(...)`. Si busca una marca nueva, agréguela a `MARCAS` en `comun.rs` para que entre en el autómata de una sola pasada.
- Resuelva algoritmos con la base de conocimiento (`por_oid`, `por_alias`); no escriba listas de algoritmos en el código.
- Nunca guarde material secreto en un `Activo`.
- Un archivo malformado devuelve `Err`, nunca provoca un pánico.
- Agregue un caso al sistema de demostración y una prueba en `crates/suaya-cbom/tests/sistema_demo.rs`.
- Registre el escáner en `escaneres_predeterminados()`.

### 3. Documentación y traducción

La documentación vive en `docs/`. Se aceptan mejoras de redacción, ejemplos y traducciones.

## Estilo

- Identificadores, comentarios y mensajes en español.
- Mensajes al usuario claros y accionables: qué se encontró, por qué importa y qué hacer.
- No use la raya tipográfica (guion largo) en textos; prefiera dos puntos, comas o paréntesis.
- Mensajes de *commit* con el formato `área: descripción en presente` (por ejemplo, `conocimiento: agrega ML-KEM-512`).
- Anote los cambios visibles en la sección «Sin publicar» de [CHANGELOG.md](CHANGELOG.md). Un cambio que afecte lo que promete el [contrato de estabilidad](docs/estabilidad.md) requiere discusión previa en un *issue* ([GOBERNANZA.md](GOBERNANZA.md)).
