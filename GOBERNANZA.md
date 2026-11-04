# Gobernanza

Cómo se toman las decisiones en Suaya, quién las toma y cómo puede cambiar eso conforme crezca la comunidad.

## Situación actual

Suaya es un proyecto personal de José Enrique Rangel Ramírez, quien lo mantiene y tiene la última palabra sobre su rumbo. No está respaldado por ninguna institución, empresa ni gobierno. Cuando el proyecto menciona marcos o estándares (NIST, CNSA 2.0, MITRE, CycloneDX), lo hace para alinearse con ellos, no porque lo avalen.

## Principios

1. **Primero, no dañar.** Ningún cambio puede hacer que Suaya copie material secreto, ejecute lo que lee o envíe datos sin que se le pida. Estas reglas no se negocian por conveniencia ni por rendimiento.
2. **El conocimiento es de todos.** La clasificación vive en datos abiertos (`conocimiento/`) con fuentes citadas. Un cambio de criterio se discute en público y se justifica con una referencia.
3. **En español, para todos.** El español es la lengua de trabajo del proyecto; las contribuciones en inglés también son bienvenidas, y la interfaz se ofrece en ambos idiomas.
4. **Inventariar, no atacar.** Suaya sondea solo los servicios que la persona nombra; no recorre rangos de red ni descubre puertos, y no incorporará esas funciones.
5. **Honestidad sobre los límites.** La documentación dice lo que Suaya no detecta y lo que no se ha probado.

## Papeles

- **Persona responsable del mantenimiento**: revisa y acepta contribuciones, publica versiones, custodia la llave de firma de publicaciones y atiende los reportes de seguridad.
- **Personas que contribuyen**: cualquiera que proponga un cambio, una corrección de la base de conocimiento, una traducción o un reporte. Toda contribución se firma con el *Developer Certificate of Origin* (`git commit -s`), como explica [CONTRIBUTING.md](CONTRIBUTING.md).
- **Personas revisoras de la base de conocimiento** (a futuro): quienes demuestren criterio sostenido en criptografía aplicada podrán aprobar cambios en `conocimiento/`.

## Decisiones

- Los cambios ordinarios se deciden en la revisión del *pull request*.
- Los cambios de criterio de clasificación, de formato del CBOM o del [contrato de estabilidad](docs/estabilidad.md) se proponen primero en un *issue* abierto al menos siete días para comentarios.
- Los reportes de seguridad siguen [SECURITY.md](SECURITY.md) y no se discuten en público hasta que exista corrección.
- Ante un desacuerdo que no se resuelva en la discusión, decide la persona responsable del mantenimiento y deja escrita la razón.

## Evolución

Cuando haya al menos tres personas con contribuciones sostenidas, el proyecto pasará a un grupo de mantenimiento con decisiones por consenso, y se evaluará su traslado a una organización neutral (por ejemplo, una fundación de software libre) para que no dependa de una sola persona. Cualquier acuerdo con una institución se hará público y no podrá contradecir los principios anteriores ni la licencia Apache 2.0.

## Nombre

*Suaya* es una palabra del yoremnokki, la lengua del pueblo yoreme mayo. Su uso como nombre del proyecto está en proceso de validación con hablantes de la lengua; el proyecto acatará lo que la comunidad indique sobre su grafía y su uso.
