# Integraciones

Suaya se integra con la integración continua, el análisis de código y el monitoreo sin servicios externos: todo lo que necesita está en este repositorio.

## GitHub Actions

La acción `action.yml` compila Suaya desde esta copia del repositorio, escanea las rutas indicadas, publica los hallazgos como SARIF en el análisis de código del repositorio y aplica el umbral al final, después de publicar, para que las alertas queden registradas aunque el flujo falle.

```yaml
name: Inventario criptográfico
on: [push, pull_request]
permissions:
  contents: read
  security-events: write   # para publicar el SARIF
jobs:
  suaya:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<commit>
        with:
          persist-credentials: false
      - uses: <organizacion>/suaya@<commit>   # v1.7.0
        with:
          rutas: "infra src"
          perfil: cnsa-2.0
          organizacion: seguridad/suaya-organizacion.toml
          fallar-en: "1"
```

| Entrada | Predeterminado | Uso |
|---|---|---|
| `rutas` | `.` | Archivos o directorios, separados por espacios |
| `perfil` | (ninguno) | Perfil de política: `nist-ir-8547`, `cnsa-2.0`, `ue-hoja-de-ruta`, `ncsc-reino-unido`, `canada-cccs`, `pci-dss-4` o un TOML propio |
| `organizacion` | (ninguno) | Contexto de la organización (sistemas, Mosca y excepciones) |
| `fallar-en` | `1` | Prioridad que hace fallar el paso (1 = crítica ... 4 = baja); vacío para no fallar |
| `cbom`, `reporte`, `sarif` | `suaya-cbom.json`, `suaya-reporte.html`, `suaya.sarif` | Archivos que se generan |
| `publicar-sarif` | `true` | Publica el SARIF en el análisis de código |

Fije la acción por commit, como en el ejemplo. Las entradas llegan al script como variables de entorno y las rutas se pasan después de `--`, para que ningún valor pueda inyectar órdenes ni opciones. Cada regla SARIF corresponde a una receta de corrección (`suaya/tls-hibrido`, `suaya/rsa-corta`...) y trae sus pasos como ayuda; las excepciones vigentes se publican como `suppressions`.

## GitLab CI

`integraciones/gitlab/suaya.gitlab-ci.yml` compila Suaya desde su repositorio y deja el CBOM, el reporte, el SARIF y el CSV como artefactos aunque haya hallazgos. El trabajo falla con el código 2 si hay hallazgos de la prioridad indicada; un resultado parcial (código 4) se permite y queda marcado.

```yaml
include:
  - project: "seguridad/suaya"
    ref: "v1.7.0"
    file: "integraciones/gitlab/suaya.gitlab-ci.yml"

variables:
  SUAYA_REPO: "https://gitlab.ejemplo.mx/seguridad/suaya.git"
  SUAYA_RUTAS: "infra src"
  SUAYA_PERFIL: "cnsa-2.0"
```

## pre-commit

Con el binario `suaya` instalado y en el `PATH`:

```yaml
repos:
  - repo: https://<servidor>/<organizacion>/suaya
    rev: v1.7.0
    hooks:
      - id: suaya             # rechaza criptografía insegura hoy (prioridad crítica)
      # - id: suaya-estricto  # también lo vulnerable a cómputo cuántico migrable hoy
```

El CBOM de cada ejecución se escribe en `.git/suaya-cbom.json`, fuera del árbol de trabajo.

## Prometheus

`suaya diagnosticar --metricas archivo.prom` escribe las métricas en el formato de texto de Prometheus, de forma atómica, como espera el recolector de archivos de node_exporter:

```sh
suaya diagnosticar tls://portal.ejemplo.mx:443 ike://vpn.ejemplo.mx dns://ejemplo.mx \
  --metricas /var/lib/node_exporter/textfile/suaya.prom
```

| Métrica | Etiquetas | Valor |
|---|---|---|
| `suaya_diagnostico_info` | `objetivo`, `protocolo`, `version` | 1 |
| `suaya_diagnostico_alcanzable` | `objetivo` | 1 si respondió |
| `suaya_diagnostico_hallazgos` | `objetivo`, `nivel` | Hallazgos de ese nivel |
| `suaya_diagnostico_poscuantico` | `objetivo` | 1 si ofrece o negocia criptografía híbrida o poscuántica |
| `suaya_diagnostico_saludo_segundos` | `objetivo` | Duración del saludo |
| `suaya_diagnostico_certificado_dias_restantes` | `objetivo` | Días hasta que vence el certificado del servidor |
| `suaya_diagnostico_cadena_valida` | `objetivo` | 1 si la cadena es válida para un cliente estándar |

Para ejecutarlo de forma periódica, sin intérprete de shell y con tiempo límite:

```sh
python3 scripts/automatizar.py --binary /usr/local/bin/suaya \
  --diagnosticar tls://portal.ejemplo.mx:443 --diagnosticar dns://ejemplo.mx \
  --metricas /var/lib/node_exporter/textfile/suaya.prom \
  --output /ruta/privada/resultados --interval 3600
```

Una alerta útil para empezar: `suaya_diagnostico_certificado_dias_restantes < 21` o `suaya_diagnostico_poscuantico == 0` en los servicios expuestos a internet.

## SIEM, hojas de cálculo y gestores de incidencias

Desde cualquier CBOM de Suaya:

```sh
suaya reporte inventario.cbom.json --formato jsonl -o inventario.jsonl     # un activo por línea
suaya reporte inventario.cbom.json --formato csv -o inventario.csv         # hojas de cálculo
suaya reporte inventario.cbom.json --formato tickets -o tickets.json       # un ticket por activo crítico a medio
suaya reporte inventario.cbom.json --formato pci -o inventario-pci.md      # PCI DSS v4.0, 12.3.3 y 4.2.1.1
```

Cada ticket trae título, prioridad, responsables, sistemas, etiquetas y una descripción en Markdown con ubicaciones, observaciones y la receta de corrección, listo para crearse con la API de su gestor.

## API y panel web

`suaya-api` sirve, además de la API, un panel en `/panel`: escaneos por alias con perfil, resumen, descargas en todos los formatos, comparación, tendencias y diagnóstico de los servicios configurados. El panel es una página estática sin dependencias externas que guarda el token solo en la pestaña (`sessionStorage`). La descripción OpenAPI 3.1 está en `/api/v1/openapi.json`.
