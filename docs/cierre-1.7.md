# Cierre SUAYA 1.7.0

Fecha: 6 de noviembre de 2026, America/Mazatlan (las marcas UTC de los CBOM de validación dicen 7 de noviembre). Entrega local macOS Apple Silicon basada en v1.6, que se conserva intacta. Este cierre acredita cambios y pruebas locales; no es una certificación ni una auditoría independiente.

## Alcance

| Área | Cambio | Validación |
|---|---|---|
| Base de conocimiento | Algoritmos nuevos (LMS/XMSS, FN-DSA, HQC, FrodoKEM, McEliece, X-Wing, ML-KEM compuestos, brainpool, SM2/3/4, GOST, Camellia, ARIA, SEED, KW, CCM, GCM-SIV, CMAC, HKDF, Argon2, bcrypt, yescrypt, crypt, SHAKE, MD4, ElGamal, Kerberos, P-224); alias de DNSSEC (incluido ML-DSA-44, algoritmo 18), JOSE (RFC 9964) y XML Signature; perfiles UE, NCSC, CCCS y PCI DSS 4; capacidades de infraestructura DNS e identidad federada; recetas de corrección (`remediacion.toml`) | Validación de la base al cargar (alias, OID, capacidades, recetas contra algoritmos y capacidades existentes); identificadores verificados en IANA (DNSSEC actualizado el 10 de agosto de 2026, DS), RFC 9964 y el calendario SC-081v3 del CA/Browser Forum |
| Escaneo de archivos | Servicios como datos (20 productos), OpenSSL, crypto-policies, GnuTLS, Kerberos, políticas de navegador, registro de Windows, nube e IaC, OpenPGP, JKS/JCEKS/PKCS#12 (con `SUAYA_CLAVE_ALMACEN`), Secure Boot, kernel, LUKS, AD (LDIF), ejecutables PE/ELF/Mach-O, JAR/APK/DEX, certificados SSH y `--llavero` | Pruebas unitarias por escáner; binarios firmados por Apple; llavero real de este Mac (172 activos, incluido un intermedio antiguo firmado con SHA-1) |
| Red y diagnóstico | Suites de TLS 1.2, cadenas por familia de firma, llaves de host SSH, IKEv2 con ML-KEM (RFC 9370), STARTTLS de FTP, XMPP y RDP, `dns://`, `oidc://`, `saml://`, vigencia del CA/Browser Forum, recetas en el diagnóstico, `--metricas` | Servidores simulados en loopback (IKE, DNS con DNSSEC, preámbulos STARTTLS) y evaluación de DNS e identidad sin red; contra servicios públicos: Cloudflare (20 suites TLS 1.2, cadenas RSA y ECDSA), `rc4.badssl.com`, `expired.badssl.com`, llaves de host de GitHub, DNSSEC de cloudflare.com e ietf.org (resolvedor del módem sin DNSSEC y 1.1.1.1 con bit AD y RRSIG), TLSA de `_25._tcp.mail.ietf.org`, DKIM de Cloudflare, OIDC de Google y Microsoft y metadatos SAML de Microsoft |
| Contexto y salidas | `--organizacion` (sistemas, Mosca y excepciones; excluidas de `--fallar-en`), propiedades `suaya:` nuevas, sección del reporte; `--sarif`, `--csv`, `reporte --formato pci|sarif|csv|jsonl|tickets`, `suaya tendencias` | Prueba de extremo a extremo de la CLI; SARIF de la demostración válido contra el esquema 2.1.0 (145 resultados); CBOM válido contra CycloneDX 1.7 |
| Integraciones | `action.yml` (SARIF publicado antes de aplicar el umbral, entradas por entorno, `upload-sarif` v4.39.3 fijado por commit), plantilla de GitLab, ganchos de pre-commit, `automatizar.py --diagnosticar --metricas` | YAML válido; `automatizar.py --diagnosticar --metricas` ejecutado una vez contra un puerto local cerrado (hallazgo crítico y métricas escritas); la acción y la plantilla no se ejecutaron en GitHub ni GitLab |
| API y panel | Perfiles incluidos (nunca rutas), contexto del operador, reportes en todos los formatos, resumen, comparación, tendencias, OpenAPI 3.1 y panel en `/panel` con CSP propia | 3 pruebas nuevas (16 en total) y panel recorrido en el navegador integrado contra la API local: escaneo con CNSA 2.0 y contexto, diagnóstico con recetas, comparación y tendencias, sin violaciones de CSP |
| macOS | Perfil, archivo de organización, llavero, exportación CSV y SARIF; diagnóstico con IKE, DNS, identidad y recetas | Compilación sin errores, regresión de exportación 0600 sin ACL heredada, app y DMG firmados |
| Idiomas | Portugués (`--idioma pt`) para el reporte, las etiquetas, las justificaciones y el resumen; catálogo en inglés para todos los textos nuevos (unas 500 entradas) | Prueba de la ayuda traducida, del catálogo y de respaldo al español; reporte real en portugués |
| Correcciones | Protocolos fuera del vocabulario de CycloneDX como `other` con `suaya:tipo-protocolo`; aviso de cobertura parcial traducido | CBOM válido contra el esquema |

## Resultados locales

- 196 pruebas Rust aprobadas, sin fallos (`validacion/tests.log`): 136 heredadas de 1.6 y 60 nuevas.
- Clippy con `-D warnings` y formato sin observaciones (`clippy.log`, `fmt.log`).
- Python: 2 pruebas de empaquetado, 4 regresiones de seguridad y 4 de imágenes aprobadas; regresión real de exportación de la GUI aprobada.
- CBOM de demostración: 0 errores contra CycloneDX 1.7; SARIF: 0 errores contra SARIF 2.1.0 (`schema.log`).
- cargo-deny: advisories, bans, licenses y sources aprobados. Semgrep: 7 reglas, 81 archivos, 0 hallazgos. Gitleaks: 0 hallazgos; se documentó en `.gitleaksignore` el mismo falso positivo de 1.6 (SHA-256 de `scripts/configurar-api.py` en el manifiesto archivado, ahora en `heredado-1.6`).
- Cobertura de líneas de fuentes propios: **81.38 %** (25369 líneas, 4723 no cubiertas; `coverage-source.json`). Es menor que en 1.6 (84.20 %) porque parte del código nuevo solo se ejercita con red o con archivos del sistema (lectura HTTPS de OIDC y SAML, llavero, ejecutables). No es cobertura de ramas.
- *Fuzzing* sancov de tres objetivos, 30 s cada uno, sin fallos, tiempos agotados ni exceso de memoria: `escaneres` 229461 ejecuciones (incluye los nombres de archivo de los escáneres nuevos), `importar_cbom` 414037 y `protocolos` 237253 (incluye IKE, DNS, DKIM, SAML y JWKS). El equipo se suspendió durante la primera corrida de `protocolos`, que se repitió despierto; `fuzz.log` registra ambas. Corpus completo en `fuzz-corpus.zip`; en `fuzz/corpus` quedan las semillas legibles.
- Compilación reproducible de CLI y API en dos rutas distintas con hashes idénticos (`reproducibilidad.log`).
- App y DMG arm64 con firma ad-hoc verificada; `hdiutil verify` válido (`package.log`, `dmg.sha256`). La firma también se verificó en la app montada desde el DMG.
- Las evidencias de 1.6 están en `validacion/heredado-1.6/` y no describen esta entrega.

## Límites

- La validación de cadenas no consulta revocación (OCSP/CRL); solo informa si el servidor engrapa OCSP.
- El portugués cubre el reporte, las etiquetas, las justificaciones y el resumen de la línea de órdenes; la ayuda, las recetas y los mensajes detallados de los hallazgos se muestran en español.
- Las recetas citan versiones y directivas vigentes al cierre; se deben contrastar con la documentación de cada producto. El calendario de vigencia del CA/Browser Forum está en el código del diagnóstico, no en la base de conocimiento.
- `dns://` usa el resolvedor del sistema: si no valida DNSSEC (como el del módem de esta validación) no hay firmas que revisar y se indica usar `SUAYA_DNS`. `oidc://` solo sigue `jwks_uri` dentro del dominio registrable aproximado del objetivo.
- La acción de GitHub, la plantilla de GitLab y los ganchos de pre-commit se validaron como YAML, no en sus plataformas. La GUI no se recorrió de forma interactiva automatizada; se verificaron compilación, decodificación y escritura.
- Dentro de la carpeta sincronizada con iCloud, macOS agrega atributos extendidos a `build/SUAYA.app` que hacen fallar `codesign --verify`; la copia sin atributos y la app del DMG verifican correctamente.
- Pendientes para después de 1.7: consulta de revocación, Sigstore y cosign, cadenas `#US` de .NET, IIS, API de nube en vivo, PKCS#11 y Vault, y cifrado de bases de datos (TDE).
- Linux, Windows, el contenedor y los workflows no se ejecutaron en sus plataformas. Notarización y Developer ID requieren la cuenta del propietario. No se publicaron artefactos.
- Implementación y verificación por el mismo asistente: se recomienda revisión independiente antes de una distribución sensible.

## Reproducción

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo deny --locked check
SUAYA_BIN="$PWD/bin/suaya" SUAYA_API="$PWD/bin/suaya-api" python3 pruebas/regresiones.py
python3 pruebas/regresion_gui.py
bin/suaya escanear pruebas/fixtures/sistema-demo -o demo.json --sarif demo.sarif
python3 pruebas/validar-cbom.py demo.json
python3 scripts/cobertura.py
bash scripts/fuzz.sh
bash scripts/compilacion-reproducible.sh
SUAYA_BUILD_DIR=/private/tmp/suaya-build SUAYA_DMG=1 bash empaquetado/build-macos.sh
```
