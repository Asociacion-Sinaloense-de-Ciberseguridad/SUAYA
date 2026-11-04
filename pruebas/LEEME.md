# Sistema de demostración

`fixtures/sistema-demo/` simula un sistema con casos buenos y malos para probar Suaya: certificados con SHA-1 y RSA-1024, un servidor nginx con `X25519MLKEM768`, un Apache con TLS 1.0 habilitado, configuraciones SSH moderna y heredada, llaves en varios formatos, una llave pública ML-DSA-65 sintética, volúmenes cifrados, un contenedor PKCS#12, HAProxy, PostgreSQL, MySQL, Postfix, políticas de Java (la predeterminada y una recortada), manifiestos de Kubernetes y VPN. `fixtures/imagenes/` contiene una imagen `docker save` con una llave borrada en una capa posterior, que también usa el registro simulado de las pruebas. `srv/app/` reúne código fuente en siete lenguajes y manifiestos de dependencias, `srv/bin/herramienta` es un binario sintético con una cadena de versión de OpenSSL y `fixtures/cbom-externo/cbomkit.json` imita un CBOM generado por otra herramienta.

**Todas las llaves son de prueba**, generadas al momento por `generar-fixtures.sh`. No protegen nada y nunca deben usarse fuera de este repositorio. Algunas tienen permisos laxos a propósito.

Para regenerarlo:

```bash
./pruebas/generar-fixtures.sh
```

Requiere `openssl` y Python 3 con el paquete `cryptography`. Como las llaves cambian en cada generación, las pruebas verifican tipos, riesgos y relaciones, no valores exactos.
