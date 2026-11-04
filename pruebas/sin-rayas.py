#!/usr/bin/env python3
"""Verifica que los textos del proyecto no usen la raya tipográfica (U+2014)."""
import pathlib
import sys

RAYA = chr(0x2014)
SUFIJOS = {".rs", ".md", ".toml", ".yml", ".py", ".sh"}
rutas = [pathlib.Path(a) for a in sys.argv[1:]] or [pathlib.Path(".")]
hallazgos = []
for raiz in rutas:
    archivos = [raiz] if raiz.is_file() else raiz.rglob("*")
    for p in archivos:
        if p.is_file() and p.suffix in SUFIJOS and "target" not in p.parts and ".git" not in p.parts:
            for n, linea in enumerate(p.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                if RAYA in linea:
                    hallazgos.append(f"{p}:{n}")
for h in hallazgos:
    print(h)
print(f"{len(hallazgos)} usos de la raya tipográfica")
sys.exit(1 if hallazgos else 0)
