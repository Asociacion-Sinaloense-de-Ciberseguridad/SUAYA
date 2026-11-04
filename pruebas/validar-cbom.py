#!/usr/bin/env python3
"""Valida un CBOM contra el esquema oficial de CycloneDX 1.7.

Uso: python3 pruebas/validar-cbom.py <cbom.json>
Requiere: pip install jsonschema referencing
Los esquemas están en pruebas/esquemas/ (copiados del repositorio
CycloneDX/specification, Licencia Apache 2.0).
"""
import json
import os
import sys

from jsonschema import Draft7Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "esquemas")


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 1
    registro = Registry()
    for nombre in os.listdir(DIR):
        esquema = json.load(open(os.path.join(DIR, nombre), encoding="utf-8"))
        recurso = Resource.from_contents(esquema, default_specification=DRAFT7)
        registro = registro.with_resource(nombre, recurso)
        if "$id" in esquema:
            registro = registro.with_resource(esquema["$id"], recurso)
    principal = json.load(open(os.path.join(DIR, "bom-1.7.schema.json"), encoding="utf-8"))
    documento = json.load(open(sys.argv[1], encoding="utf-8"))
    errores = list(Draft7Validator(principal, registry=registro).iter_errors(documento))
    for e in errores[:20]:
        print(f"- {'/'.join(str(p) for p in e.path)}: {e.message[:200]}")
    print(f"{len(errores)} errores de esquema")
    return 1 if errores else 0


if __name__ == "__main__":
    sys.exit(main())
