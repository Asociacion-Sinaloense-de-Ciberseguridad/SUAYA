#!/usr/bin/env python3
"""Manifiesto verificable de fuentes, dependencias resueltas y herramientas de build."""
import argparse, hashlib, json, os, pathlib, platform, subprocess, tomllib
p=argparse.ArgumentParser();p.add_argument('--output',required=True,type=pathlib.Path);a=p.parse_args()
root=pathlib.Path(__file__).resolve().parents[1]
def run(*args):return subprocess.check_output(args,cwd=root,text=True).strip()
metadata=json.loads(run('cargo','metadata','--locked','--offline','--format-version','1'))
lock=tomllib.loads((root/'Cargo.lock').read_text())
checksums={(x['name'],x['version']):x.get('checksum') for x in lock['package']}
packages=[dict({k:x.get(k) for k in ('name','version','license','source')}, checksum=checksums.get((x['name'],x['version']))) for x in metadata['packages']]
files={}
for folder in ('crates','conocimiento','macos','scripts','empaquetado','security','.github'):
 for path in (root/folder).rglob('*'):
  if path.is_file() and 'generado' not in path.parts:
   files[str(path.relative_to(root))]=hashlib.sha256(path.read_bytes()).hexdigest()
for name in ('Cargo.toml','Cargo.lock'):
 files[name]=hashlib.sha256((root/name).read_bytes()).hexdigest()
result={'version':'1.5.0','platform':platform.platform(),'rustc':run('rustc','--version','--verbose'),'cargo':run('cargo','--version'),'source_date_epoch':os.environ.get('SOURCE_DATE_EPOCH'),'packages':packages,'sources_sha256':files,'note':'Manifest de contenido y dependencias; la autenticidad requiere attestation del pipeline.'}
a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2)+'\n')
