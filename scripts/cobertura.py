#!/usr/bin/env python3
"""Cobertura LLVM de tests Rust. Requiere rustup component add llvm-tools-preview."""
import glob,json,os,pathlib,subprocess,tempfile
root=pathlib.Path(__file__).resolve().parents[1]
def run(args,**kwargs):return subprocess.run(args,cwd=root,check=True,**kwargs)
sysroot=pathlib.Path(subprocess.check_output(['rustc','--print','sysroot'],text=True).strip())
prof=next(sysroot.glob('lib/rustlib/*/bin/llvm-profdata'));cov=prof.with_name('llvm-cov')
with tempfile.TemporaryDirectory(prefix='suaya-coverage-') as td:
 d=pathlib.Path(td);env=dict(os.environ,RUSTFLAGS='-C instrument-coverage',LLVM_PROFILE_FILE=str(d/'%p-%m.profraw'),CARGO_TARGET_DIR=str(d/'target'))
 result=run(['cargo','test','--workspace','--locked','--message-format=json'],env=env,capture_output=True,text=True)
 executables=[]
 for line in result.stdout.splitlines():
  try:item=json.loads(line)
  except ValueError:continue
  if item.get('reason')=='compiler-artifact' and item.get('executable') and 'suaya' in item.get('package_id','') and 'custom-build' not in item.get('target',{}).get('kind',[]):executables.append(item['executable'])
 run([str(prof),'merge','-sparse',*glob.glob(str(d/'*.profraw')),'-o',str(d/'coverage.profdata')])
 cmd=[str(cov),'report','--instr-profile='+str(d/'coverage.profdata'),'--ignore-filename-regex=/.cargo/|/rustc/|/registry/|/tests/']
 for exe in executables:cmd+=['-object',exe]
 report=subprocess.check_output(cmd,text=True)
 (root/'validacion').mkdir(exist_ok=True)
 (root/'validacion/coverage.txt').write_text(report)
 print(report)

rows=[line.split() for line in report.splitlines() if '/crates/' in line and '/src/' in line]
# Columnas desde la derecha: la ruta del proyecto puede contener espacios.
lines=sum(int(row[-6]) for row in rows); missed=sum(int(row[-5]) for row in rows)
summary={'scope':'crates/*/src, incluye tests internos; excluye integración y dependencias generadas','lines':lines,'missed_lines':missed,'covered_percent':round(100*(lines-missed)/lines,2)}
(root/'validacion/coverage-source.json').write_text(json.dumps(summary,indent=2)+'\n')
print(summary)
