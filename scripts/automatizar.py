#!/usr/bin/env python3
"""Ejecuta escaneos o diagnósticos reales periódicos con timeout y sin intérprete de shell."""
import argparse, datetime, json, pathlib, subprocess, time, uuid

def marca():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]

def run(binary, target, output, timeout):
    name = marca()
    cbom = output / (name + '.cbom.json')
    report = output / (name + '.html')
    result = subprocess.run([str(binary), 'escanear', str(target), '-o', str(cbom), '-r', str(report), '--fallar-si-incompleto'], timeout=timeout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    print(json.dumps({'at':name, 'mode':'escaneo', 'exit_code': result.returncode, 'status':'completed' if result.returncode == 0 else ('partial' if result.returncode == 4 else 'failed')}), flush=True)
    return result.returncode

def diagnose(binary, targets, output, metrics, threshold, timeout):
    name = marca()
    cmd = [str(binary), 'diagnosticar', '--json', str(output / (name + '.diagnostico.json'))]
    if metrics: cmd += ['--metricas', str(metrics)]
    if threshold: cmd += ['--fallar-en', threshold]
    result = subprocess.run(cmd + ['--'] + targets, timeout=timeout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    print(json.dumps({'at':name, 'mode':'diagnostico', 'exit_code': result.returncode, 'status':'completed' if result.returncode == 0 else ('findings' if result.returncode == 2 else 'failed')}), flush=True)
    return result.returncode

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=pathlib.Path, required=True)
    p.add_argument('--target', type=pathlib.Path, help='directorio o archivo a escanear')
    p.add_argument('--diagnosticar', action='append', default=[], metavar='OBJETIVO', help='servicio a diagnosticar (repetible), p. ej. tls://portal.ejemplo.mx:443')
    p.add_argument('--metricas', type=pathlib.Path, help='archivo .prom que reescribe cada diagnóstico (recolector de archivos de node_exporter)')
    p.add_argument('--fallar-en', choices=['critico', 'alto', 'medio', 'bajo'], help='nivel del diagnóstico que se informa como hallazgo')
    p.add_argument('--output', type=pathlib.Path, required=True)
    p.add_argument('--interval', type=int, default=3600)
    p.add_argument('--timeout', type=int, default=1800)
    p.add_argument('--once', action='store_true')
    a=p.parse_args()
    if a.interval < 60 or a.timeout < 1: p.error('interval >=60 y timeout >=1')
    if not a.target and not a.diagnosticar: p.error('indique --target, --diagnosticar o ambos')
    if any(t.startswith('-') or '://' not in t for t in a.diagnosticar): p.error('cada objetivo debe tener esquema, p. ej. tls://host:443')
    binary=a.binary.resolve(strict=True); target=a.target.resolve(strict=True) if a.target else None
    a.output.mkdir(parents=True, mode=0o700, exist_ok=True)
    if a.output.is_symlink() or a.output.stat().st_mode & 0o077: p.error('output requiere directorio privado 0700')
    try:
        while True:
            status=0
            if target:
                try: status=run(binary,target,a.output,a.timeout)
                except subprocess.TimeoutExpired: print(json.dumps({'mode':'escaneo','status':'timeout'}),flush=True); status=1
            if a.diagnosticar:
                try: status=max(status, diagnose(binary,a.diagnosticar,a.output,a.metricas,a.fallar_en,a.timeout))
                except subprocess.TimeoutExpired: print(json.dumps({'mode':'diagnostico','status':'timeout'}),flush=True); status=1
            if a.once: return status
            time.sleep(a.interval)
    except KeyboardInterrupt: return 130
if __name__=='__main__': raise SystemExit(main())
