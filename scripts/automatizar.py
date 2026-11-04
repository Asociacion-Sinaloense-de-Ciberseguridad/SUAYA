#!/usr/bin/env python3
"""Ejecuta escaneos reales periódicos con timeout y sin intérprete de shell."""
import argparse, datetime, json, pathlib, subprocess, time, uuid

def run(binary, target, output, timeout):
    name = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]
    cbom = output / (name + '.cbom.json')
    report = output / (name + '.html')
    result = subprocess.run([str(binary), 'escanear', str(target), '-o', str(cbom), '-r', str(report), '--fallar-si-incompleto'], timeout=timeout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    print(json.dumps({'at':name, 'exit_code': result.returncode, 'status':'completed' if result.returncode == 0 else ('partial' if result.returncode == 4 else 'failed')}), flush=True)
    return result.returncode

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=pathlib.Path, required=True)
    p.add_argument('--target', type=pathlib.Path, required=True)
    p.add_argument('--output', type=pathlib.Path, required=True)
    p.add_argument('--interval', type=int, default=3600)
    p.add_argument('--timeout', type=int, default=1800)
    p.add_argument('--once', action='store_true')
    a=p.parse_args()
    if a.interval < 60 or a.timeout < 1: p.error('interval >=60 y timeout >=1')
    binary=a.binary.resolve(strict=True); target=a.target.resolve(strict=True)
    a.output.mkdir(parents=True, mode=0o700, exist_ok=True)
    if a.output.is_symlink() or a.output.stat().st_mode & 0o077: p.error('output requiere directorio privado 0700')
    try:
        while True:
            try: status=run(binary,target,a.output,a.timeout)
            except subprocess.TimeoutExpired: print(json.dumps({'status':'timeout'}),flush=True); status=1
            if a.once: return status
            time.sleep(a.interval)
    except KeyboardInterrupt: return 130
if __name__=='__main__': raise SystemExit(main())
