#!/usr/bin/env python3
"""Genera configuración y tokens privados; no imprime credenciales ni sobrescribe archivos."""
import argparse, hashlib, json, os, pathlib, secrets, time

def private_file(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as out:
        out.write(json.dumps(data, indent=2) + '\n')

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--directory', required=True, type=pathlib.Path)
    p.add_argument('--target', required=True, action='append', help='alias=/ruta/autorizada')
    p.add_argument('--network-target', action='append', default=[], help='alias=tls://host:puerto (o ssh://, smtp://...) para /api/v1/diagnose')
    p.add_argument('--user', required=True, action='append', help='nombre:admin o nombre:analyst')
    p.add_argument('--days', type=int, default=30)
    a = p.parse_args()
    if not 1 <= a.days <= 90: p.error('days debe estar entre 1 y 90')
    users = {}; targets = {}
    for entry in a.user:
        name, role = entry.rsplit(':', 1)
        if not name.isascii() or not name.replace('-', '').replace('_', '').isalnum() or len(name) > 64 or name in users or role not in ('admin', 'analyst'):
            p.error('usuario/rol inválido o duplicado')
        users[name] = role
    for entry in a.target:
        name, path = entry.split('=', 1)
        if not name.isascii() or not name.replace('-', '').replace('_', '').isalnum() or len(name)>64 or name in targets:
            p.error('alias inválido o duplicado')
        targets[name] = str(pathlib.Path(path).resolve(strict=True))
    network = {}
    for entry in a.network_target:
        name, url = entry.split('=', 1)
        if not name.isascii() or not name.replace('-', '').replace('_', '').isalnum() or len(name)>64 or name in targets or name in network:
            p.error('alias de red inválido o duplicado')
        if '://' not in url and ':' not in url: p.error('servicio de red inválido: use esquema://host:puerto')
        network[name] = url
    a.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if a.directory.is_symlink() or a.directory.stat().st_mode & 0o077: p.error('directorio debe ser privado (0700) y no symlink')
    if any((a.directory / f).exists() for f in ('config.json', 'tokens.json')): p.error('configuración existente; no se sobrescribe')
    tokens = {name: secrets.token_urlsafe(48) for name in users}
    config = {'targets': targets, 'network_targets': network, 'credentials': [dict(user=name, token_sha256=hashlib.sha256(tokens[name].encode()).hexdigest(), expires_at=int(time.time())+a.days*86400, admin=role=='admin', targets=list(targets)+list(network)) for name,role in users.items()]}
    private_file(a.directory / 'config.json', config)
    private_file(a.directory / 'tokens.json', tokens)
    print(f'Configuración: {a.directory / "config.json"}\nTokens privados: {a.directory / "tokens.json"}')
    print('Para revocar/rotar: cambie hashes y expiración en config.json y envíe SIGHUP a la API en Unix (o reinicie). No publique tokens.json.')
if __name__ == '__main__': main()
