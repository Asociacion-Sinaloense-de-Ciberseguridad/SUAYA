"""Regresiones no destructivas. Gates de seguridad 1.5: todos los casos deben aprobar.
SUAYA_BIN y SUAYA_API permiten probar una futura compilación corregida.
"""
import base64,hashlib,http.server,io,json,os,pathlib,socket,subprocess,tarfile,tempfile,threading,time,unittest,urllib.request,urllib.error
ROOT=str(pathlib.Path(__file__).resolve().parents[1])
BIN=os.environ.get('SUAYA_BIN',ROOT+'/bin/suaya')
API=os.environ.get('SUAYA_API',ROOT+'/bin/suaya-api')
class SecurityRegression(unittest.TestCase):
 def test_SEC003_missing_layer_is_not_completed(self):
  with tempfile.TemporaryDirectory() as td:
   d=pathlib.Path(td)
   with tarfile.open(d/'image.tar','w') as archive:
    data=json.dumps([{'Layers':['missing/layer.tar']}]).encode();h=tarfile.TarInfo('manifest.json');h.size=len(data);archive.addfile(h,io.BytesIO(data))
   p=subprocess.run([BIN,'escanear','--imagen',str(d/'image.tar'),'--fallar-si-incompleto','-o',str(d/'cbom.json')],capture_output=True,timeout=15)
   self.assertNotEqual(p.returncode,0,'Una capa ausente fue aceptada como escaneo completo')
 def test_SEC001_cdn_challenge_cannot_receive_registry_password(self):
  seen=[];servers=[];hits=[]
  class H(http.server.BaseHTTPRequestHandler):
   def log_message(self,*a):pass
   def do_GET(self):
    hits.append(self.server.role)
    if self.server.role=='registry':
     self.send_response(302);self.send_header('Location',f'http://127.0.0.1:{servers[1].server_port}/object');self.end_headers()
    elif self.server.role=='cdn':
     self.send_response(401);self.send_header('WWW-Authenticate',f'Bearer realm="http://127.0.0.1:{servers[2].server_port}/token"');self.end_headers()
    else:
     seen.append(self.headers.get('Authorization'));self.send_response(403);self.end_headers()
  for role in ('registry','cdn','token'):
   s=http.server.ThreadingHTTPServer(('127.0.0.1',0),H);s.role=role;servers.append(s);threading.Thread(target=s.serve_forever,daemon=True).start()
  try:
   with tempfile.TemporaryDirectory() as td:
    d=pathlib.Path(td);key=f'127.0.0.1:{servers[0].server_port}'
    (d/'config.json').write_text(json.dumps({'auths':{key:{'auth':base64.b64encode(b'audit:synthetic-only').decode()}}}))
    env=dict(os.environ,DOCKER_CONFIG=td);env.pop('SUAYA_REGISTRO_USUARIO',None);env.pop('SUAYA_REGISTRO_CLAVE',None)
    subprocess.run([BIN,'escanear','--registro-http-local','--imagen',f'docker://{key}/audit:demo','-o',str(d/'cbom.json')],env=env,capture_output=True,timeout=15)
    self.assertIn('registry', hits, 'La prueba no alcanzó el registro simulado')
    self.assertFalse(any(seen),'Se enviaron credenciales a un origen no autorizado')
  finally:
   for s in servers:s.shutdown();s.server_close()
 def test_SEC002_anonymous_budget_does_not_block_valid_user(self):
  with tempfile.TemporaryDirectory() as td:
   d=pathlib.Path(td);token='synthetic-test-token-'+'a'*48
   (d/'config.json').write_text(json.dumps({'credentials':[{'user':'audit','token_sha256':hashlib.sha256(token.encode()).hexdigest(),'expires_at':int(time.time())+600,'admin':True}],'targets':{}}));(d/'config.json').chmod(0o600)
   with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
   def request(path,valid=False):
    r=urllib.request.Request(f'http://127.0.0.1:{port}'+path,headers={'Authorization':'Bearer '+token} if valid else {})
    try:
     with urllib.request.urlopen(r,timeout=3) as response:return response.status
    except urllib.error.HTTPError as e:return e.code
   log=(d/'api.log').open('w')
   p=subprocess.Popen([API,'--config',str(d/'config.json'),'--database',str(d/'db'),'--listen',f'127.0.0.1:{port}'],stdout=subprocess.DEVNULL,stderr=log)
   try:
    for _ in range(100):
     try:request('/api/v1/health');break
     except OSError:time.sleep(.03)
    self.assertEqual(request('/api/v1/scans',True),200)
    for _ in range(650):request('/api/v1/scans')
    self.assertEqual(request('/api/v1/scans',True),200,'El tráfico anónimo bloqueó al usuario legítimo')
    records=[json.loads(line) for line in (d/'api.log').read_text().splitlines() if line.startswith('{')]
    requests=[r for r in records if r.get('event')=='api_request']
    self.assertTrue(any(r['status']==401 for r in requests))
    self.assertTrue(any(r['status']==429 for r in requests))
    self.assertTrue(all(r.get('request_id') for r in requests))
    self.assertNotIn(token,(d/'api.log').read_text())
   finally:p.terminate();p.wait(timeout=5);log.close()
 def test_SEC001_external_realm_requires_explicit_per_registry_allowlist(self):
  received=[];servers=[]
  class H(http.server.BaseHTTPRequestHandler):
   def log_message(self,*a):pass
   def do_GET(self):
    if self.server.role=='registry':
     self.send_response(401);self.send_header('WWW-Authenticate',f'Bearer realm="http://127.0.0.1:{servers[1].server_port}/token"');self.end_headers()
    else:
     received.append(self.headers.get('Authorization'));self.send_response(403);self.end_headers()
  for role in ('registry','token'):
   server=http.server.ThreadingHTTPServer(('127.0.0.1',0),H);server.role=role;servers.append(server);threading.Thread(target=server.serve_forever,daemon=True).start()
  try:
   with tempfile.TemporaryDirectory() as td:
    d=pathlib.Path(td);key=f'127.0.0.1:{servers[0].server_port}';auth=base64.b64encode(b'audit:synthetic-only').decode()
    (d/'config.json').write_text(json.dumps({'auths':{key:{'auth':auth}}}))
    env=dict(os.environ,DOCKER_CONFIG=td);env.pop('SUAYA_REGISTRO_USUARIO',None);env.pop('SUAYA_REGISTRO_CLAVE',None)
    cmd=[BIN,'escanear','--registro-http-local','--imagen',f'docker://{key}/audit:demo','-o',str(d/'cbom.json')]
    subprocess.run(cmd,env=env,capture_output=True,timeout=15)
    self.assertEqual(received,[])
    subprocess.run(cmd+['--registro-token-origen',f'{key}=http://127.0.0.1:{servers[1].server_port}'],env=env,capture_output=True,timeout=15)
    self.assertEqual(received,['Basic '+auth])
  finally:
   for server in servers:server.shutdown();server.server_close()
if __name__=='__main__':unittest.main(verbosity=2)
