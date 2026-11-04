"""Casos negativos y positivos de integridad de archivos OCI/Docker. Solo archivos temporales."""
import hashlib,io,json,os,pathlib,subprocess,tarfile,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
BIN=os.environ.get('SUAYA_BIN',str(ROOT/'bin/suaya'))
def archive(entries):
 out=io.BytesIO()
 with tarfile.open(fileobj=out,mode='w') as t:
  for name,data in entries:
   h=tarfile.TarInfo(name);h.size=len(data);t.addfile(h,io.BytesIO(data))
 return out.getvalue()
def digest(data):return 'sha256:'+hashlib.sha256(data).hexdigest()
def blob(d):return 'blobs/'+d.replace(':','/')
class ImageSecurity(unittest.TestCase):
 def scan(self,data):
  with tempfile.TemporaryDirectory() as td:
   p=pathlib.Path(td);(p/'image.tar').write_bytes(data)
   return subprocess.run([BIN,'escanear','--imagen',str(p/'image.tar'),'--fallar-si-incompleto','-o',str(p/'cbom.json')],capture_output=True,timeout=20).returncode
 def test_complete_docker_archive(self):
  data=archive([('manifest.json',b'[{"Layers":["layer.tar"]}]'),('layer.tar',archive([]))])
  self.assertEqual(self.scan(data),0)
 def test_duplicate_layers_and_entries_rejected(self):
  for names,entries in [(['a','a'],[('a',archive([]))]),(['a'],[('a',archive([])),('a',archive([]))]),(['a'],[('b',archive([]))])]:
   with self.subTest(names=names,count=len(entries)):
    self.assertNotEqual(self.scan(archive([('manifest.json',json.dumps([{'Layers':names}]).encode()),*entries])),0)
 def test_invalid_layer_type_rejected(self):
  for name in [None,2,{},True]:
   self.assertNotEqual(self.scan(archive([('manifest.json',json.dumps([{'Layers':[name]}]).encode())])),0)
 def test_oci_digest_and_missing_layer(self):
  layer=archive([]);ld=digest(layer)
  manifest=json.dumps({'schemaVersion':2,'layers':[{'digest':ld,'size':len(layer)}]}).encode();md=digest(manifest)
  index=json.dumps({'schemaVersion':2,'manifests':[{'digest':md,'size':len(manifest)}]}).encode()
  prefix=[('index.json',index),(blob(md),manifest)]
  self.assertEqual(self.scan(archive(prefix+[(blob(ld),layer)])),0)
  self.assertNotEqual(self.scan(archive(prefix)),0)
  self.assertNotEqual(self.scan(archive(prefix+[(blob(ld),layer[:-1]+b'x')])),0)
  self.assertNotEqual(self.scan(archive([('index.json',index),(blob(md),manifest+b' '),(blob(ld),layer)])),0)
if __name__=='__main__':unittest.main(verbosity=2)
