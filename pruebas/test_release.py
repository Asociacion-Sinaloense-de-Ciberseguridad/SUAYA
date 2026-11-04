import json, os, pathlib, shutil, subprocess, sys, tempfile, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
class ReleaseTests(unittest.TestCase):
    def test_private_config_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d); data=root/'data'
            cmd=[sys.executable,str(ROOT/'scripts/configurar-api.py'),'--directory',str(data),'--target','fixture='+str(root),'--user','analista:analyst']
            result=subprocess.run(cmd,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            token=json.loads((data/'tokens.json').read_text())['analista']
            self.assertNotIn(token,result.stdout)
            self.assertEqual((data/'tokens.json').stat().st_mode & 0o777,0o600)
            self.assertNotEqual(subprocess.run(cmd,capture_output=True).returncode,0)
    def test_packaging_aborts_if_swift_compiler_fails(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d); (root/'empaquetado').mkdir(); (root/'bin').mkdir()
            shutil.copy(ROOT/'empaquetado/build-macos.sh',root/'empaquetado/build-macos.sh')
            for name,content in [('cargo','exit 0'),('swiftc','exit 17'),('hdiutil','touch "$MARKER"')]:
                f=root/'bin'/name; f.write_text('#!/bin/sh\n'+content+'\n'); f.chmod(0o700)
            marker=root/'bad-package'
            env=dict(os.environ,PATH=str(root/'bin')+os.pathsep+os.environ['PATH'],MARKER=str(marker),SUAYA_DMG='1')
            result=subprocess.run(['bash',str(root/'empaquetado/build-macos.sh')],env=env,capture_output=True)
            self.assertNotEqual(result.returncode,0); self.assertFalse(marker.exists())
if __name__=='__main__': unittest.main()
