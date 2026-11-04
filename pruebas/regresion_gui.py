"""Ejecuta el bloque de escritura real de la GUI con Foundation, sin abrir ventanas.
Desde 1.6 el bloque vive en writePrivately, compartido por inventario y diagnóstico.
SUAYA_SWIFT permite señalar el fuente de una futura versión corregida.
Si cambia la estructura del método, falla explícitamente para adaptar el harness.
"""
import os
from pathlib import Path
import subprocess
import tempfile

source = Path(os.environ.get('SUAYA_SWIFT', str(Path(__file__).resolve().parents[1] / 'macos/SuayaApp.swift')))
text = source.read_text()
method = text.split('func writePrivately(_ data: Data, to url: URL) throws', 1)[1]
start = method.index('let tmp = url.deletingLastPathComponent()')
end = method.index('// fin de escritura privada', start)
block = method[start:end]
with tempfile.TemporaryDirectory(prefix='suaya-sec005-') as td:
    d = Path(td)
    program = '''import Foundation
func write(_ data: Data, _ url: URL) throws {
''' + block + '''
}
func check() throws {
    let fm = FileManager.default
    let dir = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try fm.createDirectory(at: dir, withIntermediateDirectories: false)
    defer { try? fm.removeItem(at: dir) }
    let inherit = Process()
    inherit.executableURL = URL(fileURLWithPath: "/bin/chmod")
    inherit.arguments = ["+a", "everyone allow read,readattr,readextattr,readsecurity,file_inherit,directory_inherit", dir.path]
    try inherit.run(); inherit.waitUntilExit()
    guard inherit.terminationStatus == 0 else { exit(3) }
    let url = dir.appendingPathComponent("report.html")
    let data = Data("synthetic inventory".utf8)
    guard fm.createFile(atPath: url.path, contents: Data("old".utf8), attributes: [.posixPermissions: 0o644]) else { throw CocoaError(.fileWriteUnknown) }
    try write(data, url)
''' + '''
    let mode = (try fm.attributesOfItem(atPath: url.path)[.posixPermissions] as! NSNumber).intValue
    print(String(format: "mode_after_real_export=%o", mode))
    guard mode == 0o600 else { exit(1) }
    guard try Data(contentsOf: url) == data else { exit(2) }
    let inspect = Process(); let pipe = Pipe()
    inspect.executableURL = URL(fileURLWithPath: "/bin/ls")
    inspect.arguments = ["-le", url.path]; inspect.standardOutput = pipe
    try inspect.run(); inspect.waitUntilExit()
    let listing = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    guard !listing.split(separator: "\\n").contains(where: { $0.trimmingCharacters(in: .whitespaces).hasPrefix("0:") }) else { print("ACL pública heredada"); exit(4) }
    print("ACL heredada eliminada")
}
try check()
'''
    (d / 'main.swift').write_text(program)
    subprocess.run(['swiftc', '-module-cache-path', str(d / 'module-cache'), str(d / 'main.swift'), '-o', str(d / 'test')], check=True)
    result = subprocess.run([str(d / 'test')])
    raise SystemExit(result.returncode)
