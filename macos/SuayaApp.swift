import SwiftUI
import AppKit
import UniformTypeIdentifiers

final class ScanJob: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false
    private var process: Process?
    func run(_ process: Process) throws {
        lock.lock(); defer { lock.unlock() }
        if cancelled { throw CancellationError() }
        self.process = process
        try process.run()
    }
    func cancel() {
        lock.lock(); defer { lock.unlock() }
        cancelled = true
        if let process, process.isRunning { process.terminate() }
    }
}

@MainActor final class ScanModel: ObservableObject {
    @Published var status = "Selecciona una carpeta para inventariar su criptografía."
    @Published var busy = false
    @Published var target: URL?
    @Published var components: [String] = []
    @Published var critical = 0
    @Published var cbom: Data?
    @Published var html: Data?
    private var job: ScanJob?
    private var generation = UUID()

    func choose() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true; panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        if panel.runModal() == .OK { target = panel.url }
    }
    func cancel() {
        generation = UUID()
        job?.cancel(); job = nil; busy = false
        status = "Escaneo cancelado."
    }
    func clear() {
        cancel(); cbom = nil; html = nil; components = []; critical = 0
        status = "Inventario borrado de la sesión."
    }
    func scan() {
        guard !busy, let target else { return }
        guard let executable = Bundle.main.url(forAuxiliaryExecutable: "suaya-engine") else {
            status = "El paquete no contiene el motor SUAYA. Reinstala la aplicación."; return
        }
        let id = UUID(); generation = id
        busy = true; cbom = nil; html = nil; components = []; critical = 0
        status = "Analizando \(target.lastPathComponent)…"
        let proc = Process(); let job = ScanJob(); self.job = job
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let dir = FileManager.default.temporaryDirectory.appendingPathComponent("suaya-\(id)")
            defer { try? FileManager.default.removeItem(at: dir) }
            do {
                try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
                let json = dir.appendingPathComponent("cbom.json")
                let report = dir.appendingPathComponent("reporte.html")
                let log = dir.appendingPathComponent("stderr.log")
                FileManager.default.createFile(atPath: log.path, contents: nil, attributes: [.posixPermissions: 0o600])
                let handle = try FileHandle(forWritingTo: log)
                defer { try? handle.close() }
                proc.executableURL = executable
                proc.arguments = ["escanear", target.path, "--hilos", "2", "-o", json.path, "-r", report.path]
                proc.standardOutput = FileHandle.nullDevice; proc.standardError = handle
                try job.run(proc); proc.waitUntilExit()
                guard proc.terminationStatus == 0 else {
                    DispatchQueue.main.async {
                        guard let self, self.generation == id else { return }
                        self.busy = false; self.job = nil
                        self.status = "El escaneo falló (código \(proc.terminationStatus)). Revisa permisos y el objetivo con la CLI."
                    }; return
                }
                let bytes = try Data(contentsOf: json)
                let reportBytes = try Data(contentsOf: report)
                let object = try JSONSerialization.jsonObject(with: bytes) as? [String: Any]
                let items = object?["components"] as? [[String: Any]] ?? []
                let names = items.map { ($0["name"] as? String) ?? "Activo" }
                let count = items.filter { item in
                    (item["properties"] as? [[String: Any]] ?? []).contains { ($0["name"] as? String) == "suaya:prioridad" && ($0["value"] as? String) == "1" }
                }.count
                let metadata = object?["metadata"] as? [String: Any]
                let properties = metadata?["properties"] as? [[String: Any]] ?? []
                let completed = properties.contains { ($0["name"] as? String) == "suaya:estado" && ($0["value"] as? String) == "completed" }
                let warnings = !completed
                DispatchQueue.main.async {
                    guard let self, self.generation == id else { return }
                    self.cbom = bytes; self.html = reportBytes; self.components = names; self.critical = count
                    self.busy = false; self.job = nil
                    self.status = warnings ? "Inventario generado con avisos. Consulta el reporte y la CLI antes de concluir cobertura completa." : "Inventario generado: \(names.count) activos, \(count) críticos."
                }
            } catch {
                DispatchQueue.main.async {
                    guard let self, self.generation == id else { return }
                    self.busy = false; self.job = nil; self.status = "No se pudo generar el inventario: \(error.localizedDescription)"
                }
            }
        }
    }
    func export(htmlReport: Bool) {
        guard let data = htmlReport ? html : cbom else { return }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = htmlReport ? "suaya-reporte.html" : "suaya-cbom.json"
        panel.allowedContentTypes = htmlReport ? [.html] : [.json]
        if panel.runModal() == .OK, let url = panel.url {
            do {
                // Escribir en un archivo privado en el mismo directorio y reemplazar atómicamente.
                let tmp = url.deletingLastPathComponent().appendingPathComponent(".suaya-\(UUID())")
                defer { try? FileManager.default.removeItem(at: tmp) }
                try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
                // Eliminar ACL heredadas antes de escribir contenido dentro del directorio privado.
                let acl = Process()
                acl.executableURL = URL(fileURLWithPath: "/bin/chmod")
                acl.arguments = ["-N", tmp.path]
                try acl.run(); acl.waitUntilExit()
                guard acl.terminationStatus == 0 else { throw CocoaError(.fileWriteNoPermission) }
                let file = tmp.appendingPathComponent("export")
                guard FileManager.default.createFile(atPath: file.path, contents: data, attributes: [.posixPermissions: 0o600]) else { throw CocoaError(.fileWriteUnknown) }
                // rename reemplaza el inode atómicamente, sin copiar ACL del destino anterior.
                guard rename(file.path, url.path) == 0 else {
                    throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
                }
                status = "Archivo guardado: \(url.lastPathComponent)"
            } catch { status = "Error de exportación: \(error.localizedDescription)" }
        }
    }
}

struct ContentView: View {
    @StateObject private var model = ScanModel()
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Image(systemName: "shield.lefthalf.filled").font(.largeTitle).foregroundColor(.teal)
                VStack(alignment: .leading) {
                    Text("SUAYA 1.5").font(.largeTitle.bold())
                    Text("Inventario criptográfico y preparación poscuántica").foregroundColor(.secondary)
                }
                Spacer()
            }
            Divider()
            HStack {
                Button("Elegir archivo o carpeta") { model.choose() }.disabled(model.busy)
                Text(model.target?.path ?? "Sin objetivo seleccionado").lineLimit(1).truncationMode(.middle)
                Spacer()
                Button("Escanear") { model.scan() }.disabled(model.target == nil || model.busy).keyboardShortcut(.return)
                if model.busy { Button("Cancelar") { model.cancel() } }
            }
            if model.busy { ProgressView().progressViewStyle(.linear) }
            Text(model.status).textSelection(.enabled)
            HStack {
                Text("\(model.components.count) activos").font(.headline)
                Text("\(model.critical) críticos").foregroundColor(model.critical > 0 ? .red : .secondary)
                Spacer()
                Button("Exportar CBOM") { model.export(htmlReport: false) }.disabled(model.cbom == nil)
                Button("Exportar HTML") { model.export(htmlReport: true) }.disabled(model.html == nil)
                Button("Limpiar") { model.clear() }
            }
            List(Array(model.components.enumerated()), id: \.offset) { _, name in Text(name).textSelection(.enabled) }
            Text("RSA, ECC y DH requieren evaluación de migración poscuántica independientemente de su tamaño. La clasificación y evidencia están en el reporte.")
                .font(.caption).foregroundColor(.secondary)
        }.padding(24).frame(minWidth: 850, minHeight: 580)
        .onDisappear { model.cancel() }
    }
}
@main struct SuayaApp: App {
    var body: some Scene { WindowGroup { ContentView() }.commands { CommandGroup(replacing: .newItem) {} } }
}
