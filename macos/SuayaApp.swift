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

/// Perfiles de política incluidos en el motor: (identificador, nombre).
let perfiles: [(String, String)] = [
    ("", "Sin perfil"),
    ("nist-ir-8547", "NIST IR 8547"),
    ("cnsa-2.0", "CNSA 2.0 (NSA)"),
    ("ue-hoja-de-ruta", "Unión Europea"),
    ("ncsc-reino-unido", "Reino Unido (NCSC)"),
    ("canada-cccs", "Canadá (CCCS)"),
    ("pci-dss-4", "PCI DSS v4.0.1"),
]

/// Lo que se puede exportar de un inventario.
enum Exportacion { case cbom, html, csv, sarif }

@MainActor final class ScanModel: ObservableObject {
    @Published var status = "Selecciona una carpeta para inventariar su criptografía."
    @Published var busy = false
    @Published var target: URL?
    @Published var profile = ""
    @Published var organization: URL?
    @Published var keychain = false
    @Published var components: [String] = []
    @Published var critical = 0
    @Published var cbom: Data?
    @Published var html: Data?
    @Published var csv: Data?
    @Published var sarif: Data?
    private var job: ScanJob?
    private var generation = UUID()

    var canScan: Bool { !busy && (target != nil || keychain) }

    func choose() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true; panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        if panel.runModal() == .OK { target = panel.url }
    }
    func chooseOrganization() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false; panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        if let toml = UTType(filenameExtension: "toml") { panel.allowedContentTypes = [toml, .plainText] }
        if panel.runModal() == .OK { organization = panel.url }
    }
    func cancel() {
        generation = UUID()
        job?.cancel(); job = nil; busy = false
        status = "Escaneo cancelado."
    }
    func clear() {
        cancel(); cbom = nil; html = nil; csv = nil; sarif = nil; components = []; critical = 0
        status = "Inventario borrado de la sesión."
    }
    func scan() {
        guard canScan else { return }
        guard let executable = Bundle.main.url(forAuxiliaryExecutable: "suaya-engine") else {
            status = "El paquete no contiene el motor SUAYA. Reinstala la aplicación."; return
        }
        let id = UUID(); generation = id
        busy = true; cbom = nil; html = nil; csv = nil; sarif = nil; components = []; critical = 0
        status = target.map { "Analizando \($0.lastPathComponent)…" } ?? "Analizando el llavero…"
        let (target, profile, organization, keychain) = (self.target, self.profile, self.organization, self.keychain)
        let proc = Process(); let job = ScanJob(); self.job = job
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let dir = FileManager.default.temporaryDirectory.appendingPathComponent("suaya-\(id)")
            defer { try? FileManager.default.removeItem(at: dir) }
            do {
                try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
                let json = dir.appendingPathComponent("cbom.json")
                let report = dir.appendingPathComponent("reporte.html")
                let csvFile = dir.appendingPathComponent("inventario.csv")
                let sarifFile = dir.appendingPathComponent("hallazgos.sarif")
                let log = dir.appendingPathComponent("stderr.log")
                FileManager.default.createFile(atPath: log.path, contents: nil, attributes: [.posixPermissions: 0o600])
                let handle = try FileHandle(forWritingTo: log)
                defer { try? handle.close() }
                var args = ["escanear", "--hilos", "2", "-o", json.path, "-r", report.path, "--csv", csvFile.path, "--sarif", sarifFile.path]
                if !profile.isEmpty { args += ["--perfil", profile] }
                if let organization { args += ["--organizacion", organization.path] }
                if keychain { args.append("--llavero") }
                // «--» cierra las opciones: la ruta elegida solo puede ser un objetivo.
                if let target { args += ["--", target.path] }
                proc.executableURL = executable
                proc.arguments = args
                proc.standardOutput = FileHandle.nullDevice; proc.standardError = handle
                try job.run(proc); proc.waitUntilExit()
                guard proc.terminationStatus == 0 else {
                    DispatchQueue.main.async {
                        guard let self, self.generation == id else { return }
                        self.busy = false; self.job = nil
                        self.status = "El escaneo falló (código \(proc.terminationStatus)). Revisa permisos, el objetivo y el archivo de organización con la CLI."
                    }; return
                }
                let bytes = try Data(contentsOf: json)
                let reportBytes = try Data(contentsOf: report)
                let csvBytes = try Data(contentsOf: csvFile)
                let sarifBytes = try Data(contentsOf: sarifFile)
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
                    self.cbom = bytes; self.html = reportBytes; self.csv = csvBytes; self.sarif = sarifBytes
                    self.components = names; self.critical = count
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
    func export(_ kind: Exportacion) {
        let (data, name, type): (Data?, String, UTType) = switch kind {
        case .cbom: (cbom, "suaya-cbom.json", .json)
        case .html: (html, "suaya-reporte.html", .html)
        case .csv: (csv, "suaya-inventario.csv", .commaSeparatedText)
        case .sarif: (sarif, "suaya-hallazgos.sarif", UTType(filenameExtension: "sarif") ?? .json)
        }
        guard let data else { return }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = name
        panel.allowedContentTypes = [type]
        if panel.runModal() == .OK, let url = panel.url {
            do {
                try writePrivately(data, to: url)
                status = "Archivo guardado: \(url.lastPathComponent)"
            } catch { status = "Error de exportación: \(error.localizedDescription)" }
        }
    }
}

/// Escribe en un archivo privado en el mismo directorio y reemplaza atómicamente.
func writePrivately(_ data: Data, to url: URL) throws {
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
    // fin de escritura privada
}

// MARK: - Diagnóstico de red

struct Hallazgo: Decodable, Hashable { let nivel: String; let codigo: String; let mensaje: String }
struct Direccion: Decodable, Hashable { let ip: String; let familia: String; let estado: String; let milisegundos: Int? }
struct Conectividad: Decodable, Hashable {
    let resolucion_ms: Int?; let error_resolucion: String?; let direcciones: [Direccion]
    let starttls: String?; let saludo_ms: Int?
}
struct SaludoTls: Decodable, Hashable {
    let cliente: String; let exito: Bool; let error: String?; let version: String?; let suite: String?
    let grupo: String?; let riesgo_grupo: String?; let reintento: Bool; let esquema_firma: String?; let firma_verificada: Bool?
}
struct IntercambioTls: Decodable, Hashable { let moderno: SaludoTls; let clasico: SaludoTls }
struct CertificadoDiag: Decodable, Hashable { let nombre: String; let algoritmo_llave: String; let no_despues: String; let dias_restantes: Int }
struct Cadena: Decodable, Hashable {
    let error_validacion: String?; let error_nombre: String?; let bytes: Int; let certificados: [CertificadoDiag]
}
struct IntercambioSsh: Decodable, Hashable { let identificacion: String; let kex: [String]; let kex_poscuanticos: [String]; let kex_estricto: Bool }
struct IntercambioIke: Decodable, Hashable { let grupos: [String]; let preferido: String?; let mlkem: String? }
struct IntercambioDns: Decodable, Hashable {
    let resolvedor: String; let validada: Bool; let llaves: [String]; let delegaciones: [String]
    let firmas: [String]; let caa: [String]; let tlsa: [String]; let dkim: [String]
}
struct IntercambioIdentidad: Decodable, Hashable {
    let documento: String; let emisor: String?; let algoritmos: [String]; let jwks: String?
    let llaves: [String]; let certificados: [String]
}
struct RecetaDiag: Decodable, Hashable { let id: String; let titulo: String; let pasos: [String]; let hallazgos: [String] }
struct Diagnostico: Decodable, Hashable, Identifiable {
    var id: String { objetivo }
    let objetivo: String; let protocolo: String; let conectividad: Conectividad
    let tls: IntercambioTls?; let certificados: Cadena?; let ssh: IntercambioSsh?
    let ike: IntercambioIke?; let dns: IntercambioDns?; let identidad: IntercambioIdentidad?
    let hallazgos: [Hallazgo]
    let recetas: [RecetaDiag]?
    var peor: String? { ["critico", "alto", "medio", "bajo", "info"].first { n in hallazgos.contains { $0.nivel == n } } }
}
struct DocumentoDiagnostico: Decodable { let diagnosticos: [Diagnostico] }

func colorNivel(_ nivel: String?) -> Color {
    switch nivel {
    case "critico": return .red
    case "alto": return .orange
    case "medio": return .yellow
    case "bajo": return .blue
    default: return .secondary
    }
}

func etiquetaNivel(_ nivel: String) -> String {
    ["critico": "CRÍTICO", "alto": "ALTO", "medio": "MEDIO", "bajo": "BAJO", "info": "INFO"][nivel] ?? nivel.uppercased()
}

@MainActor final class DiagnosisModel: ObservableObject {
    static let maximoObjetivos = 20
    @Published var input = ""
    @Published var authority: URL?
    @Published var status = "Escribe uno o más servicios (p. ej. www.ejemplo.mx, smtp://correo.ejemplo.mx, ssh://bastion:22, dns://ejemplo.mx, oidc://login.ejemplo.mx)."
    @Published var busy = false
    @Published var results: [Diagnostico] = []
    @Published var json: Data?
    private var job: ScanJob?
    private var generation = UUID()

    /// Objetivos escritos por la persona; nunca se interpretan como opciones del motor.
    var targets: [String] {
        input.split(whereSeparator: { $0 == "," || $0.isWhitespace }).map(String.init).filter { !$0.isEmpty }
    }
    func chooseAuthority() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true; panel.canChooseDirectories = false; panel.allowsMultipleSelection = false
        if panel.runModal() == .OK { authority = panel.url }
    }
    func cancel() {
        generation = UUID()
        job?.cancel(); job = nil
        if busy { status = "Diagnóstico cancelado." }
        busy = false
    }
    func run() {
        let targets = self.targets
        guard !busy, !targets.isEmpty else { return }
        guard targets.count <= Self.maximoObjetivos else {
            status = "Diagnostica como máximo \(Self.maximoObjetivos) servicios a la vez."; return
        }
        guard !targets.contains(where: { $0.hasPrefix("-") }) else {
            status = "Un servicio no puede empezar con «-»."; return
        }
        guard let executable = Bundle.main.url(forAuxiliaryExecutable: "suaya-engine") else {
            status = "El paquete no contiene el motor SUAYA. Reinstala la aplicación."; return
        }
        let id = UUID(); generation = id
        busy = true; results = []; json = nil
        status = "Diagnosticando \(targets.count) servicio(s)… cada uno recibe unas pocas conexiones breves."
        let authority = self.authority
        let proc = Process(); let job = ScanJob(); self.job = job
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let dir = FileManager.default.temporaryDirectory.appendingPathComponent("suaya-diag-\(id)")
            defer { try? FileManager.default.removeItem(at: dir) }
            do {
                try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
                let out = dir.appendingPathComponent("diagnostico.json")
                var args = ["diagnosticar", "--json", out.path]
                if let authority { args += ["--ca", authority.path] }
                // «--» cierra las opciones: lo escrito solo puede ser un objetivo.
                args += ["--"] + targets
                proc.executableURL = executable
                proc.arguments = args
                proc.standardOutput = FileHandle.nullDevice; proc.standardError = FileHandle.nullDevice
                try job.run(proc); proc.waitUntilExit()
                guard proc.terminationStatus == 0 else {
                    DispatchQueue.main.async {
                        guard let self, self.generation == id else { return }
                        self.busy = false; self.job = nil
                        self.status = "El diagnóstico falló (código \(proc.terminationStatus)). Revisa la escritura de los servicios."
                    }; return
                }
                let bytes = try Data(contentsOf: out)
                let documento = try JSONDecoder().decode(DocumentoDiagnostico.self, from: bytes)
                DispatchQueue.main.async {
                    guard let self, self.generation == id else { return }
                    self.results = documento.diagnosticos; self.json = bytes
                    self.busy = false; self.job = nil
                    let criticos = documento.diagnosticos.filter { $0.peor == "critico" }.count
                    self.status = "Diagnóstico terminado: \(documento.diagnosticos.count) servicio(s), \(criticos) con hallazgos críticos."
                }
            } catch {
                DispatchQueue.main.async {
                    guard let self, self.generation == id else { return }
                    self.busy = false; self.job = nil
                    self.status = "No se pudo completar el diagnóstico: \(error.localizedDescription)"
                }
            }
        }
    }
    func export() {
        guard let json else { return }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "suaya-diagnostico.json"
        panel.allowedContentTypes = [.json]
        if panel.runModal() == .OK, let url = panel.url {
            do {
                try writePrivately(json, to: url)
                status = "Archivo guardado: \(url.lastPathComponent)"
            } catch { status = "Error de exportación: \(error.localizedDescription)" }
        }
    }
}

struct DiagnosisRow: View {
    let d: Diagnostico
    func saludo(_ s: SaludoTls) -> String {
        guard s.exito else { return "falló (\(s.error ?? ""))" }
        var partes = [s.version, s.grupo].compactMap { $0 }
        if s.reintento { partes.append("HelloRetryRequest") }
        if let f = s.esquema_firma { partes.append(s.firma_verificada == true ? "firma \(f) verificada" : "firma \(f)") }
        return partes.joined(separator: " · ")
    }
    var body: some View {
        DisclosureGroup {
            VStack(alignment: .leading, spacing: 4) {
                let k = d.conectividad
                if let e = k.error_resolucion { Text("DNS: sin resolver (\(e))") }
                ForEach(k.direcciones, id: \.self) { x in
                    Text("\(x.ip) (\(x.familia)): \(x.estado)\(x.milisegundos.map { " en \($0) ms" } ?? "")")
                }
                if let st = k.starttls { Text("STARTTLS: \(st)") }
                if let t = d.tls {
                    Text("Cliente moderno: \(saludo(t.moderno))")
                    Text("Cliente clásico: \(saludo(t.clasico))")
                }
                if let c = d.certificados {
                    Text("Cadena (\(c.certificados.count), \(c.bytes) bytes): \(c.error_nombre ?? c.error_validacion ?? "válida para un cliente estándar")")
                    ForEach(Array(c.certificados.enumerated()), id: \.offset) { i, x in
                        Text("  \(i + 1). \(x.nombre) · \(x.algoritmo_llave) · vence \(String(x.no_despues.prefix(10))) (\(x.dias_restantes) días)")
                    }
                }
                if let s = d.ssh {
                    Text(s.identificacion)
                    Text("KEX: \(s.kex.joined(separator: ", "))")
                    Text(s.kex_estricto ? "strict KEX anunciado" : "sin strict KEX")
                }
                if let i = d.ike {
                    Text("IKEv2: \(i.grupos.joined(separator: ", "))")
                    if let m = i.mlkem { Text("Intercambio adicional: \(m)") }
                }
                if let x = d.dns {
                    Text("Resolvedor: \(x.resolvedor)\(x.validada ? " · cadena DNSSEC validada" : "")")
                    ForEach([("DNSKEY", x.llaves), ("DS", x.delegaciones), ("RRSIG", x.firmas), ("CAA", x.caa), ("TLSA", x.tlsa), ("DKIM", x.dkim)], id: \.0) { titulo, lista in
                        if !lista.isEmpty { Text("\(titulo): \(lista.joined(separator: " | "))") }
                    }
                }
                if let x = d.identidad {
                    Text("Documento: \(x.documento)")
                    ForEach(x.algoritmos, id: \.self) { Text($0) }
                    if let j = x.jwks { Text("JWKS: \(j) (\(x.llaves.count) llaves)") }
                    ForEach(x.certificados, id: \.self) { Text("Certificado \($0)") }
                }
                Divider()
                ForEach(d.hallazgos, id: \.self) { h in
                    HStack(alignment: .firstTextBaseline) {
                        Text(etiquetaNivel(h.nivel)).font(.caption.bold()).foregroundColor(colorNivel(h.nivel)).frame(width: 64, alignment: .leading)
                        Text(h.codigo).font(.caption.monospaced()).frame(width: 170, alignment: .leading)
                        Text(h.mensaje)
                    }
                }
                if let recetas = d.recetas, !recetas.isEmpty {
                    Divider()
                    Text("Cómo corregir").font(.callout.bold())
                    ForEach(recetas, id: \.self) { r in
                        Text("\(r.titulo) (\(r.hallazgos.joined(separator: ", ")))").bold()
                        ForEach(Array(r.pasos.enumerated()), id: \.offset) { i, paso in Text("  \(i + 1). \(paso)") }
                    }
                }
            }.textSelection(.enabled).font(.callout).padding(.vertical, 4)
        } label: {
            HStack {
                Circle().fill(colorNivel(d.peor)).frame(width: 10, height: 10)
                Text(d.objetivo).font(.headline)
                Spacer()
                if let g = d.tls?.moderno.grupo { Text(g).font(.caption.monospaced()) }
                Text(d.peor.map(etiquetaNivel) ?? "SIN HALLAZGOS").font(.caption.bold()).foregroundColor(colorNivel(d.peor))
            }
        }
    }
}

struct DiagnosisView: View {
    @StateObject private var model = DiagnosisModel()
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                TextField("www.ejemplo.mx  ssh://bastion:22  ike://vpn.ejemplo.mx  dns://ejemplo.mx  oidc://login.ejemplo.mx", text: $model.input)
                    .textFieldStyle(.roundedBorder).disabled(model.busy).onSubmit { model.run() }
                Button("Diagnosticar") { model.run() }.disabled(model.targets.isEmpty || model.busy).keyboardShortcut(.return)
                if model.busy { Button("Cancelar") { model.cancel() } }
            }
            HStack {
                Button("Autoridad propia (PEM)…") { model.chooseAuthority() }.disabled(model.busy)
                Text(model.authority?.lastPathComponent ?? "Autoridades del sistema").foregroundColor(.secondary).lineLimit(1)
                if model.authority != nil { Button("Quitar") { model.authority = nil }.disabled(model.busy) }
                Spacer()
                Button("Exportar JSON") { model.export() }.disabled(model.json == nil)
            }
            if model.busy { ProgressView().progressViewStyle(.linear) }
            Text(model.status).textSelection(.enabled)
            List(model.results) { d in DiagnosisRow(d: d) }
            Text("Diagnostique solo sistemas que administre o que tenga autorización expresa para evaluar. No se envían datos de aplicación.")
                .font(.caption).foregroundColor(.secondary)
        }
        .onDisappear { model.cancel() }
    }
}

struct ContentView: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Image(systemName: "shield.lefthalf.filled").font(.largeTitle).foregroundColor(.teal)
                VStack(alignment: .leading) {
                    Text("SUAYA 1.7").font(.largeTitle.bold())
                    Text("Inventario criptográfico, diagnóstico de red y preparación poscuántica").foregroundColor(.secondary)
                }
                Spacer()
            }
            TabView {
                InventoryView().padding(.top, 8).tabItem { Text("Inventario") }
                DiagnosisView().padding(.top, 8).tabItem { Text("Diagnóstico de red") }
            }
        }.padding(24).frame(minWidth: 900, minHeight: 620)
    }
}

struct InventoryView: View {
    @StateObject private var model = ScanModel()
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Button("Elegir archivo o carpeta") { model.choose() }.disabled(model.busy)
                Text(model.target?.path ?? "Sin objetivo seleccionado").lineLimit(1).truncationMode(.middle)
                if model.target != nil { Button("Quitar") { model.target = nil }.disabled(model.busy) }
                Spacer()
                Button("Escanear") { model.scan() }.disabled(!model.canScan).keyboardShortcut(.return)
                if model.busy { Button("Cancelar") { model.cancel() } }
            }
            HStack {
                Picker("Perfil", selection: $model.profile) {
                    ForEach(perfiles, id: \.0) { id, nombre in Text(nombre).tag(id) }
                }.frame(maxWidth: 280).disabled(model.busy)
                Button("Organización (TOML)…") { model.chooseOrganization() }.disabled(model.busy)
                Text(model.organization?.lastPathComponent ?? "Sin contexto").foregroundColor(.secondary).lineLimit(1)
                if model.organization != nil { Button("Quitar") { model.organization = nil }.disabled(model.busy) }
                Spacer()
                Toggle("Incluir el llavero de macOS", isOn: $model.keychain).disabled(model.busy)
                    .help("Agrega los certificados del llavero (raíces del sistema, llavero del sistema y del usuario). Nunca lee llaves privadas.")
            }
            if model.busy { ProgressView().progressViewStyle(.linear) }
            Text(model.status).textSelection(.enabled)
            HStack {
                Text("\(model.components.count) activos").font(.headline)
                Text("\(model.critical) críticos").foregroundColor(model.critical > 0 ? .red : .secondary)
                Spacer()
                Button("Exportar CBOM") { model.export(.cbom) }.disabled(model.cbom == nil)
                Button("Exportar HTML") { model.export(.html) }.disabled(model.html == nil)
                Button("Exportar CSV") { model.export(.csv) }.disabled(model.csv == nil)
                Button("Exportar SARIF") { model.export(.sarif) }.disabled(model.sarif == nil)
                Button("Limpiar") { model.clear() }
            }
            List(Array(model.components.enumerated()), id: \.offset) { _, name in Text(name).textSelection(.enabled) }
            Text("RSA, ECC y DH requieren evaluación de migración poscuántica independientemente de su tamaño. La clasificación y evidencia están en el reporte.")
                .font(.caption).foregroundColor(.secondary)
        }
        .onDisappear { model.cancel() }
    }
}
@main struct SuayaApp: App {
    var body: some Scene { WindowGroup { ContentView() }.commands { CommandGroup(replacing: .newItem) {} } }
}
