import SwiftUI
import ScannerKit

struct FileNode: Identifiable {
    let id: String
    let name: String
    let isDir: Bool
    let entry: FileManifestEntry?
    var children: [FileNode]?
}

func fileKindIcon(_ kind: String) -> String {
    switch kind {
    case "binary": return "cpu"
    case "plist": return "doc.badge.gearshape"
    case "image": return "photo"
    case "certificate": return "lock.doc"
    case "database": return "cylinder.split.1x2"
    case "archive": return "doc.zipper"
    case "script": return "terminal"
    case "font": return "textformat"
    case "media": return "play.rectangle"
    default: return "doc"
    }
}

struct FilesTab: View {
    let report: ScanReport
    @State private var filter = ""
    @State private var suspiciousOnly = false
    @State private var selection: String?

    var body: some View {
        if report.fileManifest.isEmpty {
            ContentUnavailableView("No file manifest", systemImage: "folder",
                description: Text("Re-scan to build the bundle file manifest."))
        } else {
            HSplitView {
                VStack(spacing: 0) {
                    HStack(spacing: 8) {
                        Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                        TextField("Filter …", text: $filter).textFieldStyle(.roundedBorder)
                        Toggle("Flagged", isOn: $suspiciousOnly).toggleStyle(.button).controlSize(.small)
                    }
                    .padding(8)
                    Divider()
                    List(selection: $selection) {
                        OutlineGroup(tree, children: \.children) { node in
                            FileNodeRow(node: node).tag(node.id)
                        }
                    }
                    .listStyle(.sidebar)
                }
                .frame(minWidth: 280, idealWidth: 340, maxWidth: 520)

                Group {
                    if let sel = selection, let entry = entryByPath[sel] {
                        FilePreview(report: report, entry: entry)
                            .id(sel)
                    } else {
                        ContentUnavailableView("Select a file",
                            systemImage: "doc.text.magnifyingglass",
                            description: Text("Pick a file in the bundle tree to preview its contents."))
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
    }

    private var filteredEntries: [FileManifestEntry] {
        report.fileManifest.filter { f in
            if suspiciousOnly && !f.isSuspicious { return false }
            if !filter.isEmpty {
                let q = filter.lowercased()
                if !f.relativePath.lowercased().contains(q) && !f.kind.lowercased().contains(q) { return false }
            }
            return true
        }
    }
    private var entryByPath: [String: FileManifestEntry] {
        Dictionary(uniqueKeysWithValues: report.fileManifest.map { ($0.relativePath, $0) })
    }
    private var tree: [FileNode] { Self.buildTree(filteredEntries) }

    static func buildTree(_ entries: [FileManifestEntry]) -> [FileNode] {
        final class Mut {
            var name = ""; var path = ""; var isDir = false
            var entry: FileManifestEntry?
            var children: [String: Mut] = [:]
        }
        let root = Mut()
        for e in entries {
            let parts = e.relativePath.split(separator: "/").map(String.init)
            var cur = root, acc = ""
            for (i, part) in parts.enumerated() {
                acc = acc.isEmpty ? part : acc + "/" + part
                let child: Mut
                if let existing = cur.children[part] { child = existing }
                else { let m = Mut(); m.name = part; m.path = acc; cur.children[part] = m; child = m }
                if i == parts.count - 1 { child.entry = e } else { child.isDir = true }
                cur = child
            }
        }
        func convert(_ m: Mut) -> FileNode {
            let kids = m.children.values.map(convert).sorted { a, b in
                if a.isDir != b.isDir { return a.isDir }
                return a.name.localizedCaseInsensitiveCompare(b.name) == .orderedAscending
            }
            return FileNode(id: m.path, name: m.name, isDir: m.isDir,
                            entry: m.entry, children: m.isDir ? kids : nil)
        }
        return root.children.values.map(convert).sorted { a, b in
            if a.isDir != b.isDir { return a.isDir }
            return a.name.localizedCaseInsensitiveCompare(b.name) == .orderedAscending
        }
    }
}

private struct FileNodeRow: View {
    let node: FileNode
    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: node.isDir ? "folder" : fileKindIcon(node.entry?.kind ?? "other"))
                .foregroundStyle(node.entry?.isSuspicious == true ? .orange : .secondary)
            Text(node.name).font(.callout).lineLimit(1).truncationMode(.middle)
            if node.entry?.isSuspicious == true {
                Image(systemName: "exclamationmark.triangle.fill").font(.caption2).foregroundStyle(.orange)
            }
            Spacer()
            if let e = node.entry {
                Text(ByteCountFormatter.string(fromByteCount: Int64(e.sizeBytes), countStyle: .file))
                    .font(.caption2.monospacedDigit()).foregroundStyle(.tertiary)
            }
        }
    }
}

private struct FilePreview: View {
    let report: ScanReport
    let entry: FileManifestEntry
    @EnvironmentObject var store: ScanStore
    @State private var state: LoadState = .loading

    enum LoadState {
        case loading, unavailable, tooLarge(UInt64)
        case text(String), image(NSImage), hex(String)
    }
    private static let maxPreviewBytes: UInt64 = 2 * 1024 * 1024

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            content
        }
        .task(id: entry.relativePath) { await load() }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Image(systemName: entry.isSuspicious ? "exclamationmark.triangle.fill" : fileKindIcon(entry.kind))
                    .foregroundStyle(entry.isSuspicious ? .orange : .secondary)
                Text(entry.name).font(.headline).lineLimit(1).truncationMode(.middle)
                Spacer()
                CategoryChip(category: entry.kind)
                Text(ByteCountFormatter.string(fromByteCount: Int64(entry.sizeBytes), countStyle: .file))
                    .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
            }
            Text(entry.relativePath).font(.caption2.monospaced()).foregroundStyle(.tertiary)
                .textSelection(.enabled).lineLimit(1).truncationMode(.middle)
            if let reason = entry.suspicionReason {
                Text("⚠︎ \(reason)").font(.caption2).foregroundStyle(.orange)
            }
            if let h = entry.sha256 {
                Text("sha256: \(h)").font(.caption2.monospaced()).foregroundStyle(.tertiary)
                    .textSelection(.enabled).lineLimit(1).truncationMode(.middle)
            }
        }
        .padding(10)
    }

    @ViewBuilder
    private var content: some View {
        switch state {
        case .loading:
            VStack { ProgressView(); Text("Loading…").font(.caption).foregroundStyle(.secondary) }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        case .unavailable:
            ContentUnavailableView("Can't read file", systemImage: "xmark.octagon",
                description: Text("The source IPA could not be re-extracted, or the file is unreadable."))
        case .tooLarge(let n):
            ContentUnavailableView("File too large to preview",
                systemImage: "doc",
                description: Text("\(ByteCountFormatter.string(fromByteCount: Int64(n), countStyle: .file)), exceeds the 2 MB preview limit."))
        case .text(let s):
            ScrollView([.vertical, .horizontal]) {
                Text(s).font(.caption.monospaced()).textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading).padding(10)
            }
        case .image(let img):
            ScrollView([.vertical, .horizontal]) {
                Image(nsImage: img).resizable().scaledToFit().padding(10)
            }
        case .hex(let s):
            ScrollView(.vertical) {
                Text(s).font(.caption2.monospaced()).textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading).padding(10)
            }
        }
    }

    private enum RawPreview: Sendable {
        case unavailable, text(String), imageData(Data), hex(String)
    }

    private func load() async {
        state = .loading
        if entry.sizeBytes > Self.maxPreviewBytes { state = .tooLarge(entry.sizeBytes); return }
        guard let root = await store.bundleRoot(for: report) else { state = .unavailable; return }
        let url = root.appendingPathComponent(entry.relativePath)
        let kind = entry.kind
        let raw: RawPreview = await Task.detached {
            guard let data = try? Data(contentsOf: url, options: [.mappedIfSafe]) else { return .unavailable }
            switch kind {
            case "image":
                return .imageData(data)
            case "plist":
                if let obj = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
                   let xml = try? PropertyListSerialization.data(fromPropertyList: obj, format: .xml, options: 0),
                   let s = String(data: xml, encoding: .utf8) {
                    return .text(s)
                }
                if let s = String(data: data, encoding: .utf8) { return .text(s) }
                return .hex(hexDump(data))
            case "text", "certificate", "script":
                if let s = String(data: data, encoding: .utf8) { return .text(s) }
                return .hex(hexDump(data))
            default:
                if let s = String(data: data, encoding: .utf8),
                   s.unicodeScalars.allSatisfy({ $0 == "\n" || $0 == "\t" || $0 == "\r" || ($0.value >= 32 && $0.value < 127) || $0.value > 160 }) {
                    return .text(s)
                }
                return .hex(hexDump(data))
            }
        }.value
        switch raw {
        case .unavailable:        state = .unavailable
        case .text(let s):        state = .text(s)
        case .hex(let s):         state = .hex(s)
        case .imageData(let d):   state = NSImage(data: d).map(LoadState.image) ?? .hex(hexDump(d))
        }
    }
}

private func hexDump(_ data: Data, limit: Int = 4096) -> String {
    let bytes = [UInt8](data.prefix(limit))
    var out = ""
    var i = 0
    while i < bytes.count {
        let row = Array(bytes[i..<min(i + 16, bytes.count)])
        let hex = row.map { String(format: "%02x", $0) }.joined(separator: " ")
            .padding(toLength: 47, withPad: " ", startingAt: 0)
        let ascii = row.map { (32..<127).contains($0) ? String(UnicodeScalar($0)) : "." }.joined()
        out += String(format: "%08x  ", i) + hex + "  " + ascii + "\n"
        i += 16
    }
    if data.count > limit { out += "… (\(data.count - limit) more bytes)\n" }
    return out
}
