import Foundation

public enum StorageAnalyzer {

    static let sqliteMagic = Data("SQLite format 3\u{0}".utf8)

    static var encryptionMarkers: [String] { SecurityIndicators.storage.encryptionMarkers }

    static var databaseExtensions: Set<String> { SecurityIndicators.storage.databaseExtensions }

    public static func analyze(appDirectory: URL,
                               files: [URL],
                               linkedDylibs: [String],
                               indices: [String: BinaryIndex]) -> [Finding] {
        if hasEncryptionLayer(linkedDylibs: linkedDylibs, indices: indices) { return [] }

        let plaintextStores = files.filter { isPlaintextSQLite($0) }
        guard !plaintextStores.isEmpty else { return [] }

        let linksSQLite = linkedDylibs.contains { $0.lowercased().contains("libsqlite3") }
        let evidences = plaintextStores.prefix(50).map {
            Evidence(kind: .file,
                     value: $0.relativePath(from: appDirectory),
                     source: $0.relativePath(from: appDirectory))
        }

        let copy = Messages.entry("SECH-02.plaintext_sqlite", [
            "count": String(plaintextStores.count),
            "s": plaintextStores.count == 1 ? "" : "s",
            "ies": plaintextStores.count == 1 ? "ies" : "y",
            "sqliteNote": linksSQLite ? "" : ", though libsqlite3 itself is not linked by any binary",
        ])
        return [Finding(
            ruleID: "SECH-02.plaintext_sqlite",
            vectorID: "SECH-02",
            title: copy.title,
            explanation: copy.explanation,
            severity: .derived("SECH-02.plaintext_sqlite", "SECH-02"), evidences: Array(evidences),
            masvs: ["MASVS-STORAGE"],
            remediation: copy.remediation).with(metrics: copy.values)]
    }

    static func hasEncryptionLayer(linkedDylibs: [String], indices: [String: BinaryIndex]) -> Bool {
        if linkedDylibs.contains(where: { d in
            encryptionMarkers.contains { d.lowercased().contains($0.lowercased()) }
        }) { return true }
        for index in indices.values {
            let symbols = index.importedSymbols + index.definedSymbols
            if symbols.contains(where: { s in
                encryptionMarkers.contains { s.contains($0) }
            }) { return true }
        }
        return false
    }

    static func isPlaintextSQLite(_ url: URL) -> Bool {
        let ext = url.pathExtension.lowercased()
        guard databaseExtensions.contains(ext) || ext.isEmpty else { return false }
        guard let fh = try? FileHandle(forReadingFrom: url) else { return false }
        defer { try? fh.close() }
        guard let head = try? fh.read(upToCount: sqliteMagic.count) else { return false }
        return head == sqliteMagic
    }
}
