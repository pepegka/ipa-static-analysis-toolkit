import Foundation
import CryptoKit

enum FileManifestBuilder {

    public static let maxHashBytes: UInt64 = 64 * 1024 * 1024

    public static func build(appDirectory: URL, files: [URL]) -> [FileManifestEntry] {
        var entries: [FileManifestEntry] = []
        for url in files {
            var isDir: ObjCBool = false
            guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir),
                  !isDir.boolValue else { continue }
            let rel = url.relativePath(from: appDirectory)
            let size = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize).flatMap { UInt64($0) } ?? 0
            let kind = category(for: url)
            let hash = size <= maxHashBytes ? sha256(of: url) : nil
            let (suspicious, reason) = suspicion(rel: rel, url: url, kind: kind)
            entries.append(FileManifestEntry(relativePath: rel, name: url.lastPathComponent,
                                             sizeBytes: size, kind: kind, sha256: hash,
                                             isSuspicious: suspicious, suspicionReason: reason))
        }
        entries.sort { $0.relativePath < $1.relativePath }
        return entries
    }

    static func category(for url: URL) -> String {
        switch url.pathExtension.lowercased() {
        case "plist", "xcprivacy", "mobileprovision": return "plist"
        case "png", "jpg", "jpeg", "gif", "webp", "heic", "svg", "pdf", "car", "icns": return "image"
        case "cer", "der", "pem", "p12", "crt", "key": return "certificate"
        case "sqlite", "db", "sqlite3", "realm", "sql": return "database"
        case "zip", "ipa", "tar", "gz", "bundle": return "archive"
        case "sh", "command", "rb", "py", "pl", "js": return "script"
        case "json", "xml", "txt", "md", "strings", "stringsdict", "yaml", "yml", "csv": return "text"
        case "ttf", "otf", "woff", "woff2": return "font"
        case "mp3", "mp4", "mov", "m4a", "wav", "aif", "caf": return "media"
        case "": return MachOInspector.looksLikeMachO(url) ? "binary" : "other"
        default: return "other"
        }
    }

    static func suspicion(rel: String, url: URL, kind: String) -> (Bool, String?) {
        switch kind {
        case "script":      return (true, "Embedded executable script")
        case "certificate": return (true, "Embedded certificate / key material")
        case "database":    return (true, "Embedded database, check for bundled user data")
        case "archive" where url.pathExtension.lowercased() != "bundle":
            return (true, "Nested archive inside the bundle")
        default:
            let lower = url.lastPathComponent.lowercased()
            if lower.contains("debug") || lower.hasSuffix(".dSYM") || lower.contains(".env") {
                return (true, "Possible debug / configuration artifact")
            }
            return (false, nil)
        }
    }

    static func sha256(of url: URL) -> String? {
        guard let data = try? Data(contentsOf: url, options: [.mappedIfSafe]) else { return nil }
        return sha256(of: data)
    }

    static func sha256(of data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

extension MachOInspector {
    static func looksLikeMachO(_ url: URL) -> Bool {
        guard let fh = try? FileHandle(forReadingFrom: url) else { return false }
        defer { try? fh.close() }
        guard let head = try? fh.read(upToCount: 4), head.count == 4 else { return false }
        let magic = head.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }
        return [MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64,
                FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64].contains(magic)
    }
}
