import Foundation

public struct ExtractedIPA: Sendable {
    public let ipaURL: URL
    public let workingDirectory: URL
    public let payloadDirectory: URL
    public let appDirectory: URL
}

public enum IPAExtractorError: Error, CustomStringConvertible {
    case notAFile(URL)
    case unzipFailed(String)
    case payloadNotFound
    case noAppBundle
    case insufficientDiskSpace(availableBytes: Int64, requiredBytes: Int64)

    public var description: String {
        switch self {
        case .notAFile(let u): return "Not a file: \(u.path)"
        case .unzipFailed(let s): return "Unzip failed: \(s)"
        case .payloadNotFound: return "No Payload/ directory inside IPA"
        case .noAppBundle: return "No .app bundle inside Payload/"
        case .insufficientDiskSpace(let have, let need):
            return "Insufficient disk space to extract: \(IPAExtractor.byteStr(have)) free, " +
                   "need \(IPAExtractor.byteStr(need))"
        }
    }
}

public enum IPAExtractor {

    public static let tempPrefix = "ISAT-"

    public static let minFreeBytes: Int64 = 5_000_000_000

    private final class ActiveRegistry: @unchecked Sendable {
        static let shared = ActiveRegistry()
        private let lock = NSLock()
        private var paths: Set<String> = []
        func add(_ url: URL) { lock.lock(); paths.insert(url.path); lock.unlock() }
        func remove(_ url: URL) { lock.lock(); paths.remove(url.path); lock.unlock() }
        func snapshot() -> [String] { lock.lock(); defer { lock.unlock() }; return Array(paths) }
    }

    public static func extract(ipa: URL) throws -> ExtractedIPA {
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: ipa.path, isDirectory: &isDir), !isDir.boolValue else {
            throw IPAExtractorError.notAFile(ipa)
        }

        let tmpRoot = FileManager.default.temporaryDirectory

        let ipaSize = (try? FileManager.default.attributesOfItem(atPath: ipa.path)[.size] as? Int64) ?? nil ?? 0
        let required = max(minFreeBytes, ipaSize * 2)
        if let available = availableBytes(at: tmpRoot), available < required {
            throw IPAExtractorError.insufficientDiskSpace(availableBytes: available, requiredBytes: required)
        }

        let tmp = tmpRoot.appendingPathComponent("\(tempPrefix)\(UUID().uuidString.prefix(8))", isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        ActiveRegistry.shared.add(tmp)

        do {
            let res = try Shell.run("/usr/bin/unzip", ["-q", "-o", ipa.path, "-d", tmp.path])
            if res.exitCode != 0 && res.exitCode != 1 {
                throw IPAExtractorError.unzipFailed(res.stderrString.isEmpty ? "exit \(res.exitCode)" : res.stderrString)
            }

            let payload = tmp.appendingPathComponent("Payload", isDirectory: true)
            var pIsDir: ObjCBool = false
            guard FileManager.default.fileExists(atPath: payload.path, isDirectory: &pIsDir), pIsDir.boolValue else {
                throw IPAExtractorError.payloadNotFound
            }

            let contents = try FileManager.default.contentsOfDirectory(at: payload, includingPropertiesForKeys: nil)
            guard let app = contents.first(where: { $0.pathExtension == "app" }) else {
                throw IPAExtractorError.noAppBundle
            }

            return ExtractedIPA(ipaURL: ipa, workingDirectory: tmp, payloadDirectory: payload, appDirectory: app)
        } catch {
            ActiveRegistry.shared.remove(tmp)
            try? FileManager.default.removeItem(at: tmp)
            throw error
        }
    }

    public static func cleanup(_ extracted: ExtractedIPA) {
        ActiveRegistry.shared.remove(extracted.workingDirectory)
        try? FileManager.default.removeItem(at: extracted.workingDirectory)
    }

    @discardableResult
    public static func cleanupActive() -> Int {
        var removed = 0
        for path in ActiveRegistry.shared.snapshot() {
            ActiveRegistry.shared.remove(URL(fileURLWithPath: path))
            if (try? FileManager.default.removeItem(atPath: path)) != nil { removed += 1 }
        }
        return removed
    }

    @discardableResult
    public static func sweepStaleTempDirs() -> (count: Int, bytes: Int64) {
        let fm = FileManager.default
        let root = fm.temporaryDirectory
        guard let entries = try? fm.contentsOfDirectory(at: root,
                                                        includingPropertiesForKeys: [.totalFileAllocatedSizeKey],
                                                        options: [.skipsHiddenFiles]) else {
            return (0, 0)
        }
        var count = 0
        var bytes: Int64 = 0
        for url in entries where url.lastPathComponent.hasPrefix(tempPrefix) {
            bytes += directorySize(url)
            if (try? fm.removeItem(at: url)) != nil { count += 1 }
        }
        return (count, bytes)
    }

    public static func availableBytes(at url: URL) -> Int64? {
        if let vals = try? url.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey]),
           let cap = vals.volumeAvailableCapacityForImportantUsage {
            return cap
        }
        if let attrs = try? FileManager.default.attributesOfFileSystem(forPath: url.path),
           let free = attrs[.systemFreeSize] as? NSNumber {
            return free.int64Value
        }
        return nil
    }

    private static func directorySize(_ url: URL) -> Int64 {
        let fm = FileManager.default
        guard let en = fm.enumerator(at: url, includingPropertiesForKeys: [.totalFileAllocatedSizeKey]) else { return 0 }
        var total: Int64 = 0
        for case let f as URL in en {
            if let v = try? f.resourceValues(forKeys: [.totalFileAllocatedSizeKey]),
               let s = v.totalFileAllocatedSize { total += Int64(s) }
        }
        return total
    }

    static func byteStr(_ bytes: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
    }
}
