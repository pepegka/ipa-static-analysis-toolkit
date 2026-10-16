import Foundation

public enum RuleUpdater {

    public enum UpdateError: Error, CustomStringConvertible {
        case badResponse(Int)
        case missingApplicationSupport
        case extractionFailed(String)
        public var description: String {
            switch self {
            case .badResponse(let code): return "HTTP \(code)"
            case .missingApplicationSupport: return "No Application Support directory"
            case .extractionFailed(let s): return "Extraction failed: \(s)"
            }
        }
    }

    public static func installedRulesDirectory() -> URL? {
        guard let root = try? FileManager.default.url(for: .applicationSupportDirectory,
                                                      in: .userDomainMask,
                                                      appropriateFor: nil,
                                                      create: false) else { return nil }
        return root.appendingPathComponent("ISAT/Rules", isDirectory: true)
    }

    public static func downloadAndInstall(from url: URL) throws -> URL {
        guard let dir = installedRulesDirectory() else { throw UpdateError.missingApplicationSupport }
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        let (data, response) = try syncDownload(url)
        if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
            throw UpdateError.badResponse(http.statusCode)
        }

        let lower = url.path.lowercased()
        if lower.hasSuffix(".yaml") || lower.hasSuffix(".yml") {
            let dest = dir.appendingPathComponent("rules.yaml")
            try data.write(to: dest, options: .atomic)
        } else if lower.hasSuffix(".tar.gz") || lower.hasSuffix(".tgz") || lower.hasSuffix(".tar") {
            try extractTar(data: data, isGzipped: !lower.hasSuffix(".tar"), into: dir)
        } else {
            let dest = dir.appendingPathComponent("rules.yaml")
            try data.write(to: dest, options: .atomic)
        }
        let stamp = "\(ISO8601DateFormatter().string(from: .now))\n\(url.absoluteString)\n"
        try? stamp.data(using: .utf8)?.write(to: dir.appendingPathComponent("INSTALLED.txt"), options: .atomic)
        return dir
    }

    private static func syncDownload(_ url: URL) throws -> (Data, URLResponse) {
        final class Box: @unchecked Sendable {
            var data: Data?; var response: URLResponse?; var error: Error?
        }
        let box = Box()
        let sem = DispatchSemaphore(value: 0)
        let task = URLSession.shared.dataTask(with: url) { d, r, e in
            box.data = d; box.response = r; box.error = e; sem.signal()
        }
        task.resume()
        sem.wait()
        if let e = box.error { throw e }
        guard let d = box.data, let r = box.response else { throw UpdateError.badResponse(-1) }
        return (d, r)
    }

    private static func extractTar(data: Data, isGzipped: Bool, into dir: URL) throws {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("isat-rules-\(UUID().uuidString)\(isGzipped ? ".tar.gz" : ".tar")")
        try data.write(to: tmp, options: .atomic)
        defer { try? FileManager.default.removeItem(at: tmp) }
        let res = try Shell.run("/usr/bin/tar", [isGzipped ? "-xzf" : "-xf", tmp.path, "-C", dir.path])
        if res.exitCode != 0 { throw UpdateError.extractionFailed(res.stderrString) }
    }
}
