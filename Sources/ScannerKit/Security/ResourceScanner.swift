import Foundation

enum ResourceScanner {

    public struct Result: Sendable {
        public let secrets: [SecretHit]
        public let endpoints: [ExtractedEndpoint]
        public let findings: [Finding]
        public static let empty = Result(secrets: [], endpoints: [], findings: [])
    }

    private static var textExtensions: Set<String> { SecurityIndicators.resourceScan.textExtensions }
    private static var maxFileBytes: Int { SecurityIndicators.resourceScan.maxFileBytes }
    private static var maxLinesPerFile: Int { SecurityIndicators.resourceScan.maxLinesPerFile }

    public static func scan(appDirectory: URL, files: [URL]) -> Result {
        var items: [SecretScanner.TextItem] = []
        var endpoints: [ExtractedEndpoint] = []
        var publicConfigs: Set<String> = []
        var publicClientValues: [String: SecretScanner.PublicClientValue] = [:]
        var fixtures: Set<String> = []

        for url in files {
            let ext = url.pathExtension.lowercased()
            guard textExtensions.contains(ext) else { continue }
            let name = url.lastPathComponent
            if name == "Info.plist" || name == "PrivacyInfo.xcprivacy" { continue }

            guard let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
                  let size = attrs[.size] as? Int, size > 0, size <= maxFileBytes else { continue }
            guard let data = try? Data(contentsOf: url, options: [.mappedIfSafe]),
                  let text = decodeText(data) else { continue }

            let rel = url.relativePath(from: appDirectory)
            if SecretScanner.vendorFixture(sha256: FileManifestBuilder.sha256(of: data)) != nil {
                fixtures.insert(rel)
            }
            let document = structuredDocument(data, ext: ext)
            if ext == "plist", let plist = document, SecretScanner.isPublicClientConfig(plist) {
                publicConfigs.insert(rel)
            }
            if let document {
                publicClientValues.merge(SecretScanner.publicClientValues(in: document)) { a, _ in a }
            }
            publicClientValues.merge(SecretScanner.oauthClientSecrets(inText: text)) { a, _ in a }
            if text.contains("PRIVATE KEY-----") { items.append((text, rel, nil)) }
            for line in text.split(whereSeparator: { $0 == "\n" || $0 == "\r" }).prefix(maxLinesPerFile) {
                items.append((String(line), rel, nil))
            }
            if ReferenceDocuments.match(fileName: name, text: text) == nil {
                if isLocalizationTable(rel), let document {
                    let values = stringValues(of: document).joined(separator: "\n")
                    endpoints.append(contentsOf: URLExtractor.extract(fromString: values, source: rel))
                } else if isLocalizationTable(rel) {
                    endpoints.append(contentsOf: URLExtractor.extract(fromString: text, source: rel)
                        .filter { $0.kind == .absoluteURL })
                } else {
                    endpoints.append(contentsOf: URLExtractor.extract(fromString: text, source: rel))
                }
            }
        }

        let secrets = SecretScanner.hits(in: items, publicConfigSources: publicConfigs,
                                         publicClientValues: publicClientValues,
                                         fixtureSources: fixtures)
        return Result(secrets: secrets,
                      endpoints: endpoints,
                      findings: SecretScanner.findings(from: secrets))
    }

    static func structuredDocument(_ data: Data, ext: String) -> Any? {
        switch ext {
        case "plist", "strings", "stringsdict":
            return try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        case "json":
            return try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
        default:
            return nil
        }
    }

    static func isLocalizationTable(_ rel: String) -> Bool {
        let lower = rel.lowercased()
        let base = (lower as NSString).lastPathComponent
        return lower.hasSuffix(".strings") || lower.hasSuffix(".stringsdict")
            || lower.contains(".lproj/")
            || (base.contains("localizable") && base.hasSuffix(".json"))
    }

    static func stringValues(of document: Any) -> [String] {
        var out: [String] = []
        func walk(_ x: Any) {
            if let dict = x as? [String: Any] { for v in dict.values { walk(v) } }
            else if let arr = x as? [Any] { for v in arr { walk(v) } }
            else if let s = x as? String { out.append(s) }
        }
        walk(document)
        return out.sorted()
    }

    private static func decodeText(_ data: Data) -> String? {
        if let s = String(data: data, encoding: .utf8) { return s }
        return String(data: data, encoding: .isoLatin1)
    }
}
