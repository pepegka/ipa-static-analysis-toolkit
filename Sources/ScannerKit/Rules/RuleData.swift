import Foundation

enum RuleData {

    static func decode<T: Decodable>(_ type: T.Type, _ relativePath: String) -> T {
        guard let url = locate(relativePath) else {
            fatalError("missing bundled data file Rules/\(relativePath)")
        }
        do {
            return try JSONDecoder().decode(type, from: Data(contentsOf: url))
        } catch {
            fatalError("could not read Rules/\(relativePath) at \(url.path): \(error)")
        }
    }

    static func text(_ relativePath: String) -> String {
        guard let url = locate(relativePath) else {
            fatalError("missing bundled data file Rules/\(relativePath)")
        }
        do {
            return try String(contentsOf: url, encoding: .utf8)
        } catch {
            fatalError("could not read Rules/\(relativePath) at \(url.path): \(error)")
        }
    }

    private static func locate(_ relativePath: String) -> URL? {
        if let installed = RuleUpdater.installedRulesDirectory()?.appendingPathComponent(relativePath),
           FileManager.default.fileExists(atPath: installed.path) {
            return installed
        }
        return Bundle.module.url(forResource: "Rules", withExtension: nil)?
            .appendingPathComponent(relativePath)
    }
}
