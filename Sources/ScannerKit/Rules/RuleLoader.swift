import Foundation
import Yams

public enum RuleLoader {

    public static func loadBundled() -> RulePack {
        if let installed = RuleUpdater.installedRulesDirectory(),
           FileManager.default.fileExists(atPath: installed.path),
           let pack = loadFromDirectory(installed),
           !pack.rules.isEmpty {
            return pack
        }
        guard let root = Bundle.module.url(forResource: "Rules", withExtension: nil) else {
            return RulePack(rules: [], loadErrors: ["Bundled Rules directory not found"])
        }
        return load(from: root)
    }

    public static func loadFromDirectory(_ dir: URL) -> RulePack? {
        let pack = load(from: dir)
        return pack.rules.isEmpty ? nil : pack
    }

    public static func load(from directory: URL) -> RulePack {
        var rules: [Rule] = []
        var errors: [String] = []
        guard let enumerator = FileManager.default.enumerator(at: directory,
                                                              includingPropertiesForKeys: [.isRegularFileKey]) else {
            return RulePack(rules: [], loadErrors: ["Unable to enumerate \(directory.path)"])
        }
        let decoder = YAMLDecoder()
        for case let url as URL in enumerator {
            let ext = url.pathExtension.lowercased()
            guard ext == "yaml" || ext == "yml" else { continue }
            let path = url.path
            if path.contains("/suppressions/") { continue }
            do {
                let data = try Data(contentsOf: url)
                guard let text = String(data: data, encoding: .utf8) else {
                    errors.append("\(url.lastPathComponent): non-UTF8")
                    continue
                }
                let stripped = text.split(separator: "\n").filter {
                    let s = $0.trimmingCharacters(in: .whitespaces)
                    return !s.isEmpty && !s.hasPrefix("#")
                }
                if stripped.isEmpty { continue }
                if let list = try? decoder.decode([Rule].self, from: text) {
                    rules.append(contentsOf: list)
                } else if let single = try? decoder.decode(Rule.self, from: text) {
                    rules.append(single)
                } else {
                    _ = try decoder.decode([Rule].self, from: text)
                }
            } catch {
                errors.append("\(url.lastPathComponent): \(error)")
            }
        }
        var byID: [String: Rule] = [:]
        for r in rules { byID[r.id] = r }
        return RulePack(rules: Array(byID.values).sorted { $0.id < $1.id },
                        loadErrors: errors)
    }
}
