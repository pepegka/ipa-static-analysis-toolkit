import Foundation
import Yams

struct Suppression: Codable, Sendable, Hashable {
    public let id: String
    public let reason: String
    public let ruleID: String?
    public let valuePattern: String?
    public let binaryGlob: String?
    public let vectorID: String?

    enum CodingKeys: String, CodingKey {
        case id, reason
        case ruleID = "rule_id"
        case valuePattern = "value_pattern"
        case binaryGlob = "binary_glob"
        case vectorID = "vector_id"
    }
}

enum SuppressionLoader {
    public static func load(from dir: URL) -> [Suppression] {
        var out: [Suppression] = []
        let dec = YAMLDecoder()
        guard let en = FileManager.default.enumerator(at: dir,
                                                      includingPropertiesForKeys: [.isRegularFileKey]) else { return [] }
        for case let url as URL in en {
            let ext = url.pathExtension.lowercased()
            guard ext == "yaml" || ext == "yml" else { continue }
            guard let text = try? String(contentsOf: url, encoding: .utf8) else { continue }
            if let list = try? dec.decode([Suppression].self, from: text) {
                out.append(contentsOf: list)
            } else if let single = try? dec.decode(Suppression.self, from: text) {
                out.append(single)
            }
        }
        return out
    }

    public static func loadBundled() -> [Suppression] {
        if let installed = RuleUpdater.installedRulesDirectory()?
            .appendingPathComponent("suppressions", isDirectory: true),
           FileManager.default.fileExists(atPath: installed.path) {
            let list = load(from: installed)
            if !list.isEmpty { return list }
        }
        guard let root = Bundle.module.url(forResource: "Rules", withExtension: nil)?
            .appendingPathComponent("suppressions", isDirectory: true),
              FileManager.default.fileExists(atPath: root.path) else { return [] }
        return load(from: root)
    }
}

enum SuppressionEngine {

    private static func ruleMatches(_ suppRuleID: String, _ f: Finding) -> Bool {
        suppRuleID == f.ruleID
    }

    public static func apply(_ suppressions: [Suppression],
                             to findings: [Finding]) -> (kept: [Finding], firedIDs: Set<String>) {
        if suppressions.isEmpty { return (findings, []) }
        var fired: Set<String> = []
        var kept: [Finding] = []
        let compiled: [(s: Suppression, regex: NSRegularExpression?)] = suppressions.map {
            ($0, $0.valuePattern.flatMap { try? NSRegularExpression(pattern: $0) })
        }

        for f in findings {
            var drop = false
            for (s, _) in compiled where s.valuePattern == nil {
                if let r = s.ruleID, !ruleMatches(r, f) { continue }
                if let v = s.vectorID, v != f.vectorID { continue }
                if let g = s.binaryGlob {
                    if f.affectedBinaries.isEmpty { continue }
                    if !f.affectedBinaries.allSatisfy({ fnmatch($0, glob: g) }) { continue }
                }
                drop = true; fired.insert(s.id); break
            }
            if drop { continue }

            var ev = f.evidences
            let valueSuppressors = compiled.filter { $0.s.valuePattern != nil }
            if !valueSuppressors.isEmpty {
                ev = ev.filter { e in
                    for (s, re) in valueSuppressors {
                        if let r = s.ruleID, !ruleMatches(r, f) { continue }
                        if let v = s.vectorID, v != f.vectorID { continue }
                        if let g = s.binaryGlob, !fnmatch(e.source, glob: g) { continue }
                        guard let re else { continue }
                        let range = NSRange(location: 0, length: (e.value as NSString).length)
                        if re.firstMatch(in: e.value, options: [], range: range) != nil {
                            fired.insert(s.id)
                            return false
                        }
                    }
                    return true
                }
            }
            if ev.isEmpty && !f.permissionsRequired.isEmpty == false && f.evidences.isEmpty == false {
                continue
            }
            if ev.count == f.evidences.count {
                kept.append(f)
            } else if ev.isEmpty {
                continue
            } else {
                var g = f
                g.evidences = ev
                g.affectedBinaries = Array(Set(ev.map(\.source))).sorted()
                kept.append(g)
            }
        }
        return (kept, fired)
    }

    private static func fnmatch(_ s: String, glob: String) -> Bool {
        var rx = ""
        for c in glob {
            switch c {
            case "*": rx += ".*"
            case "?": rx += "."
            case ".", "+", "(", ")", "[", "]", "{", "}", "^", "$", "|", "\\":
                rx += "\\\(c)"
            default: rx.append(c)
            }
        }
        guard let re = try? NSRegularExpression(pattern: "^\(rx)$") else { return false }
        let r = NSRange(location: 0, length: (s as NSString).length)
        return re.firstMatch(in: s, options: [], range: r) != nil
    }
}
