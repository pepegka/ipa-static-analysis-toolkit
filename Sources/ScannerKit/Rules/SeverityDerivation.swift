import Foundation

public enum SeverityDerivation {

    struct Band: Decodable, Sendable { let min: Double; let severity: Severity }

    struct SeverityMap: Decodable, Sendable {
        let values: [String: Severity]
        private struct AnyKey: CodingKey {
            var stringValue: String; var intValue: Int? { nil }
            init?(stringValue: String) { self.stringValue = stringValue }
            init?(intValue: Int) { nil }
        }
        init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: AnyKey.self)
            var out: [String: Severity] = [:]
            for k in c.allKeys where !k.stringValue.hasPrefix("$") {
                out[k.stringValue] = try c.decode(Severity.self, forKey: k)
            }
            values = out
        }
        subscript(_ k: String) -> Severity? { values[k] }
    }

    public struct HighRisk: Decodable, Sendable {
        public let source: String
        public let url: String
        public let criteria: [String: String]
        public let threshold: Int
        public let atOrAbove: Severity
        public let below: Severity
        public let notScored: [Int]
    }

    public struct Entry: Decodable, Sendable {
        public let method: String
        public let cvss: String?
        public let cvssScore: Double?
        public let wp248: [Int]?
        public let wp248When: [String: [String]]?
        public let kind: String?
        public let gdpr: [String]?
        public let linddun: [String]?
        public let solove: [String]?
        public let cwe: [String]?
        public let mitre: [String]?
        public let why: String?
    }

    struct File: Decodable, Sendable {
        let cvssBands: [Band]
        let gdprHighRisk: HighRisk
        let trackerCategories: [String: [Int]]
        let compliance: SeverityMap
        let vectors: [String: Entry]
        let rules: [String: Entry]
    }

    static let file: File = RuleData.decode(File.self, "taxonomy/severity-derivation.json")

    public static var highRisk: HighRisk { file.gdprHighRisk }

    public static func anchorKey(ruleID: String, vectorID: String) -> String? {
        var key = ruleID
        while true {
            if file.rules[key] != nil { return key }
            guard let dot = key.lastIndex(of: ".") else { break }
            key = String(key[..<dot])
        }
        return file.vectors[vectorID] != nil ? vectorID : nil
    }

    public static func entry(ruleID: String, vectorID: String) -> Entry? {
        var key = ruleID
        while true {
            if let e = file.rules[key] { return e }
            guard let dot = key.lastIndex(of: ".") else { break }
            key = String(key[..<dot])
        }
        return file.vectors[vectorID]
    }

    public static func severity(ruleID: String, vectorID: String) -> Severity? {
        guard let e = entry(ruleID: ruleID, vectorID: vectorID) else { return nil }
        return severity(for: e)
    }

    static func severity(for e: Entry) -> Severity? {
        switch e.method {
        case "capability":
            return .info
        case "cvss":
            guard let score = e.cvssScore else { return nil }
            return band(for: score)
        case "privacy":
            guard let criteria = e.wp248 else { return nil }
            return severity(criteria: criteria)
        case "compliance":
            return e.kind.flatMap { file.compliance[$0] }
        default:
            return nil
        }
    }

    public static func criteria(for e: Entry, declaredKeys: Set<String>) -> [Int] {
        guard let all = e.wp248 else { return [] }
        return all.filter { c in
            guard let keys = e.wp248When?[String(c)] else { return true }
            return keys.contains(where: declaredKeys.contains)
        }
    }

    public static func unmetConditions(for e: Entry, declaredKeys: Set<String>) -> [(criterion: Int, keys: [String])] {
        guard let all = e.wp248, let when = e.wp248When else { return [] }
        return all.compactMap { c in
            guard let keys = when[String(c)], !keys.contains(where: declaredKeys.contains) else { return nil }
            return (c, keys)
        }
    }

    public static func severity(criteria: [Int]) -> Severity {
        let scored = Set(criteria).subtracting(file.gdprHighRisk.notScored)
        return scored.count >= file.gdprHighRisk.threshold ? file.gdprHighRisk.atOrAbove : file.gdprHighRisk.below
    }

    public static func trackerCriteria(category: String) -> [Int] {
        file.trackerCategories[category.lowercased()] ?? []
    }

    public static func trackerSeverity(category: String) -> Severity {
        severity(criteria: trackerCriteria(category: category))
    }

    public static func band(for score: Double) -> Severity {
        for b in file.cvssBands.sorted(by: { $0.min > $1.min }) where score >= b.min {
            return b.severity
        }
        return .info
    }

    public static var anchoredRuleIDs: Set<String> { Set(file.rules.keys) }
    public static var anchoredVectorIDs: Set<String> { Set(file.vectors.keys) }
}
