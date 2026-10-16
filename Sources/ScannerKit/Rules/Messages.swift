import Foundation

enum Messages {
    struct Compare: Decodable, Sendable, Hashable {
        let label: String
        let value: String?
        let kind: String
        let unit: String?
        let detail: String?

        enum CodingKeys: String, CodingKey { case label, value, kind, unit, detail }
        init(from d: any Decoder) throws {
            let c = try d.container(keyedBy: CodingKeys.self)
            label = try c.decode(String.self, forKey: .label)
            value = try c.decodeIfPresent(String.self, forKey: .value)
            kind = try c.decodeIfPresent(String.self, forKey: .kind) ?? "count"
            unit = try c.decodeIfPresent(String.self, forKey: .unit)
            detail = try c.decodeIfPresent(String.self, forKey: .detail)
        }
    }

    struct Entry: Decodable {
        let title: String
        let explanation: String
        let remediation: String?
        var references: [String] = []
        var compare: Compare?
        var values: [String: String] = [:]
        var maswe: [String]?
        var mastg: [String]?
        var polarity: Polarity?
        var userAdvice: String?

        enum CodingKeys: String, CodingKey { case title, explanation, remediation, references, compare, maswe, mastg, polarity, userAdvice }
        init(from d: any Decoder) throws {
            let c = try d.container(keyedBy: CodingKeys.self)
            title = try c.decode(String.self, forKey: .title)
            explanation = try c.decode(String.self, forKey: .explanation)
            remediation = try c.decodeIfPresent(String.self, forKey: .remediation)
            references = try c.decodeIfPresent([String].self, forKey: .references) ?? []
            compare = try c.decodeIfPresent(Compare.self, forKey: .compare)
            maswe = try c.decodeIfPresent([String].self, forKey: .maswe)
            mastg = try c.decodeIfPresent([String].self, forKey: .mastg)
            polarity = try c.decodeIfPresent(Polarity.self, forKey: .polarity)
            userAdvice = try c.decodeIfPresent(String.self, forKey: .userAdvice)
        }
        init(title: String, explanation: String, remediation: String?, references: [String],
             compare: Compare? = nil, values: [String: String] = [:]) {
            self.title = title; self.explanation = explanation
            self.remediation = remediation; self.references = references
            self.compare = compare; self.values = values
        }
    }
    private struct File: Decodable { let rules: [String: Entry] }

    private static let rules = RuleData.decode(File.self, "messages/findings.json").rules

    static var ruleIDs: [String] { rules.keys.sorted() }

    static func entry(_ ruleID: String, _ values: [String: String] = [:]) -> Entry {
        guard let e = rules[ruleID] else {
            fatalError("no copy for analyzer rule \(ruleID) in Rules/messages/findings.json")
        }
        guard !values.isEmpty else { return e }
        let title = fill(e.title, values), explanation = fill(e.explanation, values)
        assert((title + explanation).firstMatch(of: /\{[A-Za-z]+\}/) == nil,
               "\(ruleID): a placeholder was left unfilled")
        return Entry(title: title,
                     explanation: explanation,
                     remediation: e.remediation.map { fill($0, values) },
                     references: e.references,
                     compare: e.compare,
                     values: values)
    }

    static func substitute(_ text: String, _ values: [String: String]) -> String {
        fill(text, values)
    }

    private static func fill(_ text: String, _ values: [String: String]) -> String {
        var out = text
        for (key, value) in values {
            out = out.replacingOccurrences(of: "{\(key)}", with: value)
        }
        return out
    }

    static var knownRuleIDs: Set<String> { Set(rules.keys) }

    static func resolve(_ id: String) -> Entry? { rules[familyKey(id)] }

    static func familyKey(_ id: String) -> String {
        if rules[id] != nil { return id }
        var candidate = id
        while let dot = candidate.lastIndex(of: ".") {
            candidate = String(candidate[candidate.startIndex..<dot])
            if rules[candidate] != nil { return candidate }
        }
        if let dot = id.firstIndex(of: ".") {
            let wildcard = String(id[id.startIndex..<dot]) + ".*"
            if rules[wildcard] != nil { return wildcard }
        }
        return id
    }

    static func references(forRuleID id: String) -> [String] { resolve(id)?.references ?? [] }

    static func compare(forRuleID id: String) -> Compare? { resolve(id)?.compare }

    static func citations(forRuleID id: String) -> [String] {
        let own = binding(forRuleID: id)
        var seen = Set<String>()
        return (references(forRuleID: id) + MASLinks.urls(maswe: own?.maswe ?? [], mastg: own?.mastg ?? []))
            .filter { seen.insert($0).inserted }
    }

    static func userAdvice(ruleID: String, vectorID: String) -> String? {
        if let own = rules[ruleID]?.userAdvice, !own.isEmpty { return own }
        if let own = ruleAdvice[ruleID], !own.isEmpty { return own }
        let v = Vectors.byID[vectorID]?.userAdvice
        return (v?.isEmpty ?? true) ? nil : v
    }

    private static let ruleAdvice: [String: String] = Dictionary(
        RuleLoader.loadBundled().rules.compactMap { r in r.userAdvice.map { (r.id, $0) } },
        uniquingKeysWith: { first, _ in first })

    static func polarity(forRuleID id: String) -> Polarity? { resolve(id)?.polarity }

    static func binding(forRuleID id: String) -> (maswe: [String], mastg: [String])? {
        guard let e = resolve(id), e.maswe != nil || e.mastg != nil else { return nil }
        return (e.maswe ?? [], e.mastg ?? [])
    }
}
