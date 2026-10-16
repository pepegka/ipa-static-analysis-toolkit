import Foundation

public struct Evidence: Codable, Sendable, Hashable {
    public enum Kind: String, Codable, Sendable {
        case stringMatch
        case symbol
        case objcSelector
        case plistKey
        case plistValue
        case entitlement
        case linkedDylib
        case url
        case file
    }
    public let kind: Kind
    public let value: String
    public let source: String
    public let section: String?
    public let offset: UInt64?
    public let context: String?

    public init(kind: Kind, value: String, source: String, section: String? = nil, offset: UInt64? = nil, context: String? = nil) {
        self.kind = kind; self.value = value; self.source = source
        self.section = section; self.offset = offset; self.context = context
    }
}

public struct Finding: Codable, Sendable, Identifiable, Hashable {
    public let id: UUID
    public let ruleID: String
    public let vectorID: String
    public let title: String
    public var explanation: String
    public var severity: Severity
    public var evidences: [Evidence]
    public var owningFramework: String?
    public var owningFrameworks: [String]
    public var affectedBinaries: [String]
    public var permissionsRequired: [String]
    public var permissionsGranted: [String]
    public var mitre: [String]
    public var references: [String]
    public var masvs: [String]
    public var masvsControls: [String] = []
    public var remediation: String?
    public var mastg: [String] = []
    public var maswe: [String] = []
    public var cwe: [String] = []
    public var linddun: [String] = []
    public var solove: [String] = []
    public var gdpr: [String] = []
    public var cvss: String? = nil
    public var why: String? = nil
    public var metrics: [String: String] = [:]
    public var instance: String? = nil
    public var polarity: Polarity = .offensive
    var boundByRule = false

    public init(id: UUID = UUID(), ruleID: String, vectorID: String, title: String, explanation: String,
                severity: Severity, evidences: [Evidence],
                owningFramework: String? = nil, owningFrameworks: [String] = [],
                affectedBinaries: [String] = [],
                permissionsRequired: [String] = [], permissionsGranted: [String] = [],
                mitre: [String] = [], references: [String] = [],
                masvs: [String] = [], masvsControls: [String] = [], remediation: String? = nil,
                mastg: [String] = [], maswe: [String] = [], cwe: [String] = [], linddun: [String] = [],
                solove: [String] = [], gdpr: [String] = [], cvss: String? = nil,
                why: String? = nil,
                metrics: [String: String] = [:],
                boundByRule: Bool = false) {
        self.id = id; self.ruleID = ruleID; self.vectorID = vectorID
        self.title = title; self.explanation = explanation
        self.severity = severity
        self.evidences = evidences; self.owningFramework = owningFramework
        self.owningFrameworks = owningFrameworks
        self.affectedBinaries = affectedBinaries
        self.permissionsRequired = permissionsRequired
        self.permissionsGranted = permissionsGranted
        self.mitre = mitre; self.references = references
        self.masvs = masvs; self.masvsControls = masvsControls; self.remediation = remediation
        self.mastg = mastg; self.maswe = maswe; self.cwe = cwe; self.linddun = linddun
        self.solove = solove; self.gdpr = gdpr; self.cvss = cvss; self.why = why
        self.metrics = metrics
        self.boundByRule = boundByRule
    }

    enum CodingKeys: String, CodingKey {
        case id, ruleID, vectorID, title, explanation, severity,
             evidences, owningFramework, owningFrameworks, affectedBinaries,
             permissionsRequired, permissionsGranted, mitre, references,
             masvs, masvsControls, remediation, mastg, maswe, cwe, linddun, solove, gdpr, cvss, why,
             metrics, instance, polarity
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try c.decode(UUID.self, forKey: .id)
        self.ruleID = try c.decode(String.self, forKey: .ruleID)
        self.vectorID = try c.decode(String.self, forKey: .vectorID)
        self.title = try c.decode(String.self, forKey: .title)
        self.explanation = try c.decode(String.self, forKey: .explanation)
        self.severity = try c.decode(Severity.self, forKey: .severity)
        self.evidences = try c.decode([Evidence].self, forKey: .evidences)
        self.owningFramework = try c.decodeIfPresent(String.self, forKey: .owningFramework)
        self.owningFrameworks = try c.decodeIfPresent([String].self, forKey: .owningFrameworks) ?? []
        self.affectedBinaries = try c.decodeIfPresent([String].self, forKey: .affectedBinaries) ?? []
        self.permissionsRequired = try c.decodeIfPresent([String].self, forKey: .permissionsRequired) ?? []
        self.permissionsGranted = try c.decodeIfPresent([String].self, forKey: .permissionsGranted) ?? []
        self.mitre = try c.decode([String].self, forKey: .mitre)
        self.references = try c.decode([String].self, forKey: .references)
        self.masvs = try c.decodeIfPresent([String].self, forKey: .masvs) ?? []
        self.masvsControls = try c.decodeIfPresent([String].self, forKey: .masvsControls) ?? []
        self.remediation = try c.decodeIfPresent(String.self, forKey: .remediation)
        self.mastg = try c.decodeIfPresent([String].self, forKey: .mastg) ?? []
        self.maswe = try c.decodeIfPresent([String].self, forKey: .maswe) ?? []
        self.cwe = try c.decodeIfPresent([String].self, forKey: .cwe) ?? []
        self.linddun = try c.decodeIfPresent([String].self, forKey: .linddun) ?? []
        self.solove = try c.decodeIfPresent([String].self, forKey: .solove) ?? []
        self.gdpr = try c.decodeIfPresent([String].self, forKey: .gdpr) ?? []
        self.cvss = try c.decodeIfPresent(String.self, forKey: .cvss)
        self.why = try c.decodeIfPresent(String.self, forKey: .why)
        self.metrics = try c.decodeIfPresent([String: String].self, forKey: .metrics) ?? [:]
        self.instance = try c.decodeIfPresent(String.self, forKey: .instance)
        self.polarity = try c.decodeIfPresent(Polarity.self, forKey: .polarity) ?? .offensive
    }

    public var countsAsWeakness: Bool { polarity == .offensive }

    public func withSeverity(_ newSeverity: Severity, note: String? = nil) -> Finding {
        var f = self
        f.severity = newSeverity
        if let note { f.explanation = "\(explanation) \(note)" }
        return f
    }

    public func with(metrics: [String: String]) -> Finding {
        guard !metrics.isEmpty else { return self }
        var f = self; f.metrics = metrics; return f
    }

    public func withPolarity(_ p: Polarity) -> Finding {
        var f = self; f.polarity = p; return f
    }

    public func with(instance: String) -> Finding {
        var f = self; f.instance = instance; return f
    }

    public func annotatedWithCrosswalk() -> Finding {
        let cw = FrameworkCrosswalk.for(vectorID: vectorID)
        var f = self
        if let p = Messages.polarity(forRuleID: ruleID) { f.polarity = p }
        if let own = Messages.binding(forRuleID: ruleID) {
            f.maswe = own.maswe.sorted(); f.mastg = own.mastg.sorted()
        } else if boundByRule {
            f.maswe = maswe.sorted(); f.mastg = mastg.sorted()
        } else {
            f.maswe = Array(Set(maswe + cw.maswe)).sorted(); f.mastg = cw.mastg
        }
        let weaknesses = f.maswe.compactMap(MASWECatalog.entry)
        f.masvsControls = Array(Set(weaknesses.flatMap(\.masvsControls))).sorted()
        let publishedCWE = Array(Set(weaknesses.flatMap(\.cwe))).sorted()

        guard let anchor = SeverityDerivation.entry(ruleID: ruleID, vectorID: vectorID) else {
            f.cvss = cw.cvss; f.cwe = publishedCWE
            f.linddun = cw.linddun; f.solove = cw.solove; f.gdpr = cw.gdpr
            return f.withMessageReferences()
        }
        f.cvss = anchor.cvss
        f.why = anchor.why
        f.cwe = anchor.cwe ?? publishedCWE
        f.linddun = anchor.linddun ?? cw.linddun
        f.solove = anchor.solove ?? cw.solove
        f.gdpr = anchor.gdpr ?? cw.gdpr
        if let mitre = anchor.mitre { f.mitre = Array(Set(self.mitre + mitre)).sorted() }
        return f.withMessageReferences()
    }

    private func withMessageReferences() -> Finding {
        var f = self
        let fromData = Messages.references(forRuleID: ruleID)
        if !fromData.isEmpty { f.references = fromData }
        var seen = Set(f.references)
        for url in MASLinks.urls(maswe: f.maswe, mastg: f.mastg) where seen.insert(url).inserted {
            f.references.append(url)
        }
        return f
    }
}
