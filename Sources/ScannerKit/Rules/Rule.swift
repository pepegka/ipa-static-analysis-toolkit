import Foundation

public struct Rule: Codable, Sendable, Hashable {

    public enum SearchKind: String, Codable, Sendable {
        case string
        case symbol
        case importedSymbol
        case definedSymbol
        case dylib
        case plistKey
        case plistValue
        case urlScheme
        case backgroundMode
        case entitlement
        case bundleID
        case frameworkName
    }

    public struct Search: Codable, Sendable, Hashable {
        public let kind: SearchKind
        public let pattern: String
        public var caseSensitive: Bool = false
        public var sections: [String]? = nil

        enum CodingKeys: String, CodingKey {
            case kind, pattern
            case caseSensitive = "case_sensitive"
            case sections
        }
        public init(kind: SearchKind, pattern: String, caseSensitive: Bool = false, sections: [String]? = nil) {
            self.kind = kind; self.pattern = pattern; self.caseSensitive = caseSensitive; self.sections = sections
        }
        public init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            self.kind = try c.decode(SearchKind.self, forKey: .kind)
            self.pattern = try c.decode(String.self, forKey: .pattern)
            self.caseSensitive = try c.decodeIfPresent(Bool.self, forKey: .caseSensitive) ?? false
            self.sections = try c.decodeIfPresent([String].self, forKey: .sections)
        }
    }

    public struct Attribution: Codable, Sendable, Hashable {
        public var benignInFrameworks: [String] = []
        public var primaryFramework: String? = nil

        enum CodingKeys: String, CodingKey {
            case benignInFrameworks = "benign_in_frameworks"
            case primaryFramework = "primary_framework"
        }
        public init(benignInFrameworks: [String] = [], primaryFramework: String? = nil) {
            self.benignInFrameworks = benignInFrameworks; self.primaryFramework = primaryFramework
        }
        public init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            self.benignInFrameworks = try c.decodeIfPresent([String].self, forKey: .benignInFrameworks) ?? []
            self.primaryFramework = try c.decodeIfPresent(String.self, forKey: .primaryFramework)
        }
    }

    public let id: String
    public let vector: String
    public let title: String
    public let description: String
    public let severity: Severity
    public let search: [Search]
    public var attribution: Attribution = Attribution()
    public var references: [String] = []
    public var mitre: [String] = []
    public var masvs: [String] = []
    public var maswe: [String]? = nil
    public var mastg: [String]? = nil
    public var polarity: Polarity = .offensive
    public var remediation: String? = nil
    public var maxEvidence: Int = 500
    public var requiresPermission: [String] = []
    public var trackerIDs: [String] = []
    public var userAdvice: String? = nil

    public var citations: [String] {
        var seen = Set<String>()
        return (references + MASLinks.urls(maswe: maswe ?? [], mastg: mastg ?? []))
            .filter { seen.insert($0).inserted }
    }

    enum CodingKeys: String, CodingKey {
        case id
        case vector, title
        case description, severity
        case search, attribution, references, mitre, masvs, maswe, mastg, polarity, remediation
        case maxEvidence = "max_evidence"
        case requiresPermission = "requires_permission"
        case trackerIDs = "tracker_ids"
        case userAdvice = "user_advice"
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try c.decode(String.self, forKey: .id)
        self.vector = try c.decode(String.self, forKey: .vector)
        self.title = try c.decode(String.self, forKey: .title)
        self.description = Self.unwrap(try c.decode(String.self, forKey: .description))
        self.severity = try c.decode(Severity.self, forKey: .severity)
        self.search = try c.decode([Search].self, forKey: .search)
        self.attribution = try c.decodeIfPresent(Attribution.self, forKey: .attribution) ?? Attribution()
        self.references = try c.decodeIfPresent([String].self, forKey: .references) ?? []
        self.mitre = try c.decodeIfPresent([String].self, forKey: .mitre) ?? []
        self.masvs = try c.decodeIfPresent([String].self, forKey: .masvs) ?? []
        self.maswe = try c.decodeIfPresent([String].self, forKey: .maswe)
        self.mastg = try c.decodeIfPresent([String].self, forKey: .mastg)
        self.polarity = try c.decodeIfPresent(Polarity.self, forKey: .polarity) ?? .offensive
        self.remediation = try c.decodeIfPresent(String.self, forKey: .remediation)
        self.maxEvidence = try c.decodeIfPresent(Int.self, forKey: .maxEvidence) ?? 500
        self.userAdvice = try c.decodeIfPresent(String.self, forKey: .userAdvice).map(Self.unwrap)
        self.requiresPermission = try c.decodeIfPresent([String].self, forKey: .requiresPermission) ?? []
        self.trackerIDs = try c.decodeIfPresent([String].self, forKey: .trackerIDs) ?? []
    }

    public init(id: String, vector: String, title: String,
                description: String, severity: Severity,
                search: [Search],
                attribution: Attribution = Attribution(), references: [String] = [],
                mitre: [String] = [], masvs: [String] = [], maswe: [String]? = nil, mastg: [String]? = nil,
                polarity: Polarity = .offensive, remediation: String? = nil,
                maxEvidence: Int = 500, requiresPermission: [String] = []) {
        self.id = id; self.vector = vector; self.title = title
        self.description = description; self.severity = severity
        self.search = search
        self.attribution = attribution
        self.references = references; self.mitre = mitre; self.masvs = masvs; self.maswe = maswe; self.mastg = mastg
        self.polarity = polarity; self.remediation = remediation
        self.maxEvidence = maxEvidence
        self.requiresPermission = requiresPermission
    }
}

public struct RulePack: Sendable {
    public let rules: [Rule]
    public let loadErrors: [String]
    public init(rules: [Rule], loadErrors: [String] = []) {
        self.rules = rules; self.loadErrors = loadErrors
    }
}

extension Rule {
    static func unwrap(_ text: String) -> String {
        text.trimmingCharacters(in: .whitespacesAndNewlines)
            .components(separatedBy: "\n\n")
            .map { $0.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }.joined(separator: " ") }
            .joined(separator: "\n\n")
    }
}
