import Foundation

public enum MASWECatalog {
    public struct Entry: Decodable, Sendable {
        public let title: String
        public let group: MASVSGroup
        public let url: String
        public let platforms: [String]
        public let profiles: [String]
        public let masvsControls: [String]
        public let cwe: [String]
        public let threat: String?
    }
    private struct File: Decodable {
        let version: String
        let weaknesses: [String: Entry]
    }
    private static let file = RuleData.decode(File.self, "taxonomy/maswe.json")

    public static var version: String { file.version }
    public static var allIDs: Set<String> { Set(file.weaknesses.keys) }

    public static func entry(_ id: String) -> Entry? { file.weaknesses[id] }
    public static func title(_ id: String) -> String? { file.weaknesses[id]?.title }
    public static func url(_ id: String) -> String? { file.weaknesses[id]?.url }
    public static func group(_ id: String) -> MASVSGroup? { file.weaknesses[id]?.group }
}

public enum MASTGCatalog {
    public struct Test: Decodable, Sendable {
        public let title: String
        public let group: MASVSGroup
        public let type: [String]
        public let maswe: [String]
        public let bestPractices: [String]
        public let url: String

        public var isStatic: Bool { type.contains("static") }
    }
    public struct Deprecated: Decodable, Sendable {
        public let title: String?
        public let coveredBy: [String]
        public let url: String
    }
    public struct BestPractice: Decodable, Sendable {
        public let title: String
        public let url: String
    }
    private struct File: Decodable {
        let version: String
        let tests: [String: Test]
        let deprecated: [String: Deprecated]
        let bestPractices: [String: BestPractice]
    }
    private static let file = RuleData.decode(File.self, "taxonomy/mastg.json")

    public static var version: String { file.version }
    public static var allTestIDs: Set<String> { Set(file.tests.keys) }
    public static var deprecatedIDs: Set<String> { Set(file.deprecated.keys) }

    public static func test(_ id: String) -> Test? { file.tests[id] }
    public static func bestPractice(_ id: String) -> BestPractice? { file.bestPractices[id] }
}

public enum MASVSCatalog {
    public struct Control: Decodable, Sendable {
        public let statement: String
        public let url: String
    }
    private struct File: Decodable {
        let version: String
        let controls: [String: Control]
    }
    private static let file = RuleData.decode(File.self, "taxonomy/masvs.json")

    public static var version: String { file.version }
    public static var allIDs: Set<String> { Set(file.controls.keys) }

    public static func control(_ id: String) -> Control? { file.controls[id] }
}

public enum MASLinks {
    public static func urls(maswe: [String], mastg: [String]) -> [String] {
        var out: [String] = []
        out += maswe.compactMap(MASWECatalog.url)
        let tests = mastg.compactMap(MASTGCatalog.test)
        out += tests.map(\.url)
        out += tests.flatMap(\.bestPractices).compactMap { MASTGCatalog.bestPractice($0)?.url }
        var seen = Set<String>()
        return out.filter { seen.insert($0).inserted }
    }
}
