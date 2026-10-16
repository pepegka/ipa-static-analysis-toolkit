import Foundation

public struct Tracker: Codable, Sendable, Hashable, Identifiable {
    public var id: String
    public var name: String
    public var owner: String
    public var country: String
    public var category: String
    public var domains: [String]
    public var is_tracker: Bool?
    public var frameworks: [String]? = nil
    public var plistKeys: [String]? = nil

    public var isTracker: Bool { is_tracker ?? false }
}

public struct TrackerDB: Sendable {
    public let trackers: [Tracker]
    public let bySuffix: [String: Tracker]
    public let byRegistrable: [String: Tracker]
    public let byFramework: [String: Tracker]
    public let byPlistKey: [String: Tracker]

    public init(trackers: [Tracker]) {
        self.trackers = trackers
        var exact: [String: Tracker] = [:]
        var owner: [String: Tracker] = [:]
        var frameworks: [String: Tracker] = [:]
        var plistKeys: [String: Tracker] = [:]
        for t in trackers {
            for f in t.frameworks ?? [] where frameworks[f] == nil { frameworks[f] = t }
            for k in t.plistKeys ?? [] where plistKeys[k] == nil { plistKeys[k] = t }
            for d in t.domains {
                let lower = d.lowercased()
                if exact[lower] == nil { exact[lower] = t }
                let reg = PublicSuffixList.registrableDomain(for: lower)
                if PublicSuffixList.publicSuffix(of: lower) != lower, owner[reg] == nil { owner[reg] = t }
            }
        }
        self.bySuffix = exact
        self.byRegistrable = owner
        self.byFramework = frameworks
        self.byPlistKey = plistKeys
    }

    static let siteLabels: Set<String> = [
        "help", "docs", "doc", "developer", "developers", "support", "status", "blog",
        "community", "forum", "learn", "academy", "kb", "legal", "privacy", "careers", "press",
    ]

    public func classify(framework name: String) -> Tracker? { byFramework[name] }

    public func classify(plistKey key: String) -> Tracker? { byPlistKey[key] }

    public func classify(host: String) -> Tracker? {
        var current = host.lowercased()
        let site = bySuffix[current] == nil
            && current.split(separator: ".").first.map { Self.siteLabels.contains(String($0)) } == true
        while true {
            if var t = bySuffix[current] {
                if site { t.is_tracker = false }
                return t
            }
            guard let dot = current.firstIndex(of: ".") else { return nil }
            current = String(current[current.index(after: dot)...])
            if !current.contains(".") && bySuffix[current] == nil { return nil }
        }
    }

    public func owner(host: String) -> Tracker? {
        if let t = classify(host: host) { return t }
        return byRegistrable[PublicSuffixList.registrableDomain(for: host)]
    }
}

public enum TrackerDBLoader {
    private struct File: Decodable {
        let trackers: [Tracker]
    }

    public static func loadBundled() -> TrackerDB {
        guard let url = Bundle.module.url(forResource: "trackers", withExtension: "json",
                                          subdirectory: "Rules/trackers") else {
            return TrackerDB(trackers: [])
        }
        do {
            let data = try Data(contentsOf: url)
            let parsed = try JSONDecoder().decode(File.self, from: data)
            return TrackerDB(trackers: parsed.trackers)
        } catch {
            return TrackerDB(trackers: [])
        }
    }
}
