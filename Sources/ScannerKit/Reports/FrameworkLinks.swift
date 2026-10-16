import Foundation

public struct FrameworkRef: Sendable, Hashable {
    public let id: String
    public let url: String?
    public let title: String?
}

public enum FrameworkLinks {

    public static func masvsControls(_ ids: [String]) -> [FrameworkRef] {
        ids.map { id in
            let c = MASVSCatalog.control(id)
            return FrameworkRef(id: id, url: c?.url, title: c?.statement)
        }
    }

    static let profileNames: [(code: String, name: String)] = [
        ("L1", "Essential Security"), ("L2", "Advanced Security"), ("R", "Resilient Security"),
        ("P", "Baseline Privacy"), ("EUDIW", "EU Digital Identity Wallet"),
    ]

    public static func profiles(maswe ids: [String]) -> [String] {
        let known = ["L1", "L2", "P", "R"]
        let all = Set(ids.compactMap(MASWECatalog.entry).flatMap(\.profiles))
        return known.filter(all.contains)
    }

    public static func profileLabels(maswe ids: [String]) -> [String] {
        let all = Set(ids.compactMap(MASWECatalog.entry).flatMap(\.profiles))
        return profileNames.filter { all.contains($0.code) }.map { "MAS-\($0.code) \u{00B7} \($0.name)" }
    }

    public static func maswe(_ ids: [String]) -> [FrameworkRef] {
        ids.map { FrameworkRef(id: $0, url: MASWECatalog.url($0), title: MASWECatalog.title($0)) }
    }

    public static func mastg(_ ids: [String]) -> [FrameworkRef] {
        ids.map { id in
            let t = MASTGCatalog.test(id)
            return FrameworkRef(id: id, url: t?.url, title: t?.title)
        }
    }

    public static func cwe(_ ids: [String]) -> [FrameworkRef] {
        ids.map { id in
            let n = id.hasPrefix("CWE-") ? Int(id.dropFirst(4)) : nil
            return FrameworkRef(id: id, url: n.map { "https://cwe.mitre.org/data/definitions/\($0).html" }, title: nil)
        }
    }

    public static func attack(_ ids: [String]) -> [FrameworkRef] {
        ids.map { id in
            let ok = id.wholeMatch(of: /T\d{4}(\.\d{3})?/) != nil
            let path = id.replacingOccurrences(of: ".", with: "/")
            return FrameworkRef(id: id, url: ok ? "https://attack.mitre.org/techniques/\(path)/" : nil, title: nil)
        }
    }

    public static func cvss(_ vector: String) -> FrameworkRef {
        FrameworkRef(id: vector,
                     url: vector.hasPrefix("CVSS:4.0/") ? "https://www.first.org/cvss/calculator/4.0#\(vector)" : nil,
                     title: nil)
    }
}
