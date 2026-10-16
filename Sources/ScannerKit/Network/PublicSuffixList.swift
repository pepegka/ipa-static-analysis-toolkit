import Foundation

enum PublicSuffixList {

    struct Rules {
        var exact: Set<String> = []
        var wildcard: Set<String> = []
        var exception: Set<String> = []
    }

    private static let text = RuleData.text("domains/public_suffix_list.dat")
    static let rules: Rules = parse(text)

    static let version: String? = {
        guard let r = text.range(of: "// VERSION: ") else { return nil }
        return String(text[r.upperBound...].prefix { $0 != "\n" })
    }()

    static func parse(_ text: String) -> Rules {
        var r = Rules()
        text.enumerateLines { raw, _ in
            let line = raw.split(whereSeparator: { $0 == " " || $0 == "\t" }).first.map(String.init) ?? ""
            if line.isEmpty || line.hasPrefix("//") { return }
            let rule = line.lowercased()
            if rule.hasPrefix("!") {
                r.exception.insert(String(rule.dropFirst()))
            } else if rule.hasPrefix("*.") {
                r.wildcard.insert(String(rule.dropFirst(2)))
            } else {
                r.exact.insert(rule)
            }
        }
        return r
    }

    static func publicSuffix(of host: String, rules: Rules = rules) -> String {
        let labels = normalized(host).split(separator: ".").map(String.init)
        guard !labels.isEmpty else { return host }
        for i in 0..<labels.count {
            let candidate = labels[i...].joined(separator: ".")
            if rules.exception.contains(candidate) {
                return labels[(i + 1)...].joined(separator: ".")
            }
            if rules.exact.contains(candidate) { return candidate }
            if i + 1 < labels.count {
                let parent = labels[(i + 1)...].joined(separator: ".")
                if rules.wildcard.contains(parent) { return candidate }
            }
        }
        return labels.last!
    }

    static func registrableDomain(for host: String, rules: Rules = rules) -> String {
        let h = normalized(host)
        let suffix = publicSuffix(of: h, rules: rules)
        guard h.count > suffix.count, h.hasSuffix("." + suffix) else { return h }
        let head = h.dropLast(suffix.count + 1)
        let owner = head.split(separator: ".").last.map(String.init) ?? String(head)
        return owner + "." + suffix
    }

    private static func normalized(_ host: String) -> String {
        var h = host.lowercased()
        while h.hasSuffix(".") { h.removeLast() }
        return h
    }
}
