import Foundation

struct ExtractedEndpoint: Sendable, Hashable {
    public enum Kind: String, Sendable, Hashable {
        case absoluteURL
        case bareHost
    }
    public let kind: Kind
    public let raw: String
    public let host: String
    public let registrableDomain: String
    public let scheme: String?
    public let path: String?
    public let source: String
    public let section: String?
    public let offset: UInt64?
    public let isUTF16: Bool
}

enum URLExtractor {

    private static let combinedPattern =
        #"(?ix)"# +
        #"(?:"# +
            #"(?:(https?)://)"# +
            #"([a-z0-9.-]+\.[a-z]{2,})"# +
            #"(/[^\s'""<>\\\)`]*)?"# +
        #"|"# +
            #"\b([a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+){1,4}\.([a-z]{2,16}))\b"# +
        #")"#

    private static let regex: NSRegularExpression = {
        try! NSRegularExpression(pattern: combinedPattern, options: [.caseInsensitive])
    }()

    private struct TLDTables: Decodable {
        let accepted: Set<String>
        let denylist: Set<String>
        let reverseDNSRoots: Set<String>
        let reverseDNSRootsFourLabels: Set<String>
    }

    private static let tlds = RuleData.decode(TLDTables.self, "domains/tlds.json")

    private static var acceptedTLDs: Set<String> { tlds.accepted }
    private static var denylist: Set<String> { tlds.denylist }

    public static func extract(from index: BinaryIndex) -> [ExtractedEndpoint] {
        var out: [ExtractedEndpoint] = []
        out.reserveCapacity(64)
        var seen: Set<String> = []
        var domainCache: [String: String] = [:]
        for ss in index.perSectionStrings {
            let qname = ss.section.qualifiedName
            for s in ss.strings {
                if s.value.utf8.count > 2048 { continue }
                let v = s.value
                if !v.contains(".") { continue }
                extractInto(string: v, source: index.relativePath, section: qname,
                            offset: s.offset, isUTF16: s.isUTF16,
                            seen: &seen, domainCache: &domainCache, into: &out)
            }
        }
        return out
    }

    public static func extract(fromString string: String, source: String) -> [ExtractedEndpoint] {
        var out: [ExtractedEndpoint] = []
        var seen: Set<String> = []
        var domainCache: [String: String] = [:]
        extractInto(string: string, source: source, section: nil, offset: nil,
                    isUTF16: false, seen: &seen, domainCache: &domainCache, into: &out)
        return out
    }

    public static func extract(fromSymbols index: BinaryIndex) -> [ExtractedEndpoint] {
        var out: [ExtractedEndpoint] = []
        var seen: Set<String> = []
        var domainCache: [String: String] = [:]
        let source = index.relativePath
        func feedSymbol(_ s: String) {
            guard s.contains("."), s.utf8.count <= 2048 else { return }
            extractInto(string: s, source: source, section: "symbols", offset: nil,
                        isUTF16: false, seen: &seen, domainCache: &domainCache, into: &out)
        }
        for sym in index.importedSymbols { feedSymbol(sym) }
        for sym in index.definedSymbols { feedSymbol(sym) }
        for d in index.linkedDylibs { feedSymbol(d) }
        return out.filter { $0.kind == .absoluteURL }
    }

    private static func extractInto(string s: String,
                                    source: String,
                                    section: String?,
                                    offset: UInt64?,
                                    isUTF16: Bool,
                                    seen: inout Set<String>,
                                    domainCache: inout [String: String],
                                    into out: inout [ExtractedEndpoint]) {
        let s = decodingSlashEscapes(s)
        let ns = s as NSString
        let range = NSRange(location: 0, length: ns.length)
        regex.enumerateMatches(in: s, options: [], range: range) { m, _, _ in
            guard let m = m else { return }
            let kind: ExtractedEndpoint.Kind
            let scheme: String?
            let host: String
            let path: String?
            let raw: String
            if m.range(at: 1).location != NSNotFound {
                kind = .absoluteURL
                scheme = ns.substring(with: m.range(at: 1)).lowercased()
                host = ns.substring(with: m.range(at: 2)).lowercased()
                path = m.range(at: 3).location != NSNotFound ? ns.substring(with: m.range(at: 3)) : nil
                raw = ns.substring(with: m.range)
            } else if m.range(at: 4).location != NSNotFound {
                kind = .bareHost
                scheme = nil
                host = ns.substring(with: m.range(at: 4)).lowercased()
                let tld = ns.substring(with: m.range(at: 5)).lowercased()
                if !acceptedTLDs.contains(tld) { return }
                if isInsideDottedIdentifier(ns, m.range) { return }
                if isMemberAccess(ns.substring(with: m.range(at: 4))) { return }
                let labels = host.split(separator: ".")
                if let first = labels.first.map(String.init),
                   tlds.reverseDNSRoots.contains(first)
                    || (labels.count >= 4 && tlds.reverseDNSRootsFourLabels.contains(first)) { return }
                path = nil
                raw = host
            } else {
                return
            }
            if denylist.contains(host) { return }
            if host.hasPrefix("self.") || host.hasPrefix("super.") { return }
            var cleanHost = host
            while let last = cleanHost.last, ".,;:".contains(last) { cleanHost.removeLast() }
            let key = "\(scheme ?? "")|\(cleanHost)|\(path ?? "")"
            if !seen.insert(key).inserted { return }
            let reg: String
            if let cached = domainCache[cleanHost] {
                reg = cached
            } else {
                reg = PublicSuffixList.registrableDomain(for: cleanHost)
                domainCache[cleanHost] = reg
            }
            out.append(ExtractedEndpoint(
                kind: kind, raw: raw, host: cleanHost, registrableDomain: reg,
                scheme: scheme, path: path, source: source, section: section,
                offset: offset, isUTF16: isUTF16))
        }
    }

    static func decodingSlashEscapes(_ s: String) -> String {
        guard s.contains("\\u00") || s.contains("%") else { return s }
        var t = s
        for (escape, char) in [("\\u00252f", "/"), ("\\u00253a", ":"), ("\\u002f", "/"),
                               ("\\u003a", ":"), ("%2f", "/"), ("%3a", ":")] {
            t = t.replacingOccurrences(of: escape, with: char, options: .caseInsensitive)
        }
        return t
    }

    static func isMemberAccess(_ original: String) -> Bool {
        guard let last = original.split(separator: ".").last else { return false }
        return last.contains(where: \.isUppercase) && original != original.uppercased()
    }

    static func isInsideDottedIdentifier(_ ns: NSString, _ r: NSRange) -> Bool {
        let end = r.location + r.length
        if end < ns.length, [0x23, 0x24, 0x28, 0x3C, 0x7B].contains(ns.character(at: end)) { return true }
        if end + 1 < ns.length, ns.character(at: end) == 0x2E {
            let next = ns.character(at: end + 1)
            if let u = Unicode.Scalar(next), !CharacterSet.whitespacesAndNewlines.contains(u) { return true }
        }
        if r.location > 0, ns.character(at: r.location - 1) == 0x2E { return true }
        return false
    }

}
