import Foundation

public enum MassScanDashboardExporter {

    public enum Format: String, CaseIterable, Sendable {
        case json, markdown, html
        public var fileExtension: String { self == .markdown ? "md" : rawValue }
    }

    public static func export(_ report: MassScanReport, format: Format) throws -> Data {
        switch format {
        case .json: return try jsonData(report)
        case .markdown: return Data(markdown(report).utf8)
        case .html: return Data(html(report).utf8)
        }
    }

    public static func format(for token: String) -> Format? {
        switch token.lowercased() {
        case "json": return .json
        case "md", "markdown": return .markdown
        case "html": return .html
        default: return nil
        }
    }

    public static func jsonData(_ report: MassScanReport) throws -> Data {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        enc.dateEncodingStrategy = .iso8601
        return try enc.encode(report)
    }

    static func compactJSON(_ report: MassScanReport) -> String {
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys]
        enc.dateEncodingStrategy = .iso8601
        return HTML.scriptJSON((try? enc.encode(report)) ?? Data("{}".utf8))
    }

    static func pctOf(_ part: Int, _ total: Int) -> String {
        total > 0 ? "\(Int((Double(part) / Double(total) * 100).rounded()))%" : "\u{2014}"
    }

    static func seconds(_ x: Double) -> String { String(format: "%.1f", x) }

    static func kpi(_ value: String, _ label: String, accent: String? = nil) -> String {
        let style = accent.map { " style=\"color:var(--\($0))\"" } ?? ""
        return "<div class=kpi><div class=kv\(style)>\(HTML.esc(value))</div><div class=kl>\(HTML.esc(label))</div></div>"
    }

    static func readablePermission(_ key: String) -> String {
        var k = key
        if k.hasPrefix("NS") { k.removeFirst(2) }
        for suffix in ["UsageDescription", "Dictionary"] where k.hasSuffix(suffix) {
            k.removeLast(suffix.count)
        }
        guard !k.isEmpty else { return key }
        var words = ""
        for (i, ch) in k.enumerated() {
            if i > 0, ch.isUppercase { words.append(" ") }
            words.append(ch)
        }
        let lowered = words.lowercased()
        return lowered.prefix(1).uppercased() + lowered.dropFirst()
    }

    static func flag(_ code: String) -> String {
        let c = code.trimmingCharacters(in: .whitespaces).uppercased()
        guard c.count == 2, c.unicodeScalars.allSatisfy({ $0.value >= 65 && $0.value <= 90 }) else { return "" }
        var out = ""
        for u in c.unicodeScalars {
            if let s = Unicode.Scalar(u.value - 65 + 0x1F1E6) { out.unicodeScalars.append(s) }
        }
        return out
    }

    static func dataTable(_ title: String, _ items: [CountItem], unit: String, limit: Int = 25,
                          rename: ((CountItem) -> String)? = nil,
                          demote: ((CountItem) -> String?)? = nil) -> String {
        let top = Array(items.prefix(limit))
        guard !top.isEmpty else { return "" }
        let hasDetail = demote == nil && top.contains { !($0.detail ?? "").isEmpty }
        var s = "<div class=card><h3>\(HTML.esc(title))</h3><div class=scroll style=\"max-height:340px\"><table>"
        s += "<thead><tr><th>\(HTML.esc(unit))</th><th class=num>Apps</th>"
        if hasDetail { s += "<th>Detail</th>" }
        s += "</tr></thead><tbody>"
        for i in top {
            let primary = rename?(i) ?? i.label
            let sub = demote?(i).flatMap { $0.isEmpty ? nil : $0 }
            let cell: String
            if let sub, sub != primary {
                if sub.hasPrefix("NS") {
                    cell = HTML.esc(primary)
                } else {
                    cell = "\(HTML.esc(primary)) <span class=sub>\(HTML.esc(sub))</span>"
                }
            } else {
                cell = HTML.esc(primary)
            }
            let hover = sub.map { " title=\"\(HTML.esc($0))\"" } ?? ""
            s += "<tr><td class=wrap\(hover)>\(cell)</td><td class=num>\(i.count)</td>"
            if hasDetail { s += "<td class=dim>\(HTML.esc(i.detail ?? ""))</td>" }
            s += "</tr>"
        }
        s += "</tbody></table></div></div>"
        return s
    }

    struct InsightCopy: Decodable {
        let label: String
        let accent: String?
        let ctx: String?
    }
    struct InsightFile: Decodable {
        struct Group: Decodable { let id: String; let heading: String }
        let groups: [Group]
        let cards: [String: InsightCopy]
    }

    static let insightFile = RuleData.decode(InsightFile.self, "messages/insights.json")

    nonisolated(unsafe) private(set) static var suppressedInsightIDs: Set<String> = []
    static func resetSuppressedInsightIDs() { suppressedInsightIDs = [] }

    static func insight(_ value: String, _ id: String,
                        _ values: [String: String] = [:],
                        accent: String? = nil) -> String {
        guard let copy = insightFile.cards[id] else {
            fatalError("no copy for insight card \(id) in Rules/messages/insights.json")
        }
        func fill(_ text: String) -> String {
            values.reduce(text) { $0.replacingOccurrences(of: "{\($1.key)}", with: $1.value) }
        }
        let html = card(value: value, label: fill(copy.label),
                        accent: accent ?? copy.accent ?? "",
                        ctx: copy.ctx.map(fill))
        if html.isEmpty { suppressedInsightIDs.insert(id) }
        return html
    }

    private static func card(value: String, label: String, accent: String, ctx: String?) -> String {
        let v = value.trimmingCharacters(in: .whitespaces)
        if ["0%", "1 in 1", "none", "—"].contains(v.lowercased()) { return "" }
        let universal = v == "100%" || v.hasPrefix("All ")
        let cls = universal ? "insight baseline" : (accent.isEmpty ? "insight" : "insight \(accent)")
        var s = "<div class=\"\(cls)\"><button class=ihide title=\"Hide this card\" aria-label=Hide>×</button>"
        s += "<div class=ival>\(HTML.esc(value))</div><div class=ilab>\(HTML.esc(label))</div>"
        var body = ctx
        if universal {
            let note = "Universal across this corpus, so it is a baseline rather than something "
                + "that separates one app from another."
            body = ctx.map { "\(note) \($0)" } ?? note
        }
        if let c = body { s += "<div class=ictx>\(HTML.esc(c))</div>" }
        return s + "</div>"
    }

    struct InsightCorpus {
        let scanned: [MassScanAppEntry]
        let st: MassScanStats
        let withDetail: [MassScanAppEntry]
        let totalIPABytes: UInt64
        let country: String

        init(_ report: MassScanReport) {
            scanned = report.apps.filter(\.ok)
            st = report.stats
            withDetail = scanned.filter { $0.details != nil }
            totalIPABytes = report.run.totalIPABytes
            country = report.run.country
        }

        var n: Int { scanned.count }
        var dn: Int { max(1, withDetail.count) }

        func pctOf(_ part: Int) -> String { MassScanDashboardExporter.pctOf(part, n) }
        func pctD(_ part: Int) -> String { MassScanDashboardExporter.pctOf(part, dn) }
        func oneIn(_ part: Int) -> String { part == 0 ? "\u{2014}" : "1 in \(max(1, Int((Double(n) / Double(part)).rounded())))" }
        func count(_ items: [CountItem], _ label: String) -> Int { items.first { $0.label == label }?.count ?? 0 }

        func quantifier(_ part: Int) -> String {
            guard part > 0 else { return "\u{2014}" }
            if part >= n { return "All \(n) apps" }
            if part * 3 <= n { return "1 in \(Int((Double(n) / Double(part)).rounded())) apps" }
            return "\(pctOf(part)) of apps"
        }

        func appsWithWeakness(_ code: String, minSeverity: Severity = .low,
                              excluding: Set<String> = []) -> Int {
            assert(Vectors.byID[code] != nil, "unknown vector code \(code)")
            return withDetail.filter { a in
                (a.details?.findings ?? []).contains { f in
                    f.vector == code && f.polarityValue == .offensive
                        && (Severity(rawValue: f.severity) ?? .info) >= minSeverity
                        && !excluding.contains(f.rule ?? "")
                }
            }.count
        }

        var home: String { country.uppercased() }
        func hasCat(_ a: MassScanAppEntry, _ c: String) -> Bool { (a.details?.trackers ?? []).contains { $0.category == c } }
        func appsWithCat(_ c: String) -> Int { withDetail.filter { hasCat($0, c) }.count }
        func appsWithPerm(_ prefixes: [String]) -> Int {
            withDetail.filter { ($0.details?.permissions ?? []).contains { p in prefixes.contains { p.key.hasPrefix($0) } } }.count
        }

        var binaries: [AppCompareDetail.DHardening] { withDetail.flatMap { $0.details?.hardening ?? [] } }
    }

    static func severityCell(_ a: MassScanAppEntry) -> String {
        let order: [Severity] = [.critical, .high, .medium, .low, .info]
        let counts = order.map { (sev: $0, n: a.severityCounts[$0.rawValue] ?? 0) }
        let total = counts.reduce(0) { $0 + $1.n }
        guard total > 0 else { return "<td data-v=0></td>" }
        let bar = counts.filter { $0.n > 0 }.map {
            "<i class=b-\($0.sev.rawValue) style=\"flex:\($0.n)\" title=\"\($0.n) \($0.sev.rawValue)\"></i>"
        }.joined()
        let rank = counts.reduce(0) { acc, c in
            acc + c.n * Int(pow(1000.0, Double(4 - (order.firstIndex(of: c.sev) ?? 0))))
        }
        let label = counts.filter { $0.n > 0 }
            .map { "\($0.n) \($0.sev.rawValue)" }.joined(separator: ", ")
        return "<td data-v=\(rank) title=\"\(HTML.esc(label))\"><div class=sevbar>\(bar)</div></td>"
    }

    static func flagsCell(_ a: MassScanAppEntry) -> String {
        let secrets = a.secretCount ?? 0
        let ats = a.atsArbitraryLoads == true
        var chips = ""
        if secrets > 0 {
            chips += "<span class=\"chipf sev-high\" title=\"\(secrets) hard-coded credential(s); public client identifiers are not counted\">\(secrets) credential\(secrets == 1 ? "" : "s")</span>"
        }
        if ats { chips += "<span class=\"chipf sev-medium\" title=\"ATS arbitrary loads enabled\">ATS</span>" }
        return "<td data-v=\(secrets * 2 + (ats ? 1 : 0))>\(chips)</td>"
    }

}
