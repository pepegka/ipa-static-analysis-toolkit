import Foundation

public enum PrivacyManifestGapAnalyzer {

    struct CategoryProbe: Decodable {
        struct Reason: Decodable {
            let code: String
            let sdkOnly: Bool
        }
        let category: String
        let humanName: String
        let indicators: [String]
        let exactSymbols: [String]
        let humanIndicators: String
        let reasons: [Reason]

        func matches(_ symbol: String) -> Bool {
            let l = symbol.lowercased()
            return indicators.contains { l.contains($0.lowercased()) }
                || PrivacyManifestGapAnalyzer.matchesExactSymbol(symbol, anyOf: exactSymbols)
        }
    }

    private struct ProbeFile: Decodable { let probes: [CategoryProbe] }

    static let probes: [CategoryProbe] =
        RuleData.decode(ProbeFile.self, "privacy/required-reason-apis.json").probes

    fileprivate static func matchesExactSymbol(_ symbol: String, anyOf needles: [String]) -> Bool {
        guard !needles.isEmpty else { return false }
        let s = symbol.lowercased()
        for n in needles {
            let ln = n.lowercased()
            if s == ln || s == "_" + ln { return true }
        }
        return false
    }

    public static func analyze(metadata: BundleMetadata,
                               indices: [String: BinaryIndex]) -> [Finding] {
        let declared = Set(metadata.privacyAccessedAPIs)
        var findings: [Finding] = []

        for probe in probes {
            if declared.contains(probe.category) { continue }

            struct Hit { let path: String; let value: String }
            var hits: [Hit] = []
            var frameworks: Set<String> = []
            let coveredElsewhere = probes.filter { $0.category != probe.category && declared.contains($0.category) }
            func matches(_ symbol: String) -> Bool {
                probe.matches(symbol) && !coveredElsewhere.contains { $0.matches(symbol) }
            }
            for (path, bi) in indices.sorted(by: { $0.key < $1.key }) {
                var matched = false
                for sym in bi.importedSymbols + bi.definedSymbols where matches(sym) {
                    matched = true
                    if hits.count < 32 { hits.append(Hit(path: path, value: sym)) }
                }
                if matched { frameworks.insert(FrameworkAttribution.framework(forRelativePath: path)) }
            }
            if hits.isEmpty { continue }

            let evidences: [Evidence] = hits.prefix(20).map { h in
                Evidence(kind: .symbol, value: h.value, source: h.path)
            }
            let owningFramework = frameworks.contains("(main)")
                ? "(main)"
                : (frameworks.sorted().first ?? "(main)")
            let copy = Messages.entry("privacy.gap", [
                "humanName": probe.humanName,
                "humanIndicators": probe.humanIndicators,
                "category": probe.category,
                "count": String(frameworks.count),
            ])
            findings.append(Finding(
                ruleID: "privacy.gap.\(probe.category)",
                vectorID: "TGAP-01",
                title: copy.title,
                explanation: copy.explanation,
                severity: .derived("privacy.gap.\(probe.category)", "TGAP-01"),
                evidences: evidences,
                owningFramework: owningFramework).with(metrics: copy.values))
        }

        return findings
    }
}
