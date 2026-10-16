import Foundation

public enum ATSAnalyzer {

    public struct Result: Sendable {
        public let config: ATSConfig
        public let findings: [Finding]
    }

    private static var strongPinningSymbols: [String] { SecurityIndicators.pinning.strong }
    private static var weakTrustSymbols: [String] { SecurityIndicators.pinning.weak }
    private static var anchorCertificateExtensions: Set<String> {
        SecurityIndicators.pinning.anchorCertificateExtensions
    }

    public static func pinningMachinery(indices: [String: BinaryIndex],
                                        bundledCertificates: [String]) -> [Evidence] {
        var out: [Evidence] = []
        var corroborating: [Evidence] = []
        for (rel, index) in indices.sorted(by: { $0.key < $1.key }) {
            let symbols = index.importedSymbols + index.definedSymbols
            for marker in strongPinningSymbols where symbols.contains(where: { $0.contains(marker) }) {
                out.append(Evidence(kind: .symbol, value: marker, source: rel))
            }
            for marker in weakTrustSymbols where symbols.contains(where: { $0.contains(marker) }) {
                corroborating.append(Evidence(kind: .symbol, value: marker, source: rel))
            }
        }
        for cert in bundledCertificates
        where anchorCertificateExtensions.contains((cert as NSString).pathExtension.lowercased()) {
            out.append(Evidence(kind: .file, value: cert, source: cert))
        }
        return out.isEmpty ? [] : out + corroborating
    }

    public static func effectiveArbitraryLoads(_ ats: [String: Any]?) -> Bool {
        guard let ats, (ats["NSAllowsArbitraryLoads"] as? Bool) == true else { return false }
        let fineGrained = ["NSAllowsArbitraryLoadsInWebContent", "NSAllowsArbitraryLoadsForMedia",
                           "NSAllowsLocalNetworking"]
        return !fineGrained.contains { ats[$0] != nil }
    }

    public static func analyze(ats: [String: Any]?,
                               source: String = "Info.plist",
                               indices: [String: BinaryIndex] = [:],
                               bundledCertificates: [String] = []) -> Result {
        guard let ats else {
            return Result(config: .empty, findings: [])
        }

        let allowsArbitraryWeb    = (ats["NSAllowsArbitraryLoadsInWebContent"] as? Bool) ?? false
        let allowsArbitraryMedia  = (ats["NSAllowsArbitraryLoadsForMedia"] as? Bool) ?? false
        let allowsLocalNetworking = (ats["NSAllowsLocalNetworking"] as? Bool) ?? false
        let allowsArbitrary       = effectiveArbitraryLoads(ats)

        var domains: [ATSDomain] = []
        if let exceptions = ats["NSExceptionDomains"] as? [String: Any] {
            for (domain, raw) in exceptions {
                let d = raw as? [String: Any] ?? [:]
                let insecure = (d["NSExceptionAllowsInsecureHTTPLoads"] as? Bool)
                            ?? (d["NSTemporaryExceptionAllowsInsecureHTTPLoads"] as? Bool) ?? false
                let includesSub = (d["NSIncludesSubdomains"] as? Bool) ?? false
                let minTLS = (d["NSExceptionMinimumTLSVersion"] as? String)
                          ?? (d["NSTemporaryExceptionMinimumTLSVersion"] as? String)
                let fs = d["NSExceptionRequiresForwardSecrecy"] as? Bool
                domains.append(ATSDomain(domain: domain, includesSubdomains: includesSub,
                                         allowsInsecureHTTPLoads: insecure,
                                         minimumTLSVersion: minTLS,
                                         requiresForwardSecrecy: fs))
            }
            domains.sort { $0.domain < $1.domain }
        }

        let config = ATSConfig(allowsArbitraryLoads: allowsArbitrary,
                               allowsArbitraryLoadsInWebContent: allowsArbitraryWeb,
                               allowsArbitraryLoadsForMedia: allowsArbitraryMedia,
                               allowsLocalNetworking: allowsLocalNetworking,
                               exceptionDomains: domains)

        var findings: [Finding] = []
        if allowsArbitrary {
            let copy = Messages.entry("SECH-01.allows_arbitrary_loads")
            findings.append(Finding(
                ruleID: "SECH-01.allows_arbitrary_loads",
                vectorID: "SECH-01",
                title: copy.title,
                explanation: copy.explanation,
                severity: .derived("SECH-01.allows_arbitrary_loads", "SECH-01"), evidences: [Evidence(kind: .plistKey, value: "NSAllowsArbitraryLoads=YES", source: source)],
                masvs: ["MASVS-NETWORK"],
                remediation: copy.remediation))
        }
        if allowsArbitraryWeb || allowsArbitraryMedia || allowsLocalNetworking {
            var which: [String] = []
            if allowsArbitraryWeb    { which.append("NSAllowsArbitraryLoadsInWebContent") }
            if allowsArbitraryMedia  { which.append("NSAllowsArbitraryLoadsForMedia") }
            if allowsLocalNetworking { which.append("NSAllowsLocalNetworking") }
            let copy = Messages.entry("SECH-01.allows_arbitrary_scoped",
                                      ["which": which.joined(separator: ", ")])
            findings.append(Finding(
                ruleID: "SECH-01.allows_arbitrary_scoped",
                vectorID: "SECH-01",
                title: copy.title,
                explanation: copy.explanation,
                severity: .derived("SECH-01.allows_arbitrary_scoped", "SECH-01"), evidences: which.map { Evidence(kind: .plistKey, value: "\($0)=YES", source: source) },
                masvs: ["MASVS-NETWORK"],
                remediation: copy.remediation).with(metrics: copy.values))
        }
        let weakened = domains.filter {
            $0.allowsInsecureHTTPLoads
                || (($0.minimumTLSVersion.map { $0 < "TLSv1.2" }) ?? false)
                || $0.requiresForwardSecrecy == false
        }
        if !weakened.isEmpty {
            let copy = Messages.entry("SECH-01.insecure_exception_domains",
                                      ["count": String(weakened.count)])
            findings.append(Finding(
                ruleID: "SECH-01.insecure_exception_domains",
                vectorID: "SECH-01",
                title: copy.title,
                explanation: copy.explanation,
                severity: .derived("SECH-01.insecure_exception_domains", "SECH-01"), evidences: weakened.prefix(50).map {
                    Evidence(kind: .plistValue,
                             value: "\($0.domain) insecureHTTP=\($0.allowsInsecureHTTPLoads) minTLS=\($0.minimumTLSVersion ?? "default") forwardSecrecy=\($0.requiresForwardSecrecy.map(String.init) ?? "default")",
                             source: source)
                },
                masvs: ["MASVS-NETWORK"],
                remediation: copy.remediation).with(metrics: copy.values))
        }
        let hasPinning = ats["NSPinnedDomains"] != nil
        let codePinning = pinningMachinery(indices: indices, bundledCertificates: bundledCertificates)
        if !domains.isEmpty && !hasPinning && codePinning.isEmpty {
            let copy = Messages.entry("SECH-01.missing_pinning")
            findings.append(Finding(
                ruleID: "SECH-01.missing_pinning",
                vectorID: "SECH-01",
                title: copy.title,
                explanation: copy.explanation,
                severity: .derived("SECH-01.missing_pinning", "SECH-01"), evidences: [Evidence(kind: .plistKey, value: "NSPinnedDomains absent", source: source)],
                masvs: ["MASVS-NETWORK"],
                remediation: copy.remediation))
        }
        return Result(config: config, findings: findings)
    }
}
