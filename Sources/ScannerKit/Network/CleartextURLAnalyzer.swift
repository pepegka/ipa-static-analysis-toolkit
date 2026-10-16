import Foundation

enum CleartextURLAnalyzer {

    private struct File: Decodable { let hosts: [String] }
    static let nonEndpointHosts = Set(RuleData.decode(File.self, "domains/non-endpoint-hosts.json").hosts)

    static func isEndpoint(_ host: String) -> Bool {
        let h = host.lowercased()
        if nonEndpointHosts.contains(h) { return false }
        return !nonEndpointHosts.contains { $0.hasPrefix(".") && h.hasSuffix($0) }
    }

    static func analyze(network: NetworkInventory) -> [Finding] {
        let hosts = network.endpoints.filter { $0.cleartext == true && isEndpoint($0.host) }
            .sorted { $0.host < $1.host }
        guard !hosts.isEmpty else { return [] }
        let copy = Messages.entry("SECH-01.hardcoded_http_urls", [
            "count": String(hosts.count),
            "s": hosts.count == 1 ? "" : "s",
            "hosts": hosts.prefix(8).map(\.host).joined(separator: ", "),
        ])
        return [Finding(
            ruleID: "SECH-01.hardcoded_http_urls", vectorID: "SECH-01",
            title: copy.title, explanation: copy.explanation,
            severity: .derived("SECH-01.hardcoded_http_urls", "SECH-01"), evidences: hosts.prefix(40).map {
                Evidence(kind: .url, value: "http://\($0.host)", source: $0.sources.first ?? "(bundle)")
            },
            remediation: copy.remediation).with(metrics: copy.values)]
    }
}
