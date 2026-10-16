import Foundation

public enum AIEgressAnalyzer {

    private struct Indicators: Decodable {
        let llmEndpoints: [String]
        let sttEndpoints: [String]
        let llmSDKSymbols: [String]
        let screenshotAPIs: [String]
        let onDeviceML: [String]
        let speechAPIs: [String]
    }

    private static let d = RuleData.decode(Indicators.self, "domains/ai-endpoints.json")

    static var llmEndpoints: [String] { d.llmEndpoints }
    static var sttEndpoints: [String] { d.sttEndpoints }
    static var llmSDKSymbols: [String] { d.llmSDKSymbols }
    static var screenshotAPIs: [String] { d.screenshotAPIs }
    static var onDeviceML: [String] { d.onDeviceML }
    static var speechAPIs: [String] { d.speechAPIs }

    public static func analyze(indices: [String: BinaryIndex]) -> [Finding] {
        var stringHits: [String: [String]] = [:]
        var symbolPresent: Set<String> = []
        func scan() {
            for (rel, idx) in indices.sorted(by: { $0.key < $1.key }) {
                for ss in idx.perSectionStrings {
                    for s in ss.strings {
                        let v = s.value
                        for host in (llmEndpoints + sttEndpoints) where v.range(of: host, options: .caseInsensitive) != nil {
                            stringHits[host, default: []].append(rel)
                        }
                    }
                }
                for sym in idx.importedSymbols + idx.definedSymbols {
                    for needle in (llmSDKSymbols + screenshotAPIs + onDeviceML + speechAPIs) where sym.contains(needle) {
                        symbolPresent.insert(needle)
                    }
                }
            }
        }
        scan()

        var out: [Finding] = []
        func ev(_ hosts: [String]) -> [Evidence] {
            hosts.prefix(10).map { Evidence(kind: .url, value: $0, source: "AI endpoint") }
        }
        let llmHosts = llmEndpoints.filter { stringHits[$0] != nil }
        let sttHosts = sttEndpoints.filter { stringHits[$0] != nil }
        let hasScreenshot = screenshotAPIs.contains { symbolPresent.contains($0) }
        let hasSpeech = speechAPIs.contains { symbolPresent.contains($0) }
        let hasOnDeviceML = onDeviceML.contains { symbolPresent.contains($0) }
        let llmSDKs = llmSDKSymbols.filter { symbolPresent.contains($0) }

        if !llmHosts.isEmpty {
            let copy = Messages.entry("TRK-05.llm_api_endpoints",
                                      ["count": String(llmHosts.count),
                                       "hosts": llmHosts.joined(separator: ", ")])
            out.append(Finding(
                ruleID: "TRK-05.llm_api_endpoints", vectorID: "TRK-05",
                title: copy.title,
                explanation: copy.explanation,
                severity: .derived("TRK-05.llm_api_endpoints", "TRK-05"), evidences: ev(llmHosts),
                remediation: copy.remediation).with(metrics: copy.values))
        }
        if !llmSDKs.isEmpty {
            let copy = Messages.entry("TRK-05.llm_sdk_symbols",
                                      ["sdks": llmSDKs.joined(separator: ", ")])
            out.append(Finding(
                ruleID: "TRK-05.llm_sdk_symbols", vectorID: "TRK-05",
                title: copy.title,
                explanation: copy.explanation,
                severity: .derived("TRK-05.llm_sdk_symbols", "TRK-05"), evidences: llmSDKs.map { Evidence(kind: .symbol, value: $0, source: "(main)") }).with(metrics: copy.values))
        }
        if hasSpeech, !sttHosts.isEmpty {
            let copy = Messages.entry("TRK-05.speech_to_cloud",
                                      ["hosts": sttHosts.joined(separator: ", ")])
            out.append(Finding(
                ruleID: "TRK-05.speech_to_cloud", vectorID: "TRK-05",
                title: copy.title,
                explanation: copy.explanation,
                severity: .derived("TRK-05.speech_to_cloud", "TRK-05"), evidences: ev(sttHosts) + [Evidence(kind: .symbol, value: "SFSpeechRecognizer", source: "(main)")]).with(metrics: copy.values))
        }
        if hasScreenshot, !llmHosts.isEmpty {
            out.append(Finding(
                ruleID: "TRK-05.screen_context_to_llm", vectorID: "TRK-05",
                title: Messages.entry("TRK-05.screen_context_to_llm").title,
                explanation: Messages.entry("TRK-05.screen_context_to_llm").explanation,
                severity: .derived("TRK-05.screen_context_to_llm", "TRK-05"), evidences: ev(llmHosts) + [Evidence(kind: .symbol, value: "UIGraphicsImageRenderer", source: "(main)")]))
        }
        if hasOnDeviceML, llmHosts.isEmpty, sttHosts.isEmpty {
            out.append(Finding(
                ruleID: "TRK-05.on_device_ml", vectorID: "TRK-05",
                title: Messages.entry("TRK-05.on_device_ml").title,
                explanation: Messages.entry("TRK-05.on_device_ml").explanation,
                severity: .derived("TRK-05.on_device_ml", "TRK-05"), evidences: onDeviceML.filter { symbolPresent.contains($0) }.map { Evidence(kind: .symbol, value: $0, source: "(main)") }))
        }
        return out
    }
}
