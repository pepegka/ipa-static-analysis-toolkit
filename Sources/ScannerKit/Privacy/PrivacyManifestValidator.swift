import Foundation

public enum PrivacyManifestValidator {

    private struct SDKList: Decodable { let sdks: [String] }
    static let listedSDKs: Set<String> =
        Set(RuleData.decode(SDKList.self, "privacy/apple-listed-sdks.json").sdks)

    private struct DataTypes: Decodable { let types: [String]; let purposes: [String] }
    private static let dataTypeFile = RuleData.decode(DataTypes.self, "privacy/collected-data-types.json")
    static let collectedDataTypes = Set(dataTypeFile.types)
    static let collectedDataPurposes = Set(dataTypeFile.purposes)

    public static func analyze(appDirectory: URL,
                               privacyManifests: [URL],
                               embeddedFrameworks: [String]) -> [Finding] {
        let probes = Dictionary(uniqueKeysWithValues:
            PrivacyManifestGapAnalyzer.probes.map { ($0.category, $0) })
        let appManifest = appDirectory.appendingPathComponent("PrivacyInfo.xcprivacy").standardizedFileURL

        var invalid: [Evidence] = []
        var missing: [Evidence] = []
        var sdkOnly: [Evidence] = []
        var badDataType: [Evidence] = []
        var trackingMismatch: [Evidence] = []
        var collected: [String: (linked: Bool, tracking: Bool)] = [:]

        for url in privacyManifests.sorted(by: { $0.path < $1.path }) {
            guard let dict = PlistUtil.load(at: url) else { continue }
            let source = url.relativePath(from: appDirectory)
            let isAppManifest = url.standardizedFileURL == appManifest

            let tracking = dict["NSPrivacyTracking"] as? Bool ?? false
            let domains = dict["NSPrivacyTrackingDomains"] as? [String] ?? []
            if tracking && domains.isEmpty {
                trackingMismatch.append(Evidence(kind: .plistValue, value: "NSPrivacyTracking=true, no domains",
                                                 source: source))
            } else if !tracking && !domains.isEmpty {
                trackingMismatch.append(Evidence(kind: .plistValue,
                                                 value: "\(domains.count) domain(s), NSPrivacyTracking not true",
                                                 source: source))
            }

            for item in dict["NSPrivacyCollectedDataTypes"] as? [[String: Any]] ?? [] {
                guard let type = item["NSPrivacyCollectedDataType"] as? String else { continue }
                for purpose in item["NSPrivacyCollectedDataTypePurposes"] as? [String] ?? []
                where !collectedDataPurposes.contains(purpose) {
                    badDataType.append(Evidence(kind: .plistValue, value: purpose, source: source,
                                                context: "purpose of \(type)"))
                }
                guard collectedDataTypes.contains(type) else {
                    badDataType.append(Evidence(kind: .plistValue, value: type, source: source))
                    continue
                }
                let prior = collected[type] ?? (false, false)
                collected[type] = (prior.linked || (item["NSPrivacyCollectedDataTypeLinked"] as? Bool ?? false),
                                   prior.tracking || (item["NSPrivacyCollectedDataTypeTracking"] as? Bool ?? false))
            }

            let apis = dict["NSPrivacyAccessedAPITypes"] as? [[String: Any]] ?? []
            for api in apis {
                guard let category = api["NSPrivacyAccessedAPIType"] as? String else { continue }
                let reasons = api["NSPrivacyAccessedAPITypeReasons"] as? [String] ?? []
                guard let probe = probes[category] else {
                    invalid.append(Evidence(kind: .plistValue, value: category, source: source,
                                            context: "not a required-reason API category"))
                    continue
                }
                if reasons.isEmpty {
                    missing.append(Evidence(kind: .plistValue, value: category, source: source))
                }
                for code in reasons {
                    guard let reason = probe.reasons.first(where: { $0.code == code }) else {
                        invalid.append(Evidence(kind: .plistValue, value: code, source: source,
                                                context: "not an approved reason for \(category)"))
                        continue
                    }
                    if reason.sdkOnly && isAppManifest {
                        sdkOnly.append(Evidence(kind: .plistValue, value: code, source: source,
                                                context: category))
                    }
                }
            }
        }

        let manifestDirs = privacyManifests.map { $0.deletingLastPathComponent().standardizedFileURL.path + "/" }
        let unmanifested: [Evidence] = embeddedFrameworks.sorted().compactMap { name in
            guard listedSDKs.contains(name) else { return nil }
            let dir = appDirectory.appendingPathComponent("Frameworks/\(name).framework")
                .standardizedFileURL.path + "/"
            if manifestDirs.contains(where: { $0.hasPrefix(dir) }) { return nil }
            return Evidence(kind: .file, value: "\(name).framework", source: "Frameworks/\(name).framework")
        }

        var out: [Finding] = []
        func add(_ ruleID: String, _ evidences: [Evidence]) {
            guard !evidences.isEmpty else { return }
            let copy = Messages.entry(ruleID, [
                "count": String(evidences.count),
                "s": evidences.count == 1 ? "" : "s",
                "values": Self.readableValues(evidences.map(\.value)),
            ])
            out.append(Finding(
                ruleID: ruleID, vectorID: "TGAP-01",
                title: copy.title, explanation: copy.explanation,
                severity: .derived(ruleID, "TGAP-01"),
                evidences: Array(evidences.prefix(40)),
                remediation: copy.remediation).with(metrics: copy.values))
        }
        add("TGAP-01.manifest_reason_invalid", invalid)
        add("TGAP-01.manifest_reason_missing", missing)
        add("TGAP-01.manifest_sdk_only_reason", sdkOnly)
        add("TGAP-01.listed_sdk_without_manifest", unmanifested)
        add("TGAP-01.manifest_data_type_invalid", badDataType)
        add("TGAP-01.manifest_tracking_mismatch", trackingMismatch)

        if !collected.isEmpty {
            let types = collected.keys.sorted()
            let short = { (t: String) in String(t.dropFirst("NSPrivacyCollectedDataType".count)) }
            let copy = Messages.entry("TGAP-01.declared_data_collection", [
                "count": String(types.count),
                "s": types.count == 1 ? "" : "s",
                "linked": String(collected.values.filter(\.linked).count),
                "tracking": String(collected.values.filter(\.tracking).count),
                "types": types.map(short).joined(separator: ", "),
            ])
            out.append(Finding(
                ruleID: "TGAP-01.declared_data_collection", vectorID: "TGAP-01",
                title: copy.title, explanation: copy.explanation,
                severity: .derived("TGAP-01.declared_data_collection", "TGAP-01"), evidences: types.map { Evidence(kind: .plistValue, value: short($0), source: "PrivacyInfo.xcprivacy",
                                                context: collected[$0]!.tracking ? "tracking" : (collected[$0]!.linked ? "linked" : nil)) }
            ).with(metrics: copy.values))
        }
        return out
    }

    static func readableValues(_ values: [String], limit: Int = 6) -> String {
        var seen = Set<String>(), out: [String] = []
        for v in values where seen.insert(v).inserted {
            out.append(v.trimmingCharacters(in: .whitespaces).isEmpty ? "an empty string (\"\")" : v)
        }
        let shown = out.prefix(limit).joined(separator: ", ")
        return out.count > limit ? "\(shown) and \(out.count - limit) more" : shown
    }
}
