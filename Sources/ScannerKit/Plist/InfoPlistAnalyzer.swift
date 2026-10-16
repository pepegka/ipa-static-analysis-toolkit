import Foundation

enum PermissionCatalog {
    struct Entry: Decodable {
        let vector: String
        let category: String?
        let description: String?
        let sensitive: Bool?
    }
    struct DefaultRule: Decodable {
        let vector: String
        let match: [String]?
        let keys: [String]
    }
    private struct File: Decodable {
        let usageDescriptionKeys: [String: Entry]
        let requiredReasonAPIs: [String: Entry]
        let defaultPermissions: [DefaultRule]
        let standardURLSchemes: Set<String>
    }

    private static let file = RuleData.decode(File.self, "taxonomy/permissions.json")

    static var usageDescriptionKeys: [String: Entry] { file.usageDescriptionKeys }
    static var requiredReasonAPIs: [String: Entry] { file.requiredReasonAPIs }
    static var standardURLSchemes: Set<String> { file.standardURLSchemes }
    static var defaultPermissions: [DefaultRule] { file.defaultPermissions }
}

enum PlistKeyMapping {
    public static let table: [String: (vectorID: String, category: String)] =
        PermissionCatalog.usageDescriptionKeys.mapValues { ($0.vector, $0.category ?? "") }
}

public enum PrivacyAPIMapping {
    public static let table: [String: (vectorID: String, description: String)] =
        PermissionCatalog.requiredReasonAPIs.mapValues { ($0.vector, $0.description ?? "") }
}

struct InfoPlistResult: Sendable {
    public let metadata: BundleMetadata
    public let findings: [Finding]
    public let ats: ATSConfig
    public init(metadata: BundleMetadata, findings: [Finding], ats: ATSConfig = .empty) {
        self.metadata = metadata; self.findings = findings; self.ats = ats
    }
}

enum InfoPlistAnalyzer {

    public static func analyze(appDirectory: URL,
                               embeddedBinaries: [EmbeddedBinary],
                               embeddedFrameworks: [String],
                               privacyManifests: [URL],
                               provisioning: ProvisioningInfo?,
                               signedTeamID: String?,
                               signedIdentifier: String?) -> InfoPlistResult {
        let infoURL = appDirectory.appendingPathComponent("Info.plist")
        let info = PlistUtil.load(at: infoURL) ?? [:]

        let bundleID  = info["CFBundleIdentifier"]   as? String ?? "unknown"
        let bundleName = info["CFBundleName"]        as? String ?? appDirectory.deletingPathExtension().lastPathComponent
        let displayName = info["CFBundleDisplayName"] as? String
        let shortVersion = info["CFBundleShortVersionString"] as? String
        let bundleVersion = info["CFBundleVersion"]  as? String
        let minOS       = info["MinimumOSVersion"]   as? String
        let executable  = info["CFBundleExecutable"] as? String
        let platforms   = info["CFBundleSupportedPlatforms"] as? [String] ?? []

        var urlSchemes: [String] = []
        if let urlTypes = info["CFBundleURLTypes"] as? [[String: Any]] {
            for type in urlTypes {
                if let s = type["CFBundleURLSchemes"] as? [String] { urlSchemes.append(contentsOf: s) }
            }
        }
        let queried = info["LSApplicationQueriesSchemes"] as? [String] ?? []
        let bgModes = info["UIBackgroundModes"] as? [String] ?? []
        let ats     = info["NSAppTransportSecurity"] as? [String: Any]
        let allowsArbitrary = ATSAnalyzer.effectiveArbitraryLoads(ats)

        var permissions: [PermissionEntry] = []
        for (k, v) in info where k.contains("UsageDescription") {
            let value = (v as? String) ?? "\(v)"
            let mapped = PlistKeyMapping.table[k]
            permissions.append(PermissionEntry(key: k, value: value,
                                               vectorID: mapped?.vectorID,
                                               category: mapped?.category))
        }
        permissions.sort { $0.key < $1.key }

        var trackingDomains: [String] = []
        var accessedAPIs: [String] = []
        var accessedReasons: [String] = []
        for url in privacyManifests {
            guard let dict = PlistUtil.load(at: url) else { continue }
            if let domains = dict["NSPrivacyTrackingDomains"] as? [String] {
                trackingDomains.append(contentsOf: domains)
            }
            if let apis = dict["NSPrivacyAccessedAPITypes"] as? [[String: Any]] {
                for api in apis {
                    if let t = api["NSPrivacyAccessedAPIType"] as? String { accessedAPIs.append(t) }
                    if let rs = api["NSPrivacyAccessedAPITypeReasons"] as? [String] { accessedReasons.append(contentsOf: rs) }
                }
            }
        }
        trackingDomains = Array(Set(trackingDomains)).sorted()
        accessedAPIs = Array(Set(accessedAPIs)).sorted()
        accessedReasons = Array(Set(accessedReasons)).sorted()

        let primaryPM = privacyManifests.first.map { $0.relativePath(from: appDirectory) }

        var metadata = BundleMetadata(
            bundleID: bundleID,
            bundleName: bundleName,
            displayName: displayName,
            shortVersion: shortVersion,
            bundleVersion: bundleVersion,
            minimumOSVersion: minOS,
            executableName: executable,
            supportedPlatforms: platforms,
            urlSchemes: urlSchemes,
            queriedURLSchemes: queried,
            backgroundModes: bgModes,
            allowsArbitraryLoads: allowsArbitrary,
            permissions: permissions,
            privacyManifestPath: primaryPM,
            privacyTrackingDomains: trackingDomains,
            privacyAccessedAPIs: accessedAPIs,
            embeddedBinaries: embeddedBinaries,
            embeddedFrameworks: embeddedFrameworks,
            provisioning: provisioning,
            signedTeamID: signedTeamID,
            signedIdentifier: signedIdentifier
        )
        metadata.privacyAccessedAPIReasons = accessedReasons
        metadata.infoPlistKeys = info.keys.sorted()

        var findings: [Finding] = []
        let infoRelative = "Info.plist"

        let atsResult = ATSAnalyzer.analyze(ats: ats, source: infoRelative)
        findings.append(contentsOf: atsResult.findings)

        if !queried.isEmpty {
            let copy = Messages.entry("DCS-06.ls_application_queries_schemes",
                                      ["count": String(queried.count)])
            let evidences = queried.prefix(50).map {
                Evidence(kind: .plistValue, value: $0, source: infoRelative)
            }
            findings.append(Finding(
                ruleID: "DCS-06.ls_application_queries_schemes",
                vectorID: "DCS-06",
                title: copy.title,
                explanation: copy.explanation,
                severity: .derived("DCS-06.ls_application_queries_schemes", "DCS-06"),
                evidences: Array(evidences),
                remediation: copy.remediation).with(metrics: copy.values))
        }

        let customSchemes = urlSchemes.filter { !PermissionCatalog.standardURLSchemes.contains($0.lowercased()) }
        if !customSchemes.isEmpty {
            let copy = Messages.entry("PLAT-02.custom_url_schemes",
                                      ["count": String(customSchemes.count),
                                       "s": customSchemes.count == 1 ? "" : "s"])
            findings.append(Finding(
                ruleID: "PLAT-02.custom_url_schemes",
                vectorID: "PLAT-02",
                title: copy.title,
                explanation: copy.explanation,
                severity: .derived("PLAT-02.custom_url_schemes", "PLAT-02"), evidences: customSchemes.prefix(50).map { Evidence(kind: .plistValue, value: $0 + "://", source: infoRelative) },
                remediation: copy.remediation).with(metrics: copy.values))
        }

        if !bgModes.isEmpty {
            let suspicious: Set<String> = ["audio", "location", "voip", "fetch", "remote-notification", "processing", "external-accessory"]
            let hits = Set(bgModes.filter { suspicious.contains($0) }).sorted()
            if !hits.isEmpty {
                let copy = Messages.entry("PLAT-04.background_modes",
                                          ["modes": hits.joined(separator: ", ")])
                findings.append(Finding(
                    ruleID: "PLAT-04.background_modes",
                    vectorID: "PLAT-04",
                    title: copy.title,
                    explanation: copy.explanation,
                    severity: .derived("PLAT-04.background_modes", "PLAT-04"),
                    evidences: hits.map { Evidence(kind: .plistValue, value: $0, source: infoRelative) },
                    remediation: copy.remediation).with(metrics: copy.values))
            }
        }

        for perm in permissions {
            guard let vec = perm.vectorID else { continue }
            findings.append(Finding(
                ruleID: "perm.\(perm.key)",
                vectorID: vec,
                title: "Requests permission: \(perm.category ?? perm.key)",
                explanation: perm.category ?? "Permission declared in Info.plist",
                severity: .derived("perm.\(perm.key)", vec), evidences: [
                    Evidence(kind: .plistKey, value: perm.key, source: infoRelative),
                    Evidence(kind: .plistValue, value: perm.value, source: infoRelative)
                ]))
        }

        let inadequate = permissions.filter { PurposeStrings.isInadequate(key: $0.key, value: $0.value) }
        if !inadequate.isEmpty {
            let copy = Messages.entry("TGAP-02.inadequate_purpose_string", [
                "count": String(inadequate.count),
                "s": inadequate.count == 1 ? "" : "s",
                "verb": inadequate.count == 1 ? "does" : "do",
                "values": inadequate.prefix(6).map { p in
                    let v = p.value.trimmingCharacters(in: .whitespacesAndNewlines)
                    return "\(p.key) = " + (v.isEmpty ? "an empty string" : "\"\(v)\"")
                }.joined(separator: "; "),
            ])
            findings.append(Finding(
                ruleID: "TGAP-02.inadequate_purpose_string",
                vectorID: "TGAP-02",
                title: copy.title,
                explanation: copy.explanation,
                severity: .derived("TGAP-02.inadequate_purpose_string", "TGAP-02"), evidences: inadequate.map {
                    Evidence(kind: .plistValue, value: $0.value, source: infoRelative, context: $0.key)
                },
                remediation: copy.remediation).with(metrics: copy.values))
        }

        for api in accessedAPIs {
            let mapping = PrivacyAPIMapping.table[api]
            findings.append(Finding(
                ruleID: "privacy.\(api)",
                vectorID: mapping?.vectorID ?? "DCS-01",
                title: "Privacy manifest declares accessed API: \(api)",
                explanation: mapping?.description ?? "API declared in PrivacyInfo.xcprivacy.",
                severity: .derived("privacy.\(api)", mapping?.vectorID ?? "DCS-01"), evidences: [Evidence(kind: .plistValue, value: api, source: primaryPM ?? "PrivacyInfo.xcprivacy")]))
        }

        if !trackingDomains.isEmpty {
            let copy = Messages.entry("privacy.tracking_domains",
                                      ["count": String(trackingDomains.count)])
            findings.append(Finding(
                ruleID: "privacy.tracking_domains",
                vectorID: "TRK-01",
                title: copy.title,
                explanation: copy.explanation,
                severity: .derived("privacy.tracking_domains", "TRK-01"), evidences: trackingDomains.prefix(50).map { Evidence(kind: .url, value: $0, source: primaryPM ?? "PrivacyInfo.xcprivacy") }).with(metrics: copy.values))
        }

        return InfoPlistResult(metadata: metadata, findings: findings, ats: atsResult.config)
    }
}

extension URL {
    func relativePath(from base: URL) -> String {
        let basePath = base.standardizedFileURL.path
        let selfPath = self.standardizedFileURL.path
        if selfPath.hasPrefix(basePath + "/") {
            return String(selfPath.dropFirst(basePath.count + 1))
        }
        return selfPath
    }
}

enum PurposeStrings {
    struct File: Decodable {
        let placeholderWords: [String]
        let templateSuffix: String
        let templateMaxWords: Int
    }
    static let data = RuleData.decode(File.self, "privacy/purpose-strings.json")

    static func isInadequate(key: String, value: String) -> Bool {
        let v = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if v.isEmpty { return true }
        if v.contains("$(") || v.contains("${") { return true }
        let lower = v.lowercased()
        let bareKey = key.replacingOccurrences(of: "UsageDescription", with: "")
            .replacingOccurrences(of: "NS", with: "", options: .anchored).lowercased()
        if lower == key.lowercased() || lower == bareKey { return true }
        if data.placeholderWords.contains(where: { lower.contains($0) }) { return true }
        if lower.hasSuffix(data.templateSuffix),
           lower.split(separator: " ").count <= data.templateMaxWords { return true }
        return false
    }
}
