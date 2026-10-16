import Foundation

enum AppExtensionAnalyzer {

    public static func analyze(appDirectory: URL) -> [Finding] {
        let pluginsDir = appDirectory.appendingPathComponent("PlugIns", isDirectory: true)
        guard let appexes = try? FileManager.default.contentsOfDirectory(
                at: pluginsDir, includingPropertiesForKeys: nil)
                .filter({ $0.pathExtension == "appex" }) else {
            return []
        }

        var findings: [Finding] = []
        for appex in appexes.sorted(by: { $0.lastPathComponent < $1.lastPathComponent }) {
            guard let info = PlistUtil.load(at: appex.appendingPathComponent("Info.plist")) else { continue }
            let name = (info["CFBundleDisplayName"] as? String)
                ?? (info["CFBundleName"] as? String)
                ?? appex.deletingPathExtension().lastPathComponent
            guard let ext = info["NSExtension"] as? [String: Any] else { continue }
            let pointID = ext["NSExtensionPointIdentifier"] as? String ?? ""
            let attrs = ext["NSExtensionAttributes"] as? [String: Any] ?? [:]
            let relSource = appex.relativePath(from: appDirectory)

            if pointID == "com.apple.keyboard-service" {
                let openAccess = (attrs["RequestsOpenAccess"] as? Bool) ?? false
                let copy = Messages.entry(
                    openAccess ? "PLAT-03.keyboard_open_access" : "PLAT-03.custom_keyboard",
                    ["name": name])
                if openAccess {
                    findings.append(Finding(
                        ruleID: "PLAT-03.keyboard_open_access",
                        vectorID: "PLAT-03",
                        title: copy.title,
                        explanation: copy.explanation,
                        severity: .derived("PLAT-03.keyboard_open_access", "PLAT-03"), evidences: [Evidence(kind: .plistValue, value: "RequestsOpenAccess=YES", source: relSource)],
                        mitre: ["T1417"],
                        masvs: ["MASVS-PLATFORM"],
                        remediation: copy.remediation).with(metrics: copy.values))
                } else {
                    findings.append(Finding(
                        ruleID: "PLAT-03.custom_keyboard",
                        vectorID: "PLAT-03",
                        title: copy.title,
                        explanation: copy.explanation,
                        severity: .derived("PLAT-03.custom_keyboard", "PLAT-03"), evidences: [Evidence(kind: .plistValue, value: pointID, source: relSource)],
                        mitre: ["T1417"]))
                }
            }

            if let rule = attrs["NSExtensionActivationRule"] as? String,
               rule.uppercased().contains("TRUEPREDICATE") {
                let copy = Messages.entry("PLAT-03.truepredicate_activation", ["name": name])
                findings.append(Finding(
                    ruleID: "PLAT-03.truepredicate_activation",
                    vectorID: "PLAT-03",
                    title: copy.title,
                    explanation: copy.explanation,
                    severity: .derived("PLAT-03.truepredicate_activation", "PLAT-03"), evidences: [Evidence(kind: .plistValue, value: "NSExtensionActivationRule=TRUEPREDICATE", source: relSource)],
                    masvs: ["MASVS-PLATFORM"],
                    remediation: copy.remediation).with(metrics: copy.values))
            }
        }
        return findings
    }
}
