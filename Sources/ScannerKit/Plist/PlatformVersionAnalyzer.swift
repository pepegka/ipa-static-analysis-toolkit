import Foundation

public enum PlatformVersionAnalyzer {

    struct UploadMinimum: Decodable {
        let sdkMajor: Int
        let xcodeMajor: Int
        let effective: String
        let source: String
    }
    private struct File: Decodable { let uploadMinimum: UploadMinimum }
    static let uploadMinimum = RuleData.decode(File.self, "platform/requirements.json").uploadMinimum

    public static func analyze(appDirectory: URL) -> [Finding] {
        guard let info = PlistUtil.load(at: appDirectory.appendingPathComponent("Info.plist")) else { return [] }
        let minOS = info["MinimumOSVersion"] as? String
        let sdk = info["DTPlatformVersion"] as? String
        guard let minOS, let sdk else { return [] }
        let sdkName = info["DTSDKName"] as? String ?? "unknown"
        let xcode = (info["DTXcode"] as? String).map(xcodeVersion) ?? "unknown"

        let evidences = [
            Evidence(kind: .plistValue, value: minOS, source: "Info.plist:MinimumOSVersion"),
            Evidence(kind: .plistValue, value: sdk, source: "Info.plist:DTPlatformVersion"),
        ]
        let copy = Messages.entry("SECH-09.platform_versions",
                                  ["minOS": minOS, "sdk": sdk, "sdkName": sdkName, "xcode": xcode])
        var out = [Finding(
            ruleID: "SECH-09.platform_versions", vectorID: "SECH-09",
            title: copy.title, explanation: copy.explanation,
            severity: .derived("SECH-09.platform_versions", "SECH-09"), evidences: evidences).with(metrics: copy.values)]

        if let major = Int(sdk.split(separator: ".").first ?? ""), major < uploadMinimum.sdkMajor {
            let m = uploadMinimum
            let below = Messages.entry("SECH-09.sdk_below_upload_minimum", [
                "sdk": sdk, "sdkMajor": String(m.sdkMajor), "xcodeMajor": String(m.xcodeMajor),
                "effective": m.effective,
            ])
            out.append(Finding(
                ruleID: "SECH-09.sdk_below_upload_minimum", vectorID: "SECH-09",
                title: below.title, explanation: below.explanation,
                severity: .derived("SECH-09.sdk_below_upload_minimum", "SECH-09"), evidences: [evidences[1]],
                remediation: below.remediation).with(metrics: below.values))
        }
        return out
    }

    static func xcodeVersion(_ raw: String) -> String {
        guard raw.count >= 3, raw.allSatisfy(\.isNumber) else { return raw }
        let major = raw.dropLast(2)
        let minor = raw.dropFirst(raw.count - 2).first.map(String.init) ?? "0"
        return "\(Int(major) ?? 0).\(minor)"
    }
}
