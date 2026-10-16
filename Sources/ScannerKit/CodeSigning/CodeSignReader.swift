import Foundation

struct CodeSignInfo: Sendable {
    public let signedIdentifier: String?
    public let signedTeamID: String?
    public let entitlementsXML: String?
    public var codeDirectoryVersion: Int? = nil
}

enum CodeSignReader {

    public static func read(appDirectory: URL) -> CodeSignInfo {
        var ident: String? = nil
        var team: String? = nil
        var cdVersion: Int? = nil
        if let res = try? Shell.run("/usr/bin/codesign", ["-dvvv", appDirectory.path]) {
            let text = res.stderrString.isEmpty ? res.stdoutString : res.stderrString
            for line in text.split(separator: "\n") {
                let s = String(line)
                if s.hasPrefix("Identifier=") {
                    ident = String(s.dropFirst("Identifier=".count))
                } else if s.hasPrefix("TeamIdentifier=") {
                    team = String(s.dropFirst("TeamIdentifier=".count))
                } else if s.hasPrefix("CodeDirectory v="),
                          let v = s.dropFirst("CodeDirectory v=".count).split(separator: " ").first {
                    cdVersion = Int(v, radix: 16)
                }
            }
        }

        var entXML: String? = nil
        if let res = try? Shell.run("/usr/bin/codesign",
                                    ["-d", "--entitlements", "-", "--xml", appDirectory.path]),
           res.exitCode == 0, !res.stdout.isEmpty {
            entXML = String(decoding: res.stdout, as: UTF8.self)
        } else if let res = try? Shell.run("/usr/bin/codesign",
                                           ["-d", "--entitlements", ":-", appDirectory.path]),
                  res.exitCode == 0, !res.stdout.isEmpty {
            entXML = String(decoding: res.stdout, as: UTF8.self)
        }

        return CodeSignInfo(signedIdentifier: ident, signedTeamID: team, entitlementsXML: entXML,
                            codeDirectoryVersion: cdVersion)
    }

    static let minimumCodeDirectoryVersion = 0x20400

    static func findings(_ info: CodeSignInfo) -> [Finding] {
        guard let v = info.codeDirectoryVersion, v < minimumCodeDirectoryVersion else { return [] }
        let shown = String(v, radix: 16)
        let copy = Messages.entry("SECH-06.outdated_signature_format", ["version": shown])
        return [Finding(
            ruleID: "SECH-06.outdated_signature_format", vectorID: "SECH-06",
            title: copy.title, explanation: copy.explanation,
            severity: .derived("SECH-06.outdated_signature_format", "SECH-06"), evidences: [Evidence(kind: .file, value: "CodeDirectory v=\(shown)", source: "codesign")],
            remediation: copy.remediation).with(metrics: copy.values)]
    }
}
