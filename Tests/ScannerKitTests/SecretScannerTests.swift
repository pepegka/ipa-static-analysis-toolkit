import XCTest
@testable import ScannerKit

final class SecretScannerTests: XCTestCase {

    func testFirebaseConfigKeyIsNotASecret() {
        let items: [SecretScanner.TextItem] = [
            ("<string>AIzaSyA1234567890abcdefghijklmnopqrstuv</string>",
             "GoogleService-Info.plist", nil),
        ]
        let findings = SecretScanner.findings(from: SecretScanner.hits(in: items))
        XCTAssertFalse(findings.isEmpty, "The key should still be inventoried, not silently dropped")
        for f in findings {
            XCTAssertEqual(f.severity, .info,
                           "A Firebase client identifier must not ship as a high-severity secret")
            XCTAssertTrue(f.ruleID.contains("public_client_identifier"), f.ruleID)
            XCTAssertTrue(f.explanation.lowercased().contains("identif"),
                          "Explanation must say the value identifies rather than authorises")
        }
    }

    func testFirebaseKeyDowngradedInInventory() {
        let items: [SecretScanner.TextItem] = [
            ("<string>AIzaSyA1234567890abcdefghijklmnopqrstuv</string>",
             "GoogleService-Info.plist", nil),
        ]
        let hits = SecretScanner.hits(in: items)
        XCTAssertEqual(hits.count, 1)
        XCTAssertEqual(hits.first?.severity, .info,
                       "The Secrets inventory must not read as a leaked credential either")
    }

    func testSameKeyOutsideFirebaseConfigIsASecret() {
        let items: [SecretScanner.TextItem] = [
            ("apiKey = \"AIzaSyA1234567890abcdefghijklmnopqrstuv\"", "MyApp", nil),
        ]
        let findings = SecretScanner.findings(from: SecretScanner.hits(in: items))
        XCTAssertTrue(findings.contains { $0.severity >= .high },
                      "A Google API key in the binary is still a real finding")
    }

    func testFrameworkDefaultsAndFixturesSuppressed() {
        let items: [SecretScanner.TextItem] = [
            (#"client_secret = "aGVsbG9Xb3JsZFNlY3JldEtleTEyMzQ1Njc4""#,
             "Data/Managed/mono/4.0/machine.config", nil),
            (#"api_key = "aGVsbG9Xb3JsZFNlY3JldEtleTEyMzQ1Njc4""#,
             "remote_config_defaults.test.plist", nil),
            (#"password = "aGVsbG9Xb3JsZFNlY3JldEtleTEyMzQ1Njc4""#,
             "Fixtures/sample-credentials.json", nil),
        ]
        XCTAssertTrue(SecretScanner.hits(in: items).isEmpty,
                      "Framework-default config and test/sample fixtures are not app secrets")
    }

    func testPublicIdentifierIsInventoryNotCredential() {
        let items: [SecretScanner.TextItem] = [
            ("<string>AIzaSyA1234567890abcdefghijklmnopqrstuv</string>",
             "GoogleService-Info.plist", nil),
        ]
        let findings = SecretScanner.findings(from: SecretScanner.hits(in: items))
        XCTAssertFalse(findings.isEmpty, "The key should still be inventoried")
        for f in findings {
            XCTAssertEqual(f.severity, .info,
                           "\(f.ruleID): Firebase client config is public, not a leaked secret")
        }
    }

    func testDetectsKnownFormats() {
        let entropy = SecretScanner.shannonEntropy("AKIAIOSFODNN7EXAMPLE")
        XCTAssertGreaterThan(entropy, 2.0)
        let redacted = SecretScanner.redact("AKIAIOSFODNN7EXAMPLE")
        XCTAssertFalse(redacted.contains("IOSFODNN"), "Redaction must not leak the middle of the secret")
        XCTAssertTrue(redacted.hasPrefix("AKIA"))
    }

    func testDetectsModernFormats() {
        let items: [SecretScanner.TextItem] = [
            ("sk-ant-api03-" + String(repeating: "A", count: 40), "b", nil),
            ("github_pat_" + String(repeating: "B", count: 30), "b", nil),
            ("glpat-" + String(repeating: "C", count: 22), "b", nil),
        ]
        let hits = SecretScanner.hits(in: items)
        let types = Set(hits.map(\.type))
        XCTAssertTrue(types.contains("Anthropic API Key"))
        XCTAssertTrue(types.contains("GitHub Fine-grained PAT"))
        XCTAssertTrue(types.contains("GitLab PAT"))
        XCTAssertTrue(hits.first { $0.type == "Anthropic API Key" }?.severity == .critical)
    }

    func testPerClassSeverities() {
        let items: [SecretScanner.TextItem] = [
            ("AKIAIOSFODNN7EXAMPLE", "bin", nil),
            ("-----BEGIN RSA PRIVATE KEY-----\n" + Array(repeating: String(repeating: "MIIEowIBAAKCAQEA", count: 4), count: 4).joined(separator: "\n") + "\n-----END RSA PRIVATE KEY-----", "bin", nil),
            (#"api_key = "aGVsbG9Xb3JsZFNlY3JldEtleTEyMzQ1Njc4""#, "bin", nil),
        ]
        let hits = SecretScanner.hits(in: items)
        func sev(_ type: String) -> Severity? { hits.first { $0.type == type }?.severity }
        XCTAssertEqual(sev("AWS Access Key ID"), .critical)
        XCTAssertEqual(sev("Private Key (PEM)"), .critical)
        XCTAssertEqual(sev("Generic Credential"), .medium)
        XCTAssertNotEqual(sev("AWS Access Key ID"), sev("Generic Credential"))
    }
}

final class SecretProvenanceTests: XCTestCase {

    private let key = "AIzaSyA1234567890abcdefghijklmnopqrstuv"

    func testFirebaseConfigVariantsAreRecognisedByName() {
        for name in ["GoogleService-Info-Prod.plist", "GoogleService-Info-us-prod.plist",
                     "PayPal-GoogleService-Info.plist", "YikYak.GoogleService-Info.Prod.plist",
                     "Config/GoogleService-Info-enterprise.plist"] {
            let hits = SecretScanner.hits(in: [("<string>\(key)</string>", name, nil)])
            XCTAssertEqual(hits.first?.publicIdentifier, true, name)
            XCTAssertEqual(hits.first?.severity, .info, name)
        }
    }

    func testFirebaseConfigRecognisedByContent() {
        XCTAssertTrue(SecretScanner.isPublicClientConfig(["GOOGLE_APP_ID": "1:2:ios:3", "API_KEY": key]))
        XCTAssertFalse(SecretScanner.isPublicClientConfig(["API_KEY": key]))
        let hits = SecretScanner.hits(in: [("<string>\(key)</string>", "Env/Secrets.plist", nil)],
                                      publicConfigSources: ["Env/Secrets.plist"])
        XCTAssertEqual(hits.first?.publicIdentifier, true)
        let other = SecretScanner.hits(in: [("<string>\(key)</string>", "Env/Secrets.plist", nil)])
        XCTAssertNotEqual(other.first?.publicIdentifier, true)
        XCTAssertEqual(other.first?.isCredential, true)
    }

    func testPEMBoundariesAloneAreNotAKey() {
        for s in ["-----BEGIN PRIVATE KEY-----",
                  "-----BEGIN RSA PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----"] {
            XCTAssertTrue(SecretScanner.hits(in: [(s, "Frameworks/X.framework/X", nil)]).isEmpty, s)
        }
    }

    func testPEMWithBodyIsAKey() {
        let body = (0..<5).map { _ in String(repeating: "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC", count: 2) }.joined(separator: "\n")
        let pem = "-----BEGIN PRIVATE KEY-----\n\(body)\n-----END PRIVATE KEY-----"
        let hits = SecretScanner.hits(in: [(pem, "keys/server.pem", nil)])
        XCTAssertEqual(hits.first?.type, "Private Key (PEM)")
        let json = #"{"key":"-----BEGIN PRIVATE KEY-----\n"# + body.replacingOccurrences(of: "\n", with: #"\n"#) + #"\n-----END PRIVATE KEY-----"}"#
        XCTAssertEqual(SecretScanner.hits(in: [(json, "config.json", nil)]).first?.type, "Private Key (PEM)")
    }

    func testPEMReassembledFromContiguousBinaryStrings() {
        let lines = ["-----BEGIN PRIVATE KEY-----"] + (0..<4).map { _ in String(repeating: "QUJDREVGR0hJSktMTU5PUA", count: 3) } + ["-----END PRIVATE KEY-----"]
        var off: UInt64 = 100
        var strs: [ExtractedString] = []
        for l in lines { strs.append(ExtractedString(value: l, offset: off, isUTF16: false)); off += UInt64(l.utf8.count) + 1 }
        let joined = SecretScanner.joinedPEM(strs, from: 0)
        XCTAssertEqual(joined, lines.joined(separator: "\n"))
        XCTAssertFalse(SecretScanner.hits(in: [(joined, "Frameworks/K.framework/K", "__TEXT/__cstring")]).isEmpty)
        var gapped = strs; gapped[1] = ExtractedString(value: lines[1], offset: strs[1].offset + 8, isUTF16: false)
        XCTAssertEqual(SecretScanner.joinedPEM(gapped, from: 0), lines[0])
    }

    func testDesignTokenIsNotAGenericCredential() {
        let hits = SecretScanner.hits(in: [(#""typographyToken" : "tsCompactControl500Medium""#, "Fintech.bundle/snackbar.json", nil)])
        XCTAssertTrue(hits.isEmpty)
        let real = SecretScanner.hits(in: [(#""xTokenClientSecret" : "8308f1c2a9b44d7e9c3a57d3""#, "quark.cfg", nil)])
        XCTAssertEqual(real.first?.type, "Generic Credential")
    }

    func testRuleIDsAreStableAndInstanceNamesTheFile() {
        let hits = SecretScanner.hits(in: [
            ("<string>\(key)</string>", "GoogleService-Info.plist", nil),
            ("token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "a/mock1.json", nil),
            ("token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwMSJ9.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG", "b/data.json", nil),
        ])
        let fs = SecretScanner.findings(from: hits)
        let ids = Set(fs.map(\.ruleID))
        XCTAssertEqual(ids, ["SECH-05.public_client_identifier.google_api_key", "SECH-05.bearer_token.json_web_token"])
        XCTAssertEqual(Set(fs.compactMap(\.instance)), ["GoogleService-Info.plist", "b/data.json"])
        XCTAssertFalse(fs.contains { $0.ruleID.contains("/") })
    }
}
