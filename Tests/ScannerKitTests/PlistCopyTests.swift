import XCTest
@testable import ScannerKit

final class PlistCopyTests: XCTestCase {

    func testInadequatePurposeStrings() {
        let bad: [(String, String)] = [
            ("NSCameraUsageDescription", ""),
            ("NSCameraUsageDescription", "   "),
            ("NSLocationWhenInUseUsageDescription", "$(PRODUCT_NAME) needs your location"),
            ("NSContactsUsageDescription", "NSContactsUsageDescription"),
            ("NSMicrophoneUsageDescription", "TODO"),
            ("NFCReaderUsageDescription", "NFC tag reading description"),
        ]
        for (k, v) in bad { XCTAssertTrue(PurposeStrings.isInadequate(key: k, value: v), "\(k) = \(v)") }
        let good: [(String, String)] = [
            ("NSCameraUsageDescription", "Scan QR codes and photograph documents to attach to applications"),
            ("NSFaceIDUsageDescription", "Unlock the app without entering your PIN"),
            ("NSPhotoLibraryUsageDescription", "Attach a photo to the item description when you list it for sale"),
        ]
        for (k, v) in good { XCTAssertFalse(PurposeStrings.isInadequate(key: k, value: v), "\(k) = \(v)") }
    }

    func testEmptyManifestValuesAreNamed() {
        XCTAssertEqual(PrivacyManifestValidator.readableValues(["", ""]), "an empty string (\"\")")
        XCTAssertEqual(PrivacyManifestValidator.readableValues(["Foo", "", "Foo"]), "Foo, an empty string (\"\")")
    }
}

final class RuleCopyTests: XCTestCase {
    func testDescriptionsAreUnwrapped() {
        XCTAssertEqual(Rule.unwrap("Imports rand() / srand(), predictable PRNGs unsuitable\nfor keys.\n"),
                       "Imports rand() / srand(), predictable PRNGs unsuitable for keys.")
        XCTAssertEqual(Rule.unwrap("One.\n\nTwo\nlines."), "One.\n\nTwo lines.")
        for r in RuleLoader.loadBundled().rules {
            XCTAssertFalse(r.description.replacingOccurrences(of: "\n\n", with: "").contains("\n"), r.id)
        }
    }

    func testMASProfilesAreNamed() {
        XCTAssertEqual(FrameworkLinks.profileLabels(maswe: ["MASWE-0066"]).first?.hasPrefix("MAS-"), true)
        XCTAssertTrue(FrameworkLinks.profileLabels(maswe: ["MASWE-0066"]).contains { $0.contains("Baseline Privacy") })
    }
}

final class DeclaredConditionTests: XCTestCase {
    private func always() -> Finding {
        Finding(ruleID: "DCS-02.always_authorization", vectorID: "DCS-02", title: "t", explanation: "e",
                severity: .medium, evidences: [])
    }

    func testAlwaysLocationWithoutTheAlwaysKeyIsInfo() {
        let out = Scanner.applyDeclaredConditions([always()], declaredKeys: ["NSLocationWhenInUseUsageDescription"])
        XCTAssertEqual(out.first?.severity, .info)
        XCTAssertTrue(out.first?.explanation.contains("criterion 3") ?? false)
    }

    func testAlwaysLocationWithTheAlwaysKeyStaysMedium() {
        let out = Scanner.applyDeclaredConditions([always()],
            declaredKeys: ["NSLocationWhenInUseUsageDescription", "NSLocationAlwaysAndWhenInUseUsageDescription"])
        XCTAssertEqual(out.first?.severity, .medium)
        XCTAssertEqual(out.first?.explanation, "e")
    }

    private func finding(_ rule: String, _ sev: Severity, requires: [String] = []) -> Finding {
        var f = Finding(ruleID: rule, vectorID: String(rule.split(separator: ".").first ?? ""), title: "t",
                        explanation: "e", severity: sev, evidences: [])
        f.permissionsRequired = requires
        return f
    }

    func testADeclaredPermissionStaysWhenItScoresAboveTheCodeFinding() {
        let key = "NSUserTrackingUsageDescription"
        let out = Scanner.droppingCoveredPermissions([
            finding("perm.\(key)", .medium), finding("DCS-01.idfa_idfv", .info, requires: [key])])
        XCTAssertEqual(out.map(\.ruleID).sorted(), ["DCS-01.idfa_idfv", "perm.\(key)"])
    }

    func testADeclaredPermissionIsDroppedWhenTheCodeFindingCoversIt() {
        let key = "NSLocationAlwaysAndWhenInUseUsageDescription"
        let out = Scanner.droppingCoveredPermissions([
            finding("perm.\(key)", .medium), finding("DCS-02.always_authorization", .medium, requires: [key]),
            finding("perm.NSCameraUsageDescription", .info)])
        XCTAssertEqual(out.map(\.ruleID).sorted(), ["DCS-02.always_authorization", "perm.NSCameraUsageDescription"])
    }

    func testAppGroupDefaultsRuleNeedsTheDeclaredReason() {
        let r = RuleLoader.loadBundled().rules.first { $0.id == "DCS-01.user_defaults_appgroup_fingerprint" }!
        XCTAssertEqual(r.polarity, .neutral)
        XCTAssertFalse(r.title.contains("IDFA"))
        XCTAssertEqual(r.maswe ?? [], [])
    }
}

final class ReasonCodeRuleTests: XCTestCase {
    func testAppGroupDefaultsRuleFiresOnTheDeclaredReason() {
        func fires(_ reasons: [String]) -> Bool {
            var m = NetworkAttributionTests.metadata()
            m.privacyAccessedAPIReasons = reasons
            let input = RuleInput(metadata: m, indices: [:], provisioningEntitlements: [], codesignEntitlements: [])
            return RuleEngine(rules: RuleLoader.loadBundled().rules).evaluate(input)
                .contains { $0.ruleID == "DCS-01.user_defaults_appgroup_fingerprint" }
        }
        XCTAssertTrue(fires(["CA92.1", "1C8F.1"]))
        XCTAssertFalse(fires(["CA92.1"]), "app-only defaults are not an App Group store")
    }
}

final class UserAdviceTests: XCTestCase {
    func testRuleAdviceOverridesTheVectorsAndFallsBack() {
        let own = Messages.userAdvice(ruleID: "TGAP-02.inadequate_purpose_string", vectorID: "TGAP-02")
        XCTAssertNotNil(own)
        XCTAssertFalse(own!.contains("Ask App Not to Track"), "the ATT advice does not fit a purpose-string finding")
        XCTAssertEqual(Messages.userAdvice(ruleID: "TGAP-02.tracking_without_att", vectorID: "TGAP-02"),
                       Vectors.byID["TGAP-02"]?.userAdvice)
    }
}

final class CertValidationRuleTests: XCTestCase {
    func testLibraryErrorTextIsNotDisabledValidation() {
        let r = RuleLoader.loadBundled().rules.first { $0.id == "SECH-01.disabled_cert_validation" }!
        let pattern = r.search.map(\.pattern).joined()
        let re = try! NSRegularExpression(pattern: pattern)
        func hit(_ s: String) -> Bool { re.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil }
        XCTAssertFalse(hit("Security option unavailable - kCFStreamSSLValidatesCertificateChain - You must use manual trust evaluation"))
        XCTAssertTrue(hit("setAllowsAnyHTTPSCertificate:forHost:"))
    }
}

final class RequiredLiteralTests: XCTestCase {
    func testRequiredLiteralsAreSubstringsOfEveryMatch() {
        let cases: [(String, [String])] = [
            ("requestAlwaysAuthorization$|\\$setAllowsBackgroundLocationUpdates:$",
             ["_objc_msgSend$requestAlwaysAuthorization", "_FBCLRequestAlwaysAuthorization",
              "_objc_msgSend$setAllowsBackgroundLocationUpdates:"]),
            ("objc_msgSend\\$setInspectable:$", ["_objc_msgSend$setInspectable:"]),
            ("^_JSGlobalContextSetInspectable2?$", ["_JSGlobalContextSetInspectable", "_JSGlobalContextSetInspectable2"]),
            ("OBJC_(META)?CLASS_\\$_FIRAnalytics$|FirebaseAnalytics", ["_OBJC_CLASS_$_FIRAnalytics", "_OBJC_METACLASS_$_FIRAnalytics"]),
            ("startMonitoringVisits|CLVisit(?!Mock)", ["_OBJC_CLASS_$_CLVisit", "_symbolic So7CLVisitC5visit"]),
        ]
        for (pattern, samples) in cases {
            let needles = RuleEngine.requiredLiterals(from: pattern)
            XCTAssertFalse(needles.isEmpty, pattern)
            let re = try! NSRegularExpression(pattern: pattern, options: [.caseInsensitive])
            for s in samples {
                XCTAssertNotNil(re.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)), "\(pattern) should match \(s)")
                XCTAssertTrue(needles.contains { s.lowercased().contains($0.lowercased()) }, "\(pattern): \(needles) miss \(s)")
            }
        }
    }
}
