import XCTest
@testable import ScannerKit

final class SeverityDerivationTests: XCTestCase {

    func testEverySecurityVectorHasACVSSv4Anchor() {
        for v in Vectors.all where v.construct == .SECH || v.construct == .PLAT {
            if SeverityDerivation.entry(ruleID: "\(v.id).probe", vectorID: v.id)?.method == "capability" { continue }
            let cw = FrameworkCrosswalk.for(vectorID: v.id)
            guard let cvss = cw.cvss else {
                return XCTFail("\(v.id) has no CVSS anchor")
            }
            XCTAssertTrue(cvss.hasPrefix("CVSS:4.0/"), "\(v.id) CVSS is not v4.0: \(cvss)")
        }
    }

    func testEveryPrivacyVectorHasAHarmCellAnchor() {
        for v in Vectors.all where [.DCS, .TRK, .TGAP].contains(v.construct) {
            let cw = FrameworkCrosswalk.for(vectorID: v.id)
            XCTAssertFalse(cw.linddun.isEmpty && cw.solove.isEmpty,
                           "\(v.id) has no privacy-harm anchor (LINDDUN/Solove)")
        }
    }

    func testFrameworkVersionsPinCVSSv4() {
        XCTAssertEqual(FrameworkVersions.current.cvss, "4.0")
    }

    func testAntiAnalysisFamilyIsDefensive() {
        let pack = RuleLoader.loadBundled()
        let surv2 = pack.rules.filter { $0.vector == "SURV-02" }
        XCTAssertFalse(surv2.isEmpty)
        for r in surv2 {
            let expected: Polarity = r.id == "SURV-02.dyld_image_introspection" ? .neutral : .defensive
            XCTAssertEqual(r.polarity, expected, r.id)
            XCTAssertLessThanOrEqual(r.severity, .low, r.id)
        }
    }

    func testHighRiskNeedsTwoScoredCriteria() {
        XCTAssertEqual(SeverityDerivation.severity(criteria: []), .info)
        XCTAssertEqual(SeverityDerivation.severity(criteria: [4]), .info)
        XCTAssertEqual(SeverityDerivation.severity(criteria: [3, 4]), .medium)
        XCTAssertEqual(SeverityDerivation.severity(criteria: [4, 5]), .info)
    }

    func testTrackerCategoriesFollowWP248() {
        XCTAssertEqual(SeverityDerivation.trackerSeverity(category: "advertising"), .medium)
        XCTAssertEqual(SeverityDerivation.trackerSeverity(category: "attribution"), .medium)
        XCTAssertEqual(SeverityDerivation.trackerSeverity(category: "antifraud"), .medium)
        XCTAssertEqual(SeverityDerivation.trackerSeverity(category: "session-replay"), .medium)
        XCTAssertEqual(SeverityDerivation.trackerSeverity(category: "analytics"), .info)
        XCTAssertEqual(SeverityDerivation.trackerSeverity(category: "crash"), .info)
    }

    func testPrivacyAnchorsNameOnlyWP248Criteria() {
        let known = Set(SeverityDerivation.highRisk.criteria.keys.compactMap(Int.init))
        XCTAssertEqual(known, Set(1...9))
        for id in SeverityDerivation.anchoredRuleIDs.union(SeverityDerivation.anchoredVectorIDs) {
            guard let e = SeverityDerivation.entry(ruleID: id, vectorID: id), e.method == "privacy" else { continue }
            XCTAssertNotNil(e.wp248, id)
            for c in e.wp248 ?? [] { XCTAssertTrue(known.contains(c), "\(id): criterion \(c)") }
            for key in (e.wp248When ?? [:]).keys {
                XCTAssertTrue(e.wp248?.contains(Int(key) ?? 0) ?? false, "\(id): condition on unlisted criterion \(key)")
            }
            XCTAssertFalse((e.why ?? "").isEmpty, "\(id) has no rationale")
        }
    }

    func testRepresentativeSeverities() {
        XCTAssertEqual(bundledRule("DCS-06.canOpenURL")?.severity, .info)
        XCTAssertEqual(bundledRule("DCS-02.always_authorization")?.severity, .medium)
        XCTAssertEqual(bundledRule("PLAT-01.legacy_uiwebview")?.severity, .high)
        XCTAssertEqual(bundledRule("SECH-03.weak_hash")?.severity, .info)
        XCTAssertEqual(bundledRule("SECH-01.cfstream_plaintext_socket")?.severity, .info)
        XCTAssertNil(bundledRule("SECH-02.plaintext_sqlite"))
        XCTAssertEqual(bundledRule("SECH-06.get_task_allow")?.severity, .high)
        let brokers = RuleLoader.loadBundled().rules.filter { $0.vector == "TRK-02" }
        XCTAssertFalse(brokers.isEmpty)
        for b in brokers { XCTAssertEqual(b.severity, .medium, b.id) }
    }


    func testEveryPackRuleAgreesWithItsDerivation() {
        let pack = RuleLoader.loadBundled().rules
        XCTAssertFalse(pack.isEmpty, "no rules loaded")
        var unanchored: [String] = []
        var disagreeing: [String] = []
        for rule in pack {
            guard let derived = SeverityDerivation.severity(ruleID: rule.id, vectorID: rule.vector) else {
                unanchored.append(rule.id)
                continue
            }
            if derived != rule.severity {
                disagreeing.append("\(rule.id): pack says \(rule.severity.rawValue), "
                    + "derivation says \(derived.rawValue)")
            }
        }
        XCTAssertEqual(unanchored, [], "rules with no anchor in taxonomy/severity-derivation.json")
        XCTAssertEqual(disagreeing, [], "run scripts/sync-rule-severities.py, read the diff, commit both")
    }

    func testAnnotatedFindingCitesItsOwnAnchor() {
        var mismatched: [String] = []
        for id in SeverityDerivation.anchoredRuleIDs {
            guard let anchor = SeverityDerivation.entry(ruleID: id, vectorID: "") else { continue }
            let vectorID = id.split(separator: ".").first.map(String.init) ?? id
            let f = Finding(ruleID: id, vectorID: vectorID, title: "t", explanation: "e",
                            severity: .info, evidences: [])
                .annotatedWithCrosswalk()
            if f.cvss != anchor.cvss {
                mismatched.append("\(id): cites \(f.cvss ?? "none"), anchored to \(anchor.cvss ?? "none")")
            }
            if let why = anchor.why, f.why != why {
                mismatched.append("\(id): dropped its rationale")
            }
            for t in anchor.mitre ?? [] where !f.mitre.contains(t) {
                mismatched.append("\(id): dropped MITRE \(t)")
            }
            for c in anchor.cwe ?? [] where !f.cwe.contains(c) {
                mismatched.append("\(id): dropped CWE \(c)")
            }
        }
        XCTAssertEqual(mismatched, [], "a finding is citing something other than the anchor that set its severity")
    }

    func testEveryAnchorResolves() {
        for id in SeverityDerivation.anchoredRuleIDs {
            guard let e = SeverityDerivation.entry(ruleID: id, vectorID: "") else {
                return XCTFail("\(id) does not resolve to itself")
            }
            XCTAssertNotNil(SeverityDerivation.severity(for: e), "\(id) has an anchor that yields no band")
        }
        for id in SeverityDerivation.anchoredVectorIDs {
            guard let e = SeverityDerivation.entry(ruleID: "\(id).nonexistent", vectorID: id) else {
                return XCTFail("\(id) has no vector entry")
            }
            XCTAssertNotNil(SeverityDerivation.severity(for: e), "\(id) has an anchor that yields no band")
        }
    }

    func testCVSSAnchorsCarryAv4VectorAndAScore() {
        for id in SeverityDerivation.anchoredRuleIDs {
            guard let e = SeverityDerivation.entry(ruleID: id, vectorID: ""), e.method == "cvss" else { continue }
            XCTAssertTrue(e.cvss?.hasPrefix("CVSS:4.0/") == true, "\(id) is not anchored to a v4.0 vector")
            guard let score = e.cvssScore else {
                return XCTFail("\(id) has no cvssScore; run node scripts/cvss4-fill.mjs")
            }
            XCTAssertTrue((0...10).contains(score), "\(id) score \(score) is outside the CVSS range")
        }
    }

    func testCVSSBandsMatchTheSpecification() {
        XCTAssertEqual(SeverityDerivation.band(for: 0.0), .info)
        XCTAssertEqual(SeverityDerivation.band(for: 0.1), .low)
        XCTAssertEqual(SeverityDerivation.band(for: 3.9), .low)
        XCTAssertEqual(SeverityDerivation.band(for: 4.0), .medium)
        XCTAssertEqual(SeverityDerivation.band(for: 6.9), .medium)
        XCTAssertEqual(SeverityDerivation.band(for: 7.0), .high)
        XCTAssertEqual(SeverityDerivation.band(for: 8.9), .high)
        XCTAssertEqual(SeverityDerivation.band(for: 9.0), .critical)
        XCTAssertEqual(SeverityDerivation.band(for: 10.0), .critical)
    }

    func testPrivacyAnchorsCiteAnArticleAndAHarm() {
        var missing: [String] = []
        for id in SeverityDerivation.anchoredRuleIDs.union(SeverityDerivation.anchoredVectorIDs) {
            let e = SeverityDerivation.entry(ruleID: id, vectorID: id)
            guard let e, e.method == "privacy" else { continue }
            if (e.gdpr ?? []).isEmpty { missing.append("\(id): no GDPR article") }
            if (e.linddun ?? []).isEmpty && (e.solove ?? []).isEmpty {
                missing.append("\(id): no LINDDUN threat or Solove harm")
            }
        }
        XCTAssertEqual(missing, [])
    }

    func testPrivacyMethodStopsAtMedium() {
        for id in SeverityDerivation.anchoredRuleIDs.union(SeverityDerivation.anchoredVectorIDs) {
            let e = SeverityDerivation.entry(ruleID: id, vectorID: id)
            guard let e, e.method == "privacy" else { continue }
            XCTAssertLessThanOrEqual(SeverityDerivation.severity(for: e) ?? .info, .medium, id)
        }
    }

    func testEgressSeverityDoesNotDependOnDestination() {
        let bands = ["us", "cn", "ru", "il", "ch", "de", "sg", "in", "gb", "jp"].map {
            Severity.derived("TRK-04.egress.\($0)", "TRK-04")
        }
        XCTAssertEqual(Set(bands), [.info], "egress severity varies by country")
    }
}
