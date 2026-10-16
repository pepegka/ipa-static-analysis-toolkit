import XCTest
@testable import ScannerKit

final class TransportSecurityTests: XCTestCase {

    func testFlagsArbitraryLoads() {
        let result = ATSAnalyzer.analyze(ats: ["NSAllowsArbitraryLoads": true])
        XCTAssertTrue(result.config.allowsArbitraryLoads)
        XCTAssertTrue(result.findings.contains { $0.vectorID == "SECH-01" })
    }

    func testParsesExceptionDomains() {
        let ats: [String: Any] = [
            "NSExceptionDomains": [
                "example.com": [
                    "NSExceptionAllowsInsecureHTTPLoads": true,
                    "NSIncludesSubdomains": true,
                    "NSExceptionMinimumTLSVersion": "TLSv1.0",
                ]
            ]
        ]
        let result = ATSAnalyzer.analyze(ats: ats)
        XCTAssertEqual(result.config.exceptionDomains.count, 1)
        let d = result.config.exceptionDomains[0]
        XCTAssertEqual(d.domain, "example.com")
        XCTAssertTrue(d.allowsInsecureHTTPLoads)
        XCTAssertTrue(result.findings.contains { $0.ruleID == "SECH-01.insecure_exception_domains" })
    }

    func testPinningMachinerySuppressesAbsenceClaim() {
        let ats: [String: Any] = [
            "NSExceptionDomains": ["example.com": ["NSIncludesSubdomains": true]]
        ]
        let index = makeIndex(rel: "MyApp",
                              imported: ["_SecTrustEvaluateWithError", "_SecTrustSetAnchorCertificates"],
                              defined: [])
        let result = ATSAnalyzer.analyze(ats: ats, indices: ["MyApp": index],
                                         bundledCertificates: ["amex-root.der"])
        XCTAssertFalse(result.findings.contains { $0.ruleID == "SECH-01.missing_pinning" },
                       "Pinning machinery is present, absence must not be asserted")
    }

    func testMissingPinningFiresWithoutMachinery() {
        let ats: [String: Any] = [
            "NSExceptionDomains": ["example.com": ["NSIncludesSubdomains": true]]
        ]
        let result = ATSAnalyzer.analyze(ats: ats)
        XCTAssertTrue(result.findings.contains { $0.ruleID == "SECH-01.missing_pinning" })
    }

    func testGenericTrustEvaluationIsNotPinning() {
        let weak = makeIndex(rel: "MyApp",
                             imported: ["_SecTrustEvaluateWithError", "_SecPolicyCreateSSL",
                                        "_SecCertificateCopyData"], defined: [])
        XCTAssertTrue(ATSAnalyzer.pinningMachinery(indices: ["MyApp": weak],
                                                   bundledCertificates: []).isEmpty,
                      "Generic trust evaluation must not suppress the absence claim on its own")

        let strong = makeIndex(rel: "MyApp",
                               imported: ["_SecTrustEvaluateWithError",
                                          "_SecTrustSetAnchorCertificates"], defined: [])
        XCTAssertFalse(ATSAnalyzer.pinningMachinery(indices: ["MyApp": strong],
                                                    bundledCertificates: []).isEmpty)
        XCTAssertFalse(ATSAnalyzer.pinningMachinery(indices: [:],
                                                    bundledCertificates: ["anchor.der"]).isEmpty)
    }

    func testServerTrustHookIsNotPinning() {
        let index = makeIndex(rel: "MyApp",
                              imported: ["_NSURLAuthenticationMethodServerTrust"], defined: [])
        XCTAssertTrue(ATSAnalyzer.pinningMachinery(indices: ["MyApp": index],
                                                   bundledCertificates: []).isEmpty,
                      "The server-trust hook is equally the way apps ACCEPT every certificate")
    }
}
