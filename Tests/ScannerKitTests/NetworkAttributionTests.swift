import XCTest
@testable import ScannerKit

final class NetworkAttributionTests: XCTestCase {

    func testICANNMultiLabelSuffixes() {
        XCTAssertEqual(PublicSuffixList.registrableDomain(for: "a.b.example.co.uk"), "example.co.uk")
        XCTAssertEqual(PublicSuffixList.registrableDomain(for: "mail.example.ne.jp"), "example.ne.jp")
        XCTAssertEqual(PublicSuffixList.registrableDomain(for: "smtp.provider.co.id"), "provider.co.id")
        XCTAssertEqual(PublicSuffixList.registrableDomain(for: "www.example.com"), "example.com")
    }

    func testPrivateSectionSeparatesTenants() {
        XCTAssertEqual(PublicSuffixList.registrableDomain(for: "lamoda-com.appspot.com"), "lamoda-com.appspot.com")
        XCTAssertEqual(PublicSuffixList.registrableDomain(for: "x.blob.core.windows.net"), "x.blob.core.windows.net")
        XCTAssertEqual(PublicSuffixList.registrableDomain(for: "bucket.s3.amazonaws.com"), "bucket.s3.amazonaws.com")
    }

    func testWildcardAndExceptionRules() {
        let r = PublicSuffixList.parse("""
            // comment
            ck
            *.ck
            !www.ck
            """)
        XCTAssertEqual(PublicSuffixList.publicSuffix(of: "a.b.ck", rules: r), "b.ck")
        XCTAssertEqual(PublicSuffixList.registrableDomain(for: "a.b.ck", rules: r), "a.b.ck")
        XCTAssertEqual(PublicSuffixList.publicSuffix(of: "www.ck", rules: r), "ck")
        XCTAssertEqual(PublicSuffixList.registrableDomain(for: "www.ck", rules: r), "www.ck")
        XCTAssertEqual(PublicSuffixList.registrableDomain(for: "a.b.unlisted", rules: r), "b.unlisted")
    }

    func testSuffixItselfHasNoRegistrableDomain() {
        XCTAssertEqual(PublicSuffixList.registrableDomain(for: "appspot.com"), "appspot.com")
        XCTAssertEqual(PublicSuffixList.registrableDomain(for: "co.uk"), "co.uk")
    }

    private let db = TrackerDB(trackers: [
        Tracker(id: "snap.ads", name: "Snap Ads", owner: "Snap", country: "US", category: "advertising",
                domains: ["tr.snapchat.com", "sc-analytics.appspot.com"], is_tracker: true),
        Tracker(id: "amazon.ads", name: "Amazon Ads", owner: "Amazon", country: "US", category: "advertising",
                domains: ["aax.amazon.com"], is_tracker: true),
        Tracker(id: "persona", name: "Persona", owner: "Persona", country: "US", category: "identity",
                domains: ["personablob.blob.core.windows.net"], is_tracker: nil),
    ])

    func testSharedHostingZoneIsNotClaimedByATracker() {
        XCTAssertEqual(db.classify(host: "sc-analytics.appspot.com")?.id, "snap.ads")
        XCTAssertNil(db.classify(host: "lamoda-com.appspot.com"))
        XCTAssertNil(db.owner(host: "lamoda-com.appspot.com"))
        XCTAssertNil(db.owner(host: "someapp.blob.core.windows.net"))
    }

    func testSubdomainOfDeclaredDomainKeepsIdentity() {
        XCTAssertEqual(db.classify(host: "eu.tr.snapchat.com")?.id, "snap.ads")
    }

    func testSiblingInheritsOwnerButNotIdentity() {
        XCTAssertNil(db.classify(host: "www.amazon.com"))
        XCTAssertEqual(db.owner(host: "www.amazon.com")?.owner, "Amazon")
    }

    func testAssociatedDomainsParsing() {
        let xml = """
            <?xml version="1.0" encoding="UTF-8"?>
            <plist version="1.0"><dict>
            <key>com.apple.developer.associated-domains</key>
            <array>
              <string>applinks:www.tiktok.com</string>
              <string>webcredentials:*.tiktokv.com?mode=developer</string>
              <string>activitycontinuation:tiktok.com</string>
            </array></dict></plist>
            """
        XCTAssertEqual(Scanner.associatedDomains(fromCodesignXML: xml),
                       ["*.tiktokv.com", "tiktok.com", "www.tiktok.com"])
        XCTAssertEqual(NetworkInventoryBuilder.firstPartyDomains(["*.tiktokv.com", "www.tiktok.com", "appspot.com"]),
                       ["tiktokv.com", "tiktok.com"])
    }

    func testFirstPartyEndpointIsNeverATracker() {
        let tiktok = TrackerDB(trackers: [
            Tracker(id: "tiktok.analytics", name: "TikTok Analytics", owner: "ByteDance", country: "CN",
                    category: "analytics", domains: ["analytics.tiktok.com"], is_tracker: true),
        ])
        var m = Self.metadata()
        m.associatedDomains = ["www.tiktok.com"]
        let e = URLExtractor.extract(fromString: "https://analytics.tiktok.com/v1", source: "config.json")
        let inv = NetworkInventoryBuilder.build(metadata: m, indices: [:], trackerDB: tiktok, extraEndpoints: e)
        let ep = try! XCTUnwrap(inv.endpoints.first { $0.host == "analytics.tiktok.com" })
        XCTAssertFalse(ep.isTracker)
        XCTAssertEqual(ep.firstParty, true)
        XCTAssertEqual(ep.owner, "ByteDance")
        XCTAssertTrue(inv.detectedSDKs.isEmpty)

        let other = NetworkInventoryBuilder.build(metadata: Self.metadata(), indices: [:], trackerDB: tiktok, extraEndpoints: e)
        XCTAssertEqual(other.endpoints.first?.isTracker, true)
    }

    func testQualifiedNamesAreNotHosts() {
        for s in ["kclass:io.ktor.utils.io.$ByteChannel", "org.kotlincrypto.hash.md.MD5",
                  "app.cash.redwood.protocol.id.ChildId", "kclass:io.ktor.utils.io#internal",
                  "kfun:ru.minsvyaz.gumetrica.storage.evententity.id#<get-id>(){}kotlin.Long",
                  "io.ktor.utils.io$ByteChannel", "com.usps.rmin.sql.addedpackage.id",
                  "org.kotlincrypto.hash.md", "net.klarna.app.dev",
                  "ru.minsvyaz.gumetrica.storage.evententity.id", "io.github.alexzhirkevich.keight.js.at"] {
            XCTAssertTrue(URLExtractor.extract(fromString: s, source: "x").isEmpty, s)
        }
        XCTAssertEqual(URLExtractor.extract(fromString: "see api.example.com.", source: "x").map(\.host),
                       ["api.example.com"])
        XCTAssertEqual(URLExtractor.extract(fromString: "host=id.vk.com;", source: "x").map(\.host),
                       ["id.vk.com"])
        XCTAssertEqual(URLExtractor.extract(fromString: "br.noticias.yahoo.com app.whiteboard.microsoft.com ru.wikipedia.org", source: "x").map(\.host),
                       ["br.noticias.yahoo.com", "app.whiteboard.microsoft.com", "ru.wikipedia.org"])
        XCTAssertEqual(URLExtractor.extract(fromString: "https://com.example.org/x", source: "x").map(\.host),
                       ["com.example.org"])
    }

    func testTCFVendorListIsAReferenceDocument() {
        let gvl = #"{"gvlSpecificationVersion":3,"vendorListVersion":120,"tcfPolicyVersion":5,"vendors":{"1":{"id":1,"name":"Ad Co","urls":[{"privacy":"https://adco.example/privacy"}]}}}"#
        XCTAssertEqual(ReferenceDocuments.match(fileName: "vendor-list.json", text: gvl), "IAB TCF Global Vendor List")
        XCTAssertNil(ReferenceDocuments.match(fileName: "config.json", text: #"{"vendors":{},"api":"https://api.example.com"}"#))
    }

    func testLicenseTextsAreReferenceDocumentsButLicenseConfigIsNot() {
        XCTAssertNotNil(ReferenceDocuments.match(fileName: "Licenses.html", text: "<a href=https://github.com/x>"))
        XCTAssertNotNil(ReferenceDocuments.match(fileName: "Acknowledgements.plist", text: ""))
        XCTAssertNil(ReferenceDocuments.match(fileName: "license.conf", text: "server=https://lic.example.com"))
    }

    func testCapKeepsDeclaredAndOwnedHostsAndIsDeterministic() {
        var text = ""
        for i in 0..<60 { text += "https://h\(i).example\(i).com/ " }
        text += "https://aax.amazon.com/x https://aax.amazon.com/y"
        let e = URLExtractor.extract(fromString: text, source: "providers.json")
        var m = Self.metadata(trackingDomains: ["declared.example.org"])
        m.associatedDomains = []
        let a = NetworkInventoryBuilder.build(metadata: m, indices: [:], trackerDB: db, extraEndpoints: e, cap: 10)
        let b = NetworkInventoryBuilder.build(metadata: m, indices: [:], trackerDB: db, extraEndpoints: e.reversed(), cap: 10)
        XCTAssertEqual(a.endpoints.count, 10)
        XCTAssertEqual(a.hostsBeforeCap, 62)
        XCTAssertEqual(Set(a.endpoints.map(\.host)), Set(b.endpoints.map(\.host)))
        XCTAssertTrue(a.endpoints.contains { $0.host == "declared.example.org" })
        XCTAssertTrue(a.endpoints.contains { $0.host == "aax.amazon.com" })
    }

    static func metadata(trackingDomains: [String] = []) -> BundleMetadata {
        BundleMetadata(
            bundleID: "com.test.app", bundleName: "T", displayName: "T", shortVersion: "1.0",
            bundleVersion: "1", minimumOSVersion: "17.0", executableName: "T",
            supportedPlatforms: ["iPhoneOS"], urlSchemes: [], queriedURLSchemes: [],
            backgroundModes: [], allowsArbitraryLoads: false, permissions: [],
            privacyManifestPath: nil, privacyTrackingDomains: trackingDomains, privacyAccessedAPIs: [],
            embeddedBinaries: [], embeddedFrameworks: [], provisioning: nil,
            signedTeamID: nil, signedIdentifier: nil)
    }
}

final class DelegatedLinkDomainTests: XCTestCase {
    func testVendorHostedLinkDomainsAreNotFirstParty() {
        let db = TrackerDBLoader.loadBundled()
        let fp = NetworkInventoryBuilder.firstPartyDomains(
            ["cdek.onelink.me", "axje.adj.st", "2c61.ulink.adjust.com", "b80x-alternate.app.link",
             "x.test-app.link", "3162844.redirect.appmetrica.yandex.com", "brand.go.link", "cdek.ru",
             "yxd5a62d0a148c482a894c4ed349cc2e5c.oauth.yandex.ru"],
            trackerDB: db)
        XCTAssertEqual(fp, ["cdek.ru", "yandex.ru"])
    }
}
