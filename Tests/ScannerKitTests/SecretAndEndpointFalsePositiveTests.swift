import XCTest
@testable import ScannerKit

final class SecretAndEndpointFalsePositiveTests: XCTestCase {

    private func tempApp(_ files: [String: Data]) throws -> (URL, [URL]) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("fp-\(UUID().uuidString)/Payload/App.app", isDirectory: true)
        var urls: [URL] = []
        for (rel, data) in files {
            let url = dir.appendingPathComponent(rel)
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                                                    withIntermediateDirectories: true)
            try data.write(to: url)
            urls.append(url)
        }
        return (dir, urls)
    }

    private func plist(_ dict: [String: Any]) throws -> Data {
        try PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
    }

    private let placesKey = "AIza" + "SyDq8ZkP2mXv9LwT4rNbY7cH3jKs5tUa1eW"

    func testURLPathUnderATokenKeyIsNotACredential() {
        let items: [SecretScanner.TextItem] = [
            ("\"URLRequestAuthToken\": \"/svc/rr/accounts/secure/gateway/authservice/token\"", "AppConfig.json", nil),
            ("\"URLRequestMarkitToken\": \"/svc/wr/dwm/secure/markit/v1/token/list\"", "AppConfig.json", nil),
        ]
        XCTAssertTrue(SecretScanner.hits(in: items).isEmpty)
    }

    func testRelativeURLPathUnderAPasswordKeyIsNotACredential() {
        let items: [SecretScanner.TextItem] = [
            ("\"customerChangePassword\": \"customer/security/password/change\"", "gma_api_config.json", nil),
        ]
        XCTAssertTrue(SecretScanner.hits(in: items).isEmpty)
    }

    func testAnOAuthClientSecretInANativeProviderConfigIsPublic() {
        let secret = "q8ZkP2mXv9LwT4rNbY7cH3jK"
        let xml = """
        <provider id="google" token_endpoint="https://accounts.google.com/o/oauth2/token"
            client_id="1234-abc.apps.googleusercontent.com"
            client_secret="\(secret)">
        </provider>
        """
        let values = SecretScanner.oauthClientSecrets(inText: xml)
        XCTAssertNotNil(values[secret])
        let hits = SecretScanner.hits(in: [("client_secret=\"\(secret)\">", "oauth.xml", nil)],
                                      publicClientValues: values)
        XCTAssertEqual(hits.first?.publicIdentifier, true)
    }

    func testAClientSecretOutsideAnOAuthProviderConfigStaysACredential() {
        XCTAssertTrue(SecretScanner.oauthClientSecrets(inText: "{\"client_secret\": \"q8ZkP2mXv9LwT4rNbY7cH3jK\"}").isEmpty)
    }

    func testARandomValueUnderATokenKeyIsStillACredential() {
        let items: [SecretScanner.TextItem] = [
            ("\"apiToken\": \"q8ZkP2mXv9LwT4rNbY7cH3jK\"", "Config.json", nil),
        ]
        let hits = SecretScanner.hits(in: items)
        XCTAssertEqual(hits.count, 1)
        XCTAssertNotEqual(hits.first?.publicIdentifier, true)
    }

    func testAPlacesSDKKeyIsAPublicClientIdentifier() throws {
        let (dir, files) = try tempApp([
            "Auth.bundle/Secrets.plist": try plist(["GooglePlacesAPIKey": placesKey]),
        ])
        let result = ResourceScanner.scan(appDirectory: dir, files: files)
        let hit = try XCTUnwrap(result.secrets.first { $0.type == "Google API Key" })
        XCTAssertEqual(hit.publicIdentifier, true)
        XCTAssertEqual(hit.severity, .info)
        XCTAssertTrue(hit.publicReason?.contains("bundle ID") == true)
        XCTAssertFalse(hit.isCredential)
        XCTAssertTrue(result.findings.allSatisfy { $0.ruleID.hasPrefix("SECH-05.public_client_identifier") })
    }

    func testAGoogleKeyUnderAnUnrelatedSettingStaysACredential() throws {
        let (dir, files) = try tempApp([
            "Config.plist": try plist(["GenerativeLanguageKey": placesKey]),
        ])
        let hit = try XCTUnwrap(ResourceScanner.scan(appDirectory: dir, files: files)
            .secrets.first { $0.type == "Google API Key" })
        XCTAssertNotEqual(hit.publicIdentifier, true)
        XCTAssertTrue(hit.isCredential)
    }

    func testANestedPlacesKeyInJSONIsAPublicClientIdentifier() throws {
        let json = "{\"placesSdkKey\": {\"production\": {\"android\": \"\(placesKey)\"}}}"
        let (dir, files) = try tempApp(["shared.bundle/configuration.json": Data(json.utf8)])
        let hit = try XCTUnwrap(ResourceScanner.scan(appDirectory: dir, files: files)
            .secrets.first { $0.type == "Google API Key" })
        XCTAssertEqual(hit.publicIdentifier, true)
    }

    func testAGoogleOAuthClientIDIsPublicEverywhere() {
        let id = "123456789012-" + "abcdefghijklmnopqrstuvwxyz012345" + ".apps.googleusercontent.com"
        let hits = SecretScanner.hits(in: [("clientID = \(id)", "SSOConfig.plist", nil)])
        XCTAssertEqual(hits.first?.publicIdentifier, true)
        XCTAssertEqual(hits.first?.severity, .info)
    }

    func testDemoDataIsNotProduction() {
        XCTAssertEqual(SecretScanner.classify(type: "JSON Web Token", source: "Demo/Demo-API.json"),
                       .nonProduction(reason: "non-production fixture path (demo-api.json)"))
    }

    func testLocalizationKeysAreNotHosts() throws {
        let strings = """
        "Card.Collection.Agency.Info" = "Your account has been assigned to %@. Visit https://help.example-bank.com/collections";
        "QP.ManageToken.DepositAccount.Info" = "Call us or go to www.example-bank.com for details";
        """
        let json = "{\"QP.ManageToken.DepositAccount.Info\": {\"default\": \"You'll receive money\"}}"
        let (dir, files) = try tempApp([
            "Dashboard.bundle/en.lproj/Localizable.strings": Data(strings.utf8),
            "Core.bundle/Localizable.json": Data(json.utf8),
            "Deposits.bundle/Merged-Localizable.json": Data(json.utf8),
        ])
        let hosts = Set(ResourceScanner.scan(appDirectory: dir, files: files).endpoints.map(\.host))
        XCTAssertFalse(hosts.contains("card.collection.agency.info"))
        XCTAssertFalse(hosts.contains("qp.managetoken.depositaccount.info"))
        XCTAssertTrue(hosts.contains("help.example-bank.com"))
        XCTAssertTrue(hosts.contains("www.example-bank.com"), "a bare host in the displayed text still counts")
    }

    func testPropertyAccessIsNotAHost() {
        let js = "cart.items.forEach(item => counts[parseInt(item.reference.ID)] = 1); Number(itm.reference.ID)"
        XCTAssertTrue(URLExtractor.extract(fromString: js, source: "149677.json").isEmpty)
        let prose = "Order at www.Walmart.com or WWW.EXAMPLE.COM"
        XCTAssertEqual(Set(URLExtractor.extract(fromString: prose, source: "a.strings").map(\.host)),
                       ["www.walmart.com", "www.example.com"])
    }

    func testEscapedSlashesDoNotFuseWithTheHost() {
        for s in [#"{"u":"https:%2F%2Fwww.facebook.com%2Fpage"}"#,
                  #"{"u":"https://www.facebook.com"}"#,
                  "next=https%3A%2F%2Fwww.facebook.com%2Fpage"] {
            XCTAssertEqual(Set(URLExtractor.extract(fromString: s, source: "a.json").map(\.host)),
                           ["www.facebook.com"], s)
        }
    }

    func testIdentifiersAndAttributionTokensAreNotCredentials() {
        let items: [SecretScanner.TextItem] = [
            ("\"titleToken\": \"SET_employeeAvailability\"", "app_config.json", nil),
            ("\"flag_token\": \"XRAY_PLAYER_FEATURE_V4_2\"", "Config.json", nil),
            ("\"attributionToken\": \"JpQKq8ZkP2mXv9LwT4rNbY7cH3jKs5tUa1eW\"", "AutoSuggestion.json", nil),
        ]
        XCTAssertTrue(SecretScanner.hits(in: items).isEmpty)
        XCTAssertTrue(SecretScanner.hits(in: [("\"secret\": \"sk_live_4eC39HqLyjWDarjtT1zdp7dc\"", "c.json", nil)])
                        .contains { $0.type == "Generic Credential" }, "a real key with underscores still counts")
    }

    private func b64url(_ json: String) -> String {
        Data(json.utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private func jws(_ header: String, _ claims: String) -> String {
        b64url(header) + "." + b64url(claims) + ".q8ZkP2mXv9LwT4rNbY7cH3jKs5tUa1eWdF0gH2iJ4kL"
    }

    private let scanDate = Date(timeIntervalSince1970: 1_790_640_000)

    func testAnExpiredJWTIsNotACredential() {
        let token = jws(#"{"alg":"HS256","typ":"JWT"}"#,
                        #"{"exp":1669062469,"iat":1669058869,"jti":"7c1e","gift_wrap_id":"starbucks-birthday-cake"}"#)
        let items: [SecretScanner.TextItem] = [
            ("\"token\": \"\(token)\"", "VenmoGifting_VenmoGifting.bundle/gift-card-list.json", nil),
        ]
        XCTAssertTrue(SecretScanner.hits(in: items, now: scanDate).isEmpty)
        XCTAssertEqual(SecretScanner.hits(in: items, now: Date(timeIntervalSince1970: 1_669_060_000)).count, 1,
                       "the same token before its expiry is a bearer token")
    }

    func testAJWTWithoutAnExpiryStaysACredential() {
        let token = jws(#"{"alg":"HS256","typ":"JWT"}"#, #"{"iat":1589430902,"jti":"a1b2","funding_source_external_id":"fs_1"}"#)
        let hits = SecretScanner.hits(in: [("\"payment_method_token\": \"\(token)\"", "api.json", nil)], now: scanDate)
        XCTAssertEqual(hits.map(\.type), ["JSON Web Token"])
        XCTAssertEqual(hits.first?.isCredential, true)
    }

    func testAnAdAttributionKitImpressionIsNotACredential() {
        let claims = #"{"impression-identifier":"0b1c","publisher-item-identifier":1,"impression-type":"app-impression","ad-network-identifier":"example.adattributionkit","source-identifier":1,"timestamp":1747307934217,"advertised-item-identifier":2}"#
        for kid in ["example.adattributionkit", "example.skadnetwork"] {
            let token = jws("{\"kid\":\"\(kid)\",\"alg\":\"ES256\"}", claims)
            XCTAssertTrue(SecretScanner.hits(in: [("\"jwt\": \"\(token)\"", "Ads/impressions.json", nil)], now: scanDate).isEmpty, kid)
        }
        let other = jws(#"{"kid":"example.adattributionkit","alg":"ES256"}"#, #"{"sub":"user-1","scope":"payments"}"#)
        XCTAssertEqual(SecretScanner.hits(in: [("\"jwt\": \"\(other)\"", "Ads/impressions.json", nil)], now: scanDate).count, 1)
    }

    func testHyBidDemoAndTestFilesAreRecognisedByContent() {
        XCTAssertNotNil(SecretScanner.vendorFixture(sha256: "1111bbce829f5fb803ffbe0786963d3b9263043b84750998fbcf37db198a08c2"))
        XCTAssertNotNil(SecretScanner.vendorFixture(sha256: "72f254566182e95ab024a198668df7e64c554755894d0c0f403cacb77146773c"))
        XCTAssertNil(SecretScanner.vendorFixture(sha256: String(repeating: "0", count: 64)))
    }

    func testTokensInAVendorFixtureAreNotTheAppsSecrets() {
        let items: [SecretScanner.TextItem] = [
            ("'authToken': '705a4c1f9e2b4d7a8c3e6f1b2d9a787b',", "Frameworks/HyBid.framework/ur.txt", nil),
        ]
        XCTAssertTrue(SecretScanner.hits(in: items, fixtureSources: ["Frameworks/HyBid.framework/ur.txt"]).isEmpty)
        XCTAssertEqual(SecretScanner.hits(in: items).count, 1, "the same line elsewhere is still reported")
    }

    func testResourceScanHashesFilesToFindVendorFixtures() throws {
        let body = Data("'authToken': '705a4c1f9e2b4d7a8c3e6f1b2d9a787b',\n".utf8)
        let (dir, files) = try tempApp(["Frameworks/HyBid.framework/ur.txt": body])
        XCTAssertEqual(ResourceScanner.scan(appDirectory: dir, files: files).secrets.count, 1,
                       "a file that is not byte-identical to the vendor's is scanned as usual")
        XCTAssertEqual(FileManifestBuilder.sha256(of: body), FileManifestBuilder.sha256(of: files[0]))
    }
}

final class MetaAttributionTests: XCTestCase {
    private static let db = TrackerDBLoader.loadBundled()

    func testFacebookSiteAndCDNAreNotTheSDK() {
        for host in ["www.facebook.com", "m.facebook.com", "developers.facebook.com",
                     "scontent.xx.fbcdn.net", "www.instagram.com"] {
            let t = Self.db.classify(host: host)
            XCTAssertEqual(t?.owner, "Meta", host)
            XCTAssertEqual(t?.isTracker, false, host)
        }
        for host in ["graph.facebook.com", "ep1.facebook.com", "connect.facebook.net"] {
            XCTAssertEqual(Self.db.classify(host: host)?.id, "facebook.core", host)
        }
    }

    func testVendorDocumentationHostsAreNotTelemetry() {
        for host in ["help.fullstory.com", "developer.arkoselabs.com", "help.openai.com"] {
            XCTAssertEqual(Self.db.classify(host: host)?.isTracker, false, host)
        }
        XCTAssertEqual(Self.db.classify(host: "rs.fullstory.com")?.isTracker, true)
        XCTAssertEqual(Self.db.classify(host: "t.co")?.isTracker, false)
        XCTAssertEqual(Self.db.classify(host: "log.byteoversea.com")?.isTracker, false)
        XCTAssertEqual(Self.db.classify(framework: "FullStory")?.id, "fullstory")
        XCTAssertEqual(Self.db.classify(framework: "FirebaseAnalytics")?.id, "google.analytics")
    }

    func testTheSDKIsFoundByItsRequiredPlistKey() {
        var m = BundleMetadata(
            bundleID: "com.test.app", bundleName: "T", displayName: "T", shortVersion: "1.0",
            bundleVersion: "1", minimumOSVersion: "17.0", executableName: "T",
            supportedPlatforms: ["iPhoneOS"], urlSchemes: [], queriedURLSchemes: [],
            backgroundModes: [], allowsArbitraryLoads: false, permissions: [],
            privacyManifestPath: nil, privacyTrackingDomains: [], privacyAccessedAPIs: [],
            embeddedBinaries: [], embeddedFrameworks: [], provisioning: nil,
            signedTeamID: nil, signedIdentifier: nil)
        m.infoPlistKeys = ["CFBundleName", "GADApplicationIdentifier", "FacebookAppID"]
        let sdks = NetworkInventoryBuilder.build(metadata: m, indices: [:], trackerDB: Self.db).detectedSDKs
        XCTAssertEqual(sdks.first { $0.trackerID == "google.ads" }?.plistKeys, ["GADApplicationIdentifier"])
        XCTAssertNil(sdks.first { $0.trackerID == "facebook.core" })
    }

    func testTheSDKIsFoundByItsFramework() {
        let m = BundleMetadata(
            bundleID: "com.test.app", bundleName: "T", displayName: "T", shortVersion: "1.0",
            bundleVersion: "1", minimumOSVersion: "17.0", executableName: "T",
            supportedPlatforms: ["iPhoneOS"], urlSchemes: [], queriedURLSchemes: [],
            backgroundModes: [], allowsArbitraryLoads: false, permissions: [],
            privacyManifestPath: nil, privacyTrackingDomains: [], privacyAccessedAPIs: [],
            embeddedBinaries: [], embeddedFrameworks: ["FBSDKCoreKit", "FBLPromises", "FBSDKLoginKit"],
            provisioning: nil, signedTeamID: nil, signedIdentifier: nil)
        let link = URLExtractor.extract(fromString: "https://www.facebook.com/acme", source: "About.plist")
        let sdks = NetworkInventoryBuilder.build(metadata: m, indices: [:], trackerDB: Self.db,
                                                 extraEndpoints: link).detectedSDKs
        let meta = sdks.first { $0.trackerID == "facebook.core" }
        XCTAssertEqual(meta?.isTracker, true)
        XCTAssertEqual(meta?.frameworks, ["FBSDKCoreKit", "FBSDKLoginKit"], "FBLPromises is Google's")
        XCTAssertEqual(sdks.first { $0.trackerID == "meta.social" }?.isTracker, false)
    }

    func testAFrameworkKeepsTheSDKATrackerNextToADocumentationLink() {
        let m = BundleMetadata(
            bundleID: "com.test.app", bundleName: "T", displayName: "T", shortVersion: "1.0",
            bundleVersion: "1", minimumOSVersion: "17.0", executableName: "T",
            supportedPlatforms: ["iPhoneOS"], urlSchemes: [], queriedURLSchemes: [],
            backgroundModes: [], allowsArbitraryLoads: false, permissions: [],
            privacyManifestPath: nil, privacyTrackingDomains: [], privacyAccessedAPIs: [],
            embeddedBinaries: [], embeddedFrameworks: ["FullStory"],
            provisioning: nil, signedTeamID: nil, signedIdentifier: nil)
        let docs = URLExtractor.extract(fromString: "https://help.fullstory.com/hc/en-us", source: "FullStory")
        let sdk = NetworkInventoryBuilder.build(metadata: m, indices: [:], trackerDB: Self.db,
                                                extraEndpoints: docs).detectedSDKs.first { $0.trackerID == "fullstory" }
        XCTAssertEqual(sdk?.isTracker, true)
        XCTAssertEqual(sdk?.frameworks.contains("FullStory"), true)
    }

    func testATelemetryHostKeepsTheSDKATrackerWhateverTheHostOrder() {
        let m = BundleMetadata(
            bundleID: "com.test.app", bundleName: "T", displayName: "T", shortVersion: "1.0",
            bundleVersion: "1", minimumOSVersion: "17.0", executableName: "T",
            supportedPlatforms: ["iPhoneOS"], urlSchemes: [], queriedURLSchemes: [],
            backgroundModes: [], allowsArbitraryLoads: false, permissions: [],
            privacyManifestPath: nil, privacyTrackingDomains: [], privacyAccessedAPIs: [],
            embeddedBinaries: [], embeddedFrameworks: [],
            provisioning: nil, signedTeamID: nil, signedIdentifier: nil)
        let hosts = URLExtractor.extract(fromString: "https://help.fullstory.com/a https://rs.fullstory.com/rec", source: "c.json")
        for order in [hosts, hosts.reversed()] {
            let sdk = NetworkInventoryBuilder.build(metadata: m, indices: [:], trackerDB: Self.db,
                                                    extraEndpoints: Array(order)).detectedSDKs.first { $0.trackerID == "fullstory" }
            XCTAssertEqual(sdk?.isTracker, true)
        }
    }
}
