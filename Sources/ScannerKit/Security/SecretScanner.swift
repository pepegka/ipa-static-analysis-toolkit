import Foundation

public enum SecretScanner {

    struct Pattern {
        let type: String
        let regex: NSRegularExpression
        let credentialClass: String
        let captureGroup: Int
        let entropyGate: Double
        let reject: NSRegularExpression?
        let rejectIfExpired: Bool

        var severity: Severity { .derived("SECH-05.\(credentialClass)", "SECH-05") }
        var isBlock: Bool { regex.pattern.hasPrefix("-----BEGIN") }
    }

    public struct Result: Sendable {
        public let secrets: [SecretHit]
        public let findings: [Finding]
    }

    private struct PatternFile: Decodable {
        struct Spec: Decodable {
            let type: String
            let pattern: String
            let credentialClass: String
            let captureGroup: Int
            let entropyGate: Double
            let rejectIfTokenMatches: String?
            let rejectIfExpired: Bool?
        }
        struct ConfigSignature: Decodable {
            let name: String
            let requiredKeys: [String]
            let source: String
            let why: String
        }
        struct KeyContext: Decodable {
            let name: String
            let types: Set<String>
            let keyPattern: String
            let source: String
            let reason: String
        }
        struct AlwaysPublic: Decodable {
            let type: String
            let source: String
            let reason: String
        }
        struct OAuthSecretContext: Decodable {
            let name: String
            let types: Set<String>
            let documentMarkers: [String]
            let endpointPattern: String
            let valuePattern: String
            let source: String
            let reason: String
        }
        struct SignedAssertion: Decodable {
            let name: String
            let types: Set<String>
            let headerKeyIDSuffixes: [String]
            let requiredClaims: [String]
            let source: String
            let reason: String
        }
        struct Provenance: Decodable {
            let frameworkDefaultPaths: [String]
            let publicClientConfigFiles: [String]
            let publicClientConfigFilePattern: String
            let publicClientConfigSignatures: [ConfigSignature]
            let publicClientTypes: Set<String>
            let nonProductionBasenameMarkers: [String]
            let nonProductionPathMarkers: [String]
            let publicClientKeyContexts: [KeyContext]?
            let alwaysPublicTypes: [AlwaysPublic]?
            let oauthClientSecretContexts: [OAuthSecretContext]?
            let signedAssertions: [SignedAssertion]?
            let vendorFixtureFiles: [VendorFixture]?
        }
        let patterns: [Spec]
        let provenance: Provenance
    }

    private static let file = RuleData.decode(PatternFile.self, "secrets/patterns.json")

    static var credentialClasses: Set<String> { Set(file.patterns.map { $0.credentialClass }) }

    private static let patterns: [Pattern] = file.patterns.compactMap { spec in
        guard let re = try? NSRegularExpression(pattern: spec.pattern, options: []) else { return nil }
        return Pattern(type: spec.type, regex: re, credentialClass: spec.credentialClass,
                       captureGroup: spec.captureGroup, entropyGate: spec.entropyGate,
                       reject: spec.rejectIfTokenMatches.flatMap { try? NSRegularExpression(pattern: $0) },
                       rejectIfExpired: spec.rejectIfExpired ?? false)
    }

    struct VendorFixture: Decodable {
        let sha256: String
        let name: String
        let source: String
    }

    private static let vendorFixtures: [String: VendorFixture] = Dictionary(
        (file.provenance.vendorFixtureFiles ?? []).map { ($0.sha256.lowercased(), $0) },
        uniquingKeysWith: { first, _ in first })

    static func vendorFixture(sha256: String) -> VendorFixture? { vendorFixtures[sha256.lowercased()] }

    static func jwsParts(_ token: String) -> (header: [String: Any], claims: [String: Any])? {
        func object(_ segment: Substring) -> [String: Any]? {
            var b64 = segment.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
            b64 += String(repeating: "=", count: (4 - b64.count % 4) % 4)
            guard let data = Data(base64Encoded: b64) else { return nil }
            return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        }
        let segments = token.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count == 3, let header = object(segments[0]),
              let claims = object(segments[1]) else { return nil }
        return (header, claims)
    }

    static func isExpired(_ claims: [String: Any], at now: Date) -> Bool {
        guard let exp = claims["exp"] as? NSNumber else { return false }
        return Date(timeIntervalSince1970: exp.doubleValue) <= now
    }

    static func isSignedAssertion(type: String, token: String) -> Bool {
        guard let formats = file.provenance.signedAssertions, !formats.isEmpty,
              let parts = jwsParts(token), let kid = parts.header["kid"] as? String else { return false }
        return formats.contains { f in
            f.types.contains(type) && f.headerKeyIDSuffixes.contains { kid.hasSuffix($0) }
                && f.requiredClaims.allSatisfy { parts.claims[$0] != nil }
        }
    }

    private static let publicConfigName = try! NSRegularExpression(
        pattern: file.provenance.publicClientConfigFilePattern)

    static func isPublicClientConfig(_ plist: Any) -> Bool {
        guard let dict = plist as? [String: Any] else { return false }
        return file.provenance.publicClientConfigSignatures.contains { sig in
            sig.requiredKeys.allSatisfy { dict[$0] != nil }
        }
    }

    private static let keyContexts: [(context: PatternFile.KeyContext, regex: NSRegularExpression)] =
        (file.provenance.publicClientKeyContexts ?? []).compactMap { c in
            (try? NSRegularExpression(pattern: c.keyPattern)).map { (c, $0) }
        }

    public struct PublicClientValue: Sendable, Equatable {
        public let types: Set<String>
        public let reason: String
    }

    static func publicClientValues(in document: Any) -> [String: PublicClientValue] {
        guard !keyContexts.isEmpty else { return [:] }
        var out: [String: PublicClientValue] = [:]
        func walk(_ x: Any, _ path: String) {
            if let dict = x as? [String: Any] {
                for (k, v) in dict { walk(v, path + "/" + k) }
            } else if let arr = x as? [Any] {
                for v in arr { walk(v, path) }
            } else if let value = x as? String, !value.isEmpty {
                let range = NSRange(path.startIndex..., in: path)
                for (c, re) in keyContexts where re.firstMatch(in: path, range: range) != nil {
                    out[value] = PublicClientValue(types: c.types, reason: c.reason)
                    break
                }
            }
        }
        walk(document, "")
        return out
    }

    private static let oauthContexts: [(context: PatternFile.OAuthSecretContext, endpoint: NSRegularExpression, value: NSRegularExpression)] =
        (file.provenance.oauthClientSecretContexts ?? []).compactMap { c in
            guard let e = try? NSRegularExpression(pattern: c.endpointPattern),
                  let v = try? NSRegularExpression(pattern: c.valuePattern) else { return nil }
            return (c, e, v)
        }

    static func oauthClientSecrets(inText text: String) -> [String: PublicClientValue] {
        var out: [String: PublicClientValue] = [:]
        let whole = NSRange(text.startIndex..., in: text)
        for (c, endpoint, value) in oauthContexts {
            guard c.documentMarkers.allSatisfy({ text.contains($0) }),
                  endpoint.firstMatch(in: text, range: whole) != nil else { continue }
            for m in value.matches(in: text, range: whole) {
                guard let r = Range(m.range(at: 1), in: text) else { continue }
                out[String(text[r])] = PublicClientValue(types: c.types, reason: c.reason)
            }
        }
        return out
    }

    public typealias TextItem = (value: String, source: String, section: String?)

    public enum Provenance: Sendable, Equatable {
        case credential
        case publicIdentifier(reason: String)
        case nonProduction(reason: String)
    }

    public static func classify(type: String, source: String,
                                publicConfigSources: Set<String> = [],
                                fixtureSources: Set<String> = []) -> Provenance {
        let lower = source.lowercased()
        let base = (lower as NSString).lastPathComponent
        if fixtureSources.contains(source) {
            return .nonProduction(reason: "vendor demo or test file (\(base))")
        }
        let namedConfig = file.provenance.publicClientConfigFiles.contains(base)
            || publicConfigName.firstMatch(in: base, range: NSRange(base.startIndex..., in: base)) != nil

        if file.provenance.publicClientTypes.contains(type),
           namedConfig || publicConfigSources.contains(source) {
            return .publicIdentifier(reason: publicReason(source))
        }
        if file.provenance.frameworkDefaultPaths.contains(where: { lower.contains($0) }) {
            return .nonProduction(reason: "framework-supplied default configuration (\(base))")
        }
        for marker in file.provenance.nonProductionBasenameMarkers where base.contains(marker) {
            return .nonProduction(reason: "non-production fixture path (\(base))")
        }
        for marker in file.provenance.nonProductionPathMarkers where lower.contains(marker) {
            return .nonProduction(reason: "non-production fixture path (\(base))")
        }
        return .credential
    }

    public static func scan(indices: [String: BinaryIndex], maxHits: Int = 2000) -> Result {
        var items: [TextItem] = []
        for (rel, index) in indices.sorted(by: { $0.key < $1.key }) {
            for sectionStrings in index.perSectionStrings {
                let secName = "\(sectionStrings.section.segment)/\(sectionStrings.section.section)"
                let strs = sectionStrings.strings
                for (i, ex) in strs.enumerated() {
                    if ex.value.contains("PRIVATE KEY-----"), ex.value.contains("-----BEGIN") {
                        items.append((joinedPEM(strs, from: i), rel, secName))
                    } else {
                        items.append((ex.value, rel, secName))
                    }
                }
            }
        }
        let secrets = hits(in: items, maxHits: maxHits)
        return Result(secrets: secrets, findings: findings(from: secrets))
    }

    static func joinedPEM(_ strs: [ExtractedString], from start: Int, maxLines: Int = 200) -> String {
        var out = strs[start].value
        var end = strs[start].offset + UInt64(strs[start].value.utf8.count)
        var i = start + 1
        while i < strs.count, i - start <= maxLines, !strs[i].isUTF16, strs[i].offset == end + 1 {
            out += "\n" + strs[i].value
            end = strs[i].offset + UInt64(strs[i].value.utf8.count)
            if strs[i].value.hasPrefix("-----END") { break }
            i += 1
        }
        return out
    }

    public static func hits(in items: [TextItem], maxHits: Int = 2000,
                            publicConfigSources: Set<String> = [],
                            publicClientValues: [String: PublicClientValue] = [:],
                            fixtureSources: Set<String> = [],
                            now: Date = Date()) -> [SecretHit] {
        var seen = Set<String>()
        var secrets: [SecretHit] = []

        outer: for item in items {
            let s = item.value
            if s.count < 16 { continue }
            let long = s.utf8.count > 4096
            for p in patterns {
                if long && !p.isBlock { continue }
                let range = NSRange(s.startIndex..<s.endIndex, in: s)
                guard let m = p.regex.firstMatch(in: s, options: [], range: range) else { continue }
                let tokenRange = m.range(at: min(p.captureGroup, m.numberOfRanges - 1))
                guard tokenRange.location != NSNotFound,
                      let r = Range(tokenRange, in: s) else { continue }
                let token = String(s[r])
                let entropy = shannonEntropy(token)
                if p.entropyGate > 0, entropy < p.entropyGate { continue }
                if let rej = p.reject,
                   rej.firstMatch(in: token, range: NSRange(token.startIndex..., in: token)) != nil { continue }
                if p.rejectIfExpired, let claims = jwsParts(token)?.claims, isExpired(claims, at: now) { continue }
                if isSignedAssertion(type: p.type, token: token) { continue }
                var provenance = classify(type: p.type, source: item.source,
                                          publicConfigSources: publicConfigSources,
                                          fixtureSources: fixtureSources)
                if case .credential = provenance {
                    if let always = file.provenance.alwaysPublicTypes?.first(where: { $0.type == p.type }) {
                        provenance = .publicIdentifier(reason: always.reason)
                    } else if let ctx = publicClientValues[token], ctx.types.contains(p.type) {
                        provenance = .publicIdentifier(reason: ctx.reason)
                    }
                }
                if case .nonProduction = provenance { continue }
                let severity: Severity
                if case .publicIdentifier = provenance {
                    severity = .derived("SECH-05.public_client_identifier", "SECH-05")
                } else {
                    severity = p.severity
                }
                let redacted = redact(token)
                let key = "\(p.type)|\(item.source)|\(redacted)"
                if !seen.insert(key).inserted { continue }
                var hit = SecretHit(type: p.type, redactedValue: redacted,
                                    entropy: entropy, severity: severity,
                                    source: item.source, section: item.section)
                hit.credentialClass = p.credentialClass
                if case .publicIdentifier(let reason) = provenance {
                    hit.publicIdentifier = true
                    hit.publicReason = reason
                }
                secrets.append(hit)
                if secrets.count >= maxHits { break outer }
            }
        }

        secrets.sort { ($0.severity, $0.entropy) > ($1.severity, $1.entropy) }
        return secrets
    }

    static func slug(_ type: String) -> String {
        type.lowercased().map { $0.isLetter || $0.isNumber ? String($0) : "_" }.joined()
            .split(separator: "_").joined(separator: "_")
    }

    public static func findings(from secrets: [SecretHit]) -> [Finding] {
        var findings: [Finding] = []
        let byTypeSource = Dictionary(grouping: secrets) { "\($0.type)@\($0.source)" }
        for key in byTypeSource.keys.sorted() {
            guard let hits = byTypeSource[key], let first = hits.first else { continue }
            let evidences = hits.prefix(20).map {
                Evidence(kind: .stringMatch, value: $0.redactedValue, source: $0.source, section: $0.section)
            }
            if first.publicIdentifier == true {
                let reason = first.publicReason ?? publicReason(first.source)
                let copy = Messages.entry("SECH-05.public_client_identifier",
                                          ["type": first.type, "source": first.source, "reason": reason])
                findings.append(Finding(
                    ruleID: "SECH-05.public_client_identifier.\(slug(first.type))",
                    vectorID: "SECH-05",
                    title: copy.title,
                    explanation: copy.explanation,
                    severity: .derived("SECH-05.public_client_identifier", "SECH-05"), evidences: evidences,
                    masvs: ["MASVS-STORAGE"],
                    remediation: copy.remediation).with(metrics: copy.values).with(instance: first.source))
                continue
            }
            let cls = first.credentialClass ?? "generic_credential"
            let copy = Messages.entry("SECH-05.hardcoded_secret",
                                      ["type": first.type, "source": first.source,
                                       "count": String(hits.count), "s": hits.count == 1 ? "" : "s"])
            findings.append(Finding(
                ruleID: "SECH-05.\(cls).\(slug(first.type))",
                vectorID: "SECH-05",
                title: copy.title,
                explanation: copy.explanation,
                severity: first.severity, evidences: evidences,
                mitre: ["T1552.001"],
                masvs: ["MASVS-STORAGE", "MASVS-CODE"],
                remediation: copy.remediation).with(metrics: copy.values).with(instance: first.source))
        }
        return findings
    }

    private static func publicReason(_ source: String) -> String {
        let base = (source as NSString).lastPathComponent
        return "\(base) is a Firebase client configuration. A Firebase API key identifies the project; authorisation is enforced server-side by Security Rules, App Check and IAM. An unrestricted key can still be abused against billable Google APIs, and restriction is server-side state the bundle cannot show."
    }

    static func shannonEntropy(_ s: String) -> Double {
        guard !s.isEmpty else { return 0 }
        var counts: [Character: Int] = [:]
        for c in s { counts[c, default: 0] += 1 }
        let n = Double(s.count)
        var h = 0.0
        for c in counts.values {
            let p = Double(c) / n
            h -= p * log2(p)
        }
        return h
    }

    static func redact(_ token: String) -> String {
        if token.contains("PRIVATE KEY") { return "-----BEGIN PRIVATE KEY----- (redacted)" }
        let n = token.count
        guard n > 8 else { return String(repeating: "*", count: n) }
        let head = token.prefix(4)
        let tail = token.suffix(4)
        return "\(head)…\(tail) (\(n) chars)"
    }
}
