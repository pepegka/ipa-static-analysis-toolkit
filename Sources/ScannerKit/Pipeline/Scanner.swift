import Foundation

public struct ScanProgress: Sendable {
    public let phase: String
    public let fraction: Double
    public init(phase: String, fraction: Double) {
        self.phase = phase; self.fraction = fraction
    }
}

public protocol ScanProgressReporter: Sendable {
    func report(_ progress: ScanProgress)
}

public enum ScannerError: Error, CustomStringConvertible {
    case extractionFailed(String)
    case insufficientDiskSpace(String)
    public var description: String {
        switch self {
        case .extractionFailed(let s): return "Extraction failed: \(s)"
        case .insufficientDiskSpace(let s): return s
        }
    }
}

public struct Scanner: Sendable {
    public let rulePack: RulePack
    public let trackerDB: TrackerDB

    public init(rulePack: RulePack? = nil, trackerDB: TrackerDB? = nil) {
        self.rulePack = rulePack ?? RuleLoader.loadBundled()
        self.trackerDB = trackerDB ?? TrackerDBLoader.loadBundled()
    }

    public func scanIndexed(ipa: URL,
                            progress: ScanProgressReporter? = nil,
                            maxStringsPerBinary: Int = BinaryIndexer.defaultMaxStringsPerBinary,
                            storeGenre: String? = nil,
                            contentRating: String? = nil) throws -> IndexedReport {
        let result = try _scan(ipa: ipa, progress: progress,
                               maxStringsPerBinary: maxStringsPerBinary,
                               storeGenre: storeGenre, contentRating: contentRating)
        return IndexedReport(report: result.report, indices: result.indices)
    }

    private struct ScanOutcome { let report: ScanReport; let indices: [String: BinaryIndex] }

    private func _scan(ipa: URL,
                       progress: ScanProgressReporter?,
                       maxStringsPerBinary: Int,
                       storeGenre: String? = nil,
                       contentRating: String? = nil) throws -> ScanOutcome {
        let start = Date()
        progress?.report(.init(phase: "Extracting IPA", fraction: 0.05))

        let extracted: ExtractedIPA
        do {
            extracted = try IPAExtractor.extract(ipa: ipa)
        } catch let e as IPAExtractorError {
            if case .insufficientDiskSpace = e { throw ScannerError.insufficientDiskSpace("\(e)") }
            throw ScannerError.extractionFailed("\(e)")
        } catch {
            throw ScannerError.extractionFailed("\(error)")
        }
        defer { IPAExtractor.cleanup(extracted) }

        let app = extracted.appDirectory

        progress?.report(.init(phase: "Enumerating bundle", fraction: 0.10))
        let (allFiles, outsideLinks) = Self.bundleFiles(in: app)

        let privacyManifests = allFiles.filter { $0.lastPathComponent == "PrivacyInfo.xcprivacy" }
        let embeddedFrameworks: [String] = (try? FileManager.default
            .contentsOfDirectory(at: app.appendingPathComponent("Frameworks"), includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "framework" }
            .map { $0.deletingPathExtension().lastPathComponent }) ?? []

        progress?.report(.init(phase: "Inspecting Mach-O binaries", fraction: 0.20))
        let skipExtensions: Set<String> = [
            "plist", "png", "jpg", "jpeg", "gif", "json", "car", "nib", "storyboardc",
            "ttf", "otf", "woff", "woff2", "html", "css", "js", "mp3", "mp4", "mov",
            "m4a", "wav", "txt", "md", "strings", "stringsdict", "xcprivacy", "lproj",
            "cer", "der", "pem", "p12", "mobileprovision", "scnassets", "icns",
            "metallib", "momd", "mom", "framework", "bundle", "app", "appex", "lock",
            "xib", "pdf", "svg", "webp", "heic", "aif", "caf",
        ]
        var embeddedBinaries: [EmbeddedBinary] = []
        var binaryURLs: [(url: URL, relativePath: String)] = []
        var machoByRel: [String: MachOInfo] = [:]
        for file in allFiles {
            if skipExtensions.contains(file.pathExtension.lowercased()) { continue }
            if file.path.hasSuffix(".lproj") { continue }
            var isDir: ObjCBool = false
            guard FileManager.default.fileExists(atPath: file.path, isDirectory: &isDir), !isDir.boolValue else { continue }

            guard let info = (try? MachOInspector.inspect(url: file)) ?? nil, info.slices.isEmpty == false else { continue }
            let rel = file.relativePath(from: app)
            embeddedBinaries.append(EmbeddedBinary(
                relativePath: rel,
                name: file.lastPathComponent,
                architectures: info.architectures,
                isFairPlayEncrypted: info.isAnySliceEncrypted,
                sizeBytes: info.sizeBytes,
                linkedDylibs: info.allDylibs
            ))
            binaryURLs.append((file, rel))
            machoByRel[rel] = info
        }

        progress?.report(.init(phase: "Parsing provisioning profile", fraction: 0.30))
        let provision = MobileProvisionParser.parse(at: app.appendingPathComponent("embedded.mobileprovision"))

        progress?.report(.init(phase: "Reading code signature", fraction: 0.35))
        let codesign = CodeSignReader.read(appDirectory: app)

        progress?.report(.init(phase: "Analyzing Info.plist & privacy manifests", fraction: 0.40))
        let infoResult = InfoPlistAnalyzer.analyze(
            appDirectory: app,
            embeddedBinaries: embeddedBinaries,
            embeddedFrameworks: embeddedFrameworks,
            privacyManifests: privacyManifests,
            provisioning: provision,
            signedTeamID: codesign.signedTeamID,
            signedIdentifier: codesign.signedIdentifier
        )

        var findings = infoResult.findings
        findings.append(contentsOf: CodeSignReader.findings(codesign))

        var indices: [String: BinaryIndex] = [:]
        if !binaryURLs.isEmpty {
            progress?.report(.init(phase: "Indexing binaries (strings + symbols)", fraction: 0.50))
            let mainExe = infoResult.metadata.executableName
            let snapshot = binaryURLs
            let cap = maxStringsPerBinary
            final class Bucket: @unchecked Sendable {
                var items: [(String, BinaryIndex)] = []
                let lock = NSLock()
                func add(_ k: String, _ v: BinaryIndex) {
                    lock.lock(); items.append((k, v)); lock.unlock()
                }
            }
            let bucket = Bucket()
            DispatchQueue.concurrentPerform(iterations: snapshot.count) { idx in
                let (url, rel) = snapshot[idx]
                let isMain = (url.lastPathComponent == mainExe)
                if let bi = try? BinaryIndexer.build(forBinary: url, relativePath: rel,
                                                    isMainExecutable: isMain,
                                                    maxStringsPerBinary: cap) {
                    bucket.add(rel, bi)
                }
            }
            for (k, v) in bucket.items { indices[k] = v }
        }

        if let mainExe = infoResult.metadata.executableName,
           let main = embeddedBinaries.first(where: { $0.name == mainExe }),
           main.isFairPlayEncrypted {
            let copy = Messages.entry("meta.fairplay_main")
            findings.append(Finding(
                ruleID: "meta.fairplay_main",
                vectorID: "SURV-02",
                title: copy.title,
                explanation: copy.explanation,
                severity: .derived("meta.fairplay_main", "meta"), evidences: [Evidence(kind: .file, value: main.relativePath, source: main.relativePath)],
                remediation: copy.remediation))
        }

        if !rulePack.rules.isEmpty {
            progress?.report(.init(phase: "Evaluating rules (\(rulePack.rules.count))", fraction: 0.80))
            let provEnts = Array(provision?.entitlements.keys ?? Dictionary<String,String>().keys)
            let cdEnts = Self.extractEntitlementKeys(fromCodesignXML: codesign.entitlementsXML)
            let input = RuleInput(metadata: infoResult.metadata,
                                  indices: indices,
                                  provisioningEntitlements: provEnts,
                                  codesignEntitlements: cdEnts)
            let engine = RuleEngine(rules: rulePack.rules)
            let ruleFindings = engine.evaluate(input)
            findings.append(contentsOf: ruleFindings)
        }

        if findings.contains(where: { $0.ruleID == "SECH-01.missing_pinning" }) {
            let certs = allFiles
                .filter { ["der", "cer", "crt", "pem"].contains($0.pathExtension.lowercased()) }
                .map { $0.relativePath(from: app) }
            if !ATSAnalyzer.pinningMachinery(indices: indices, bundledCertificates: certs).isEmpty {
                findings.removeAll { $0.ruleID == "SECH-01.missing_pinning" }
            }
        }

        progress?.report(.init(phase: "Privacy-Manifest gap analysis", fraction: 0.85))
        let gapFindings = PrivacyManifestGapAnalyzer.analyze(metadata: infoResult.metadata,
                                                             indices: indices)
        findings.append(contentsOf: gapFindings)
        findings.append(contentsOf: PrivacyManifestValidator.analyze(appDirectory: app,
                                                                     privacyManifests: privacyManifests,
                                                                     embeddedFrameworks: embeddedFrameworks))

        let resourceResult = ResourceScanner.scan(appDirectory: app, files: allFiles)

        progress?.report(.init(phase: "Classifying network endpoints", fraction: 0.90))
        var netMeta = infoResult.metadata
        netMeta.associatedDomains = Self.associatedDomains(fromCodesignXML: codesign.entitlementsXML)
        let network = NetworkInventoryBuilder.build(metadata: netMeta,
                                                    indices: indices,
                                                    trackerDB: trackerDB,
                                                    extraEndpoints: resourceResult.endpoints)
        for sdk in network.detectedSDKs where sdk.isTracker {
            let shipped = sdk.frameworks.filter { trackerDB.classify(framework: $0)?.id == sdk.trackerID }
            let keys = sdk.plistKeys ?? []
            let evidences = sdk.endpoints.map {
                Evidence(kind: .url, value: $0, source: sdk.frameworks.first ?? "(main)")
            } + shipped.map {
                Evidence(kind: .file, value: "\($0).framework", source: "Frameworks/\($0).framework")
            } + keys.map {
                Evidence(kind: .plistKey, value: $0, source: "Info.plist")
            }
            var parts: [String] = []
            if !sdk.endpoints.isEmpty {
                parts.append("\(sdk.endpoints.count) host\(sdk.endpoints.count == 1 ? "" : "s") attributed to it observed")
            }
            if !shipped.isEmpty {
                parts.append("its framework ships in Frameworks/ (\(shipped.joined(separator: ", ")))")
            }
            if !keys.isEmpty {
                parts.append("its configuration key is set in Info.plist (\(keys.joined(separator: ", ")))")
            }
            let how = parts.joined(separator: "; ")
            let copy = Messages.entry("tracker.endpoint", [
                "name": sdk.name,
                "category": sdk.category,
                "owner": sdk.owner,
                "countryNote": sdk.country.isEmpty ? "" : " \u{00b7} \(sdk.country)",
                "how": how,
                "count": String(evidences.count),
            ])
            findings.append(Finding(
                ruleID: "tracker.\(sdk.trackerID)",
                vectorID: "TRK-01",
                title: copy.title,
                explanation: copy.explanation,
                severity: SeverityDerivation.trackerSeverity(category: sdk.category),
                evidences: Array(evidences),
                owningFramework: sdk.frameworks.first,
                remediation: copy.remediation).with(metrics: copy.values))
        }

        findings = Self.droppingDuplicateSDKRules(findings, rules: rulePack.rules, network: network,
                                                  trackerDB: trackerDB)

        findings.append(contentsOf: CleartextURLAnalyzer.analyze(network: network))
        findings.append(contentsOf: ConsentProvenanceAnalyzer.analyze(metadata: infoResult.metadata,
                                                               network: network, indices: indices,
                                                               trackerDB: trackerDB))
        findings.append(contentsOf: AIEgressAnalyzer.analyze(indices: indices))
        var childMeta = netMeta
        childMeta.storeGenre = storeGenre; childMeta.contentRating = contentRating
        findings.append(contentsOf: ChildSafetyAnalyzer.analyze(metadata: childMeta,
                                                                network: network, indices: indices))

        progress?.report(.init(phase: "Evaluating security posture", fraction: 0.95))
        let hardeningResult = BinaryHardeningAnalyzer.analyze(embeddedBinaries: embeddedBinaries,
                                                              machoByRel: machoByRel,
                                                              indices: indices)
        findings.append(contentsOf: hardeningResult.findings)

        findings.append(contentsOf: StorageAnalyzer.analyze(
            appDirectory: app,
            files: allFiles,
            linkedDylibs: Array(Set(embeddedBinaries.flatMap { $0.linkedDylibs })),
            indices: indices))

        let secretResult = SecretScanner.scan(indices: indices)
        findings.append(contentsOf: secretResult.findings)
        findings.append(contentsOf: resourceResult.findings)
        let allSecrets = (secretResult.secrets + resourceResult.secrets)
            .sorted { ($0.severity, $0.entropy) > ($1.severity, $1.entropy) }

        findings.append(contentsOf: AppExtensionAnalyzer.analyze(appDirectory: app))
        findings.append(contentsOf: PlatformVersionAnalyzer.analyze(appDirectory: app))

        let fileManifest = FileManifestBuilder.build(appDirectory: app, files: allFiles)

        findings = Self.collapseFindingsByRuleID(findings)

        let declaredKeys = Set(infoResult.metadata.permissions.map(\.key))
        let rulesByID = Dictionary(uniqueKeysWithValues: rulePack.rules.map { ($0.id, $0) })
        findings = findings.map { f in
            let ruleReq = rulesByID[f.ruleID]?.requiresPermission ?? []
            let resolved = PermissionGate.resolve(ruleID: f.ruleID, vectorID: f.vectorID,
                                                  ruleRequires: ruleReq,
                                                  declaredKeys: declaredKeys)
            if resolved.required.isEmpty { return f }
            var g = f
            g.permissionsRequired = resolved.required
            g.permissionsGranted = resolved.granted
            return g
        }

        findings = Self.applyDeclaredConditions(findings, declaredKeys: declaredKeys)

        findings = Self.droppingCoveredPermissions(findings)

        findings = findings.map { f in
            guard f.masvs.isEmpty, let group = Vectors.byID[f.vectorID]?.group else { return f }
            var g = f
            g.masvs = [group.rawValue]
            return g
        }

        let suppressions = SuppressionLoader.loadBundled()
        let suppressed = SuppressionEngine.apply(suppressions, to: findings)
        findings = suppressed.kept
        let firedSuppressions = suppressed.firedIDs

        findings = findings.map { $0.annotatedWithCrosswalk() }

        let vectorSummaries: [VectorSummary] = Vectors.all.map { v in
            let fs = findings.filter { $0.vectorID == v.id }
            let unique = Set(fs.flatMap { $0.evidences.map(\.value) }).count
            let maxSev = fs.map(\.severity).max() ?? .info
            return VectorSummary(vectorID: v.id, uniqueArtifactCount: unique, maxSeverity: maxSev)
        }

        var notes: [String] = []
        if let mainExe = infoResult.metadata.executableName,
           let main = embeddedBinaries.first(where: { $0.name == mainExe }), main.isFairPlayEncrypted {
            notes.append("Main binary is FairPlay-encrypted, TEXT-segment strings are unavailable. " +
                         "Resource files, symbols, and dylibs were still scanned for secrets/endpoints. " +
                         "Drop a decrypted .ipa (frida-ios-dump / bagbak output) for full TEXT coverage.")
        }
        let readableText = indices.values.filter { idx in
            idx.perSectionStrings.contains { $0.section.segment == "__TEXT" && !$0.strings.isEmpty }
        }.count
        let stringOnly = rulePack.rules.filter { !$0.search.isEmpty && $0.search.allSatisfy { $0.kind == .string } }
            .map(\.id).sorted()
        let coverage = ScanCoverage(binaries: indices.count, binariesWithReadableText: readableText,
                                    stringOnlyRules: stringOnly)
        if !indices.isEmpty && readableText < indices.count && !stringOnly.isEmpty {
            notes.append(readableText == 0
                ? "No binary has readable code strings (all FairPlay-encrypted), so \(stringOnly.count) rules that search only code strings could not be evaluated."
                : "Code strings are readable in \(readableText) of \(indices.count) binaries; \(stringOnly.count) rules that search only code strings saw those binaries alone.")
        }
        if !outsideLinks.isEmpty {
            notes.append("The bundle contains \(outsideLinks.count) symbolic link(s) pointing outside it, which were not followed: "
                         + outsideLinks.prefix(5).joined(separator: ", "))
        }
        if provision == nil {
            notes.append("No embedded.mobileprovision found, typical for App Store builds re-signed by the store.")
        }
        if !firedSuppressions.isEmpty {
            notes.append("Noise suppressions applied (\(firedSuppressions.count)): \(firedSuppressions.sorted().joined(separator: ", "))")
        }

        let report = ScanReport(
            sourceIPAPath: ipa.path,
            metadata: childMeta,
            findings: findings.sorted { ($0.severity, $1.ruleID) > ($1.severity, $0.ruleID) },
            vectorSummaries: vectorSummaries,
            scanDurationSeconds: Date().timeIntervalSince(start),
            notes: notes,
            network: network,
            hardening: hardeningResult.hardening,
            secrets: allSecrets,
            ats: infoResult.ats,
            fileManifest: fileManifest,
            coverage: coverage
        )
        progress?.report(.init(phase: "Done", fraction: 1.0))
        return ScanOutcome(report: report, indices: indices)
    }

    static func bundleFiles(in app: URL) -> (files: [URL], outsideLinks: [String]) {
        let keys: [URLResourceKey] = [.isRegularFileKey, .isDirectoryKey, .isSymbolicLinkKey, .fileSizeKey]
        var files: [URL] = []
        var outside: [String] = []
        let root = app.resolvingSymlinksInPath().standardizedFileURL.path + "/"
        guard let walk = FileManager.default.enumerator(at: app, includingPropertiesForKeys: keys) else {
            return ([], [])
        }
        for case let u as URL in walk {
            guard let v = try? u.resourceValues(forKeys: Set(keys)) else { continue }
            if v.isSymbolicLink == true {
                let target = u.resolvingSymlinksInPath().standardizedFileURL.path
                if !target.hasPrefix(root) { outside.append(u.relativePath(from: app)) }
                continue
            }
            if v.isRegularFile == true || v.isDirectory == true { files.append(u) }
        }
        return (files, outside.sorted())
    }

    static func droppingDuplicateSDKRules(_ findings: [Finding], rules: [Rule],
                                          network: NetworkInventory, trackerDB: TrackerDB) -> [Finding] {
        let detected = Set(network.detectedSDKs.filter(\.isTracker).map(\.trackerID))
        guard !detected.isEmpty else { return findings }
        let byID = Dictionary(uniqueKeysWithValues: rules.map { ($0.id, $0) })
        return findings.filter { f in
            guard let ids = byID[f.ruleID]?.trackerIDs, !ids.isEmpty else { return true }
            let covering = Set(ids).intersection(detected)
            if covering.isEmpty { return true }
            let frameworks = f.evidences.filter { $0.kind == .file }.map {
                ($0.value as NSString).deletingPathExtension
            }
            return frameworks.contains { name in
                guard let t = trackerDB.classify(framework: name) else { return true }
                return !covering.contains(t.id)
            }
        }
    }


    static func applyDeclaredConditions(_ findings: [Finding], declaredKeys: Set<String>) -> [Finding] {
        findings.map { f in
            guard let e = SeverityDerivation.entry(ruleID: f.ruleID, vectorID: f.vectorID),
                  e.method == "privacy" else { return f }
            let unmet = SeverityDerivation.unmetConditions(for: e, declaredKeys: declaredKeys)
            guard !unmet.isEmpty else { return f }
            let met = SeverityDerivation.criteria(for: e, declaredKeys: declaredKeys)
            let note = unmet.map { u in
                "WP248 criterion \(u.criterion) is not met: the Info.plist does not declare \(u.keys.joined(separator: " or "))."
            }.joined(separator: " ")
            return f.withSeverity(SeverityDerivation.severity(criteria: met), note: note)
        }
    }

    static func droppingCoveredPermissions(_ findings: [Finding]) -> [Finding] {
        var covered: [String: Severity] = [:]
        for f in findings where !f.ruleID.hasPrefix("perm.") {
            for key in f.permissionsRequired { covered[key] = max(covered[key] ?? f.severity, f.severity) }
        }
        return findings.filter { f in
            guard f.ruleID.hasPrefix("perm."), let sev = covered[String(f.ruleID.dropFirst(5))] else { return true }
            return f.severity > sev
        }
    }

    static func collapseFindingsByRuleID(_ findings: [Finding]) -> [Finding] {
        var byRule: [String: Finding] = [:]
        var order: [String] = []
        for f in findings {
            let key = f.ruleID + "\u{0}" + (f.instance ?? "")
            if let existing = byRule[key] {
                var seen = Set(existing.evidences)
                var ev = existing.evidences
                for e in f.evidences where !seen.contains(e) { seen.insert(e); ev.append(e) }
                let fws = Array(Set(existing.owningFrameworks + f.owningFrameworks
                    + [existing.owningFramework, f.owningFramework].compactMap { $0 })).sorted()
                let bins = Array(Set(existing.affectedBinaries + f.affectedBinaries)).sorted()
                let sev = max(existing.severity, f.severity)
                let masvs = Array(Set(existing.masvs + f.masvs)).sorted()
                var merged = existing
                merged.severity = sev
                merged.evidences = ev
                merged.owningFramework = fws.count == 1 ? fws[0] : nil
                merged.owningFrameworks = fws
                merged.affectedBinaries = bins
                merged.masvs = masvs
                merged.remediation = existing.remediation ?? f.remediation
                byRule[key] = merged
            } else {
                byRule[key] = f
                order.append(key)
            }
        }
        return order.compactMap { byRule[$0] }
    }

    static func associatedDomains(fromCodesignXML xml: String?) -> [String] {
        guard let data = xml?.data(using: .utf8),
              let top = (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? [String: Any],
              let entries = top["com.apple.developer.associated-domains"] as? [String] else { return [] }
        let hosts = entries.compactMap { entry -> String? in
            var e = Substring(entry)
            if let colon = e.firstIndex(of: ":") { e = e[e.index(after: colon)...] }
            if let q = e.firstIndex(of: "?") { e = e[..<q] }
            let h = e.trimmingCharacters(in: .whitespaces).lowercased()
            return h.contains(".") ? h : nil
        }
        return Array(Set(hosts)).sorted()
    }

    static func extractEntitlementKeys(fromCodesignXML xml: String?) -> [String] {
        guard let xml else { return [] }
        guard let data = xml.data(using: .utf8) else { return [] }
        guard let obj = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) else { return [] }
        var out: [String: String] = [:]
        PlistUtil.flatten(obj, prefix: "", into: &out)
        if let top = obj as? [String: Any] {
            for k in top.keys { out[k] = "1" }
        }
        return Array(out.keys)
    }
}
