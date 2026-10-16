import Foundation

public struct MassScanRun: Codable, Sendable, Hashable {
    public let createdAt: Date
    public let country: String
    public let feed: String
    public let genre: String?
    public let requested: Int
    public let downloaded: Int
    public let scanned: Int
    public let failed: Int
    public let totalScanSeconds: Double
    public let totalIPABytes: UInt64

    public init(createdAt: Date, country: String, feed: String, genre: String?,
                requested: Int, downloaded: Int, scanned: Int, failed: Int,
                totalScanSeconds: Double, totalIPABytes: UInt64) {
        self.createdAt = createdAt; self.country = country; self.feed = feed; self.genre = genre
        self.requested = requested; self.downloaded = downloaded; self.scanned = scanned
        self.failed = failed; self.totalScanSeconds = totalScanSeconds
        self.totalIPABytes = totalIPABytes
    }
}

public struct AppCompareDetail: Codable, Sendable, Hashable {
    public struct DFinding: Codable, Sendable, Hashable {
        public let severity: String
        public let vector: String
        public let title: String
        public let group: String
        public let framework: String?
        public let label: String
        public let count: Int?
        public let detail: String?
        public let maswe: [String]?
        public let mastg: [String]?
        public let cluster: String?
        public let rule: String?
        public let polarity: String?

        public init(severity: String, vector: String, title: String, group: String, framework: String?,
                    label: String = "", count: Int? = nil, detail: String? = nil,
                    maswe: [String]? = nil, mastg: [String]? = nil, cluster: String? = nil,
                    rule: String? = nil, polarity: String? = nil) {
            self.severity = severity; self.vector = vector; self.title = title
            self.group = group; self.framework = framework
            self.label = label.isEmpty ? title : label
            self.count = count; self.detail = detail
            self.maswe = maswe; self.mastg = mastg; self.cluster = cluster
            self.rule = rule; self.polarity = polarity
        }

        public var polarityValue: Polarity { polarity.flatMap(Polarity.init(rawValue:)) ?? .offensive }

        enum CodingKeys: String, CodingKey {
            case severity, vector, title, group, framework, label, count, detail, maswe, mastg, cluster, rule, polarity
        }
        public init(from d: any Decoder) throws {
            let c = try d.container(keyedBy: CodingKeys.self)
            severity = try c.decode(String.self, forKey: .severity)
            vector = try c.decode(String.self, forKey: .vector)
            title = try c.decode(String.self, forKey: .title)
            group = try c.decode(String.self, forKey: .group)
            framework = try c.decodeIfPresent(String.self, forKey: .framework)
            label = try c.decodeIfPresent(String.self, forKey: .label) ?? title
            count = try c.decodeIfPresent(Int.self, forKey: .count)
            detail = try c.decodeIfPresent(String.self, forKey: .detail)
            maswe = try c.decodeIfPresent([String].self, forKey: .maswe)
            mastg = try c.decodeIfPresent([String].self, forKey: .mastg)
            cluster = try c.decodeIfPresent(String.self, forKey: .cluster)
            rule = try c.decodeIfPresent(String.self, forKey: .rule)
            polarity = try c.decodeIfPresent(String.self, forKey: .polarity)
        }
    }
    public struct DVector: Codable, Sendable, Hashable {
        public let code: String
        public let title: String
        public let group: String
        public let severity: String
        public let artifacts: Int
        public init(code: String, title: String, group: String, severity: String, artifacts: Int) {
            self.code = code; self.title = title; self.group = group
            self.severity = severity; self.artifacts = artifacts
        }
        enum CodingKeys: String, CodingKey { case code, title, group, severity, artifacts }
        public init(from d: any Decoder) throws {
            let c = try d.container(keyedBy: CodingKeys.self)
            code = try c.decode(String.self, forKey: .code)
            title = try c.decode(String.self, forKey: .title)
            group = try c.decode(String.self, forKey: .group)
            severity = try c.decode(String.self, forKey: .severity)
            artifacts = try c.decode(Int.self, forKey: .artifacts)
        }
    }
    public struct DTracker: Codable, Sendable, Hashable {
        public let name: String
        public let owner: String
        public let country: String
        public let category: String
        public init(name: String, owner: String, country: String, category: String) {
            self.name = name; self.owner = owner; self.country = country; self.category = category
        }
    }
    public struct DHardening: Codable, Sendable, Hashable {
        public let name: String
        public let pie: Bool
        public let canary: Bool?
        public let arc: Bool?
        public let encrypted: Bool
        public init(name: String, pie: Bool, canary: Bool?, arc: Bool?, encrypted: Bool) {
            self.name = name; self.pie = pie
            self.canary = canary; self.arc = arc; self.encrypted = encrypted
        }
    }
    public struct DPermission: Codable, Sendable, Hashable {
        public let key: String
        public let category: String?
        public init(key: String, category: String?) { self.key = key; self.category = category }
    }
    public let findings: [DFinding]
    public let vectors: [DVector]
    public let trackers: [DTracker]
    public let hardening: [DHardening]
    public let permissions: [DPermission]

    public init(findings: [DFinding], vectors: [DVector], trackers: [DTracker],
                hardening: [DHardening], permissions: [DPermission]) {
        self.findings = findings; self.vectors = vectors; self.trackers = trackers
        self.hardening = hardening; self.permissions = permissions
    }

    static func comparable(_ f: Finding) -> (label: String, count: Int?, detail: String?) {
        guard let c = Messages.compare(forRuleID: f.ruleID) else { return (f.title, nil, nil) }
        let label = Messages.substitute(c.label, f.metrics)
        guard !label.contains("{") else { return (f.title, nil, nil) }
        let detail = c.detail.flatMap { f.metrics[$0] }.flatMap { $0.isEmpty ? nil : $0 }
        guard let key = c.value, let raw = f.metrics[key] else { return (label, nil, detail) }
        if c.kind == "list" {
            let items = raw.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
            return (label, items.count, items.sorted().joined(separator: ", "))
        }
        return (label, Int(raw), detail)
    }

    public static func from(_ r: ScanReport) -> AppCompareDetail {
        let findings = r.findings.map { f -> DFinding in
            let (label, count, detail) = Self.comparable(f)
            return DFinding(severity: f.severity.rawValue,
                            vector: f.vectorID,
                            title: f.title,
                            group: Vectors.group(forVectorID: f.vectorID)?.rawValue ?? "",
                            framework: f.owningFramework,
                            label: label,
                            count: count,
                            detail: detail,
                            maswe: f.maswe,
                            mastg: f.mastg,
                            cluster: f.polarity == .defensive ? nil : FindingCluster.of(f)?.id,
                            rule: f.ruleID,
                            polarity: f.polarity == .offensive ? nil : f.polarity.rawValue)
        }
        let vectors = r.vectorSummaries.filter { $0.uniqueArtifactCount > 0 }.map { vs -> DVector in
            let v = Vectors.byID[vs.vectorID]
            return DVector(code: vs.vectorID, title: v?.title ?? "",
                           group: v?.group.rawValue ?? "", severity: vs.maxSeverity.rawValue,
                           artifacts: vs.uniqueArtifactCount)
        }
        let trackers = r.network.detectedSDKs.filter(\.isTracker).map {
            DTracker(name: $0.name, owner: $0.owner, country: $0.country, category: $0.category)
        }
        let hardening = r.hardening.filter { $0.isAnalysable }.map {
            DHardening(name: $0.name, pie: $0.hasPIE,
                       canary: $0.hasStackCanary, arc: $0.hasARC, encrypted: $0.isEncrypted)
        }
        let permissions = r.metadata.permissions.map { DPermission(key: $0.key, category: $0.category) }
        return AppCompareDetail(findings: findings, vectors: vectors, trackers: trackers,
                                hardening: hardening, permissions: permissions)
    }
}

public struct MassScanAppEntry: Codable, Sendable, Hashable, Identifiable {
    public var id: String { "\(appID)/\(bundleID)" }

    public let appID: Int64
    public let bundleID: String
    public let appStoreName: String
    public let artist: String?
    public let category: String?
    public let chartRank: Int?
    public let version: String?

    public let findingsCount: Int?
    public let criticalCount: Int?
    public let highCount: Int?
    public let trackerCount: Int?
    public let secretCount: Int?
    public let atsArbitraryLoads: Bool?
    public let sizeBytes: UInt64?
    public let scanSeconds: Double?
    public let reportPaths: [String: String]
    public let error: String?
    public let severityCounts: [String: Int]
    public let masvsCounts: [String: Int]
    public let clusterCounts: [String: Int]
    public let trackerNames: [String]
    public var details: AppCompareDetail?

    public var ok: Bool { error == nil && findingsCount != nil }

    public var severityRank: [Int] {
        [criticalCount ?? 0, highCount ?? 0,
         severityCounts[Severity.medium.rawValue] ?? 0,
         severityCounts[Severity.low.rawValue] ?? 0]
    }

    public init(appID: Int64, bundleID: String, appStoreName: String, artist: String?,
                category: String?, chartRank: Int?, version: String?,
                findingsCount: Int? = nil, criticalCount: Int? = nil,
                highCount: Int? = nil, trackerCount: Int? = nil, secretCount: Int? = nil,
                atsArbitraryLoads: Bool? = nil,
                sizeBytes: UInt64? = nil, scanSeconds: Double? = nil,
                reportPaths: [String: String] = [:], error: String? = nil,
                severityCounts: [String: Int] = [:], masvsCounts: [String: Int] = [:],
                clusterCounts: [String: Int] = [:],
                trackerNames: [String] = [], details: AppCompareDetail? = nil) {
        self.appID = appID; self.bundleID = bundleID; self.appStoreName = appStoreName
        self.artist = artist; self.category = category; self.chartRank = chartRank
        self.version = version
        self.findingsCount = findingsCount
        self.criticalCount = criticalCount; self.highCount = highCount
        self.trackerCount = trackerCount; self.secretCount = secretCount
        self.atsArbitraryLoads = atsArbitraryLoads
        self.sizeBytes = sizeBytes; self.scanSeconds = scanSeconds
        self.reportPaths = reportPaths; self.error = error
        self.severityCounts = severityCounts; self.masvsCounts = masvsCounts
        self.clusterCounts = clusterCounts
        self.trackerNames = trackerNames; self.details = details
    }

    enum CodingKeys: String, CodingKey {
        case appID, bundleID, appStoreName, artist, category, chartRank, version
        case findingsCount, criticalCount, highCount, trackerCount, secretCount
        case atsArbitraryLoads, sizeBytes, scanSeconds, reportPaths, error
        case severityCounts, masvsCounts, clusterCounts, trackerNames, details
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        appID = try c.decode(Int64.self, forKey: .appID)
        bundleID = try c.decode(String.self, forKey: .bundleID)
        appStoreName = try c.decode(String.self, forKey: .appStoreName)
        artist = try c.decodeIfPresent(String.self, forKey: .artist)
        category = try c.decodeIfPresent(String.self, forKey: .category)
        chartRank = try c.decodeIfPresent(Int.self, forKey: .chartRank)
        version = try c.decodeIfPresent(String.self, forKey: .version)
        findingsCount = try c.decodeIfPresent(Int.self, forKey: .findingsCount)
        criticalCount = try c.decodeIfPresent(Int.self, forKey: .criticalCount)
        highCount = try c.decodeIfPresent(Int.self, forKey: .highCount)
        trackerCount = try c.decodeIfPresent(Int.self, forKey: .trackerCount)
        secretCount = try c.decodeIfPresent(Int.self, forKey: .secretCount)
        atsArbitraryLoads = try c.decodeIfPresent(Bool.self, forKey: .atsArbitraryLoads)
        sizeBytes = try c.decodeIfPresent(UInt64.self, forKey: .sizeBytes)
        scanSeconds = try c.decodeIfPresent(Double.self, forKey: .scanSeconds)
        reportPaths = try c.decodeIfPresent([String: String].self, forKey: .reportPaths) ?? [:]
        error = try c.decodeIfPresent(String.self, forKey: .error)
        severityCounts = try c.decodeIfPresent([String: Int].self, forKey: .severityCounts) ?? [:]
        masvsCounts = try c.decodeIfPresent([String: Int].self, forKey: .masvsCounts) ?? [:]
        clusterCounts = try c.decodeIfPresent([String: Int].self, forKey: .clusterCounts) ?? [:]
        trackerNames = try c.decodeIfPresent([String].self, forKey: .trackerNames) ?? []
        details = try c.decodeIfPresent(AppCompareDetail.self, forKey: .details)
    }

    public func withScan(_ r: ScanReport, sizeBytes: UInt64?, reportPaths: [String: String]) -> MassScanAppEntry {
        let crit = r.findings.filter { $0.severity == .critical }.count
        let high = r.findings.filter { $0.severity == .high }.count
        var sevCounts: [String: Int] = Dictionary(uniqueKeysWithValues: Severity.allCases.map { ($0.rawValue, 0) })
        for f in r.findings { sevCounts[f.severity.rawValue, default: 0] += 1 }
        let masvsCounts = Dictionary(uniqueKeysWithValues: r.masvsRollup().map { ($0.group.rawValue, $0.hitCount) })
        let clusterCounts = Dictionary(uniqueKeysWithValues: r.findings.clusterRollup().map { ($0.id, $0.findingCount) })
        let trackers = Array(Set(r.network.detectedSDKs.filter(\.isTracker).map(\.name))).sorted()
        return MassScanAppEntry(
            appID: appID, bundleID: bundleID, appStoreName: appStoreName, artist: artist,
            category: category, chartRank: chartRank, version: version ?? r.metadata.shortVersion,
            findingsCount: r.findings.count, criticalCount: crit, highCount: high,
            trackerCount: r.network.detectedSDKs.filter(\.isTracker).count,
            secretCount: r.secrets.filter(\.isCredential).count, atsArbitraryLoads: r.ats.allowsArbitraryLoads,
            sizeBytes: sizeBytes, scanSeconds: r.scanDurationSeconds,
            reportPaths: reportPaths, error: nil,
            severityCounts: sevCounts, masvsCounts: masvsCounts,
            clusterCounts: clusterCounts, trackerNames: trackers,
            details: AppCompareDetail.from(r))
    }

    public func withClusterCounts(_ clusterCounts: [String: Int]?) -> MassScanAppEntry {
        MassScanAppEntry(
            appID: appID, bundleID: bundleID, appStoreName: appStoreName, artist: artist,
            category: category, chartRank: chartRank, version: version,
            findingsCount: findingsCount, criticalCount: criticalCount, highCount: highCount,
            trackerCount: trackerCount, secretCount: secretCount, atsArbitraryLoads: atsArbitraryLoads,
            sizeBytes: sizeBytes, scanSeconds: scanSeconds,
            reportPaths: reportPaths, error: error, severityCounts: severityCounts,
            masvsCounts: masvsCounts, clusterCounts: clusterCounts ?? self.clusterCounts,
            trackerNames: trackerNames, details: details)
    }

    public func withStoreMetadata(appID: Int64? = nil, category: String? = nil,
                                  artist: String? = nil) -> MassScanAppEntry {
        MassScanAppEntry(
            appID: appID ?? self.appID, bundleID: bundleID, appStoreName: appStoreName,
            artist: artist ?? self.artist, category: category ?? self.category,
            chartRank: chartRank, version: version,
            findingsCount: findingsCount, criticalCount: criticalCount, highCount: highCount,
            trackerCount: trackerCount, secretCount: secretCount, atsArbitraryLoads: atsArbitraryLoads,
            sizeBytes: sizeBytes, scanSeconds: scanSeconds,
            reportPaths: reportPaths, error: error, severityCounts: severityCounts,
            masvsCounts: masvsCounts, clusterCounts: clusterCounts,
            trackerNames: trackerNames, details: details)
    }

    public func withError(_ message: String) -> MassScanAppEntry {
        MassScanAppEntry(appID: appID, bundleID: bundleID, appStoreName: appStoreName,
                         artist: artist, category: category, chartRank: chartRank,
                         version: version, error: message)
    }
}

public struct CountItem: Codable, Sendable, Hashable {
    public let label: String
    public let count: Int
    public let detail: String?
    public init(label: String, count: Int, detail: String? = nil) {
        self.label = label; self.count = count; self.detail = detail
    }
}

public struct MassScanStats: Codable, Sendable, Hashable {
    public let appsScanned: Int
    public let totalFindings: Int
    public let totalUniqueTrackers: Int
    public let appsWithATSArbitraryLoads: Int
    public let appsWithSecrets: Int
    public let severityHistogram: [CountItem]
    public let clusterFrequency: [CountItem]
    public let masweFrequency: [CountItem]
    public let topTrackers: [CountItem]
    public let topEndpointOwners: [CountItem]
    public let topEndpointCountries: [CountItem]
    public let topPermissions: [CountItem]
    public let topVectors: [CountItem]
    public let masvsGroupFrequency: [CountItem]

    public static let empty = MassScanStats(
        appsScanned: 0,
        totalFindings: 0, totalUniqueTrackers: 0, appsWithATSArbitraryLoads: 0, appsWithSecrets: 0,
        severityHistogram: [], clusterFrequency: [], masweFrequency: [],
        topTrackers: [], topEndpointOwners: [], topEndpointCountries: [], topPermissions: [],
        topVectors: [], masvsGroupFrequency: [])

    public init(appsScanned: Int, totalFindings: Int, totalUniqueTrackers: Int,
                appsWithATSArbitraryLoads: Int, appsWithSecrets: Int,
                severityHistogram: [CountItem],
                clusterFrequency: [CountItem], masweFrequency: [CountItem],
                topTrackers: [CountItem],
                topEndpointOwners: [CountItem], topEndpointCountries: [CountItem],
                topPermissions: [CountItem], topVectors: [CountItem], masvsGroupFrequency: [CountItem]) {
        self.appsScanned = appsScanned
        self.totalFindings = totalFindings; self.totalUniqueTrackers = totalUniqueTrackers
        self.appsWithATSArbitraryLoads = appsWithATSArbitraryLoads; self.appsWithSecrets = appsWithSecrets
        self.severityHistogram = severityHistogram
        self.clusterFrequency = clusterFrequency; self.masweFrequency = masweFrequency
        self.topTrackers = topTrackers; self.topEndpointOwners = topEndpointOwners
        self.topEndpointCountries = topEndpointCountries; self.topPermissions = topPermissions
        self.topVectors = topVectors; self.masvsGroupFrequency = masvsGroupFrequency
    }
}

extension MassScanStats {
    enum CodingKeys: String, CodingKey {
        case appsScanned, totalFindings, totalUniqueTrackers
        case appsWithATSArbitraryLoads, appsWithSecrets
        case severityHistogram, clusterFrequency, masweFrequency
        case topTrackers, topEndpointOwners, topEndpointCountries, topPermissions
        case topVectors, masvsGroupFrequency
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        func items(_ k: CodingKeys) throws -> [CountItem] {
            try c.decodeIfPresent([CountItem].self, forKey: k) ?? []
        }
        self.init(
            appsScanned: try c.decodeIfPresent(Int.self, forKey: .appsScanned) ?? 0,
            totalFindings: try c.decodeIfPresent(Int.self, forKey: .totalFindings) ?? 0,
            totalUniqueTrackers: try c.decodeIfPresent(Int.self, forKey: .totalUniqueTrackers) ?? 0,
            appsWithATSArbitraryLoads: try c.decodeIfPresent(Int.self, forKey: .appsWithATSArbitraryLoads) ?? 0,
            appsWithSecrets: try c.decodeIfPresent(Int.self, forKey: .appsWithSecrets) ?? 0,
            severityHistogram: try items(.severityHistogram),
            clusterFrequency: try items(.clusterFrequency),
            masweFrequency: try items(.masweFrequency),
            topTrackers: try items(.topTrackers),
            topEndpointOwners: try items(.topEndpointOwners),
            topEndpointCountries: try items(.topEndpointCountries),
            topPermissions: try items(.topPermissions),
            topVectors: try items(.topVectors),
            masvsGroupFrequency: try items(.masvsGroupFrequency))
    }
}

public struct MassScanReport: Codable, Sendable, Hashable {
    public let run: MassScanRun
    public let apps: [MassScanAppEntry]
    public let stats: MassScanStats

    public init(run: MassScanRun, apps: [MassScanAppEntry], stats: MassScanStats) {
        self.run = run; self.apps = apps; self.stats = stats
    }

    public static func make(run: MassScanRun,
                            scans: [(entry: MassScanAppEntry, report: ScanReport?)]) -> MassScanReport {
        let reports = scans.compactMap(\.report)
        let scored = scans.map(\.entry).filter(\.ok)
        let failed = scans.map(\.entry).filter { !$0.ok }

        func appFrequency(_ keysPerReport: (ScanReport) -> [(key: String, detail: String?)]) -> [CountItem] {
            var count: [String: Int] = [:]
            var detail: [String: String?] = [:]
            for r in reports {
                var seen = Set<String>()
                for (k, d) in keysPerReport(r) where !k.isEmpty && seen.insert(k).inserted {
                    count[k, default: 0] += 1
                    if detail[k] == nil { detail[k] = d }
                }
            }
            return count.map { CountItem(label: $0.key, count: $0.value, detail: detail[$0.key] ?? nil) }
                .sorted { $0.count != $1.count ? $0.count > $1.count : $0.label < $1.label }
        }

        let severityHistogram = Severity.allCases.map { sev in
            CountItem(label: sev.rawValue, count: reports.reduce(0) { $0 + $1.findings.filter { $0.severity == sev }.count })
        }

        let topTrackers = appFrequency { r in
            r.network.detectedSDKs.filter(\.isTracker).map { sdk in
                (sdk.name, [sdk.owner, sdk.country, sdk.category].filter { !$0.isEmpty }.joined(separator: " · "))
            }
        }
        let topEndpointOwners = appFrequency { r in
            r.network.endpoints.compactMap { e in e.owner.map { ($0, e.country) } }
        }
        let topEndpointCountries = appFrequency { r in
            r.network.endpoints.compactMap { e in e.country.map { ($0, nil) } }
        }
        let topPermissions = appFrequency { r in
            r.metadata.permissions.map { ($0.key, $0.category) }
        }
        let topVectors = appFrequency { r in
            Set(r.findings.filter { $0.countsAsWeakness && $0.severity > .info }.map(\.vectorID))
                .sorted().map { id in
                    let v = Vectors.byID[id]
                    return ("\(id), \(v?.title ?? "")", v?.group.rawValue)
                }
        }
        let masvsGroupFrequency = appFrequency { r in
            Self.weaknessClusters(r.findings).compactMap { c -> (String, String?)? in
                guard case .masvs(let g) = c else { return nil }
                return ("\(g.rawValue) \u{00B7} \(g.title)", nil)
            }
        }
        let clusterFrequency = appFrequency { r in
            Self.weaknessClusters(r.findings).map { ("\($0.id) \u{00B7} \($0.title)", nil) }
        }
        let masweFrequency: [CountItem] = {
            var count: [String: Int] = [:], title: [String: String] = [:]
            for r in reports {
                for w in r.findings.filter({ $0.severity > .info }).clusterRollup().flatMap(\.children) {
                    count[w.id, default: 0] += w.findingCount
                    title[w.id] = w.title
                }
            }
            return count.map { CountItem(label: $0.key, count: $0.value, detail: title[$0.key]) }
                .sorted { $0.count != $1.count ? $0.count > $1.count : $0.label < $1.label }
        }()

        let uniqueTrackers = Set(reports.flatMap { $0.network.detectedSDKs.filter(\.isTracker).map(\.trackerID) }).count

        let stats = MassScanStats(
            appsScanned: scored.count,
            totalFindings: reports.reduce(0) { $0 + $1.findings.count },
            totalUniqueTrackers: uniqueTrackers,
            appsWithATSArbitraryLoads: scored.filter { $0.atsArbitraryLoads == true }.count,
            appsWithSecrets: scored.filter { ($0.secretCount ?? 0) > 0 }.count,
            severityHistogram: severityHistogram,
            clusterFrequency: clusterFrequency, masweFrequency: masweFrequency,
            topTrackers: topTrackers, topEndpointOwners: topEndpointOwners,
            topEndpointCountries: topEndpointCountries, topPermissions: topPermissions,
            topVectors: topVectors, masvsGroupFrequency: masvsGroupFrequency)

        return MassScanReport(run: run, apps: Self.ordered(scored) + failed, stats: stats)
    }

    public func rederivedFromDetail() -> MassScanReport {
        let rescored: [MassScanAppEntry] = apps.map { app in
            guard app.ok, let det = app.details else { return app }
            return app.withClusterCounts(Self.clusterCounts(det))
        }

        let scored = rescored.filter(\.ok)
        let failed = rescored.filter { !$0.ok }

        func frequency(_ key: (AppCompareDetail) -> [(String, String?)]) -> [CountItem] {
            var count: [String: Int] = [:], detail: [String: String?] = [:]
            for app in scored {
                guard let det = app.details else { continue }
                var seen = Set<String>()
                for (k, d) in key(det) where !k.isEmpty && seen.insert(k).inserted {
                    count[k, default: 0] += 1
                    if detail[k] == nil { detail[k] = d }
                }
            }
            return count.map { CountItem(label: $0.key, count: $0.value, detail: detail[$0.key] ?? nil) }
                .sorted { $0.count != $1.count ? $0.count > $1.count : $0.label < $1.label }
        }
        let clusterFrequency = frequency { det in
            Self.weaknessClusters(Self.findings(det)).map { ("\($0.id) \u{00B7} \($0.title)", nil) }
        }
        let masvsGroupFrequency = frequency { det in
            Self.weaknessClusters(Self.findings(det)).compactMap { c -> (String, String?)? in
                guard case .masvs(let g) = c else { return nil }
                return ("\(g.rawValue) \u{00B7} \(g.title)", nil)
            }
        }
        let masweFrequency: [CountItem] = {
            var count: [String: Int] = [:], title: [String: String] = [:]
            for app in scored {
                guard let det = app.details else { continue }
                for w in Self.findings(det).filter({ $0.severity > .info }).clusterRollup().flatMap(\.children) {
                    count[w.id, default: 0] += w.findingCount
                    title[w.id] = w.title
                }
            }
            return count.map { CountItem(label: $0.key, count: $0.value, detail: title[$0.key]) }
                .sorted { $0.count != $1.count ? $0.count > $1.count : $0.label < $1.label }
        }()

        let old = stats
        let newStats = MassScanStats(
            appsScanned: old.appsScanned,
            totalFindings: old.totalFindings, totalUniqueTrackers: old.totalUniqueTrackers,
            appsWithATSArbitraryLoads: old.appsWithATSArbitraryLoads, appsWithSecrets: old.appsWithSecrets,
            severityHistogram: old.severityHistogram,
            clusterFrequency: clusterFrequency, masweFrequency: masweFrequency,
            topTrackers: old.topTrackers, topEndpointOwners: old.topEndpointOwners,
            topEndpointCountries: old.topEndpointCountries, topPermissions: old.topPermissions,
            topVectors: old.topVectors, masvsGroupFrequency: masvsGroupFrequency)

        return MassScanReport(run: run, apps: Self.ordered(scored) + failed, stats: newStats)
    }

    static func ordered(_ apps: [MassScanAppEntry]) -> [MassScanAppEntry] {
        apps.sorted {
            $0.severityRank != $1.severityRank
                ? $0.severityRank.lexicographicallyPrecedes($1.severityRank, by: >)
                : $0.appStoreName.localizedCaseInsensitiveCompare($1.appStoreName) == .orderedAscending
        }
    }

    static func weaknessClusters(_ findings: [Finding]) -> [FindingCluster] {
        let hit = Set(findings.filter { $0.countsAsWeakness && $0.severity > .info }
            .compactMap(FindingCluster.of))
        return FindingCluster.allOrdered.filter(hit.contains)
    }

    static func findings(_ det: AppCompareDetail) -> [Finding] {
        det.findings.map {
            let cw = FrameworkCrosswalk.for(vectorID: $0.vector)
            return Finding(ruleID: $0.rule ?? "", vectorID: $0.vector, title: $0.title, explanation: "",
                           severity: Severity(rawValue: $0.severity) ?? .info,
                           evidences: [],
                           mastg: $0.mastg ?? cw.mastg, maswe: $0.maswe ?? cw.maswe)
                .withPolarity($0.polarityValue)
        }
    }

    static func clusters(_ det: AppCompareDetail) -> [ClusterSummary] {
        det.findings.map {
            let cw = FrameworkCrosswalk.for(vectorID: $0.vector)
            return Finding(ruleID: "", vectorID: $0.vector, title: $0.title, explanation: "",
                           severity: Severity(rawValue: $0.severity) ?? .info,
                           evidences: [],
                           mastg: $0.mastg ?? cw.mastg, maswe: $0.maswe ?? cw.maswe)
                .withPolarity($0.polarityValue)
        }.clusterRollup()
    }

    static func clusterCounts(_ det: AppCompareDetail) -> [String: Int] {
        Dictionary(uniqueKeysWithValues: clusters(det).map { ($0.id, $0.findingCount) })
    }
}
