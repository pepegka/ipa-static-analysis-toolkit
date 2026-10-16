import Foundation

enum NetworkInventoryBuilder {

    public static func build(metadata: BundleMetadata,
                             indices: [String: BinaryIndex],
                             trackerDB: TrackerDB,
                             extraEndpoints: [ExtractedEndpoint] = [],
                             mineSymbols: Bool = true,
                             cap: Int = 5000) -> NetworkInventory {
        var byHost: [String: Agg] = [:]

        let pairs = indices.sorted { $0.key < $1.key }
        final class Slots: @unchecked Sendable {
            var items: [[ExtractedEndpoint]]
            let lock = NSLock()
            init(_ n: Int) { items = Array(repeating: [], count: n) }
            func set(_ i: Int, _ v: [ExtractedEndpoint]) { lock.lock(); items[i] = v; lock.unlock() }
        }
        let slots = Slots(pairs.count)
        let mine = mineSymbols
        DispatchQueue.concurrentPerform(iterations: pairs.count) { idx in
            let bi = pairs[idx].value
            var extracted = URLExtractor.extract(from: bi)
            if mine { extracted.append(contentsOf: URLExtractor.extract(fromSymbols: bi)) }
            slots.set(idx, extracted)
        }
        for batch in slots.items { for e in batch { aggregate(e, into: &byHost) } }
        for e in extraEndpoints { aggregate(e, into: &byHost) }

        var declared = Set<String>()
        for d in metadata.privacyTrackingDomains {
            let e = ExtractedEndpoint(kind: .bareHost, raw: d, host: d.lowercased(),
                                      registrableDomain: PublicSuffixList.registrableDomain(for: d),
                                      scheme: nil, path: nil,
                                      source: "PrivacyInfo.xcprivacy",
                                      section: nil, offset: nil, isUTF16: false)
            aggregate(e, into: &byHost)
            declared.insert(d.lowercased())
        }

        let total = byHost.count
        if total > cap {
            let ranked = byHost.keys.sorted { a, b in
                let ra = (declared.contains(a) ? 0 : 1, trackerDB.owner(host: a) == nil ? 1 : 0)
                let rb = (declared.contains(b) ? 0 : 1, trackerDB.owner(host: b) == nil ? 1 : 0)
                if ra != rb { return ra < rb }
                let oa = byHost[a]!.occurrence, ob = byHost[b]!.occurrence
                if oa != ob { return oa > ob }
                return a < b
            }
            let keep = Set(ranked.prefix(cap))
            byHost = byHost.filter { keep.contains($0.key) }
        }
        let firstParty = firstPartyDomains(metadata.associatedDomains ?? [], trackerDB: trackerDB)
        return makeInventory(byHost: byHost, db: trackerDB, firstParty: firstParty,
                             frameworks: metadata.embeddedFrameworks,
                             plistKeys: metadata.infoPlistKeys ?? [],
                             hostsBeforeCap: total > cap ? total : nil)
    }

    static func firstPartyDomains(_ associated: [String], trackerDB: TrackerDB? = nil) -> Set<String> {
        Set(associated.compactMap { raw -> String? in
            var h = raw.lowercased()
            if h.hasPrefix("*.") { h.removeFirst(2) }
            guard h.contains("."), PublicSuffixList.publicSuffix(of: h) != h else { return nil }
            if trackerDB?.classify(host: h) != nil { return nil }
            return PublicSuffixList.registrableDomain(for: h)
        })
    }

    private struct Agg {
        var occurrence = 0
        var sources: Set<String> = []
        var paths: [String] = []
        var plistKeys: [String] = []
        var cleartext = false
    }

    private static func aggregate(_ e: ExtractedEndpoint, into byHost: inout [String: Agg]) {
        var a = byHost[e.host] ?? Agg()
        a.occurrence += 1
        if e.scheme?.lowercased() == "http" { a.cleartext = true }
        if a.sources.count < 12 { a.sources.insert(e.source) }
        if let p = e.path, !p.isEmpty, a.paths.count < 8, !a.paths.contains(p) {
            a.paths.append(p)
        }
        if e.source == "PrivacyInfo.xcprivacy" && !a.plistKeys.contains(e.source) {
            a.plistKeys.append(e.source)
        }
        byHost[e.host] = a
    }

    private static func makeInventory(byHost: [String: Agg], db: TrackerDB,
                                      firstParty: Set<String>,
                                      frameworks: [String] = [],
                                      plistKeys: [String] = [],
                                      hostsBeforeCap: Int?) -> NetworkInventory {
        var endpoints: [ClassifiedEndpoint] = []
        endpoints.reserveCapacity(byHost.count)
        var sdkBuckets: [String: (tracker: Tracker, occ: Int, hosts: Set<String>, frameworks: Set<String>, keys: Set<String>)] = [:]

        for (host, agg) in byHost {
            let etld = PublicSuffixList.registrableDomain(for: host)
            let own = firstParty.contains(etld)
            let t = own ? nil : db.classify(host: host)
            let owner = t ?? db.owner(host: host)
            endpoints.append(ClassifiedEndpoint(
                host: host,
                registrableDomain: etld,
                trackerID: t?.id,
                owner: owner?.owner,
                country: owner?.country,
                category: t?.category,
                isTracker: t?.isTracker ?? false,
                occurrenceCount: agg.occurrence,
                sources: Array(agg.sources).sorted(),
                samplePaths: agg.paths,
                samplePlistKeys: agg.plistKeys,
                cleartext: agg.cleartext,
                firstParty: own ? true : nil
            ))
            if let t {
                var s = sdkBuckets[t.id] ?? (t, 0, [], [], [])
                if t.isTracker { s.tracker = t }
                s.occ += agg.occurrence
                s.hosts.insert(host)
                for src in agg.sources {
                    s.frameworks.insert(FrameworkAttribution.framework(forRelativePath: src))
                }
                sdkBuckets[t.id] = s
            }
        }
        for name in Set(frameworks).sorted() {
            guard let t = db.classify(framework: name) else { continue }
            var s = sdkBuckets[t.id] ?? (t, 0, [], [], [])
            s.tracker = t
            s.occ += 1
            s.frameworks.insert(name)
            sdkBuckets[t.id] = s
        }
        for key in Set(plistKeys).sorted() {
            guard let t = db.classify(plistKey: key) else { continue }
            var s = sdkBuckets[t.id] ?? (t, 0, [], [], [])
            s.tracker = t
            s.occ += 1
            s.keys.insert(key)
            sdkBuckets[t.id] = s
        }
        endpoints.sort {
            if $0.isTracker != $1.isTracker { return $0.isTracker && !$1.isTracker }
            if $0.occurrenceCount != $1.occurrenceCount { return $0.occurrenceCount > $1.occurrenceCount }
            return $0.host < $1.host
        }
        let sdks: [DetectedSDK] = sdkBuckets.values.map {
            DetectedSDK(trackerID: $0.tracker.id, name: $0.tracker.name,
                        owner: $0.tracker.owner, country: $0.tracker.country,
                        category: $0.tracker.category, isTracker: $0.tracker.isTracker,
                        evidenceCount: $0.occ,
                        endpoints: Array($0.hosts).sorted(),
                        frameworks: Array($0.frameworks).sorted(),
                        plistKeys: $0.keys.isEmpty ? nil : Array($0.keys).sorted())
        }.sorted {
            if $0.evidenceCount != $1.evidenceCount { return $0.evidenceCount > $1.evidenceCount }
            return $0.name < $1.name
        }
        var inv = NetworkInventory(endpoints: endpoints, detectedSDKs: sdks)
        inv.hostsBeforeCap = hostsBeforeCap
        return inv
    }
}
