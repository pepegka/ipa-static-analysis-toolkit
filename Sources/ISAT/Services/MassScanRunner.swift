import Foundation
import ScannerKit

struct MassScanConfig: Sendable {
    var top: Int = 100
    var feed: String = "top-free"
    var kind: String = "all"
    var maxSizeBytes: UInt64? = nil
    var country: String = "us"
    var genre: Int? = nil
    var outputRoot: URL
    var perAppFormats: [ReportExporter.Format] = [.json]
    var dashboardFormats: [MassScanDashboardExporter.Format] = [.json, .markdown, .html]
    var delaySeconds: Double = 4
    var concurrency: Int = 1
    var maxRetries: Int = 3
    var rescan: Bool = false
    var keepIPA: Bool = false
    var platform: String? = nil
    var scanOnlyDir: URL? = nil
    var storeMetadata: URL? = nil
    var dryRun: Bool = false
}

enum MassScanRunner {

    private struct Job: Sendable {
        let chart: ChartApp
        let localIPA: URL?
        var knownSizeBytes: UInt64? = nil
        var contentRating: String? = nil
        var store: MassScanAppEntry? = nil
    }

    static func run(_ config: MassScanConfig) async {
        let scanner = ScannerKit.Scanner()
        let fm = FileManager.default

        let swept = IPAExtractor.sweepStaleTempDirs()
        if swept.count > 0 {
            err("reclaimed \(swept.count) stale temp extraction dir(s) (\(byteSizeStr(UInt64(max(0, swept.bytes)))))")
        }

        let liveProgress = config.concurrency == 1 && isatty(fileno(stderr)) != 0

        var jobs: [Job]
        do {
            jobs = try await resolveJobs(config)
        } catch {
            err("could not resolve app list: \(error.localizedDescription)")
            return
        }
        if jobs.isEmpty { err("no apps to scan."); return }

        if config.scanOnlyDir == nil {
            let details = await TopChartsService.lookupDetails(appIDs: jobs.map { $0.chart.appID },
                                                               country: config.country)
            jobs = jobs.map {
                var j = $0
                j.knownSizeBytes = details[$0.chart.appID]?.sizeBytes
                j.contentRating = details[$0.chart.appID]?.contentRating
                return j
            }
            if let maxB = config.maxSizeBytes {
                let before = jobs.count
                jobs = jobs.filter { ($0.knownSizeBytes.map { $0 <= maxB }) ?? true }
                let dropped = before - jobs.count
                if dropped > 0 { err("size filter: dropped \(dropped) app(s) over \(byteSizeStr(maxB)) before download") }
            }
            if jobs.isEmpty { err("no apps left after the size filter."); return }
        }

        if config.dryRun {
            for j in jobs {
                print("\(j.chart.rank)\t\(j.chart.appID)\t\(j.chart.bundleID)\t\(j.chart.name)\(j.chart.category.map { "\t\($0)" } ?? "")")
            }
            err("dry run: \(jobs.count) apps resolved, nothing downloaded.")
            return
        }

        let appsDir = config.outputRoot.appendingPathComponent("apps", isDirectory: true)
        let ipasDir = config.outputRoot.appendingPathComponent("ipas", isDirectory: true)
        try? fm.createDirectory(at: appsDir, withIntermediateDirectories: true)
        if config.scanOnlyDir == nil {
            try? fm.createDirectory(at: ipasDir, withIntermediateDirectories: true)
        }

        if config.scanOnlyDir == nil {
            err("storefront: using the '\(config.country)' App Store (override with --country). Apps must be available in your Apple ID's region to download.")
            let account = (try? await IpatoolService.shared.accountInfo()) ?? nil
            if account == nil {
                err("warning: not signed in to the App Store, downloads will fail. Run `ISAT --login` first.")
            }
        }

        var collected: [(entry: MassScanAppEntry, report: ScanReport?)] = []
        let batchSize = max(1, config.concurrency)
        let total = jobs.count
        var done = 0
        var availabilityFails = 0
        var hintedStorefront = false
        for batch in jobs.chunked(into: batchSize) {
            let results = await withTaskGroup(of: Processed.self) { group in
                for job in batch {
                    group.addTask {
                        await process(job: job, config: config, scanner: scanner,
                                      appsDir: appsDir, ipasDir: ipasDir, liveProgress: liveProgress)
                    }
                }
                var acc: [Processed] = []
                for await r in group { acc.append(r) }
                return acc
            }
            collected.append(contentsOf: results.map { (entry: $0.entry, report: $0.report) })
            done += batch.count
            for r in results {
                let e = r.entry
                if e.ok {
                    let sev = e.severityRank
                    err("[\(done)/\(total)] ✓ \(e.appStoreName), \(e.findingsCount ?? 0) findings "
                        + "(\(sev[0]) critical, \(sev[1]) high)")
                } else {
                    err("[\(done)/\(total)] ✗ \(e.appStoreName), \(e.error ?? "failed")")
                    if let msg = e.error, classify(msg) == .availability { availabilityFails += 1 }
                }
            }
            if results.contains(where: { $0.fatal }) {
                err("stopping: disk space too low to continue safely. " +
                    "Free up space (the downloaded IPAs live in \(ipasDir.path)) and re-run, " +
                    "completed apps are reused, so the scan resumes where it left off.")
                break
            }
            let didAnyDownload = results.contains { $0.didDownload }
            if config.scanOnlyDir == nil, !hintedStorefront, done >= 10,
               Double(availabilityFails) / Double(done) >= 0.5 {
                hintedStorefront = true
                err("hint: \(availabilityFails)/\(done) apps were unavailable in the '\(config.country)' store. " +
                    "If your Apple ID is in another region, stop (Ctrl-C) and re-run with --country <cc> " +
                    "(e.g. --country de) so the charts match what you can download.")
            }
            if done < total && didAnyDownload {
                try? await Task.sleep(nanoseconds: UInt64(config.delaySeconds * 1_000_000_000))
            }
        }

        let okCount = collected.filter { $0.entry.ok }.count
        let downloaded = config.scanOnlyDir == nil ? okCount : 0
        let run = MassScanRun(
            createdAt: Date(),
            country: config.country,
            feed: config.scanOnlyDir == nil ? config.feed : "scan-only",
            genre: config.genre.map(String.init),
            requested: config.scanOnlyDir == nil ? config.top : jobs.count,
            downloaded: downloaded,
            scanned: okCount,
            failed: collected.count - okCount,
            totalScanSeconds: collected.compactMap { $0.entry.scanSeconds }.reduce(0, +),
            totalIPABytes: collected.compactMap { $0.entry.sizeBytes }.reduce(0, +))
        let report = MassScanReport.make(run: run, scans: collected)

        for f in config.dashboardFormats {
            let dest = config.outputRoot.appendingPathComponent("dashboard.\(f.fileExtension)")
            do {
                try MassScanDashboardExporter.export(report, format: f).write(to: dest, options: .atomic)
                err("wrote \(dest.path)")
            } catch {
                err("failed to write \(dest.lastPathComponent): \(error.localizedDescription)")
            }
        }
        if config.dashboardFormats.contains(.html) { await vendorECharts(into: config.outputRoot) }
        err("done: \(okCount) scanned, \(collected.count - okCount) failed → \(config.outputRoot.path)")
    }

    private struct Processed {
        let entry: MassScanAppEntry
        let report: ScanReport?
        let didDownload: Bool
        var fatal: Bool = false
    }

    private static func process(job: Job, config: MassScanConfig, scanner: ScannerKit.Scanner,
                                appsDir: URL, ipasDir: URL, liveProgress: Bool) async -> Processed {
        let fm = FileManager.default
        let chart = job.chart
        let ipaStem = job.localIPA?.deletingPathExtension().lastPathComponent ?? ""
        let dirLabel = !chart.name.isEmpty ? chart.name
            : (!chart.bundleID.isEmpty ? chart.bundleID : (!ipaStem.isEmpty ? ipaStem : String(chart.appID)))
        let dirName = "\(chart.appID)_\(sanitize(dirLabel))"
        let appDir = appsDir.appendingPathComponent(dirName, isDirectory: true)
        let displayLabel = chart.name.isEmpty
            ? (job.localIPA?.deletingPathExtension().lastPathComponent ?? String(chart.appID))
            : chart.name

        let store = job.store
        func base(name: String, bundleID: String = chart.bundleID) -> MassScanAppEntry {
            MassScanAppEntry(appID: chart.appID != 0 ? chart.appID : (store?.appID ?? 0), bundleID: bundleID,
                             appStoreName: name, artist: chart.artist ?? store?.artist,
                             category: chart.category ?? store?.category,
                             chartRank: chart.rank != 0 ? chart.rank : store?.chartRank, version: nil)
        }

        let existingJSON = appDir.appendingPathComponent("report.json")
        if !config.rescan, let data = try? Data(contentsOf: existingJSON) {
            let dec = JSONDecoder(); dec.dateDecodingStrategy = .iso8601
            if let r = try? dec.decode(ScanReport.self, from: data) {
                let name = chart.name.isEmpty ? (r.metadata.displayName ?? r.metadata.bundleName) : chart.name
                let bid = chart.bundleID.isEmpty ? r.metadata.bundleID : chart.bundleID
                let paths = reportPaths(in: appDir, root: config.outputRoot, formats: config.perAppFormats)
                let ipa = job.localIPA ?? existingIPA(bundleID: bid, in: ipasDir, fm: fm)
                let size = ipa.flatMap { (try? fm.attributesOfItem(atPath: $0.path)[.size] as? UInt64) ?? nil }
                return Processed(entry: base(name: name, bundleID: bid).withScan(r, sizeBytes: size, reportPaths: paths),
                                 report: r, didDownload: false)
            }
        }

        let ipaURL: URL
        let downloaded: Bool
        if let local = job.localIPA {
            ipaURL = local; downloaded = false
        } else if let existing = existingIPA(bundleID: chart.bundleID, in: ipasDir, fm: fm) {
            err("[\(chart.rank)] ↩ reusing \(existing.lastPathComponent)")
            ipaURL = existing; downloaded = false
        } else {
            let monitor: Task<Void, Never>? = liveProgress
                ? Task { await monitorDownload(label: displayLabel, dir: ipasDir, appID: chart.appID, total: job.knownSizeBytes) }
                : nil
            do {
                ipaURL = try await downloadWithRetry(chart: chart, into: ipasDir, config: config)
                downloaded = true
                monitor?.cancel()
            } catch {
                monitor?.cancel()
                if liveProgress { ProgressBar.clear() }
                return Processed(entry: base(name: chart.name).withError(error.localizedDescription),
                                 report: nil, didDownload: false)
            }
            if liveProgress { ProgressBar.clear() }
        }

        let ipaSize = (try? fm.attributesOfItem(atPath: ipaURL.path)[.size] as? UInt64) ?? nil
        if let maxB = config.maxSizeBytes, let sz = ipaSize, sz > maxB {
            if downloaded && !config.keepIPA { try? fm.removeItem(at: ipaURL) }
            return Processed(entry: base(name: chart.name).withError("skipped: \(byteSizeStr(sz)) exceeds max \(byteSizeStr(maxB))"),
                             report: nil, didDownload: downloaded)
        }

        let report: ScanReport
        let reporter: ScannerKit.ScanProgressReporter? = liveProgress ? CLIScanProgress(label: displayLabel) : nil
        do {
            report = try scanner.scanIndexed(ipa: ipaURL, progress: reporter,
                                             storeGenre: chart.category ?? store?.category,
                                             contentRating: job.contentRating).report
            if liveProgress { ProgressBar.clear() }
        } catch let e as ScannerError {
            if liveProgress { ProgressBar.clear() }
            if downloaded && !config.keepIPA { try? fm.removeItem(at: ipaURL) }
            if case .insufficientDiskSpace = e {
                return Processed(entry: base(name: chart.name).withError("aborting: \(e)"),
                                 report: nil, didDownload: downloaded, fatal: true)
            }
            return Processed(entry: base(name: chart.name).withError("scan failed: \(e)"),
                             report: nil, didDownload: downloaded)
        } catch {
            if liveProgress { ProgressBar.clear() }
            if downloaded && !config.keepIPA { try? fm.removeItem(at: ipaURL) }
            return Processed(entry: base(name: chart.name).withError("scan failed: \(error)"),
                             report: nil, didDownload: downloaded)
        }

        try? fm.createDirectory(at: appDir, withIntermediateDirectories: true)
        for fmt in config.perAppFormats {
            let dest = appDir.appendingPathComponent("report.\(fmt.fileExtension)")
            try? ReportExporter.write(report, format: fmt, to: dest,
                                      dashboardPath: "../../dashboard.html")
        }

        let size = (try? fm.attributesOfItem(atPath: ipaURL.path)[.size] as? UInt64) ?? nil
        if downloaded && !config.keepIPA { try? fm.removeItem(at: ipaURL) }

        let name = chart.name.isEmpty ? (report.metadata.displayName ?? report.metadata.bundleName) : chart.name
        let bid = chart.bundleID.isEmpty ? report.metadata.bundleID : chart.bundleID
        let paths = reportPaths(in: appDir, root: config.outputRoot, formats: config.perAppFormats)
        return Processed(entry: base(name: name, bundleID: bid).withScan(report, sizeBytes: size, reportPaths: paths),
                         report: report, didDownload: downloaded)
    }

    private static func downloadWithRetry(chart: ChartApp, into dir: URL, config: MassScanConfig) async throws -> URL {
        var attempt = 0
        while true {
            do {
                return try await IpatoolService.shared.download(
                    appID: chart.appID, bundleID: chart.bundleID, into: dir, platform: config.platform)
            } catch {
                attempt += 1
                if attempt > config.maxRetries || classify(error.localizedDescription) != .transient { throw error }
                let backoff = config.delaySeconds * pow(2.0, Double(attempt - 1))
                err("  retry \(attempt)/\(config.maxRetries) for \(chart.name) in \(Int(backoff))s (\(error.localizedDescription))")
                try? await Task.sleep(nanoseconds: UInt64(backoff * 1_000_000_000))
            }
        }
    }

    enum ErrClass { case transient, availability, other }
    static func classify(_ message: String) -> ErrClass {
        let m = message.lowercased()
        for k in ["too many", "rate limit", "timeout", "timed out", "try again",
                  "temporarily unavailable due to", "network", "connection reset",
                  "could not connect", "eof", "503", "502"] where m.contains(k) { return .transient }
        for k in ["not available", "unavailable", "not found", "purchase", "license",
                  "not eligible", "price", "region", "country", "storefront"] where m.contains(k) { return .availability }
        return .other
    }

    private static func vendorECharts(into dir: URL) async {
        let fm = FileManager.default
        let dest = dir.appendingPathComponent("echarts.min.js")
        if fm.fileExists(atPath: dest.path) { return }

        let cacheDir = (try? fm.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                    appropriateFor: nil, create: true))?
            .appendingPathComponent("ISAT", isDirectory: true)
        let cache = cacheDir?.appendingPathComponent("echarts.min.js")
        if let cache, fm.fileExists(atPath: cache.path) {
            try? fm.copyItem(at: cache, to: dest); return
        }
        guard let url = URL(string: "https://cdn.jsdelivr.net/npm/echarts@5.5.0/dist/echarts.min.js") else { return }
        do {
            let (data, resp) = try await URLSession.shared.data(from: url)
            let ok = (resp as? HTTPURLResponse).map { (200...299).contains($0.statusCode) } ?? false
            guard ok, data.count > 100_000 else { return }
            try data.write(to: dest, options: .atomic)
            if let cacheDir, let cache {
                try? fm.createDirectory(at: cacheDir, withIntermediateDirectories: true)
                try? data.write(to: cache, options: .atomic)
            }
            err("vendored echarts.min.js (\(data.count / 1024) KB) for offline viewing")
        } catch {
            err("note: couldn't vendor echarts.min.js (\(error.localizedDescription)); dashboard will use the CDN")
        }
    }

    private static func resolveJobs(_ config: MassScanConfig) async throws -> [Job] {
        if let dir = config.scanOnlyDir {
            let urls = (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil))?
                .filter { $0.pathExtension.lowercased() == "ipa" }
                .sorted { $0.lastPathComponent < $1.lastPathComponent } ?? []
            let known = loadStoreMetadata(config.storeMetadata)
            return urls.map { url in
                let stem = url.deletingPathExtension().lastPathComponent
                let appID = Int64(stem.split(separator: "_").first.map(String.init) ?? "") ?? 0
                let chart = ChartApp(appID: appID, bundleID: "", name: "",
                                     artist: nil, category: nil, genreID: nil, rank: 0)
                return Job(chart: chart, localIPA: url, store: known[stem])
            }
        }
        let apps = try await TopChartsService.fetchTop(
            country: config.country, feed: config.feed, genre: config.genre,
            kind: config.kind, limit: config.top)
        return apps.map { Job(chart: $0, localIPA: nil) }
    }

    static func loadStoreMetadata(_ url: URL?) -> [String: MassScanAppEntry] {
        guard let url else { return [:] }
        let dec = JSONDecoder(); dec.dateDecodingStrategy = .iso8601
        guard let data = try? Data(contentsOf: url),
              let report = try? dec.decode(MassScanReport.self, from: data) else {
            err("warning: could not read --store-metadata \(url.path); continuing without it")
            return [:]
        }
        var out: [String: MassScanAppEntry] = [:]
        for a in report.apps where !a.bundleID.isEmpty && out[a.bundleID] == nil { out[a.bundleID] = a }
        err("store metadata: \(out.count) app(s) from \(url.lastPathComponent)")
        return out
    }

    private static func reportPaths(in appDir: URL, root: URL, formats: [ReportExporter.Format]) -> [String: String] {
        var out: [String: String] = [:]
        let prefix = root.path.hasSuffix("/") ? root.path : root.path + "/"
        for f in formats {
            let p = appDir.appendingPathComponent("report.\(f.fileExtension)").path
            out[f.rawValue] = p.hasPrefix(prefix) ? String(p.dropFirst(prefix.count)) : p
        }
        return out
    }

    private static func byteSizeStr(_ bytes: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
    }

    private static func existingIPA(bundleID: String, in dir: URL, fm: FileManager) -> URL? {
        let b = bundleID.trimmingCharacters(in: .whitespaces)
        guard !b.isEmpty else { return nil }
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: ".-_"))
        let safe = String(b.unicodeScalars.map { allowed.contains($0) ? Character($0) : "_" })
        let url = dir.appendingPathComponent("\(safe).ipa")
        return fm.fileExists(atPath: url.path) ? url : nil
    }

    private static func sanitize(_ s: String) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-._"))
        let mapped = String(s.unicodeScalars.map { allowed.contains($0) ? Character($0) : "-" })
        return String(mapped.prefix(60)).trimmingCharacters(in: CharacterSet(charactersIn: "-"))
    }

    private static func monitorDownload(label: String, dir: URL, appID: Int64, total: UInt64?) async {
        let fm = FileManager.default
        let marker = "_\(appID)_"
        while !Task.isCancelled {
            if let files = try? fm.contentsOfDirectory(atPath: dir.path),
               let tmp = files.first(where: { $0.hasSuffix(".tmp") && $0.contains(marker) })
                    ?? files.first(where: { $0.hasSuffix(".ipa.tmp") }),
               let size = (try? fm.attributesOfItem(atPath: dir.appendingPathComponent(tmp).path)[.size]) as? Int64 {
                if let total, total > 0 {
                    let frac = min(0.99, Double(size) / Double(total))
                    ProgressBar.render("↓ " + label, fraction: frac,
                                       suffix: "\(byteSizeStr(UInt64(size))) / \(byteSizeStr(total))")
                } else {
                    ProgressBar.renderText("↓ " + label, suffix: "downloading… \(byteSizeStr(UInt64(size)))")
                }
            }
            try? await Task.sleep(nanoseconds: 400_000_000)
        }
    }

    private static func err(_ s: String) {
        FileHandle.standardError.write(Data((s + "\n").utf8))
    }
}

enum ProgressBar {
    private static let width = 22
    static func render(_ label: String, fraction: Double, suffix: String) {
        let f = max(0, min(1, fraction))
        let fill = Int(f * Double(width))
        let bar = String(repeating: "█", count: fill) + String(repeating: "░", count: width - fill)
        write(String(format: "  %@ [%@] %3.0f%%  %@", trim(label), bar, f * 100, suffix))
    }
    static func renderText(_ label: String, suffix: String) {
        write("  \(trim(label))  \(suffix)")
    }
    static func clear() { FileHandle.standardError.write(Data("\r\u{1B}[K".utf8)) }
    private static func write(_ s: String) { FileHandle.standardError.write(Data(("\r\u{1B}[K" + s).utf8)) }
    private static func trim(_ s: String) -> String { s.count > 30 ? String(s.prefix(29)) + "…" : s }
}

final class CLIScanProgress: ScannerKit.ScanProgressReporter, @unchecked Sendable {
    let label: String
    init(label: String) { self.label = label }
    func report(_ progress: ScannerKit.ScanProgress) {
        ProgressBar.render(label, fraction: progress.fraction, suffix: progress.phase)
    }
}

private extension Array {
    func chunked(into size: Int) -> [[Element]] {
        guard size > 0 else { return [self] }
        return stride(from: 0, to: count, by: size).map { Array(self[$0 ..< Swift.min($0 + size, count)]) }
    }
}
