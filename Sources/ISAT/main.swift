import Foundation
import ScannerKit
import AppKit
import SwiftUI

let args = CommandLine.arguments

let interruptSources: [DispatchSourceSignal] = [SIGINT, SIGTERM].map { sig in
    signal(sig, SIG_IGN)
    let src = DispatchSource.makeSignalSource(signal: sig, queue: .global())
    src.setEventHandler {
        let n = IPAExtractor.cleanupActive()
        if n > 0 { FileHandle.standardError.write(Data("\ninterrupted, cleaned \(n) temp extraction dir(s)\n".utf8)) }
        exit(130)
    }
    src.resume()
    return src
}
_ = interruptSources

func flagValue(_ name: String) -> String? {
    guard let i = args.firstIndex(of: name), i + 1 < args.count else { return nil }
    return args[i + 1]
}
func hasFlag(_ name: String) -> Bool { args.contains(name) }

func parseByteSize(_ raw: String) -> UInt64? {
    let s = raw.trimmingCharacters(in: .whitespaces).uppercased()
    guard !s.isEmpty else { return nil }
    let digits = s.prefix { $0.isNumber || $0 == "." }
    guard let value = Double(digits), value >= 0 else { return nil }
    let unit = s.dropFirst(digits.count).trimmingCharacters(in: .whitespaces)
    let mult: Double
    switch unit {
    case "", "B":        mult = 1
    case "K", "KB":      mult = 1_000
    case "M", "MB":      mult = 1_000_000
    case "G", "GB":      mult = 1_000_000_000
    case "T", "TB":      mult = 1_000_000_000_000
    default: return nil
    }
    return UInt64(value * mult)
}

func runAsync(timeoutSeconds: Int? = 600, _ body: @escaping @Sendable () async -> Void) {
    let sem = DispatchSemaphore(value: 0)
    Task { await body(); sem.signal() }
    guard let timeoutSeconds else { sem.wait(); return }
    if sem.wait(timeout: .now() + .seconds(timeoutSeconds)) == .timedOut {
        FileHandle.standardError.write(Data("timed out (a keychain prompt may be waiting; run the GUI once and click Allow)\n".utf8))
        exit(1)
    }
}

func guiPrompt(_ prompt: String, title: String = "ISAT sign-in", hidden: Bool = false) -> String? {
    let script = """
    try
      set r to display dialog "\(prompt)" default answer "" \(hidden ? "with hidden answer" : "") with title "\(title)" buttons {"Cancel", "OK"} default button "OK"
      return text returned of r
    on error number -128
      return "<<CANCELLED>>"
    end try
    """
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
    p.arguments = ["-e", script]
    let out = Pipe()
    p.standardOutput = out
    p.standardError = FileHandle.nullDevice
    do { try p.run() } catch { return nil }
    let data = out.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    let s = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
    return (s.isEmpty || s == "<<CANCELLED>>") ? nil : s
}

func stdinIsTTY() -> Bool { isatty(fileno(stdin)) != 0 }

func interactiveLogin(email: String, passwordSeed: String?, authSeed: String?, gui: Bool) async -> Bool {
    func ask(_ prompt: String, hidden: Bool) -> String? {
        if gui { return guiPrompt(prompt, hidden: hidden) }
        if hidden { return String(cString: getpass(prompt + " ")) }
        FileHandle.standardError.write(Data((prompt + " ").utf8)); return readLine()
    }
    let password = passwordSeed
        ?? ProcessInfo.processInfo.environment["ISAT_APPLE_ID_PASSWORD"]
        ?? ask("Apple ID password for \(email):", hidden: true) ?? ""
    guard !password.isEmpty else { FileHandle.standardError.write(Data("sign-in cancelled\n".utf8)); return false }
    do {
        var code = authSeed
        for attempt in 0..<2 {
            switch try await IpatoolService.shared.login(email: email, password: password, authCode: code) {
            case .success(let acc):
                FileHandle.standardError.write(Data("signed in as \(acc.name) <\(acc.email)>\n".utf8)); return true
            case .needsTwoFactor:
                guard attempt == 0, let c = ask("Two-factor code sent to your Apple devices:", hidden: false), !c.isEmpty else {
                    FileHandle.standardError.write(Data("2FA required, re-run with --auth-code <code>\n".utf8)); return false
                }
                code = c
            }
        }
    } catch {
        FileHandle.standardError.write(Data("login failed: \(error.localizedDescription)\n".utf8))
    }
    return false
}

let usage = """
ISAT: IPA Static Analysis Toolkit

USAGE
  ISAT                                     Launch the macOS app (no arguments)
  ISAT --help                              Show this help

SCAN & REPORT
  ISAT --scan <ipa>                        Scan and print the JSON report to stdout
  ISAT --report <fmt> <ipa> [out]          Export a report; fmt: json|md|markdown|html|sarif
  ISAT --sbom cyclonedx <ipa> [out]        Export a CycloneDX SBOM of detected SDKs/frameworks
  ISAT --diff <old.json> <new.json> [--json]  Longitudinal diff of two reports
  ISAT --time <ipa>                        Scan and print per-phase timing
  ISAT --canary <ipa>                      Probe a fixed list of high-signal indicators
  ISAT --index-stats <ipa>                 Print string/symbol index statistics
    --store-genre G    App Store genre for --scan / --report, e.g. "Kids"; not in the IPA, so
                       child-safety checks (TGAP-03) stay quiet without it
    --content-rating R App Store age rating, e.g. "4+". --massscan and --download resolve both
                       from the iTunes Lookup API

MASS-SCAN (top-N popular apps → batch scan → aggregate dashboard)
  ISAT --massscan [options]                Pull popular apps, scan each, build a dashboard
    --top N            number of apps (default 100)
    --feed F           top-free | top-paid (default top-free)
    --kind K           apps | games | all (default all)
    --max-size SIZE    skip apps larger than SIZE, e.g. 100MB, 1.5GB (default: no limit)
    --country CC       App Store storefront; must match your Apple ID region (default: your Mac's)
    --genre ID         restrict to one App Store genre ID (optional)
    --output DIR       output root (default ./massscan-<date>)
    --formats LIST     per-app report formats: json,html,md,sarif (default json)
    --dashboard LIST   dashboard formats: html,json,md (default html,json,md)
    --delay S          seconds between download batches (default 4)
    --concurrency N    parallel downloads/scans per batch (default 1)
    --max-retries N    download retry attempts with backoff (default 3)
    --rescan           re-scan even if a per-app report.json already exists (default: reuse it)
    --keep-ipa         keep downloaded .ipa files (default: delete after scan)
    --scan-only DIR    skip charts/download; aggregate a folder of existing .ipa files
    --store-metadata F with --scan-only: App Store identity (id, category, developer, chart
                       rank) from an earlier dashboard.json, matched by bundle ID. The category
                       also reaches the scanner, so the kids-category checks run on a rescan
    --dry-run          resolve and print the app list only (no download)
    --platform P       iphone | ipad | appletv (default iphone)
    --email/--password/--auth-code/--gui
                       sign in before the download run, as for --login
  ISAT --render-report <report.json|dir> [fmt]
                                           Render per-app report.html/.md/.sarif from saved
                                           report.json files (no re-scan); fmt default html
  ISAT --render-dashboard <dashboard.json> [out-dir] [--enrich-metadata] [--refresh-detail]
                                           Re-render dashboard.html + .md from an existing
                                           dashboard.json (no re-download or re-scan).
                                           --refresh-detail re-derives every app's drill-down
                                           detail from its report.json, for use after a re-scan.

RULES
  ISAT --rules-info                        List loaded detection rules by vector
  ISAT --update-rules <https-url>          Install a rule pack (YAML or .tar.gz) into Application Support
  ISAT --sources-report [--check [--file PATH]]
                                           Print the attribution table for THIRD_PARTY.md
                                           (--check exits 1 if the committed table is stale)

APP STORE (via the bundled ipatool helper)
  ISAT --login --email <e> [--password <p>] [--auth-code <c>] [--gui]
                                           Sign in (password from --password, $ISAT_APPLE_ID_PASSWORD,
                                           or a prompt). --gui pops native macOS dialogs for the
                                           password + 2FA code (also used automatically with no TTY).
                                           --massscan accepts the same --email/--password/--gui to
                                           sign in before a download run.
  ISAT --account-info                      Show the signed-in Apple ID, if any
  ISAT --logout                            Revoke the stored App Store session
  ISAT --search <term> [--limit N] [--platform iphone|ipad|appletv]
                                           Search the App Store (requires login). --appstore-search
                                           is an accepted alias
  ISAT --download <appID|bundleID> [--output <dir>] [--platform ...] [--scan]
                                           Download an app's .ipa (acquires a free license if needed);
                                           --scan also runs a static scan and prints the JSON report
"""

let storeGenreArg = flagValue("--store-genre")
let contentRatingArg = flagValue("--content-rating")

if args.count >= 2, args[1] == "--help" || args[1] == "-h" {
    print(usage)
    exit(0)
}

if args.count >= 3, args[1] == "--scan" {
    let url = URL(fileURLWithPath: args[2])
    do {
        let report = try ScannerKit.Scanner().scanIndexed(ipa: url, storeGenre: storeGenreArg,
                                                          contentRating: contentRatingArg).report
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        enc.dateEncodingStrategy = .iso8601
        let data = try enc.encode(report)
        FileHandle.standardOutput.write(data)
        exit(0)
    } catch {
        FileHandle.standardError.write(Data("Scan failed: \(error)\n".utf8))
        exit(1)
    }
}

if args.count >= 4, args[1] == "--sbom" {
    let fmt = args[2].lowercased()
    guard fmt == "cyclonedx" || fmt == "cdx" else {
        FileHandle.standardError.write(Data("Unknown SBOM format '\(args[2])'. Supported: cyclonedx\n".utf8)); exit(1)
    }
    let url = URL(fileURLWithPath: args[3])
    do {
        let report = try ScannerKit.Scanner().scanIndexed(ipa: url).report
        let data = try ScannerKit.CycloneDXExporter.data(report)
        if args.count >= 5, !args[4].hasPrefix("--") {
            try data.write(to: URL(fileURLWithPath: args[4]))
            print("Wrote CycloneDX SBOM (\(report.network.detectedSDKs.count) SDKs) to \(args[4])")
        } else {
            FileHandle.standardOutput.write(data)
        }
        exit(0)
    } catch {
        FileHandle.standardError.write(Data("SBOM failed: \(error)\n".utf8)); exit(1)
    }
}

if args.count >= 4, args[1] == "--diff" {
    let dec = JSONDecoder(); dec.dateDecodingStrategy = .iso8601
    do {
        let oldR = try dec.decode(ScannerKit.ScanReport.self, from: Data(contentsOf: URL(fileURLWithPath: args[2])))
        let newR = try dec.decode(ScannerKit.ScanReport.self, from: Data(contentsOf: URL(fileURLWithPath: args[3])))
        let d = ScannerKit.ReportDiff.compute(old: oldR, new: newR)
        if args.contains("--json") {
            let enc = JSONEncoder(); enc.outputFormatting = [.prettyPrinted, .sortedKeys]
            FileHandle.standardOutput.write(try enc.encode(d))
        } else {
            print(ScannerKit.ReportDiff.render(d))
        }
        exit(0)
    } catch {
        FileHandle.standardError.write(Data("Diff failed: \(error)\n".utf8)); exit(1)
    }
}

if args.count >= 3, args[1] == "--search" || args[1] == "--appstore-search" {
    let term = args[2]
    let limit = flagValue("--limit").flatMap { Int($0) } ?? 10
    let platform = flagValue("--platform") ?? "iphone"
    runAsync {
        do {
            let apps = try await IpatoolService.shared.search(term: term, limit: limit, platform: platform)
            for a in apps { print("\(a.id)\t\(a.bundleID)\t\(a.name)\tv\(a.version)") }
        } catch {
            FileHandle.standardError.write(Data("search failed: \(error.localizedDescription)\n".utf8))
        }
    }
    exit(0)
}

if args.count >= 2, args[1] == "--account-info" {
    runAsync {
        if let acc = try? await IpatoolService.shared.accountInfo() {
            print("\(acc.name) <\(acc.email)>")
        } else {
            FileHandle.standardError.write(Data("not signed in\n".utf8))
        }
    }
    exit(0)
}

if args.count >= 2, args[1] == "--logout" {
    runAsync {
        do { try await IpatoolService.shared.revoke(); print("signed out") }
        catch { FileHandle.standardError.write(Data("logout failed: \(error.localizedDescription)\n".utf8)) }
    }
    exit(0)
}

if args.count >= 2, args[1] == "--login" {
    guard let email = flagValue("--email") else {
        FileHandle.standardError.write(Data("--login requires --email <address>\n".utf8)); exit(1)
    }
    let gui = hasFlag("--gui") || !stdinIsTTY()
    runAsync {
        let ok = await interactiveLogin(email: email, passwordSeed: flagValue("--password"),
                                        authSeed: flagValue("--auth-code"), gui: gui)
        if !ok { exit(1) }
    }
    exit(0)
}

if args.count >= 3, args[1] == "--download" {
    let ident = args[2]
    let appID = Int64(ident)
    let bundleID = appID == nil ? ident : ""
    let platform = flagValue("--platform")
    let outDir: URL = flagValue("--output").map { URL(fileURLWithPath: $0, isDirectory: true) }
        ?? URL(fileURLWithPath: FileManager.default.currentDirectoryPath).appendingPathComponent("ipas", isDirectory: true)
    try? FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)
    let alsoScan = hasFlag("--scan")
    runAsync {
        do {
            let cc = Locale.current.region?.identifier.lowercased() ?? "us"
            var bid = bundleID
            if bid.isEmpty, let appID {
                bid = await TopChartsService.lookupBundleID(appID: appID, country: cc) ?? ""
            }
            let url = try await IpatoolService.shared.download(appID: appID, bundleID: bid,
                                                              into: outDir, platform: platform)
            FileHandle.standardError.write(Data("downloaded \(url.path)\n".utf8))
            if alsoScan {
                var rating = contentRatingArg
                if rating == nil, let appID {
                    rating = await TopChartsService.lookupDetails(appID: appID, country: cc)?.contentRating
                }
                let report = try ScannerKit.Scanner().scanIndexed(ipa: url, storeGenre: storeGenreArg,
                                                                  contentRating: rating).report
                let enc = JSONEncoder()
                enc.outputFormatting = [.prettyPrinted, .sortedKeys]
                enc.dateEncodingStrategy = .iso8601
                FileHandle.standardOutput.write(try enc.encode(report))
            } else {
                print(url.path)
            }
        } catch {
            FileHandle.standardError.write(Data("download failed: \(error.localizedDescription)\n".utf8))
        }
    }
    exit(0)
}

if args.count >= 3, args[1] == "--time" {
    let url = URL(fileURLWithPath: args[2])
    final class StageReporter: ScannerKit.ScanProgressReporter, @unchecked Sendable {
        var stamps: [(String, Date)] = []
        let lock = NSLock()
        func report(_ progress: ScannerKit.ScanProgress) {
            lock.lock(); stamps.append((progress.phase, Date())); lock.unlock()
        }
    }
    let rep = StageReporter()
    let t0 = Date()
    do {
        let _ = try ScannerKit.Scanner().scanIndexed(ipa: url, progress: rep)
        rep.stamps.append(("end", Date()))
        var prev = t0
        for (label, t) in rep.stamps {
            print(String(format: "  +%.2fs  %@", t.timeIntervalSince(prev), label))
            prev = t
        }
        print(String(format: "  total %.2fs", Date().timeIntervalSince(t0)))
        exit(0)
    } catch {
        FileHandle.standardError.write(Data("Timed scan failed: \(error)\n".utf8))
        exit(1)
    }
}

if args.count >= 3, args[1] == "--render-report" {
    let src = URL(fileURLWithPath: args[2])
    let fmtArg = args.count >= 4 ? args[3] : "html"
    let formats = fmtArg.split(separator: ",").compactMap { ReportExporter.Format(argument: String($0)) }
    guard !formats.isEmpty else {
        FileHandle.standardError.write(Data(
            "Unknown format '\(fmtArg)'. Use \(ReportExporter.Format.argumentNames).\n".utf8))
        exit(2)
    }

    var sources: [URL] = []
    var isDir: ObjCBool = false
    if FileManager.default.fileExists(atPath: src.path, isDirectory: &isDir), isDir.boolValue {
        let e = FileManager.default.enumerator(at: src, includingPropertiesForKeys: nil)
        while let u = e?.nextObject() as? URL {
            if u.lastPathComponent == "report.json" { sources.append(u) }
        }
        sources.sort { $0.path < $1.path }
    } else {
        sources = [src]
    }
    guard !sources.isEmpty else {
        FileHandle.standardError.write(Data("No report.json found under \(src.path)\n".utf8))
        exit(1)
    }

    let dec = JSONDecoder()
    dec.dateDecodingStrategy = .iso8601
    var written = 0, failed = 0
    for url in sources {
        do {
            let report = try dec.decode(ScanReport.self, from: Data(contentsOf: url))
            let appDir = url.deletingLastPathComponent()
            let dash = appDir.deletingLastPathComponent().deletingLastPathComponent()
                .appendingPathComponent("dashboard.html")
            let backLink = FileManager.default.fileExists(atPath: dash.path) ? "../../dashboard.html" : nil
            for fmt in formats {
                let dest = appDir
                    .appendingPathComponent("report.\(fmt.rawValue == "markdown" ? "md" : fmt.rawValue)")
                try ReportExporter.write(report, format: fmt, to: dest, dashboardPath: backLink)
                written += 1
            }
        } catch {
            failed += 1
            FileHandle.standardError.write(Data("! \(url.path): \(error.localizedDescription)\n".utf8))
        }
    }
    FileHandle.standardError.write(Data("Rendered \(written) file(s) from \(sources.count) report(s), \(failed) failed\n".utf8))
    exit(failed == 0 ? 0 : 1)
}


func enrichStoreMetadata(_ apps: [MassScanAppEntry], country: String) -> [MassScanAppEntry] {
    let fm = FileManager.default
    let cacheDir = (try? fm.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                appropriateFor: nil, create: true))?.appendingPathComponent("ISAT")
    let cacheURL = cacheDir?.appendingPathComponent("store-meta-\(country.lowercased()).json")

    struct Cached: Codable { var appID: Int64; var category: String?; var artist: String? }
    var cache: [String: Cached] = [:]
    if let u = cacheURL, let d = try? Data(contentsOf: u),
       let c = try? JSONDecoder().decode([String: Cached].self, from: d) { cache = c }

    let needed = apps.filter { $0.category == nil || $0.appID == 0 }
        .map(\.bundleID).filter { !$0.isEmpty && cache[$0] == nil }
    if !needed.isEmpty {
        FileHandle.standardError.write(Data("Looking up App Store metadata for \(needed.count) bundle ID(s)…\n".utf8))
        let found = runBlocking { await TopChartsService.lookupByBundleIDs(needed, country: country) }
        for (bid, id) in found {
            cache[bid] = Cached(appID: id.appID, category: id.category, artist: id.artist)
        }
        FileHandle.standardError.write(Data("Resolved \(found.count) of \(needed.count)\n".utf8))
        if let u = cacheURL, let d = try? JSONEncoder().encode(cache) {
            try? d.write(to: u, options: .atomic)
        }
    }
    guard !cache.isEmpty else { return apps }

    var filled = 0
    let out = apps.map { app -> MassScanAppEntry in
        guard let c = cache[app.bundleID] else { return app }
        guard app.category == nil || app.appID == 0 else { return app }
        filled += 1
        return app.withStoreMetadata(appID: c.appID == 0 ? nil : c.appID,
                                     category: c.category, artist: c.artist)
    }
    FileHandle.standardError.write(Data("Enriched \(filled) app(s) with App Store metadata\n".utf8))
    return out
}

func runBlocking<T: Sendable>(_ body: @escaping @Sendable () async -> T) -> T {
    let sem = DispatchSemaphore(value: 0)
    nonisolated(unsafe) var result: T?
    Task { result = await body(); sem.signal() }
    sem.wait()
    return result!
}

if args.count >= 3, args[1] == "--render-dashboard" {
    let enrichMetadata = args.contains("--enrich-metadata")
    let positional = args.dropFirst(3).filter { !$0.hasPrefix("--") }
    let src = URL(fileURLWithPath: args[2])
    let outDir = URL(fileURLWithPath: positional.first ?? src.deletingLastPathComponent().path,
                     isDirectory: true)
    do {
        let data = try Data(contentsOf: src)
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        var report = try dec.decode(MassScanReport.self, from: data)

        let root = src.deletingLastPathComponent()
        let refreshDetail = hasFlag("--refresh-detail")
        var enriched = 0
        var apps = report.apps.map { app -> MassScanAppEntry in
            guard refreshDetail || app.details == nil,
                  app.ok, let rel = app.reportPaths["json"] else { return app }
            let url = root.appendingPathComponent(rel)
            guard let d = try? Data(contentsOf: url),
                  let scan = try? dec.decode(ScanReport.self, from: d) else { return app }
            var copy = app
            copy.details = AppCompareDetail.from(scan)
            enriched += 1
            return copy
        }
        if enrichMetadata {
            apps = enrichStoreMetadata(apps, country: report.run.country)
        }
        report = MassScanReport(run: report.run, apps: apps, stats: report.stats).rederivedFromDetail()
        if enriched > 0 { FileHandle.standardError.write(Data("Enriched \(enriched) app(s) with drill-down detail\n".utf8)) }
        FileHandle.standardError.write(Data("Recomputed cluster rollups for \(report.apps.filter(\.ok).count) app(s) from their embedded detail\n".utf8))

        do {
            let enc = JSONEncoder()
            enc.dateEncodingStrategy = .iso8601
            enc.outputFormatting = [.prettyPrinted, .sortedKeys]
            let jsonDest = outDir.appendingPathComponent("dashboard.json")
            try enc.encode(report).write(to: jsonDest, options: .atomic)
            FileHandle.standardError.write(Data("Wrote dashboard.json to \(jsonDest.path)\n".utf8))
        }

        let fm = FileManager.default
        var echarts: String? = nil
        let localJS = root.appendingPathComponent("echarts.min.js")
        let cacheJS = (try? fm.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: false))?
            .appendingPathComponent("ISAT/echarts.min.js")
        for cand in [localJS, cacheJS].compactMap({ $0 }) where fm.fileExists(atPath: cand.path) {
            echarts = try? String(contentsOf: cand, encoding: .utf8)
            if echarts != nil { break }
        }
        FileHandle.standardError.write(Data((echarts != nil ? "Inlining echarts.min.js → self-contained HTML\n" : "No echarts.min.js found; HTML will load it externally\n").utf8))

        let mdDest = outDir.appendingPathComponent("dashboard.md")
        let md = try MassScanDashboardExporter.export(report, format: .markdown)
        try md.write(to: mdDest, options: .atomic)
        FileHandle.standardError.write(Data("Wrote \(md.count) bytes to \(mdDest.path)\n".utf8))
        let htmlDest = outDir.appendingPathComponent("dashboard.html")
        let htmlData = Data(MassScanDashboardExporter.html(report, inlineECharts: echarts, assetRoot: outDir).utf8)
        try htmlData.write(to: htmlDest, options: .atomic)
        FileHandle.standardError.write(Data("Wrote \(htmlData.count) bytes to \(htmlDest.path)\n".utf8))
        exit(0)
    } catch {
        FileHandle.standardError.write(Data("Render failed: \(error)\n".utf8))
        exit(1)
    }
}

if args.count >= 4, args[1] == "--report" {
    let fmtArg = args[2].lowercased()
    let format: ReportExporter.Format = {
        if let f = ReportExporter.Format(argument: fmtArg) { return f }
        FileHandle.standardError.write(Data(
            "unknown format '\(fmtArg)'; expected \(ReportExporter.Format.argumentNames)\n".utf8))
        exit(2)
    }()
    let url = URL(fileURLWithPath: args[3])
    do {
        let report = try ScannerKit.Scanner().scanIndexed(ipa: url, storeGenre: storeGenreArg,
                                                          contentRating: contentRatingArg).report
        let data = try ReportExporter.export(report, format: format)
        if args.count >= 5, !args[4].hasPrefix("--") {
            try data.write(to: URL(fileURLWithPath: args[4]), options: .atomic)
            FileHandle.standardError.write(Data("Wrote \(data.count) bytes to \(args[4])\n".utf8))
        } else {
            FileHandle.standardOutput.write(data)
        }
        exit(0)
    } catch {
        FileHandle.standardError.write(Data("Report failed: \(error)\n".utf8))
        exit(1)
    }
}

if args.count >= 2, args[1] == "--update-rules" {
    guard args.count >= 3 else {
        FileHandle.standardError.write(Data("usage: ISAT --update-rules <https-url>\n".utf8)); exit(2)
    }
    let src = args[2]
    guard let url = URL(string: src), url.scheme?.lowercased() == "https" else {
        FileHandle.standardError.write(Data("Rule packs are only fetched over https: \(src)\n".utf8)); exit(1)
    }
    do {
        let dest = try RuleUpdater.downloadAndInstall(from: url)
        print("Installed rule pack at: \(dest.path)")
        let pack = RuleLoader.loadFromDirectory(dest) ?? RuleLoader.loadBundled()
        print("Loaded \(pack.rules.count) rules (\(pack.loadErrors.count) errors)")
        exit(0)
    } catch {
        FileHandle.standardError.write(Data("Rule update failed: \(error)\n".utf8))
        exit(1)
    }
}

if args.count >= 2, args[1] == "--sources-report" {
    let report = ScannerKit.SourceRegistry.bundledMarkdownReport()
    if hasFlag("--check") {
        let path = flagValue("--file") ?? "THIRD_PARTY.md"
        guard let existing = try? String(contentsOfFile: path, encoding: .utf8) else {
            FileHandle.standardError.write(Data("cannot read \(path)\n".utf8)); exit(1)
        }
        let begin = "<!-- BEGIN GENERATED SOURCES -->"
        let end = "<!-- END GENERATED SOURCES -->"
        guard let b = existing.range(of: begin), let e = existing.range(of: end) else {
            FileHandle.standardError.write(Data("\(path) has no generated-sources block\n".utf8)); exit(1)
        }
        let current = String(existing[b.lowerBound..<e.upperBound]) + "\n"
        if current == report { print("THIRD_PARTY.md sources table is up to date."); exit(0) }
        FileHandle.standardError.write(Data("THIRD_PARTY.md sources table is stale; run ISAT --sources-report\n".utf8))
        exit(1)
    }
    print(report, terminator: "")
    exit(0)
}

if args.count >= 2, args[1] == "--rules-info" {
    let pack = ScannerKit.RuleLoader.loadBundled()
    let fw = ScannerKit.FrameworkVersions.current
    print("Loaded \(pack.rules.count) rules; \(pack.loadErrors.count) load errors.")
    for e in pack.loadErrors { print("  ERR: \(e)") }
    print("Frameworks: MASVS \(fw.masvs) · MASTG \(fw.mastg) · MASWE \(fw.maswe) · ATT&CK Mobile \(fw.attackMobile) · CVSS \(fw.cvss)")
    print("Crosswalk coverage: \(ScannerKit.FrameworkCrosswalk.implementedMASTGTests.count) MASTG tests, "
          + "\(ScannerKit.FrameworkCrosswalk.implementedMASWEWeaknesses.count) MASWE weaknesses bound.")
    let byVec = Dictionary(grouping: pack.rules, by: { $0.vector })
    for construct in ScannerKit.Construct.allCases {
        let vecs = (ScannerKit.Vectors.byConstruct[construct] ?? []).sorted { $0.id < $1.id }
        print("\n\(construct.rawValue), \(construct.title)")
        for v in vecs {
            let cw = ScannerKit.FrameworkCrosswalk.for(vectorID: v.id)
            let tags = (cw.maswe + cw.mastg).joined(separator: ",")
            print("  \(v.id)  \(v.title) , \(byVec[v.id]?.count ?? 0) YAML rules  [\(tags)]")
            for r in (byVec[v.id] ?? []).prefix(5) {
                print("      - \(r.id)  [\(r.severity.rawValue)]  \(r.title)")
            }
        }
    }
    exit(0)
}

if args.count >= 3, args[1] == "--canary" {
    let url = URL(fileURLWithPath: args[2])
    let canaries: [(label: String, pattern: String)] = [
        ("Frida port 27042", "27042"),
        ("utun interface", "utun"),
        ("CydiaSubstrate", "CydiaSubstrate"),
        ("AppMetrica", "AppMetrica"),
        ("MyTracker", "MyTracker"),
        ("Group-IB SDK", "group_ib"),
        ("NEVPNManager", "NEVPNManager"),
        ("getifaddrs", "getifaddrs"),
        ("ipify (VPN-check)", "ipify"),
        ("sysctlbyname", "sysctlbyname"),
        ("PT_DENY_ATTACH", "PT_DENY_ATTACH"),
        ("isJailbroken", "isJailbroken"),
        ("CoreMotion", "CMMotionManager"),
        ("UIPasteboard", "UIPasteboard"),
        ("Cydia URL scheme", "cydia://"),
        ("hw.machine sysctl", "hw.machine"),
        ("CLLocationManager", "CLLocationManager"),
        ("AVCaptureSession", "AVCaptureSession"),
        ("AVAudioRecorder", "AVAudioRecorder"),
        ("UITouch / forceTouch", "forceTouch"),
        ("BGTaskScheduler", "BGTaskScheduler"),
        ("dyld_image_count", "dyld_image_count"),
        ("ptrace", "ptrace"),
        ("frida-server", "frida"),
        ("Sentry crash SDK", "SentryCrash"),
        ("Firebase Analytics", "FIRAnalytics"),
        ("AppsFlyer", "AppsFlyer"),
    ]
    do {
        let r = try ScannerKit.Scanner().scanIndexed(ipa: url)
        print("=== \(r.report.metadata.bundleID)  v\(r.report.metadata.shortVersion ?? "?") ===")
        for (label, pat) in canaries {
            let needle = pat.lowercased()
            var hits: [(String, String)] = []
            outer: for (path, bi) in r.indices.sorted(by: { $0.key < $1.key }) {
                for ss in bi.perSectionStrings {
                    for s in ss.strings where s.value.lowercased().contains(needle) {
                        hits.append((URL(fileURLWithPath: path).lastPathComponent, s.value))
                        if hits.count >= 3 { break outer }
                    }
                }
                for sym in bi.importedSymbols where sym.lowercased().contains(needle) {
                    hits.append((URL(fileURLWithPath: path).lastPathComponent, "imp:" + sym))
                    if hits.count >= 3 { break outer }
                }
                for sym in bi.definedSymbols where sym.lowercased().contains(needle) {
                    hits.append((URL(fileURLWithPath: path).lastPathComponent, "def:" + sym))
                    if hits.count >= 3 { break outer }
                }
            }
            if hits.isEmpty {
                print("  [    ] \(label)")
            } else {
                print("  [HIT ] \(label)")
                for h in hits.prefix(3) {
                    let v = h.1.count > 90 ? String(h.1.prefix(90)) + "…" : h.1
                    print("        \(h.0)  ·  \(v)")
                }
            }
        }
        exit(0)
    } catch {
        FileHandle.standardError.write(Data("Canary scan failed: \(error)\n".utf8))
        exit(1)
    }
}

if args.count >= 3, args[1] == "--index-stats" {
    let url = URL(fileURLWithPath: args[2])
    do {
        let indexed = try ScannerKit.Scanner().scanIndexed(ipa: url)
        let r = indexed.report
        print("=== \(r.metadata.bundleID)  v\(r.metadata.shortVersion ?? "?")  \(r.findings.count) findings ===")
        print("scan: \(String(format: "%.2f", r.scanDurationSeconds))s · \(indexed.indices.count) binaries indexed")
        let totalStrings = indexed.indices.values.reduce(0) { $0 + $1.totalStrings }
        let totalImports = indexed.indices.values.reduce(0) { $0 + $1.importedSymbols.count }
        let totalDefined = indexed.indices.values.reduce(0) { $0 + $1.definedSymbols.count }
        let totalEncSkipped = indexed.indices.values.reduce(0) { $0 + $1.encryptedSectionsSkipped.count }
        print("total: \(totalStrings) strings · \(totalImports) imported / \(totalDefined) defined symbols · \(totalEncSkipped) sections skipped (FairPlay)")
        let sorted = indexed.indices.values.sorted { $0.totalStrings > $1.totalStrings }
        print("\ntop 10 binaries by string count:")
        for bi in sorted.prefix(10) {
            let main = bi.isMainExecutable ? "*" : " "
            print("  \(main) \(String(format: "%7d", bi.totalStrings)) strings · " +
                  "\(String(format: "%4d", bi.importedSymbols.count)) imp · " +
                  "\(String(format: "%4d", bi.definedSymbols.count)) def · \(bi.relativePath)")
        }
        if let probe = sorted.first {
            print("\nsection breakdown for \(URL(fileURLWithPath: probe.relativePath).lastPathComponent):")
            for ss in probe.perSectionStrings.sorted(by: { $0.strings.count > $1.strings.count }).prefix(10) {
                let pad = ss.section.qualifiedName.padding(toLength: 42, withPad: " ", startingAt: 0)
                print("  \(pad) \(String(format: "%6d", ss.strings.count)) strings")
            }
            print("\n  skipped (FairPlay) sections in this binary: \(probe.encryptedSectionsSkipped.count)")
            for s in probe.encryptedSectionsSkipped.prefix(5) {
                print("    - \(s.qualifiedName)  size=\(s.size)")
            }
        }
        exit(0)
    } catch {
        FileHandle.standardError.write(Data("Indexed scan failed: \(error)\n".utf8))
        exit(1)
    }
}

if args.count >= 2, args[1] == "--massscan" {
    let perApp: [ReportExporter.Format] = (flagValue("--formats")?
        .split(separator: ",").compactMap { ReportExporter.Format(argument: String($0)) })
        .flatMap { $0.isEmpty ? nil : $0 } ?? [.json]
    let dashboard: [MassScanDashboardExporter.Format] = (flagValue("--dashboard")?
        .split(separator: ",").compactMap { MassScanDashboardExporter.format(for: String($0)) })
        .flatMap { $0.isEmpty ? nil : $0 } ?? [.html, .json, .markdown]

    let stamp: String = {
        let f = DateFormatter()
        f.dateFormat = "yyyyMMdd-HHmmss"
        return f.string(from: Date())
    }()
    let defaultOut = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        .appendingPathComponent("massscan-\(stamp)", isDirectory: true)
    let outputRoot = flagValue("--output").map { URL(fileURLWithPath: $0, isDirectory: true) } ?? defaultOut
    try? FileManager.default.createDirectory(at: outputRoot, withIntermediateDirectories: true)

    var config = MassScanConfig(outputRoot: outputRoot)
    config.top = flagValue("--top").flatMap { Int($0) } ?? 100
    config.feed = flagValue("--feed") ?? "top-free"
    config.kind = (flagValue("--kind") ?? "all").lowercased()
    let defaultCountry = Locale.current.region?.identifier.lowercased() ?? "us"
    if let sizeArg = flagValue("--max-size") {
        guard let bytes = parseByteSize(sizeArg) else {
            FileHandle.standardError.write(Data("bad --max-size '\(sizeArg)' (try 100MB, 1.5GB)\n".utf8)); exit(1)
        }
        config.maxSizeBytes = bytes
    }
    config.country = (flagValue("--country") ?? defaultCountry).lowercased()
    config.genre = flagValue("--genre").flatMap { Int($0) }
    config.perAppFormats = perApp
    config.dashboardFormats = dashboard
    config.delaySeconds = flagValue("--delay").flatMap { Double($0) } ?? 4
    config.concurrency = max(1, flagValue("--concurrency").flatMap { Int($0) } ?? 1)
    config.maxRetries = flagValue("--max-retries").flatMap { Int($0) } ?? 3
    config.rescan = hasFlag("--rescan")
    config.keepIPA = hasFlag("--keep-ipa")
    config.platform = flagValue("--platform")
    config.scanOnlyDir = flagValue("--scan-only").map { URL(fileURLWithPath: $0, isDirectory: true) }
    config.storeMetadata = flagValue("--store-metadata").map { URL(fileURLWithPath: $0) }
    config.dryRun = hasFlag("--dry-run")

    let finalConfig = config
    let loginEmail = (finalConfig.scanOnlyDir == nil && !finalConfig.dryRun) ? flagValue("--email") : nil
    let loginGUI = hasFlag("--gui") || !stdinIsTTY()
    runAsync(timeoutSeconds: nil) {
        if let loginEmail {
            let already = (try? await IpatoolService.shared.accountInfo()) ?? nil
            if already == nil {
                _ = await interactiveLogin(email: loginEmail, passwordSeed: flagValue("--password"),
                                           authSeed: flagValue("--auth-code"), gui: loginGUI)
            }
        }
        await MassScanRunner.run(finalConfig)
    }
    exit(0)
}

ISATApp.main()
