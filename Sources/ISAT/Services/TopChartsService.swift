import Foundation

struct ChartApp: Sendable, Hashable, Identifiable {
    var id: Int64 { appID }
    let appID: Int64
    let bundleID: String
    let name: String
    let artist: String?
    let category: String?
    let genreID: Int?
    let rank: Int

    var isGame: Bool {
        if genreID == 6014 { return true }
        if let g = genreID, (7000...7999).contains(g) { return true }
        return (category?.lowercased() == "games")
    }
}

enum TopChartsError: LocalizedError {
    case badResponse(Int)
    case noApps
    var errorDescription: String? {
        switch self {
        case .badResponse(let c): return "Apple charts feed returned HTTP \(c)."
        case .noApps: return "The charts feed returned no apps."
        }
    }
}

enum TopChartsService {

    static let genreIDs: [Int] = [
        6014,
        6005,
        6008,
        6007,
        6002,
        6015,
        6024,
        6016,
        6012,
        6013,
        6023,
        6009,
        6011,
        6010,
        6004,
        6003,
        6006,
        6017,
        6000,
        6020,
        6008, 6018,
        6001,
    ]

    static let gameSubgenreIDs: [Int] = Array(7001...7019)

    static func fetchTop(country: String, feed: String, genre: Int?, kind: String, limit: Int) async throws -> [ChartApp] {
        let feedPath = (feed == "top-paid") ? "toppaidapplications" : "topfreeapplications"
        let feedLimit = min(200, max(1, limit))
        func keep(_ a: ChartApp) -> Bool {
            switch kind {
            case "games": return a.isGame
            case "apps":  return !a.isGame
            default:      return true
            }
        }

        var merged: [ChartApp] = []
        var seen = Set<Int64>()
        func absorb(_ apps: [ChartApp]) {
            for a in apps where keep(a) && seen.insert(a.appID).inserted { merged.append(a) }
        }

        if let genre {
            absorb(try await fetchFeed(country: country, feedPath: feedPath, genre: genre, limit: feedLimit))
            return rerank(Array(merged.prefix(limit)))
        }

        let fanout: [Int]
        if kind == "games" {
            absorb(try await fetchFeed(country: country, feedPath: feedPath, genre: 6014, limit: feedLimit))
            fanout = gameSubgenreIDs
        } else {
            absorb(try await fetchFeed(country: country, feedPath: feedPath, genre: nil, limit: feedLimit))
            fanout = kind == "apps" ? genreIDs.filter { $0 != 6014 } : genreIDs
        }

        var gi = 0
        while merged.count < limit && gi < fanout.count {
            let g = fanout[gi]; gi += 1
            if let apps = try? await fetchFeed(country: country, feedPath: feedPath, genre: g, limit: 200) {
                absorb(apps)
            }
            try? await Task.sleep(nanoseconds: 300_000_000)
        }
        if merged.count < limit {
            FileHandle.standardError.write(Data(
                "note: charts feed yielded \(merged.count) \(kind) (requested \(limit)); Apple caps each feed at ~200.\n".utf8))
        }
        return rerank(Array(merged.prefix(limit)))
    }

    static func lookupBundleID(appID: Int64, country: String) async -> String? {
        var tried = Set<String>()
        for c in [country.lowercased(), "us"] where !c.isEmpty && tried.insert(c).inserted {
            guard let url = URL(string: "https://itunes.apple.com/lookup?id=\(appID)&country=\(c)"),
                  let (data, _) = try? await URLSession.shared.data(from: url),
                  let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let results = root["results"] as? [[String: Any]],
                  let bid = results.first?["bundleId"] as? String, !bid.isEmpty else { continue }
            return bid
        }
        return nil
    }

    struct StoreDetails: Sendable {
        var sizeBytes: UInt64?
        var contentRating: String?
    }

    static func lookupDetails(appIDs: [Int64], country: String) async -> [Int64: StoreDetails] {
        var out: [Int64: StoreDetails] = [:]
        for chunk in stride(from: 0, to: appIDs.count, by: 100).map({ Array(appIDs[$0 ..< min($0 + 100, appIDs.count)]) }) {
            let ids = chunk.map(String.init).joined(separator: ",")
            guard let url = URL(string: "https://itunes.apple.com/lookup?id=\(ids)&country=\(country.lowercased())") else { continue }
            if let (data, _) = try? await URLSession.shared.data(from: url),
               let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let results = root["results"] as? [[String: Any]] {
                for r in results {
                    guard let id = (r["trackId"] as? NSNumber)?.int64Value else { continue }
                    let size = (r["fileSizeBytes"] as? String).flatMap { UInt64($0) }
                        ?? (r["fileSizeBytes"] as? NSNumber)?.uint64Value
                    out[id] = StoreDetails(sizeBytes: size,
                                           contentRating: r["trackContentRating"] as? String
                                               ?? r["contentAdvisoryRating"] as? String)
                }
            }
            try? await Task.sleep(nanoseconds: 200_000_000)
        }
        return out
    }

    struct StoreIdentity: Sendable {
        var appID: Int64
        var category: String?
        var artist: String?
    }

    static func lookupByBundleIDs(_ bundleIDs: [String], country: String) async -> [String: StoreIdentity] {
        var out: [String: StoreIdentity] = [:]
        let unique = Array(Set(bundleIDs.filter { !$0.isEmpty }))
        for chunk in stride(from: 0, to: unique.count, by: 100).map({ Array(unique[$0 ..< min($0 + 100, unique.count)]) }) {
            let joined = chunk.joined(separator: ",")
            guard let encoded = joined.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed),
                  let url = URL(string: "https://itunes.apple.com/lookup?bundleId=\(encoded)&country=\(country.lowercased())&limit=200")
            else { continue }
            if let (data, _) = try? await URLSession.shared.data(from: url),
               let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let results = root["results"] as? [[String: Any]] {
                for r in results {
                    guard let bid = r["bundleId"] as? String, !bid.isEmpty else { continue }
                    out[bid] = StoreIdentity(
                        appID: (r["trackId"] as? NSNumber)?.int64Value ?? 0,
                        category: r["primaryGenreName"] as? String,
                        artist: r["artistName"] as? String)
                }
            }
            try? await Task.sleep(nanoseconds: 200_000_000)
        }
        return out
    }

    static func lookupDetails(appID: Int64, country: String) async -> StoreDetails? {
        await lookupDetails(appIDs: [appID], country: country)[appID]
    }

    private static func rerank(_ apps: [ChartApp]) -> [ChartApp] {
        apps.enumerated().map { i, a in
            ChartApp(appID: a.appID, bundleID: a.bundleID, name: a.name,
                     artist: a.artist, category: a.category, genreID: a.genreID, rank: i + 1)
        }
    }

    private static func fetchFeed(country: String, feedPath: String, genre: Int?, limit: Int) async throws -> [ChartApp] {
        var path = "https://itunes.apple.com/\(country.lowercased())/rss/\(feedPath)/limit=\(limit)"
        if let genre { path += "/genre=\(genre)" }
        path += "/json"
        guard let url = URL(string: path) else { return [] }

        var req = URLRequest(url: url)
        req.setValue("ISAT-massscan", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await URLSession.shared.data(for: req)
        if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
            throw TopChartsError.badResponse(http.statusCode)
        }
        return parse(data)
    }

    static func parse(_ data: Data) -> [ChartApp] {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let feed = root["feed"] as? [String: Any] else { return [] }
        let entries: [[String: Any]]
        if let arr = feed["entry"] as? [[String: Any]] { entries = arr }
        else if let one = feed["entry"] as? [String: Any] { entries = [one] }
        else { return [] }

        var out: [ChartApp] = []
        for (i, e) in entries.enumerated() {
            guard let idObj = e["id"] as? [String: Any],
                  let attrs = idObj["attributes"] as? [String: Any],
                  let idStr = attrs["im:id"] as? String, let appID = Int64(idStr) else { continue }
            let bundleID = (attrs["im:bundleId"] as? String) ?? ""
            let name = (e["im:name"] as? [String: Any])?["label"] as? String ?? ""
            let artist = (e["im:artist"] as? [String: Any])?["label"] as? String
            let catAttrs = (e["category"] as? [String: Any])?["attributes"] as? [String: Any]
            let category = catAttrs?["label"] as? String
            let genreID = (catAttrs?["im:id"] as? String).flatMap { Int($0) }
            out.append(ChartApp(appID: appID, bundleID: bundleID, name: name,
                                artist: artist, category: category, genreID: genreID, rank: i + 1))
        }
        return out
    }
}
