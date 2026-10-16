import Foundation
import SwiftUI

@MainActor
final class AppStoreStore: ObservableObject {

    @Published private(set) var account: IpatoolAccount?
    @Published var isAuthenticating = false
    @Published var loginError: String?
    @Published var awaitingTwoFactor = false

    @Published var searchTerm = ""
    @Published var platform = "iphone"
    @Published private(set) var results: [IpatoolApp] = []
    @Published var isSearching = false
    @Published var searchError: String?

    @Published private(set) var downloading: Set<Int64> = []
    @Published private(set) var downloadStatus: [Int64: String] = [:]
    @Published private(set) var downloadProgress: [Int64: Double] = [:]
    @Published var actionError: String?

    private var downloadTotals: [Int64: UInt64] = [:]

    @Published private(set) var downloaded: [DownloadedIPA] = []

    struct DownloadedIPA: Identifiable, Hashable {
        var id: String { url.path }
        let url: URL
        let name: String
        let sizeBytes: Int64
    }

    private let service = IpatoolService.shared

    private var pendingEmail = ""
    private var pendingPassword = ""

    var isLoggedIn: Bool { account != nil }

    func refreshAccount() async {
        let acc = try? await service.accountInfo()
        account = acc
    }

    func login(email: String, password: String) async {
        isAuthenticating = true
        loginError = nil
        awaitingTwoFactor = false
        defer { isAuthenticating = false }
        pendingEmail = email
        pendingPassword = password
        do {
            let result = try await service.login(email: email, password: password, authCode: nil)
            handle(result)
        } catch {
            loginError = error.localizedDescription
            clearPending()
        }
    }

    func submitTwoFactor(code: String) async {
        guard !pendingEmail.isEmpty else { return }
        isAuthenticating = true
        loginError = nil
        defer { isAuthenticating = false }
        do {
            let result = try await service.login(email: pendingEmail, password: pendingPassword, authCode: code)
            handle(result)
        } catch {
            loginError = error.localizedDescription
        }
    }

    func cancelLogin() {
        awaitingTwoFactor = false
        loginError = nil
        clearPending()
    }

    func logout() async {
        try? await service.revoke()
        account = nil
        results = []
    }

    private func handle(_ result: IpatoolLoginResult) {
        switch result {
        case .success(let acc):
            account = acc
            awaitingTwoFactor = false
            clearPending()
        case .needsTwoFactor:
            awaitingTwoFactor = true
        }
    }

    private func clearPending() {
        pendingEmail = ""
        pendingPassword = ""
    }

    func search() async {
        let term = searchTerm.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !term.isEmpty else { return }
        isSearching = true
        searchError = nil
        defer { isSearching = false }
        do {
            results = try await service.search(term: term, limit: 25, platform: platform)
            if results.isEmpty { searchError = "No results." }
        } catch IpatoolError.notLoggedIn {
            searchError = "Sign in to the App Store to search."
        } catch {
            searchError = error.localizedDescription
        }
    }

    static func defaultDownloadDirectory() -> URL {
        let fm = FileManager.default
        let projectRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let projectIpas = projectRoot.appendingPathComponent("ipas", isDirectory: true)
        if (try? fm.createDirectory(at: projectIpas, withIntermediateDirectories: true)) != nil,
           fm.isWritableFile(atPath: projectIpas.path) {
            return projectIpas
        }
        let base = (try? fm.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                appropriateFor: nil, create: true)) ?? fm.temporaryDirectory
        let dir = base.appendingPathComponent("ISAT/ipas", isDirectory: true)
        try? fm.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    func download(_ app: IpatoolApp, into directory: URL) async -> URL? {
        guard !downloading.contains(app.id) else { return nil }
        downloading.insert(app.id)
        downloadStatus[app.id] = "Preparing…"
        downloadProgress[app.id] = nil
        actionError = nil
        if let total = await TopChartsService.lookupDetails(appID: app.id, country: "us")?.sizeBytes {
            downloadTotals[app.id] = total
        }
        let monitor = Task { await monitorProgress(appID: app.id, directory: directory) }
        defer {
            monitor.cancel()
            downloading.remove(app.id)
            downloadStatus[app.id] = nil
            downloadProgress[app.id] = nil
            downloadTotals[app.id] = nil
        }
        do {
            let url = try await service.download(appID: app.id, bundleID: app.bundleID,
                                                 into: directory, platform: platform)
            refreshDownloads()
            return url
        } catch {
            actionError = "\(app.name): \(error.localizedDescription)"
            return nil
        }
    }

    func isDownloading(_ app: IpatoolApp) -> Bool { downloading.contains(app.id) }

    private func monitorProgress(appID: Int64, directory: URL) async {
        let fm = FileManager.default
        let marker = "_\(appID)_"
        while !Task.isCancelled {
            if let files = try? fm.contentsOfDirectory(atPath: directory.path) {
                if let tmp = files.first(where: { $0.hasSuffix(".tmp") && $0.contains(marker) })
                    ?? files.first(where: { $0.hasSuffix(".ipa.tmp") }) {
                    let path = directory.appendingPathComponent(tmp).path
                    if let attr = try? fm.attributesOfItem(atPath: path),
                       let size = attr[.size] as? Int64 {
                        if let total = downloadTotals[appID], total > 0 {
                            let frac = min(0.99, Double(size) / Double(total))
                            downloadProgress[appID] = frac
                            downloadStatus[appID] = "\(Self.bytes(size)) / \(Self.bytes(Int64(total))) · \(Int(frac * 100))%"
                        } else {
                            downloadProgress[appID] = nil
                            downloadStatus[appID] = "Downloaded \(Self.bytes(size))"
                        }
                    }
                }
            }
            try? await Task.sleep(nanoseconds: 400_000_000)
        }
    }

    func refreshDownloads() {
        let dir = Self.defaultDownloadDirectory()
        let fm = FileManager.default
        let urls = (try? fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: [.fileSizeKey]))?
            .filter { $0.pathExtension.lowercased() == "ipa" } ?? []
        downloaded = urls.map { url in
            let size = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize).flatMap { $0 } ?? 0
            return DownloadedIPA(url: url, name: url.lastPathComponent, sizeBytes: Int64(size))
        }
        .sorted { $0.name < $1.name }
    }

    func deleteDownload(_ item: DownloadedIPA) {
        try? FileManager.default.removeItem(at: item.url)
        refreshDownloads()
    }

    static func bytes(_ n: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: n, countStyle: .file)
    }
}
