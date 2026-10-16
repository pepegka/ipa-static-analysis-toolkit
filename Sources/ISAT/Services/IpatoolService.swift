import Foundation

struct IpatoolAccount: Equatable, Sendable {
    let name: String
    let email: String
}

struct IpatoolApp: Identifiable, Hashable, Sendable {
    let id: Int64
    let bundleID: String
    let name: String
    let version: String
    let price: Double
}

enum IpatoolLoginResult: Sendable {
    case success(IpatoolAccount)
    case needsTwoFactor
}

enum IpatoolError: LocalizedError {
    case binaryMissing
    case notLoggedIn
    case message(String)
    case badOutput(String)

    var errorDescription: String? {
        switch self {
        case .binaryMissing: return "The bundled ipatool helper could not be located."
        case .notLoggedIn: return "Not signed in to the App Store. Log in first."
        case .message(let m): return m
        case .badOutput(let m): return "Unexpected ipatool output: \(m)"
        }
    }
}

actor IpatoolService {
    static let shared = IpatoolService()

    private var cachedBinary: URL?
    private let execQueue = DispatchQueue(label: "isat.ipatool.exec", qos: .userInitiated)

    func accountInfo() async throws -> IpatoolAccount? {
        let out = try await run(["auth", "info"])
        if let acc = account(from: out.jsonLines) { return acc }
        return nil
    }

    func login(email: String, password: String, authCode: String?) async throws -> IpatoolLoginResult {
        var args = ["auth", "login", "--email", email, "--password", password]
        if let code = authCode, !code.isEmpty { args += ["--auth-code", code] }
        let out = try await run(args)

        if let acc = account(from: out.jsonLines) { return .success(acc) }

        let combined = (out.stdout + " " + out.stderr).lowercased()
        if combined.contains("2fa") || combined.contains("auth-code") || combined.contains("auth code") {
            return .needsTwoFactor
        }
        throw IpatoolError.message(errorMessage(from: out) ?? "Login failed.")
    }

    func search(term: String, limit: Int, platform: String?) async throws -> [IpatoolApp] {
        var args = ["search", term, "--limit", String(limit)]
        if let p = platform, !p.isEmpty { args += ["--platform", p] }
        let out = try await run(args)

        guard let line = out.jsonLines.first(where: { $0["apps"] != nil }),
              let apps = line["apps"] as? [[String: Any]] else {
            if let msg = errorMessage(from: out) {
                if msg.lowercased().contains("account") || msg.lowercased().contains("login") {
                    throw IpatoolError.notLoggedIn
                }
                throw IpatoolError.message(msg)
            }
            return []
        }
        return apps.compactMap { d in
            guard let id = (d["id"] as? NSNumber)?.int64Value ?? (d["id"] as? Int64) else { return nil }
            return IpatoolApp(
                id: id,
                bundleID: d["bundleID"] as? String ?? "",
                name: d["name"] as? String ?? "",
                version: d["version"] as? String ?? "",
                price: (d["price"] as? NSNumber)?.doubleValue ?? 0)
        }
    }

    func download(appID: Int64?, bundleID: String, into directory: URL, platform: String?) async throws -> URL {
        do {
            return try await rawDownload(appID: appID, bundleID: bundleID, directory: directory, platform: platform)
        } catch let IpatoolError.message(msg) where isLicenseError(msg) {
            guard !bundleID.isEmpty else { throw IpatoolError.message(msg) }
            try await acquireLicense(bundleID: bundleID, platform: platform)
            for _ in 0..<4 {
                try? await Task.sleep(nanoseconds: 2_500_000_000)
                do {
                    return try await rawDownload(appID: appID, bundleID: bundleID, directory: directory, platform: platform)
                } catch let IpatoolError.message(m) where isLicenseError(m) {
                    continue
                }
            }
            throw IpatoolError.message("License acquired, but the App Store hasn't activated it yet. Wait a moment and try downloading again.")
        }
    }

    func acquireLicense(bundleID: String, platform: String?) async throws {
        var args = ["purchase", "-b", bundleID]
        if let p = platform, !p.isEmpty { args += ["--platform", p] }
        let out = try await run(args)
        if out.jsonLines.contains(where: { ($0["success"] as? Bool) == true }) { return }
        throw IpatoolError.message(errorMessage(from: out) ?? "Could not acquire a license for this app.")
    }

    private func rawDownload(appID: Int64?, bundleID: String, directory: URL, platform: String?) async throws -> URL {
        var args = ["download"]
        if let appID { args += ["-i", String(appID)] } else { args += ["-b", bundleID] }
        args += ["-o", directory.path, "--purchase"]
        if let p = platform, !p.isEmpty { args += ["--platform", p] }
        let out = try await run(args)
        if let line = out.jsonLines.first(where: { ($0["success"] as? Bool) == true && $0["output"] != nil }),
           let path = line["output"] as? String {
            return finalizedURL(URL(fileURLWithPath: path), bundleID: bundleID)
        }
        throw IpatoolError.message(errorMessage(from: out) ?? "Download failed.")
    }

    private func finalizedURL(_ url: URL, bundleID: String) -> URL {
        let trimmed = bundleID.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return url }
        let safe = String(trimmed.unicodeScalars.map {
            CharacterSet.alphanumerics.union(CharacterSet(charactersIn: ".-_")).contains($0) ? Character($0) : "_"
        })
        let dest = url.deletingLastPathComponent().appendingPathComponent("\(safe).ipa")
        guard dest != url else { return url }
        let fm = FileManager.default
        do {
            if fm.fileExists(atPath: dest.path) { try fm.removeItem(at: dest) }
            try fm.moveItem(at: url, to: dest)
            return dest
        } catch {
            return url
        }
    }

    private func isLicenseError(_ msg: String) -> Bool {
        msg.lowercased().contains("license")
    }

    func revoke() async throws {
        _ = try await run(["auth", "revoke"])
    }

    private struct ProcOut: Sendable {
        let stdout: String
        let stderr: String
        let code: Int32
        var jsonLines: [[String: Any]] {
            stdout.split(separator: "\n").compactMap { line in
                guard let data = line.data(using: .utf8),
                      let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
                else { return nil }
                return obj
            }
        }
    }

    private func account(from lines: [[String: Any]]) -> IpatoolAccount? {
        guard let line = lines.first(where: {
            ($0["success"] as? Bool) == true && $0["email"] != nil && $0["name"] != nil
        }) else { return nil }
        return IpatoolAccount(name: line["name"] as? String ?? "",
                              email: line["email"] as? String ?? "")
    }

    private func errorMessage(from out: ProcOut) -> String? {
        if let line = out.jsonLines.first(where: { ($0["level"] as? String) == "error" }),
           let err = line["error"] as? String {
            return err
        }
        if let line = out.jsonLines.first(where: { $0["error"] != nil }),
           let err = line["error"] as? String {
            return err
        }
        return nil
    }

    private func run(_ args: [String]) async throws -> ProcOut {
        let bin = try binaryURL()
        let fullArgs = args + ["--format", "json", "--non-interactive"]
        return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<ProcOut, Error>) in
            execQueue.async {
                let p = Process()
                p.executableURL = bin
                p.arguments = fullArgs
                let outPipe = Pipe(), errPipe = Pipe()
                p.standardOutput = outPipe
                p.standardError = errPipe
                do {
                    try p.run()
                } catch {
                    cont.resume(throwing: IpatoolError.message("Failed to launch ipatool: \(error.localizedDescription)"))
                    return
                }
                let oData = outPipe.fileHandleForReading.readDataToEndOfFile()
                let eData = errPipe.fileHandleForReading.readDataToEndOfFile()
                p.waitUntilExit()
                cont.resume(returning: ProcOut(
                    stdout: String(decoding: oData, as: UTF8.self),
                    stderr: String(decoding: eData, as: UTF8.self),
                    code: p.terminationStatus))
            }
        }
    }

    private func binaryURL() throws -> URL {
        if let cached = cachedBinary { return cached }

        guard let bundled = Bundle.module.url(forResource: "ipatool", withExtension: nil)
            ?? developmentFallback() else {
            throw IpatoolError.binaryMissing
        }

        let fm = FileManager.default
        let supportDir = try fm.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                    appropriateFor: nil, create: true)
            .appendingPathComponent("ISAT", isDirectory: true)
        try fm.createDirectory(at: supportDir, withIntermediateDirectories: true)
        let dest = supportDir.appendingPathComponent("ipatool")

        let needsCopy: Bool = {
            guard let bAttr = try? fm.attributesOfItem(atPath: bundled.path),
                  let dAttr = try? fm.attributesOfItem(atPath: dest.path) else { return true }
            return (bAttr[.size] as? Int) != (dAttr[.size] as? Int)
        }()
        if needsCopy {
            if fm.fileExists(atPath: dest.path) { try? fm.removeItem(at: dest) }
            try fm.copyItem(at: bundled, to: dest)
        }
        try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: dest.path)
        cachedBinary = dest
        return dest
    }

    private func developmentFallback() -> URL? {
        let candidates = [
            URL(fileURLWithPath: #filePath)
                .deletingLastPathComponent().deletingLastPathComponent()
                .deletingLastPathComponent().deletingLastPathComponent()
                .appendingPathComponent("ipatool/ipatool"),
        ]
        return candidates.first { FileManager.default.isExecutableFile(atPath: $0.path) }
    }
}
