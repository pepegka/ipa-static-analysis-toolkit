import Foundation

struct ShellResult: Sendable {
    public let stdout: Data
    public let stderr: Data
    public let exitCode: Int32
    public var stdoutString: String { String(decoding: stdout, as: UTF8.self) }
    public var stderrString: String { String(decoding: stderr, as: UTF8.self) }
}

enum Shell {
    @discardableResult
    public static func run(_ executable: String, _ arguments: [String]) throws -> ShellResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments

        let outPipe = Pipe()
        let errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe
        try process.run()

        final class Box: @unchecked Sendable { var data = Data() }
        let err = Box()
        let group = DispatchGroup()
        group.enter()
        DispatchQueue.global().async {
            err.data = errPipe.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }
        let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
        group.wait()
        let errData = err.data
        process.waitUntilExit()
        return ShellResult(stdout: outData, stderr: errData, exitCode: process.terminationStatus)
    }
}
