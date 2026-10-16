import Foundation

public enum SwiftDemangler {

    public static func moduleTokens(fromMangled name: String, max: Int = 3, minLength: Int = 3) -> [String] {
        let bytes = Array(name.utf8)
        var i = 0
        let n = bytes.count
        func isDigit(_ b: UInt8) -> Bool { b >= 0x30 && b <= 0x39 }

        if i < n, bytes[i] == 0x5F { i += 1 }
        if i + 1 < n, bytes[i] == 0x24, (bytes[i+1] == 0x73 || bytes[i+1] == 0x53) {
            i += 2
        } else {
            return []
        }

        var out: [String] = []
        while i < n, out.count < max {
            guard isDigit(bytes[i]) else { break }
            var len = 0
            while i < n, isDigit(bytes[i]) { len = len * 10 + Int(bytes[i] - 0x30); i += 1 }
            guard len > 0, i + len <= n else { break }
            let slice = bytes[i ..< i + len]
            i += len
            if let id = String(bytes: slice, encoding: .utf8),
               id.count >= minLength,
               id.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "_" }) {
                out.append(id)
            }
        }
        return out
    }
}
