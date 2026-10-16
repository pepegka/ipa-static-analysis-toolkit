import Foundation

enum HTML {

    static func esc(_ s: String) -> String {
        s.replacingOccurrences(of: "&", with: "&amp;")
         .replacingOccurrences(of: "<", with: "&lt;")
         .replacingOccurrences(of: ">", with: "&gt;")
         .replacingOccurrences(of: "\"", with: "&quot;")
         .replacingOccurrences(of: "'", with: "&#39;")
    }

    static func scriptJSON(_ data: Data) -> String {
        String(decoding: data, as: UTF8.self)
            .replacingOccurrences(of: "</", with: "<\\/")
            .replacingOccurrences(of: "\u{2028}", with: "\\u2028")
            .replacingOccurrences(of: "\u{2029}", with: "\\u2029")
    }

    static func bundledText(_ path: String) -> String {
        guard let url = Bundle.module.url(forResource: path, withExtension: nil),
              let text = try? String(contentsOf: url, encoding: .utf8) else {
            fatalError("missing bundled asset \(path)")
        }
        return text.trimmingCharacters(in: .newlines)
    }

    static func byteSize(_ bytes: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
    }

    static func mark(_ b: Bool?) -> String { b == nil ? "?" : (b! ? "✓" : "✗") }
}
