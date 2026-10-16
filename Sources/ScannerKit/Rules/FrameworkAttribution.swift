import Foundation

enum FrameworkAttribution {
    public static func framework(forRelativePath rel: String) -> String {
        let parts = rel.split(separator: "/")
        for i in 0..<parts.count {
            let p = String(parts[i])
            if p.hasSuffix(".framework") {
                return String(p.dropLast(".framework".count))
            }
            if p.hasSuffix(".appex") {
                return p
            }
            if p.hasSuffix(".bundle") {
                return p
            }
        }
        return "(main)"
    }
}
