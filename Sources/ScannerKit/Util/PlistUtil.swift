import Foundation

enum PlistUtil {
    public static func load(at url: URL) -> [String: Any]? {
        guard let v = try? url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey]),
              v.isRegularFile == true, v.isSymbolicLink != true,
              let data = try? Data(contentsOf: url),
              let obj = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
              let dict = obj as? [String: Any] else { return nil }
        return dict
    }

    public static func flatten(_ value: Any, prefix: String = "", into out: inout [String: String]) {
        switch value {
        case let dict as [String: Any]:
            for (k, v) in dict {
                flatten(v, prefix: prefix.isEmpty ? k : "\(prefix).\(k)", into: &out)
            }
        case let arr as [Any]:
            for (i, v) in arr.enumerated() {
                flatten(v, prefix: "\(prefix)[\(i)]", into: &out)
            }
        case let str as String:
            out[prefix] = str
        case let n as NSNumber:
            out[prefix] = n.stringValue
        case let d as Date:
            out[prefix] = ISO8601DateFormatter().string(from: d)
        case let data as Data:
            out[prefix] = "<\(data.count) bytes>"
        case _ as NSNull:
            out[prefix] = "null"
        default:
            out[prefix] = "\(value)"
        }
    }
}
