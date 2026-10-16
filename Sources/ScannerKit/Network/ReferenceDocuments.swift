import Foundation

enum ReferenceDocuments {

    struct Signature: Decodable {
        let name: String
        let requiredTopLevelKeys: [String]
        let source: String
        let why: String
    }
    struct LinkList: Decodable {
        let name: String
        let linkKeys: [String]
        let minimumEntries: Int
        let source: String
        let why: String
    }
    struct File: Decodable {
        let structural: [Signature]
        let linkLists: [LinkList]
        let nameMarkers: [String]
        let nameMarkerExtensions: [String]
    }

    static let data = RuleData.decode(File.self, "domains/reference-documents.json")

    static func match(fileName: String, text: String, data: File = data) -> String? {
        let lower = fileName.lowercased()
        let ext = (lower as NSString).pathExtension
        if data.nameMarkerExtensions.contains(ext),
           let m = data.nameMarkers.first(where: { lower.contains($0) }) { return "name:\(m)" }
        guard lower.hasSuffix(".json") else { return nil }
        let first = text.first(where: { !$0.isWhitespace })
        if first == "{" {
            for sig in data.structural where sig.requiredTopLevelKeys.allSatisfy({ text.contains("\"\($0)\"") }) {
                guard let obj = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] else { continue }
                if sig.requiredTopLevelKeys.allSatisfy({ obj[$0] != nil }) { return sig.name }
            }
        }
        guard first == "{" || first == "[" else { return nil }
        let lowerText = text.lowercased()
        for list in data.linkLists where list.linkKeys.contains(where: { lowerText.contains("\"\($0.lowercased())\"") }) {
            guard let root = try? JSONSerialization.jsonObject(with: Data(text.utf8)) else { return nil }
            if isLinkList(root, list: list) { return list.name }
        }
        return nil
    }

    static func isLinkList(_ root: Any, list: LinkList) -> Bool {
        let keys = Set(list.linkKeys.map { $0.lowercased() })
        func namesHost(_ s: String) -> Bool { !URLExtractor.extract(fromString: s, source: "").isEmpty }
        var entries = 0
        func walk(_ value: Any) -> Bool {
            if let array = value as? [Any] { return array.allSatisfy(walk) }
            guard let object = value as? [String: Any] else {
                if let s = value as? String { return !namesHost(s) }
                return true
            }
            var hasLink = false, strayName = false
            for (key, v) in object {
                guard let s = v as? String else {
                    if !walk(v) { return false }
                    continue
                }
                guard namesHost(s) else { continue }
                if keys.contains(key.lowercased()) { hasLink = true }
                else if s.contains("://") { return false }
                else { strayName = true }
            }
            if hasLink { entries += 1 }
            return hasLink || !strayName
        }
        return walk(root) && entries >= list.minimumEntries
    }
}
