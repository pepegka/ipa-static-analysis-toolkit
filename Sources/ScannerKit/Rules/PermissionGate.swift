import Foundation

enum PermissionGate {

    public static func resolve(ruleID: String, vectorID: String,
                               ruleRequires: [String],
                               declaredKeys: Set<String>) -> (required: [String], granted: [String]) {
        var required = Set(ruleRequires)
        required.formUnion(defaultPermissions(forVector: vectorID, ruleID: ruleID))
        let req = Array(required).sorted()
        let granted = req.filter { declaredKeys.contains($0) }
        return (req, granted)
    }

    public static func defaultPermissions(forVector vectorID: String, ruleID: String) -> [String] {
        let rid = ruleID.lowercased()
        for rule in PermissionCatalog.defaultPermissions where rule.vector == vectorID {
            guard let needles = rule.match else { return rule.keys }
            if needles.contains(where: { rid.contains($0) }) { return rule.keys }
        }
        return []
    }
}
