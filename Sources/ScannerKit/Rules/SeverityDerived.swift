import Foundation

public extension Severity {
    static func derived(_ ruleID: String, _ vectorID: String) -> Severity {
        SeverityDerivation.severity(ruleID: ruleID, vectorID: vectorID) ?? .info
    }
}
