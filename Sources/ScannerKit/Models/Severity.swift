import Foundation

public enum Severity: String, Codable, Sendable, CaseIterable, Comparable {
    case info, low, medium, high, critical

    public static func < (lhs: Severity, rhs: Severity) -> Bool {
        let order: [Severity] = [.info, .low, .medium, .high, .critical]
        return order.firstIndex(of: lhs)! < order.firstIndex(of: rhs)!
    }
}

public enum Polarity: String, Codable, Sendable, CaseIterable {
    case offensive
    case defensive
    case neutral
}
