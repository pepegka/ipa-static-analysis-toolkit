import Foundation

public enum Construct: String, Codable, Sendable, Hashable, CaseIterable, Identifiable {
    case DCS
    case TRK
    case TGAP
    case SURV
    case SECH
    case PLAT

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .DCS:  return "Data collection"
        case .TRK:  return "Tracking"
        case .TGAP: return "Transparency gap"
        case .SURV: return "Surveillance/evasion"
        case .SECH: return "Security hygiene"
        case .PLAT: return "Platform surface"
        }
    }
}
