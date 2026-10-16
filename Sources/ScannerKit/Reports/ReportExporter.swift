import Foundation

public enum ReportExporter {

    public enum Format: String, CaseIterable, Sendable {
        case json, markdown, html, sarif

        public init?(argument: String) {
            switch argument.lowercased() {
            case "md": self = .markdown
            case let other: 
                guard let f = Format(rawValue: other) else { return nil }
                self = f
            }
        }

        public static var argumentNames: String {
            (allCases.map(\.rawValue) + ["md"]).sorted().joined(separator: "|")
        }
        public var fileExtension: String {
            switch self {
            case .json: return "json"
            case .markdown: return "md"
            case .html: return "html"
            case .sarif: return "sarif"
            }
        }
    }

    public static func export(_ report: ScanReport, format: Format,
                              dashboardPath: String? = nil) throws -> Data {
        switch format {
        case .json: return try jsonData(report)
        case .markdown: return Data(markdown(report).utf8)
        case .html: return Data(html(report, dashboardPath: dashboardPath).utf8)
        case .sarif: return try sarifData(report)
        }
    }

    public static func write(_ report: ScanReport, format: Format, to url: URL,
                             dashboardPath: String? = nil) throws {
        try export(report, format: format, dashboardPath: dashboardPath).write(to: url, options: .atomic)
    }

    public static func jsonData(_ report: ScanReport) throws -> Data {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        enc.dateEncodingStrategy = .iso8601
        return try enc.encode(report)
    }

}
