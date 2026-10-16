import Foundation
import SwiftUI
import ScannerKit
import AppKit
import UniformTypeIdentifiers

@MainActor
final class ScanStore: ObservableObject {

    struct PendingScan: Identifiable {
        let id = UUID()
        let url: URL
        var phase: String = "Queued"
        var fraction: Double = 0
        var error: String?
    }

    @Published var reports: [ScanReport] = []
    @Published var pending: [PendingScan] = []
    @Published var selectedReportID: ScanReport.ID?

    private(set) var indicesByReportID: [ScanReport.ID: [String: BinaryIndex]] = [:]

    private var extractedByReportID: [ScanReport.ID: ExtractedIPA] = [:]

    func bundleRoot(for report: ScanReport) async -> URL? {
        if let cached = extractedByReportID[report.id] { return cached.appDirectory }
        let path = report.sourceIPAPath
        guard FileManager.default.fileExists(atPath: path) else { return nil }
        let extracted = await Task.detached {
            try? IPAExtractor.extract(ipa: URL(fileURLWithPath: path))
        }.value
        guard let extracted else { return nil }
        extractedByReportID[report.id] = extracted
        return extracted.appDirectory
    }

    private let scanner = ScannerKit.Scanner()
    private let queue = DispatchQueue(label: "ipa.scan.queue", qos: .userInitiated, attributes: .concurrent)

    var selectedReport: ScanReport? {
        guard let selectedReportID else { return reports.first }
        return reports.first { $0.id == selectedReportID }
    }

    public func indices(for reportID: ScanReport.ID) -> [String: BinaryIndex] {
        indicesByReportID[reportID] ?? [:]
    }

    func openPanel() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        if let ipa = UTType(filenameExtension: "ipa") {
            panel.allowedContentTypes = [ipa]
        }
        if panel.runModal() == .OK {
            for url in panel.urls { enqueue(url) }
        }
    }

    func enqueue(_ url: URL) {
        guard url.pathExtension.lowercased() == "ipa" else { return }
        let p = PendingScan(url: url)
        pending.append(p)
        let id = p.id
        queue.async { [weak self] in
            guard let self else { return }
            final class Reporter: ScanProgressReporter, @unchecked Sendable {
                let cb: @Sendable (ScanProgress) -> Void
                init(_ cb: @escaping @Sendable (ScanProgress) -> Void) { self.cb = cb }
                func report(_ progress: ScanProgress) { cb(progress) }
            }
            let reporter = Reporter { [weak self] progress in
                Task { @MainActor [weak self] in
                    guard let self else { return }
                    if let idx = self.pending.firstIndex(where: { $0.id == id }) {
                        self.pending[idx].phase = progress.phase
                        self.pending[idx].fraction = progress.fraction
                    }
                }
            }
            do {
                let indexed = try self.scanner.scanIndexed(ipa: url, progress: reporter)
                Task { @MainActor [weak self] in
                    guard let self else { return }
                    self.pending.removeAll { $0.id == id }
                    self.indicesByReportID[indexed.report.id] = indexed.indices
                    self.reports.append(indexed.report)
                    self.selectedReportID = indexed.report.id
                }
            } catch {
                let msg = "\(error)"
                Task { @MainActor [weak self] in
                    guard let self else { return }
                    if let idx = self.pending.firstIndex(where: { $0.id == id }) {
                        self.pending[idx].error = msg
                        self.pending[idx].phase = "Failed"
                    }
                }
            }
        }
    }

    func removeReport(_ id: ScanReport.ID) {
        reports.removeAll { $0.id == id }
        indicesByReportID.removeValue(forKey: id)
        if let extracted = extractedByReportID.removeValue(forKey: id) {
            IPAExtractor.cleanup(extracted)
        }
        if selectedReportID == id { selectedReportID = reports.first?.id }
    }

    func cleanupExtractions() {
        for extracted in extractedByReportID.values { IPAExtractor.cleanup(extracted) }
        extractedByReportID.removeAll()
    }
}
