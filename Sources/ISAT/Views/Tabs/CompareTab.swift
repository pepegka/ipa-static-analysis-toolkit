import SwiftUI
import Charts
import ScannerKit

struct CompareTab: View {
    let report: ScanReport
    @EnvironmentObject var store: ScanStore
    @State private var otherID: ScanReport.ID?

    var body: some View {
        let others = store.reports.filter { $0.id != report.id }
        if others.isEmpty {
            VStack(spacing: 14) {
                Image(systemName: "rectangle.split.2x1")
                    .font(.system(size: 48, weight: .light))
                    .foregroundStyle(.secondary)
                Text("Drop another IPA to compare against.")
                    .foregroundStyle(.secondary)
                Text("Tip: compare two builds of an app, or an app against a comparable alternative.")
                    .font(.caption).foregroundStyle(.tertiary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            VStack(spacing: 0) {
                HStack {
                    Text("Compare with:").foregroundStyle(.secondary)
                    Picker("", selection: $otherID) {
                        Text("(pick one)").tag(ScanReport.ID?.none)
                        ForEach(others) { r in
                            Text("\(r.metadata.displayName ?? r.metadata.bundleName) · \(r.metadata.bundleID)")
                                .tag(ScanReport.ID?.some(r.id))
                        }
                    }
                    .pickerStyle(.menu)
                    Spacer()
                }
                .padding(10)
                Divider()
                if let id = otherID, let other = others.first(where: { $0.id == id }) {
                    CompareContent(left: report, right: other)
                } else {
                    VStack {
                        Text("Pick a scanned app to diff against.")
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
        }
    }
}

private struct CompareContent: View {
    let left: ScanReport
    let right: ScanReport

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                CompareHeaderRow(left: left, right: right)
                VectorBarsCompare(left: left, right: right)
                SDKCompareCard(left: left, right: right)
                EndpointCompareCard(left: left, right: right)
                FindingsCompareCard(left: left, right: right)
            }
            .padding(16)
        }
    }
}

private struct CompareHeaderRow: View {
    let left: ScanReport
    let right: ScanReport
    var body: some View {
        HStack(spacing: 12) {
            ReportSummaryColumn(report: left, alignment: .leading)
            Divider().frame(maxHeight: 80)
            ReportSummaryColumn(report: right, alignment: .trailing)
        }
        .padding(12)
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 10))
    }
}

private struct ReportSummaryColumn: View {
    let report: ScanReport
    let alignment: HorizontalAlignment
    var body: some View {
        VStack(alignment: alignment, spacing: 4) {
            HStack(spacing: 8) {
                if alignment == .leading { Spacer().frame(width: 0) }
                Text(report.metadata.displayName ?? report.metadata.bundleName)
                    .font(.headline)
            }
            Text(report.metadata.bundleID).font(.caption.monospaced()).foregroundStyle(.secondary)
            HStack(spacing: 8) {
                SeverityTally(findings: report.findings)
                VStack(alignment: alignment, spacing: 2) {
                    Text("\(report.findings.count) findings").font(.caption2)
                    Text("\(report.network.endpoints.count) endpoints").font(.caption2)
                    Text("\(report.network.detectedSDKs.count) SDKs").font(.caption2)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: alignment == .leading ? .leading : .trailing)
    }
}

private struct VectorBarsCompare: View {
    let left: ScanReport
    let right: ScanReport
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Vectors").font(.headline)
            Chart {
                ForEach(Vectors.all) { v in
                    let l = left.vectorSummaries.first { $0.vectorID == v.id }?.uniqueArtifactCount ?? 0
                    let r = right.vectorSummaries.first { $0.vectorID == v.id }?.uniqueArtifactCount ?? 0
                    BarMark(x: .value("count", l), y: .value("vec", v.id))
                        .foregroundStyle(by: .value("app", "A"))
                    BarMark(x: .value("count", r), y: .value("vec", v.id))
                        .foregroundStyle(by: .value("app", "B"))
                }
            }
            .chartLegend(.visible)
            .chartForegroundStyleScale(["A": Color.accentColor, "B": Color.purple])
            .frame(height: CGFloat(Vectors.all.count) * 22 + 24)
        }
        .padding(12)
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 10))
    }
}

private struct SDKCompareCard: View {
    let left: ScanReport
    let right: ScanReport
    var body: some View {
        let leftSet = Set(left.network.detectedSDKs.map(\.trackerID))
        let rightSet = Set(right.network.detectedSDKs.map(\.trackerID))
        let leftOnly = leftSet.subtracting(rightSet)
        let rightOnly = rightSet.subtracting(leftSet)
        let both = leftSet.intersection(rightSet)
        let sdkByID = Dictionary(uniqueKeysWithValues:
            (left.network.detectedSDKs + right.network.detectedSDKs).map { ($0.trackerID, $0) })

        VStack(alignment: .leading, spacing: 6) {
            Text("SDKs").font(.headline)
            HStack(alignment: .top, spacing: 12) {
                column("Only in A", ids: leftOnly, sdkByID: sdkByID, color: .accentColor)
                column("Shared", ids: both, sdkByID: sdkByID, color: .gray)
                column("Only in B", ids: rightOnly, sdkByID: sdkByID, color: .purple)
            }
        }
        .padding(12)
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 10))
    }
    private func column(_ title: String, ids: Set<String>,
                        sdkByID: [String: DetectedSDK], color: Color) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(title).font(.caption.bold())
                Text("(\(ids.count))").font(.caption2).foregroundStyle(.secondary)
            }
            ForEach(ids.sorted(), id: \.self) { id in
                if let sdk = sdkByID[id] {
                    HStack(spacing: 4) {
                        Circle().fill(color).frame(width: 6, height: 6)
                        Text(sdk.name).font(.caption.monospaced())
                            .lineLimit(1).truncationMode(.tail)
                        if sdk.isTracker {
                            Text("T").font(.caption2.bold())
                                .foregroundStyle(.red)
                        }
                    }
                }
            }
            if ids.isEmpty {
                Text("—").font(.caption2).foregroundStyle(.tertiary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct EndpointCompareCard: View {
    let left: ScanReport
    let right: ScanReport
    var body: some View {
        let leftHosts = Set(left.network.endpoints.map(\.host))
        let rightHosts = Set(right.network.endpoints.map(\.host))
        VStack(alignment: .leading, spacing: 6) {
            Text("Endpoints").font(.headline)
            HStack(alignment: .top, spacing: 12) {
                hostsColumn("Only in A", Array(leftHosts.subtracting(rightHosts)).sorted(), .accentColor)
                hostsColumn("Shared", Array(leftHosts.intersection(rightHosts)).sorted(), .gray)
                hostsColumn("Only in B", Array(rightHosts.subtracting(leftHosts)).sorted(), .purple)
            }
        }
        .padding(12)
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 10))
    }
    private func hostsColumn(_ title: String, _ hosts: [String], _ color: Color) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                Text(title).font(.caption.bold())
                Text("(\(hosts.count))").font(.caption2).foregroundStyle(.secondary)
            }
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 1) {
                    ForEach(hosts, id: \.self) {
                        Text($0).font(.caption2.monospaced())
                            .textSelection(.enabled)
                            .lineLimit(1).truncationMode(.middle)
                    }
                    if hosts.isEmpty {
                        Text("—").font(.caption2).foregroundStyle(.tertiary)
                    }
                }
            }
            .frame(maxHeight: 320)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct FindingsCompareCard: View {
    let left: ScanReport
    let right: ScanReport
    var body: some View {
        let leftRules = Set(left.findings.map(\.ruleID))
        let rightRules = Set(right.findings.map(\.ruleID))
        let aOnly = leftRules.subtracting(rightRules).sorted()
        let bOnly = rightRules.subtracting(leftRules).sorted()
        VStack(alignment: .leading, spacing: 6) {
            Text("Findings").font(.headline)
            HStack(alignment: .top, spacing: 12) {
                rulesColumn("Only in A", aOnly, .accentColor)
                rulesColumn("Only in B", bOnly, .purple)
            }
        }
        .padding(12)
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 10))
    }
    private func rulesColumn(_ title: String, _ ids: [String], _ color: Color) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                Text(title).font(.caption.bold())
                Text("(\(ids.count))").font(.caption2).foregroundStyle(.secondary)
            }
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 1) {
                    ForEach(ids, id: \.self) {
                        Text($0).font(.caption2.monospaced())
                            .foregroundStyle(color)
                    }
                    if ids.isEmpty {
                        Text("—").font(.caption2).foregroundStyle(.tertiary)
                    }
                }
            }
            .frame(maxHeight: 360)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
