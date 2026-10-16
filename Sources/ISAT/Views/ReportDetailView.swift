import SwiftUI
import ScannerKit

struct ReportDetailView: View {
    let report: ScanReport
    @State private var section: Section = .overview
    @State private var subBySection: [Section: SubTab] = [:]

    enum Section: String, CaseIterable, Identifiable {
        case overview, privacy, security, network, research, compare
        var id: Self { self }
        var label: String {
            switch self {
            case .overview: return "Overview"
            case .privacy:  return "Privacy"
            case .security: return "Security"
            case .network:  return "Network"
            case .research: return "Research"
            case .compare:  return "Compare"
            }
        }
        var icon: String {
            switch self {
            case .overview: return "gauge.with.needle"
            case .privacy:  return "hand.raised"
            case .security: return "lock.shield"
            case .network:  return "network"
            case .research: return "magnifyingglass"
            case .compare:  return "rectangle.split.2x1"
            }
        }
        var subTabs: [SubTab] {
            switch self {
            case .overview: return [.overview]
            case .privacy:  return [.privacyFindings, .sdks, .permissions, .privacyManifest]
            case .security: return [.securityFindings, .hardening, .secrets]
            case .network:  return [.networkFindings, .endpoints, .transport]
            case .research: return [.binaries, .strings, .files]
            case .compare:  return [.compare]
            }
        }
    }

    enum SubTab: String, Identifiable {
        case overview, privacyFindings, sdks, permissions, privacyManifest
        case securityFindings, hardening, secrets
        case networkFindings, endpoints, transport
        case binaries, strings, files, compare
        var id: Self { self }
        var label: String {
            switch self {
            case .overview: return "Overview"
            case .privacyFindings, .securityFindings, .networkFindings: return "Findings"
            case .sdks: return "SDKs"
            case .permissions: return "Permissions"
            case .privacyManifest: return "Privacy Manifest"
            case .hardening: return "Hardening"
            case .secrets: return "Secrets"
            case .endpoints: return "Endpoints"
            case .transport: return "Transport (ATS)"
            case .binaries: return "Binaries"
            case .strings: return "Strings"
            case .files: return "Files"
            case .compare: return "Compare"
            }
        }
    }

    private var activeSubTab: SubTab {
        let subs = section.subTabs
        if let s = subBySection[section], subs.contains(s) { return s }
        return subs.first ?? .overview
    }

    var body: some View {
        VStack(spacing: 0) {
            HeaderBar(report: report)
            Divider()
            Picker("", selection: $section) {
                ForEach(Section.allCases) { s in
                    Label(s.label, systemImage: s.icon).tag(s)
                }
            }
            .pickerStyle(.segmented)
            .labelStyle(.titleAndIcon)
            .padding(8)

            if section.subTabs.count > 1 {
                Picker("", selection: Binding(
                    get: { activeSubTab },
                    set: { subBySection[section] = $0 }
                )) {
                    ForEach(section.subTabs) { Text($0.label).tag($0) }
                }
                .pickerStyle(.segmented)
                .padding(.horizontal, 8)
                .padding(.bottom, 8)
            }
            Divider()

            subTabView(activeSubTab)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    @ViewBuilder
    private func subTabView(_ sub: SubTab) -> some View {
        switch sub {
        case .overview:         OverviewTab(report: report)
        case .privacyFindings:  VectorsTab(report: report, groups: [.privacy])
        case .sdks:             SDKsTab(report: report)
        case .permissions:      PermissionsTab(report: report)
        case .privacyManifest:  PrivacyManifestTab(report: report)
        case .securityFindings: VectorsTab(report: report,
                                           groups: [.storage, .crypto, .auth, .platform, .code, .resilience])
        case .hardening:        HardeningTab(report: report)
        case .secrets:          SecretsTab(report: report)
        case .networkFindings:  VectorsTab(report: report, groups: [.network])
        case .endpoints:        NetworkTab(report: report)
        case .transport:        NetworkSecurityTab(report: report)
        case .binaries:         BinariesTab(report: report)
        case .strings:          StringsTab(report: report)
        case .files:            FilesTab(report: report)
        case .compare:          CompareTab(report: report)
        }
    }
}

struct HeaderBar: View {
    let report: ScanReport
    var body: some View {
        HStack(alignment: .center, spacing: 16) {
            SeverityTally(findings: report.findings)
            VStack(alignment: .leading, spacing: 2) {
                Text(report.metadata.displayName ?? report.metadata.bundleName)
                    .font(.title2.weight(.semibold))
                HStack(spacing: 12) {
                    Text(report.metadata.bundleID).font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                    if let v = report.metadata.shortVersion {
                        Text("v\(v)").font(.caption).foregroundStyle(.secondary)
                    }
                    if let min = report.metadata.minimumOSVersion {
                        Text("iOS \(min)+").font(.caption).foregroundStyle(.secondary)
                    }
                    if !report.metadata.embeddedBinaries.isEmpty {
                        Text("\(report.metadata.embeddedBinaries.count) Mach-O")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    if !report.metadata.embeddedFrameworks.isEmpty {
                        Text("\(report.metadata.embeddedFrameworks.count) frameworks")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            Spacer()
            VStack(alignment: .trailing) {
                Text(String(format: "%.1fs scan", report.scanDurationSeconds))
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
                Text(report.findings.count.formatted() + " findings")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }
}

struct SeverityTally: View {
    let findings: [Finding]
    var body: some View {
        HStack(spacing: 6) {
            ForEach(Severity.allCases.reversed(), id: \.self) { sev in
                let n = findings.filter { $0.severity == sev }.count
                if n > 0 { SeverityBadge(label: sev.rawValue, count: n, severity: sev) }
            }
        }
    }
}

struct SeverityBadge: View {
    let label: String
    let count: Int
    let severity: Severity
    var body: some View {
        VStack(spacing: 1) {
            Text("\(count)")
                .font(.system(size: 20, weight: .bold, design: .rounded).monospacedDigit())
            Text(label.uppercased())
                .font(.system(size: 8, weight: .bold))
        }
        .frame(width: 56, height: 52)
        .background(color.opacity(0.18), in: RoundedRectangle(cornerRadius: 10))
        .foregroundStyle(color)
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(color, lineWidth: 1))
    }
    private var color: Color { severityDotColor(severity) }
}
