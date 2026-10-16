import Foundation

public enum BinaryHardeningAnalyzer {

    public struct Result: Sendable {
        public let hardening: [BinaryHardening]
        public let findings: [Finding]
    }

    private static let objcSections = ["__objc_classlist", "__objc_data", "__objc_catlist",
                                       "__objc_nlclslist", "__objc_methlist"]

    static func definesObjCOrC(definedSymbols: [String], sections: [MachOSection]) -> Bool {
        if definedSymbols.contains(where: { $0.contains("_OBJC_CLASS_$_") }) { return true }
        return sections.contains { objcSections.contains($0.section) }
    }

    public static func canaryVerdict(symbols: [String],
                                     definedSymbols: [String] = [],
                                     sections: [MachOSection] = []) -> Bool? {
        if symbols.contains(where: { $0.contains("stack_chk") }) { return true }
        return definesObjCOrC(definedSymbols: definedSymbols, sections: sections) ? false : nil
    }

    public static func isAppleSuppliedStub(relativePath: String) -> Bool {
        relativePath.contains("/_WatchKitStub/") || relativePath.hasSuffix("_WatchKitStub/WK")
    }

    public static func analyze(embeddedBinaries: [EmbeddedBinary],
                               machoByRel: [String: MachOInfo],
                               indices: [String: BinaryIndex]) -> Result {
        var hardening: [BinaryHardening] = []
        var findings: [Finding] = []

        for bin in embeddedBinaries {
            let macho = machoByRel[bin.relativePath]
            let isExecutable = macho?.isExecutable ?? false
            let hasPIE = isExecutable ? (macho?.isPIE ?? false) : true
            let index = indices[bin.relativePath]

            let canary: Bool?
            let arc: Bool?
            if let index {
                let symbols = index.importedSymbols + index.definedSymbols
                canary = canaryVerdict(symbols: symbols,
                                       definedSymbols: index.definedSymbols,
                                       sections: index.sections)
                arc = symbols.contains {
                    $0.contains("objc_release") || $0.contains("objc_retainAutorelease")
                    || $0.contains("objc_storeStrong")
                }
            } else {
                canary = nil; arc = nil
            }

            hardening.append(BinaryHardening(
                relativePath: bin.relativePath,
                name: bin.name,
                architectures: bin.architectures,
                isEncrypted: bin.isFairPlayEncrypted,
                hasPIE: hasPIE,
                hasStackCanary: canary,
                hasARC: arc))

            if isExecutable, !hasPIE {
                let copy = Messages.entry("SECH-04.no_pie", ["name": bin.name])
                findings.append(Finding(
                    ruleID: "SECH-04.no_pie",
                    vectorID: "SECH-04",
                    title: copy.title,
                    explanation: copy.explanation,
                    severity: .derived("SECH-04.no_pie", "SECH-04"), evidences: [Evidence(kind: .file, value: bin.relativePath, source: bin.relativePath)],
                    masvs: ["MASVS-CODE"],
                    remediation: copy.remediation).with(metrics: copy.values).with(instance: bin.relativePath))
            }
            if isExecutable, canary == false, !isAppleSuppliedStub(relativePath: bin.relativePath) {
                let copy = Messages.entry("SECH-04.no_stack_canary", ["name": bin.name])
                findings.append(Finding(
                    ruleID: "SECH-04.no_stack_canary",
                    vectorID: "SECH-04",
                    title: copy.title,
                    explanation: copy.explanation,
                    severity: .derived("SECH-04.no_stack_canary", "SECH-04"), evidences: [Evidence(kind: .file, value: bin.relativePath, source: bin.relativePath)],
                    masvs: ["MASVS-CODE"],
                    remediation: copy.remediation).with(metrics: copy.values).with(instance: bin.relativePath))
            }
        }

        let withStabs = indices.sorted(by: { $0.key < $1.key }).filter { $0.value.debugStabCount > 0 }
        if !withStabs.isEmpty {
            let total = withStabs.reduce(0) { $0 + $1.value.debugStabCount }
            let copy = Messages.entry("SECH-04.debug_symbols", [
                "count": String(withStabs.count),
                "s": withStabs.count == 1 ? "" : "s",
                "entries": String(total),
                "names": withStabs.prefix(6).map { FrameworkAttribution.framework(forRelativePath: $0.key) }
                    .joined(separator: ", "),
            ])
            findings.append(Finding(
                ruleID: "SECH-04.debug_symbols",
                vectorID: "SECH-04",
                title: copy.title,
                explanation: copy.explanation,
                severity: .derived("SECH-04.debug_symbols", "SECH-04"), evidences: withStabs.prefix(20).flatMap { rel, idx in
                    idx.debugStabs.prefix(2).map { Evidence(kind: .symbol, value: $0, source: rel) }
                },
                remediation: copy.remediation).with(metrics: copy.values))
        }

        return Result(hardening: hardening, findings: findings)
    }
}
