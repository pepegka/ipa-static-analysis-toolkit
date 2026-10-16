import Foundation

public struct BinaryIndex: Sendable {

    public struct SectionStrings: Sendable {
        public let section: MachOSection
        public let strings: [ExtractedString]
        public init(section: MachOSection, strings: [ExtractedString]) {
            self.section = section; self.strings = strings
        }
    }

    public let relativePath: String
    public let absolutePath: String
    public let architectures: [String]
    public let isMainExecutable: Bool
    public let linkedDylibs: [String]
    public let rpaths: [String]
    public let sections: [MachOSection]
    public let perSectionStrings: [SectionStrings]
    public let importedSymbols: [String]
    public let definedSymbols: [String]
    public let encryptedSectionsSkipped: [MachOSection]
    public let stringCountCapped: Bool
    public var debugStabs: [String] = []
    public var debugStabCount: Int = 0

    public var totalStrings: Int { perSectionStrings.reduce(0) { $0 + $1.strings.count } }
}

public enum BinaryIndexer {

    public static let defaultMaxStringsPerBinary = 250_000

    public static let definedSymbolsCapPerBinary = 25_000

    static func isStringWorthy(_ s: MachOSection) -> Bool {
        let segOK = s.segment == "__TEXT" || s.segment == "__DATA"
                  || s.segment == "__DATA_CONST" || s.segment == "__DATA_DIRTY"
                  || s.segment == "__RODATA" || s.segment == "__OBJC"
        guard segOK else { return false }
        switch s.section {
        case "__cstring", "__cfstring", "__const", "__data",
             "__objc_classname", "__objc_methname", "__objc_methtype",
             "__objc_classlist", "__objc_selrefs", "__objc_classrefs",
             "__objc_superrefs", "__objc_imageinfo", "__objc_const",
             "__ustring", "__oslogstring", "__swift5_typeref", "__swift5_reflstr":
            return true
        default:
            return s.section.hasPrefix("__obj") || s.section.hasPrefix("__cfstr")
                   || s.section.hasPrefix("__cstr")
        }
    }

    public static func build(forBinary url: URL,
                             relativePath: String,
                             isMainExecutable: Bool,
                             maxStringsPerBinary: Int = defaultMaxStringsPerBinary) throws -> BinaryIndex? {
        let data = try Data(contentsOf: url, options: [.mappedIfSafe])
        guard let deep = try MachODeepInspector.inspect(data: data) else { return nil }
        guard let firstSlice = deep.slices.first else { return nil }
        let allSections = firstSlice.sections
        let worthy = allSections.filter(isStringWorthy)
        var perSection: [BinaryIndex.SectionStrings] = []
        var skipped: [MachOSection] = []
        var total = 0
        var capped = false

        for sec in worthy {
            if sec.isInEncryptedRange {
                skipped.append(sec)
                continue
            }
            let start = Int(sec.fileOffset)
            let end = Int(sec.fileOffset &+ sec.size)
            guard end <= data.count else {
                skipped.append(sec); continue
            }
            let minASCII: Int
            let minUTF16: Int
            switch sec.section {
            case "__objc_classname", "__objc_methname", "__objc_methtype":
                minASCII = 2; minUTF16 = 4
            default:
                minASCII = 4; minUTF16 = 4
            }
            let remaining = max(0, maxStringsPerBinary - total)
            if remaining == 0 { capped = true; break }
            let strings = StringExtractor.scan(data: data,
                                               rangeStart: start, rangeEnd: end,
                                               minASCII: minASCII, minUTF16: minUTF16,
                                               maxResults: remaining)
            total += strings.count
            perSection.append(.init(section: sec, strings: strings))
            if total >= maxStringsPerBinary { capped = true; break }
        }

        var imported: [String] = []
        var defined: [String] = []
        var seenI = Set<String>(); var seenD = Set<String>()
        var stabs: [String] = []
        var stabCount = 0
        var swiftTokens = Set<String>()
        func recoverSwift(_ name: String) {
            for t in SwiftDemangler.moduleTokens(fromMangled: name) { swiftTokens.insert(t) }
        }
        for s in firstSlice.symbols {
            let n = s.name
            let isSwiftMangled = n.hasPrefix("_$s") || n.hasPrefix("$s")
                              || n.hasPrefix("__$s") || n.hasPrefix("symbolic ")
            switch s.kind {
            case .importedSymbol:
                if isSwiftMangled { recoverSwift(n) }
                if seenI.insert(n).inserted { imported.append(n) }
            case .debugStab:
                stabCount += 1
                if stabs.count < 20 { stabs.append(n) }
            case .definedSymbol:
                if isSwiftMangled { recoverSwift(n); continue }
                if defined.count >= Self.definedSymbolsCapPerBinary {
                    continue
                }
                if seenD.insert(n).inserted { defined.append(n) }
            }
        }
        for t in swiftTokens.sorted() where seenD.insert(t).inserted { defined.append(t) }

        return BinaryIndex(
            relativePath: relativePath,
            absolutePath: url.path,
            architectures: deep.architectures,
            isMainExecutable: isMainExecutable,
            linkedDylibs: firstSlice.linkedDylibs,
            rpaths: firstSlice.rpaths,
            sections: allSections,
            perSectionStrings: perSection,
            importedSymbols: imported,
            definedSymbols: defined,
            encryptedSectionsSkipped: skipped,
            stringCountCapped: capped,
            debugStabs: stabs,
            debugStabCount: stabCount
        )
    }
}

public struct IndexedReport: Sendable {
    public let report: ScanReport
    public let indices: [String: BinaryIndex]
    public init(report: ScanReport, indices: [String: BinaryIndex]) {
        self.report = report; self.indices = indices
    }
}
