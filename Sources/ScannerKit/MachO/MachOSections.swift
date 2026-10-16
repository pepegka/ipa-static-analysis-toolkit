import Foundation

public struct MachOSection: Sendable, Hashable {
    public let segment: String
    public let section: String
    public let fileOffset: UInt64
    public let size: UInt64
    public let isInEncryptedRange: Bool

    public var qualifiedName: String { "\(segment),\(section)" }
}

public struct MachOSymbol: Sendable, Hashable {
    public enum Kind: String, Sendable {
        case importedSymbol
        case definedSymbol
        case debugStab
    }
    public let kind: Kind
    public let name: String
}

public struct MachODeepSlice: Sendable {
    public let arch: String
    public let isEncrypted: Bool
    public let linkedDylibs: [String]
    public let rpaths: [String]
    public let sections: [MachOSection]
    public let symbols: [MachOSymbol]
}

public struct MachODeepInfo: Sendable {
    public let slices: [MachODeepSlice]
    public let sizeBytes: UInt64
    public var isAnySliceEncrypted: Bool { slices.contains { $0.isEncrypted } }
    public var architectures: [String] { slices.map(\.arch) }
    public var allDylibs: [String] { Array(Set(slices.flatMap { $0.linkedDylibs })).sorted() }
}

public enum MachODeepInspector {

    static let LC_SEGMENT: UInt32        = 0x01
    static let LC_SEGMENT_64: UInt32     = 0x19
    static let LC_SYMTAB: UInt32         = 0x02

    public static func inspect(data: Data) throws -> MachODeepInfo? {
        guard data.count >= 4 else { return nil }
        let magic = data.readU32(at: 0, bigEndian: false)
        let size = UInt64(data.count)

        var sliceRanges: [(offset: UInt64, size: UInt64)] = []
        switch magic {
        case MachOInspector.FAT_MAGIC, MachOInspector.FAT_CIGAM,
             MachOInspector.FAT_MAGIC_64, MachOInspector.FAT_CIGAM_64:
            sliceRanges = MachOInspector.fatSlices(data: data, magic: magic).map { ($0.offset, $0.size) }
        case MachOInspector.MH_MAGIC, MachOInspector.MH_CIGAM,
             MachOInspector.MH_MAGIC_64, MachOInspector.MH_CIGAM_64:
            sliceRanges.append((0, UInt64(data.count)))
        default:
            return nil
        }

        var slices: [MachODeepSlice] = []
        for r in sliceRanges {
            if let slice = parseThin(data: data, sliceOffset: r.offset, sliceSize: r.size) {
                slices.append(slice)
            }
        }
        return MachODeepInfo(slices: slices, sizeBytes: size)
    }

    private static func parseThin(data: Data, sliceOffset: UInt64, sliceSize: UInt64) -> MachODeepSlice? {
        let base = Int(sliceOffset)
        guard base + 28 <= data.count else { return nil }
        let magic = data.readU32(at: base, bigEndian: false)
        let isBig: Bool; let is64: Bool
        switch magic {
        case MachOInspector.MH_MAGIC:    isBig = false; is64 = false
        case MachOInspector.MH_CIGAM:    isBig = true;  is64 = false
        case MachOInspector.MH_MAGIC_64: isBig = false; is64 = true
        case MachOInspector.MH_CIGAM_64: isBig = true;  is64 = true
        default: return nil
        }
        let cpuType = data.readU32(at: base + 4, bigEndian: isBig)
        let cpuSubtype = data.readU32(at: base + 8, bigEndian: isBig)
        let ncmds = data.readU32(at: base + 16, bigEndian: isBig)
        let headerSize = is64 ? 32 : 28

        var cursor = base + headerSize
        var dylibs: [String] = []
        var rpaths: [String] = []
        var encrypted = false
        var encryptedRanges: [(UInt64, UInt64)] = []
        var sections: [MachOSection] = []
        var symbols: [MachOSymbol] = []

        for _ in 0..<Int(ncmds) {
            guard cursor + 8 <= data.count else { break }
            let cmd = data.readU32(at: cursor, bigEndian: isBig)
            let cmdsize = Int(data.readU32(at: cursor + 4, bigEndian: isBig))
            guard cmdsize >= 8, cursor + cmdsize <= data.count else { break }

            switch cmd {
            case MachOInspector.LC_LOAD_DYLIB,
                 MachOInspector.LC_LOAD_WEAK_DYLIB,
                 MachOInspector.LC_REEXPORT_DYLIB,
                 MachOInspector.LC_LOAD_UPWARD_DYLIB:
                if cursor + 24 <= data.count {
                    let nameOff = Int(data.readU32(at: cursor + 8, bigEndian: isBig))
                    if let s = data.readCString(at: cursor + nameOff, maxLength: cmdsize - nameOff) {
                        dylibs.append(s)
                    }
                }
            case MachOInspector.LC_RPATH:
                if cursor + 12 <= data.count {
                    let pathOff = Int(data.readU32(at: cursor + 8, bigEndian: isBig))
                    if let s = data.readCString(at: cursor + pathOff, maxLength: cmdsize - pathOff) {
                        rpaths.append(s)
                    }
                }
            case MachOInspector.LC_ENCRYPTION_INFO,
                 MachOInspector.LC_ENCRYPTION_INFO_64:
                if cursor + 20 <= data.count {
                    let cryptoff = UInt64(data.readU32(at: cursor + 8,  bigEndian: isBig))
                    let cryptsize = UInt64(data.readU32(at: cursor + 12, bigEndian: isBig))
                    let cryptid = data.readU32(at: cursor + 16, bigEndian: isBig)
                    if cryptid != 0 {
                        encrypted = true
                        encryptedRanges.append((cryptoff, cryptsize))
                    }
                }
            case LC_SEGMENT_64:
                if cursor + 72 <= data.count {
                    let segName = data.readFixedString(at: cursor + 8, length: 16)
                    let fileoff = data.readU64(at: cursor + 32, bigEndian: isBig)
                    _ = data.readU64(at: cursor + 40, bigEndian: isBig)
                    let nsects = data.readU32(at: cursor + 64, bigEndian: isBig)
                    var sCursor = cursor + 72
                    for _ in 0..<Int(nsects) {
                        guard sCursor + 80 <= data.count else { break }
                        let secName = data.readFixedString(at: sCursor, length: 16)
                        let segName2 = data.readFixedString(at: sCursor + 16, length: 16)
                        let secSize = data.readU64(at: sCursor + 40, bigEndian: isBig)
                        let secOffset = UInt64(data.readU32(at: sCursor + 48, bigEndian: isBig))
                        let absOffset = sliceOffset + secOffset
                        let inEnc = rangesOverlap(secOffset: secOffset, secSize: secSize,
                                                  encryptedRanges: encryptedRanges)
                        sections.append(MachOSection(
                            segment: segName2.isEmpty ? segName : segName2,
                            section: secName,
                            fileOffset: absOffset,
                            size: secSize,
                            isInEncryptedRange: inEnc
                        ))
                        sCursor += 80
                    }
                    _ = fileoff
                }
            case LC_SEGMENT:
                if cursor + 56 <= data.count {
                    let segName = data.readFixedString(at: cursor + 8, length: 16)
                    let nsects = data.readU32(at: cursor + 48, bigEndian: isBig)
                    var sCursor = cursor + 56
                    for _ in 0..<Int(nsects) {
                        guard sCursor + 68 <= data.count else { break }
                        let secName = data.readFixedString(at: sCursor, length: 16)
                        let segName2 = data.readFixedString(at: sCursor + 16, length: 16)
                        let secSize = UInt64(data.readU32(at: sCursor + 36, bigEndian: isBig))
                        let secOffset = UInt64(data.readU32(at: sCursor + 40, bigEndian: isBig))
                        let absOffset = sliceOffset + secOffset
                        let inEnc = rangesOverlap(secOffset: secOffset, secSize: secSize,
                                                  encryptedRanges: encryptedRanges)
                        sections.append(MachOSection(
                            segment: segName2.isEmpty ? segName : segName2,
                            section: secName,
                            fileOffset: absOffset,
                            size: secSize,
                            isInEncryptedRange: inEnc
                        ))
                        sCursor += 68
                    }
                }
            case LC_SYMTAB:
                if cursor + 24 <= data.count {
                    let symoff = UInt64(data.readU32(at: cursor + 8,  bigEndian: isBig))
                    let nsyms  = data.readU32(at: cursor + 12, bigEndian: isBig)
                    let stroff = UInt64(data.readU32(at: cursor + 16, bigEndian: isBig))
                    let strsize = UInt64(data.readU32(at: cursor + 20, bigEndian: isBig))
                    parseSymtab(data: data, sliceOffset: sliceOffset,
                                symoff: symoff, nsyms: Int(nsyms),
                                stroff: stroff, strsize: strsize,
                                is64: is64, isBig: isBig,
                                into: &symbols)
                }
            default:
                break
            }
            cursor += cmdsize
        }

        if !encryptedRanges.isEmpty {
            sections = sections.map { sec in
                if sec.isInEncryptedRange { return sec }
                let inEnc = rangesOverlap(secOffset: sec.fileOffset - sliceOffset,
                                          secSize: sec.size,
                                          encryptedRanges: encryptedRanges)
                if inEnc {
                    return MachOSection(segment: sec.segment, section: sec.section,
                                        fileOffset: sec.fileOffset, size: sec.size,
                                        isInEncryptedRange: true)
                }
                return sec
            }
        }

        let arch = MachOInspector.archName(cpuType: cpuType, cpuSubtype: cpuSubtype)
        return MachODeepSlice(arch: arch, isEncrypted: encrypted,
                              linkedDylibs: dylibs, rpaths: rpaths,
                              sections: sections, symbols: symbols)
    }

    private static func parseSymtab(data: Data, sliceOffset: UInt64,
                                    symoff: UInt64, nsyms: Int,
                                    stroff: UInt64, strsize: UInt64,
                                    is64: Bool, isBig: Bool,
                                    into symbols: inout [MachOSymbol]) {
        let symBase = Int(sliceOffset + symoff)
        let strBase = Int(sliceOffset + stroff)
        let strEnd  = Int(sliceOffset + stroff + strsize)
        let entrySize = is64 ? 16 : 12
        guard symBase >= 0, strBase >= 0,
              symBase + nsyms * entrySize <= data.count,
              strEnd <= data.count else { return }

        let N_STAB: UInt8 = 0xe0
        let N_OPT: UInt8 = 0x3c
        let N_TYPE: UInt8 = 0x0e
        let N_EXT: UInt8 = 0x01
        let N_UNDF: UInt8 = 0x00

        var seen = Set<String>()
        seen.reserveCapacity(nsyms)
        for i in 0..<nsyms {
            let e = symBase + i * entrySize
            let strx = Int(data.readU32(at: e, bigEndian: isBig))
            guard strx > 0, strBase + strx < strEnd else { continue }
            let nType = data[e + 4]
            guard let name = data.readCString(at: strBase + strx, maxLength: strEnd - (strBase + strx)),
                  !name.isEmpty else { continue }
            if seen.contains(name) { continue }
            seen.insert(name)
            let kind: MachOSymbol.Kind
            let typeField = nType & N_TYPE
            if nType == N_OPT {
                continue
            } else if (nType & N_STAB) != 0 {
                kind = .debugStab
            } else if (nType & N_EXT) != 0, typeField == N_UNDF {
                kind = .importedSymbol
            } else if typeField == N_UNDF {
                kind = .importedSymbol
            } else {
                kind = .definedSymbol
            }
            symbols.append(MachOSymbol(kind: kind, name: name))
        }
    }

    private static func rangesOverlap(secOffset: UInt64, secSize: UInt64,
                                      encryptedRanges: [(UInt64, UInt64)]) -> Bool {
        let a0 = secOffset
        let a1 = secOffset &+ secSize
        for (off, sz) in encryptedRanges {
            let b0 = off
            let b1 = off &+ sz
            if a0 < b1 && b0 < a1 { return true }
        }
        return false
    }
}


extension Data {
    func readFixedString(at offset: Int, length: Int) -> String {
        guard offset + length <= count, offset >= 0 else { return "" }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(length)
        for i in 0..<length {
            let b = self[offset + i]
            if b == 0 { break }
            bytes.append(b)
        }
        return String(bytes: bytes, encoding: .ascii) ?? ""
    }
}
