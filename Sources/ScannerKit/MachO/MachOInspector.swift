import Foundation

public struct MachOSlice: Sendable, Hashable {
    public let arch: String
    public let isEncrypted: Bool
    public let linkedDylibs: [String]
    public let rpaths: [String]
    public var hasPIE: Bool = false
    public var fileType: UInt32 = 0
}

public struct MachOInfo: Sendable, Hashable {
    public let slices: [MachOSlice]
    public let sizeBytes: UInt64
    public var isAnySliceEncrypted: Bool { slices.contains { $0.isEncrypted } }
    public var architectures: [String] { slices.map(\.arch) }
    public var isExecutable: Bool { slices.contains { $0.fileType == MachOInspector.MH_EXECUTE } }
    public var isPIE: Bool { !slices.isEmpty && slices.allSatisfy { $0.hasPIE } }
    public var allDylibs: [String] {
        Array(Set(slices.flatMap { $0.linkedDylibs })).sorted()
    }
}

public enum MachOInspector {

    static let MH_MAGIC: UInt32     = 0xFEEDFACE
    static let MH_CIGAM: UInt32     = 0xCEFAEDFE
    static let MH_MAGIC_64: UInt32  = 0xFEEDFACF
    static let MH_CIGAM_64: UInt32  = 0xCFFAEDFE
    static let FAT_MAGIC: UInt32    = 0xCAFEBABE
    static let FAT_CIGAM: UInt32    = 0xBEBAFECA
    static let FAT_MAGIC_64: UInt32 = 0xCAFEBABF
    static let FAT_CIGAM_64: UInt32 = 0xBFBAFECA

    static let LC_REQ_DYLD: UInt32            = 0x80000000
    static let LC_LOAD_DYLIB: UInt32          = 0x0C
    static let LC_LOAD_WEAK_DYLIB: UInt32     = 0x18 | LC_REQ_DYLD
    static let LC_REEXPORT_DYLIB: UInt32      = 0x1F | LC_REQ_DYLD
    static let LC_LOAD_UPWARD_DYLIB: UInt32   = 0x23 | LC_REQ_DYLD
    static let LC_RPATH: UInt32               = 0x1C | LC_REQ_DYLD
    static let LC_ENCRYPTION_INFO: UInt32     = 0x21
    static let LC_ENCRYPTION_INFO_64: UInt32  = 0x2C

    static let MH_PIE: UInt32                 = 0x200000
    static let MH_EXECUTE: UInt32             = 0x2

    static let CPU_ARCH_ABI64: UInt32        = 0x01000000
    static let CPU_ARCH_ABI64_32: UInt32     = 0x02000000
    static let CPU_TYPE_X86: UInt32          = 7
    static let CPU_TYPE_ARM: UInt32          = 12

    public static func inspect(url: URL) throws -> MachOInfo? {
        let data = try Data(contentsOf: url, options: [.mappedIfSafe])
        guard data.count >= 4 else { return nil }

        let magic: UInt32 = data.readU32(at: 0, bigEndian: false)
        let size = UInt64(data.count)

        switch magic {
        case FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64:
            return try parseFat(data: data, magic: magic, sizeBytes: size)
        case MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64:
            if let slice = parseThin(data: data, sliceOffset: 0, sliceSize: UInt64(data.count)) {
                return MachOInfo(slices: [slice], sizeBytes: size)
            }
            return nil
        default:
            return nil
        }
    }

    static func fatSlices(data: Data, magic: UInt32) -> [(cpuType: UInt32, offset: UInt64, size: UInt64)] {
        let isBig = (magic == FAT_CIGAM || magic == FAT_CIGAM_64)
        let is64 = (magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64)
        let nfat = data.readU32(at: 4, bigEndian: isBig)
        let entrySize = is64 ? 32 : 20

        var out: [(cpuType: UInt32, offset: UInt64, size: UInt64)] = []
        for i in 0..<Int(nfat) {
            let base = 8 + i * entrySize
            guard base + entrySize <= data.count else { break }
            let cpuType = data.readU32(at: base, bigEndian: isBig)
            if is64 {
                out.append((cpuType,
                            data.readU64(at: base + 8, bigEndian: isBig),
                            data.readU64(at: base + 16, bigEndian: isBig)))
            } else {
                out.append((cpuType,
                            UInt64(data.readU32(at: base + 8, bigEndian: isBig)),
                            UInt64(data.readU32(at: base + 12, bigEndian: isBig))))
            }
        }
        return out
    }

    private static func parseFat(data: Data, magic: UInt32, sizeBytes: UInt64) throws -> MachOInfo {
        let slices = fatSlices(data: data, magic: magic).compactMap {
            parseThin(data: data, sliceOffset: $0.offset, sliceSize: $0.size)
        }
        return MachOInfo(slices: slices, sizeBytes: sizeBytes)
    }

    private static func parseThin(data: Data, sliceOffset: UInt64, sliceSize: UInt64) -> MachOSlice? {
        let base = Int(sliceOffset)
        guard base + 28 <= data.count else { return nil }
        let magic: UInt32 = data.readU32(at: base, bigEndian: false)
        let isBig: Bool
        let is64: Bool
        switch magic {
        case MH_MAGIC:    isBig = false; is64 = false
        case MH_CIGAM:    isBig = true;  is64 = false
        case MH_MAGIC_64: isBig = false; is64 = true
        case MH_CIGAM_64: isBig = true;  is64 = true
        default: return nil
        }
        let cpuType   = data.readU32(at: base + 4, bigEndian: isBig)
        let cpuSubtype = data.readU32(at: base + 8, bigEndian: isBig)
        let fileType  = data.readU32(at: base + 12, bigEndian: isBig)
        let ncmds = data.readU32(at: base + 16, bigEndian: isBig)
        let flags = data.readU32(at: base + 24, bigEndian: isBig)
        let hasPIE = (flags & MH_PIE) != 0
        let headerSize = is64 ? 32 : 28

        var cursor = base + headerSize
        var dylibs: [String] = []
        var rpaths: [String] = []
        var encrypted = false

        for _ in 0..<Int(ncmds) {
            guard cursor + 8 <= data.count else { break }
            let cmd = data.readU32(at: cursor, bigEndian: isBig)
            let cmdsize = Int(data.readU32(at: cursor + 4, bigEndian: isBig))
            guard cmdsize >= 8, cursor + cmdsize <= data.count else { break }

            switch cmd {
            case LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LOAD_UPWARD_DYLIB:
                if cursor + 24 <= data.count {
                    let nameOff = Int(data.readU32(at: cursor + 8, bigEndian: isBig))
                    if let s = data.readCString(at: cursor + nameOff, maxLength: cmdsize - nameOff) {
                        dylibs.append(s)
                    }
                }
            case LC_RPATH:
                if cursor + 12 <= data.count {
                    let pathOff = Int(data.readU32(at: cursor + 8, bigEndian: isBig))
                    if let s = data.readCString(at: cursor + pathOff, maxLength: cmdsize - pathOff) {
                        rpaths.append(s)
                    }
                }
            case LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64:
                if cursor + 20 <= data.count {
                    let cryptid = data.readU32(at: cursor + 16, bigEndian: isBig)
                    if cryptid != 0 { encrypted = true }
                }
            default:
                break
            }
            cursor += cmdsize
        }

        let arch = archName(cpuType: cpuType, cpuSubtype: cpuSubtype)
        return MachOSlice(arch: arch, isEncrypted: encrypted, linkedDylibs: dylibs,
                          rpaths: rpaths, hasPIE: hasPIE, fileType: fileType)
    }

    static func archName(cpuType: UInt32, cpuSubtype: UInt32) -> String {
        let masked = cpuType & ~(CPU_ARCH_ABI64 | CPU_ARCH_ABI64_32)
        let is64 = (cpuType & CPU_ARCH_ABI64) != 0
        let is64_32 = (cpuType & CPU_ARCH_ABI64_32) != 0
        switch masked {
        case CPU_TYPE_ARM:
            if is64_32 { return "arm64_32" }
            if is64 {
                let sub = cpuSubtype & 0x00FFFFFF
                return sub == 2 ? "arm64e" : "arm64"
            }
            return "armv7"
        case CPU_TYPE_X86:
            return is64 ? "x86_64" : "i386"
        default:
            return String(format: "cpu_0x%x", cpuType)
        }
    }
}

extension Data {
    func readU32(at offset: Int, bigEndian: Bool) -> UInt32 {
        guard offset + 4 <= count else { return 0 }
        let raw: UInt32 = self.withUnsafeBytes { ptr in
            ptr.loadUnaligned(fromByteOffset: offset, as: UInt32.self)
        }
        return bigEndian ? UInt32(bigEndian: raw) : UInt32(littleEndian: raw)
    }
    func readU64(at offset: Int, bigEndian: Bool) -> UInt64 {
        guard offset + 8 <= count else { return 0 }
        let raw: UInt64 = self.withUnsafeBytes { ptr in
            ptr.loadUnaligned(fromByteOffset: offset, as: UInt64.self)
        }
        return bigEndian ? UInt64(bigEndian: raw) : UInt64(littleEndian: raw)
    }
    func readCString(at offset: Int, maxLength: Int) -> String? {
        guard offset >= 0, offset < count, maxLength > 0 else { return nil }
        let end = Swift.min(offset + maxLength, count)
        var i = offset
        while i < end {
            if self[i] == 0 { break }
            i += 1
        }
        guard i > offset else { return "" }
        return String(data: self.subdata(in: offset..<i), encoding: .utf8)
    }
}
