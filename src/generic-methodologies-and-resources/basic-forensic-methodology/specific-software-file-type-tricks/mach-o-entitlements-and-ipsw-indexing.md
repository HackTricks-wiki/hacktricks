# Mach-O Entitlements Extraction & IPSW Indexing

{{#include ../../../banners/hacktricks-training.md}}

## Overview

This page covers how to extract entitlements from Mach-O binaries programmatically by walking LC_CODE_SIGNATURE and parsing the code signing SuperBlob, and how to scale this across Apple IPSW firmwares by mounting and indexing their contents for forensic search/diff.

If you need a refresher on Mach-O format and code signing, see also: macOS code signing and SuperBlob internals.
- Check macOS code signing details (SuperBlob, Code Directory, special slots): [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- Check general Mach-O structures/load commands: [Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Entitlements in Mach-O: where they live

Entitlements are stored inside the code signature data referenced by the LC_CODE_SIGNATURE load command and placed in the __LINKEDIT segment. The signature is a CS_SuperBlob containing multiple blobs (code directory, requirements, entitlements, CMS, etc.). The entitlements blob is a CS_GenericBlob whose data is an Apple Binary Property List (bplist00) mapping entitlement keys to values.

Key structures (from xnu):

```c
/* mach-o/loader.h */
struct mach_header_64 {
    uint32_t magic;
    cpu_type_t cputype;
    cpu_subtype_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
};

struct load_command {
    uint32_t cmd;
    uint32_t cmdsize;
};

/* Entitlements live behind LC_CODE_SIGNATURE (cmd=0x1d) */
struct linkedit_data_command {
    uint32_t cmd;        /* LC_CODE_SIGNATURE */
    uint32_t cmdsize;    /* sizeof(struct linkedit_data_command) */
    uint32_t dataoff;    /* file offset of data in __LINKEDIT */
    uint32_t datasize;   /* file size of data in __LINKEDIT */
};

/* osfmk/kern/cs_blobs.h */
typedef struct __SC_SuperBlob {
    uint32_t magic;   /* CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0 */
    uint32_t length;
    uint32_t count;
    CS_BlobIndex index[];
} CS_SuperBlob;

typedef struct __BlobIndex {
    uint32_t type;    /* e.g., CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7171 */
    uint32_t offset;  /* offset of entry */
} CS_BlobIndex;

typedef struct __SC_GenericBlob {
    uint32_t magic;   /* same as type when standalone */
    uint32_t length;
    char data[];      /* Apple Binary Plist containing entitlements */
} CS_GenericBlob;
```

Important constants:
- LC_CODE_SIGNATURE cmd = 0x1d
- CS SuperBlob magic = 0xfade0cc0
- Entitlements blob type (CSMAGIC_EMBEDDED_ENTITLEMENTS) = 0xfade7171
- DER entitlements may be present via special slot (e.g., -7), see the macOS Code Signing page for special slots and DER entitlements notes

Note: Multi-arch (fat) binaries contain multiple Mach-O slices. You must pick the slice for the architecture you want to inspect and then walk its load commands.


## Extraction steps (generic, lossless-enough)

1) Parse Mach-O header; iterate ncmds worth of load_command records.
2) Locate LC_CODE_SIGNATURE; read linkedit_data_command.dataoff/datasize to map the Code Signing SuperBlob placed in __LINKEDIT.
3) Validate CS_SuperBlob.magic == 0xfade0cc0; iterate count entries of CS_BlobIndex.
4) Locate index.type == 0xfade7171 (embedded entitlements). Read the pointed CS_GenericBlob and parse its data as an Apple binary plist (bplist00) to key/value entitlements.

Implementation notes:
- Code signature structures use big-endian fields; swap byte order when parsing on little-endian hosts.
- The entitlements GenericBlob data itself is a binary plist (handled by standard plist libraries).
- Some iOS binaries may carry DER entitlements; also some stores/slots differ across platforms/versions. Cross-check both standard and DER entitlements as needed.
- For fat binaries, use the fat headers (FAT_MAGIC/FAT_MAGIC_64) to locate the correct slice and offset before walking Mach-O load commands.


## Minimal parsing outline (Python)

The following is a compact outline showing the control flow to find and decode entitlements. It intentionally omits robust bounds checks and full fat binary support for brevity.

```python
import plistlib, struct

LC_CODE_SIGNATURE = 0x1d
CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7171

# all code-signing integers are big-endian per cs_blobs.h
be32 = lambda b, off: struct.unpack_from(">I", b, off)[0]

def parse_entitlements(macho_bytes):
    # assume already positioned at a single-arch Mach-O slice
    magic, = struct.unpack_from("<I", macho_bytes, 0)
    is64 = magic in (0xfeedfacf,)
    if is64:
        ncmds = struct.unpack_from("<I", macho_bytes, 0x10)[0]
        sizeofcmds = struct.unpack_from("<I", macho_bytes, 0x14)[0]
        off = 0x20
    else:
        # 32-bit not shown
        return None

    code_sig_off = code_sig_size = None
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", macho_bytes, off)
        if cmd == LC_CODE_SIGNATURE:
            # struct linkedit_data_command is little-endian in file
            _, _, dataoff, datasize = struct.unpack_from("<IIII", macho_bytes, off)
            code_sig_off, code_sig_size = dataoff, datasize
        off += cmdsize

    if code_sig_off is None:
        return None

    blob = macho_bytes[code_sig_off: code_sig_off + code_sig_size]
    if be32(blob, 0x0) != CSMAGIC_EMBEDDED_SIGNATURE:
        return None

    count = be32(blob, 0x8)
    # iterate BlobIndex entries (8 bytes each after 12-byte header)
    for i in range(count):
        idx_off = 12 + i*8
        btype = be32(blob, idx_off)
        boff  = be32(blob, idx_off+4)
        if btype == CSMAGIC_EMBEDDED_ENTITLEMENTS:
            # GenericBlob is big-endian header followed by bplist
            glen = be32(blob, boff+4)
            data = blob[boff+8: boff+glen]
            return plistlib.loads(data)
    return None
```

Usage tips:
- To handle fat binaries, first read struct fat_header/fat_arch, choose the desired architecture slice, then pass the subrange to parse_entitlements.
- On macOS you can validate results with: codesign -d --entitlements :- /path/to/binary


## Example findings

Privileged platform binaries often request sensitive entitlements such as:
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

Searching these at scale across firmware images is extremely valuable for attack surface mapping and diffing across releases/devices.


## Scaling across IPSWs (mounting and indexing)

To enumerate executables and extract entitlements at scale without storing full images:

- Use the ipsw tool by @blacktop to download and mount firmware filesystems. Mounting leverages apfs-fuse, so you can traverse APFS volumes without full extraction.

```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```

- Walk mounted volumes to locate Mach-O files (check magic and/or use file/otool), then parse entitlements and imported frameworks.
- Persist a normalized view into a relational database to avoid linear growth across thousands of IPSWs:
  - executables, operating_system_versions, entitlements, frameworks
  - many-to-many: executable↔OS version, executable↔entitlement, executable↔framework

Example query to list all OS versions containing a given executable name:

```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = "launchd";
```

Notes on DB portability (if you implement your own indexer):
- Use an ORM/abstraction (e.g., SeaORM) to keep code DB-agnostic (SQLite/PostgreSQL).
- SQLite requires AUTOINCREMENT only on an INTEGER PRIMARY KEY; if you want i64 PKs in Rust, generate entities as i32 and convert types, SQLite stores INTEGER as 8-byte signed internally.


## Open-source tooling and references for entitlement hunting

- Firmware mount/download: https://github.com/blacktop/ipsw
- Entitlement databases and references:
  - Jonathan Levin’s entitlement DB: https://newosxbook.com/ent.php
  - entdb: https://github.com/ChiChou/entdb
- Large-scale indexer (Rust, self-hosted Web UI + OpenAPI): https://github.com/synacktiv/appledb_rs
- Apple headers for structures and constants:
  - loader.h (Mach-O headers, load commands)
  - cs_blobs.h (SuperBlob, GenericBlob, CodeDirectory)

For more on code signing internals (Code Directory, special slots, DER entitlements), see: [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)


## References

- [appledb_rs: a research support tool for Apple platforms](https://www.synacktiv.com/publications/appledbrs-un-outil-daide-a-la-recherche-sur-plateformes-apple.html)
- [synacktiv/appledb_rs](https://github.com/synacktiv/appledb_rs)
- [blacktop/ipsw](https://github.com/blacktop/ipsw)
- [Jonathan Levin’s entitlement DB](https://newosxbook.com/ent.php)
- [ChiChou/entdb](https://github.com/ChiChou/entdb)
- [XNU cs_blobs.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [XNU mach-o/loader.h](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [SQLite Datatypes](https://sqlite.org/datatype3.html)

{{#include ../../../banners/hacktricks-training.md}}
