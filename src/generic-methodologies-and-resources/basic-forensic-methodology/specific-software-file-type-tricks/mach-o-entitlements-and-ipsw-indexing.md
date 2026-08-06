# Mach-O Entitlements-ekstraksie & IPSW-indeksering

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Hierdie bladsy dek hoe om entitlements programmaties uit Mach-O binaries te onttrek deur deur LC_CODE_SIGNATURE te loop en die code signing SuperBlob te parse, asook hoe om dit oor Apple IPSW firmwares te skaal deur hul inhoud te mount en te indexeer vir forensiese soektog/diff.

Indien jy 'n opknapping oor Mach-O-formaat en code signing nodig het, sien ook: macOS code signing en SuperBlob internals.
- Gaan macOS code signing-besonderhede na (SuperBlob, Code Directory, special slots): [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- Gaan algemene Mach-O-strukture/load commands na: [Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Entitlements in Mach-O: waar hulle gestoor word

Entitlements word binne die code signature-data gestoor waarna die LC_CODE_SIGNATURE load command verwys en in die __LINKEDIT-segment geplaas word. Die signature is 'n CS_SuperBlob wat verskeie blobs bevat (code directory, requirements, entitlements, CMS, ens.). Die entitlements blob is 'n CS_GenericBlob waarvan die data 'n Apple Binary Property List (bplist00) is wat entitlement keys na waardes map.<sup>[[1]](#references)</sup>

Sleutelstrukture (van xnu):<sup>[[6]](#references)[[7]](#references)</sup>
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
Belangrike konstantes:
- LC_CODE_SIGNATURE cmd = 0x1d
- CS SuperBlob magic = 0xfade0cc0
- Entitlements blob type (CSMAGIC_EMBEDDED_ENTITLEMENTS) = 0xfade7171
- DER entitlements kan via 'n spesiale slot (bv. -7) teenwoordig wees; sien die macOS Code Signing-bladsy vir spesiale slots en DER entitlements-notas

Nota: Multi-arch (fat) binaries bevat veelvuldige Mach-O slices. Jy moet die slice kies vir die argitektuur wat jy wil inspekteer en dan deur sy load commands loop.


## Extraction steps (generies, voldoende lossless)

1) Parse die Mach-O-header; itereer oor ncmds load_command-rekords.
2) Vind LC_CODE_SIGNATURE; lees linkedit_data_command.dataoff/datasize om die Code Signing SuperBlob wat in __LINKEDIT geplaas is, te karteer.
3) Valideer dat CS_SuperBlob.magic == 0xfade0cc0; itereer oor count-inskrywings van CS_BlobIndex.
4) Vind index.type == 0xfade7171 (embedded entitlements). Lees die aangewese CS_GenericBlob en parse sy data as 'n Apple binary plist (bplist00) na sleutel/waarde-entitlements.<sup>[[1]](#references)</sup>

Implementeringsnotas:
- Code signature-strukture gebruik big-endian-velde; ruil die byte-volgorde om wanneer dit op little-endian-hosts geparse word.
- Die entitlements GenericBlob-data self is 'n binary plist (wat deur standaard plist-libraries hanteer word).
- Sommige iOS-binaries kan DER entitlements bevat; sommige stores/slots verskil ook tussen platforms/versions. Kruisverifieer beide standaard- en DER-entitlements soos nodig.
- Vir fat binaries, gebruik die fat headers (FAT_MAGIC/FAT_MAGIC_64) om die korrekte slice en offset te vind voordat jy deur Mach-O-load commands loop.<sup>[[1]](#references)</sup>


## Minimal parsing outline (Python)

Die volgende is 'n kompakte outline wat die control flow toon om entitlements te vind en te decodeer. Dit laat doelbewus robuuste bounds checks en volledige fat binary-ondersteuning weg ter wille van bondigheid.<sup>[[1]](#references)</sup>
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
Gebruikwenke:
- Om fat binaries te hanteer, lees eers struct fat_header/fat_arch, kies die verlangde architecture slice, en gee dan die subreeks aan parse_entitlements.
- Op macOS kan jy resultate valideer met: codesign -d --entitlements :- /path/to/binary


## Voorbeeldbevindinge

Bevoorregte platform binaries versoek dikwels sensitiewe entitlements soos:<sup>[[1]](#references)</sup>
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

Om hierna op groot skaal binne firmwarebeelde te soek, is uiters waardevol vir attack surface mapping en die vergelyking van verskille oor releases/devices.


## Skaalvergroting oor IPSWs (montering en indeksering)

Om uitvoerbare lêers op groot skaal te enumereer en entitlements te onttrek sonder om volledige beelde te stoor:<sup>[[1]](#references)</sup>

- Gebruik die ipsw tool deur @blacktop om firmware-lêerstelsels af te laai en te mount. Montering gebruik apfs-fuse, sodat jy deur APFS-volumes kan navigeer sonder volledige ekstraksie.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- Doorloop gemonteerde volumes om Mach-O-lêers te vind (kontroleer magic en/of gebruik file/otool), en ontleed dan entitlements en ingevoerde frameworks.
- Behou ’n genormaliseerde weergawe in ’n relasionele databasis om lineêre groei oor duisende IPSWs te voorkom:
- executables, operating_system_versions, entitlements, frameworks
- many-to-many: executable↔OS version, executable↔entitlement, executable↔framework

Voorbeeldnavraag om alle OS versions te lys wat ’n gegewe executable-naam bevat:
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = "launchd";
```
Notas oor DB-draagbaarheid (indien jy jou eie indexer implementeer):<sup>[[1]](#references)</sup>
- Gebruik ’n ORM/abstraction (bv. SeaORM) om die code DB-agnosties te hou (SQLite/PostgreSQL).
- SQLite vereis AUTOINCREMENT slegs op ’n INTEGER PRIMARY KEY; indien jy i64 PKs in Rust wil gebruik, genereer entities as i32 en skakel die tipes om; SQLite stoor INTEGER intern as ’n 8-grepe signed waarde.<sup>[[8]](#references)</sup>


## Open-source tooling en verwysings vir entitlement-soektogte

- Firmware mount/download: https://github.com/blacktop/ipsw<sup>[[3]](#references)</sup>
- Entitlement-databasisse en verwysings:
- Jonathan Levin se entitlement DB: https://newosxbook.com/ent.php<sup>[[4]](#references)</sup>
- entdb: https://github.com/ChiChou/entdb<sup>[[5]](#references)</sup>
- Grootskaalse indexer (Rust, self-hosted Web UI + OpenAPI): https://github.com/synacktiv/appledb_rs<sup>[[2]](#references)</sup>
- Apple headers vir strukture en konstantes:
- loader.h (Mach-O headers, load commands)
- cs_blobs.h (SuperBlob, GenericBlob, CodeDirectory)

Vir meer inligting oor code signing-internals (Code Directory, special slots, DER entitlements), sien: [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)


## Verwysings

- [1] [appledb_rs: ’n navorsingsondersteuningsinstrument vir Apple-platforms](https://www.synacktiv.com/publications/appledbrs-un-outil-daide-a-la-recherche-sur-plateformes-apple.html)
- [2] [synacktiv/appledb_rs](https://github.com/synacktiv/appledb_rs)
- [3] [blacktop/ipsw](https://github.com/blacktop/ipsw)
- [4] [Jonathan Levin se entitlement DB](https://newosxbook.com/ent.php)
- [5] [ChiChou/entdb](https://github.com/ChiChou/entdb)
- [6] [XNU cs_blobs.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [7] [XNU mach-o/loader.h](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [8] [SQLite Datatypes](https://sqlite.org/datatype3.html)

{{#include ../../../banners/hacktricks-training.md}}
