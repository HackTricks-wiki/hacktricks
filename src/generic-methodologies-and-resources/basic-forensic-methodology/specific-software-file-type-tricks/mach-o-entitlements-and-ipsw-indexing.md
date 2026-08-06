# Utoaji wa Mach-O Entitlements na Uorodheshaji wa IPSW

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Ukurasa huu unaeleza jinsi ya kutoa entitlements kutoka kwenye Mach-O binaries kwa programmatically kwa kupitia LC_CODE_SIGNATURE na kuchanganua code signing SuperBlob, pamoja na jinsi ya kuongeza kiwango cha mchakato huu katika Apple IPSW firmwares kwa ku-mount na kuorodhesha yaliyomo kwa ajili ya forensic search/diff.

Ikiwa unahitaji kukumbushwa kuhusu muundo wa Mach-O na code signing, tazama pia: macOS code signing na SuperBlob internals.
- Angalia maelezo ya macOS code signing (SuperBlob, Code Directory, special slots): [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- Angalia miundo ya jumla ya Mach-O/load commands: [Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Entitlements katika Mach-O: zinapatikana wapi

Entitlements huhifadhiwa ndani ya code signature data inayorejelewa na LC_CODE_SIGNATURE load command na kuwekwa katika __LINKEDIT segment. Signature ni CS_SuperBlob iliyo na blobs nyingi (code directory, requirements, entitlements, CMS, n.k.). Entitlements blob ni CS_GenericBlob ambayo data yake ni Apple Binary Property List (bplist00) inayopanga entitlement keys na values.<sup>[[1]](#references)</sup>

Key structures (kutoka xnu):<sup>[[6]](#references)[[7]](#references)</sup>
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
Konstanti muhimu:
- LC_CODE_SIGNATURE cmd = 0x1d
- CS SuperBlob magic = 0xfade0cc0
- Entitlements blob type (CSMAGIC_EMBEDDED_ENTITLEMENTS) = 0xfade7171
- DER entitlements zinaweza kuwepo kupitia slot maalum (kwa mfano, -7), angalia ukurasa wa macOS Code Signing kwa maelezo kuhusu special slots na DER entitlements

Kumbuka: Multi-arch (fat) binaries huwa na Mach-O slices nyingi. Lazima uchague slice ya architecture unayotaka kukagua, kisha upitie load commands zake.


## Hatua za extraction (generic, lossless-enough)

1) Parse Mach-O header; pitia records za load_command kwa idadi ya ncmds.
2) Tafuta LC_CODE_SIGNATURE; soma linkedit_data_command.dataoff/datasize ili kumap Code Signing SuperBlob iliyo ndani ya __LINKEDIT.
3) Thibitisha kuwa CS_SuperBlob.magic == 0xfade0cc0; pitia entries za CS_BlobIndex kwa idadi ya count.
4) Tafuta index.type == 0xfade7171 (embedded entitlements). Soma CS_GenericBlob iliyoonyeshwa na pointer na parse data yake kama Apple binary plist (bplist00) ili kupata entitlements za key/value.<sup>[[1]](#references)</sup>

Maelezo ya implementation:
- Miundo ya code signature hutumia fields za big-endian; badilisha byte order unapoparsing kwenye hosts za little-endian.
- Data ya entitlements GenericBlob yenyewe ni binary plist (inashughulikiwa na standard plist libraries).
- Baadhi ya iOS binaries zinaweza kuwa na DER entitlements; pia baadhi ya stores/slots hutofautiana kulingana na platforms/versions. Kagua entitlements za standard na DER inapohitajika.
- Kwa fat binaries, tumia fat headers (FAT_MAGIC/FAT_MAGIC_64) kutafuta slice na offset sahihi kabla ya kupitia Mach-O load commands.<sup>[[1]](#references)</sup>


## Muhtasari wa minimal parsing (Python)

Ifuatayo ni muhtasari mfupi unaoonyesha control flow ya kutafuta na kudecode entitlements. Kwa ufupi, umeacha bounds checks imara na full fat binary support.<sup>[[1]](#references)</sup>
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
Vidokezo vya matumizi:
- Ili kushughulikia fat binaries, kwanza soma struct fat_header/fat_arch, chagua architecture slice inayotakiwa, kisha pitisha subrange kwa parse_entitlements.
- Kwenye macOS unaweza kuthibitisha matokeo kwa: codesign -d --entitlements :- /path/to/binary


## Mifano ya matokeo

Privileged platform binaries mara nyingi huomba entitlements nyeti kama vile:<sup>[[1]](#references)</sup>
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

Kutafuta hizi kwa kiwango kikubwa kwenye firmware images ni muhimu sana kwa attack surface mapping na diffing kati ya releases/devices.


## Kuongeza kiwango kwenye IPSWs (mounting na indexing)

Ili kuorodhesha executables na kutoa entitlements kwa kiwango kikubwa bila kuhifadhi images kamili:<sup>[[1]](#references)</sup>

- Tumia ipsw tool ya @blacktop kupakua na ku-mount firmware filesystems. Mounting hutumia apfs-fuse, hivyo unaweza kupitia APFS volumes bila extraction kamili.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- Pitia volumes zilizowekwa ili kupata faili za Mach-O (kagua magic na/au tumia file/otool), kisha parse entitlements na imported frameworks.
- Hifadhi mwonekano uliosanifishwa kwenye relational database ili kuzuia ukuaji wa mstari katika maelfu ya IPSWs:
- executables, operating_system_versions, entitlements, frameworks
- many-to-many: executable↔OS version, executable↔entitlement, executable↔framework

Mfano wa query ya kuorodhesha OS versions zote zilizo na executable yenye jina fulani:
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = "launchd";
```
Maelezo kuhusu portability ya DB (ukitekeleza indexer yako mwenyewe):<sup>[[1]](#references)</sup>
- Tumia ORM/abstraction (k.m., SeaORM) ili kuweka code ikiwa DB-agnostic (SQLite/PostgreSQL).
- SQLite inahitaji AUTOINCREMENT iwe kwenye INTEGER PRIMARY KEY pekee; ikiwa unataka PK za i64 katika Rust, tengeneza entities kama i32 na ubadilishe aina, kwa kuwa SQLite huhifadhi INTEGER ndani kama signed ya baiti 8.<sup>[[8]](#references)</sup>


## Open-source tooling na marejeo ya entitlement hunting

- Firmware mount/download: https://github.com/blacktop/ipsw
- Entitlement databases na marejeo:
- Jonathan Levin’s entitlement DB: https://newosxbook.com/ent.php
- entdb: https://github.com/ChiChou/entdb
- Large-scale indexer (Rust, self-hosted Web UI + OpenAPI): https://github.com/synacktiv/appledb_rs
- Apple headers za structures na constants:
- loader.h (Mach-O headers, load commands)
- cs_blobs.h (SuperBlob, GenericBlob, CodeDirectory)

Kwa maelezo zaidi kuhusu code signing internals (Code Directory, special slots, DER entitlements), tazama: [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)


## Marejeo

- [1] [appledb_rs: a research support tool for Apple platforms](https://www.synacktiv.com/publications/appledbrs-un-outil-daide-a-la-recherche-sur-plateformes-apple.html)
- [2] [synacktiv/appledb_rs](https://github.com/synacktiv/appledb_rs)
- [3] [blacktop/ipsw](https://github.com/blacktop/ipsw)
- [4] [Jonathan Levin’s entitlement DB](https://newosxbook.com/ent.php)
- [5] [ChiChou/entdb](https://github.com/ChiChou/entdb)
- [6] [XNU cs_blobs.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [7] [XNU mach-o/loader.h](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [8] [SQLite Datatypes](https://sqlite.org/datatype3.html)

{{#include ../../../banners/hacktricks-training.md}}
