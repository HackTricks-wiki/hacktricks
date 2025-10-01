# Mach-O Uchimbaji wa Entitlements & Kuorodhesha IPSW

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Kurasa hii inaelezea jinsi ya kuchimba entitlements kutoka Mach-O binaries kwa njia ya programu kwa kupitia LC_CODE_SIGNATURE na kuchambua code signing SuperBlob, na jinsi ya kupanua hili kwa firmwares za Apple IPSW kwa kuiweka (mount) na kuorodhesha yaliyomo yao kwa ajili ya utafutaji/ukilinganishaji wa forensi.

Ikiwa unahitaji ukumbusho kuhusu muundo wa Mach-O na code signing, angalia pia: macOS code signing and SuperBlob internals.
- Angalia macOS code signing details (SuperBlob, Code Directory, special slots): [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- Angalia general Mach-O structures/load commands: [Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Entitlements in Mach-O: where they live

Entitlements zimetunzwa ndani ya data ya code signature inayorejelewa na load command ya LC_CODE_SIGNATURE na kuwekwa katika segment ya __LINKEDIT. Saini ni CS_SuperBlob iliyobeba blobs nyingi (code directory, requirements, entitlements, CMS, n.k.). The entitlements blob ni CS_GenericBlob ambayo data yake ni Apple Binary Property List (bplist00) inayofananisha funguo za entitlement na thamani.

Miundo kuu (kutoka xnu):
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
- DER entitlements may be present via special slot (e.g., -7), see the macOS Code Signing page for special slots and DER entitlements notes

Kumbuka: Multi-arch (fat) binaries zina Mach-O slices nyingi. Lazima uchague slice kwa architecture unayotaka kuchunguza kisha upitie load commands zake.


## Hatua za uchimbaji (za jumla, zisizopoteza-data-kutosha)

1) Changanua Mach-O header; rudi kupitia rekodi za load_command zilizo ndani ya ncmds.
2) Tafuta LC_CODE_SIGNATURE; soma linkedit_data_command.dataoff/datasize ili ramani Code Signing SuperBlob iliyowekwa katika __LINKEDIT.
3) Thibitisha CS_SuperBlob.magic == 0xfade0cc0; pitia idadi ya entries za CS_BlobIndex.
4) Tafuta index.type == 0xfade7171 (embedded entitlements). Soma CS_GenericBlob inayokaliwa na changanua data yake kama Apple binary plist (bplist00) ili kupata entitlements za key/value.

Vidokezo vya utekelezaji:
- Code signature structures zinatumia fields za big-endian; badilisha mpangilio wa bytes unapochanganua kwenye hosts za little-endian.
- The entitlements GenericBlob data yenyewe ni binary plist (inashughulikiwa na maktaba za kawaida za plist).
- Binaries za iOS zinaweza kubeba DER entitlements; pia baadhi ya stores/slots zinaweza kutofautiana kwa platforms/versions tofauti. Angalia kwa pande zote entitlements za kawaida na DER kadri inavyohitajika.
- Kwa fat binaries, tumia fat headers (FAT_MAGIC/FAT_MAGIC_64) kupata slice na offset sahihi kabla ya kupitia Mach-O load commands.


## Muhtasari mdogo wa parsing (Python)

Ifuatayo ni muhtasari mfupi unaoonyesha mtiririko wa udhibiti wa kupata na ku-decoder entitlements. Kwa makusudi haujajumuisha ukaguzi thabiti wa bounds na msaada kamili wa fat binary kwa kifupi.
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
- Ili kushughulikia fat binaries, kwanza soma struct fat_header/fat_arch, chagua slice ya architecture unayotaka, kisha pate subrange kwa parse_entitlements.
- Kwenye macOS unaweza kuthibitisha matokeo kwa: codesign -d --entitlements :- /path/to/binary


## Mfano za matokeo

Binaries za platform zenye ruhusa za juu mara nyingi huomba entitlements nyeti kama:
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

Kutafuta hizi kwa wingi katika firmware images ni muhimu sana kwa attack surface mapping na diffing across releases/devices.


## Kupanua kwa IPSWs (mounting and indexing)

Ili kuorodhesha executables na kutoa entitlements kwa wingi bila kuhifadhi picha kamili:

- Tumia ipsw tool by @blacktop kupakua na ku-mount firmware filesystems. Mounting inategemea apfs-fuse, hivyo unaweza kupitia APFS volumes bila full extraction.
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- Pitia volumes zilizowekwa (mounted) ili kupata Mach-O files (angalia magic na/au tumia file/otool), kisha changanua entitlements na imported frameworks.
- Hifadhi mtazamo uliosanifishwa katika relational database ili kuepuka ukuaji wa mstari kwa mamilioni ya IPSWs:
- executables, operating_system_versions, entitlements, frameworks
- many-to-many: executable↔OS version, executable↔entitlement, executable↔framework

Mfano wa query kuorodhesha OS versions zote zenye executable name fulani:
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = "launchd";
```
Vidokezo kuhusu portability ya DB (ikiwa utaweka indexer yako mwenyewe):
- Tumia ORM/abstraction (mfano, SeaORM) ili kuweka code DB-agnostic (SQLite/PostgreSQL).
- SQLite inahitaji AUTOINCREMENT tu kwenye INTEGER PRIMARY KEY; ikiwa unataka i64 PKs katika Rust, tengeneza entities kama i32 na ubadilishe aina, SQLite huhifadhi INTEGER kama 8-byte signed ndani.


## Open-source tooling and references for entitlement hunting

- Mount/download ya firmware: https://github.com/blacktop/ipsw
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
