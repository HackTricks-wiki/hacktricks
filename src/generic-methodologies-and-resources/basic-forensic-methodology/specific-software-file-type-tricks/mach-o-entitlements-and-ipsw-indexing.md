# Mach-O Entitlements Extraction & IPSW Indexing

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Hierdie bladsy behandel hoe om entitlements uit Mach-O binaries programmaties te onttrek deur LC_CODE_SIGNATURE te deurloop en die code signing SuperBlob te ontleed, en hoe om dit op te skaal oor Apple IPSW firmwares deur hul inhoud te mount en te indekseer vir forensiese soektog/vergelyking.

As jy 'n opfrisser nodig het oor Mach-O formaat en code signing, sien ook: macOS code signing and SuperBlob internals.
- Kyk na macOS code signing besonderhede (SuperBlob, Code Directory, special slots): [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- Kyk na algemene Mach-O strukture/load commands: [Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Entitlements in Mach-O: waar hulle geleë is

Entitlements word gestoor binne die code signature data wat deur die LC_CODE_SIGNATURE load command verwys word en geplaas in die __LINKEDIT segment. Die signature is 'n CS_SuperBlob wat meerdere blobs bevat (code directory, requirements, entitlements, CMS, ens.). Die entitlements blob is 'n CS_GenericBlob waarvan die data 'n Apple Binary Property List (bplist00) is wat entitlement-sleutels na waardes map.

Sleutelstrukture (van xnu):
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
- DER entitlements may be present via special slot (e.g., -7), see the macOS Code Signing page for special slots and DER entitlements notes

Let wel: Multi-arch (fat) binaries bevat meerdere Mach-O slices. Jy moet die slice vir die argitektuur wat jy wil inspekteer kies en dan sy load commands deurloop.


## Uittrekselstappe (generies, genoegsaam verliesloos)

1) Ontleed die Mach-O header; itereer oor ncmds load_command rekords.
2) Vind LC_CODE_SIGNATURE; lees linkedit_data_command.dataoff/datasize om die Code Signing SuperBlob in __LINKEDIT te map.
3) Valideer CS_SuperBlob.magic == 0xfade0cc0; itereer deur die count inskrywings van CS_BlobIndex.
4) Vind index.type == 0xfade7171 (embedded entitlements). Lees die aangeduide CS_GenericBlob en parse sy data as 'n Apple binary plist (bplist00) na sleutel/waarde entitlements.

Implementasienotas:
- Code signature structures gebruik big-endian fields; ruil die byte volgorde wanneer jy op little-endian hosts parse.
- Die entitlements GenericBlob data self is 'n binary plist (hanteer deur standaard plist-biblioteke).
- Sommige iOS binaries kan DER entitlements dra; ook verskil sommige stores/slots oor platforms/weergawe. Kontroleer beide standaard en DER entitlements soos nodig.
- Vir fat binaries, gebruik die fat headers (FAT_MAGIC/FAT_MAGIC_64) om die korrekte slice en offset te vind voordat jy die Mach-O load commands deurloop.


## Minimale parsing-opsomming (Python)

Die volgende is 'n beknopte opsomming wat die beheervloei toon om entitlements te vind en te decodeer. Dit laat doelbewus robuuste bounds checks en volledige fat binary ondersteuning uit ter wille van beknoptheid.
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
Gebruikswenke:
- To handle fat binaries, first read struct fat_header/fat_arch, choose the desired architecture slice, then pass the subrange to parse_entitlements.
- Op macOS kan jy resultate valideer met: codesign -d --entitlements :- /path/to/binary


## Voorbeeldbevindinge

Privileged platform binaries vra dikwels vir sensitiewe entitlements soos:
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

Om hierna op skaal oor firmware images te soek is uiters waardevol vir attack surface mapping en diffing oor weergawes/toestelle.


## Opskaal oor IPSWs (mounting and indexing)

Om executables te enumereer en entitlements op skaal te onttrek sonder om volledige images te stoor:

- Gebruik die ipsw tool deur @blacktop om firmware filesystems af te laai en te mount. Mounting maak gebruik van apfs-fuse, sodat jy APFS-volumes kan deurkruis sonder volledige ekstraksie.
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- Loop deur gemonteerde volumes om Mach-O files te lokaliseer (kontroleer magic en/of gebruik file/otool), en ontleed dan entitlements en imported frameworks.
- Bêre 'n genormaliseerde aansig in 'n relationele databasis om lineêre groei oor duisende IPSWs te vermy:
- executables, operating_system_versions, entitlements, frameworks
- veel-tot-veel: executable↔OS version, executable↔entitlement, executable↔framework

Voorbeeld navraag om alle OS versions te lys wat 'n gegewe executable naam bevat:
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = "launchd";
```
Aantekeninge oor DB-draagbaarheid (as jy jou eie indekser implementeer):
- Gebruik 'n ORM/abstraksie (bv. SeaORM) om kode DB-agnosties te hou (SQLite/PostgreSQL).
- SQLite vereis AUTOINCREMENT slegs op 'n INTEGER PRIMARY KEY; as jy i64 PKs in Rust wil hê, genereer entiteite as i32 en converteer tipes, SQLite stoor INTEGER intern as 8-byte signed.


## Open-source tooling and references for entitlement hunting

- Firmware mount/aflaai: https://github.com/blacktop/ipsw
- Entitlement databasisse en verwysings:
- Jonathan Levin se entitlement DB: https://newosxbook.com/ent.php
- entdb: https://github.com/ChiChou/entdb
- Grootskaalse indekser (Rust, self-hosted Web UI + OpenAPI): https://github.com/synacktiv/appledb_rs
- Apple headers vir strukture en konstantes:
- loader.h (Mach-O headers, load commands)
- cs_blobs.h (SuperBlob, GenericBlob, CodeDirectory)

Vir meer oor code signing internals (Code Directory, special slots, DER entitlements), sien: [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)


## Verwysings

- [appledb_rs: a research support tool for Apple platforms](https://www.synacktiv.com/publications/appledbrs-un-outil-daide-a-la-recherche-sur-plateformes-apple.html)
- [synacktiv/appledb_rs](https://github.com/synacktiv/appledb_rs)
- [blacktop/ipsw](https://github.com/blacktop/ipsw)
- [Jonathan Levin’s entitlement DB](https://newosxbook.com/ent.php)
- [ChiChou/entdb](https://github.com/ChiChou/entdb)
- [XNU cs_blobs.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [XNU mach-o/loader.h](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [SQLite Datatypes](https://sqlite.org/datatype3.html)

{{#include ../../../banners/hacktricks-training.md}}
