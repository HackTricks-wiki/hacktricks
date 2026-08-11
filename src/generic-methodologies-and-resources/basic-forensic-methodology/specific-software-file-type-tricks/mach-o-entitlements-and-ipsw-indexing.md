# Mach-O Entitlements Extraction और IPSW Indexing

{{#include ../../../banners/hacktricks-training.md}}

## Overview

यह पेज बताता है कि प्रोग्रामेटिक रूप से Mach-O binaries से entitlements कैसे extract किए जाते हैं—इसके लिए LC_CODE_SIGNATURE को traverse करके code signing SuperBlob को parse किया जाता है—और Apple IPSW firmwares पर इसे scale करने के लिए उनकी contents को mount और index करके forensic search/diff किया जाता है।

यदि आपको Mach-O format और code signing का refresher चाहिए, तो यह भी देखें: macOS code signing और SuperBlob internals।
- macOS code signing details (SuperBlob, Code Directory, special slots) देखें: [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- सामान्य Mach-O structures/load commands देखें: [Universal binaries और Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Mach-O में Entitlements: ये कहाँ रहते हैं

Entitlements, LC_CODE_SIGNATURE load command द्वारा referenced code signature data के अंदर store होते हैं और __LINKEDIT segment में रखे जाते हैं। Signature एक CS_SuperBlob होती है जिसमें multiple blobs (code directory, requirements, entitlements, CMS, आदि) होते हैं। Entitlements blob एक CS_GenericBlob होती है, जिसका data एक serialized property list होता है और entitlement keys को values से map करता है; parsers को XML और binary plist दोनों encodings स्वीकार करनी चाहिए।<sup>[[1]](#references)[[6]](#references)</sup>

मुख्य structures (xnu से):<sup>[[6]](#references)[[7]](#references)</sup>
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
uint32_t type;    /* slot type, e.g. CSSLOT_ENTITLEMENTS = 5 */
uint32_t offset;  /* offset of entry */
} CS_BlobIndex;

typedef struct __SC_GenericBlob {
uint32_t magic;   /* blob magic, e.g. CSMAGIC_EMBEDDED_ENTITLEMENTS */
uint32_t length;
char data[];      /* serialized plist containing entitlements */
} CS_GenericBlob;
```
Apple headers के महत्वपूर्ण constants में शामिल हैं:<sup>[[6]](#references)[[7]](#references)</sup>
- LC_CODE_SIGNATURE cmd = 0x1d
- CS SuperBlob magic = 0xfade0cc0
- Entitlements index slot (`CSSLOT_ENTITLEMENTS`) = 5; उस slot पर मौजूद blob का magic `CSMAGIC_EMBEDDED_ENTITLEMENTS` = 0xfade7171 है
- DER entitlements `CSSLOT_DER_ENTITLEMENTS` = 7 slot और blob magic `CSMAGIC_EMBEDDED_DER_ENTITLEMENTS` = 0xfade7172 का उपयोग करते हैं

ध्यान दें: Multi-arch (fat) binaries में कई Mach-O slices होते हैं। आपको उस architecture के लिए slice चुनना होगा जिसका निरीक्षण करना है और फिर उसके load commands को traverse करना होगा।


## Extraction steps (generic, lossless-enough)

1) Mach-O header को parse करें; जितने `ncmds` हों उतने load_command records पर iterate करें।
2) LC_CODE_SIGNATURE को locate करें; __LINKEDIT में रखे गए Code Signing SuperBlob को map करने के लिए linkedit_data_command.dataoff/datasize पढ़ें।
3) CS_SuperBlob.magic == 0xfade0cc0 को validate करें; CS_BlobIndex की count entries पर iterate करें।
4) `index.type == CSSLOT_ENTITLEMENTS` (5) को locate करें, फिर verify करें कि pointed `CS_GenericBlob` का magic `CSMAGIC_EMBEDDED_ENTITLEMENTS` (0xfade7171) है। इसके data को property list के रूप में parse करके key/value entitlements प्राप्त करें।<sup>[[1]](#references)[[6]](#references)</sup>

Implementation notes:
- Code signature structures big-endian fields का उपयोग करते हैं; little-endian hosts पर parsing करते समय byte order swap करें।
- Entitlements `GenericBlob` में serialized plist होती है; standard plist libraries इसके XML या binary representation को handle कर सकती हैं।
- कुछ iOS binaries में DER entitlements हो सकते हैं; XNU एक अलग DER blob type expose करता है, और entitlement representations या slots अलग-अलग platforms और versions में भिन्न हो सकते हैं, इसलिए आवश्यकता के अनुसार standard और DER entitlements को cross-check करें।<sup>[[6]](#references)</sup>
- Fat binaries के लिए, Mach-O load commands पर चलने से पहले सही slice और offset locate करने हेतु fat headers (FAT_MAGIC/FAT_MAGIC_64) का उपयोग करें।


## Minimal parsing outline (Python)

निम्न compact outline entitlements को find और decode करने के control flow को दिखाता है। संक्षिप्तता के लिए इसमें robust bounds checks और पूर्ण fat binary support जानबूझकर शामिल नहीं किए गए हैं।<sup>[[6]](#references)[[7]](#references)</sup>
```python
import plistlib, struct

LC_CODE_SIGNATURE = 0x1d
CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0
CSSLOT_ENTITLEMENTS = 5
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
if btype == CSSLOT_ENTITLEMENTS:
# GenericBlob is a big-endian header followed by a serialized plist
glen = be32(blob, boff+4)
if be32(blob, boff) != CSMAGIC_EMBEDDED_ENTITLEMENTS:
return None
data = blob[boff+8: boff+glen]
return plistlib.loads(data)
return None
```
उपयोग संबंधी सुझाव:
- fat binaries को संभालने के लिए, पहले struct fat_header/fat_arch पढ़ें, वांछित architecture slice चुनें, फिर subrange को parse_entitlements में पास करें।
- macOS पर आप परिणामों को इस तरह validate कर सकते हैं: codesign -d --entitlements :- /path/to/binary


## उदाहरण के निष्कर्ष

source article macOS 14.0 के `launchd` binary में ये entitlements दिखाता है:<sup>[[1]](#references)</sup>
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

firmware images में बड़े पैमाने पर इन्हें खोजना attack surface mapping और releases/devices के बीच diffing के लिए अत्यंत उपयोगी है।


## IPSWs में scaling (mounting और indexing)

full images को store किए बिना executables को enumerate करने और बड़े पैमाने पर entitlements extract करने के लिए:<sup>[[1]](#references)</sup>

- firmware filesystems को download और mount करने के लिए @blacktop के ipsw tool का उपयोग करें। Mounting में apfs-fuse का उपयोग होता है, इसलिए आप full extraction के बिना APFS volumes को traverse कर सकते हैं।<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- Mach-O files का पता लगाने के लिए mounted volumes पर जाएँ (magic जाँचें और/या file/otool का उपयोग करें), फिर entitlements और imported frameworks को parse करें।
- हजारों IPSWs में linear growth से बचने के लिए normalized view को relational database में persist करें:
- executables, operating_system_versions, entitlements, frameworks
- many-to-many: executable↔OS version, executable↔entitlement, executable↔framework

किसी दिए गए executable name वाले सभी OS versions की सूची बनाने के लिए Example query (appledb_rs से adapted):<sup>[[1]](#references)</sup>
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = 'launchd';
```
DB portability पर नोट्स (यदि आप अपना indexer implement करते हैं):<sup>[[1]](#references)</sup>
- Code को DB-agnostic (SQLite/PostgreSQL) रखने के लिए ORM/abstraction (जैसे, SeaORM) का उपयोग करें।
- SQLite `AUTOINCREMENT` की अनुमति केवल `INTEGER PRIMARY KEY` पर देता है; वह key signed 64-bit ROWID का alias होती है, हालांकि SQLite disk पर छोटे integer widths का उपयोग कर सकता है। यदि SeaORM-generated Rust entities को i64 IDs की आवश्यकता है, तो entities को i32 के रूप में generate करें और boundary पर types convert करें।<sup>[[1]](#references)[[8]](#references)[[9]](#references)</sup>


## Entitlement hunting के लिए Open-source tooling और references

- Firmware mount/download: https://github.com/blacktop/ipsw.<sup>[[3]](#references)</sup>
- Entitlement databases और references:
- Jonathan Levin का entitlement DB: https://newosxbook.com/ent.php.<sup>[[4]](#references)</sup>
- entdb: https://github.com/ChiChou/entdb.<sup>[[5]](#references)</sup>
- Large-scale indexer (Rust, self-hosted Web UI + OpenAPI): https://github.com/synacktiv/appledb_rs.<sup>[[2]](#references)</sup>
- Structures और constants के लिए Apple headers:
- loader.h (Mach-O headers, load commands)
- cs_blobs.h (SuperBlob, GenericBlob, CodeDirectory)

Code signing internals (Code Directory, special slots, DER entitlements) के बारे में अधिक जानकारी के लिए देखें: [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)


## References

- [1] [Corentin Liaud (Synacktiv), Apple platforms के लिए एक research support tool: appledb_rs](https://www.synacktiv.com/publications/appledbrs-un-outil-daide-a-la-recherche-sur-plateformes-apple.html)
- [2] [synacktiv/appledb_rs](https://github.com/synacktiv/appledb_rs)
- [3] [blacktop/ipsw](https://github.com/blacktop/ipsw)
- [4] [Jonathan Levin का entitlement DB](https://newosxbook.com/ent.php)
- [5] [ChiChou/entdb](https://github.com/ChiChou/entdb)
- [6] [XNU cs_blobs.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [7] [XNU mach-o/loader.h](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [8] [SQLite Datatypes](https://sqlite.org/datatype3.html)
- [9] [SQLite Autoincrement](https://sqlite.org/autoinc.html)
{{#include ../../../banners/hacktricks-training.md}}
