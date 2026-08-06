# Mach-O Entitlements Extraction और IPSW Indexing

{{#include ../../../banners/hacktricks-training.md}}

## Mach-O में Entitlements: ये कहाँ मौजूद होते हैं

यह पेज प्रोग्रामेटिक रूप से Mach-O binaries से entitlements extract करने के तरीके को कवर करता है। इसके लिए LC_CODE_SIGNATURE को traverse करके code signing SuperBlob को parse किया जाता है। साथ ही, Apple IPSW firmwares में इस प्रक्रिया को scale करने के लिए उनके contents को mount और index करने का तरीका भी बताया गया है, ताकि forensic search/diff किया जा सके।

यदि आपको Mach-O format और code signing का refresh चाहिए, तो यह भी देखें: macOS code signing और SuperBlob internals।
- macOS code signing details (SuperBlob, Code Directory, special slots) देखें: [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- General Mach-O structures/load commands देखें: [Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Mach-O में Entitlements: ये कहाँ मौजूद होते हैं

Entitlements, LC_CODE_SIGNATURE load command द्वारा referenced code signature data के अंदर store होते हैं और __LINKEDIT segment में रखे जाते हैं। Signature एक CS_SuperBlob होता है जिसमें कई blobs (code directory, requirements, entitlements, CMS आदि) होते हैं। Entitlements blob एक CS_GenericBlob होता है, जिसका data एक Apple Binary Property List (bplist00) होता है और जो entitlement keys को values से map करता है।<sup>[[1]](#references)</sup>

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
uint32_t type;    /* e.g., CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7171 */
uint32_t offset;  /* offset of entry */
} CS_BlobIndex;

typedef struct __SC_GenericBlob {
uint32_t magic;   /* same as type when standalone */
uint32_t length;
char data[];      /* Apple Binary Plist containing entitlements */
} CS_GenericBlob;
```
महत्वपूर्ण constants:
- LC_CODE_SIGNATURE cmd = 0x1d
- CS SuperBlob magic = 0xfade0cc0
- Entitlements blob type (CSMAGIC_EMBEDDED_ENTITLEMENTS) = 0xfade7171
- DER entitlements special slot (जैसे, -7) के माध्यम से मौजूद हो सकते हैं; special slots और DER entitlements notes के लिए macOS Code Signing page देखें

ध्यान दें: Multi-arch (fat) binaries में कई Mach-O slices होते हैं। आपको उस architecture के लिए slice चुनना होगा जिसका निरीक्षण करना है, और फिर उसके load commands को पढ़ना होगा।


## Extraction steps (generic, lossless-enough)

1) Mach-O header को parse करें; ncmds के बराबर load_command records पर iterate करें।
2) LC_CODE_SIGNATURE खोजें; __LINKEDIT में रखे गए Code Signing SuperBlob को map करने के लिए linkedit_data_command.dataoff/datasize पढ़ें।
3) CS_SuperBlob.magic == 0xfade0cc0 को validate करें; CS_BlobIndex की count entries पर iterate करें।
4) index.type == 0xfade7171 (embedded entitlements) खोजें। संबंधित CS_GenericBlob पढ़ें और उसके data को Apple binary plist (bplist00) के रूप में parse करके key/value entitlements प्राप्त करें।<sup>[[1]](#references)</sup>

Implementation notes:
- Code signature structures big-endian fields का उपयोग करते हैं; little-endian hosts पर parse करते समय byte order swap करें।
- Entitlements GenericBlob का data स्वयं एक binary plist है (इसे standard plist libraries संभाल सकती हैं)।
- कुछ iOS binaries में DER entitlements हो सकते हैं; साथ ही, अलग-अलग platforms/versions में stores/slots भी अलग हो सकते हैं। आवश्यकता के अनुसार standard और DER entitlements दोनों को cross-check करें।
- Fat binaries के लिए, Mach-O load commands को पढ़ने से पहले सही slice और offset खोजने हेतु fat headers (FAT_MAGIC/FAT_MAGIC_64) का उपयोग करें।<sup>[[1]](#references)</sup>


## Minimal parsing outline (Python)

नीचे entitlements खोजने और decode करने के control flow को दिखाने वाला एक compact outline दिया गया है। संक्षिप्तता के लिए इसमें robust bounds checks और पूर्ण fat binary support जानबूझकर शामिल नहीं किए गए हैं।<sup>[[1]](#references)</sup>
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
- fat binaries को handle करने के लिए, पहले struct fat_header/fat_arch पढ़ें, इच्छित architecture slice चुनें, फिर subrange को parse_entitlements में पास करें।
- macOS पर आप परिणामों को इस तरह validate कर सकते हैं: codesign -d --entitlements :- /path/to/binary


## Example findings

Privileged platform binaries अक्सर sensitive entitlements request करते हैं:<sup>[[1]](#references)</sup>
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

Firmware images में बड़े पैमाने पर इन्हें search करना attack surface mapping और releases/devices के बीच diffing के लिए बेहद उपयोगी है।


## IPSWs में Scaling (mounting और indexing)

Full images store किए बिना executables enumerate करने और entitlements को बड़े पैमाने पर extract करने के लिए:<sup>[[1]](#references)</sup>

- Firmware filesystems को download और mount करने के लिए @blacktop के ipsw tool का उपयोग करें। Mounting apfs-fuse का लाभ उठाती है, इसलिए आप full extraction के बिना APFS volumes को traverse कर सकते हैं।<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- Mounted volumes पर जाकर Mach-O files खोजें (magic चेक करें और/या file/otool का उपयोग करें), फिर entitlements और imported frameworks को parse करें।
- हजारों IPSWs में linear growth से बचने के लिए normalized view को relational database में persist करें:
- executables, operating_system_versions, entitlements, frameworks
- many-to-many: executable↔OS version, executable↔entitlement, executable↔framework

किसी दिए गए executable name वाले सभी OS versions की सूची बनाने के लिए उदाहरण query:
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = "launchd";
```
DB portability पर नोट्स (यदि आप अपना indexer implement करते हैं):<sup>[[1]](#references)</sup>
- Code को DB-agnostic (SQLite/PostgreSQL) रखने के लिए ORM/abstraction (जैसे SeaORM) का उपयोग करें।
- SQLite में AUTOINCREMENT केवल INTEGER PRIMARY KEY पर आवश्यक है; यदि आप Rust में i64 PKs चाहते हैं, तो entities को i32 के रूप में generate करें और types convert करें। SQLite आंतरिक रूप से INTEGER को 8-byte signed रूप में store करता है।<sup>[[8]](#references)</sup>


## Entitlement hunting के लिए Open-source tooling और references

- Firmware mount/download: https://github.com/blacktop/ipsw<sup>[[3]](#references)</sup>
- Entitlement databases और references:
- Jonathan Levin’s entitlement DB: https://newosxbook.com/ent.php<sup>[[4]](#references)</sup>
- entdb: https://github.com/ChiChou/entdb<sup>[[5]](#references)</sup>
- Large-scale indexer (Rust, self-hosted Web UI + OpenAPI): https://github.com/synacktiv/appledb_rs<sup>[[2]](#references)</sup>
- Structures और constants के लिए Apple headers:
- loader.h (Mach-O headers, load commands)
- cs_blobs.h (SuperBlob, GenericBlob, CodeDirectory)

Code signing internals (Code Directory, special slots, DER entitlements) के बारे में अधिक जानकारी के लिए देखें: [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)


## References

- [1] [appledb_rs: a research support tool for Apple platforms](https://www.synacktiv.com/publications/appledbrs-un-outil-daide-a-la-recherche-sur-plateformes-apple.html)
- [2] [synacktiv/appledb_rs](https://github.com/synacktiv/appledb_rs)
- [3] [blacktop/ipsw](https://github.com/blacktop/ipsw)
- [4] [Jonathan Levin’s entitlement DB](https://newosxbook.com/ent.php)
- [5] [ChiChou/entdb](https://github.com/ChiChou/entdb)
- [6] [XNU cs_blobs.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [7] [XNU mach-o/loader.h](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [8] [SQLite Datatypes](https://sqlite.org/datatype3.html)

{{#include ../../../banners/hacktricks-training.md}}
