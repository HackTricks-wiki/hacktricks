# Mach-O Entitlements Extraction & IPSW Indexing

{{#include ../../../banners/hacktricks-training.md}}

## अवलोकन

यह पृष्ठ बताता है कि कैसे Mach-O बाइनरी से प्रोग्रामेटिक रूप से entitlements निकाले जाएं by walking LC_CODE_SIGNATURE और code signing SuperBlob को parse करके, और कैसे इसे Apple IPSW firmwares पर स्केल किया जाए उनके contents को mount और index करके forensic search/diff के लिए।

यदि आपको Mach-O फॉर्मैट और code signing पर refresher चाहिए, तो नीचे देखें:
- macOS code signing विवरण (SuperBlob, Code Directory, special slots) देखें: [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- सामान्य Mach-O संरचनाएं/load commands देखें: [Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Mach-O में Entitlements: वे कहाँ होते हैं

Entitlements code signature data के अंदर संग्रहीत होते हैं जो LC_CODE_SIGNATURE load command द्वारा संदर्भित होते हैं और __LINKEDIT segment में रखे जाते हैं। Signature एक CS_SuperBlob है जिसमें कई blobs होते हैं (code directory, requirements, entitlements, CMS, आदि)। Entitlements blob एक CS_GenericBlob है जिसका data एक Apple Binary Property List (bplist00) है जो entitlement keys को values से map करता है।

मुख्य संरचनाएँ (xnu से):
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
महत्वपूर्ण स्थिरांक:
- LC_CODE_SIGNATURE cmd = 0x1d
- CS SuperBlob magic = 0xfade0cc0
- Entitlements blob type (CSMAGIC_EMBEDDED_ENTITLEMENTS) = 0xfade7171
- DER entitlements may be present via special slot (e.g., -7), see the macOS Code Signing page for special slots and DER entitlements notes

नोट: Multi-arch (fat) binaries में एक से अधिक Mach-O slices होते हैं। आपको उस आर्किटेक्चर के लिए उपयुक्त slice चुनना होगा जिसे आप निरीक्षण करना चाहते हैं और फिर उसके load commands को वॉक करना होगा।


## निष्कर्षण चरण (सामान्य, पर्याप्त हानि-रहित)

1) Mach-O header पार्स करें; ncmds जितने load_command रिकॉर्ड्स पर iterate करें।
2) LC_CODE_SIGNATURE खोजें; linkedit_data_command.dataoff/datasize पढ़कर __LINKEDIT में रखे Code Signing SuperBlob को मैप करें।
3) CS_SuperBlob.magic == 0xfade0cc0 मान्य करें; CS_BlobIndex की count प्रविष्टियों पर iterate करें।
4) index.type == 0xfade7171 (embedded entitlements) वाले एंट्री को खोजें। उस द्वारा संकेतित CS_GenericBlob पढ़ें और उसके डेटा को Apple binary plist (bplist00) के रूप में पार्स करके key/value entitlements निकालें।

कार्यान्वयन नोट्स:
- Code signature संरचनाएँ big-endian फील्ड्स का उपयोग करती हैं; little-endian होस्ट पर पार्स करते समय byte order swap करें।
- Entitlements GenericBlob का डेटा स्वयं एक binary plist है (मानक plist लाइब्रेरीज़ द्वारा संभाला जाता है)।
- कुछ iOS बाइनरीज़ में DER entitlements हो सकते हैं; साथ ही कुछ stores/slots प्लेटफ़ॉर्म/वर्शन के अनुसार अलग होते हैं। आवश्यकता अनुसार standard और DER entitlements दोनों को क्रॉस-चेक करें।
- fat बाइनरीज़ के लिए, Mach-O load commands पर जाएँ उससे पहले सही slice और offset ढूँढने हेतु fat headers (FAT_MAGIC/FAT_MAGIC_64) का उपयोग करें।


## न्यूनतम पार्सिंग रूपरेखा (Python)

निम्न एक संक्षिप्त रूपरेखा है जो entitlements खोजने और डिकोड करने के नियंत्रण प्रवाह को दिखाती है। संक्षिप्तता के लिए इसमें जानबूझकर सख्त bounds checks और पूर्ण fat binary समर्थन शामिल नहीं किया गया है।
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
- fat binaries को संभालने के लिए, पहले struct fat_header/fat_arch पढ़ें, इच्छित architecture slice चुनें, फिर subrange को parse_entitlements में पास करें।
- macOS पर आप परिणामों को निम्न से मान्य कर सकते हैं: codesign -d --entitlements :- /path/to/binary


## उदाहरण निष्कर्ष

Privileged platform binaries अक्सर निम्न संवेदनशील entitlements का अनुरोध करते हैं:
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

इनें firmware images में बड़े पैमाने पर खोजना releases/devices के बीच attack surface mapping और diffing के लिए अत्यंत उपयोगी है।


## IPSWs पर स्केलिंग (mounting और indexing)

पूर्ण images को स्टोर किए बिना बड़े पैमाने पर executables को enumerate करके entitlements निकालने के लिए:

- @blacktop द्वारा बनाए गए ipsw tool का उपयोग करके firmware filesystems को डाउनलोड और mount करें। Mounting apfs-fuse का उपयोग करता है, इसलिए आप बिना पूर्ण extraction के APFS volumes को traverse कर सकते हैं।
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- Mounted volumes को स्कैन करके Mach-O files ढूंढें (check magic and/or use file/otool), फिर entitlements और imported frameworks पार्स करें।
- हजारों IPSWs में रेखीय वृद्धि से बचने के लिए एक normalized view को relational database में persist करें:
- executables, operating_system_versions, entitlements, frameworks
- many-to-many: executable↔OS version, executable↔entitlement, executable↔framework

उदाहरण क्वेरी: किसी दिए गए executable नाम को शामिल करने वाले सभी OS versions सूचीबद्ध करने के लिए:
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


## entitlement hunting के लिए ओपन-सोर्स टूलिंग और संदर्भ

- Firmware माउंट/डाउनलोड: https://github.com/blacktop/ipsw
- Entitlement डेटाबेस और संदर्भ:
- Jonathan Levin का entitlement DB: https://newosxbook.com/ent.php
- entdb: https://github.com/ChiChou/entdb
- Large-scale indexer (Rust, self-hosted Web UI + OpenAPI): https://github.com/synacktiv/appledb_rs
- Apple headers for structures and constants:
- loader.h (Mach-O headers, load commands)
- cs_blobs.h (SuperBlob, GenericBlob, CodeDirectory)

Code signing के अंदरूनी विवरण (Code Directory, special slots, DER entitlements) के बारे में अधिक जानकारी के लिए देखें: [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)


## संदर्भ

- [appledb_rs: a research support tool for Apple platforms](https://www.synacktiv.com/publications/appledbrs-un-outil-daide-a-la-recherche-sur-plateformes-apple.html)
- [synacktiv/appledb_rs](https://github.com/synacktiv/appledb_rs)
- [blacktop/ipsw](https://github.com/blacktop/ipsw)
- [Jonathan Levin’s entitlement DB](https://newosxbook.com/ent.php)
- [ChiChou/entdb](https://github.com/ChiChou/entdb)
- [XNU cs_blobs.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [XNU mach-o/loader.h](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [SQLite Datatypes](https://sqlite.org/datatype3.html)

{{#include ../../../banners/hacktricks-training.md}}
