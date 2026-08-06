# Εξαγωγή Entitlements από Mach-O και ευρετηρίαση IPSW

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Αυτή η σελίδα καλύπτει τον τρόπο προγραμματιστικής εξαγωγής entitlements από Mach-O binaries μέσω περιήγησης στο LC_CODE_SIGNATURE και parsing του code signing SuperBlob, καθώς και τον τρόπο κλιμάκωσης αυτής της διαδικασίας σε Apple IPSW firmwares με mounting και indexing του περιεχομένου τους για forensic search/diff.

Αν χρειάζεστε μια υπενθύμιση σχετικά με το Mach-O format και το code signing, δείτε επίσης: macOS code signing και SuperBlob internals.
- Ελέγξτε τις λεπτομέρειες του macOS code signing (SuperBlob, Code Directory, special slots): [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- Ελέγξτε τις γενικές Mach-O structures/load commands: [Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Entitlements στο Mach-O: πού βρίσκονται

Τα entitlements αποθηκεύονται μέσα στα code signature data που αναφέρονται από το LC_CODE_SIGNATURE load command και τοποθετούνται στο __LINKEDIT segment. Η signature είναι ένα CS_SuperBlob που περιέχει πολλαπλά blobs (code directory, requirements, entitlements, CMS κ.λπ.). Το entitlements blob είναι ένα CS_GenericBlob, του οποίου τα data είναι ένα Apple Binary Property List (bplist00) που αντιστοιχίζει entitlement keys σε values.<sup>[[1]](#references)</sup>

Βασικές structures (από το xnu):<sup>[[6]](#references)[[7]](#references)</sup>
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
Σημαντικές constants:
- LC_CODE_SIGNATURE cmd = 0x1d
- CS SuperBlob magic = 0xfade0cc0
- Entitlements blob type (CSMAGIC_EMBEDDED_ENTITLEMENTS) = 0xfade7171
- DER entitlements μπορεί να υπάρχουν μέσω special slot (π.χ. -7), δείτε τη σελίδα macOS Code Signing για special slots και σημειώσεις σχετικά με DER entitlements

Σημείωση: Τα Multi-arch (fat) binaries περιέχουν πολλαπλά Mach-O slices. Πρέπει να επιλέξετε το slice για την αρχιτεκτονική που θέλετε να επιθεωρήσετε και, στη συνέχεια, να διατρέξετε τα load commands του.


## Βήματα extraction (generic, επαρκώς lossless)

1) Κάντε parse το Mach-O header· διατρέξτε τόσα records `load_command` όσα ορίζει το `ncmds`.
2) Εντοπίστε το `LC_CODE_SIGNATURE`· χρησιμοποιήστε τα `linkedit_data_command.dataoff/datasize` για να χαρτογραφήσετε το Code Signing SuperBlob που βρίσκεται στο `__LINKEDIT`.
3) Επαληθεύστε ότι το `CS_SuperBlob.magic == 0xfade0cc0`· διατρέξτε τα entries `CS_BlobIndex` του `count`.
4) Εντοπίστε το `index.type == 0xfade7171` (embedded entitlements). Διαβάστε το `CS_GenericBlob` που υποδεικνύεται και κάντε parse τα δεδομένα του ως Apple binary plist (`bplist00`) για να ανακτήσετε τα key/value entitlements.<sup>[[1]](#references)</sup>

Σημειώσεις υλοποίησης:
- Οι δομές code signature χρησιμοποιούν big-endian πεδία· κάντε swap τη σειρά των bytes κατά το parsing σε little-endian hosts.
- Τα δεδομένα του ίδιου του entitlements `GenericBlob` είναι binary plist (το χειρίζονται standard plist libraries).
- Ορισμένα iOS binaries μπορεί να περιέχουν DER entitlements· επίσης, ορισμένα stores/slots διαφέρουν ανάμεσα σε platforms/versions. Κάντε cross-check τόσο των standard όσο και των DER entitlements, όταν χρειάζεται.
- Για fat binaries, χρησιμοποιήστε τα fat headers (`FAT_MAGIC`/`FAT_MAGIC_64`) για να εντοπίσετε το σωστό slice και offset πριν διατρέξετε τα Mach-O load commands.<sup>[[1]](#references)</sup>


## Minimal parsing outline (Python)

Το ακόλουθο είναι ένα compact outline που δείχνει τη ροή ελέγχου για τον εντοπισμό και την αποκωδικοποίηση των entitlements. Παραλείπει σκόπιμα robust bounds checks και πλήρη υποστήριξη fat binaries για λόγους συντομίας.<sup>[[1]](#references)</sup>
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
Συμβουλές χρήσης:
- Για τον χειρισμό fat binaries, διαβάστε πρώτα τα struct fat_header/fat_arch, επιλέξτε το επιθυμητό architecture slice και, στη συνέχεια, περάστε το subrange στο parse_entitlements.
- Σε macOS μπορείτε να επικυρώσετε τα αποτελέσματα με: codesign -d --entitlements :- /path/to/binary


## Παραδείγματα ευρημάτων

Τα privileged platform binaries συχνά ζητούν ευαίσθητα entitlements, όπως:<sup>[[1]](#references)</sup>
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

Η αναζήτηση αυτών σε μεγάλη κλίμακα μέσα σε firmware images είναι εξαιρετικά χρήσιμη για attack surface mapping και diffing μεταξύ releases/devices.


## Κλιμάκωση σε IPSWs (mounting και indexing)

Για την απαρίθμηση executables και την εξαγωγή entitlements σε μεγάλη κλίμακα χωρίς αποθήκευση ολόκληρων images:<sup>[[1]](#references)</sup>

- Χρησιμοποιήστε το ipsw tool του @blacktop για τη λήψη και το mounting των firmware filesystems. Το mounting αξιοποιεί το apfs-fuse, ώστε να μπορείτε να περιηγείστε σε APFS volumes χωρίς πλήρες extraction.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- Περιηγηθείτε στους mounted volumes για να εντοπίσετε Mach-O files (ελέγξτε το magic ή χρησιμοποιήστε file/otool), και στη συνέχεια κάντε parse τα entitlements και τα imported frameworks.
- Αποθηκεύστε μια normalized view σε relational database για να αποφύγετε τη γραμμική αύξηση του όγκου δεδομένων σε χιλιάδες IPSWs:
- executables, operating_system_versions, entitlements, frameworks
- many-to-many: executable↔OS version, executable↔entitlement, executable↔framework

Παράδειγμα query για την εμφάνιση όλων των OS versions που περιέχουν ένα δεδομένο executable name:
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = "launchd";
```
Σημειώσεις σχετικά με τη φορητότητα της DB (αν υλοποιείτε το δικό σας indexer):<sup>[[1]](#references)</sup>
- Χρησιμοποιήστε ένα ORM/abstraction (π.χ. SeaORM), ώστε ο κώδικας να παραμένει ανεξάρτητος από τη DB (SQLite/PostgreSQL).
- Το SQLite απαιτεί AUTOINCREMENT μόνο σε ένα INTEGER PRIMARY KEY· αν θέλετε i64 PKs στη Rust, δημιουργήστε entities ως i32 και μετατρέψτε τους τύπους, καθώς το SQLite αποθηκεύει εσωτερικά το INTEGER ως signed τιμή 8 byte.<sup>[[8]](#references)</sup>


## Open-source εργαλεία και references για entitlement hunting

- Firmware mount/download: https://github.com/blacktop/ipsw<sup>[[3]](#references)</sup>
- Βάσεις δεδομένων και references για entitlements:
- Entitlement DB του Jonathan Levin: https://newosxbook.com/ent.php<sup>[[4]](#references)</sup>
- entdb: https://github.com/ChiChou/entdb<sup>[[5]](#references)</sup>
- Indexer μεγάλης κλίμακας (Rust, self-hosted Web UI + OpenAPI): https://github.com/synacktiv/appledb_rs<sup>[[2]](#references)</sup>
- Apple headers για structures και constants:
- loader.h (Mach-O headers, load commands)
- cs_blobs.h (SuperBlob, GenericBlob, CodeDirectory)

Για περισσότερες πληροφορίες σχετικά με τα εσωτερικά του code signing (Code Directory, special slots, DER entitlements), δείτε: [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)


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
