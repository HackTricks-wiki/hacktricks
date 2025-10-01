# Mach-O Entitlements (İzinler) Çıkarma ve IPSW İndeksleme

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

Bu sayfa, Mach-O ikili dosyalarından programatik olarak entitlements (izinler) nasıl çıkarılacağını — LC_CODE_SIGNATURE içinde gezip code signing SuperBlob'u parse ederek — ve Apple IPSW firmware'leri üzerinde içeriklerini mount edip indeksleyerek adli arama/farklama için bunu nasıl ölçeklendireceğinizi ele alır.

Mach-O formatı ve code signing hakkında bir tazelemeye ihtiyacınız varsa, ayrıca bakınız: macOS code signing and SuperBlob internals.
- Check macOS code signing details (SuperBlob, Code Directory, special slots): [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- Check general Mach-O structures/load commands: [Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Entitlements in Mach-O: nerede bulunurlar

Entitlements, LC_CODE_SIGNATURE load command tarafından referans verilen ve __LINKEDIT segmentine yerleştirilen code signature verisinin içinde saklanır. İmza, birden fazla blob içeren CS_SuperBlob'dur (code directory, requirements, entitlements, CMS, vb.). Entitlements blob'u, verisi Apple Binary Property List (bplist00) olan bir CS_GenericBlob'dur ve entitlements anahtarlarını değerlerle eşler.

Ana yapılar (xnu'dan):
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
Önemli sabitler:
- LC_CODE_SIGNATURE cmd = 0x1d
- CS SuperBlob magic = 0xfade0cc0
- Entitlements blob type (CSMAGIC_EMBEDDED_ENTITLEMENTS) = 0xfade7171
- DER entitlements özel bir slotta (ör. -7) bulunabilir; özel slotlar ve DER entitlements ile ilgili notlar için macOS Code Signing sayfasına bakın

Not: Multi-arch (fat) binaries birden fazla Mach-O slice içerir. İncelemek istediğiniz mimariye ait slice'ı seçip yükleme komutları (load commands) üzerinde dolaşmalısınız.


## Extraction steps (generic, lossless-enough)

1) Mach-O header'ını ayrıştırın; ncmds kadar load_command kaydı üzerinde yineleyin.
2) LC_CODE_SIGNATURE'ı bulun; linkedit_data_command.dataoff/datasize değerlerini okuyarak __LINKEDIT içine yerleştirilmiş Code Signing SuperBlob'u haritalayın.
3) CS_SuperBlob.magic == 0xfade0cc0 olduğunu doğrulayın; count adet CS_BlobIndex girdisi üzerinde yineleyin.
4) index.type == 0xfade7171 (embedded entitlements) olan girdiyi bulun. İşaret edilen CS_GenericBlob'u okuyun ve verisini Apple binary plist (bplist00) olarak ayrıştırıp anahtar/değer entitlements elde edin.

Uygulama notları:
- Code signature yapıları big-endian alanlar kullanır; little-endian host'larda ayrıştırırken byte sırasını ters çevirin.
- Entitlements GenericBlob verisi kendisi bir binary plist'tir (standart plist kütüphaneleriyle işlenir).
- Bazı iOS binary'leri DER entitlements taşıyabilir; ayrıca bazı store/slot'lar platform/versiyona göre farklılık gösterebilir. Gerekirse hem standart hem DER entitlements'ı çapraz kontrol edin.
- Fat binary'ler için, Mach-O load commands üzerinde dolaşmadan önce doğru slice ve offset'i bulmak amacıyla fat başlıkları (FAT_MAGIC/FAT_MAGIC_64) kullanın.


## Minimal parsing outline (Python)

Aşağıdakiler, entitlements'ı bulup decode etmek için kontrol akışını gösteren kompakt bir taslaktır. Kısalık için kasıtlı olarak sağlam sınır kontrolleri ve tam fat binary desteği hariç bırakılmıştır.
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
- Bağlı hacimleri gezerek Mach-O dosyalarını bul (magic'i kontrol et ve/veya file/otool kullan), sonra entitlements ve imported frameworks'i parse et.
- Binlerce IPSWs üzerinde lineer büyümeyi önlemek için normalize edilmiş bir görünümü ilişkisel bir veritabanına sakla:
- executables, operating_system_versions, entitlements, frameworks
- çoktan-çoğa: executable↔OS version, executable↔entitlement, executable↔framework

Verilen bir executable adını içeren tüm OS versiyonlarını listelemek için örnek sorgu:
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


## Açık kaynaklı araçlar ve referanslar (entitlement hunting için)

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
