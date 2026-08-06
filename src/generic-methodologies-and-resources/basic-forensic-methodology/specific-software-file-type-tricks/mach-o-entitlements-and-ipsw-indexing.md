# Mach-O Entitlements Çıkarma ve IPSW Indexleme

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

Bu sayfa, LC_CODE_SIGNATURE üzerinden ilerleyip code signing SuperBlob'unu ayrıştırarak Mach-O binary'lerinden programatik olarak entitlements çıkarma ve adli arama/diff için Apple IPSW firmware'leri genelinde içeriklerini mount edip indexleyerek bu işlemi ölçeklendirme yöntemlerini kapsar.

Mach-O formatı ve code signing hakkında kısa bir hatırlatmaya ihtiyacınız varsa şuna da bakabilirsiniz: macOS code signing ve SuperBlob internals.
- macOS code signing ayrıntılarını inceleyin (SuperBlob, Code Directory, special slots): [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- Genel Mach-O yapıları/load command'larını inceleyin: [Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Mach-O'da Entitlements: nerede bulunurlar

Entitlements, LC_CODE_SIGNATURE load command tarafından referans verilen ve __LINKEDIT segmentine yerleştirilen code signature verilerinin içinde saklanır. Signature, birden fazla blob (code directory, requirements, entitlements, CMS vb.) içeren bir CS_SuperBlob'dur. Entitlements blob'u, entitlement anahtarlarını değerlerle eşleyen bir Apple Binary Property List'tir (bplist00).<sup>[[1]](#references)</sup>

Temel yapılar (xnu'dan):<sup>[[6]](#references)[[7]](#references)</sup>
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
- DER entitlements, özel bir slot (ör. -7) üzerinden mevcut olabilir; özel slotlar ve DER entitlements notları için macOS Code Signing sayfasına bakın

Not: Multi-arch (fat) binary'ler birden fazla Mach-O slice içerir. İncelemek istediğiniz architecture için slice'ı seçmeli ve ardından load commands'leri üzerinde ilerlemelisiniz.


## Extraction steps (generic, lossless-enough)

1) Mach-O header'ını parse edin; ncmds kadar load_command kaydını iterate edin.
2) LC_CODE_SIGNATURE'ı bulun; __LINKEDIT içine yerleştirilmiş Code Signing SuperBlob'ı map etmek için linkedit_data_command.dataoff/datasize değerlerini okuyun.
3) CS_SuperBlob.magic == 0xfade0cc0 olduğunu doğrulayın; CS_BlobIndex girdilerinin count değerini iterate edin.
4) index.type == 0xfade7171 (embedded entitlements) girdisini bulun. İşaret edilen CS_GenericBlob'ı okuyun ve verisini Apple binary plist (bplist00) olarak parse ederek key/value entitlements değerlerini alın.<sup>[[1]](#references)</sup>

Implementation notes:
- Code signature yapıları big-endian alanlar kullanır; little-endian host'larda parse ederken byte order'ı değiştirin.
- Entitlements GenericBlob verisinin kendisi bir binary plist'tir (standart plist library'leri tarafından işlenir).
- Bazı iOS binary'leri DER entitlements taşıyabilir; ayrıca bazı store/slot'lar platformlar ve version'lar arasında farklılık gösterir. Gerektiğinde hem standard hem de DER entitlements'ı karşılaştırın.
- Fat binary'lerde, Mach-O load commands'leri üzerinde ilerlemeden önce doğru slice'ı ve offset'i bulmak için fat header'ları (FAT_MAGIC/FAT_MAGIC_64) kullanın.<sup>[[1]](#references)</sup>


## Minimal parsing outline (Python)

Aşağıda, entitlements'ı bulup decode etmek için control flow'u gösteren kısa bir outline yer alır. Kısalık amacıyla robust bounds check'ler ve full fat binary desteği kasıtlı olarak dahil edilmemiştir.<sup>[[1]](#references)</sup>
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
Kullanım ipuçları:
- fat binaries işlemek için önce struct fat_header/fat_arch yapılarını okuyun, istenen architecture slice'ı seçin, ardından alt aralığı parse_entitlements'a aktarın.
- macOS üzerinde sonuçları şu komutla doğrulayabilirsiniz: codesign -d --entitlements :- /path/to/binary


## Örnek bulgular

Privileged platform binaries genellikle aşağıdaki gibi hassas entitlements talep eder:<sup>[[1]](#references)</sup>
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

Firmware images genelinde bunları büyük ölçekte aramak, attack surface mapping ve farklı release/device sürümleri arasında diffing yapmak için son derece değerlidir.


## IPSW genelinde ölçeklendirme (mounting ve indexing)

Full images depolamadan executables listelemek ve entitlements'ı büyük ölçekte çıkarmak için:<sup>[[1]](#references)</sup>

- Firmware filesystems indirmek ve mount etmek için @blacktop tarafından geliştirilen ipsw tool'u kullanın. Mounting, apfs-fuse kullanır; bu sayede full extraction gerçekleştirmeden APFS volumes'ları tarayabilirsiniz.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- Mach-O dosyalarını bulmak için mount edilmiş volume'lar üzerinde dolaşın (magic değerini kontrol edin ve/veya file/otool kullanın), ardından entitlements ve imported frameworks'leri ayrıştırın.
- Binlerce IPSW genelinde lineer büyümeyi önlemek için normalize edilmiş bir görünümü relational database'e kaydedin:
- executables, operating_system_versions, entitlements, frameworks
- many-to-many: executable↔OS version, executable↔entitlement, executable↔framework

Belirli bir executable adı bulunan tüm OS version'ları listelemek için örnek query:
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = "launchd";
```
DB portability hakkında notlar (kendi indexer'ınızı uyguluyorsanız):<sup>[[1]](#references)</sup>
- Code'u DB-agnostic tutmak için bir ORM/abstraction (ör. SeaORM) kullanın (SQLite/PostgreSQL).
- SQLite, AUTOINCREMENT'i yalnızca bir INTEGER PRIMARY KEY üzerinde gerektirir; Rust'ta i64 PK'ler istiyorsanız entity'leri i32 olarak oluşturun ve type'ları dönüştürün; SQLite, INTEGER'ı dahili olarak 8-byte signed biçiminde depolar.<sup>[[8]](#references)</sup>


## Entitlement hunting için open-source tooling ve referanslar

- Firmware mount/download: https://github.com/blacktop/ipsw
- Entitlement veritabanları ve referanslar:
- Jonathan Levin’s entitlement DB: https://newosxbook.com/ent.php
- entdb: https://github.com/ChiChou/entdb
- Large-scale indexer (Rust, self-hosted Web UI + OpenAPI): https://github.com/synacktiv/appledb_rs
- Yapılar ve constant'lar için Apple header'ları:
- loader.h (Mach-O headers, load commands)
- cs_blobs.h (SuperBlob, GenericBlob, CodeDirectory)

Code signing internals (Code Directory, special slots, DER entitlements) hakkında daha fazla bilgi için: [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)


## Referanslar

- [1] [appledb_rs: a research support tool for Apple platforms](https://www.synacktiv.com/publications/appledbrs-un-outil-daide-a-la-recherche-sur-plateformes-apple.html)
- [2] [synacktiv/appledb_rs](https://github.com/synacktiv/appledb_rs)
- [3] [blacktop/ipsw](https://github.com/blacktop/ipsw)
- [4] [Jonathan Levin’s entitlement DB](https://newosxbook.com/ent.php)
- [5] [ChiChou/entdb](https://github.com/ChiChou/entdb)
- [6] [XNU cs_blobs.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [7] [XNU mach-o/loader.h](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [8] [SQLite Datatypes](https://sqlite.org/datatype3.html)

{{#include ../../../banners/hacktricks-training.md}}
