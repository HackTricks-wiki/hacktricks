# Mach-O Entitlements Çıkarma ve IPSW Indexleme

## Genel Bakış

Bu sayfada, LC_CODE_SIGNATURE üzerinden ilerleyip code signing SuperBlob'unu ayrıştırarak Mach-O binary'lerinden entitlements bilgilerinin programatik olarak nasıl çıkarılacağı ve adli arama/diff işlemleri için Apple IPSW firmware'leri bağlayıp içeriklerini indexleyerek bu işlemin nasıl ölçeklendirileceği ele alınmaktadır.

Mach-O formatı ve code signing hakkında hızlı bir hatırlatmaya ihtiyacınız varsa şu kaynaklara da bakabilirsiniz: macOS code signing ve SuperBlob internals.
- macOS code signing ayrıntılarını inceleyin (SuperBlob, Code Directory, special slots): [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- Genel Mach-O structures/load commands bilgilerini inceleyin: [Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Mach-O içindeki Entitlements: nerede bulunurlar

Entitlements bilgileri, LC_CODE_SIGNATURE load command tarafından referans verilen ve __LINKEDIT segmentine yerleştirilen code signature verilerinin içinde saklanır. Signature, birden fazla blob (code directory, requirements, entitlements, CMS vb.) içeren bir CS_SuperBlob'dur. Entitlements blob'u, entitlement key'lerini değerlerle eşleyen serialize edilmiş bir property list içeren bir CS_GenericBlob'dur; parser'lar hem XML hem de binary plist encoding'lerini kabul etmelidir.<sup>[[1]](#references)[[6]](#references)</sup>

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
uint32_t type;    /* slot type, e.g. CSSLOT_ENTITLEMENTS = 5 */
uint32_t offset;  /* offset of entry */
} CS_BlobIndex;

typedef struct __SC_GenericBlob {
uint32_t magic;   /* blob magic, e.g. CSMAGIC_EMBEDDED_ENTITLEMENTS */
uint32_t length;
char data[];      /* serialized plist containing entitlements */
} CS_GenericBlob;
```
Apple headers içindeki önemli sabitler şunlardır:<sup>[[6]](#references)[[7]](#references)</sup>
- LC_CODE_SIGNATURE cmd = 0x1d
- CS SuperBlob magic = 0xfade0cc0
- Entitlements index slot (`CSSLOT_ENTITLEMENTS`) = 5; bu slotta bulunan blob’un magic değeri `CSMAGIC_EMBEDDED_ENTITLEMENTS` = 0xfade7171
- DER entitlements, `CSSLOT_DER_ENTITLEMENTS` = 7 slotunu ve `CSMAGIC_EMBEDDED_DER_ENTITLEMENTS` = 0xfade7172 blob magic değerini kullanır

Not: Multi-arch (fat) binary’ler birden fazla Mach-O slice içerir. İncelemek istediğiniz architecture için slice’ı seçmeli ve ardından onun load command’ları üzerinde ilerlemelisiniz.


## Extraction adımları (genel, yeterince kayıpsız)

1) Mach-O header’ını parse edin; `load_command` kayıtları için `ncmds` sayısı kadar ilerleyin.
2) LC_CODE_SIGNATURE konumunu bulun; __LINKEDIT içine yerleştirilen Code Signing SuperBlob’u eşlemek için `linkedit_data_command.dataoff/datasize` değerlerini okuyun.
3) `CS_SuperBlob.magic == 0xfade0cc0` olduğunu doğrulayın; `CS_BlobIndex` girişlerinin `count` sayısı kadar ilerleyin.
4) `index.type == CSSLOT_ENTITLEMENTS` (5) konumunu bulun, ardından gösterilen `CS_GenericBlob` değerinin magic değerinin `CSMAGIC_EMBEDDED_ENTITLEMENTS` (0xfade7171) olduğunu doğrulayın. Key/value entitlements değerlerini elde etmek için verisini property list olarak parse edin.<sup>[[1]](#references)[[6]](#references)</sup>

Implementation notes:
- Code signature structures big-endian alanlar kullanır; little-endian host’larda parse ederken byte order’ı değiştirin.
- Entitlements `GenericBlob`, serialize edilmiş bir plist içerir; standart plist library’leri XML veya binary gösterimini işleyebilir.
- Bazı iOS binary’leri DER entitlements içerebilir; XNU ayrı bir DER blob type sunar ve entitlement gösterimleri veya slot’ları platformlar ve version’lar arasında farklılık gösterebilir. Bu nedenle gerektiğinde standart ve DER entitlements değerlerini karşılaştırın.<sup>[[6]](#references)</sup>
- Fat binary’lerde, Mach-O load command’ları üzerinde ilerlemeden önce doğru slice’ı ve offset’i bulmak için fat header’larını (FAT_MAGIC/FAT_MAGIC_64) kullanın.


## Minimal parsing outline (Python)

Aşağıdaki kısa outline, entitlements değerlerini bulup decode etmek için control flow’u gösterir. Kısalık amacıyla sağlam bounds check’leri ve tam fat binary desteği kasıtlı olarak dahil edilmemiştir.<sup>[[6]](#references)[[7]](#references)</sup>
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
Kullanım ipuçları:
- fat binaries işlemek için önce struct fat_header/fat_arch yapılarını okuyun, istenen architecture slice'ı seçin, ardından alt aralığı parse_entitlements'a geçirin.
- macOS'ta sonuçları şu komutla doğrulayabilirsiniz: codesign -d --entitlements :- /path/to/binary


## Örnek bulgular

Kaynak makale, macOS 14.0 `launchd` binary'sinde şu entitlements'ları gösterir:<sup>[[1]](#references)</sup>
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

Bunları firmware image'ları genelinde aramak, attack surface mapping ve farklı release/device'lar arasındaki karşılaştırmalar için son derece değerlidir.


## IPSW'ler genelinde ölçeklendirme (mounting ve indexing)

Tam image'ları depolamadan executable'ları enumerate etmek ve entitlements'ları geniş ölçekte çıkarmak için:<sup>[[1]](#references)</sup>

- Firmware filesystem'larını download etmek ve mount etmek için @blacktop tarafından geliştirilen ipsw tool'unu kullanın. Mounting, apfs-fuse'dan yararlanır; böylece tam extraction yapmadan APFS volume'larında gezinebilirsiniz.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- Mach-O dosyalarını bulmak için bağlı volume'lar üzerinde dolaşın (magic değerini kontrol edin ve/veya `file`/`otool` kullanın), ardından entitlements ve içe aktarılan framework'leri ayrıştırın.
- Binlerce IPSW genelinde lineer büyümeyi önlemek için normalize edilmiş görünümü ilişkisel bir database'e kalıcı olarak kaydedin:
- executables, operating_system_versions, entitlements, frameworks
- many-to-many: executable↔OS version, executable↔entitlement, executable↔framework

Belirli bir executable adına sahip tüm OS version'larını listelemek için örnek query (`appledb_rs`'den uyarlanmıştır):<sup>[[1]](#references)</sup>
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = 'launchd';
```
Kendi indexer’ınızı geliştiriyorsanız DB taşınabilirliğiyle ilgili notlar:<sup>[[1]](#references)</sup>
- Code’u DB’den bağımsız (SQLite/PostgreSQL) tutmak için bir ORM/abstraction (ör. SeaORM) kullanın.
- SQLite, `AUTOINCREMENT` için yalnızca `INTEGER PRIMARY KEY` kullanımına izin verir; bu anahtar, işaretli 64 bitlik bir ROWID için alias görevi görür, ancak SQLite disk üzerinde daha küçük integer genişlikleri kullanabilir. SeaORM tarafından oluşturulan Rust entity’leri i64 ID’lere ihtiyaç duyuyorsa entity’leri i32 olarak oluşturun ve boundary’de type conversion yapın.<sup>[[1]](#references)[[8]](#references)[[9]](#references)</sup>


## Entitlement hunting için Open-source tooling ve referanslar

- Firmware mount/download: https://github.com/blacktop/ipsw.<sup>[[3]](#references)</sup>
- Entitlement database’leri ve referanslar:
- Jonathan Levin’in entitlement DB’si: https://newosxbook.com/ent.php.<sup>[[4]](#references)</sup>
- entdb: https://github.com/ChiChou/entdb.<sup>[[5]](#references)</sup>
- Large-scale indexer (Rust, self-hosted Web UI + OpenAPI): https://github.com/synacktiv/appledb_rs.<sup>[[2]](#references)</sup>
- Yapılar ve constant’lar için Apple header’ları:
- loader.h (Mach-O header’ları, load command’ler)
- cs_blobs.h (SuperBlob, GenericBlob, CodeDirectory)

Code signing internals (Code Directory, special slot’lar, DER entitlements) hakkında daha fazla bilgi için bkz.: [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)


## References

- [1] [Corentin Liaud (Synacktiv), Apple platformları için bir research support tool olan appledb_rs](https://www.synacktiv.com/publications/appledbrs-un-outil-daide-a-la-recherche-sur-plateformes-apple.html)
- [2] [synacktiv/appledb_rs](https://github.com/synacktiv/appledb_rs)
- [3] [blacktop/ipsw](https://github.com/blacktop/ipsw)
- [4] [Jonathan Levin’in entitlement DB’si](https://newosxbook.com/ent.php)
- [5] [ChiChou/entdb](https://github.com/ChiChou/entdb)
- [6] [XNU cs_blobs.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [7] [XNU mach-o/loader.h](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [8] [SQLite Veri Türleri](https://sqlite.org/datatype3.html)
- [9] [SQLite Autoincrement](https://sqlite.org/autoinc.html)
{{#include ../../../banners/hacktricks-training.md}}
