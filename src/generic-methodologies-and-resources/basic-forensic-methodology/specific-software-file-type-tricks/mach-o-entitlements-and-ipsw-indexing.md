# Витягування Entitlements з Mach-O та індексація IPSW

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

На цій сторінці описано, як програмно витягувати entitlements із Mach-O binaries шляхом проходження LC_CODE_SIGNATURE і парсингу code signing SuperBlob, а також як масштабувати цей процес для Apple IPSW firmwares, монтувати їхній вміст та індексувати його для forensic-пошуку й diff.

Якщо вам потрібно освіжити знання про формат Mach-O і code signing, також перегляньте: macOS code signing та внутрішню будову SuperBlob.
- Перегляньте деталі macOS code signing (SuperBlob, Code Directory, special slots): [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- Перегляньте загальні структури Mach-O/load commands: [Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Entitlements у Mach-O: де вони зберігаються

Entitlements зберігаються всередині code signature data, на яку посилається load command LC_CODE_SIGNATURE і яка розміщена в сегменті __LINKEDIT. Signature є CS_SuperBlob, що містить кілька blobs (code directory, requirements, entitlements, CMS тощо). Entitlements blob є CS_GenericBlob, чиї data — це Apple Binary Property List (bplist00), що відображає entitlement keys на values.<sup>[[1]](#references)</sup>

Ключові структури (з xnu):<sup>[[6]](#references)[[7]](#references)</sup>
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
Важливі константи:
- LC_CODE_SIGNATURE cmd = 0x1d
- CS SuperBlob magic = 0xfade0cc0
- Entitlements blob type (CSMAGIC_EMBEDDED_ENTITLEMENTS) = 0xfade7171
- DER entitlements можуть бути присутні через спеціальний слот (наприклад, -7); див. сторінку macOS Code Signing щодо спеціальних слотів і приміток про DER entitlements

Примітка: Multi-arch (fat) бінарні файли містять кілька Mach-O зрізів. Потрібно вибрати зріз для потрібної архітектури, а потім пройтися його load commands.


## Кроки вилучення (загальні, достатньо lossless)

1) Розібрати Mach-O header; виконати ітерацію по ncmds записах load_command.
2) Знайти LC_CODE_SIGNATURE; прочитати linkedit_data_command.dataoff/datasize, щоб відобразити Code Signing SuperBlob, розміщений у __LINKEDIT.
3) Перевірити, що CS_SuperBlob.magic == 0xfade0cc0; виконати ітерацію по count записах CS_BlobIndex.
4) Знайти index.type == 0xfade7171 (embedded entitlements). Прочитати вказаний CS_GenericBlob і розібрати його data як Apple binary plist (bplist00), щоб отримати key/value entitlements.<sup>[[1]](#references)</sup>

Примітки щодо реалізації:
- Структури code signature використовують поля у big-endian; під час розбору на little-endian hosts потрібно поміняти порядок байтів.
- Дані Entitlements GenericBlob самі є binary plist (обробляються стандартними plist libraries).
- Деякі iOS бінарні файли можуть містити DER entitlements; також деякі stores/slots відрізняються залежно від platform/version. За потреби перевіряйте і стандартні, і DER entitlements.
- Для fat бінарних файлів використовуйте fat headers (FAT_MAGIC/FAT_MAGIC_64), щоб знайти правильний slice та offset перед проходженням Mach-O load commands.<sup>[[1]](#references)</sup>


## Мінімальний outline розбору (Python)

Наведений нижче компактний outline показує control flow для пошуку та декодування entitlements. Для стислості він навмисно не містить надійних bounds checks і повної підтримки fat бінарних файлів.<sup>[[1]](#references)</sup>
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
Поради щодо використання:
- Для роботи з fat binaries спочатку прочитайте struct fat_header/fat_arch, виберіть потрібний архітектурний slice, а потім передайте піддіапазон до parse_entitlements.
- У macOS результати можна перевірити за допомогою: codesign -d --entitlements :- /path/to/binary


## Приклади результатів

Привілейовані platform binaries часто запитують чутливі entitlements, як-от:<sup>[[1]](#references)</sup>
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

Пошук цих entitlements у масштабі всіх firmware images є надзвичайно цінним для картографування attack surface і порівняння відмінностей між релізами та пристроями.


## Масштабування на IPSW (монтування та індексація)

Щоб перераховувати executable-файли та видобувати entitlements у масштабі без зберігання повних images:<sup>[[1]](#references)</sup>

- Використовуйте інструмент ipsw від @blacktop для завантаження та монтування firmware filesystems. Монтування використовує apfs-fuse, тому можна переглядати APFS volumes без повного extraction.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- Обійти змонтовані томи, щоб знайти Mach-O-файли (перевірити magic та/або використати file/otool), а потім проаналізувати entitlements і імпортовані frameworks.
- Зберігати нормалізоване представлення в реляційній базі даних, щоб уникнути лінійного зростання обсягу даних для тисяч IPSW:
- executables, operating_system_versions, entitlements, frameworks
- зв’язки багато-до-багатьох: executable↔OS version, executable↔entitlement, executable↔framework

Приклад запиту для переліку всіх версій ОС, що містять executable із заданою назвою:
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = "launchd";
```
Нотатки щодо переносимості DB (якщо ви реалізуєте власний indexer):<sup>[[1]](#references)</sup>
- Використовуйте ORM/abstraction (наприклад, SeaORM), щоб код не залежав від DB (SQLite/PostgreSQL).
- SQLite вимагає AUTOINCREMENT лише для INTEGER PRIMARY KEY; якщо ви хочете використовувати i64 PK у Rust, генеруйте entities як i32 і конвертуйте типи, оскільки SQLite внутрішньо зберігає INTEGER як 8-байтове signed значення.<sup>[[8]](#references)</sup>


## Open-source інструменти та references для пошуку entitlement

- Mount/download firmware: https://github.com/blacktop/ipsw
- Бази даних entitlement та references:
- Jonathan Levin’s entitlement DB: https://newosxbook.com/ent.php
- entdb: https://github.com/ChiChou/entdb
- Large-scale indexer (Rust, self-hosted Web UI + OpenAPI): https://github.com/synacktiv/appledb_rs
- Заголовки Apple для структур і constants:
- loader.h (Mach-O headers, load commands)
- cs_blobs.h (SuperBlob, GenericBlob, CodeDirectory)

Докладніше про внутрішню будову code signing (Code Directory, special slots, DER entitlements) див. [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)


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
