# Витягування Entitlements із Mach-O та індексування IPSW

## Огляд

На цій сторінці описано, як програмно витягувати entitlements із Mach-O бінарних файлів, проходячи через LC_CODE_SIGNATURE і аналізуючи code signing SuperBlob, а також як масштабувати цей процес для Apple IPSW firmware, монту​​ючи та індексуючи їхній вміст для forensic-пошуку й порівняння.

Якщо вам потрібно повторити формат Mach-O та code signing, див. також: macOS code signing і внутрішню будову SuperBlob.
- Ознайомтеся з деталями macOS code signing (SuperBlob, Code Directory, special slots): [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- Ознайомтеся із загальними структурами Mach-O та load commands: [Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Entitlements у Mach-O: де вони зберігаються

Entitlements зберігаються всередині даних code signature, на які посилається load command LC_CODE_SIGNATURE, і розміщуються в сегменті __LINKEDIT. Підпис є CS_SuperBlob, що містить кілька blob-об’єктів (code directory, requirements, entitlements, CMS тощо). Entitlements blob є CS_GenericBlob, дані якого являють собою серіалізований property list, що зіставляє ключі entitlements зі значеннями; парсери мають підтримувати кодування як XML plist, так і binary plist.<sup>[[1]](#references)[[6]](#references)</sup>

Ключові структури (із xnu):<sup>[[6]](#references)[[7]](#references)</sup>
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
Важливі константи із заголовків Apple включають:<sup>[[6]](#references)[[7]](#references)</sup>
- LC_CODE_SIGNATURE cmd = 0x1d
- CS SuperBlob magic = 0xfade0cc0
- Entitlements index slot (`CSSLOT_ENTITLEMENTS`) = 5; blob у цьому slot має magic `CSMAGIC_EMBEDDED_ENTITLEMENTS` = 0xfade7171
- DER entitlements використовують slot `CSSLOT_DER_ENTITLEMENTS` = 7 і blob magic `CSMAGIC_EMBEDDED_DER_ENTITLEMENTS` = 0xfade7172

Примітка: Multi-arch (fat) бінарники містять кілька Mach-O slices. Потрібно вибрати slice для потрібної архітектури, а потім пройтися його load commands.


## Кроки extraction (generic, достатньо lossless)

1) Розібрати Mach-O header; виконати ітерацію по `ncmds` записах load_command.
2) Знайти LC_CODE_SIGNATURE; прочитати `linkedit_data_command.dataoff/datasize`, щоб відобразити Code Signing SuperBlob, розміщений у __LINKEDIT.
3) Перевірити, що `CS_SuperBlob.magic == 0xfade0cc0`; виконати ітерацію по `count` записах CS_BlobIndex.
4) Знайти `index.type == CSSLOT_ENTITLEMENTS` (5), потім перевірити, що вказаний `CS_GenericBlob` має magic `CSMAGIC_EMBEDDED_ENTITLEMENTS` (0xfade7171). Розібрати його data як property list, щоб отримати key/value entitlements.<sup>[[1]](#references)[[6]](#references)</sup>

Примітки щодо реалізації:
- Структури code signature використовують big-endian поля; під час parsing на little-endian hosts потрібно поміняти порядок байтів.
- `GenericBlob` entitlements містить serialized plist; стандартні plist libraries можуть обробляти її XML- або binary-представлення.
- Деякі iOS бінарники можуть містити DER entitlements; XNU відкриває окремий тип DER blob, а представлення або slots entitlements можуть відрізнятися залежно від platforms і versions, тому за потреби перевіряйте стандартні та DER entitlements повторно.<sup>[[6]](#references)</sup>
- Для fat бінарників використовуйте fat headers (FAT_MAGIC/FAT_MAGIC_64), щоб знайти правильний slice та offset перед проходженням Mach-O load commands.


## Мінімальний parsing outline (Python)

Нижче наведено компактний outline, що демонструє control flow для пошуку та декодування entitlements. Для стислості він навмисно не містить надійних bounds checks і повної підтримки fat бінарників.<sup>[[6]](#references)[[7]](#references)</sup>
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
Поради щодо використання:
- Щоб обробляти fat binaries, спочатку прочитайте struct fat_header/fat_arch, виберіть потрібний architecture slice, а потім передайте subrange до parse_entitlements.
- У macOS можна перевірити результати за допомогою: codesign -d --entitlements :- /path/to/binary


## Приклади результатів

У вихідній статті показано такі entitlements у бінарному файлі `launchd` для macOS 14.0:<sup>[[1]](#references)</sup>
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

Пошук цих entitlements у великому масштабі по образах firmware надзвичайно цінний для mapping attack surface і порівняння відмінностей між релізами та пристроями.


## Масштабування між IPSW (монтування та індексація)

Щоб перелічувати executables і видобувати entitlements у великому масштабі без зберігання повних образів:<sup>[[1]](#references)</sup>

- Використовуйте ipsw tool від @blacktop для завантаження та монтування файлових систем firmware. Монтування використовує apfs-fuse, тому можна переглядати APFS volumes без повного видобування.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- Пройдіть змонтовані томи, щоб знайти файли Mach-O (перевірте magic та/або використайте `file`/`otool`), після чого проаналізуйте entitlements та імпортовані frameworks.
- Збережіть нормалізоване представлення в реляційній базі даних, щоб уникнути лінійного зростання обсягу даних під час роботи з тисячами IPSW:
- executables, operating_system_versions, entitlements, frameworks
- зв’язки багато-до-багатьох: executable↔OS version, executable↔entitlement, executable↔framework

Приклад запиту для перелічення всіх версій ОС, що містять виконуваний файл із заданою назвою (адаптовано з appledb_rs):<sup>[[1]](#references)</sup>
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = 'launchd';
```
Нотатки щодо переносимості DB (якщо ви реалізуєте власний indexer):<sup>[[1]](#references)</sup>
- Використовуйте ORM/abstraction (наприклад, SeaORM), щоб код не залежав від DB (SQLite/PostgreSQL).
- SQLite дозволяє `AUTOINCREMENT` лише для `INTEGER PRIMARY KEY`; цей ключ є псевдонімом для знакового 64-бітного ROWID, хоча SQLite може використовувати на диску цілі числа меншої розрядності. Якщо згенеровані SeaORM Rust entities потребують ідентифікатори i64, генеруйте entities як i32 і конвертуйте типи на межі.<sup>[[1]](#references)[[8]](#references)[[9]](#references)</sup>


## Open-source інструменти та references для пошуку entitlements

- Монтування/завантаження Firmware: https://github.com/blacktop/ipsw.<sup>[[3]](#references)</sup>
- Бази даних entitlements і references:
- DB entitlements Jonathan Levin: https://newosxbook.com/ent.php.<sup>[[4]](#references)</sup>
- entdb: https://github.com/ChiChou/entdb.<sup>[[5]](#references)</sup>
- Indexer для великомасштабного використання (Rust, self-hosted Web UI + OpenAPI): https://github.com/synacktiv/appledb_rs.<sup>[[2]](#references)</sup>
- Apple headers для структур і констант:
- loader.h (Mach-O headers, load commands)
- cs_blobs.h (SuperBlob, GenericBlob, CodeDirectory)

Докладніше про внутрішню будову code signing (Code Directory, special slots, DER entitlements) див. у: [Code signing у macOS](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)


## References

- [1] [Corentin Liaud (Synacktiv), appledb_rs: інструмент підтримки досліджень для Apple platforms](https://www.synacktiv.com/publications/appledbrs-un-outil-daide-a-la-recherche-sur-plateformes-apple.html)
- [2] [synacktiv/appledb_rs](https://github.com/synacktiv/appledb_rs)
- [3] [blacktop/ipsw](https://github.com/blacktop/ipsw)
- [4] [DB entitlements Jonathan Levin](https://newosxbook.com/ent.php)
- [5] [ChiChou/entdb](https://github.com/ChiChou/entdb)
- [6] [XNU cs_blobs.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [7] [XNU mach-o/loader.h](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [8] [Типи даних SQLite](https://sqlite.org/datatype3.html)
- [9] [SQLite Autoincrement](https://sqlite.org/autoinc.html)
{{#include ../../../banners/hacktricks-training.md}}
