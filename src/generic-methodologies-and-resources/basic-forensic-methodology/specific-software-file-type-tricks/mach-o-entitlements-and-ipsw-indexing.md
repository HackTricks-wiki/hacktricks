# Ekstrakcja Entitlements z Mach-O i indeksowanie IPSW

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Ta strona opisuje, jak programowo wyodrębniać entitlements z plików binarnych Mach-O poprzez przechodzenie przez LC_CODE_SIGNATURE i parsowanie code signing SuperBlob, a także jak skalować ten proces dla firmware Apple IPSW poprzez montowanie i indeksowanie ich zawartości na potrzeby wyszukiwania/diff w analizie forensic.

Jeśli potrzebujesz przypomnienia dotyczącego formatu Mach-O i code signing, zobacz także: macOS code signing i mechanizmy wewnętrzne SuperBlob.
- Sprawdź szczegóły macOS code signing (SuperBlob, Code Directory, special slots): [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- Sprawdź ogólne struktury Mach-O/load commands: [Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Entitlements w Mach-O: gdzie się znajdują

Entitlements są przechowywane wewnątrz danych code signature, do których odwołuje się load command LC_CODE_SIGNATURE, i umieszczone w segmencie __LINKEDIT. Sygnatura jest CS_SuperBlob zawierającym wiele blobów (code directory, requirements, entitlements, CMS itd.). Blob entitlements to CS_GenericBlob, którego dane są serializowaną property list mapującą klucze entitlement na wartości; parsery powinny akceptować zarówno kodowanie XML, jak i binarne kodowanie plist.<sup>[[1]](#references)[[6]](#references)</sup>

Kluczowe struktury (z xnu):<sup>[[6]](#references)[[7]](#references)</sup>
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
Ważne stałe z nagłówków Apple obejmują:<sup>[[6]](#references)[[7]](#references)</sup>
- LC_CODE_SIGNATURE cmd = 0x1d
- CS SuperBlob magic = 0xfade0cc0
- Entitlements index slot (`CSSLOT_ENTITLEMENTS`) = 5; blob w tym slocie ma magic `CSMAGIC_EMBEDDED_ENTITLEMENTS` = 0xfade7171
- DER entitlements używają slotu `CSSLOT_DER_ENTITLEMENTS` = 7 oraz magic blobu `CSMAGIC_EMBEDDED_DER_ENTITLEMENTS` = 0xfade7172

Uwaga: Pliki binarne Multi-arch (fat) zawierają wiele slices Mach-O. Musisz wybrać slice dla architektury, którą chcesz sprawdzić, a następnie przejść przez jej load commands.


## Kroki ekstrakcji (ogólne, wystarczająco bezstratne)

1) Przeanalizuj nagłówek Mach-O; iteruj po liczbie rekordów load_command określonej przez ncmds.
2) Zlokalizuj LC_CODE_SIGNATURE; odczytaj dataoff/datasize z linkedit_data_command, aby zmapować Code Signing SuperBlob umieszczony w __LINKEDIT.
3) Sprawdź, czy CS_SuperBlob.magic == 0xfade0cc0; iteruj po count wpisach CS_BlobIndex.
4) Zlokalizuj `index.type == CSSLOT_ENTITLEMENTS` (5), a następnie sprawdź, czy wskazany `CS_GenericBlob` ma magic `CSMAGIC_EMBEDDED_ENTITLEMENTS` (0xfade7171). Przeanalizuj jego dane jako property list, aby uzyskać entitlements w formie klucz/wartość.<sup>[[1]](#references)[[6]](#references)</sup>

Uwagi dotyczące implementacji:
- Struktury code signature używają pól big-endian; zamień kolejność bajtów podczas parsowania na hostach little-endian.
- `GenericBlob` entitlements zawiera zserializowany plist; standardowe biblioteki plist mogą obsługiwać jego reprezentację XML lub binarną.
- Niektóre pliki binarne iOS mogą zawierać DER entitlements; XNU udostępnia osobny typ DER blob, a reprezentacje lub sloty entitlements mogą różnić się między platformami i wersjami, dlatego w razie potrzeby porównaj standardowe i DER entitlements.<sup>[[6]](#references)</sup>
- W przypadku plików binarnych fat użyj nagłówków fat (FAT_MAGIC/FAT_MAGIC_64), aby zlokalizować właściwy slice i offset przed przejściem przez load commands Mach-O.


## Minimalny zarys parsowania (Python)

Poniżej przedstawiono zwięzły zarys pokazujący przepływ sterowania służący do znalezienia i zdekodowania entitlements. Dla zwięzłości celowo pomija on solidne sprawdzanie zakresów oraz pełną obsługę plików binarnych fat.<sup>[[6]](#references)[[7]](#references)</sup>
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
Wskazówki dotyczące użycia:
- Aby obsłużyć fat binaries, najpierw odczytaj struct fat_header/fat_arch, wybierz żądany wycinek architektury, a następnie przekaż podzakres do parse_entitlements.
- W systemie macOS możesz zweryfikować wyniki za pomocą: codesign -d --entitlements :- /path/to/binary


## Przykładowe ustalenia

Artykuł źródłowy pokazuje następujące entitlements w pliku binarnym `launchd` z systemu macOS 14.0:<sup>[[1]](#references)</sup>
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

Wyszukiwanie tych danych na dużą skalę w obrazach firmware jest niezwykle przydatne do mapowania powierzchni ataku oraz porównywania różnic między wydaniami i urządzeniami.


## Skalowanie na IPSW (montowanie i indeksowanie)

Aby wyliczać pliki wykonywalne i wyodrębniać entitlements na dużą skalę bez przechowywania pełnych obrazów:<sup>[[1]](#references)</sup>

- Użyj narzędzia ipsw autorstwa @blacktop do pobierania i montowania systemów plików firmware. Montowanie wykorzystuje apfs-fuse, dzięki czemu możesz przeglądać woluminy APFS bez pełnego rozpakowywania.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- Przeszukuj zamontowane woluminy w celu znalezienia plików Mach-O (sprawdzaj sygnaturę magiczną i/lub używaj `file`/`otool`), a następnie analizuj entitlements i zaimportowane frameworks.
- Zapisuj znormalizowany widok w relacyjnej bazie danych, aby uniknąć liniowego wzrostu danych w przypadku tysięcy IPSW:
- executables, operating_system_versions, entitlements, frameworks
- relacja wiele-do-wielu: executable↔OS version, executable↔entitlement, executable↔framework

Przykładowe zapytanie wyświetlające wszystkie wersje systemu operacyjnego zawierające plik wykonywalny o podanej nazwie (na podstawie appledb_rs):<sup>[[1]](#references)</sup>
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = 'launchd';
```
Uwagi dotyczące przenośności DB (jeśli implementujesz własny indexer):<sup>[[1]](#references)</sup>
- Użyj ORM/abstrakcji (np. SeaORM), aby kod był niezależny od DB (SQLite/PostgreSQL).
- SQLite zezwala na `AUTOINCREMENT` wyłącznie dla `INTEGER PRIMARY KEY`; ten klucz jest aliasem dla podpisanego 64-bitowego ROWID, chociaż SQLite może używać na dysku mniejszych szerokości liczb całkowitych. Jeśli encje Rust generowane przez SeaORM wymagają identyfikatorów i64, wygeneruj encje jako i32 i konwertuj typy na granicy.<sup>[[1]](#references)[[8]](#references)[[9]](#references)</sup>


## Narzędzia open-source i materiały referencyjne dotyczące wyszukiwania entitlementów

- Montowanie/pobieranie firmware: https://github.com/blacktop/ipsw.<sup>[[3]](#references)</sup>
- Bazy danych entitlementów i materiały referencyjne:
- Baza entitlementów Jonathana Levina: https://newosxbook.com/ent.php.<sup>[[4]](#references)</sup>
- entdb: https://github.com/ChiChou/entdb.<sup>[[5]](#references)</sup>
- Indexer na dużą skalę (Rust, self-hosted Web UI + OpenAPI): https://github.com/synacktiv/appledb_rs.<sup>[[2]](#references)</sup>
- Nagłówki Apple dotyczące struktur i stałych:
- loader.h (nagłówki Mach-O, load commands)
- cs_blobs.h (SuperBlob, GenericBlob, CodeDirectory)

Więcej informacji o wewnętrznym działaniu code signing (Code Directory, special slots, DER entitlements) znajdziesz tutaj: [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)


## References

- [1] [Corentin Liaud (Synacktiv), appledb_rs: narzędzie wspierające badania platform Apple](https://www.synacktiv.com/publications/appledbrs-un-outil-daide-a-la-recherche-sur-plateformes-apple.html)
- [2] [synacktiv/appledb_rs](https://github.com/synacktiv/appledb_rs)
- [3] [blacktop/ipsw](https://github.com/blacktop/ipsw)
- [4] [Baza entitlementów Jonathana Levina](https://newosxbook.com/ent.php)
- [5] [ChiChou/entdb](https://github.com/ChiChou/entdb)
- [6] [XNU cs_blobs.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [7] [XNU mach-o/loader.h](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [8] [Typy danych SQLite](https://sqlite.org/datatype3.html)
- [9] [Autoincrement SQLite](https://sqlite.org/autoinc.html)
{{#include ../../../banners/hacktricks-training.md}}
