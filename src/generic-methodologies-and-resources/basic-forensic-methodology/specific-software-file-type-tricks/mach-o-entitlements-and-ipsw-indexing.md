# Ekstrakcja Entitlements z Mach-O i indeksowanie IPSW

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Ta strona opisuje programowe wyodrębnianie entitlements z plików binarnych Mach-O poprzez przejście po LC_CODE_SIGNATURE i parsowanie code signing SuperBlob, a także skalowanie tego procesu na firmware Apple IPSW przez montowanie i indeksowanie ich zawartości na potrzeby wyszukiwania/diff w analizie forensics.

Jeśli potrzebujesz przypomnienia dotyczącego formatu Mach-O i code signing, zobacz także: macOS code signing i elementy wewnętrzne SuperBlob.
- Szczegóły macOS code signing (SuperBlob, Code Directory, special slots): [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- Ogólne struktury Mach-O/load commands: [Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Entitlements w Mach-O: gdzie się znajdują

Entitlements są przechowywane w danych code signature wskazywanych przez load command LC_CODE_SIGNATURE i umieszczonych w segmencie __LINKEDIT. Sygnatura jest CS_SuperBlob zawierającym wiele blobów (code directory, requirements, entitlements, CMS itd.). Blob entitlements jest CS_GenericBlob, którego dane stanowią Apple Binary Property List (bplist00) mapujący klucze entitlements na wartości.<sup>[[1]](#references)</sup>

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
uint32_t type;    /* e.g., CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7171 */
uint32_t offset;  /* offset of entry */
} CS_BlobIndex;

typedef struct __SC_GenericBlob {
uint32_t magic;   /* same as type when standalone */
uint32_t length;
char data[];      /* Apple Binary Plist containing entitlements */
} CS_GenericBlob;
```
Ważne stałe:
- LC_CODE_SIGNATURE cmd = 0x1d
- CS SuperBlob magic = 0xfade0cc0
- Entitlements blob type (CSMAGIC_EMBEDDED_ENTITLEMENTS) = 0xfade7171
- DER entitlements mogą być obecne w specjalnym slocie (np. -7); zobacz stronę macOS Code Signing, aby zapoznać się z informacjami o special slots i DER entitlements

Uwaga: Binaries multi-arch (fat) zawierają wiele slices Mach-O. Musisz wybrać slice dla architektury, którą chcesz sprawdzić, a następnie przejść przez jej load commands.


## Kroki ekstrakcji (ogólne, wystarczająco bezstratne)

1) Przeanalizuj nagłówek Mach-O; iteruj po ncmds rekordach load_command.
2) Znajdź LC_CODE_SIGNATURE; odczytaj linkedit_data_command.dataoff/datasize, aby zmapować Code Signing SuperBlob umieszczony w __LINKEDIT.
3) Sprawdź, czy CS_SuperBlob.magic == 0xfade0cc0; iteruj po count wpisach CS_BlobIndex.
4) Znajdź index.type == 0xfade7171 (embedded entitlements). Odczytaj wskazany CS_GenericBlob i przeanalizuj jego data jako Apple binary plist (bplist00), aby uzyskać entitlements w formie key/value.<sup>[[1]](#references)</sup>

Uwagi dotyczące implementacji:
- Struktury code signature używają pól big-endian; zamień kolejność bajtów podczas analizy na hostach little-endian.
- Dane entitlements GenericBlob są binary plist (obsługiwanym przez standardowe biblioteki plist).
- Niektóre binaries iOS mogą zawierać DER entitlements; także niektóre stores/slots różnią się między platformami i wersjami. W razie potrzeby porównaj zarówno standardowe, jak i DER entitlements.
- W przypadku binaries fat użyj nagłówków fat (FAT_MAGIC/FAT_MAGIC_64), aby znaleźć właściwy slice i offset przed przejściem przez load commands Mach-O.<sup>[[1]](#references)</sup>


## Minimalny zarys analizy (Python)

Poniżej przedstawiono zwięzły zarys pokazujący przebieg sterowania potrzebny do znalezienia i zdekodowania entitlements. Dla zachowania zwięzłości celowo pominięto solidne sprawdzanie granic oraz pełną obsługę binaries fat.<sup>[[1]](#references)</sup>
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
Wskazówki dotyczące użycia:
- Aby obsługiwać fat binaries, najpierw odczytaj struct fat_header/fat_arch, wybierz żądany wycinek architektury, a następnie przekaż podzakres do parse_entitlements.
- W macOS możesz zweryfikować wyniki za pomocą: codesign -d --entitlements :- /path/to/binary


## Przykładowe ustalenia

Uprzywilejowane platform binaries często żądają wrażliwych entitlements, takich jak:<sup>[[1]](#references)</sup>
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

Wyszukiwanie tych wartości na dużą skalę w obrazach firmware jest niezwykle przydatne do mapowania attack surface i diffingu między wydaniami/urządzeniami.


## Skalowanie w wielu IPSW (montowanie i indeksowanie)

Aby wyliczać pliki wykonywalne i wyodrębniać entitlements na dużą skalę bez przechowywania pełnych obrazów:<sup>[[1]](#references)</sup>

- Użyj narzędzia ipsw autorstwa @blacktop do pobierania i montowania systemów plików firmware. Montowanie wykorzystuje apfs-fuse, dzięki czemu możesz przeglądać woluminy APFS bez pełnego rozpakowywania.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- Przeszukuj zamontowane woluminy w celu znalezienia plików Mach-O (sprawdzaj magic lub użyj file/otool), a następnie analizuj entitlements i zaimportowane frameworks.
- Zapisuj znormalizowany widok w relacyjnej bazie danych, aby uniknąć liniowego wzrostu ilości danych w przypadku tysięcy IPSW:
- executables, operating_system_versions, entitlements, frameworks
- relacje wiele-do-wielu: executable↔OS version, executable↔entitlement, executable↔framework

Przykładowe zapytanie wyświetlające wszystkie wersje systemu operacyjnego zawierające plik wykonywalny o podanej nazwie:
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = "launchd";
```
Uwagi dotyczące przenośności DB (jeśli implementujesz własny indexer):<sup>[[1]](#references)</sup>
- Użyj ORM/abstrakcji (np. SeaORM), aby zachować niezależność kodu od DB (SQLite/PostgreSQL).
- SQLite wymaga AUTOINCREMENT tylko dla INTEGER PRIMARY KEY; jeśli chcesz używać kluczy głównych i64 w Rust, generuj encje jako i32 i konwertuj typy. SQLite wewnętrznie przechowuje INTEGER jako 8-bajtową liczbę ze znakiem.<sup>[[8]](#references)</sup>


## Narzędzia open-source i materiały referencyjne dotyczące wyszukiwania entitlement

- Montowanie/pobieranie firmware: https://github.com/blacktop/ipsw
- Bazy danych entitlement i materiały referencyjne:
- Baza danych entitlement Jonathana Levina: https://newosxbook.com/ent.php
- entdb: https://github.com/ChiChou/entdb
- Indexer na dużą skalę (Rust, self-hosted Web UI + OpenAPI): https://github.com/synacktiv/appledb_rs
- Nagłówki Apple dotyczące struktur i stałych:
- loader.h (nagłówki Mach-O, load commands)
- cs_blobs.h (SuperBlob, GenericBlob, CodeDirectory)

Więcej informacji na temat wewnętrznego działania code signing (Code Directory, special slots, DER entitlements) znajdziesz w: [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)


## Materiały referencyjne

- [1] [appledb_rs: narzędzie wspierające badania platform Apple](https://www.synacktiv.com/publications/appledbrs-un-outil-daide-a-la-recherche-sur-plateformes-apple.html)
- [2] [synacktiv/appledb_rs](https://github.com/synacktiv/appledb_rs)
- [3] [blacktop/ipsw](https://github.com/blacktop/ipsw)
- [4] [Baza danych entitlement Jonathana Levina](https://newosxbook.com/ent.php)
- [5] [ChiChou/entdb](https://github.com/ChiChou/entdb)
- [6] [XNU cs_blobs.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [7] [XNU mach-o/loader.h](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [8] [Typy danych SQLite](https://sqlite.org/datatype3.html)

{{#include ../../../banners/hacktricks-training.md}}
