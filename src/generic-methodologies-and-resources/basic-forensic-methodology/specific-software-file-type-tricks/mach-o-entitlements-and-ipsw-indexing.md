# Wydobywanie entitlements Mach-O i indeksowanie IPSW

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Ta strona opisuje, jak programowo wyodrębnić entitlements z binariów Mach-O, przechodząc po LC_CODE_SIGNATURE i parsując code signing SuperBlob, oraz jak skalować to na firmware Apple IPSW przez montowanie i indeksowanie ich zawartości do celów przeszukiwania/porównywania kryminalistycznego.

Jeśli potrzebujesz przypomnienia dotyczącego formatu Mach-O i code signing, zobacz także: macOS code signing and SuperBlob internals.
- Sprawdź macOS code signing details (SuperBlob, Code Directory, special slots): [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- Sprawdź general Mach-O structures/load commands: [Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Entitlements in Mach-O: gdzie się znajdują

Entitlements są przechowywane wewnątrz danych podpisu kodu, na które wskazuje polecenie ładowania LC_CODE_SIGNATURE i które umieszczone są w segmencie __LINKEDIT. Podpis to CS_SuperBlob zawierający wiele blobów (Code Directory, requirements, entitlements, CMS itd.). Blok entitlements to CS_GenericBlob, którego dane są Apple Binary Property List (bplist00) mapującą klucze entitlements na wartości.

Kluczowe struktury (z xnu):
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
- DER entitlements may be present via special slot (e.g., -7), see the macOS Code Signing page for special slots and DER entitlements notes

Uwaga: Multi-arch (fat) binaries contain multiple Mach-O slices. Musisz wybrać slice dla architektury, którą chcesz zbadać, a następnie przejść przez jej load commands.


## Extraction steps (generic, lossless-enough)

1) Parsuj nagłówek Mach-O; iteruj ncmds rekordów load_command.
2) Zlokalizuj LC_CODE_SIGNATURE; odczytaj linkedit_data_command.dataoff/datasize, aby zmapować Code Signing SuperBlob umieszczony w __LINKEDIT.
3) Zwaliduj CS_SuperBlob.magic == 0xfade0cc0; iteruj count wpisów CS_BlobIndex.
4) Zlokalizuj index.type == 0xfade7171 (embedded entitlements). Odczytaj wskazywany CS_GenericBlob i sparsuj jego dane jako Apple binary plist (bplist00) na pary klucz/wartość entitlements.

Implementation notes:
- Struktury Code Signature używają pól big-endian; zamień kolejność bajtów przy parsowaniu na little-endian hostach.
- Dane entitlements GenericBlob same w sobie są binary plist (obsługiwane przez standardowe biblioteki plist).
- Niektóre iOS binaries mogą mieć DER entitlements; też niektóre stores/slots różnią się między platformami/wersjami. Sprawdź zarówno standardowe, jak i DER entitlements w razie potrzeby.
- Dla fat binaries użyj fat headers (FAT_MAGIC/FAT_MAGIC_64), aby zlokalizować właściwy slice i offset przed przejściem przez Mach-O load commands.


## Minimal parsing outline (Python)

Poniżej znajduje się zwarty zarys pokazujący przepływ sterowania do znalezienia i dekodowania entitlements. Celowo pomija solidne sprawdzanie granic i pełne wsparcie dla fat binaries ze względów zwięzłości.
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
- Aby obsłużyć fat binaries, najpierw przeczytaj struct fat_header/fat_arch, wybierz żądany architecture slice, a następnie przekaż podzakres do parse_entitlements.
- On macOS you can validate results with: codesign -d --entitlements :- /path/to/binary


## Example findings

Privileged platform binaries często żądają wrażliwych entitlements, takich jak:
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

Wyszukiwanie ich na dużą skalę w obrazach firmware jest niezwykle cenne do attack surface mapping oraz diffing między releases/devices.


## Scaling across IPSWs (mounting and indexing)

Aby enumerate executables i extract entitlements na dużą skalę bez przechowywania pełnych obrazów:

- Use the ipsw tool by @blacktop to download and mount firmware filesystems. Montowanie wykorzystuje apfs-fuse, więc możesz przeglądać wolumeny APFS bez pełnej ekstrakcji.
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- Przeglądaj zamontowane wolumeny, aby odnaleźć pliki Mach-O (sprawdź magic i/lub użyj file/otool), a następnie sparsuj entitlements i zaimportowane frameworks.
- Utrwal znormalizowany widok w relacyjnej bazie danych, aby uniknąć liniowego wzrostu przy tysiącach IPSWs:
- executables, operating_system_versions, entitlements, frameworks
- many-to-many: executable↔OS version, executable↔entitlement, executable↔framework

Przykładowe zapytanie do wylistowania wszystkich wersji OS zawierających daną nazwę executable:
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = "launchd";
```
Uwagi dotyczące przenośności bazy danych (jeśli implementujesz własny indeksator):
- Użyj ORM/abstrakcji (np. SeaORM), aby kod był niezależny od bazy danych (SQLite/PostgreSQL).
- SQLite wymaga AUTOINCREMENT tylko dla INTEGER PRIMARY KEY; jeśli chcesz i64 PKs w Rust, generuj encje jako i32 i konwertuj typy — SQLite wewnętrznie przechowuje INTEGER jako 8-bajtową liczbę ze znakiem.


## Open-source tooling i odniesienia dla entitlement hunting

- Firmware mount/download: https://github.com/blacktop/ipsw
- Entitlement databases and references:
- Entitlement DB Jonathana Levina: https://newosxbook.com/ent.php
- entdb: https://github.com/ChiChou/entdb
- Indeksator na dużą skalę (Rust, self-hosted Web UI + OpenAPI): https://github.com/synacktiv/appledb_rs
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
