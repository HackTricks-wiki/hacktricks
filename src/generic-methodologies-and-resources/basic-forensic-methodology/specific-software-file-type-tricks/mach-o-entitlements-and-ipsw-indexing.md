# Ekstrakcija Mach-O Entitlements i IPSW indeksiranje

{{#include ../../../banners/hacktricks-training.md}}

## Entitlements u Mach-O: gde se nalaze

Ova stranica objašnjava kako programski ekstrahovati entitlements iz Mach-O binarnih datoteka prolaskom kroz LC_CODE_SIGNATURE i parsiranjem code signing SuperBlob-a, kao i kako ovaj postupak skalirati na Apple IPSW firmware-e montiranjem i indeksiranjem njihovog sadržaja radi forenzičkog pretraživanja i poređenja.

Ako vam je potrebno osveženje o Mach-O formatu i code signing-u, pogledajte i: macOS code signing i interne detalje SuperBlob-a.
- Pogledajte detalje macOS code signing-a (SuperBlob, Code Directory, special slots): [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- Pogledajte opšte Mach-O strukture/load commands: [Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Entitlements u Mach-O: gde se nalaze

Entitlements su smešteni unutar podataka code signature-a na koje ukazuje LC_CODE_SIGNATURE load command i postavljeni su u segment __LINKEDIT. Signature je CS_SuperBlob koji sadrži više blob-ova (code directory, requirements, entitlements, CMS itd.). Entitlements blob je CS_GenericBlob čiji podaci predstavljaju Apple Binary Property List (bplist00) koji mapira ključeve entitlements-a na vrednosti.<sup>[[1]](#references)</sup>

Ključne strukture (iz xnu):<sup>[[6]](#references)[[7]](#references)</sup>
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
Važne konstante:
- LC_CODE_SIGNATURE cmd = 0x1d
- CS SuperBlob magic = 0xfade0cc0
- Entitlements blob type (CSMAGIC_EMBEDDED_ENTITLEMENTS) = 0xfade7171
- DER entitlements mogu biti prisutni putem posebnog slota (npr. -7); pogledajte stranicu macOS Code Signing za posebne slotove i napomene o DER entitlements

Napomena: Multi-arch (fat) binaries sadrže više Mach-O slice-ova. Morate izabrati slice za architecture koji želite da pregledate, a zatim proći kroz njegove load commands.


## Koraci ekstrakcije (generički, dovoljno bez gubitaka)

1) Parsirajte Mach-O header; iterirajte kroz ncmds load_command zapisa.
2) Pronađite LC_CODE_SIGNATURE; pročitajte linkedit_data_command.dataoff/datasize da biste mapirali Code Signing SuperBlob smešten u __LINKEDIT.
3) Validirajte da je CS_SuperBlob.magic == 0xfade0cc0; iterirajte kroz count stavki CS_BlobIndex.
4) Pronađite index.type == 0xfade7171 (embedded entitlements). Pročitajte pokazani CS_GenericBlob i parsirajte njegove podatke kao Apple binary plist (bplist00) da biste dobili key/value entitlements.<sup>[[1]](#references)</sup>

Napomene za implementaciju:
- Code signature strukture koriste big-endian polja; zamenite redosled bajtova prilikom parsiranja na little-endian hostovima.
- Podaci entitlements GenericBlob-a su sami po sebi binary plist (obrađuju ih standardne plist biblioteke).
- Neki iOS binaries mogu sadržati DER entitlements; takođe, neki store-ovi/slot-ovi se razlikuju među platformama/verzijama. Po potrebi proverite i standardne i DER entitlements.
- Za fat binaries koristite fat headers (FAT_MAGIC/FAT_MAGIC_64) da biste pronašli odgovarajući slice i offset pre prolaska kroz Mach-O load commands.<sup>[[1]](#references)</sup>


## Minimalni outline parsiranja (Python)

U nastavku je sažet outline koji prikazuje tok kontrole za pronalaženje i dekodiranje entitlements. Namerno izostavlja robusne provere granica i punu podršku za fat binary radi sažetosti.<sup>[[1]](#references)</sup>
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
Saveti za upotrebu:
- Za rukovanje fat binaries, prvo pročitajte struct fat_header/fat_arch, izaberite željeni architecture slice, a zatim prosledite podopseg funkciji parse_entitlements.
- Na macOS-u možete proveriti rezultate pomoću: codesign -d --entitlements :- /path/to/binary


## Primeri nalaza

Privileged platform binaries često zahtevaju osetljive entitlements kao što su:<sup>[[1]](#references)</sup>
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

Pretraživanje ovih vrednosti u velikom obimu kroz firmware images izuzetno je korisno za mapiranje attack surface-a i poređenje razlika između izdanja/uređaja.


## Skaliranje kroz IPSW-ove (montiranje i indeksiranje)

Za nabrajanje izvršnih datoteka i izdvajanje entitlements u velikom obimu bez čuvanja kompletnih images:<sup>[[1]](#references)</sup>

- Koristite ipsw alat autora @blacktop za preuzimanje i montiranje firmware filesystem-a. Montiranje koristi apfs-fuse, tako da možete prolaziti kroz APFS volumes bez potpunog raspakivanja.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- Prođite kroz montirane volumene da biste pronašli Mach-O datoteke (proverite magic i/ili koristite file/otool), a zatim analizirajte entitlements i uvezene frameworks.
- Sačuvajte normalizovani prikaz u relacionoj bazi podataka da biste izbegli linearni rast kroz hiljade IPSW-ova:
- executables, operating_system_versions, entitlements, frameworks
- many-to-many: executable↔OS version, executable↔entitlement, executable↔framework

Primer upita za izlistavanje svih OS verzija koje sadrže dato ime executable-a:
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = "launchd";
```
Napomene o prenosivosti DB-a (ako implementirate sopstveni indexer):<sup>[[1]](#references)</sup>
- Koristite ORM/apstrakciju (npr. SeaORM) da bi kod ostao nezavisan od DB-a (SQLite/PostgreSQL).
- SQLite zahteva AUTOINCREMENT samo uz INTEGER PRIMARY KEY; ako želite i64 PK-ove u Rust-u, generišite entitete kao i32 i konvertujte tipove. SQLite interno skladišti INTEGER kao 8-bajtni signed tip.<sup>[[8]](#references)</sup>


## Alati otvorenog koda i reference za pronalaženje entitlements

- Montiranje/preuzimanje firmware-a: https://github.com/blacktop/ipsw
- Baze entitlements i reference:
- Baza entitlements autora Jonathana Levina: https://newosxbook.com/ent.php
- entdb: https://github.com/ChiChou/entdb
- Indexer velikih razmera (Rust, self-hosted Web UI + OpenAPI): https://github.com/synacktiv/appledb_rs
- Apple header-i za strukture i konstante:
- loader.h (Mach-O header-i, load commands)
- cs_blobs.h (SuperBlob, GenericBlob, CodeDirectory)

Za više informacija o internim detaljima code signing-a (Code Directory, special slots, DER entitlements), pogledajte: [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)


## Reference

- [1] [appledb_rs: alat za podršku istraživanju Apple platformi](https://www.synacktiv.com/publications/appledbrs-un-outil-daide-a-la-recherche-sur-plateformes-apple.html)
- [2] [synacktiv/appledb_rs](https://github.com/synacktiv/appledb_rs)
- [3] [blacktop/ipsw](https://github.com/blacktop/ipsw)
- [4] [Baza entitlements autora Jonathana Levina](https://newosxbook.com/ent.php)
- [5] [ChiChou/entdb](https://github.com/ChiChou/entdb)
- [6] [XNU cs_blobs.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [7] [XNU mach-o/loader.h](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [8] [SQLite tipovi podataka](https://sqlite.org/datatype3.html)

{{#include ../../../banners/hacktricks-training.md}}
