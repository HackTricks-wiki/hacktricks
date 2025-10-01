# Mach-O Entitlements Extraction & IPSW Indexing

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Ova stranica objašnjava kako programatski izvući entitlements iz Mach-O binarnih fajlova prolaskom kroz LC_CODE_SIGNATURE i parsiranjem code signing SuperBlob-a, i kako to skalirati preko Apple IPSW firmware-ova montiranjem i indeksiranjem njihovog sadržaja za forenzičko pretraživanje/razlike.

Ako vam treba podsetnik o Mach-O formatu i code signing-u, pogledajte i: macOS code signing and SuperBlob internals.
- Check macOS code signing details (SuperBlob, Code Directory, special slots): [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- Check general Mach-O structures/load commands: [Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Entitlements in Mach-O: where they live

Entitlements su smešteni unutar code signature podataka na koje pokazuje LC_CODE_SIGNATURE load command i nalaze se u __LINKEDIT segmentu. Potpis je CS_SuperBlob koji sadrži više blob-ova (Code Directory, requirements, entitlements, CMS, itd.). Entitlements blob je CS_GenericBlob čiji su podaci Apple Binary Property List (bplist00) koji mapira ključeve entitlements na njihove vrednosti.

Key structures (from xnu):
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
Important constants:
- LC_CODE_SIGNATURE cmd = 0x1d
- CS SuperBlob magic = 0xfade0cc0
- Entitlements blob type (CSMAGIC_EMBEDDED_ENTITLEMENTS) = 0xfade7171
- DER entitlements may be present via special slot (e.g., -7), see the macOS Code Signing page for special slots and DER entitlements notes

Note: Multi-arch (fat) binaries contain multiple Mach-O slices. You must pick the slice for the architecture you want to inspect and then walk its load commands.


## Koraci ekstrakcije (generički, dovoljno bez gubitaka)

1) Parsirajte Mach-O header; iterirajte kroz ncmds worth of load_command records.
2) Pronađite LC_CODE_SIGNATURE; pročitajte linkedit_data_command.dataoff/datasize da mapirate Code Signing SuperBlob smešten u __LINKEDIT.
3) Potvrdite CS_SuperBlob.magic == 0xfade0cc0; prođite kroz count unosa CS_BlobIndex.
4) Pronađite index.type == 0xfade7171 (embedded entitlements). Pročitajte adresirani CS_GenericBlob i parsirajte njegove podatke kao Apple binary plist (bplist00) u key/value entitlements.

Napomene implementacije:
- Strukture Code signature koriste big-endian polja; pri parsiranju na little-endian hostovima zamenite redosled bajtova.
- Podaci entitlements GenericBlob-a su binary plist (rukuju im standardne plist biblioteke).
- Neki iOS binarni fajlovi mogu nositi DER entitlements; takođe neki stores/slots se razlikuju među platformama/versijama. Po potrebi proverite i standardne i DER entitlements.
- Za fat binarne fajlove, koristite fat headers (FAT_MAGIC/FAT_MAGIC_64) da locirate odgovarajući slice i offset pre nego što prođete kroz Mach-O load commands.


## Minimalni pregled parsiranja (Python)

Sledeći kompaktni pregled prikazuje kontrolni tok za pronalaženje i dekodiranje entitlements. Namerno izostavlja robusne provere granica i punu podršku za fat binarne fajlove radi sažetosti.
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
- Za rad sa fat binaries, prvo pročitajte struct fat_header/fat_arch, odaberite željeni architecture slice, zatim prosledite podopseg funkciji parse_entitlements.
- Na macOS možete potvrditi rezultate sa: codesign -d --entitlements :- /path/to/binary


## Primeri nalaza

Privileged platform binaries često zahtevaju osetljive entitlements kao što su:
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

Pretraživanje ovih na velikoj skali kroz firmware image-ove je izuzetno vredno za attack surface mapping i diffing između izdanja/uređaja.


## Skaliranje preko IPSWs (montiranje i indeksiranje)

Da biste na skali nabrojali executables i izdvojili entitlements bez čuvanja kompletnih image-ova:

- Koristite ipsw tool by @blacktop za preuzimanje i mountovanje firmware filesystems. Mounting koristi apfs-fuse, tako da možete traversirati APFS volumene bez pune ekstrakcije.
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- Pregledajte montirane volumene da biste locirali Mach-O fajlove (proverite magic i/ili koristite file/otool), zatim parsirajte entitlements i imported frameworks.
- Sačuvajte normalizovani prikaz u relacionoj bazi podataka da biste izbegli linearni rast kroz hiljade IPSWs:
- executables, operating_system_versions, entitlements, frameworks
- many-to-many: executable↔OS version, executable↔entitlement, executable↔framework

Primer upita za listanje svih OS verzija koje sadrže dati executable name:
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = "launchd";
```
Napomene o DB prenosivosti (ako implementirate sopstveni indeksator):
- Koristite ORM/abstrakciju (npr., SeaORM) kako bi kod bio nezavisan od DB-a (SQLite/PostgreSQL).
- SQLite zahteva AUTOINCREMENT samo za INTEGER PRIMARY KEY; ako želite i64 PK-ove u Rust-u, generišite entitete kao i32 i konvertujte tipove — SQLite interno čuva INTEGER kao 8-bajtni potpisani tip.


## Open-source alati i reference za entitlement hunting

- Firmware mount/download: https://github.com/blacktop/ipsw
- Entitlement databases and references:
- Jonathan Levin’s entitlement DB: https://newosxbook.com/ent.php
- entdb: https://github.com/ChiChou/entdb
- Indeksator velike razmere (Rust, self-hosted Web UI + OpenAPI): https://github.com/synacktiv/appledb_rs
- Apple zaglavlja za strukture i konstante:
- loader.h (Mach-O headers, load commands)
- cs_blobs.h (SuperBlob, GenericBlob, CodeDirectory)

Za više o internim detaljima code signing (Code Directory, special slots, DER entitlements), vidi: [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)


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
