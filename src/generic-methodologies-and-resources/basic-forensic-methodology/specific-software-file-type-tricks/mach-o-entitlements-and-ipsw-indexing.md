# Mach-O Entitlements Extraction & IPSW Indexing

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Ova stranica opisuje kako programski izdvojiti entitlements iz Mach-O binarnih datoteka prolaskom kroz LC_CODE_SIGNATURE i parsiranjem code signing SuperBlob-a, kao i kako ovaj proces skalirati na Apple IPSW firmware-e montiranjem i indeksiranjem njihovog sadržaja radi forenzičke pretrage i poređenja.

Ako vam je potrebno osveženje o Mach-O formatu i code signing-u, pogledajte i: macOS code signing i SuperBlob internals.
- Check macOS code signing details (SuperBlob, Code Directory, special slots): [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- Check general Mach-O structures/load commands: [Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Entitlements u Mach-O-u: gde se nalaze

Entitlements se čuvaju unutar code signature podataka na koje upućuje LC_CODE_SIGNATURE load command i smeštaju se u segment __LINKEDIT. Potpis je CS_SuperBlob koji sadrži više blob-ova (code directory, requirements, entitlements, CMS itd.). Entitlements blob je CS_GenericBlob čiji su podaci serijalizovana property lista koja mapira entitlement ključeve na vrednosti; parseri treba da podržavaju i XML i binary plist kodiranja.<sup>[[1]](#references)[[6]](#references)</sup>

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
uint32_t type;    /* slot type, e.g. CSSLOT_ENTITLEMENTS = 5 */
uint32_t offset;  /* offset of entry */
} CS_BlobIndex;

typedef struct __SC_GenericBlob {
uint32_t magic;   /* blob magic, e.g. CSMAGIC_EMBEDDED_ENTITLEMENTS */
uint32_t length;
char data[];      /* serialized plist containing entitlements */
} CS_GenericBlob;
```
Važne konstante iz Apple header fajlova uključuju:<sup>[[6]](#references)[[7]](#references)</sup>
- LC_CODE_SIGNATURE cmd = 0x1d
- CS SuperBlob magic = 0xfade0cc0
- Entitlements index slot (`CSSLOT_ENTITLEMENTS`) = 5; blob na tom slotu ima magic `CSMAGIC_EMBEDDED_ENTITLEMENTS` = 0xfade7171
- DER entitlements koriste slot `CSSLOT_DER_ENTITLEMENTS` = 7 i blob magic `CSMAGIC_EMBEDDED_DER_ENTITLEMENTS` = 0xfade7172

Napomena: Multi-arch (fat) binarni fajlovi sadrže više Mach-O slice-ova. Morate izabrati slice za arhitekturu koju želite da proverite, a zatim proći kroz njegove load commands.


## Koraci ekstrakcije (generički, dovoljno bez gubitaka)

1) Parsirajte Mach-O header; iterirajte kroz onoliko `load_command` zapisa koliko je navedeno u ncmds.
2) Pronađite LC_CODE_SIGNATURE; pročitajte `linkedit_data_command.dataoff/datasize` da biste mapirali Code Signing SuperBlob smešten u __LINKEDIT.
3) Potvrdite da je CS_SuperBlob.magic == 0xfade0cc0; iterirajte kroz count stavki tipa CS_BlobIndex.
4) Pronađite `index.type == CSSLOT_ENTITLEMENTS` (5), zatim proverite da pointed `CS_GenericBlob` ima magic `CSMAGIC_EMBEDDED_ENTITLEMENTS` (0xfade7171). Parsirajte njegove podatke kao property list da biste dobili key/value entitlements.<sup>[[1]](#references)[[6]](#references)</sup>

Napomene za implementaciju:
- Strukture code signature koriste big-endian polja; zamenite redosled bajtova pri parsiranju na little-endian hostovima.
- Entitlements `GenericBlob` sadrži serijalizovani plist; standardne plist biblioteke mogu da obrade njegov XML ili binary prikaz.
- Neki iOS binarni fajlovi mogu sadržati DER entitlements; XNU izlaže poseban DER blob tip, a prikazi entitlements ili slotovi mogu da se razlikuju između platformi i verzija, zato po potrebi uporedite standardne i DER entitlements.<sup>[[6]](#references)</sup>
- Za fat binarne fajlove koristite fat headers (FAT_MAGIC/FAT_MAGIC_64) da biste pronašli odgovarajući slice i offset pre prolaska kroz Mach-O load commands.


## Minimalni outline parsiranja (Python)

U nastavku je kompaktan outline koji prikazuje tok kontrole za pronalaženje i dekodiranje entitlements. Namerno izostavlja robusne provere granica i punu podršku za fat binarne fajlove radi sažetosti.<sup>[[6]](#references)[[7]](#references)</sup>
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
Saveti za upotrebu:
- Za rad sa fat binarnim datotekama najpre pročitajte `struct fat_header/fat_arch`, izaberite željeni architecture slice, a zatim prosledite podopseg funkciji `parse_entitlements`.
- Na macOS-u možete proveriti rezultate pomoću: `codesign -d --entitlements :- /path/to/binary`


## Primeri nalaza

Izvorni članak prikazuje sledeće entitlements u macOS 14.0 `launchd` binarnoj datoteci:<sup>[[1]](#references)</sup>
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

Pretraživanje ovih stavki u velikom obimu kroz firmware images izuzetno je korisno za mapiranje površine napada i poređenje razlika između izdanja/uređaja.


## Skaliranje kroz IPSW-ove (mounting i indeksiranje)

Za nabrajanje executable datoteka i izdvajanje entitlements u velikom obimu bez čuvanja potpunih images:<sup>[[1]](#references)</sup>

- Koristite ipsw tool autora @blacktop za preuzimanje i mountovanje firmware filesystems. Mounting koristi apfs-fuse, tako da možete prolaziti kroz APFS volumes bez potpunog extraction-a.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- Prođite kroz montirane volumene da biste pronašli Mach-O datoteke (proverite magic i/ili koristite file/otool), zatim analizirajte entitlements i uvezene frameworks.
- Sačuvajte normalizovani prikaz u relacionoj bazi podataka da biste izbegli linearni rast među hiljadama IPSW-ova:
- executables, operating_system_versions, entitlements, frameworks
- many-to-many: executable↔OS version, executable↔entitlement, executable↔framework

Primer upita za izlistavanje svih OS verzija koje sadrže dati naziv executable-a (prilagođeno iz appledb_rs):<sup>[[1]](#references)</sup>
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = 'launchd';
```
Napomene o prenosivosti DB-a (ako implementirate sopstveni indeksator):<sup>[[1]](#references)</sup>
- Koristite ORM/apstrakciju (npr. SeaORM) da bi code ostao nezavisan od DB-a (SQLite/PostgreSQL).
- SQLite dozvoljava `AUTOINCREMENT` samo uz `INTEGER PRIMARY KEY`; taj ključ je alias za 64-bitni potpisani ROWID, iako SQLite može koristiti manje širine celih brojeva na disku. Ako entiteti u Rust-u generisani pomoću SeaORM-a zahtevaju i64 ID-jeve, generišite entitete kao i32 i konvertujte tipove na granici.<sup>[[1]](#references)[[8]](#references)[[9]](#references)</sup>


## Alati otvorenog koda i reference za entitlement hunting

- Montiranje/preuzimanje firmware-a: https://github.com/blacktop/ipsw.<sup>[[3]](#references)</sup>
- Baze podataka entitlement-a i reference:
- DB entitlement-a Jonathana Levina: https://newosxbook.com/ent.php.<sup>[[4]](#references)</sup>
- entdb: https://github.com/ChiChou/entdb.<sup>[[5]](#references)</sup>
- Indeksator velikih razmera (Rust, self-hosted Web UI + OpenAPI): https://github.com/synacktiv/appledb_rs.<sup>[[2]](#references)</sup>
- Apple zaglavlja za strukture i konstante:
- loader.h (Mach-O zaglavlja, load commands)
- cs_blobs.h (SuperBlob, GenericBlob, CodeDirectory)

Za više informacija o internim detaljima code signing-a (Code Directory, special slots, DER entitlements), pogledajte: [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)


## References

- [1] [Corentin Liaud (Synacktiv), appledb_rs: alat za podršku istraživanju Apple platformi](https://www.synacktiv.com/publications/appledbrs-un-outil-daide-a-la-recherche-sur-plateformes-apple.html)
- [2] [synacktiv/appledb_rs](https://github.com/synacktiv/appledb_rs)
- [3] [blacktop/ipsw](https://github.com/blacktop/ipsw)
- [4] [DB entitlement-a Jonathana Levina](https://newosxbook.com/ent.php)
- [5] [ChiChou/entdb](https://github.com/ChiChou/entdb)
- [6] [XNU cs_blobs.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [7] [XNU mach-o/loader.h](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [8] [SQLite Datatypes](https://sqlite.org/datatype3.html)
- [9] [SQLite Autoincrement](https://sqlite.org/autoinc.html)
{{#include ../../../banners/hacktricks-training.md}}
