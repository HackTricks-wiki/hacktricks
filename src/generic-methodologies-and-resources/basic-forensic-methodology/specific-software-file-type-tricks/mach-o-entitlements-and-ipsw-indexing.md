# Extraction des entitlements Mach-O & indexation d'IPSW

{{#include ../../../banners/hacktricks-training.md}}

## Vue d'ensemble

Cette page explique comment extraire les entitlements depuis des binaires Mach-O de façon programmatique en parcourant LC_CODE_SIGNATURE et en analysant le code signing SuperBlob, et comment mettre cela à l'échelle sur les firmwares IPSW d'Apple en montant et en indexant leur contenu pour des recherches/diffs forensiques.

Si vous avez besoin d'un rappel sur le format Mach-O et le code signing, voir aussi : macOS code signing and SuperBlob internals.
- Consultez macOS code signing details (SuperBlob, Code Directory, special slots): [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- Consultez general Mach-O structures/load commands: [Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Entitlements dans Mach-O : où elles se trouvent

Les entitlements sont stockés dans les données de code signature référencées par le load command LC_CODE_SIGNATURE et placées dans le segment __LINKEDIT. La signature est un CS_SuperBlob contenant plusieurs blobs (code directory, requirements, entitlements, CMS, etc.). Le blob d'entitlements est un CS_GenericBlob dont les données sont un Apple Binary Property List (bplist00) associant des clés d'entitlement à des valeurs.

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
Constantes importantes :
- LC_CODE_SIGNATURE cmd = 0x1d
- CS SuperBlob magic = 0xfade0cc0
- Entitlements blob type (CSMAGIC_EMBEDDED_ENTITLEMENTS) = 0xfade7171
- DER entitlements may be present via special slot (e.g., -7), see the macOS Code Signing page for special slots and DER entitlements notes

Remarque : les binaires multi-arch (fat) contiennent plusieurs slices Mach-O. Vous devez choisir la slice correspondant à l'architecture que vous souhaitez inspecter, puis parcourir ses load commands.


## Étapes d'extraction (génériques, suffisamment sans perte)

1) Parser le Mach-O header ; itérer ncmds records de load_command.  
2) Localiser LC_CODE_SIGNATURE ; lire linkedit_data_command.dataoff/datasize pour mapper le Code Signing SuperBlob placé dans __LINKEDIT.  
3) Valider CS_SuperBlob.magic == 0xfade0cc0 ; itérer count entries de CS_BlobIndex.  
4) Localiser index.type == 0xfade7171 (embedded entitlements). Lire le CS_GenericBlob pointé et parser ses données comme un Apple binary plist (bplist00) pour obtenir les entitlements en clé/valeur.

Notes d'implémentation :
- Les structures de code signature utilisent des champs big-endian ; inverser l'ordre des octets lors du parsing sur des hosts little-endian.  
- Les données du GenericBlob des entitlements sont elles-mêmes un binary plist (pris en charge par les bibliothèques plist standard).  
- Certains binaires iOS peuvent porter des DER entitlements ; certains stores/slots diffèrent aussi entre plateformes/versions. Vérifier à la fois les entitlements standard et DER selon les besoins.  
- Pour les fat binaries, utiliser les fat headers (FAT_MAGIC/FAT_MAGIC_64) pour localiser la slice et l'offset corrects avant de parcourir les load commands du Mach-O.


## Plan d'analyse minimal (Python)

The following is a compact outline showing the control flow to find and decode entitlements. It intentionally omits robust bounds checks and full fat binary support for brevity.
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
- To handle fat binaries, first read struct fat_header/fat_arch, choose the desired architecture slice, then pass the subrange to parse_entitlements.
- On macOS you can validate results with: codesign -d --entitlements :- /path/to/binary


## Example findings

Privileged platform binaries often request sensitive entitlements such as:
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

Searching these at scale across firmware images is extremely valuable for attack surface mapping and diffing across releases/devices.


## Scaling across IPSWs (mounting and indexing)

To enumerate executables and extract entitlements at scale without storing full images:

- Use the ipsw tool by @blacktop to download and mount firmware filesystems. Mounting leverages apfs-fuse, so you can traverse APFS volumes without full extraction.
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- Parcourir les volumes montés pour localiser les fichiers Mach-O (vérifier le magic et/ou utiliser file/otool), puis analyser les entitlements et les frameworks importés.
- Conserver une vue normalisée dans une base de données relationnelle pour éviter une croissance linéaire à travers des milliers d'IPSWs :
- executables, operating_system_versions, entitlements, frameworks
- many-to-many: executable↔OS version, executable↔entitlement, executable↔framework

Exemple de requête pour lister toutes les versions d'OS contenant un nom d'exécutable donné :
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = "launchd";
```
Notes sur la portabilité de la DB (si vous implémentez votre propre indexeur) :
- Utilisez un ORM/une abstraction (par ex., SeaORM) pour garder le code agnostique vis-à-vis de la DB (SQLite/PostgreSQL).
- SQLite n'exige AUTOINCREMENT que pour un INTEGER PRIMARY KEY ; si vous voulez des PK i64 en Rust, générez les entités en i32 et convertissez les types, SQLite stocke INTEGER comme un entier signé sur 8 octets en interne.


## Outils open-source et références pour entitlement hunting

- Firmware mount/download: https://github.com/blacktop/ipsw
- Bases de données et références d'entitlements :
- Entitlement DB de Jonathan Levin: https://newosxbook.com/ent.php
- entdb: https://github.com/ChiChou/entdb
- Indexeur à grande échelle (Rust, Web UI auto-hébergée + OpenAPI): https://github.com/synacktiv/appledb_rs
- Apple headers pour structures et constantes :
- loader.h (Mach-O headers, load commands)
- cs_blobs.h (SuperBlob, GenericBlob, CodeDirectory)

Pour plus d'informations sur les internals du code signing (Code Directory, special slots, DER entitlements), voir : [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)


## Références

- [appledb_rs: a research support tool for Apple platforms](https://www.synacktiv.com/publications/appledbrs-un-outil-daide-a-la-recherche-sur-plateformes-apple.html)
- [synacktiv/appledb_rs](https://github.com/synacktiv/appledb_rs)
- [blacktop/ipsw](https://github.com/blacktop/ipsw)
- [Jonathan Levin’s entitlement DB](https://newosxbook.com/ent.php)
- [ChiChou/entdb](https://github.com/ChiChou/entdb)
- [XNU cs_blobs.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [XNU mach-o/loader.h](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [SQLite Datatypes](https://sqlite.org/datatype3.html)

{{#include ../../../banners/hacktricks-training.md}}
