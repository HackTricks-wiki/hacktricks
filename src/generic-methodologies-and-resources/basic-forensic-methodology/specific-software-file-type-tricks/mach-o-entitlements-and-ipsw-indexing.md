# Extraction des Entitlements Mach-O et indexation IPSW

{{#include ../../../banners/hacktricks-training.md}}

## Vue d'ensemble

Cette page explique comment extraire programmatiquement les entitlements des binaires Mach-O en parcourant LC_CODE_SIGNATURE et en analysant le code signing SuperBlob, ainsi que comment appliquer cette méthode à grande échelle aux firmwares Apple IPSW en montant et en indexant leur contenu pour effectuer des recherches et des comparaisons forensiques.

Si vous avez besoin d'un rappel sur le format Mach-O et le code signing, consultez également : macOS code signing et les composants internes de SuperBlob.
- Consultez les détails du macOS code signing (SuperBlob, Code Directory, special slots) : [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- Consultez les structures Mach-O générales et les load commands : [Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Entitlements dans Mach-O : où sont-ils stockés ?

Les entitlements sont stockés dans les données de code signature référencées par le load command LC_CODE_SIGNATURE et placées dans le segment __LINKEDIT. La signature est un CS_SuperBlob contenant plusieurs blobs (code directory, requirements, entitlements, CMS, etc.). Le blob des entitlements est un CS_GenericBlob dont les données sont une Apple Binary Property List (bplist00) associant des clés d'entitlements à leurs valeurs.<sup>[[1]](#references)</sup>

Structures principales (issues de xnu) :<sup>[[6]](#references)[[7]](#references)</sup>
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
- Les DER entitlements peuvent être présents via un slot spécial (par exemple, -7) ; consultez la page macOS Code Signing pour les slots spéciaux et les informations sur les DER entitlements

Note : les binaires multi-arch (fat) contiennent plusieurs slices Mach-O. Vous devez sélectionner la slice correspondant à l'architecture que vous souhaitez inspecter, puis parcourir ses load commands.


## Étapes d'extraction (génériques, suffisamment sans perte)

1) Analyser l'en-tête Mach-O ; itérer sur les enregistrements load_command au nombre de ncmds.
2) Localiser LC_CODE_SIGNATURE ; lire linkedit_data_command.dataoff/datasize pour mapper le Code Signing SuperBlob placé dans __LINKEDIT.
3) Valider que CS_SuperBlob.magic == 0xfade0cc0 ; itérer sur les entrées count de CS_BlobIndex.
4) Localiser index.type == 0xfade7171 (embedded entitlements). Lire le CS_GenericBlob pointé et analyser ses données comme une Apple binary plist (bplist00) afin d'obtenir les entitlements clé/valeur.<sup>[[1]](#references)</sup>

Notes d'implémentation :
- Les structures de code signature utilisent des champs big-endian ; inverser l'ordre des octets lors de l'analyse sur des hosts little-endian.
- Les données du entitlements GenericBlob sont elles-mêmes une binary plist (gérée par les bibliothèques plist standard).
- Certains binaires iOS peuvent contenir des DER entitlements ; certains stores/slots diffèrent également selon les plateformes/versions. Vérifier à la fois les entitlements standard et DER si nécessaire.
- Pour les binaires fat, utiliser les en-têtes fat (FAT_MAGIC/FAT_MAGIC_64) afin de localiser la slice et l'offset appropriés avant de parcourir les load commands Mach-O.<sup>[[1]](#references)</sup>


## Schéma minimal d'analyse (Python)

Le schéma suivant montre de manière concise le flux de contrôle permettant de trouver et de décoder les entitlements. Il omet volontairement les vérifications robustes des limites et la prise en charge complète des binaires fat par souci de concision.<sup>[[1]](#references)</sup>
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
Conseils d’utilisation :
- Pour gérer les fat binaries, lisez d’abord struct fat_header/fat_arch, choisissez la slice d’architecture souhaitée, puis passez la subrange à parse_entitlements.
- Sur macOS, vous pouvez valider les résultats avec : codesign -d --entitlements :- /path/to/binary


## Exemples de résultats

Les platform binaries privilégiés demandent souvent des entitlements sensibles tels que :<sup>[[1]](#references)</sup>
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

Les rechercher à grande échelle dans les firmware images est extrêmement utile pour la cartographie de la surface d’attaque et le diffing entre les releases/devices.


## Mise à l’échelle sur les IPSWs (montage et indexation)

Pour énumérer les exécutables et extraire les entitlements à grande échelle sans stocker les images complètes :<sup>[[1]](#references)</sup>

- Utilisez l’outil ipsw de @blacktop pour télécharger et monter les firmware filesystems. Le montage s’appuie sur apfs-fuse, ce qui permet de parcourir les volumes APFS sans extraction complète.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- Parcourir les volumes montés pour localiser les fichiers Mach-O (vérifier le magic et/ou utiliser file/otool), puis analyser les entitlements et les frameworks importés.
- Conserver une vue normalisée dans une base de données relationnelle afin d’éviter une croissance linéaire avec des milliers d’IPSW :
- executables, operating_system_versions, entitlements, frameworks
- plusieurs-à-plusieurs : executable↔OS version, executable↔entitlement, executable↔framework

Exemple de requête pour répertorier toutes les versions d’OS contenant un nom d’exécutable donné :
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = "launchd";
```
Notes sur la portabilité des DB (si vous implémentez votre propre indexer):<sup>[[1]](#references)</sup>
- Utilisez un ORM/une abstraction (par ex., SeaORM) pour garder le code indépendant de la DB (SQLite/PostgreSQL).
- SQLite exige AUTOINCREMENT uniquement sur une INTEGER PRIMARY KEY ; si vous voulez des PK i64 en Rust, générez les entités en i32 et convertissez les types. SQLite stocke les valeurs INTEGER en interne sous forme d'entiers signés de 8 octets.<sup>[[8]](#references)</sup>


## Outils open source et références pour la recherche d'entitlements

- Montage/téléchargement du firmware : https://github.com/blacktop/ipsw
- Bases de données et références d'entitlements :
- DB d'entitlements de Jonathan Levin : https://newosxbook.com/ent.php
- entdb : https://github.com/ChiChou/entdb
- Indexer à grande échelle (Rust, Web UI auto-hébergée + OpenAPI) : https://github.com/synacktiv/appledb_rs
- Headers Apple pour les structures et constantes :
- loader.h (headers Mach-O, load commands)
- cs_blobs.h (SuperBlob, GenericBlob, CodeDirectory)

Pour en savoir plus sur les composants internes de code signing (Code Directory, special slots, DER entitlements), voir : [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)


## Références

- [1] [appledb_rs : un outil d'aide à la recherche sur les plateformes Apple](https://www.synacktiv.com/publications/appledbrs-un-outil-daide-a-la-recherche-sur-plateformes-apple.html)
- [2] [synacktiv/appledb_rs](https://github.com/synacktiv/appledb_rs)
- [3] [blacktop/ipsw](https://github.com/blacktop/ipsw)
- [4] [DB d'entitlements de Jonathan Levin](https://newosxbook.com/ent.php)
- [5] [ChiChou/entdb](https://github.com/ChiChou/entdb)
- [6] [XNU cs_blobs.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [7] [XNU mach-o/loader.h](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [8] [Types de données SQLite](https://sqlite.org/datatype3.html)

{{#include ../../../banners/hacktricks-training.md}}
