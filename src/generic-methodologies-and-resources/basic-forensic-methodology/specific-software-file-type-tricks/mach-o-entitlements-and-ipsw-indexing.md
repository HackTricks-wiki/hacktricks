# Extraction des Entitlements Mach-O et indexation des IPSW

{{#include ../../../banners/hacktricks-training.md}}

## Vue d’ensemble

Cette page explique comment extraire les entitlements des binaires Mach-O par programmation en parcourant LC_CODE_SIGNATURE et en analysant le code signing SuperBlob, ainsi que comment appliquer cette méthode à grande échelle aux firmwares Apple IPSW en montant et en indexant leur contenu pour effectuer des recherches et des diff forensics.

Si vous avez besoin d’un rappel sur le format Mach-O et le code signing, consultez également : les composants internes du code signing macOS et de SuperBlob.
- Consultez les détails du code signing macOS (SuperBlob, Code Directory, special slots) : [Code Signing macOS](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- Consultez les structures Mach-O générales et les load commands : [Universal binaries et format Mach-O](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Entitlements dans Mach-O : où sont-ils stockés ?

Les entitlements sont stockés dans les données du code signing référencées par le load command LC_CODE_SIGNATURE et placées dans le segment __LINKEDIT. La signature est un CS_SuperBlob contenant plusieurs blobs (code directory, requirements, entitlements, CMS, etc.). Le blob des entitlements est un CS_GenericBlob dont les données sont une property list sérialisée associant les clés d’entitlements à leurs valeurs ; les parsers doivent accepter les encodages plist XML et binaire.<sup>[[1]](#references)[[6]](#references)</sup>

Structures principales (provenant de xnu) :<sup>[[6]](#references)[[7]](#references)</sup>
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
Les constantes importantes issues des headers Apple comprennent :<sup>[[6]](#references)[[7]](#references)</sup>
- LC_CODE_SIGNATURE cmd = 0x1d
- CS SuperBlob magic = 0xfade0cc0
- Entitlements index slot (`CSSLOT_ENTITLEMENTS`) = 5 ; le blob à ce slot possède le magic `CSMAGIC_EMBEDDED_ENTITLEMENTS` = 0xfade7171
- Les entitlements DER utilisent le slot `CSSLOT_DER_ENTITLEMENTS` = 7 et le blob magic `CSMAGIC_EMBEDDED_DER_ENTITLEMENTS` = 0xfade7172

Remarque : les binaires multi-architectures (fat) contiennent plusieurs slices Mach-O. Vous devez sélectionner la slice correspondant à l'architecture que vous souhaitez inspecter, puis parcourir ses load commands.


## Étapes d'extraction (génériques, suffisamment sans perte)

1) Analyser le header Mach-O ; parcourir les enregistrements `load_command` au nombre de ncmds.
2) Localiser LC_CODE_SIGNATURE ; lire `linkedit_data_command.dataoff/datasize` pour mapper le Code Signing SuperBlob placé dans __LINKEDIT.
3) Vérifier que `CS_SuperBlob.magic == 0xfade0cc0` ; parcourir les entrées `CS_BlobIndex` au nombre de count.
4) Localiser `index.type == CSSLOT_ENTITLEMENTS` (5), puis vérifier que le `CS_GenericBlob` pointé possède le magic `CSMAGIC_EMBEDDED_ENTITLEMENTS` (0xfade7171). Analyser ses données comme une property list afin d'obtenir les entitlements clé/valeur.<sup>[[1]](#references)[[6]](#references)</sup>

Notes d'implémentation :
- Les structures de signature de code utilisent des champs big-endian ; inverser l'ordre des octets lors de l'analyse sur des hosts little-endian.
- Le `GenericBlob` des entitlements contient une plist sérialisée ; les bibliothèques plist standard peuvent gérer sa représentation XML ou binaire.
- Certains binaires iOS peuvent contenir des entitlements DER ; XNU expose un type de blob DER distinct, et les représentations ou les slots des entitlements peuvent différer selon les plateformes et les versions. Il faut donc comparer les entitlements standard et DER si nécessaire.<sup>[[6]](#references)</sup>
- Pour les binaires fat, utiliser les headers fat (`FAT_MAGIC/FAT_MAGIC_64`) afin de localiser la slice et l'offset corrects avant de parcourir les load commands Mach-O.


## Schéma minimal d'analyse (Python)

Ce qui suit est un schéma compact montrant le flux de contrôle permettant de trouver et de décoder les entitlements. Il omet volontairement les vérifications robustes des limites et la prise en charge complète des binaires fat par souci de concision.<sup>[[6]](#references)[[7]](#references)</sup>
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
Conseils d'utilisation :
- Pour gérer les fat binaries, lisez d'abord `struct fat_header`/`fat_arch`, sélectionnez la slice d'architecture souhaitée, puis transmettez la sous-plage à `parse_entitlements`.
- Sur macOS, vous pouvez valider les résultats avec : `codesign -d --entitlements :- /path/to/binary`


## Exemples de résultats

L'article source présente ces entitlements dans le binaire `launchd` de macOS 14.0 :<sup>[[1]](#references)</sup>
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

Les rechercher à grande échelle dans les images firmware est extrêmement utile pour cartographier la surface d'attaque et effectuer du diffing entre les releases et les devices.


## Mise à l'échelle sur les IPSWs (montage et indexation)

Pour énumérer les exécutables et extraire les entitlements à grande échelle sans stocker les images complètes :<sup>[[1]](#references)</sup>

- Utilisez l'outil ipsw de @blacktop pour télécharger et monter les filesystems firmware. Le montage s'appuie sur apfs-fuse, ce qui vous permet de parcourir les volumes APFS sans extraction complète.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- Parcourir les volumes montés pour localiser les fichiers Mach-O (vérifier le magic et/ou utiliser file/otool), puis analyser les entitlements et les frameworks importés.
- Persister une vue normalisée dans une base de données relationnelle afin d’éviter une croissance linéaire pour des milliers d’IPSW :
- executables, operating_system_versions, entitlements, frameworks
- many-to-many : executable↔OS version, executable↔entitlement, executable↔framework

Exemple de requête pour lister toutes les versions d’OS contenant un nom d’exécutable donné (adapté de appledb_rs) :<sup>[[1]](#references)</sup>
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = 'launchd';
```
Notes sur la portabilité des DB (si vous implémentez votre propre indexer) :<sup>[[1]](#references)</sup>
- Utilisez un ORM/une abstraction (par ex., SeaORM) pour garder le code indépendant de la DB (SQLite/PostgreSQL).
- SQLite autorise `AUTOINCREMENT` uniquement sur une `INTEGER PRIMARY KEY` ; cette clé est un alias d’un ROWID signé sur 64 bits, bien que SQLite puisse utiliser des largeurs d’entiers plus petites sur le disque. Si les entités Rust générées par SeaORM nécessitent des identifiants i64, générez les entités en i32 et convertissez les types à la frontière.<sup>[[1]](#references)[[8]](#references)[[9]](#references)</sup>


## Outils open source et références pour la recherche d’entitlements

- Montage/téléchargement du firmware : https://github.com/blacktop/ipsw.<sup>[[3]](#references)</sup>
- Bases de données et références d’entitlements :
- DB d’entitlements de Jonathan Levin : https://newosxbook.com/ent.php.<sup>[[4]](#references)</sup>
- entdb : https://github.com/ChiChou/entdb.<sup>[[5]](#references)</sup>
- Indexer à grande échelle (Rust, Web UI + OpenAPI auto-hébergée) : https://github.com/synacktiv/appledb_rs.<sup>[[2]](#references)</sup>
- Headers Apple pour les structures et constantes :
- loader.h (headers Mach-O, load commands)
- cs_blobs.h (SuperBlob, GenericBlob, CodeDirectory)

Pour en savoir plus sur les mécanismes internes de la signature de code (Code Directory, special slots, DER entitlements), consultez : [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)


## References

- [1] [Corentin Liaud (Synacktiv), appledb_rs : un outil d’aide à la recherche sur les plateformes Apple](https://www.synacktiv.com/publications/appledbrs-un-outil-daide-a-la-recherche-sur-plateformes-apple.html)
- [2] [synacktiv/appledb_rs](https://github.com/synacktiv/appledb_rs)
- [3] [blacktop/ipsw](https://github.com/blacktop/ipsw)
- [4] [DB d’entitlements de Jonathan Levin](https://newosxbook.com/ent.php)
- [5] [ChiChou/entdb](https://github.com/ChiChou/entdb)
- [6] [XNU cs_blobs.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [7] [XNU mach-o/loader.h](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [8] [Types de données SQLite](https://sqlite.org/datatype3.html)
- [9] [AUTOINCREMENT de SQLite](https://sqlite.org/autoinc.html)
{{#include ../../../banners/hacktricks-training.md}}
