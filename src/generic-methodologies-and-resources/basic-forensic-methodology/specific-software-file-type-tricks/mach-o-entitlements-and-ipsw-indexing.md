# Mach-O-Entitlements-Extraktion & IPSW-Indizierung

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Diese Seite behandelt, wie man Entitlements programmgesteuert aus Mach-O-Binaries extrahiert, indem man LC_CODE_SIGNATURE durchläuft und den Code-Signing-SuperBlob parst, sowie wie man diesen Vorgang über Apple-IPSW-Firmwares hinweg skaliert, indem man deren Inhalte mountet und für die forensische Suche bzw. den Diff indexiert.

Falls du eine Auffrischung zum Mach-O-Format und zu Code Signing benötigst, siehe auch: macOS code signing und SuperBlob internals.
- Details zu macOS code signing ansehen (SuperBlob, Code Directory, spezielle Slots): [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- Allgemeine Mach-O-Strukturen und Load Commands ansehen: [Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Entitlements in Mach-O: Wo sie gespeichert sind

Entitlements werden innerhalb der von dem LC_CODE_SIGNATURE Load Command referenzierten Code-Signature-Daten gespeichert und im __LINKEDIT-Segment platziert. Die Signatur ist ein CS_SuperBlob, der mehrere Blobs enthält (Code Directory, Requirements, Entitlements, CMS usw.). Der Entitlements-Blob ist ein CS_GenericBlob, dessen Daten eine Apple Binary Property List (bplist00) sind, die Entitlement-Schlüssel auf Werte abbildet.<sup>[[1]](#references)</sup>

Wichtige Strukturen (aus xnu):<sup>[[6]](#references)[[7]](#references)</sup>
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
Wichtige Konstanten:
- LC_CODE_SIGNATURE cmd = 0x1d
- CS SuperBlob magic = 0xfade0cc0
- Entitlements blob type (CSMAGIC_EMBEDDED_ENTITLEMENTS) = 0xfade7171
- DER entitlements may be present via special slot (z. B. -7), siehe die macOS Code Signing-Seite für Hinweise zu special slots und DER entitlements

Hinweis: Multi-Architektur-(fat-)Binaries enthalten mehrere Mach-O-Slices. Du musst den Slice für die Architektur auswählen, die du untersuchen möchtest, und anschließend dessen load commands durchlaufen.


## Extraktionsschritte (generisch, ausreichend verlustfrei)

1) Mach-O-Header parsen; ncmds load_command-Datensätze durchlaufen.
2) LC_CODE_SIGNATURE finden; linkedit_data_command.dataoff/datasize lesen, um den in __LINKEDIT abgelegten Code Signing SuperBlob abzubilden.
3) Prüfen, ob CS_SuperBlob.magic == 0xfade0cc0 ist; die count-Einträge von CS_BlobIndex durchlaufen.
4) Den Eintrag index.type == 0xfade7171 (embedded entitlements) finden. Den referenzierten CS_GenericBlob lesen und dessen Daten als Apple binary plist (bplist00) parsen, um die Key/Value-entitlements zu erhalten.<sup>[[1]](#references)</sup>

Implementierungshinweise:
- Code-Signature-Strukturen verwenden Big-Endian-Felder; beim Parsen auf Little-Endian-Hosts die Byte-Reihenfolge tauschen.
- Die Daten des Entitlements GenericBlob selbst sind eine binary plist (wird von Standard-plist-Bibliotheken verarbeitet).
- Einige iOS-Binaries können DER entitlements enthalten; außerdem unterscheiden sich manche Stores/Slots je nach Plattform/Version. Bei Bedarf sowohl standardmäßige als auch DER entitlements überprüfen.
- Bei fat Binaries die fat headers (FAT_MAGIC/FAT_MAGIC_64) verwenden, um den korrekten Slice und Offset zu finden, bevor die Mach-O load commands durchlaufen werden.<sup>[[1]](#references)</sup>


## Minimale Parsing-Übersicht (Python)

Die folgende kompakte Übersicht zeigt den Kontrollfluss zum Finden und Dekodieren von entitlements. Der Kürze halber werden robuste Bounds Checks und die vollständige Unterstützung für fat Binaries bewusst ausgelassen.<sup>[[1]](#references)</sup>
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
Verwendungstipps:
- Um fat binaries zu verarbeiten, lies zuerst `struct fat_header`/`fat_arch`, wähle den gewünschten Architektur-Slice aus und übergib anschließend den Teilbereich an `parse_entitlements`.
- Unter macOS kannst du die Ergebnisse mit folgendem Befehl validieren: `codesign -d --entitlements :- /path/to/binary`


## Beispielergebnisse

Privilegierte platform binaries fordern häufig sensible entitlements an:<sup>[[1]](#references)</sup>
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

Diese auf breiter Ebene über Firmware-Images hinweg zu suchen, ist für das Mapping der Angriffsfläche sowie das Diffing zwischen Releases und Geräten äußerst wertvoll.


## Skalierung über IPSWs hinweg (Mounten und Indexieren)

Um Executables auf breiter Ebene aufzulisten und entitlements zu extrahieren, ohne vollständige Images zu speichern:<sup>[[1]](#references)</sup>

- Verwende das ipsw-Tool von @blacktop, um Firmware-Dateisysteme herunterzuladen und zu mounten. Das Mounten nutzt apfs-fuse, sodass du APFS-Volumes ohne vollständige Extraktion durchsuchen kannst.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- Durchsuche gemountete Volumes nach Mach-O-Dateien (Magic prüfen und/oder `file`/`otool` verwenden), und parse anschließend Entitlements und importierte Frameworks.
- Speichere eine normalisierte Ansicht in einer relationalen Datenbank, um lineares Wachstum bei tausenden IPSWs zu vermeiden:
- executables, operating_system_versions, entitlements, frameworks
- Viele-zu-viele-Beziehungen: executable↔OS version, executable↔entitlement, executable↔framework

Beispielabfrage, um alle OS-Versionen aufzulisten, die einen bestimmten Namen eines Executables enthalten:
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = "launchd";
```
Hinweise zur DB-Portabilität (falls du deinen eigenen Indexer implementierst):<sup>[[1]](#references)</sup>
- Verwende ein ORM/eine Abstraktion (z. B. SeaORM), damit der Code DB-agnostisch bleibt (SQLite/PostgreSQL).
- SQLite erfordert AUTOINCREMENT nur bei einem INTEGER PRIMARY KEY; wenn du i64-PKs in Rust verwenden möchtest, generiere Entitäten als i32 und konvertiere die Typen. SQLite speichert INTEGER intern als vorzeichenbehaftete 8-Byte-Werte.<sup>[[8]](#references)</sup>


## Open-Source-Tools und Referenzen für die Entitlement-Suche

- Firmware mount/download: https://github.com/blacktop/ipsw<sup>[[3]](#references)</sup>
- Entitlement-Datenbanken und Referenzen:
- Jonathan Levins Entitlement-DB: https://newosxbook.com/ent.php<sup>[[4]](#references)</sup>
- entdb: https://github.com/ChiChou/entdb<sup>[[5]](#references)</sup>
- Großangelegter Indexer (Rust, selbst gehostete Web UI + OpenAPI): https://github.com/synacktiv/appledb_rs<sup>[[2]](#references)</sup>
- Apple-Header für Strukturen und Konstanten:
- loader.h (Mach-O-Header, load commands)
- cs_blobs.h (SuperBlob, GenericBlob, CodeDirectory)

Weitere Informationen zu den Interna von Code Signing (Code Directory, special slots, DER entitlements) findest du unter: [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)


## Referenzen

- [1] [appledb_rs: a research support tool for Apple platforms](https://www.synacktiv.com/publications/appledbrs-un-outil-daide-a-la-recherche-sur-plateformes-apple.html)
- [2] [synacktiv/appledb_rs](https://github.com/synacktiv/appledb_rs)
- [3] [blacktop/ipsw](https://github.com/blacktop/ipsw)
- [4] [Jonathan Levin’s entitlement DB](https://newosxbook.com/ent.php)
- [5] [ChiChou/entdb](https://github.com/ChiChou/entdb)
- [6] [XNU cs_blobs.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [7] [XNU mach-o/loader.h](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [8] [SQLite Datatypes](https://sqlite.org/datatype3.html)

{{#include ../../../banners/hacktricks-training.md}}
