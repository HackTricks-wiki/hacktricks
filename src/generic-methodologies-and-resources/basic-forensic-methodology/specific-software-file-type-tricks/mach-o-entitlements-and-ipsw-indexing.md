# Extraktion von Mach-O-Entitlements & IPSW-Indexierung

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Diese Seite beschreibt, wie Entitlements programmgesteuert aus Mach-O-Binaries extrahiert werden, indem LC_CODE_SIGNATURE durchlaufen und der Code-Signing-SuperBlob geparst wird. Außerdem wird beschrieben, wie sich dieser Vorgang auf Apple-IPSW-Firmwares skalieren lässt, indem deren Inhalte für die forensische Suche und das Diffing gemountet und indexiert werden.

Wenn du eine Auffrischung zum Mach-O-Format und zu Code Signing benötigst, siehe auch: macOS Code Signing und die Interna von SuperBlob.
- Details zu macOS Code Signing (SuperBlob, Code Directory, spezielle Slots): [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- Allgemeine Mach-O-Strukturen und Load Commands: [Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Entitlements in Mach-O: Wo sie gespeichert sind

Entitlements werden innerhalb der von der LC_CODE_SIGNATURE-Load-Command referenzierten Code-Signing-Daten gespeichert und im __LINKEDIT-Segment abgelegt. Die Signatur ist ein CS_SuperBlob, der mehrere Blobs enthält (Code Directory, Requirements, Entitlements, CMS usw.). Der Entitlements-Blob ist ein CS_GenericBlob, dessen Daten eine serialisierte Property List sind, die Entitlement-Schlüssel auf Werte abbildet. Parser sollten sowohl XML- als auch binäre Plist-Kodierungen akzeptieren.<sup>[[1]](#references)[[6]](#references)</sup>

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
uint32_t type;    /* slot type, e.g. CSSLOT_ENTITLEMENTS = 5 */
uint32_t offset;  /* offset of entry */
} CS_BlobIndex;

typedef struct __SC_GenericBlob {
uint32_t magic;   /* blob magic, e.g. CSMAGIC_EMBEDDED_ENTITLEMENTS */
uint32_t length;
char data[];      /* serialized plist containing entitlements */
} CS_GenericBlob;
```
Wichtige Konstanten aus den Apple-Headern umfassen:<sup>[[6]](#references)[[7]](#references)</sup>
- LC_CODE_SIGNATURE cmd = 0x1d
- CS SuperBlob magic = 0xfade0cc0
- Entitlements index slot (`CSSLOT_ENTITLEMENTS`) = 5; der Blob an diesem Slot hat die Magic `CSMAGIC_EMBEDDED_ENTITLEMENTS` = 0xfade7171
- DER entitlements verwenden den Slot `CSSLOT_DER_ENTITLEMENTS` = 7 und die Blob-Magic `CSMAGIC_EMBEDDED_DER_ENTITLEMENTS` = 0xfade7172

Hinweis: Multi-Arch-(fat-)Binaries enthalten mehrere Mach-O-Slices. Sie müssen den Slice für die gewünschte Architektur auswählen und anschließend dessen Load Commands durchlaufen.


## Extraktionsschritte (generisch, ausreichend verlustfrei)

1) Mach-O-Header parsen; so viele `load_command`-Records durchlaufen, wie `ncmds` angibt.
2) LC_CODE_SIGNATURE lokalisieren; `linkedit_data_command.dataoff/datasize` auslesen, um den im `__LINKEDIT` platzierten Code Signing SuperBlob zuzuordnen.
3) Überprüfen, dass `CS_SuperBlob.magic == 0xfade0cc0` ist; die `count`-Einträge von `CS_BlobIndex` durchlaufen.
4) `index.type == CSSLOT_ENTITLEMENTS` (5) lokalisieren und anschließend überprüfen, dass der referenzierte `CS_GenericBlob` die Magic `CSMAGIC_EMBEDDED_ENTITLEMENTS` (0xfade7171) hat. Seine Daten als Property List parsen, um die Key/Value-Entitlements zu erhalten.<sup>[[1]](#references)[[6]](#references)</sup>

Implementierungshinweise:
- Code-Signature-Strukturen verwenden Big-Endian-Felder; beim Parsen auf Little-Endian-Hosts muss die Byte-Reihenfolge vertauscht werden.
- Der Entitlements-`GenericBlob` enthält eine serialisierte Plist; standardmäßige Plist-Bibliotheken können deren XML- oder Binärdarstellung verarbeiten.
- Einige iOS-Binaries können DER entitlements enthalten; XNU stellt einen separaten DER-Blob-Typ bereit, und Entitlement-Darstellungen oder Slots können sich je nach Plattform und Version unterscheiden. Daher sollten bei Bedarf standardmäßige und DER entitlements gegengeprüft werden.<sup>[[6]](#references)</sup>
- Verwenden Sie bei fat Binaries die Fat-Header (`FAT_MAGIC/FAT_MAGIC_64`), um den korrekten Slice und Offset zu lokalisieren, bevor Sie die Mach-O-Load-Commands durchlaufen.


## Minimale Parsing-Übersicht (Python)

Die folgende kompakte Übersicht zeigt den Kontrollfluss zum Auffinden und Decodieren von Entitlements. Der Kürze halber werden robuste Bounds-Checks und die vollständige Unterstützung für fat Binaries absichtlich ausgelassen.<sup>[[6]](#references)[[7]](#references)</sup>
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
Usage tips:
- Um fat binaries zu verarbeiten, lies zunächst struct fat_header/fat_arch, wähle den gewünschten Architektur-Slice aus und übergib anschließend den Subbereich an parse_entitlements.
- Unter macOS kannst du die Ergebnisse mit folgendem Befehl validieren: codesign -d --entitlements :- /path/to/binary


## Beispielbefunde

Der Quellartikel zeigt diese Entitlements in der macOS-14.0-`launchd`-Binary:<sup>[[1]](#references)</sup>
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

Das systematische Suchen nach diesen Entitlements in Firmware-Images ist für die Abbildung der Angriffsfläche sowie den Vergleich zwischen Releases und Geräten äußerst wertvoll.


## Skalierung über IPSWs (Mounten und Indexieren)

Um Executables systematisch aufzulisten und Entitlements zu extrahieren, ohne vollständige Images zu speichern:<sup>[[1]](#references)</sup>

- Verwende das Tool ipsw von @blacktop, um Firmware-Dateisysteme herunterzuladen und zu mounten. Das Mounten nutzt apfs-fuse, sodass du APFS-Volumes ohne vollständige Extraktion durchsuchen kannst.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- Durchsuche gemountete Volumes, um Mach-O-Dateien zu finden (überprüfe die Magic Number und/oder verwende file/otool). Analysiere anschließend Entitlements und importierte Frameworks.
- Speichere eine normalisierte Ansicht in einer relationalen Datenbank, um lineares Wachstum bei Tausenden von IPSWs zu vermeiden:
- executables, operating_system_versions, entitlements, frameworks
- Viele-zu-viele-Beziehungen: executable↔OS version, executable↔entitlement, executable↔framework

Beispielabfrage, um alle OS-Versionen aufzulisten, die einen bestimmten Namen einer ausführbaren Datei enthalten (angepasst von appledb_rs):<sup>[[1]](#references)</sup>
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = 'launchd';
```
Hinweise zur DB-Portabilität (falls du deinen eigenen Indexer implementierst):<sup>[[1]](#references)</sup>
- Verwende ein ORM/eine Abstraktion (z. B. SeaORM), damit der Code DB-agnostisch bleibt (SQLite/PostgreSQL).
- SQLite erlaubt `AUTOINCREMENT` nur für einen `INTEGER PRIMARY KEY`; dieser Schlüssel ist ein Alias für eine vorzeichenbehaftete 64-Bit-ROWID, obwohl SQLite auf der Festplatte möglicherweise kleinere Integer-Breiten verwendet. Wenn von SeaORM generierte Rust-Entities i64-IDs benötigen, generiere die Entities als i32 und konvertiere die Typen an der Grenze.<sup>[[1]](#references)[[8]](#references)[[9]](#references)</sup>


## Open-Source-Tools und Referenzen für die Entitlement-Suche

- Firmware mount/download: https://github.com/blacktop/ipsw.<sup>[[3]](#references)</sup>
- Entitlement-Datenbanken und Referenzen:
- Entitlement-DB von Jonathan Levin: https://newosxbook.com/ent.php.<sup>[[4]](#references)</sup>
- entdb: https://github.com/ChiChou/entdb.<sup>[[5]](#references)</sup>
- Groß angelegter Indexer (Rust, selbst gehostete Web UI + OpenAPI): https://github.com/synacktiv/appledb_rs.<sup>[[2]](#references)</sup>
- Apple-Header für Strukturen und Konstanten:
- loader.h (Mach-O-Header, load commands)
- cs_blobs.h (SuperBlob, GenericBlob, CodeDirectory)

Weitere Informationen zu den Interna von Code Signing (Code Directory, special slots, DER entitlements) findest du unter: [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)


## References

- [1] [Corentin Liaud (Synacktiv), appledb_rs: ein Tool zur Forschungsunterstützung für Apple-Plattformen](https://www.synacktiv.com/publications/appledbrs-un-outil-daide-a-la-recherche-sur-plateformes-apple.html)
- [2] [synacktiv/appledb_rs](https://github.com/synacktiv/appledb_rs)
- [3] [blacktop/ipsw](https://github.com/blacktop/ipsw)
- [4] [Entitlement-DB von Jonathan Levin](https://newosxbook.com/ent.php)
- [5] [ChiChou/entdb](https://github.com/ChiChou/entdb)
- [6] [XNU cs_blobs.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [7] [XNU mach-o/loader.h](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [8] [SQLite-Datentypen](https://sqlite.org/datatype3.html)
- [9] [SQLite-Autoincrement](https://sqlite.org/autoinc.html)
{{#include ../../../banners/hacktricks-training.md}}
