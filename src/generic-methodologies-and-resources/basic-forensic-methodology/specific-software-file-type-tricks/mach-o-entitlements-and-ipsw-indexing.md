# Estrazione degli Entitlements Mach-O e indicizzazione IPSW

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

Questa pagina descrive come estrarre programmaticamente gli entitlements dai binari Mach-O attraversando LC_CODE_SIGNATURE e analizzando il code signing SuperBlob, nonché come scalare questa procedura sui firmware IPSW di Apple montandone e indicizzandone i contenuti per la ricerca/diff forense.

Se ti serve un ripasso sul formato Mach-O e sul code signing, consulta anche: macOS code signing e i componenti interni di SuperBlob.
- Consulta i dettagli sul macOS code signing (SuperBlob, Code Directory, special slots): [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- Consulta le strutture Mach-O generali/load commands: [Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Entitlements in Mach-O: dove si trovano

Gli entitlements sono memorizzati nei dati della code signature referenziati dal load command LC_CODE_SIGNATURE e inseriti nel segmento __LINKEDIT. La signature è un CS_SuperBlob contenente più blob (code directory, requirements, entitlements, CMS, ecc.). Il blob degli entitlements è un CS_GenericBlob i cui dati consistono in una property list serializzata che associa le chiavi degli entitlements ai relativi valori; i parser dovrebbero accettare sia la codifica XML sia quella binary plist.<sup>[[1]](#references)[[6]](#references)</sup>

Strutture principali (da xnu):<sup>[[6]](#references)[[7]](#references)</sup>
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
Le costanti importanti dagli header Apple includono:<sup>[[6]](#references)[[7]](#references)</sup>
- LC_CODE_SIGNATURE cmd = 0x1d
- CS SuperBlob magic = 0xfade0cc0
- Entitlements index slot (`CSSLOT_ENTITLEMENTS`) = 5; il blob in quello slot ha magic `CSMAGIC_EMBEDDED_ENTITLEMENTS` = 0xfade7171
- DER entitlements usano lo slot `CSSLOT_DER_ENTITLEMENTS` = 7 e il blob magic `CSMAGIC_EMBEDDED_DER_ENTITLEMENTS` = 0xfade7172

Nota: i binary multi-arch (fat) contengono più slice Mach-O. È necessario selezionare la slice relativa all'architettura da analizzare e poi attraversare i suoi load commands.


## Passaggi di estrazione (generici, sufficientemente lossless)

1) Analizzare l'header Mach-O; iterare il numero di record `load_command` indicato da ncmds.
2) Individuare LC_CODE_SIGNATURE; leggere `linkedit_data_command.dataoff/datasize` per mappare il Code Signing SuperBlob posizionato in __LINKEDIT.
3) Verificare `CS_SuperBlob.magic == 0xfade0cc0`; iterare le entry count di `CS_BlobIndex`.
4) Individuare `index.type == CSSLOT_ENTITLEMENTS` (5), quindi verificare che il `CS_GenericBlob` puntato abbia magic `CSMAGIC_EMBEDDED_ENTITLEMENTS` (0xfade7171). Analizzare i suoi dati come property list per ottenere le entitlements key/value.<sup>[[1]](#references)[[6]](#references)</sup>

Note di implementazione:
- Le strutture della Code signature usano campi big-endian; invertire l'ordine dei byte durante l'analisi su host little-endian.
- L'`GenericBlob` delle entitlements contiene una plist serializzata; le librerie standard per plist possono gestirne la rappresentazione XML o binary.
- Alcuni binary iOS possono contenere DER entitlements; XNU espone un tipo di blob DER separato e le rappresentazioni o gli slot delle entitlements possono differire tra piattaforme e versioni, quindi verificare, quando necessario, sia le entitlements standard sia quelle DER.<sup>[[6]](#references)</sup>
- Per i binary fat, usare gli header fat (FAT_MAGIC/FAT_MAGIC_64) per individuare la slice e l'offset corretti prima di attraversare i load commands Mach-O.


## Schema di parsing minimale (Python)

Di seguito è riportato uno schema compatto che mostra il flusso di controllo per individuare e decodificare le entitlements. Per brevità, omette i robusti controlli dei limiti e il supporto completo ai binary fat.<sup>[[6]](#references)[[7]](#references)</sup>
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
Suggerimenti d'uso:
- Per gestire i fat binaries, leggi prima `struct fat_header/fat_arch`, scegli lo slice dell'architettura desiderata, quindi passa il sottointervallo a `parse_entitlements`.
- Su macOS puoi convalidare i risultati con: `codesign -d --entitlements :- /path/to/binary`


## Risultati di esempio

L'articolo sorgente mostra questi entitlements nel binary `launchd` di macOS 14.0:<sup>[[1]](#references)</sup>
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

La ricerca di questi elementi su larga scala nelle firmware images è estremamente utile per la mappatura della attack surface e il confronto tra release/device.


## Scaling tra IPSW (mounting e indexing)

Per enumerare gli eseguibili ed estrarre gli entitlements su larga scala senza memorizzare le immagini complete:<sup>[[1]](#references)</sup>

- Usa lo strumento ipsw di @blacktop per scaricare e montare i filesystem del firmware. Il mounting sfrutta apfs-fuse, quindi puoi attraversare i volumi APFS senza un'estrazione completa.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- Scansionare i volumi montati per individuare i file Mach-O (verificare il magic e/o usare file/otool), quindi analizzare gli entitlements e i framework importati.
- Salvare una vista normalizzata in un database relazionale per evitare una crescita lineare su migliaia di IPSW:
- executables, operating_system_versions, entitlements, frameworks
- molti-a-molti: executable↔OS version, executable↔entitlement, executable↔framework

Esempio di query per elencare tutte le versioni del sistema operativo contenenti un determinato nome di executable (adattato da appledb_rs):<sup>[[1]](#references)</sup>
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = 'launchd';
```
Note sulla portabilità del DB (se implementi il tuo indexer):<sup>[[1]](#references)</sup>
- Usa un ORM/abstraction (ad es., SeaORM) per mantenere il codice indipendente dal DB (SQLite/PostgreSQL).
- SQLite consente `AUTOINCREMENT` solo su una `INTEGER PRIMARY KEY`; questa chiave è un alias di un ROWID con signed 64-bit, sebbene SQLite possa usare integer widths più piccole su disco. Se le entità Rust generate da SeaORM richiedono ID i64, genera le entità come i32 e converti i tipi al boundary.<sup>[[1]](#references)[[8]](#references)[[9]](#references)</sup>


## Tool open-source e riferimenti per la ricerca degli entitlement

- Mount/download del firmware: https://github.com/blacktop/ipsw.<sup>[[3]](#references)</sup>
- Database e riferimenti sugli entitlement:
- Jonathan Levin’s entitlement DB: https://newosxbook.com/ent.php.<sup>[[4]](#references)</sup>
- entdb: https://github.com/ChiChou/entdb.<sup>[[5]](#references)</sup>
- Indexer su larga scala (Rust, Web UI self-hosted + OpenAPI): https://github.com/synacktiv/appledb_rs.<sup>[[2]](#references)</sup>
- Header Apple per strutture e costanti:
- loader.h (header Mach-O, load commands)
- cs_blobs.h (SuperBlob, GenericBlob, CodeDirectory)

Per ulteriori informazioni sugli internals della code signing (Code Directory, special slots, DER entitlements), consulta: [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)


## References

- [1] [Corentin Liaud (Synacktiv), appledb_rs: uno strumento di supporto alla ricerca per le piattaforme Apple](https://www.synacktiv.com/publications/appledbrs-un-outil-daide-a-la-recherche-sur-plateformes-apple.html)
- [2] [synacktiv/appledb_rs](https://github.com/synacktiv/appledb_rs)
- [3] [blacktop/ipsw](https://github.com/blacktop/ipsw)
- [4] [Jonathan Levin’s entitlement DB](https://newosxbook.com/ent.php)
- [5] [ChiChou/entdb](https://github.com/ChiChou/entdb)
- [6] [XNU cs_blobs.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [7] [XNU mach-o/loader.h](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [8] [SQLite Datatypes](https://sqlite.org/datatype3.html)
- [9] [SQLite Autoincrement](https://sqlite.org/autoinc.html)
{{#include ../../../banners/hacktricks-training.md}}
