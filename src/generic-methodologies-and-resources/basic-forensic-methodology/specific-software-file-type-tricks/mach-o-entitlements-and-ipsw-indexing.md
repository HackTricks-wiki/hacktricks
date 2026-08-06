# Estrazione degli Entitlements Mach-O e indicizzazione degli IPSW

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

Questa pagina illustra come estrarre programmaticamente gli entitlements dai binari Mach-O attraversando LC_CODE_SIGNATURE e analizzando il code signing SuperBlob, nonché come scalare questa procedura tra i firmware IPSW di Apple montandone e indicizzandone i contenuti per la ricerca/diff forense.

Se ti serve un ripasso sul formato Mach-O e sul code signing, consulta anche: dettagli sul code signing di macOS e sugli interni del SuperBlob.
- Consulta i dettagli del code signing di macOS (SuperBlob, Code Directory, slot speciali): [Code Signing di macOS](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- Consulta le strutture Mach-O generali/load commands: [Binari universali e formato Mach-O](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Entitlements in Mach-O: dove si trovano

Gli entitlements sono memorizzati all'interno dei dati della code signature referenziati dal load command LC_CODE_SIGNATURE e collocati nel segmento __LINKEDIT. La signature è un CS_SuperBlob contenente più blob (code directory, requirements, entitlements, CMS, ecc.). Il blob degli entitlements è un CS_GenericBlob i cui dati consistono in un Apple Binary Property List (bplist00) che associa le chiavi degli entitlements ai relativi valori.<sup>[[1]](#references)</sup>

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
uint32_t type;    /* e.g., CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7171 */
uint32_t offset;  /* offset of entry */
} CS_BlobIndex;

typedef struct __SC_GenericBlob {
uint32_t magic;   /* same as type when standalone */
uint32_t length;
char data[];      /* Apple Binary Plist containing entitlements */
} CS_GenericBlob;
```
Importanti costanti:
- comando LC_CODE_SIGNATURE = 0x1d
- magic di CS SuperBlob = 0xfade0cc0
- tipo di blob degli entitlements (CSMAGIC_EMBEDDED_ENTITLEMENTS) = 0xfade7171
- Gli entitlements DER possono essere presenti tramite uno slot speciale (ad es., -7); consulta la pagina macOS Code Signing per informazioni sugli slot speciali e sugli entitlements DER

Nota: i binari multi-arch (fat) contengono più slice Mach-O. Devi selezionare la slice relativa all'architettura che vuoi esaminare e quindi analizzarne i load commands.


## Passaggi di estrazione (generici, sufficientemente lossless)

1) Analizza l'header Mach-O; itera sui record load_command indicati da ncmds.
2) Individua LC_CODE_SIGNATURE; leggi dataoff/datasize di linkedit_data_command per mappare il Code Signing SuperBlob collocato in __LINKEDIT.
3) Verifica che CS_SuperBlob.magic == 0xfade0cc0; itera sulle entry count di CS_BlobIndex.
4) Individua index.type == 0xfade7171 (entitlements embedded). Leggi il CS_GenericBlob puntato e analizza i suoi dati come Apple binary plist (bplist00) per ottenere gli entitlements key/value.<sup>[[1]](#references)</sup>

Note di implementazione:
- Le strutture della code signature usano campi big-endian; inverti l'ordine dei byte durante l'analisi su host little-endian.
- I dati del GenericBlob degli entitlements sono a loro volta un binary plist (gestito dalle librerie plist standard).
- Alcuni binari iOS possono contenere entitlements DER; inoltre, alcuni store/slot differiscono tra piattaforme e versioni. Esegui il cross-check degli entitlements standard e DER secondo necessità.
- Per i binari fat, usa gli header fat (FAT_MAGIC/FAT_MAGIC_64) per individuare la slice corretta e il relativo offset prima di analizzare i load commands Mach-O.<sup>[[1]](#references)</sup>


## Schema minimo di parsing (Python)

Di seguito è riportato uno schema compatto che mostra il flusso di controllo per trovare e decodificare gli entitlements. Per brevità, omette i robusti controlli dei limiti e il supporto completo ai binari fat.<sup>[[1]](#references)</sup>
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
Suggerimenti d'uso:
- Per gestire i fat binaries, leggi prima struct fat_header/fat_arch, scegli lo slice dell'architettura desiderata, quindi passa il subrange a parse_entitlements.
- Su macOS puoi convalidare i risultati con: codesign -d --entitlements :- /path/to/binary


## Esempi di risultati

I binary di piattaforma privilegiati spesso richiedono entitlements sensibili:<sup>[[1]](#references)</sup>
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

La ricerca di questi elementi su larga scala nelle immagini firmware è estremamente utile per la mappatura della attack surface e il confronto tra release/device.


## Scalabilità tra IPSW (montaggio e indicizzazione)

Per enumerare gli eseguibili ed estrarre gli entitlements su larga scala senza archiviare le immagini complete:<sup>[[1]](#references)</sup>

- Usa il tool ipsw di @blacktop per scaricare e montare i filesystem del firmware. Il montaggio sfrutta apfs-fuse, permettendo di attraversare i volumi APFS senza un'estrazione completa.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- Percorri i volumi montati per individuare i file Mach-O (verifica il magic e/o usa file/otool), quindi analizza gli entitlements e i frameworks importati.
- Mantieni una vista normalizzata in un database relazionale per evitare una crescita lineare tra migliaia di IPSW:
- executables, operating_system_versions, entitlements, frameworks
- molti-a-molti: executable↔OS version, executable↔entitlement, executable↔framework

Esempio di query per elencare tutte le versioni di OS contenenti un determinato nome di executable:
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = "launchd";
```
Note sulla portabilità del DB (se implementi il tuo indexer):<sup>[[1]](#references)</sup>
- Usa un ORM/astrazione (ad es., SeaORM) per mantenere il codice indipendente dal DB (SQLite/PostgreSQL).
- SQLite richiede AUTOINCREMENT solo su una INTEGER PRIMARY KEY; se vuoi PK i64 in Rust, genera le entities come i32 e converti i tipi; internamente, SQLite memorizza INTEGER come interi signed a 8 byte.<sup>[[8]](#references)</sup>


## Tooling open-source e riferimenti per la ricerca degli entitlements

- Mount/download del firmware: https://github.com/blacktop/ipsw
- Database e riferimenti sugli entitlements:
- DB degli entitlements di Jonathan Levin: https://newosxbook.com/ent.php
- entdb: https://github.com/ChiChou/entdb
- Indexer su larga scala (Rust, Web UI self-hosted + OpenAPI): https://github.com/synacktiv/appledb_rs
- Header Apple per strutture e costanti:
- loader.h (header Mach-O, load commands)
- cs_blobs.h (SuperBlob, GenericBlob, CodeDirectory)

Per ulteriori informazioni sugli internals del code signing (Code Directory, special slots, entitlements DER), consulta: [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)


## Riferimenti

- [1] [appledb_rs: uno strumento di supporto alla ricerca per le piattaforme Apple](https://www.synacktiv.com/publications/appledbrs-un-outil-daide-a-la-recherche-sur-plateformes-apple.html)
- [2] [synacktiv/appledb_rs](https://github.com/synacktiv/appledb_rs)
- [3] [blacktop/ipsw](https://github.com/blacktop/ipsw)
- [4] [DB degli entitlements di Jonathan Levin](https://newosxbook.com/ent.php)
- [5] [ChiChou/entdb](https://github.com/ChiChou/entdb)
- [6] [XNU cs_blobs.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [7] [XNU mach-o/loader.h](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [8] [Tipi di dati SQLite](https://sqlite.org/datatype3.html)

{{#include ../../../banners/hacktricks-training.md}}
