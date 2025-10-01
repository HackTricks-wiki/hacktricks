# Mach-O Estrazione degli Entitlements & Indicizzazione IPSW

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

Questa pagina spiega come estrarre gli entitlements dai binari Mach-O in modo programmatico percorrendo LC_CODE_SIGNATURE e parsando il SuperBlob della firma del codice, e come scalare questo processo attraverso i firmware Apple IPSW montando e indicizzando i loro contenuti per ricerca/diff forense.

Se ti serve un ripasso sul formato Mach-O e sul code signing, vedi anche: macOS code signing and SuperBlob internals.
- Check macOS code signing details (SuperBlob, Code Directory, special slots): [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- Check general Mach-O structures/load commands: [Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Entitlements in Mach-O: where they live

Gli entitlements sono memorizzati all'interno dei dati della firma del codice referenziati dal load command LC_CODE_SIGNATURE e posizionati nel segmento __LINKEDIT. La signature è una CS_SuperBlob contenente multiple blob (code directory, requirements, entitlements, CMS, ecc.). L'entitlements blob è una CS_GenericBlob il cui dato è un Apple Binary Property List (bplist00) che mappa le chiavi degli entitlements ai valori.

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
Costanti importanti:
- LC_CODE_SIGNATURE cmd = 0x1d
- CS SuperBlob magic = 0xfade0cc0
- Entitlements blob type (CSMAGIC_EMBEDDED_ENTITLEMENTS) = 0xfade7171
- DER entitlements possono essere presenti tramite slot speciali (es., -7); vedi la pagina macOS Code Signing per note su slot speciali e DER entitlements

Nota: Multi-arch (fat) binaries contengono multiple Mach-O slices. Devi selezionare la slice per l'architettura che vuoi ispezionare e poi percorrere i suoi load commands.


## Passaggi di estrazione (generici, sufficientemente senza perdita)

1) Analizza l'header Mach-O; itera i record load_command per il numero ncmds.
2) Individua LC_CODE_SIGNATURE; leggi linkedit_data_command.dataoff/datasize per mappare il Code Signing SuperBlob posizionato in __LINKEDIT.
3) Valida CS_SuperBlob.magic == 0xfade0cc0; itera count voci di CS_BlobIndex.
4) Individua index.type == 0xfade7171 (embedded entitlements). Leggi il CS_GenericBlob puntato e parsalo come un plist binario Apple (bplist00) per ottenere entitlements chiave/valore.

Note di implementazione:
- Le strutture di Code signature utilizzano campi big-endian; scambia l'ordine dei byte quando esegui il parsing su host little-endian.
- I dati del GenericBlob delle entitlements sono un plist binario (gestito dalle librerie plist standard).
- Alcuni binari iOS possono includere DER entitlements; inoltre alcuni store/slot variano tra piattaforme/versioni. Verifica sia le entitlements standard sia quelle DER se necessario.
- Per i binari fat, usa gli header fat (FAT_MAGIC/FAT_MAGIC_64) per localizzare la slice e l'offset corretti prima di attraversare i load commands Mach-O.


## Schema minimo di parsing (Python)

Quanto segue è uno schema compatto che mostra il flusso di controllo per trovare e decodificare le entitlements. Omesso intenzionalmente controlli di confine robusti e il supporto completo per binari fat per brevità.
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
- Per gestire fat binaries, prima leggi struct fat_header/fat_arch, scegli la slice di architettura desiderata, poi passa il sottointervallo a parse_entitlements.
- Su macOS puoi verificare i risultati con: codesign -d --entitlements :- /path/to/binary


## Esempi di risultati

I binari di piattaforma privilegiati spesso richiedono entitlements sensibili come:
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

La ricerca di questi su larga scala attraverso le immagini firmware è estremamente utile per attack surface mapping e per il diffing tra release/dispositivi.


## Scalare attraverso IPSWs (montaggio e indicizzazione)

Per enumerare gli eseguibili ed estrarre gli entitlements su larga scala senza conservare le immagini complete:

- Usa lo strumento ipsw di @blacktop per scaricare e montare i filesystem del firmware. Il montaggio sfrutta apfs-fuse, così puoi attraversare i volumi APFS senza estrazione completa.
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- Esplora i volumi montati per individuare file Mach-O (controlla magic e/o usa file/otool), poi analizza entitlements e imported frameworks.
- Conserva una vista normalizzata in un database relazionale per evitare una crescita lineare attraverso migliaia di IPSWs:
- executables, operating_system_versions, entitlements, frameworks
- relazione molti-a-molti: executable↔OS version, executable↔entitlement, executable↔framework

Esempio di query per elencare tutte le OS versions che contengono un dato executable name:
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = "launchd";
```
Note sulla portabilità del DB (se implementi il tuo indexer):
- Usa un ORM/abstraction (es., SeaORM) per mantenere il codice DB-agnostic (SQLite/PostgreSQL).
- SQLite richiede AUTOINCREMENT solo su un INTEGER PRIMARY KEY; se vuoi i64 PKs in Rust, genera le entità come i32 e converti i tipi, SQLite memorizza INTEGER come intero con segno a 8 byte internamente.


## Open-source tooling and references for entitlement hunting

- Firmware mount/download: https://github.com/blacktop/ipsw
- Databases e riferimenti per entitlements:
- Jonathan Levin’s entitlement DB: https://newosxbook.com/ent.php
- entdb: https://github.com/ChiChou/entdb
- Large-scale indexer (Rust, self-hosted Web UI + OpenAPI): https://github.com/synacktiv/appledb_rs
- Apple headers per strutture e costanti:
- loader.h (Mach-O headers, load commands)
- cs_blobs.h (SuperBlob, GenericBlob, CodeDirectory)

Per maggiori dettagli sugli internals del code signing (Code Directory, special slots, DER entitlements), vedi: [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)


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
