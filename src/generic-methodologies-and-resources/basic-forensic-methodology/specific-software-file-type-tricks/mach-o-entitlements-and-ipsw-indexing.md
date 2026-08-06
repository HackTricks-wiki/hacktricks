# Extracción de Entitlements de Mach-O e indexación de IPSW

{{#include ../../../banners/hacktricks-training.md}}

## Dónde se encuentran los Entitlements en Mach-O

Esta página explica cómo extraer programáticamente los entitlements de binarios Mach-O recorriendo LC_CODE_SIGNATURE y analizando el SuperBlob de firma de código, así como cómo escalar este proceso a través de firmwares IPSW de Apple montando e indexando su contenido para búsquedas y comparaciones forenses.

Si necesitas repasar el formato Mach-O y la firma de código, consulta también: macOS code signing e internos de SuperBlob.
- Consulta los detalles de macOS code signing (SuperBlob, Code Directory, special slots): [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- Consulta las estructuras generales de Mach-O/load commands: [Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


Los entitlements se almacenan dentro de los datos de firma de código referenciados por el load command LC_CODE_SIGNATURE y ubicados en el segmento __LINKEDIT. La firma es un CS_SuperBlob que contiene varios blobs (code directory, requirements, entitlements, CMS, etc.). El blob de entitlements es un CS_GenericBlob cuyos datos son un Apple Binary Property List (bplist00) que asigna claves de entitlements a valores.<sup>[[1]](#references)</sup>

Estructuras clave (de xnu):<sup>[[6]](#references)[[7]](#references)</sup>
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
Constantes importantes:
- LC_CODE_SIGNATURE cmd = 0x1d
- CS SuperBlob magic = 0xfade0cc0
- Entitlements blob type (CSMAGIC_EMBEDDED_ENTITLEMENTS) = 0xfade7171
- DER entitlements pueden estar presentes mediante un slot especial (por ejemplo, -7); consulta la página macOS Code Signing para obtener información sobre los special slots y las notas sobre DER entitlements

Nota: Los binarios multi-arch (fat) contienen múltiples slices de Mach-O. Debes elegir el slice correspondiente a la arquitectura que quieres inspeccionar y, después, recorrer sus load commands.


## Pasos de extracción (genéricos, suficientemente lossless)

1) Analiza la cabecera de Mach-O; itera los registros load_command indicados por ncmds.
2) Localiza LC_CODE_SIGNATURE; lee dataoff/datasize de linkedit_data_command para mapear el Code Signing SuperBlob ubicado en __LINKEDIT.
3) Valida que CS_SuperBlob.magic == 0xfade0cc0; itera las entradas count de CS_BlobIndex.
4) Localiza index.type == 0xfade7171 (embedded entitlements). Lee el CS_GenericBlob apuntado y analiza sus datos como un Apple binary plist (bplist00) para obtener los entitlements de tipo clave/valor.<sup>[[1]](#references)</sup>

Notas de implementación:
- Las estructuras de code signature utilizan campos big-endian; intercambia el orden de los bytes al analizar en hosts little-endian.
- Los datos del entitlements GenericBlob son un binary plist (gestionado por las librerías estándar de plist).
- Algunos binarios de iOS pueden incluir DER entitlements; además, algunos stores/slots varían según las plataformas/versiones. Comprueba tanto los entitlements estándar como los DER cuando sea necesario.
- Para los binarios fat, utiliza las cabeceras fat (FAT_MAGIC/FAT_MAGIC_64) para localizar el slice y el offset correctos antes de recorrer los load commands de Mach-O.<sup>[[1]](#references)</sup>


## Esquema mínimo de parsing (Python)

El siguiente esquema compacto muestra el flujo de control para localizar y decodificar entitlements. Por brevedad, omite los bounds checks robustos y la compatibilidad completa con binarios fat.<sup>[[1]](#references)</sup>
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
Consejos de uso:
- Para manejar fat binaries, primero lee struct fat_header/fat_arch, elige el slice de arquitectura deseado y, después, pasa el subrango a parse_entitlements.
- En macOS, puedes validar los resultados con: codesign -d --entitlements :- /path/to/binary


## Hallazgos de ejemplo

Los platform binaries privilegiados suelen solicitar entitlements sensibles como:<sup>[[1]](#references)</sup>
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

Buscar estos elementos a escala en imágenes de firmware es extremadamente valioso para el mapeo de la superficie de ataque y la comparación entre releases/dispositivos.


## Escalado entre IPSWs (montaje e indexación)

Para enumerar ejecutables y extraer entitlements a escala sin almacenar imágenes completas:<sup>[[1]](#references)</sup>

- Usa la herramienta ipsw de @blacktop para descargar y montar filesystems de firmware. El montaje utiliza apfs-fuse, por lo que puedes recorrer volúmenes APFS sin realizar una extracción completa.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- Recorre los volúmenes montados para localizar archivos Mach-O (comprueba el magic y/o usa file/otool); después analiza los entitlements y los frameworks importados.
- Persiste una vista normalizada en una base de datos relacional para evitar un crecimiento lineal entre miles de IPSW:
- executables, operating_system_versions, entitlements, frameworks
- many-to-many: executable↔OS version, executable↔entitlement, executable↔framework

Consulta de ejemplo para listar todas las versiones de OS que contienen un nombre de executable determinado:
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = "launchd";
```
Notas sobre la portabilidad de la DB (si implementas tu propio indexer):<sup>[[1]](#references)</sup>
- Usa un ORM/abstraction (p. ej., SeaORM) para mantener el código independiente de la DB (SQLite/PostgreSQL).
- SQLite requiere AUTOINCREMENT solo en un INTEGER PRIMARY KEY; si quieres PKs i64 en Rust, genera las entidades como i32 y convierte los tipos; SQLite almacena INTEGER internamente como un entero con signo de 8 bytes.<sup>[[8]](#references)</sup>


## Herramientas open-source y referencias para la búsqueda de entitlements

- Montaje/descarga de Firmware: https://github.com/blacktop/ipsw
- Bases de datos y referencias de entitlements:
- DB de entitlements de Jonathan Levin: https://newosxbook.com/ent.php
- entdb: https://github.com/ChiChou/entdb
- Indexer a gran escala (Rust, Web UI self-hosted + OpenAPI): https://github.com/synacktiv/appledb_rs
- Headers de Apple para estructuras y constantes:
- loader.h (headers de Mach-O, load commands)
- cs_blobs.h (SuperBlob, GenericBlob, CodeDirectory)

Para obtener más información sobre los internals de code signing (Code Directory, special slots, DER entitlements), consulta: [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)


## Referencias

- [1] [appledb_rs: una herramienta de apoyo a la investigación para plataformas Apple](https://www.synacktiv.com/publications/appledbrs-un-outil-daide-a-la-recherche-sur-plateformes-apple.html)
- [2] [synacktiv/appledb_rs](https://github.com/synacktiv/appledb_rs)
- [3] [blacktop/ipsw](https://github.com/blacktop/ipsw)
- [4] [DB de entitlements de Jonathan Levin](https://newosxbook.com/ent.php)
- [5] [ChiChou/entdb](https://github.com/ChiChou/entdb)
- [6] [XNU cs_blobs.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [7] [XNU mach-o/loader.h](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [8] [Tipos de datos de SQLite](https://sqlite.org/datatype3.html)

{{#include ../../../banners/hacktricks-training.md}}
