# Extração de Entitlements de Mach-O & Indexação de IPSW

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

Esta página explica como extrair entitlements de binários Mach-O programaticamente percorrendo LC_CODE_SIGNATURE e analisando o code signing SuperBlob, e como escalar isso em firmwares IPSW da Apple montando e indexando seus conteúdos para busca/diff forense.

Se precisar de uma revisão sobre o formato Mach-O e code signing, veja também: macOS code signing and SuperBlob internals.
- Consulte os detalhes de macOS code signing (SuperBlob, Code Directory, special slots): [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- Consulte estruturas gerais do Mach-O / load commands: [Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Entitlements no Mach-O: onde residem

Entitlements são armazenados dentro dos dados de code signature referenciados pelo load command LC_CODE_SIGNATURE e colocados no segmento __LINKEDIT. A assinatura é um CS_SuperBlob contendo múltiplos blobs (code directory, requirements, entitlements, CMS, etc.). O blob de entitlements é um CS_GenericBlob cujo dado é um Apple Binary Property List (bplist00) que mapeia chaves de entitlements para valores.

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
Constantes importantes:
- LC_CODE_SIGNATURE cmd = 0x1d
- CS SuperBlob magic = 0xfade0cc0
- Entitlements blob type (CSMAGIC_EMBEDDED_ENTITLEMENTS) = 0xfade7171
- DER entitlements may be present via special slot (e.g., -7), see the macOS Code Signing page for special slots and DER entitlements notes

Nota: Binários multi-arch (fat) contêm múltiplos Mach-O slices. Você deve escolher o slice da arquitetura que quer inspecionar e então percorrer seus load commands.


## Etapas de extração (genéricas, praticamente sem perda)

1) Analise o cabeçalho Mach-O; itere pelos registros load_command conforme ncmds.
2) Localize LC_CODE_SIGNATURE; leia linkedit_data_command.dataoff/datasize para mapear o Code Signing SuperBlob colocado em __LINKEDIT.
3) Valide CS_SuperBlob.magic == 0xfade0cc0; itere pelas count entradas de CS_BlobIndex.
4) Localize index.type == 0xfade7171 (embedded entitlements). Leia o CS_GenericBlob apontado e parseie seus dados como um plist binário Apple (bplist00) para chaves/valores de entitlements.

Notas de implementação:
- As estruturas de code signature usam campos big-endian; troque a ordem de bytes ao parsear em hosts little-endian.
- Os dados do GenericBlob de entitlements em si são um plist binário (tratado por bibliotecas padrão de plist).
- Alguns binários iOS podem conter DER entitlements; também alguns stores/slots diferem entre plataformas/versões. Verifique tanto os entitlements padrão quanto os DER conforme necessário.
- Para binários fat, use os fat headers (FAT_MAGIC/FAT_MAGIC_64) para localizar o slice e offset corretos antes de percorrer os Mach-O load commands.


## Esboço mínimo de parsing (Python)

O seguinte é um esboço compacto mostrando o fluxo de controle para encontrar e decodificar entitlements. Intencionalmente omite verificações robustas de limites e suporte completo a fat binaries por brevidade.
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
Dicas de uso:
- Para lidar com fat binaries, primeiro leia struct fat_header/fat_arch, escolha o slice de arquitetura desejado, então passe o subrange para parse_entitlements.
- No macOS você pode validar os resultados com: codesign -d --entitlements :- /path/to/binary


## Exemplos de descobertas

Binários de plataforma privilegiados frequentemente solicitam entitlements sensíveis como:
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

Pesquisar esses em escala através de imagens de firmware é extremamente valioso para mapeamento da superfície de ataque e diffing entre releases/dispositivos.


## Escalando através de IPSWs (montagem e indexação)

Para enumerar executáveis e extrair entitlements em escala sem armazenar imagens completas:

- Use the ipsw tool by @blacktop para baixar e montar filesystems de firmware. A montagem aproveita apfs-fuse, então você pode percorrer volumes APFS sem extração completa.
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- Percorra volumes montados para localizar arquivos Mach-O (verifique magic e/ou use file/otool) e, em seguida, analise entitlements e frameworks importados.
- Persista uma visão normalizada em um banco de dados relacional para evitar crescimento linear através de milhares de IPSWs:
- executables, operating_system_versions, entitlements, frameworks
- many-to-many: executable↔OS version, executable↔entitlement, executable↔framework

Exemplo de query para listar todas as versões do OS que contenham um determinado nome de executável:
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = "launchd";
```
Notas sobre portabilidade de DB (se você implementar seu próprio indexador):
- Use um ORM/abstraction (e.g., SeaORM) para manter o código DB-agnostic (SQLite/PostgreSQL).
- SQLite requer AUTOINCREMENT apenas em um INTEGER PRIMARY KEY; se você quiser i64 PKs em Rust, gere entidades como i32 e converta tipos, SQLite armazena INTEGER como inteiro com sinal de 8 bytes internamente.


## Open-source tooling and references for entitlement hunting

- Firmware mount/download: https://github.com/blacktop/ipsw
- Entitlement databases and references:
- Jonathan Levin’s entitlement DB: https://newosxbook.com/ent.php
- entdb: https://github.com/ChiChou/entdb
- Large-scale indexer (Rust, self-hosted Web UI + OpenAPI): https://github.com/synacktiv/appledb_rs
- Apple headers for structures and constants:
- loader.h (Mach-O headers, load commands)
- cs_blobs.h (SuperBlob, GenericBlob, CodeDirectory)

For more on code signing internals (Code Directory, special slots, DER entitlements), see: [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)


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
