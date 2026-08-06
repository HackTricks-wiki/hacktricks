# Extração de Entitlements do Mach-O e Indexação de IPSW

{{#include ../../../banners/hacktricks-training.md}}

## Entitlements no Mach-O: onde ficam

Os Entitlements são armazenados dentro dos dados da assinatura de código referenciados pelo comando de carregamento LC_CODE_SIGNATURE e colocados no segmento __LINKEDIT. A assinatura é um CS_SuperBlob contendo vários blobs (diretório de código, requisitos, entitlements, CMS etc.). O blob de entitlements é um CS_GenericBlob cujos dados são uma Apple Binary Property List (bplist00) que mapeia chaves de entitlement para valores.<sup>[[1]](#references)</sup>

Estruturas principais (do xnu):<sup>[[6]](#references)[[7]](#references)</sup>
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
- DER entitlements podem estar presentes via slot especial (por exemplo, -7); consulte a página macOS Code Signing para obter informações sobre special slots e DER entitlements

Nota: binários Multi-arch (fat) contêm vários slices Mach-O. Você deve escolher o slice da arquitetura que deseja inspecionar e, em seguida, percorrer seus load commands.


## Etapas de extração (genéricas, suficientemente lossless)

1) Analise o cabeçalho Mach-O; percorra ncmds registros de load_command.
2) Localize LC_CODE_SIGNATURE; leia dataoff/datasize de linkedit_data_command para mapear o Code Signing SuperBlob localizado em __LINKEDIT.
3) Valide se CS_SuperBlob.magic == 0xfade0cc0; percorra count entradas de CS_BlobIndex.
4) Localize index.type == 0xfade7171 (embedded entitlements). Leia o CS_GenericBlob apontado e analise seus dados como um binary plist da Apple (bplist00) para obter os entitlements de key/value.<sup>[[1]](#references)</sup>

Notas de implementação:
- As estruturas de code signature usam campos big-endian; troque a ordem dos bytes ao analisar em hosts little-endian.
- Os dados do próprio Entitlements GenericBlob são um binary plist (tratados por bibliotecas plist padrão).
- Alguns binários iOS podem conter DER entitlements; além disso, alguns stores/slots variam entre plataformas/versões. Faça cross-check dos entitlements padrão e DER conforme necessário.
- Para binários fat, use os cabeçalhos fat (FAT_MAGIC/FAT_MAGIC_64) para localizar o slice e o offset corretos antes de percorrer os load commands Mach-O.<sup>[[1]](#references)</sup>


## Esboço mínimo de parsing (Python)

O exemplo a seguir é um esboço compacto que mostra o fluxo de controle para localizar e decodificar entitlements. Ele omite intencionalmente verificações robustas de limites e o suporte completo a binários fat por questões de brevidade.<sup>[[1]](#references)</sup>
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
- Para lidar com fat binaries, primeiro leia struct fat_header/fat_arch, escolha o slice de arquitetura desejado e, em seguida, passe o subintervalo para parse_entitlements.
- No macOS, você pode validar os resultados com: codesign -d --entitlements :- /path/to/binary


## Exemplos de descobertas

Binaries de plataforma privilegiados frequentemente solicitam entitlements sensíveis, como:<sup>[[1]](#references)</sup>
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

Pesquisar esses itens em larga escala em firmware images é extremamente valioso para mapear a attack surface e comparar diferenças entre releases/devices.


## Escalonamento entre IPSWs (montagem e indexação)

Para enumerar executáveis e extrair entitlements em larga escala sem armazenar imagens completas:<sup>[[1]](#references)</sup>

- Use a ferramenta ipsw de @blacktop para baixar e montar filesystems de firmware. A montagem utiliza apfs-fuse, permitindo percorrer volumes APFS sem extração completa.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- Percorra os volumes montados para localizar arquivos Mach-O (verifique o magic e/ou use file/otool), depois analise os entitlements e os frameworks importados.
- Persista uma visão normalizada em um banco de dados relacional para evitar o crescimento linear em milhares de IPSWs:
- executáveis, operating_system_versions, entitlements, frameworks
- muitos-para-muitos: executável↔versão do OS, executável↔entitlement, executável↔framework

Exemplo de consulta para listar todas as versões do OS que contêm um determinado nome de executável:
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = "launchd";
```
Notas sobre a portabilidade do DB (se você implementar seu próprio indexer):<sup>[[1]](#references)</sup>
- Use um ORM/abstraction (por exemplo, SeaORM) para manter o código independente do DB (SQLite/PostgreSQL).
- O SQLite exige AUTOINCREMENT somente em uma INTEGER PRIMARY KEY; se você quiser PKs i64 em Rust, gere as entidades como i32 e converta os tipos; internamente, o SQLite armazena INTEGER como um inteiro assinado de 8 bytes.<sup>[[8]](#references)</sup>


## Ferramentas open-source e referências para a busca de entitlements

- Firmware mount/download: https://github.com/blacktop/ipsw
- Bancos de dados e referências de entitlements:
- DB de entitlements de Jonathan Levin: https://newosxbook.com/ent.php
- entdb: https://github.com/ChiChou/entdb
- Indexer em larga escala (Rust, Web UI self-hosted + OpenAPI): https://github.com/synacktiv/appledb_rs
- Headers da Apple para estruturas e constantes:
- loader.h (headers Mach-O, load commands)
- cs_blobs.h (SuperBlob, GenericBlob, CodeDirectory)

Para saber mais sobre os componentes internos de code signing (Code Directory, special slots, DER entitlements), consulte: [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)


## Referências

- [1] [appledb_rs: uma ferramenta de suporte à pesquisa para plataformas Apple](https://www.synacktiv.com/publications/appledbrs-un-outil-daide-a-la-recherche-sur-plateformes-apple.html)
- [2] [synacktiv/appledb_rs](https://github.com/synacktiv/appledb_rs)
- [3] [blacktop/ipsw](https://github.com/blacktop/ipsw)
- [4] [DB de entitlements de Jonathan Levin](https://newosxbook.com/ent.php)
- [5] [ChiChou/entdb](https://github.com/ChiChou/entdb)
- [6] [XNU cs_blobs.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [7] [XNU mach-o/loader.h](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [8] [Tipos de dados do SQLite](https://sqlite.org/datatype3.html)

{{#include ../../../banners/hacktricks-training.md}}
