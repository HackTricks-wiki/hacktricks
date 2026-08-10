# Extração de Entitlements de Mach-O e Indexação de IPSW

## Visão geral

Esta página aborda como extrair programaticamente entitlements de binários Mach-O percorrendo LC_CODE_SIGNATURE e analisando o SuperBlob de code signing, além de como escalar esse processo em firmwares IPSW da Apple montando e indexando seu conteúdo para pesquisa/diff forense.

Se você precisa revisar o formato Mach-O e code signing, consulte também: macOS code signing e os componentes internos do SuperBlob.
- Consulte os detalhes de macOS code signing (SuperBlob, Code Directory, special slots): [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- Consulte as estruturas gerais de Mach-O/load commands: [Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Entitlements em Mach-O: onde ficam

Os entitlements são armazenados nos dados de code signature referenciados pelo load command LC_CODE_SIGNATURE e posicionados no segmento __LINKEDIT. A assinatura é um CS_SuperBlob contendo vários blobs (code directory, requirements, entitlements, CMS etc.). O blob de entitlements é um CS_GenericBlob cujos dados são uma property list serializada que mapeia chaves de entitlement para valores; os parsers devem aceitar codificações XML e binary plist.<sup>[[1]](#references)[[6]](#references)</sup>

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
uint32_t type;    /* slot type, e.g. CSSLOT_ENTITLEMENTS = 5 */
uint32_t offset;  /* offset of entry */
} CS_BlobIndex;

typedef struct __SC_GenericBlob {
uint32_t magic;   /* blob magic, e.g. CSMAGIC_EMBEDDED_ENTITLEMENTS */
uint32_t length;
char data[];      /* serialized plist containing entitlements */
} CS_GenericBlob;
```
Constantes importantes dos headers da Apple incluem:<sup>[[6]](#references)[[7]](#references)</sup>
- cmd LC_CODE_SIGNATURE = 0x1d
- magic do CS SuperBlob = 0xfade0cc0
- Slot do índice de entitlements (`CSSLOT_ENTITLEMENTS`) = 5; o blob nesse slot tem o magic `CSMAGIC_EMBEDDED_ENTITLEMENTS` = 0xfade7171
- Entitlements DER usam o slot `CSSLOT_DER_ENTITLEMENTS` = 7 e o magic de blob `CSMAGIC_EMBEDDED_DER_ENTITLEMENTS` = 0xfade7172

Nota: binários Multi-arch (fat) contêm múltiplas slices Mach-O. Você deve selecionar a slice da architecture que deseja inspecionar e, em seguida, percorrer seus load commands.


## Etapas de extração (genéricas, suficientemente lossless)

1) Analise o header Mach-O; itere a quantidade ncmds de registros load_command.
2) Localize LC_CODE_SIGNATURE; leia dataoff/datasize de linkedit_data_command para mapear o Code Signing SuperBlob localizado em __LINKEDIT.
3) Valide se CS_SuperBlob.magic == 0xfade0cc0; itere as entradas count de CS_BlobIndex.
4) Localize `index.type == CSSLOT_ENTITLEMENTS` (5) e, em seguida, verifique se o `CS_GenericBlob` apontado tem o magic `CSMAGIC_EMBEDDED_ENTITLEMENTS` (0xfade7171). Analise seus dados como uma property list para obter os entitlements de chave/valor.<sup>[[1]](#references)[[6]](#references)</sup>

Notas de implementação:
- As estruturas de code signature usam campos big-endian; troque a ordem dos bytes ao analisar em hosts little-endian.
- O `GenericBlob` de entitlements contém uma plist serializada; bibliotecas padrão de plist conseguem lidar com sua representação XML ou binária.
- Alguns binários iOS podem conter entitlements DER; o XNU expõe um tipo de blob DER separado, e as representações ou os slots de entitlements podem variar entre plataformas e versões; portanto, faça cross-check dos entitlements padrão e DER conforme necessário.<sup>[[6]](#references)</sup>
- Para binários fat, use os headers fat (FAT_MAGIC/FAT_MAGIC_64) para localizar a slice e o offset corretos antes de percorrer os load commands do Mach-O.


## Esboço de parsing mínimo (Python)

O exemplo a seguir é um esboço compacto que mostra o fluxo de controle para localizar e decodificar entitlements. Ele omite intencionalmente verificações robustas de limites e o suporte completo a binários fat por questões de brevidade.<sup>[[6]](#references)[[7]](#references)</sup>
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
Dicas de uso:
- Para lidar com fat binaries, primeiro leia `struct fat_header/fat_arch`, escolha o slice de arquitetura desejado e, em seguida, passe o subintervalo para `parse_entitlements`.
- No macOS, você pode validar os resultados com: `codesign -d --entitlements :- /path/to/binary`


## Exemplos de descobertas

O artigo de origem mostra estes entitlements no binário `launchd` do macOS 14.0:<sup>[[1]](#references)</sup>
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

Pesquisar esses itens em escala por imagens de firmware é extremamente valioso para o mapeamento da superfície de ataque e para fazer diff entre releases/dispositivos.


## Escalonamento entre IPSWs (montagem e indexação)

Para enumerar executáveis e extrair entitlements em escala sem armazenar imagens completas:<sup>[[1]](#references)</sup>

- Use a ferramenta `ipsw`, de @blacktop, para baixar e montar sistemas de arquivos de firmware. A montagem utiliza `apfs-fuse`, permitindo percorrer volumes APFS sem extração completa.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- Percorra os volumes montados para localizar arquivos Mach-O (verifique o magic e/ou use file/otool), depois analise os entitlements e os frameworks importados.
- Persista uma visão normalizada em um banco de dados relacional para evitar o crescimento linear em milhares de IPSWs:
- executables, operating_system_versions, entitlements, frameworks
- muitos-para-muitos: executable↔OS version, executable↔entitlement, executable↔framework

Exemplo de consulta para listar todas as versões do sistema operacional que contêm um determinado nome de executável (adaptado de appledb_rs):<sup>[[1]](#references)</sup>
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = 'launchd';
```
Notas sobre a portabilidade de DB (se você implementar seu próprio indexer):<sup>[[1]](#references)</sup>
- Use um ORM/abstraction (e.g., SeaORM) para manter o código agnóstico ao DB (SQLite/PostgreSQL).
- SQLite permite `AUTOINCREMENT` somente em uma `INTEGER PRIMARY KEY`; essa chave é um alias de um ROWID de 64 bits com sinal, embora o SQLite possa usar larguras inteiras menores no disco. Se as entidades Rust geradas pelo SeaORM precisarem de IDs i64, gere as entidades como i32 e converta os tipos na fronteira.<sup>[[1]](#references)[[8]](#references)[[9]](#references)</sup>


## Ferramentas open-source e referências para hunting de entitlements

- Montagem/download de firmware: https://github.com/blacktop/ipsw.<sup>[[3]](#references)</sup>
- Databases e referências de entitlements:
- Entitlement DB de Jonathan Levin: https://newosxbook.com/ent.php.<sup>[[4]](#references)</sup>
- entdb: https://github.com/ChiChou/entdb.<sup>[[5]](#references)</sup>
- Indexer em larga escala (Rust, Web UI self-hosted + OpenAPI): https://github.com/synacktiv/appledb_rs.<sup>[[2]](#references)</sup>
- Apple headers para estruturas e constantes:
- loader.h (headers Mach-O, load commands)
- cs_blobs.h (SuperBlob, GenericBlob, CodeDirectory)

Para saber mais sobre os internals de code signing (Code Directory, special slots, DER entitlements), consulte: [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)


## References

- [1] [Corentin Liaud (Synacktiv), appledb_rs: uma ferramenta de suporte à pesquisa para plataformas Apple](https://www.synacktiv.com/publications/appledbrs-un-outil-daide-a-la-recherche-sur-plateformes-apple.html)
- [2] [synacktiv/appledb_rs](https://github.com/synacktiv/appledb_rs)
- [3] [blacktop/ipsw](https://github.com/blacktop/ipsw)
- [4] [Entitlement DB de Jonathan Levin](https://newosxbook.com/ent.php)
- [5] [ChiChou/entdb](https://github.com/ChiChou/entdb)
- [6] [XNU cs_blobs.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [7] [XNU mach-o/loader.h](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [8] [Tipos de dados do SQLite](https://sqlite.org/datatype3.html)
- [9] [Autoincrement do SQLite](https://sqlite.org/autoinc.html)
{{#include ../../../banners/hacktricks-training.md}}
