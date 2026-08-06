# Mach-O Entitlements の抽出と IPSW のインデックス作成

{{#include ../../../banners/hacktricks-training.md}}

## Mach-O Entitlements の概要

このページでは、プログラムから Mach-O バイナリの entitlements を抽出する方法を扱います。具体的には、LC_CODE_SIGNATURE をたどって code signing SuperBlob を解析する方法と、Apple IPSW firmware 全体に処理を拡張し、その内容を mount および indexing してフォレンジック検索や差分分析を行う方法を説明します。

Mach-O format と code signing の復習が必要な場合は、macOS code signing と SuperBlob internals も参照してください。
- macOS code signing の詳細（SuperBlob、Code Directory、special slots）を確認：[macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- Mach-O structures/load commands の概要を確認：[Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Mach-O 内の Entitlements：保存場所

Entitlements は、LC_CODE_SIGNATURE load command が参照する code signature data 内に保存され、__LINKEDIT segment に配置されます。Signature は CS_SuperBlob であり、複数の blob（code directory、requirements、entitlements、CMS など）を含みます。Entitlements blob は CS_GenericBlob で、その data は entitlement keys から values への対応を格納した Apple Binary Property List（bplist00）です。<sup>[[1]](#references)</sup>

主要な構造体（xnu 由来）：<sup>[[6]](#references)[[7]](#references)</sup>
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
重要な定数:
- LC_CODE_SIGNATURE cmd = 0x1d
- CS SuperBlob magic = 0xfade0cc0
- Entitlements blob type (CSMAGIC_EMBEDDED_ENTITLEMENTS) = 0xfade7171
- DER entitlements は special slot（例: -7）経由で存在する場合があります。special slots と DER entitlements に関する注意事項については、macOS Code Signing ページを参照してください

注: Multi-arch (fat) binaries には複数の Mach-O slices が含まれます。検査対象の architecture 用 slice を選択してから、その load commands を走査する必要があります。


## Extraction steps (generic, lossless-enough)

1) Mach-O header を parse し、ncmds 個の load_command records を反復処理します。
2) LC_CODE_SIGNATURE を特定し、linkedit_data_command.dataoff/datasize を読み取って、__LINKEDIT に配置された Code Signing SuperBlob を map します。
3) CS_SuperBlob.magic == 0xfade0cc0 を検証し、CS_BlobIndex の count 個の entries を反復処理します。
4) index.type == 0xfade7171（embedded entitlements）を特定します。指し示された CS_GenericBlob を読み取り、その data を Apple binary plist (bplist00) として parse して、key/value entitlements を取得します。<sup>[[1]](#references)</sup>

Implementation notes:
- Code signature structures は big-endian fields を使用するため、little-endian hosts で parse する場合は byte order を入れ替えます。
- Entitlements GenericBlob の data 自体は binary plist です（standard plist libraries で処理できます）。
- 一部の iOS binaries には DER entitlements が含まれる場合があります。また、platform/version によって stores/slots が異なる場合もあります。必要に応じて standard と DER の両方の entitlements を cross-check してください。
- Fat binaries では、Mach-O load commands を走査する前に、fat headers (FAT_MAGIC/FAT_MAGIC_64) を使用して正しい slice と offset を特定します。<sup>[[1]](#references)</sup>


## Minimal parsing outline (Python)

以下は、entitlements を見つけて decode するための control flow を示す簡潔な outline です。簡潔さを優先しているため、堅牢な bounds checks と完全な fat binary support は省略しています。<sup>[[1]](#references)</sup>
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
使用上のヒント:
- fat binaries を扱うには、まず struct fat_header/fat_arch を読み取り、対象の architecture slice を選択してから、そのサブ範囲を parse_entitlements に渡します。
- macOS では、次のコマンドで結果を検証できます: `codesign -d --entitlements :- /path/to/binary`


## Example findings

Privileged platform binaries は、次のような機密性の高い entitlements を要求することがよくあります:<sup>[[1]](#references)</sup>
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

これらを firmware images 全体から大規模に検索することは、attack surface mapping や、リリース間およびデバイス間の diffing に非常に役立ちます。


## IPSWs 全体へのスケーリング（mounting と indexing）

full images を保存せずに executables を列挙し、entitlements を大規模に抽出するには:<sup>[[1]](#references)</sup>

- @blacktop の ipsw tool を使用して firmware filesystems を download および mount します。mounting では apfs-fuse が利用されるため、完全に extraction しなくても APFS volumes を traverse できます。<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- マウントされたボリュームを走査して Mach-O ファイルを特定する（magic を確認、および/または file/otool を使用）。その後、entitlements と imported frameworks を解析する。
- 数千の IPSW にわたる線形増加を避けるため、正規化したビューを relational database に保存する:
- executables、operating_system_versions、entitlements、frameworks
- many-to-many: executable↔OS version、executable↔entitlement、executable↔framework

指定した executable name を含むすべての OS version を一覧表示するクエリの例:
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = "launchd";
```
DB portabilityに関する注意事項（独自の indexer を実装する場合）:<sup>[[1]](#references)</sup>
- ORM/abstraction（例: SeaORM）を使用して、codeをDB-agnostic（SQLite/PostgreSQL対応）に保つ。
- SQLiteでAUTOINCREMENTを使用できるのはINTEGER PRIMARY KEYの場合のみ。Rustでi64 PKsを使用したい場合は、entitiesをi32として生成して型を変換する。SQLiteは内部的にINTEGERを8-byte signedとして保存する。<sup>[[8]](#references)</sup>


## entitlement hunting向けのOpen-source toolingとreferences

- Firmwareのmount/download: https://github.com/blacktop/ipsw<sup>[[3]](#references)</sup>
- Entitlement databasesとreferences:
- Jonathan Levinのentitlement DB: https://newosxbook.com/ent.php<sup>[[4]](#references)</sup>
- entdb: https://github.com/ChiChou/entdb<sup>[[5]](#references)</sup>
- Large-scale indexer（Rust、self-hosted Web UI + OpenAPI）: https://github.com/synacktiv/appledb_rs<sup>[[2]](#references)</sup>
- Structuresとconstants用のApple headers:
- loader.h（Mach-O headers、load commands）
- cs_blobs.h（SuperBlob、GenericBlob、CodeDirectory）

Code signing internals（Code Directory、special slots、DER entitlements）の詳細については、[macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)を参照。


## References

- [1] [appledb_rs: a research support tool for Apple platforms](https://www.synacktiv.com/publications/appledbrs-un-outil-daide-a-la-recherche-sur-plateformes-apple.html)
- [2] [synacktiv/appledb_rs](https://github.com/synacktiv/appledb_rs)
- [3] [blacktop/ipsw](https://github.com/blacktop/ipsw)
- [4] [Jonathan Levin’s entitlement DB](https://newosxbook.com/ent.php)
- [5] [ChiChou/entdb](https://github.com/ChiChou/entdb)
- [6] [XNU cs_blobs.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [7] [XNU mach-o/loader.h](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [8] [SQLite Datatypes](https://sqlite.org/datatype3.html)

{{#include ../../../banners/hacktricks-training.md}}
