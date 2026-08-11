# Mach-O Entitlements の抽出と IPSW のインデックス化

{{#include ../../../banners/hacktricks-training.md}}

## 概要

このページでは、プログラムから Mach-O バイナリの entitlements を抽出する方法について説明します。具体的には、LC_CODE_SIGNATURE をたどって code signing の SuperBlob を解析する方法と、Apple IPSW firmware 全体にこれを適用するため、内容を mount して forensic search/diff 用にインデックス化する方法を扱います。

Mach-O format と code signing の復習が必要な場合は、macOS code signing と SuperBlob internals も参照してください。
- macOS code signing の詳細（SuperBlob、Code Directory、special slots）: [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- Mach-O の一般的な structures/load commands: [Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Mach-O の Entitlements: 保存場所

Entitlements は、LC_CODE_SIGNATURE load command が参照する code signature data 内に保存され、__LINKEDIT segment に配置されます。Signature は CS_SuperBlob であり、複数の blob（code directory、requirements、entitlements、CMS など）を含みます。Entitlements blob は CS_GenericBlob で、その data は entitlement keys と values の対応を格納した serialized property list です。parsers は XML と binary plist の両方の encoding を受け入れる必要があります。<sup>[[1]](#references)[[6]](#references)</sup>

主な structures（xnu より）:<sup>[[6]](#references)[[7]](#references)</sup>
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
Apple headers に含まれる重要な定数:<sup>[[6]](#references)[[7]](#references)</sup>
- LC_CODE_SIGNATURE cmd = 0x1d
- CS SuperBlob magic = 0xfade0cc0
- Entitlements index slot (`CSSLOT_ENTITLEMENTS`) = 5。このスロットの blob には magic `CSMAGIC_EMBEDDED_ENTITLEMENTS` = 0xfade7171 が設定される
- DER entitlements は slot `CSSLOT_DER_ENTITLEMENTS` = 7 と blob magic `CSMAGIC_EMBEDDED_DER_ENTITLEMENTS` = 0xfade7172 を使用する

注: Multi-arch (fat) binaries には複数の Mach-O slices が含まれます。調査対象の architecture の slice を選択してから、その load commands を走査する必要があります。


## Extraction steps (generic, lossless-enough)

1) Mach-O header を parse し、ncmds 分の load_command records を iterate する。
2) LC_CODE_SIGNATURE を特定し、linkedit_data_command.dataoff/datasize を読み取って、__LINKEDIT に配置された Code Signing SuperBlob を map する。
3) CS_SuperBlob.magic == 0xfade0cc0 を検証し、CS_BlobIndex の count エントリを iterate する。
4) `index.type == CSSLOT_ENTITLEMENTS` (5) を特定し、参照先の `CS_GenericBlob` が magic `CSMAGIC_EMBEDDED_ENTITLEMENTS` (0xfade7171) を持つことを検証する。その data を property list として parse し、key/value entitlements を取得する。<sup>[[1]](#references)[[6]](#references)</sup>

実装上の注意:
- Code signature structures は big-endian fields を使用する。little-endian hosts で parse する場合は byte order を swap する。
- Entitlements `GenericBlob` には serialized plist が含まれる。標準的な plist libraries で XML または binary representation を処理できる。
- 一部の iOS binaries には DER entitlements が含まれている場合がある。XNU は別の DER blob type を公開しており、entitlement representations や slots は platforms や versions によって異なる可能性があるため、必要に応じて標準 entitlements と DER entitlements を cross-check する。<sup>[[6]](#references)</sup>
- fat binaries では、Mach-O load commands を走査する前に fat headers (FAT_MAGIC/FAT_MAGIC_64) を使用して、正しい slice と offset を特定する。


## Minimal parsing outline (Python)

以下は、entitlements を見つけて decode するための control flow を示す簡潔な outline です。簡潔さを優先しており、堅牢な bounds checks と完全な fat binary support は意図的に省略しています。<sup>[[6]](#references)[[7]](#references)</sup>
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
使用上のヒント:
- fat binariesを扱うには、まずstruct fat_header/fat_archを読み取り、目的のarchitecture sliceを選択してから、そのサブ範囲をparse_entitlementsに渡します。
- macOSでは、次のコマンドで結果を検証できます: codesign -d --entitlements :- /path/to/binary


## 発見例

source articleでは、macOS 14.0の`launchd` binaryに次のentitlementsが示されています:<sup>[[1]](#references)</sup>
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

これらをfirmware images全体で大規模に検索することは、attack surface mappingや、release/device間のdiffingに非常に役立ちます。


## IPSWs全体へのスケーリング（mountingとindexing）

full imagesを保存せずにexecutablesを列挙し、entitlementsを大規模に抽出するには:<sup>[[1]](#references)</sup>

- @blacktopのipsw toolを使用してfirmware filesystemsをdownloadおよびmountします。Mountingではapfs-fuseを利用するため、full extractionなしでAPFS volumesを走査できます。<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- マウントされたボリュームを走査して Mach-O ファイルを特定する（magic を確認する、または file/otool を使用する）。その後、entitlements とインポートされた frameworks を解析する。
- 数千の IPSW にわたる線形増加を避けるため、正規化したビューを relational database に保存する：
- executables、operating_system_versions、entitlements、frameworks
- 多対多：executable↔OS version、executable↔entitlement、executable↔framework

指定した executable name を含むすべての OS version を一覧表示するクエリの例（appledb_rs から改変）：<sup>[[1]](#references)</sup>
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = 'launchd';
```
DB portability に関する注意事項（独自の indexer を実装する場合）:<sup>[[1]](#references)</sup>
- ORM/abstraction（例：SeaORM）を使用して、コードを DB-agnostic（SQLite/PostgreSQL 対応）に保つ。
- SQLite では `AUTOINCREMENT` を `INTEGER PRIMARY KEY` に対してのみ使用できる。このキーは符号付き64ビットの ROWID の alias だが、SQLite はディスク上でより小さい integer width を使用する場合がある。SeaORM が生成した Rust entities で i64 IDs が必要な場合は、entities を i32 として生成し、境界で types を変換する。<sup>[[1]](#references)[[8]](#references)[[9]](#references)</sup>


## entitlement hunting 向けの Open-source tooling と references

- Firmware の mount/download: https://github.com/blacktop/ipsw.<sup>[[3]](#references)</sup>
- Entitlement databases と references:
- Jonathan Levin の entitlement DB: https://newosxbook.com/ent.php.<sup>[[4]](#references)</sup>
- entdb: https://github.com/ChiChou/entdb.<sup>[[5]](#references)</sup>
- 大規模 indexer（Rust、self-hosted Web UI + OpenAPI）: https://github.com/synacktiv/appledb_rs.<sup>[[2]](#references)</sup>
- Structures と constants 用の Apple headers:
- loader.h（Mach-O headers、load commands）
- cs_blobs.h（SuperBlob、GenericBlob、CodeDirectory）

Code signing internals（Code Directory、special slots、DER entitlements）の詳細については、[macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md) を参照。


## References

- [1] [Corentin Liaud (Synacktiv), Apple platforms 向けの research support tool appledb_rs](https://www.synacktiv.com/publications/appledbrs-un-outil-daide-a-la-recherche-sur-plateformes-apple.html)
- [2] [synacktiv/appledb_rs](https://github.com/synacktiv/appledb_rs)
- [3] [blacktop/ipsw](https://github.com/blacktop/ipsw)
- [4] [Jonathan Levin の entitlement DB](https://newosxbook.com/ent.php)
- [5] [ChiChou/entdb](https://github.com/ChiChou/entdb)
- [6] [XNU cs_blobs.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [7] [XNU mach-o/loader.h](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [8] [SQLite の Datatypes](https://sqlite.org/datatype3.html)
- [9] [SQLite の Autoincrement](https://sqlite.org/autoinc.html)
{{#include ../../../banners/hacktricks-training.md}}
