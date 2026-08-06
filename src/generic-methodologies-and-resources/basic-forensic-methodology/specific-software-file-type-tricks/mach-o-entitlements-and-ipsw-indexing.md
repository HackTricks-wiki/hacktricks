# Mach-O Entitlements 提取与 IPSW 索引

{{#include ../../../banners/hacktricks-training.md}}

## Mach-O 中的 Entitlements：它们存放在哪里

本页面介绍如何通过遍历 LC_CODE_SIGNATURE 并解析 code signing SuperBlob，以编程方式从 Mach-O binaries 中提取 entitlements；同时介绍如何通过挂载并索引 Apple IPSW firmware 的内容，将此过程扩展到大规模 forensic search/diff。

如果需要复习 Mach-O 格式和 code signing，也可以参考：macOS code signing 和 SuperBlob internals。
- 查看 macOS code signing 详情（SuperBlob、Code Directory、special slots）：[macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- 查看通用 Mach-O structures/load commands：[Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Mach-O 中的 Entitlements：它们存放在哪里

Entitlements 存储在由 LC_CODE_SIGNATURE load command 引用的 code signature data 中，并位于 __LINKEDIT segment 内。该 signature 是一个 CS_SuperBlob，其中包含多个 blobs（code directory、requirements、entitlements、CMS 等）。entitlements blob 是一个 CS_GenericBlob，其数据是一个将 entitlement keys 映射到 values 的 Apple Binary Property List（bplist00）。<sup>[[1]](#references)</sup>

关键 structures（来自 xnu）：<sup>[[6]](#references)[[7]](#references)</sup>
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
重要常量：
- LC_CODE_SIGNATURE cmd = 0x1d
- CS SuperBlob magic = 0xfade0cc0
- Entitlements blob type (CSMAGIC_EMBEDDED_ENTITLEMENTS) = 0xfade7171
- DER entitlements 可能通过特殊 slot（例如 -7）存在，关于特殊 slots 和 DER entitlements 的说明，请参阅 macOS Code Signing 页面

注意：Multi-arch（fat）binaries 包含多个 Mach-O slices。必须选择要检查的架构对应的 slice，然后遍历其 load commands。


## Extraction steps（通用，尽量无损）

1) 解析 Mach-O header；迭代 ncmds 个 load_command records。
2) 定位 LC_CODE_SIGNATURE；读取 linkedit_data_command.dataoff/datasize，以映射位于 __LINKEDIT 中的 Code Signing SuperBlob。
3) 验证 CS_SuperBlob.magic == 0xfade0cc0；迭代 count 个 CS_BlobIndex entries。
4) 定位 index.type == 0xfade7171（embedded entitlements）。读取其指向的 CS_GenericBlob，并将其 data 作为 Apple binary plist（bplist00）解析为 key/value entitlements。<sup>[[1]](#references)</sup>

Implementation notes：
- Code signature structures 使用 big-endian fields；在 little-endian hosts 上解析时需要交换 byte order。
- Entitlements GenericBlob 的 data 本身是 binary plist（由标准 plist libraries 处理）。
- 某些 iOS binaries 可能携带 DER entitlements；此外，不同 platforms/versions 的 stores/slots 也可能有所不同。必要时同时交叉检查 standard 和 DER entitlements。
- 对于 fat binaries，使用 fat headers（FAT_MAGIC/FAT_MAGIC_64）在遍历 Mach-O load commands 之前定位正确的 slice 及其 offset。<sup>[[1]](#references)</sup>


## Minimal parsing outline（Python）

以下是用于查找并解码 entitlements 的简要 outline，展示了控制流程。为简洁起见，其中有意省略了 robust bounds checks 和完整的 fat binary support。<sup>[[1]](#references)</sup>
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
使用提示：
- 要处理 fat binaries，首先读取 struct fat_header/fat_arch，选择所需的 architecture slice，然后将该子范围传递给 parse_entitlements。
- 在 macOS 上，可以使用以下命令验证结果：codesign -d --entitlements :- /path/to/binary


## 示例发现

具有特权的平台二进制文件通常会请求敏感的 entitlements，例如：<sup>[[1]](#references)</sup>
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

在 firmware images 中大规模搜索这些 entitlements，对于攻击面映射以及跨版本和设备进行差异比较都极具价值。


## 跨 IPSWs 扩展（挂载和索引）

要在不存储完整镜像的情况下，大规模枚举可执行文件并提取 entitlements：<sup>[[1]](#references)</sup>

- 使用 @blacktop 的 ipsw tool 下载并挂载 firmware filesystems。挂载利用 apfs-fuse，因此无需完整提取即可遍历 APFS volumes。<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- 遍历已挂载的卷以定位 Mach-O 文件（检查 magic 和/或使用 file/otool），然后解析 entitlements 和 imported frameworks。
- 将规范化视图持久化到关系型数据库中，以避免数千个 IPSW 导致线性增长：
- executables、operating_system_versions、entitlements、frameworks
- 多对多关系：executable↔OS version、executable↔entitlement、executable↔framework

列出包含指定 executable 名称的所有 OS version 的示例查询：
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = "launchd";
```
关于 DB 可移植性的注意事项（如果你实现自己的 indexer）：<sup>[[1]](#references)</sup>
- 使用 ORM/abstraction（例如 SeaORM），以保持代码与 DB 无关（SQLite/PostgreSQL）。
- SQLite 仅要求在 INTEGER PRIMARY KEY 上使用 AUTOINCREMENT；如果你希望在 Rust 中使用 i64 PK，请将 entities 生成为 i32 并转换类型，SQLite 在内部将 INTEGER 存储为 8 字节有符号整数。<sup>[[8]](#references)</sup>


## 用于 entitlement hunting 的开源 tooling 和 references

- Firmware mount/download: https://github.com/blacktop/ipsw<sup>[[3]](#references)</sup>
- Entitlement databases 和 references：
- Jonathan Levin 的 entitlement DB: https://newosxbook.com/ent.php<sup>[[4]](#references)</sup>
- entdb: https://github.com/ChiChou/entdb<sup>[[5]](#references)</sup>
- 大规模 indexer（Rust，self-hosted Web UI + OpenAPI）：https://github.com/synacktiv/appledb_rs<sup>[[2]](#references)</sup>
- 用于 structures 和 constants 的 Apple headers：
- loader.h（Mach-O headers、load commands）
- cs_blobs.h（SuperBlob、GenericBlob、CodeDirectory）

如需进一步了解 code signing internals（Code Directory、special slots、DER entitlements），请参阅：[macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)


## References

- [1] [appledb_rs：用于 Apple platforms research support 的 tool](https://www.synacktiv.com/publications/appledbrs-un-outil-daide-a-la-recherche-sur-plateformes-apple.html)
- [2] [synacktiv/appledb_rs](https://github.com/synacktiv/appledb_rs)
- [3] [blacktop/ipsw](https://github.com/blacktop/ipsw)
- [4] [Jonathan Levin 的 entitlement DB](https://newosxbook.com/ent.php)
- [5] [ChiChou/entdb](https://github.com/ChiChou/entdb)
- [6] [XNU cs_blobs.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [7] [XNU mach-o/loader.h](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [8] [SQLite Datatypes](https://sqlite.org/datatype3.html)

{{#include ../../../banners/hacktricks-training.md}}
