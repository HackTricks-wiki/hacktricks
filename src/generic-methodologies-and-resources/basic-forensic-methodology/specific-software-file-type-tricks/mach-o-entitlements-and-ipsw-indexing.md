# Mach-O Entitlements 추출 및 IPSW Indexing

{{#include ../../../banners/hacktricks-training.md}}

## Mach-O의 Entitlements: 저장 위치

이 페이지에서는 프로그래밍 방식으로 `LC_CODE_SIGNATURE`를 순회하고 code signing `SuperBlob`을 파싱하여 Mach-O 바이너리에서 entitlements를 추출하는 방법과, Apple IPSW firmware 전반으로 이를 확장하기 위해 해당 콘텐츠를 mount하고 forensic search/diff를 수행할 수 있도록 indexing하는 방법을 다룹니다.

Mach-O format 및 code signing에 대한 복습이 필요하다면 다음도 참조하세요: macOS code signing 및 SuperBlob internals.
- macOS code signing 세부 정보 확인 (`SuperBlob`, `Code Directory`, special slots): [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- 일반적인 Mach-O structures/load commands 확인: [Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Mach-O의 Entitlements: 저장 위치

Entitlements는 `LC_CODE_SIGNATURE` load command가 참조하고 `__LINKEDIT` segment에 배치된 code signature data 내부에 저장됩니다. Signature는 여러 blob(`code directory`, `requirements`, `entitlements`, `CMS` 등)을 포함하는 `CS_SuperBlob`입니다. Entitlements blob은 entitlement keys를 values에 매핑하는 Apple Binary Property List(`bplist00`)의 data를 포함하는 `CS_GenericBlob`입니다.<sup>[[1]](#references)</sup>

주요 structures (`xnu`에서 가져옴):<sup>[[6]](#references)[[7]](#references)</sup>
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
중요한 상수:
- LC_CODE_SIGNATURE cmd = 0x1d
- CS SuperBlob magic = 0xfade0cc0
- Entitlements blob type (CSMAGIC_EMBEDDED_ENTITLEMENTS) = 0xfade7171
- DER entitlements는 특수 slot(예: -7)을 통해 존재할 수 있습니다. 특수 slot 및 DER entitlements 관련 참고 사항은 macOS Code Signing 페이지를 참조하세요.

참고: Multi-arch (fat) binary에는 여러 Mach-O slice가 포함됩니다. 검사하려는 architecture에 해당하는 slice를 선택한 다음 해당 slice의 load command를 순회해야 합니다.


## Extraction 단계 (일반적이며 충분히 lossless한 방식)

1) Mach-O header를 파싱하고, ncmds 개수만큼의 load_command record를 순회합니다.
2) LC_CODE_SIGNATURE를 찾고, linkedit_data_command.dataoff/datasize를 읽어 __LINKEDIT에 배치된 Code Signing SuperBlob을 매핑합니다.
3) CS_SuperBlob.magic == 0xfade0cc0인지 검증하고, CS_BlobIndex의 count 항목을 순회합니다.
4) index.type == 0xfade7171 (embedded entitlements)인 항목을 찾습니다. 해당 항목이 가리키는 CS_GenericBlob을 읽고, 그 데이터를 Apple binary plist (bplist00)로 파싱하여 key/value entitlements를 가져옵니다.<sup>[[1]](#references)</sup>

구현 참고 사항:
- Code signature 구조체는 big-endian field를 사용하므로, little-endian host에서 파싱할 때 byte order를 변환해야 합니다.
- Entitlements GenericBlob 데이터 자체는 binary plist이며, 표준 plist library로 처리할 수 있습니다.
- 일부 iOS binary에는 DER entitlements가 포함될 수 있으며, platform/version에 따라 일부 store/slot이 다를 수 있습니다. 필요에 따라 standard entitlements와 DER entitlements를 모두 교차 검증하세요.
- fat binary의 경우, Mach-O load command를 순회하기 전에 fat header (FAT_MAGIC/FAT_MAGIC_64)를 사용하여 올바른 slice와 offset을 찾아야 합니다.<sup>[[1]](#references)</sup>


## Minimal parsing 개요 (Python)

다음은 entitlements를 찾고 decode하기 위한 control flow를 보여주는 간결한 개요입니다. 간결하게 작성하기 위해 견고한 bounds check와 전체 fat binary 지원은 의도적으로 생략했습니다.<sup>[[1]](#references)</sup>
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
사용 팁:
- fat binaries를 처리하려면 먼저 struct fat_header/fat_arch를 읽고, 원하는 architecture slice를 선택한 다음 subrange를 parse_entitlements에 전달하세요.
- macOS에서는 다음 명령으로 결과를 검증할 수 있습니다: codesign -d --entitlements :- /path/to/binary


## Example findings

Privileged platform binaries는 다음과 같은 민감한 entitlements를 요청하는 경우가 많습니다:<sup>[[1]](#references)</sup>
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

펌웨어 이미지 전반에서 이러한 항목을 대규모로 검색하면 attack surface mapping 및 release/device 간 diffing에 매우 유용합니다.


## IPSW 전반의 Scaling (mounting 및 indexing)

전체 이미지를 저장하지 않고 executable을 열거하고 entitlements를 대규모로 추출하려면:<sup>[[1]](#references)</sup>

- @blacktop의 ipsw tool을 사용하여 firmware filesystem을 download하고 mount하세요. Mounting은 apfs-fuse를 활용하므로 전체 extraction 없이 APFS volume을 탐색할 수 있습니다.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- 마운트된 볼륨을 순회하여 Mach-O 파일을 찾습니다(magic을 확인하거나 file/otool 사용). 그런 다음 entitlements와 imported frameworks를 파싱합니다.
- 수천 개의 IPSW에 걸쳐 데이터가 선형적으로 증가하는 것을 방지하기 위해 정규화된 뷰를 relational database에 저장합니다:
- executables, operating_system_versions, entitlements, frameworks
- 다대다 관계: executable↔OS version, executable↔entitlement, executable↔framework

지정된 executable 이름을 포함하는 모든 OS version을 나열하는 예시 쿼리:
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = "launchd";
```
DB portability에 대한 참고 사항 (자체 indexer를 구현하는 경우):<sup>[[1]](#references)</sup>
- ORM/abstraction(예: SeaORM)을 사용하여 code를 DB-agnostic(SQLite/PostgreSQL) 상태로 유지하세요.
- SQLite에서는 INTEGER PRIMARY KEY에만 AUTOINCREMENT가 필요합니다. Rust에서 i64 PK를 사용하려면 entity를 i32로 생성하고 type을 변환하세요. SQLite는 내부적으로 INTEGER를 8바이트 signed 값으로 저장합니다.<sup>[[8]](#references)</sup>


## Entitlement hunting을 위한 Open-source tooling 및 references

- Firmware mount/download: https://github.com/blacktop/ipsw
- Entitlement databases 및 references:
- Jonathan Levin의 entitlement DB: https://newosxbook.com/ent.php
- entdb: https://github.com/ChiChou/entdb
- Large-scale indexer (Rust, self-hosted Web UI + OpenAPI): https://github.com/synacktiv/appledb_rs
- Structures 및 constants를 위한 Apple headers:
- loader.h (Mach-O headers, load commands)
- cs_blobs.h (SuperBlob, GenericBlob, CodeDirectory)

Code signing internals(Code Directory, special slots, DER entitlements)에 대한 자세한 내용은 [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)을 참조하세요.


## References

- [1] [appledb_rs: Apple platforms를 위한 research support tool](https://www.synacktiv.com/publications/appledbrs-un-outil-daide-a-la-recherche-sur-plateformes-apple.html)
- [2] [synacktiv/appledb_rs](https://github.com/synacktiv/appledb_rs)
- [3] [blacktop/ipsw](https://github.com/blacktop/ipsw)
- [4] [Jonathan Levin의 entitlement DB](https://newosxbook.com/ent.php)
- [5] [ChiChou/entdb](https://github.com/ChiChou/entdb)
- [6] [XNU cs_blobs.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [7] [XNU mach-o/loader.h](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [8] [SQLite Datatypes](https://sqlite.org/datatype3.html)

{{#include ../../../banners/hacktricks-training.md}}
