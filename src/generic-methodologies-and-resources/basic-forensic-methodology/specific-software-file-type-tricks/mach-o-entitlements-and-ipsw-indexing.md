# Mach-O 권한(Entitlements) 추출 및 IPSW 인덱싱

{{#include ../../../banners/hacktricks-training.md}}

## 개요

이 페이지에서는 LC_CODE_SIGNATURE를 따라 코드 서명 SuperBlob을 파싱하여 Mach-O 바이너리에서 프로그래밍적으로 entitlements를 추출하는 방법과, Apple IPSW 펌웨어의 내용을 마운트하고 인덱싱하여 포렌식 검색/비교에 적용하는 방법을 다룹니다.

Mach-O 형식 및 코드 서명에 대한 복습이 필요하면 다음을 참조하세요:
- Check macOS code signing details (SuperBlob, Code Directory, special slots): [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- Check general Mach-O structures/load commands: [Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Mach-O 권한(Entitlements): 저장 위치

Entitlements는 LC_CODE_SIGNATURE load command가 참조하는 코드 서명 데이터 내부에 저장되며 __LINKEDIT 세그먼트에 배치됩니다. 서명은 여러 블롭(code directory, requirements, entitlements, CMS 등)을 포함하는 CS_SuperBlob입니다. entitlements 블롭은 데이터가 Apple Binary Property List(bplist00)인 CS_GenericBlob이며, 이 plist는 entitlement 키를 값에 매핑합니다.

주요 구조체 (xnu에서):
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
중요 상수:
- LC_CODE_SIGNATURE cmd = 0x1d
- CS SuperBlob magic = 0xfade0cc0
- Entitlements blob type (CSMAGIC_EMBEDDED_ENTITLEMENTS) = 0xfade7171
- DER entitlements may be present via special slot (e.g., -7), see the macOS Code Signing page for special slots and DER entitlements notes

Note: Multi-arch (fat) binaries contain multiple Mach-O slices. You must pick the slice for the architecture you want to inspect and then walk its load commands.


## Extraction steps (generic, lossless-enough)

1) Parse Mach-O header; iterate ncmds worth of load_command records.
2) Locate LC_CODE_SIGNATURE; read linkedit_data_command.dataoff/datasize to map the Code Signing SuperBlob placed in __LINKEDIT.
3) Validate CS_SuperBlob.magic == 0xfade0cc0; iterate count entries of CS_BlobIndex.
4) Locate index.type == 0xfade7171 (embedded entitlements). Read the pointed CS_GenericBlob and parse its data as an Apple binary plist (bplist00) to key/value entitlements.

Implementation notes:
- Code signature structures use big-endian fields; swap byte order when parsing on little-endian hosts.
- The entitlements GenericBlob data itself is a binary plist (handled by standard plist libraries).
- Some iOS binaries may carry DER entitlements; also some stores/slots differ across platforms/versions. Cross-check both standard and DER entitlements as needed.
- For fat binaries, use the fat headers (FAT_MAGIC/FAT_MAGIC_64) to locate the correct slice and offset before walking Mach-O load commands.


## Minimal parsing outline (Python)

The following is a compact outline showing the control flow to find and decode entitlements. It intentionally omits robust bounds checks and full fat binary support for brevity.
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
Usage tips:
- fat binaries를 처리하려면 먼저 struct fat_header/fat_arch를 읽고, 원하는 architecture slice를 선택한 다음 subrange를 parse_entitlements에 전달하세요.
- macOS에서 다음 명령으로 결과를 검증할 수 있습니다: codesign -d --entitlements :- /path/to/binary


## Example findings

Privileged platform binaries는 종종 다음과 같은 민감한 entitlements를 요청합니다:
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

이를 펌웨어 이미지 전반에 걸쳐 대규모로 검색하는 것은 attack surface mapping 및 releases/devices 간의 diffing에 매우 유용합니다.


## Scaling across IPSWs (mounting and indexing)

전체 이미지를 저장하지 않고 실행 파일을 열거하고 entitlements를 대규모로 추출하려면:

- @blacktop의 ipsw tool을 사용하여 펌웨어 파일시스템을 다운로드하고 마운트하세요. 마운트는 apfs-fuse를 활용하므로 전체 추출 없이 APFS 볼륨을 탐색할 수 있습니다.
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- 마운트된 볼륨을 순회하여 Mach-O 파일을 찾고 (magic을 확인하거나 file/otool 사용), entitlements와 imported frameworks를 파싱한다.
- 수천 개의 IPSWs에 걸친 선형 성장을 피하기 위해 정규화된 뷰를 관계형 데이터베이스에 저장한다:
- executables, operating_system_versions, entitlements, frameworks
- many-to-many: executable↔OS version, executable↔entitlement, executable↔framework

Example query to list all OS versions containing a given executable name:
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = "launchd";
```
DB 이식성에 대한 메모 (자체 인덱서를 구현하는 경우):
- ORM/추상화 계층을 사용하세요 (예: SeaORM) — 코드가 DB에 종속되지 않도록 유지 (SQLite/PostgreSQL).
- SQLite는 AUTOINCREMENT가 INTEGER PRIMARY KEY에만 필요합니다; Rust에서 i64 PK를 원한다면 엔티티를 i32로 생성하고 타입을 변환하세요. SQLite는 내부적으로 INTEGER를 8바이트 부호 있는 정수로 저장합니다.


## 오픈소스 도구 및 entitlement hunting 참고자료

- 펌웨어 마운트/다운로드: https://github.com/blacktop/ipsw
- Entitlement 데이터베이스 및 참조:
- Jonathan Levin’s entitlement DB: https://newosxbook.com/ent.php
- entdb: https://github.com/ChiChou/entdb
- 대규모 인덱서 (Rust, self-hosted Web UI + OpenAPI): https://github.com/synacktiv/appledb_rs
- 구조체 및 상수용 Apple 헤더:
- loader.h (Mach-O headers, load commands)
- cs_blobs.h (SuperBlob, GenericBlob, CodeDirectory)

코드 서명 내부 동작(Code Directory, special slots, DER entitlements)에 대한 자세한 내용은 다음을 참조하세요: [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)


## 참고자료

- [appledb_rs: a research support tool for Apple platforms](https://www.synacktiv.com/publications/appledbrs-un-outil-daide-a-la-recherche-sur-plateformes-apple.html)
- [synacktiv/appledb_rs](https://github.com/synacktiv/appledb_rs)
- [blacktop/ipsw](https://github.com/blacktop/ipsw)
- [Jonathan Levin’s entitlement DB](https://newosxbook.com/ent.php)
- [ChiChou/entdb](https://github.com/ChiChou/entdb)
- [XNU cs_blobs.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [XNU mach-o/loader.h](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [SQLite Datatypes](https://sqlite.org/datatype3.html)

{{#include ../../../banners/hacktricks-training.md}}
