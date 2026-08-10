# Mach-O Entitlements 추출 및 IPSW 인덱싱

## 개요

이 페이지에서는 프로그래밍 방식으로 `LC_CODE_SIGNATURE`를 순회하고 code signing `SuperBlob`을 파싱하여 Mach-O 바이너리에서 entitlements를 추출하는 방법과, Apple IPSW firmware 전반에 걸쳐 해당 작업을 확장하기 위해 콘텐츠를 마운트하고 인덱싱하여 포렌식 검색 및 diff를 수행하는 방법을 다룹니다.

Mach-O format 및 code signing에 대한 복습이 필요하다면 다음도 참고하세요: macOS code signing 및 SuperBlob 내부 구조.
- Check macOS code signing details (SuperBlob, Code Directory, special slots): [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- Check general Mach-O structures/load commands: [Universal binaries & Mach-O Format](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Mach-O의 Entitlements: 저장 위치

Entitlements는 `LC_CODE_SIGNATURE` load command가 참조하고 `__LINKEDIT` segment에 배치된 code signature data 내부에 저장됩니다. Signature는 여러 blob(code directory, requirements, entitlements, CMS 등)을 포함하는 `CS_SuperBlob`입니다. Entitlements blob은 entitlement key와 value를 매핑하는 serialized property list인 `CS_GenericBlob`이며, parser는 XML 및 binary plist encoding을 모두 허용해야 합니다.<sup>[[1]](#references)[[6]](#references)</sup>

주요 구조체(xnu 기준):<sup>[[6]](#references)[[7]](#references)</sup>
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
Apple headers의 중요한 상수는 다음과 같습니다:<sup>[[6]](#references)[[7]](#references)</sup>
- LC_CODE_SIGNATURE cmd = 0x1d
- CS SuperBlob magic = 0xfade0cc0
- Entitlements index slot (`CSSLOT_ENTITLEMENTS`) = 5; 해당 slot의 blob은 `CSMAGIC_EMBEDDED_ENTITLEMENTS` = 0xfade7171 magic을 가집니다.
- DER entitlements는 `CSSLOT_DER_ENTITLEMENTS` = 7 slot과 `CSMAGIC_EMBEDDED_DER_ENTITLEMENTS` = 0xfade7172 blob magic을 사용합니다.

참고: Multi-arch (fat) 바이너리에는 여러 Mach-O slice가 포함됩니다. 검사하려는 architecture의 slice를 선택한 다음 해당 slice의 load commands를 순회해야 합니다.


## Extraction 단계 (generic, lossless-enough)

1) Mach-O header를 parse하고, ncmds 개수만큼의 load_command records를 순회합니다.
2) LC_CODE_SIGNATURE를 찾고, linkedit_data_command.dataoff/datasize를 읽어 __LINKEDIT에 배치된 Code Signing SuperBlob을 매핑합니다.
3) CS_SuperBlob.magic == 0xfade0cc0인지 검증하고, CS_BlobIndex의 count entries를 순회합니다.
4) `index.type == CSSLOT_ENTITLEMENTS` (5)를 찾은 다음, 해당 위치가 가리키는 `CS_GenericBlob`의 magic이 `CSMAGIC_EMBEDDED_ENTITLEMENTS` (0xfade7171)인지 확인합니다. 해당 데이터를 property list로 parse하여 key/value entitlements를 가져옵니다.<sup>[[1]](#references)[[6]](#references)</sup>

Implementation 참고 사항:
- Code signature structures는 big-endian fields를 사용하므로 little-endian hosts에서 parse할 때 byte order를 교체해야 합니다.
- entitlements `GenericBlob`에는 serialized plist가 포함되어 있으며, standard plist libraries는 해당 XML 또는 binary representation을 처리할 수 있습니다.
- 일부 iOS 바이너리에는 DER entitlements가 포함될 수 있습니다. XNU는 별도의 DER blob type을 노출하며, entitlement representations 또는 slots는 platforms와 versions에 따라 다를 수 있으므로 필요에 따라 standard 및 DER entitlements를 교차 검증해야 합니다.<sup>[[6]](#references)</sup>
- fat binaries의 경우 fat headers (FAT_MAGIC/FAT_MAGIC_64)를 사용하여 Mach-O load commands를 순회하기 전에 올바른 slice와 offset을 찾아야 합니다.


## Minimal parsing 개요 (Python)

다음은 entitlements를 찾고 decode하기 위한 control flow를 보여주는 간결한 개요입니다. 간결성을 위해 robust bounds checks와 full fat binary support는 의도적으로 생략했습니다.<sup>[[6]](#references)[[7]](#references)</sup>
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
사용 팁:
- fat binaries를 처리하려면 먼저 struct fat_header/fat_arch를 읽고, 원하는 architecture slice를 선택한 다음 subrange를 parse_entitlements에 전달합니다.
- macOS에서는 다음 명령으로 결과를 검증할 수 있습니다: codesign -d --entitlements :- /path/to/binary


## Example findings

source article에서는 macOS 14.0 `launchd` binary에서 다음 entitlements를 확인했습니다:<sup>[[1]](#references)</sup>
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

firmware images 전체에서 이를 대규모로 검색하면 attack surface mapping과 releases/devices 간 diffing에 매우 유용합니다.


## Scaling across IPSWs (mounting and indexing)

전체 이미지를 저장하지 않고 executables를 열거하고 entitlements를 대규모로 추출하려면:<sup>[[1]](#references)</sup>

- @blacktop의 ipsw tool을 사용하여 firmware filesystems를 download하고 mount합니다. Mounting에는 apfs-fuse가 사용되므로 full extraction 없이 APFS volumes를 탐색할 수 있습니다.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```
- 마운트된 볼륨을 순회하여 Mach-O 파일을 찾고(magic을 확인하거나 file/otool 사용), entitlements와 imported frameworks를 파싱합니다.
- 수천 개의 IPSW에 걸쳐 선형적으로 증가하는 것을 방지하기 위해 정규화된 뷰를 relational database에 저장합니다:
- executables, operating_system_versions, entitlements, frameworks
- 다대다 관계: executable↔OS version, executable↔entitlement, executable↔framework

특정 executable name을 포함하는 모든 OS version을 나열하는 예제 쿼리(appeldb_rs에서 수정):<sup>[[1]](#references)</sup>
```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = 'launchd';
```
자체 indexer를 구현하는 경우 DB portability에 관한 참고 사항:<sup>[[1]](#references)</sup>
- ORM/abstraction(예: SeaORM)을 사용하여 code를 DB-agnostic(SQLite/PostgreSQL)으로 유지하세요.
- SQLite는 `AUTOINCREMENT`를 `INTEGER PRIMARY KEY`에서만 허용합니다. 해당 key는 signed 64-bit ROWID의 alias이지만, SQLite는 디스크에서 더 작은 integer width를 사용할 수 있습니다. SeaORM으로 생성한 Rust entities에 i64 IDs가 필요한 경우, entities를 i32로 생성하고 boundary에서 type을 변환하세요.<sup>[[1]](#references)[[8]](#references)[[9]](#references)</sup>


## entitlement hunting을 위한 오픈 소스 tooling 및 참고 자료

- Firmware mount/download: https://github.com/blacktop/ipsw.<sup>[[3]](#references)</sup>
- Entitlement databases 및 참고 자료:
- Jonathan Levin의 entitlement DB: https://newosxbook.com/ent.php.<sup>[[4]](#references)</sup>
- entdb: https://github.com/ChiChou/entdb.<sup>[[5]](#references)</sup>
- 대규모 indexer(Rust, self-hosted Web UI + OpenAPI): https://github.com/synacktiv/appledb_rs.<sup>[[2]](#references)</sup>
- structures 및 constants를 위한 Apple headers:
- loader.h (Mach-O headers, load commands)
- cs_blobs.h (SuperBlob, GenericBlob, CodeDirectory)

code signing internals(Code Directory, special slots, DER entitlements)에 대한 자세한 내용은 [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)을 참고하세요.


## References

- [1] [Corentin Liaud (Synacktiv), Apple 플랫폼을 위한 research support tool인 appledb_rs](https://www.synacktiv.com/publications/appledbrs-un-outil-daide-a-la-recherche-sur-plateformes-apple.html)
- [2] [synacktiv/appledb_rs](https://github.com/synacktiv/appledb_rs)
- [3] [blacktop/ipsw](https://github.com/blacktop/ipsw)
- [4] [Jonathan Levin의 entitlement DB](https://newosxbook.com/ent.php)
- [5] [ChiChou/entdb](https://github.com/ChiChou/entdb)
- [6] [XNU cs_blobs.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [7] [XNU mach-o/loader.h](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [8] [SQLite 데이터 유형](https://sqlite.org/datatype3.html)
- [9] [SQLite Autoincrement](https://sqlite.org/autoinc.html)
{{#include ../../../banners/hacktricks-training.md}}
