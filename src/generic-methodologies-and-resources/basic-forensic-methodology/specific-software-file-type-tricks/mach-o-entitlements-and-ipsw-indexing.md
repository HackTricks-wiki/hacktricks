# Trích xuất Entitlements từ Mach-O & lập chỉ mục IPSW

{{#include ../../../banners/hacktricks-training.md}}

## Tổng quan

Trang này trình bày cách trích xuất entitlements từ các tệp nhị phân Mach-O bằng lập trình: duyệt qua LC_CODE_SIGNATURE và phân tích code signing SuperBlob. Trang cũng hướng dẫn mở rộng quy trình này cho các firmware IPSW của Apple bằng cách mount và lập chỉ mục nội dung để phục vụ tìm kiếm/đối chiếu pháp chứng.

Nếu cần ôn lại định dạng Mach-O và code signing, hãy xem thêm: macOS code signing và cấu trúc bên trong SuperBlob.
- Xem chi tiết về macOS code signing (SuperBlob, Code Directory, special slots): [Code signing trên macOS](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)
- Xem các cấu trúc Mach-O và load command tổng quát: [Universal binaries & định dạng Mach-O](../../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)


## Entitlements trong Mach-O: chúng nằm ở đâu

Entitlements được lưu trong dữ liệu chữ ký mã được tham chiếu bởi load command LC_CODE_SIGNATURE và đặt trong segment __LINKEDIT. Chữ ký là một CS_SuperBlob chứa nhiều blob (code directory, requirements, entitlements, CMS, v.v.). Blob entitlements là một CS_GenericBlob có dữ liệu là property list được tuần tự hóa, ánh xạ các khóa entitlement với giá trị; parser cần chấp nhận cả định dạng XML và binary plist.<sup>[[1]](#references)[[6]](#references)</sup>

Các cấu trúc chính (từ xnu):<sup>[[6]](#references)[[7]](#references)</sup>

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

Các hằng số quan trọng trong header của Apple gồm:<sup>[[6]](#references)[[7]](#references)</sup>
- LC_CODE_SIGNATURE cmd = 0x1d
- CS SuperBlob magic = 0xfade0cc0
- Entitlements index slot (`CSSLOT_ENTITLEMENTS`) = 5; blob ở slot đó có magic `CSMAGIC_EMBEDDED_ENTITLEMENTS` = 0xfade7171
- DER entitlements dùng slot `CSSLOT_DER_ENTITLEMENTS` = 7 và blob magic `CSMAGIC_EMBEDDED_DER_ENTITLEMENTS` = 0xfade7172

Lưu ý: Các binary đa kiến trúc (fat) chứa nhiều Mach-O slice. Bạn phải chọn slice tương ứng với kiến trúc muốn kiểm tra, sau đó duyệt qua các load command của nó.


## Các bước trích xuất (tổng quát, bảo toàn dữ liệu ở mức đủ dùng)

1) Phân tích Mach-O header; duyệt qua số bản ghi load_command theo ncmds.
2) Tìm LC_CODE_SIGNATURE; đọc linkedit_data_command.dataoff/datasize để ánh xạ Code Signing SuperBlob nằm trong __LINKEDIT.
3) Xác thực CS_SuperBlob.magic == 0xfade0cc0; duyệt qua các mục count của CS_BlobIndex.
4) Tìm `index.type == CSSLOT_ENTITLEMENTS` (5), sau đó xác minh rằng `CS_GenericBlob` được trỏ đến có magic `CSMAGIC_EMBEDDED_ENTITLEMENTS` (0xfade7171). Phân tích dữ liệu của blob này dưới dạng property list để lấy các entitlement dạng key/value.<sup>[[1]](#references)[[6]](#references)</sup>

Lưu ý khi triển khai:
- Các cấu trúc code signature dùng trường big-endian; hãy hoán đổi thứ tự byte khi phân tích trên host little-endian.
- `GenericBlob` của entitlements chứa plist đã được tuần tự hóa; các thư viện plist tiêu chuẩn có thể xử lý định dạng XML hoặc binary.
- Một số binary iOS có thể chứa DER entitlements; XNU cung cấp một kiểu DER blob riêng, và cách biểu diễn hoặc slot của entitlement có thể khác nhau tùy nền tảng và phiên bản, vì vậy hãy đối chiếu entitlements tiêu chuẩn với DER khi cần.<sup>[[6]](#references)</sup>
- Với các binary fat, hãy dùng fat header (FAT_MAGIC/FAT_MAGIC_64) để tìm đúng slice và offset trước khi duyệt qua các load command của Mach-O.


## Phác thảo phân tích tối giản (Python)

Sau đây là phác thảo ngắn gọn về luồng điều khiển để tìm và giải mã entitlements. Để ngắn gọn, phác thảo cố ý lược bỏ việc kiểm tra giới hạn dữ liệu toàn diện và hỗ trợ đầy đủ binary fat.<sup>[[6]](#references)[[7]](#references)</sup>

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

Mẹo sử dụng:
- Để xử lý fat binaries, trước tiên hãy đọc struct fat_header/fat_arch, chọn slice kiến trúc mong muốn, rồi truyền khoảng con đó vào parse_entitlements.
- Trên macOS, bạn có thể xác thực kết quả bằng: codesign -d --entitlements :- /path/to/binary


## Các phát hiện mẫu

Bài viết nguồn cho thấy các entitlement này trong binary `launchd` của macOS 14.0:<sup>[[1]](#references)</sup>
- com.apple.security.network.server = true
- com.apple.rootless.storage.early_boot_mount = true
- com.apple.private.kernel.system-override = true
- com.apple.private.pmap.load-trust-cache = ["cryptex1.boot.os", "cryptex1.boot.app", "cryptex1.safari-downlevel"]

Tìm kiếm các entitlement này trên quy mô lớn trong các firmware image rất hữu ích cho việc lập bản đồ attack surface và so sánh khác biệt giữa các bản phát hành/thiết bị.


## Mở rộng quy mô trên nhiều IPSW (mount và lập chỉ mục)

Để liệt kê các executable và trích xuất entitlement trên quy mô lớn mà không lưu trữ toàn bộ image:<sup>[[1]](#references)</sup>

- Dùng công cụ ipsw của @blacktop để tải xuống và mount các filesystem firmware. Việc mount sử dụng apfs-fuse, nhờ đó bạn có thể duyệt các volume APFS mà không cần giải nén toàn bộ.<sup>[[1]](#references)[[3]](#references)</sup>

```bash
# Download latest IPSW for iPhone11,2 (iPhone XS)
ipsw download ipsw -y --device iPhone11,2 --latest

# Mount IPSW filesystem (uses underlying apfs-fuse)
ipsw mount fs <IPSW_FILE>
```

- Duyệt qua các volume đã mount để tìm file Mach-O (kiểm tra magic và/hoặc dùng file/otool), sau đó phân tích entitlements và các framework được import.
- Lưu một dạng biểu diễn đã chuẩn hóa vào cơ sở dữ liệu quan hệ để tránh tăng trưởng tuyến tính khi xử lý hàng nghìn IPSW:
  - executables, operating_system_versions, entitlements, frameworks
  - quan hệ nhiều-nhiều: executable↔OS version, executable↔entitlement, executable↔framework

Ví dụ truy vấn liệt kê tất cả phiên bản OS có chứa một executable với tên cho trước (được điều chỉnh từ appledb_rs):<sup>[[1]](#references)</sup>

```sql
SELECT osv.version AS "Versions"
FROM device d
LEFT JOIN operating_system_version osv ON osv.device_id = d.id
LEFT JOIN executable_operating_system_version eosv ON eosv.operating_system_version_id = osv.id
LEFT JOIN executable e ON e.id = eosv.executable_id
WHERE e.name = 'launchd';
```

Ghi chú về tính khả chuyển của DB (nếu bạn tự triển khai indexer):<sup>[[1]](#references)</sup>
- Dùng ORM/lớp trừu tượng (ví dụ: SeaORM) để code không phụ thuộc DB (SQLite/PostgreSQL).
- SQLite chỉ cho phép `AUTOINCREMENT` trên `INTEGER PRIMARY KEY`; khóa này là bí danh của ROWID 64-bit có dấu, dù SQLite có thể dùng độ rộng số nguyên nhỏ hơn trên đĩa. Nếu các Rust entity do SeaORM tạo cần ID kiểu i64, hãy tạo entity với kiểu i32 rồi chuyển đổi kiểu tại ranh giới.<sup>[[1]](#references)[[8]](#references)[[9]](#references)</sup>


## Công cụ mã nguồn mở và tài liệu tham khảo để tìm kiếm entitlement

- Mount/tải firmware: https://github.com/blacktop/ipsw.<sup>[[3]](#references)</sup>
- Cơ sở dữ liệu entitlement và tài liệu tham khảo:
  - Cơ sở dữ liệu entitlement của Jonathan Levin: https://newosxbook.com/ent.php.<sup>[[4]](#references)</sup>
  - entdb: https://github.com/ChiChou/entdb.<sup>[[5]](#references)</sup>
- Indexer quy mô lớn (Rust, Web UI tự host + OpenAPI): https://github.com/synacktiv/appledb_rs.<sup>[[2]](#references)</sup>
- Header của Apple cho các cấu trúc và hằng số:
  - loader.h (header Mach-O, load command)
  - cs_blobs.h (SuperBlob, GenericBlob, CodeDirectory)

Để tìm hiểu thêm về các thành phần bên trong của code signing (Code Directory, special slot, DER entitlement), xem: [macOS Code Signing](../../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing.md)


## References

- [1] [Corentin Liaud (Synacktiv), appledb_rs: công cụ hỗ trợ nghiên cứu các nền tảng Apple](https://www.synacktiv.com/publications/appledbrs-un-outil-daide-a-la-recherche-sur-plateformes-apple.html)
- [2] [synacktiv/appledb_rs](https://github.com/synacktiv/appledb_rs)
- [3] [blacktop/ipsw](https://github.com/blacktop/ipsw)
- [4] [Cơ sở dữ liệu entitlement của Jonathan Levin](https://newosxbook.com/ent.php)
- [5] [ChiChou/entdb](https://github.com/ChiChou/entdb)
- [6] [XNU cs_blobs.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [7] [XNU mach-o/loader.h](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [8] [Kiểu dữ liệu SQLite](https://sqlite.org/datatype3.html)
- [9] [Tự động tăng trong SQLite](https://sqlite.org/autoinc.html)
{{#include ../../../banners/hacktricks-training.md}}
