# Giải mã archive PAT/SPK được mã hóa của Synology

{{#include ../../banners/hacktricks-training.md}}

## Tổng quan

Một số thiết bị Synology (NAS DSM/BSM, BeeStation, …) phân phối firmware và gói ứng dụng dưới dạng **archive PAT / SPK được mã hóa**. Có thể giải mã các archive này *offline* chỉ bằng các tệp tải xuống công khai, nhờ những key hard-code được nhúng trong các thư viện giải nén chính thức.

Trang này hướng dẫn từng bước cách thức hoạt động của định dạng được mã hóa và cách khôi phục đầy đủ **TAR** dạng clear-text nằm bên trong mỗi gói. Quy trình này dựa trên nghiên cứu của Synacktiv trong sự kiện Pwn2Own Ireland 2024 và được triển khai trong công cụ mã nguồn mở [`synodecrypt`](https://github.com/synacktiv/synodecrypt).<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

> ⚠️ Định dạng hoàn toàn giống nhau đối với cả archive `*.pat` (bản cập nhật hệ thống) và `*.spk` (ứng dụng) – chúng chỉ khác nhau ở cặp key hard-code được chọn.

---

## 1. Tải archive

Thông thường, có thể tải bản cập nhật firmware/ứng dụng từ cổng thông tin công khai của Synology:

```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```

## 2. Dump cấu trúc PAT (tùy chọn)

Các image `*.pat` bản thân là một **gói cpio** chứa nhiều tệp (boot loader, kernel, rootfs, packages…). Tiện ích miễn phí [`patology`](https://github.com/sud0woodo/patology) rất hữu ích để kiểm tra wrapper đó:<sup>[[3]](#references)</sup>

```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```

Với `*.spk`, bạn có thể chuyển thẳng đến bước 3.

## 3. Trích xuất các thư viện giải nén của Synology

Logic giải mã thực sự nằm trong:

* `/usr/syno/sbin/synoarchive`               → wrapper CLI chính
* `/usr/lib/libsynopkg.so.1`                 → gọi wrapper từ giao diện DSM
* `libsynocodesign.so`                       → **chứa phần triển khai mật mã**

Cả hai binary đều có trong rootfs của hệ thống (`hda1.tgz`) **và** trong init-rd đã nén (`rd.bin`). Nếu chỉ có PAT, bạn có thể lấy chúng theo cách sau:

```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```

## 4. Khôi phục các khóa hard-coded (`get_keys`)

Trong `libsynocodesign.so`, hàm `get_keys(int keytype)` chỉ trả về hai biến toàn cục 128-bit tương ứng với họ archive được yêu cầu:<sup>[[1]](#references)</sup>

```c
case 0:            // PAT (system)
case 10:
case 11:
  signature_key = qword_23A40;
  master_key    = qword_23A68;
  break;

case 3:            // SPK (applications)
  signature_key = qword_23AE0;
  master_key    = qword_23B08;
  break;
```

* **signature_key** → Khóa công khai Ed25519 dùng để xác minh header của archive.
* **master_key**    → Khóa gốc dùng để dẫn xuất khóa mã hóa riêng cho từng archive.

Bạn chỉ cần dump hai hằng số này một lần cho mỗi phiên bản DSM chính.

## 5. Cấu trúc header & xác minh chữ ký

`synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()` thực hiện các bước sau:<sup>[[1]](#references)</sup>

1. Đọc magic (3 byte) `0xBFBAAD` **hoặc** `0xADBEEF`.
2. Đọc `header_len` 32-bit little-endian.
3. Đọc `header_len` byte + chữ ký Ed25519 **0x40 byte** tiếp theo.
4. Lần lượt thử tất cả khóa công khai được nhúng cho đến khi `crypto_sign_verify_detached()` thành công.
5. Giải mã header bằng **MessagePack**, thu được:

```python
[
  data: bytes,
  entries: [ [size: int, sha256: bytes], … ],
  archive_description: bytes,
  serial_number: [bytes],
  not_valid_before: int
]
```

`entries` sau đó cho phép libarchive kiểm tra tính toàn vẹn của từng tệp trong quá trình giải mã.

## 6. Tạo sub-key cho từng archive

Từ blob `data` có trong header MessagePack:

* `subkey_id`  = `uint64` little-endian tại offset 0x10
* `ctx`        = 7 byte tại offset 0x18

**stream key** 32 byte được tạo bằng libsodium:

```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```

## 7. Backend **libarchive** tùy chỉnh của Synology

Synology đóng gói một phiên bản libarchive đã được vá, đăng ký định dạng "tar" giả khi magic là `0xADBEEF`:<sup>[[1]](#references)</sup>

```c
register_format(
   "tar", spk_bid, spk_options,
   spk_read_header, spk_read_data, spk_read_data_skip,
   NULL, spk_cleanup, NULL, NULL);
```

### spk_read_header()

```
- Read 0x200 bytes
- nonce  = buf[0:0x18]
- cipher = buf[0x18:0x18+0x193]
- crypto_secretstream_xchacha20poly1305_init_pull(state, nonce, kdf_subkey)
- crypto_secretstream_xchacha20poly1305_pull(state, tar_hdr, …, cipher, 0x193)
```

`tar_hdr` đã giải mã là **header TAR POSIX cổ điển**.

### spk_read_data()

```
while (remaining > 0):
    chunk_len = min(0x400000, remaining) + 0x11   # +tag
    buf   = archive_read_ahead(chunk_len)
    crypto_secretstream_xchacha20poly1305_pull(state, out, …, buf, chunk_len)
    remaining -= chunk_len - 0x11
```

Mỗi **nonce 0x18 byte** được thêm vào trước chunk đã mã hóa.

Sau khi xử lý tất cả các mục, libarchive tạo ra một **`.tar`** hoàn toàn hợp lệ, có thể giải nén bằng bất kỳ công cụ tiêu chuẩn nào.

## 8. Giải mã tất cả bằng synodecrypt

```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```

`synodecrypt` tự động phát hiện PAT/SPK, tải đúng keys và áp dụng toàn bộ chuỗi đã mô tả ở trên.<sup>[[2]](#references)</sup>

## 9. Các lỗi thường gặp

* **Không** hoán đổi `signature_key` và `master_key` – chúng có mục đích khác nhau.
* **Nonce** đứng *trước* ciphertext trong mọi block (header và dữ liệu).
* Kích thước chunk được mã hóa tối đa là **0x400000 + 0x11** (tag của libsodium).
* Các archive được tạo cho một thế hệ DSM có thể chuyển sang dùng các keys hard-coded khác trong bản phát hành tiếp theo.

## 10. Công cụ bổ sung

* [`patology`](https://github.com/sud0woodo/patology) – phân tích/đổ nội dung archive PAT.<sup>[[3]](#references)</sup>
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – giải mã PAT/SPK/các định dạng khác.<sup>[[2]](#references)</sup>
* [`libsodium`](https://github.com/jedisct1/libsodium) – triển khai tham chiếu của XChaCha20-Poly1305 secretstream.
* [`msgpack`](https://msgpack.org/) – tuần tự hóa header.

## References

- [1] [Trích xuất archive Synology được mã hóa – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [2] [synodecrypt trên GitHub](https://github.com/synacktiv/synodecrypt)
- [3] [patology trên GitHub](https://github.com/sud0woodo/patology)
{{#include ../../banners/hacktricks-training.md}}