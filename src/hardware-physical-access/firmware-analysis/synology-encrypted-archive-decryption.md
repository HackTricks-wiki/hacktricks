# Synology PAT/SPK 加密归档解密

{{#include ../../banners/hacktricks-training.md}}

## 概述

多个 Synology 设备（DSM/BSM NAS、BeeStation，……）会以**加密的 PAT / SPK 归档**形式分发其 firmware 和 application packages。得益于官方 extraction libraries 内嵌的 hard-coded keys，只需公开下载的文件，即可在 *offline* 环境中解密这些归档。

本文将分步说明加密格式的工作原理，以及如何完整恢复每个 package 内部的明文 **TAR**。该过程基于 Synacktiv 在 Pwn2Own Ireland 2024 期间开展的研究，并通过开源工具 [`synodecrypt`](https://github.com/synacktiv/synodecrypt) 实现。<sup>[[1]](#references)[[2]](#references)</sup>

> ⚠️ 该格式对 `*.pat`（system update）和 `*.spk`（application）归档完全相同——两者的区别仅在于所选择的 hard-coded keys 对不同。

---

## 1. 获取归档

通常可以从 Synology 的 public portal 下载 firmware/application update：
```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```
## 2. Dump PAT 结构（可选）

`*.pat` 镜像本身是一个 **cpio bundle**，其中嵌入了多个文件（boot loader、kernel、rootfs、packages……）。免费的工具 [`patology`](https://github.com/sud0woodo/patology) 便于检查这个 wrapper：<sup>[[3]](#references)</sup>
```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```
对于 `*.spk`，可以直接跳到第 3 步。

## 3. 提取 Synology extraction libraries

真正的解密逻辑位于：

* `/usr/syno/sbin/synoarchive`               → 主 CLI wrapper
* `/usr/lib/libsynopkg.so.1`                 → 从 DSM UI 调用 wrapper
* `libsynocodesign.so`                       → **包含 cryptographic implementation**

这两个 binaries 都存在于系统 rootfs（`hda1.tgz`）和压缩的 init-rd（`rd.bin`）中。如果你只有 PAT，可以通过以下方式获取它们：
```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```
## 4. 恢复硬编码密钥（`get_keys`）

在 `libsynocodesign.so` 中，函数 `get_keys(int keytype)` 会根据请求的 archive 类型，直接返回两个 128 位全局变量：<sup>[[1]](#references)</sup>
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
* **signature_key** → 用于验证 archive header 的 Ed25519 public key。
* **master_key**    → 用于派生每个 archive encryption key 的根密钥。

对于每个 DSM major version，只需 dump 这两个常量一次。

## 5. Header 结构与 signature verification

`synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()` 执行以下操作：<sup>[[1]](#references)</sup>

1. 读取 magic（3 字节）`0xBFBAAD` **或** `0xADBEEF`。
2. 读取 little-endian 32-bit `header_len`。
3. 读取 `header_len` 字节，以及接下来的 **0x40 字节 Ed25519 signature**。
4. 遍历所有嵌入的 public keys，直到 `crypto_sign_verify_detached()` 成功。
5. 使用 **MessagePack** 解码 header，得到：
```python
[
data: bytes,
entries: [ [size: int, sha256: bytes], … ],
archive_description: bytes,
serial_number: [bytes],
not_valid_before: int
]
```
`entries` 随后允许 libarchive 在解密每个文件时执行完整性检查。

## 6. 派生每个 archive 的子密钥

从 MessagePack header 中包含的 `data` blob 获取：

* `subkey_id`  = 偏移量 0x10 处的小端序 `uint64`
* `ctx`        = 偏移量 0x18 处的 7 个字节

32 字节的 **stream key** 使用 libsodium 获取：
```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```
## 7. Synology 自定义的 **libarchive** 后端

Synology 集成了一个经过修补的 libarchive，当 magic 为 `0xADBEEF` 时注册一个伪造的 "tar" 格式：<sup>[[1]](#references)</sup>
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
解密后的 `tar_hdr` 是一个**经典的 POSIX TAR header**。

### spk_read_data()
```
while (remaining > 0):
chunk_len = min(0x400000, remaining) + 0x11   # +tag
buf   = archive_read_ahead(chunk_len)
crypto_secretstream_xchacha20poly1305_pull(state, out, …, buf, chunk_len)
remaining -= chunk_len - 0x11
```
每个 **0x18-byte nonce** 都会添加到加密 chunk 的前面。

处理完所有条目后，libarchive 会生成一个完全有效的 **`.tar`** 文件，可以使用任何标准工具解包。

## 8. 使用 synodecrypt 解密所有内容
```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```
`synodecrypt` 会自动检测 PAT/SPK，加载正确的密钥，并应用上述完整链条。<sup>[[2]](#references)</sup>

## 9. 常见陷阱

* **不要** 交换 `signature_key` 和 `master_key` ——它们用途不同。
* 对于每个 block（header 和 data），**nonce** 都位于 ciphertext 之前。
* 最大加密 chunk 大小为 **0x400000 + 0x11**（libsodium tag）。
* 为某一 DSM 代创建的 archive，可能会在下一个版本中切换到不同的硬编码密钥。

## 10. 其他工具

* [`patology`](https://github.com/sud0woodo/patology) – 解析/导出 PAT archive。<sup>[[3]](#references)</sup>
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – 解密 PAT/SPK/其他格式。<sup>[[2]](#references)</sup>
* [`libsodium`](https://github.com/jedisct1/libsodium) – XChaCha20-Poly1305 secretstream 的参考实现。
* [`msgpack`](https://msgpack.org/) – header 序列化。

## 参考资料

- [1] [Extraction of Synology encrypted archives – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [2] [synodecrypt on GitHub](https://github.com/synacktiv/synodecrypt)
- [3] [patology on GitHub](https://github.com/sud0woodo/patology)

{{#include ../../banners/hacktricks-training.md}}
