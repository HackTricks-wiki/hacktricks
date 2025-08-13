# Synology PAT/SPK 加密档案解密

{{#include ../../banners/hacktricks-training.md}}

## 概述

多个 Synology 设备（DSM/BSM NAS, BeeStation 等）以 **加密的 PAT / SPK 档案** 形式分发其固件和应用程序包。这些档案可以通过仅使用公共下载文件在 *离线* 状态下解密，得益于嵌入在官方提取库中的硬编码密钥。

本页面逐步记录了加密格式的工作原理以及如何完全恢复每个包内的明文 **TAR**。该过程基于 Synacktiv 在 2024 年 Pwn2Own 爱尔兰期间进行的研究，并在开源工具 [`synodecrypt`](https://github.com/synacktiv/synodecrypt) 中实现。

> ⚠️  `*.pat`（系统更新）和 `*.spk`（应用程序）档案的格式完全相同——它们仅在选择的硬编码密钥对上有所不同。

---

## 1. 获取档案

固件/应用程序更新通常可以从 Synology 的公共门户下载：
```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```
## 2. 转储 PAT 结构（可选）

`*.pat` 镜像本身是一个 **cpio 包**，其中嵌入了多个文件（引导加载程序、内核、rootfs、软件包……）。 免费工具 [`patology`](https://github.com/sud0woodo/patology) 方便用于检查该封装：
```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```
对于 `*.spk`，您可以直接跳到第 3 步。

## 3. 提取 Synology 解压库

真正的解密逻辑位于：

* `/usr/syno/sbin/synoarchive`               → 主要 CLI 包装器
* `/usr/lib/libsynopkg.so.1`                 → 从 DSM UI 调用包装器
* `libsynocodesign.so`                       → **包含加密实现**

这两个二进制文件都存在于系统根文件系统 (`hda1.tgz`) **和** 压缩的 init-rd (`rd.bin`) 中。如果您只有 PAT，可以通过以下方式获取它们：
```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```
## 4. 恢复硬编码的密钥 (`get_keys`)

在 `libsynocodesign.so` 中，函数 `get_keys(int keytype)` 简单地返回请求的归档系列的两个 128 位全局变量：
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
* **signature_key** → Ed25519 公钥，用于验证归档头。
* **master_key**    → 根密钥，用于推导每个归档的加密密钥。

您只需为每个 DSM 主要版本转储这两个常量一次。

## 5. 头结构与签名验证

`synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()` 执行以下操作：

1. 读取魔数 (3 字节) `0xBFBAAD` **或** `0xADBEEF`。
2. 读取小端 32 位 `header_len`。
3. 读取 `header_len` 字节 + 下一个 **0x40 字节的 Ed25519 签名**。
4. 遍历所有嵌入的公钥，直到 `crypto_sign_verify_detached()` 成功。
5. 使用 **MessagePack** 解码头，得到：
```python
[
data: bytes,
entries: [ [size: int, sha256: bytes], … ],
archive_description: bytes,
serial_number: [bytes],
not_valid_before: int
]
```
`entries` 后续允许 libarchive 在解密每个文件时进行完整性检查。

## 6. 派生每个归档的子密钥

从 MessagePack 头中包含的 `data` blob：

* `subkey_id`  = 小端 `uint64` 在偏移量 0x10
* `ctx`        = 偏移量 0x18 处的 7 字节

32 字节的 **stream key** 通过 libsodium 获得：
```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```
## 7. Synology的自定义 **libarchive** 后端

Synology捆绑了一个修补过的libarchive，当魔术值为`0xADBEEF`时，它会注册一个假的"tar"格式：
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
解密后的 `tar_hdr` 是一个 **经典的 POSIX TAR 头**。

### spk_read_data()
```
while (remaining > 0):
chunk_len = min(0x400000, remaining) + 0x11   # +tag
buf   = archive_read_ahead(chunk_len)
crypto_secretstream_xchacha20poly1305_pull(state, out, …, buf, chunk_len)
remaining -= chunk_len - 0x11
```
每个 **0x18-byte nonce** 被添加到加密块之前。

一旦所有条目被处理，libarchive 生成一个完全有效的 **`.tar`**，可以使用任何标准工具解压。

## 8. 使用 synodecrypt 解密所有内容
```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```
`synodecrypt` 自动检测 PAT/SPK，加载正确的密钥并应用上述完整链。

## 9. 常见陷阱

* **不要** 交换 `signature_key` 和 `master_key` – 它们的用途不同。
* **nonce** 在每个块（头部和数据）的密文 *之前*。
* 最大加密块大小为 **0x400000 + 0x11**（libsodium 标签）。
* 为一个 DSM 版本创建的档案可能在下一个版本中切换到不同的硬编码密钥。

## 10. 额外工具

* [`patology`](https://github.com/sud0woodo/patology) – 解析/转储 PAT 档案。
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – 解密 PAT/SPK/其他。
* [`libsodium`](https://github.com/jedisct1/libsodium) – XChaCha20-Poly1305 secretstream 的参考实现。
* [`msgpack`](https://msgpack.org/) – 头部序列化。

## 参考文献

- [Extraction of Synology encrypted archives – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [synodecrypt on GitHub](https://github.com/synacktiv/synodecrypt)
- [patology on GitHub](https://github.com/sud0woodo/patology)

{{#include ../../banners/hacktricks-training.md}}
