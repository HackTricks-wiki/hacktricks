# Synology PAT/SPK Encrypted Archive Decryption

{{#include ../../banners/hacktricks-training.md}}

## 概要

複数の Synology デバイス（DSM/BSM NAS、BeeStation、…）は、firmware および application package を **encrypted PAT / SPK archives** として配布しています。これらの archive は、official extraction libraries 内に埋め込まれた hard-coded keys のおかげで、public download files だけを使って *offline* で復号できます。

このページでは、encrypted format の仕組みと、各 package 内に格納された clear-text **TAR** を完全に復元する方法を step-by-step で説明します。この手順は、Pwn2Own Ireland 2024 中に Synacktiv が実施した research に基づいており、open-source tool [`synodecrypt`](https://github.com/synacktiv/synodecrypt) に実装されています。<sup>[[1]](#references)[[2]](#references)</sup>

> ⚠️ 形式は `*.pat`（system update）と `*.spk`（application）archive の両方でまったく同じです。異なるのは、選択される hard-coded keys の pair だけです。

---

## 1. archive を取得する

firmware/application update は通常、Synology の public portal から download できます。
```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```
## 2. PAT構造をdumpする（任意）

`*.pat` images自体が、複数のファイル（boot loader、kernel、rootfs、packagesなど）を内包する**cpio bundle**です。無償のutility [`patology`](https://github.com/sud0woodo/patology)を使うと、このwrapperを簡単に調査できます:<sup>[[3]](#references)</sup>
```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```
For `*.spk` の場合は、直接 step 3 に進めます。

## 3. Synology の extraction libraries を抽出する

実際の decryption logic は以下にあります。

* `/usr/syno/sbin/synoarchive`               → main CLI wrapper
* `/usr/lib/libsynopkg.so.1`                 → DSM UI から wrapper を呼び出す
* `libsynocodesign.so`                       → **cryptographic implementation を含む**

両方の binary は system rootfs（`hda1.tgz`）**と** compressed init-rd（`rd.bin`）に存在します。PAT しかない場合は、次の方法で取得できます。
```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```
## 4. ハードコードされたキーの復元（`get_keys`）

`libsynocodesign.so` 内の関数 `get_keys(int keytype)` は、要求されたアーカイブファミリに対応する2つの128ビットのグローバル変数を単に返します。<sup>[[1]](#references)</sup>
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
* **signature_key** → archive header の検証に使用する Ed25519 public key。
* **master_key**    → archive ごとの encryption key の導出に使用する root key。

DSM の major version ごとに、これら 2 つの constants を一度だけ dump すればよい。

## 5. Header structure と signature verification

`synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()` は、以下を実行する:<sup>[[1]](#references)</sup>

1. magic (3 bytes) `0xBFBAAD` **または** `0xADBEEF` を読み取る。
2. little-endian 32-bit の `header_len` を読み取る。
3. `header_len` bytes と、その直後の **0x40-byte Ed25519 signature** を読み取る。
4. `crypto_sign_verify_detached()` が成功するまで、埋め込まれたすべての public keys を順に処理する。
5. **MessagePack** で header を decode し、以下を取得する:
```python
[
data: bytes,
entries: [ [size: int, sha256: bytes], … ],
archive_description: bytes,
serial_number: [bytes],
not_valid_before: int
]
```
`entries`により、後で復号中の各ファイルのintegrity-checkをlibarchiveで実行できます。

## 6. archiveごとのsub-keyを導出する

MessagePackヘッダーに含まれる`data` blobから:

* `subkey_id`  = オフセット0x10にあるlittle-endianの`uint64`
* `ctx`        = オフセット0x18にある7バイト

32バイトの**stream key**はlibsodiumで取得します:
```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```
## 7. Synology独自の **libarchive** backend

Synologyは、magicが`0xADBEEF`の場合に偽の「tar」formatを登録する、パッチ適用済みのlibarchiveをバンドルしています。<sup>[[1]](#references)</sup>
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
復号された `tar_hdr` は**標準的な POSIX TAR ヘッダ**です。

### spk_read_data()
```
while (remaining > 0):
chunk_len = min(0x400000, remaining) + 0x11   # +tag
buf   = archive_read_ahead(chunk_len)
crypto_secretstream_xchacha20poly1305_pull(state, out, …, buf, chunk_len)
remaining -= chunk_len - 0x11
```
各 **0x18-byte nonce** は暗号化されたチャンクの前に付加されます。

すべてのエントリが処理されると、libarchive は完全に有効な **`.tar`** を生成し、標準的なツールで展開できます。

## 8. synodecryptですべてを復号する
```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```
`synodecrypt` は PAT/SPK を自動的に検出し、正しい keys を読み込み、上記で説明した完全な chain を適用します。<sup>[[2]](#references)</sup>

## 9. よくある落とし穴

* `signature_key` と `master_key` を **入れ替えない** でください。これらは異なる目的で使用されます。
* **nonce** は、すべての block（header と data）の ciphertext より *前* に置かれます。
* 暗号化された chunk の最大サイズは **0x400000 + 0x11**（libsodium tag）です。
* ある DSM generation 用に作成された archives では、次の release で別の hard-coded keys に切り替わる場合があります。

## 10. 追加の tooling

* [`patology`](https://github.com/sud0woodo/patology) – PAT archives を parse/dump します。<sup>[[3]](#references)</sup>
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – PAT/SPK/その他を decrypt します。<sup>[[2]](#references)</sup>
* [`libsodium`](https://github.com/jedisct1/libsodium) – XChaCha20-Poly1305 secretstream の reference implementation です。
* [`msgpack`](https://msgpack.org/) – header serialisation に使用します。

## References

- [1] [Extraction of Synology encrypted archives – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [2] [synodecrypt on GitHub](https://github.com/synacktiv/synodecrypt)
- [3] [patology on GitHub](https://github.com/sud0woodo/patology)

{{#include ../../banners/hacktricks-training.md}}
