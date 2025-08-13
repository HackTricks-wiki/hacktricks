# Synology PAT/SPK 暗号化アーカイブの復号

{{#include ../../banners/hacktricks-training.md}}

## 概要

いくつかのSynologyデバイス（DSM/BSM NAS、BeeStationなど）は、**暗号化されたPAT / SPKアーカイブ**でファームウェアとアプリケーションパッケージを配布しています。これらのアーカイブは、公式の抽出ライブラリに埋め込まれたハードコーディングされたキーのおかげで、公開ダウンロードファイルだけで*オフライン*で復号できます。

このページでは、暗号化形式の動作と、各パッケージ内にあるクリアテキストの**TAR**を完全に復元する方法をステップバイステップで文書化しています。この手順は、Pwn2Own Ireland 2024中に行われたSynacktivの研究に基づいており、オープンソースツール[`synodecrypt`](https://github.com/synacktiv/synodecrypt)に実装されています。

> ⚠️  フォーマットは`*.pat`（システム更新）と`*.spk`（アプリケーション）アーカイブの両方で全く同じです – 選択されるハードコーディングされたキーのペアだけが異なります。

---

## 1. アーカイブを取得する

ファームウェア/アプリケーションの更新は、通常、Synologyの公開ポータルからダウンロードできます:
```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```
## 2. PAT構造をダンプする（オプション）

`*.pat`イメージは、いくつかのファイル（ブートローダー、カーネル、rootfs、パッケージなど）を埋め込んだ**cpioバンドル**です。無料のユーティリティ[`patology`](https://github.com/sud0woodo/patology)は、そのラッパーを検査するのに便利です：
```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```
`*.spk`の場合、直接ステップ3に進むことができます。

## 3. Synologyの抽出ライブラリを抽出する

実際の復号化ロジックは以下にあります：

* `/usr/syno/sbin/synoarchive`               → メインCLIラッパー
* `/usr/lib/libsynopkg.so.1`                 → DSM UIからラッパーを呼び出す
* `libsynocodesign.so`                       → **暗号実装を含む**

両方のバイナリはシステムのrootfs（`hda1.tgz`）**および**圧縮されたinit-rd（`rd.bin`）に存在します。PATのみを持っている場合は、次の方法で取得できます：
```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```
## 4. ハードコーディングされたキーの回復 (`get_keys`)

`libsynocodesign.so` 内の関数 `get_keys(int keytype)` は、要求されたアーカイブファミリーのために単に2つの128ビットのグローバル変数を返します:
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
* **signature_key** → アーカイブヘッダーを検証するために使用されるEd25519公開鍵。
* **master_key**    → アーカイブごとの暗号化キーを導出するために使用されるルートキー。

各DSMメジャーバージョンごとに、これらの2つの定数を一度だけダンプする必要があります。

## 5. ヘッダー構造と署名検証

`synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()` は以下を実行します：

1. マジックを読み取る (3バイト) `0xBFBAAD` **または** `0xADBEEF`。
2. リトルエンディアン32ビット `header_len` を読み取る。
3. `header_len` バイト + 次の **0x40バイトのEd25519署名** を読み取る。
4. `crypto_sign_verify_detached()` が成功するまで、すべての埋め込まれた公開鍵を反復処理する。
5. **MessagePack** でヘッダーをデコードし、次の結果を得る：
```python
[
data: bytes,
entries: [ [size: int, sha256: bytes], … ],
archive_description: bytes,
serial_number: [bytes],
not_valid_before: int
]
```
`entries` は、libarchive が各ファイルの整合性をチェックできるようにします。

## 6. アーカイブごとのサブキーを導出する

MessagePack ヘッダーに含まれる `data` ブロブから:

* `subkey_id`  = オフセット 0x10 のリトルエンディアン `uint64`
* `ctx`        = オフセット 0x18 の 7 バイト

32 バイトの **ストリームキー** は libsodium を使用して取得されます:
```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```
## 7. Synologyのカスタム **libarchive** バックエンド

Synologyは、マジックが `0xADBEEF` の場合に偽の "tar" フォーマットを登録するパッチを当てたlibarchiveをバンドルしています:
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
復号化された `tar_hdr` は **古典的なPOSIX TARヘッダー** です。

### spk_read_data()
```
while (remaining > 0):
chunk_len = min(0x400000, remaining) + 0x11   # +tag
buf   = archive_read_ahead(chunk_len)
crypto_secretstream_xchacha20poly1305_pull(state, out, …, buf, chunk_len)
remaining -= chunk_len - 0x11
```
各 **0x18バイトのノンス** は暗号化されたチャンクの前に追加されます。

すべてのエントリが処理されると、libarchiveは任意の標準ツールで解凍できる完全に有効な **`.tar`** を生成します。

## 8. synodecryptを使用してすべてを復号化する
```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```
`synodecrypt` は自動的に PAT/SPK を検出し、正しいキーをロードして、上記で説明したフルチェーンを適用します。

## 9. 一般的な落とし穴

* `signature_key` と `master_key` を入れ替えないでください – それぞれ異なる目的があります。
* **nonce** はすべてのブロック（ヘッダーとデータ）の暗号文の *前* に来ます。
* 最大暗号化チャンクサイズは **0x400000 + 0x11** （libsodium タグ）です。
* 一つの DSM 世代のために作成されたアーカイブは、次のリリースで異なるハードコーディングされたキーに切り替わる可能性があります。

## 10. 追加ツール

* [`patology`](https://github.com/sud0woodo/patology) – PAT アーカイブを解析/ダンプします。
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – PAT/SPK/その他を復号化します。
* [`libsodium`](https://github.com/jedisct1/libsodium) – XChaCha20-Poly1305 secretstream のリファレンス実装です。
* [`msgpack`](https://msgpack.org/) – ヘッダーのシリアライゼーション。

## 参考文献

- [Extraction of Synology encrypted archives – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [synodecrypt on GitHub](https://github.com/synacktiv/synodecrypt)
- [patology on GitHub](https://github.com/sud0woodo/patology)

{{#include ../../banners/hacktricks-training.md}}
