# Crypto CTF ワークフロー

{{#include ../../banners/hacktricks-training.md}}

## トリアージチェックリスト

1. 所持しているものを識別する: encoding vs encryption vs hash vs signature vs MAC.
2. 制御されているものを特定する: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. 分類する: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. 高確率のチェックを最初に行う: decode layers, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior.
5. 必要な場合にのみ高度な手法にエスカレートする: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## オンラインリソース & ユーティリティ

これは、タスクが識別やレイヤー剥離の場合、または仮説の迅速な確認が必要なときに有用です。

### Hash lookups

- Googleでhashを検索する（意外と有効）。
- [https://crackstation.net/](https://crackstation.net/)
- [https://md5decrypt.net/](https://md5decrypt.net/)
- [https://hashes.org/search.php](https://hashes.org/search.php)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com/)
- [https://gpuhash.me/](https://gpuhash.me/)
- [http://hashtoolkit.com/reverse-hash](http://hashtoolkit.com/reverse-hash)

### Identification helpers

- CyberChef (magic, decode, convert): https://gchq.github.io/CyberChef/
- dCode (ciphers/encodings playground): https://www.dcode.fr/tools-list
- Boxentriq (substitution solvers): https://www.boxentriq.com/code-breaking

### Practice platforms / references

- CryptoHack (hands-on crypto challenges): https://cryptohack.org/
- Cryptopals (classic modern crypto pitfalls): https://cryptopals.com/

### Automated decoding

- Ciphey: https://github.com/Ciphey/Ciphey
- python-codext (tries many bases/encodings): https://github.com/dhondta/python-codext

## Encodings & classical ciphers

### Technique

多くのCTFのcryptoタスクはレイヤー化された変換です: base encoding + simple substitution + compression。目的はレイヤーを識別し、安全に剥がすことです。

### Encodings: try many bases

レイヤードなエンコーディング（base64 → base32 → …）が疑われる場合は、次を試してください:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

一般的な特徴:

- Base64: `A-Za-z0-9+/=` （パディング `=` がよく見られる）
- Base32: `A-Z2-7=` （しばしば大量の `=` パディング）
- Ascii85/Base85: 句読点が密集；時に `<~ ~>` でラップされる

### Substitution / monoalphabetic

- Boxentriq cryptogram solver: https://www.boxentriq.com/code-breaking/cryptogram
- quipqiup: https://quipqiup.com/

### Caesar / ROT / Atbash

- Nayuki auto breaker: https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript
- Atbash: http://rumkin.com/tools/cipher/atbash.php

### Vigenère

- [https://www.dcode.fr/vigenere-cipher](https://www.dcode.fr/vigenere-cipher)
- [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)

### Bacon cipher

Often appears as groups of 5 bits or 5 letters:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### ルーン

ルーンはしばしば置換アルファベットです; search for "futhark cipher" and try mapping tables.

## チャレンジでの圧縮

### 手法

圧縮はしばしば追加レイヤーとして現れます（zlib/deflate/gzip/xz/zstd）、時にネストしています。出力がほぼ解析できるがゴミに見える場合は、圧縮を疑ってください。

### 簡易判別

- `file <blob>`
- Look for magic bytes:
- gzip: `1f 8b`
- zlib: often `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef has **Raw Deflate/Raw Inflate**, which is often the fastest path when the blob looks compressed but `zlib` fails.

### 便利なCLI
```bash
python3 - <<'PY'
import sys, zlib
data = sys.stdin.buffer.read()
for wbits in [zlib.MAX_WBITS, -zlib.MAX_WBITS]:
try:
print(zlib.decompress(data, wbits=wbits)[:200])
except Exception:
pass
PY
```
## 一般的なCTFの暗号構成

### 手法

これらは現実的な開発者のミスや一般的なライブラリの誤用で頻出します。目的は通常、認識して既知の抽出や再構築のワークフローを適用することです。

### Fernet

典型的なヒント：二つのBase64文字列（token + key）。

- Decoder/notes: https://asecuritysite.com/encryption/ferdecode
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

複数のsharesを見て、threshold `t` が言及されている場合、Shamirである可能性が高い。

- Online reconstructor (handy for CTFs): http://christian.gen.co/secrets/

### OpenSSL salted formats

CTFでは `openssl enc` の出力（ヘッダがしばしば `Salted__` で始まる）が与えられることがある。

Bruteforce helpers:

- [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [https://github.com/carlospolop/easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)

### 一般的なツールセット

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## 推奨ローカルセットアップ

実践的なCTFスタック：

- Python + `pycryptodome`：対称プリミティブと迅速なプロトタイピング用
- SageMath：剰余演算、CRT、格子、RSA/ECC に関する作業に
- Z3：制約ベースのチャレンジ向け（cryptoが制約に帰着する場合）

推奨Pythonパッケージ：
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
