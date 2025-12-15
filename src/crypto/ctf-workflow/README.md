# Crypto CTF ワークフロー

{{#include ../../banners/hacktricks-training.md}}

## トリアージチェックリスト

1. 持っているものを識別する: encoding vs encryption vs hash vs signature vs MAC.
2. 制御されているものを特定する: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. 分類する: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. 最も可能性の高いチェックを先に行う: decode layers, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior.
5. 必要な場合にのみ高度な手法にエスカレーションする: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## オンラインリソース & ユーティリティ

これらは、タスクが識別やレイヤー剥離のとき、または仮説を素早く確認したいときに有用です。

### Hash lookups

- Google the hash (驚くほど効果的).
- https://crackstation.net/
- https://md5decrypt.net/
- https://hashes.org/search.php
- https://www.onlinehashcrack.com/
- https://gpuhash.me/
- http://hashtoolkit.com/reverse-hash

### 識別ヘルパー

- CyberChef (magic, decode, convert): https://gchq.github.io/CyberChef/
- dCode (ciphers/encodings playground): https://www.dcode.fr/tools-list
- Boxentriq (substitution solvers): https://www.boxentriq.com/code-breaking

### 練習プラットフォーム / 参考

- CryptoHack (hands-on crypto challenges): https://cryptohack.org/
- Cryptopals (classic modern crypto pitfalls): https://cryptopals.com/

### Automated decoding

- Ciphey: https://github.com/Ciphey/Ciphey
- python-codext (tries many bases/encodings): https://github.com/dhondta/python-codext

## Encodings & classical ciphers

### Technique

多くの CTF crypto タスクはレイヤー化された変換（base encoding + simple substitution + compression）です。目標はレイヤーを識別して安全に剥がすことです。

### Encodings: try many bases

layered encoding を疑う場合（base64 → base32 → …）、次を試す:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

一般的な特徴:

- Base64: `A-Za-z0-9+/=` (padding `=` が一般的)
- Base32: `A-Z2-7=` (しばしば多くの `=` padding)
- Ascii85/Base85: dense punctuation; sometimes wrapped in `<~ ~>`

### Substitution / monoalphabetic

- Boxentriq cryptogram solver: https://www.boxentriq.com/code-breaking/cryptogram
- quipqiup: https://quipqiup.com/

### Caesar / ROT / Atbash

- Nayuki auto breaker: https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript
- Atbash: http://rumkin.com/tools/cipher/atbash.php

### Vigenère

- https://www.dcode.fr/vigenere-cipher
- https://www.guballa.de/vigenere-solver

### Bacon cipher

しばしば5ビットまたは5文字のグループとして現れる:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### ルーン

ルーンはしばしば置換アルファベットです。 "futhark cipher" を検索してマッピング表を試してください。

## チャレンジでの圧縮

### テクニック

圧縮は追加のレイヤーとして常に出現します（zlib/deflate/gzip/xz/zstd）、時にはネストされています。出力がほとんど解析できるがゴミに見える場合は、圧縮を疑ってください。

### クイック識別

- `file <blob>`
- マジックバイトを確認する:
- gzip: `1f 8b`
- zlib: often `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef has **Raw Deflate/Raw Inflate**, which is often the fastest path when the blob looks compressed but `zlib` fails.

### 便利な CLI
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
## 一般的な CTF の暗号構成

### 手法

これらは現実的な開発者のミスやライブラリの誤使用で頻出します。目的は通常、認識して既知の抽出・再構築ワークフローを適用することです。

### Fernet

典型的なヒント: 二つの Base64 strings (token + key)。

- Decoder/notes: https://asecuritysite.com/encryption/ferdecode
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

複数の shares を見て閾値 `t` が言及されている場合、それは Shamir である可能性が高いです。

- Online reconstructor (handy for CTFs): http://christian.gen.co/secrets/

### OpenSSL salted formats

CTF では時々 `openssl enc` の出力（ヘッダはしばしば `Salted__` で始まる）が与えられます。

Bruteforce helpers:

- https://github.com/glv2/bruteforce-salted-openssl
- https://github.com/carlospolop/easy_BFopensslCTF

### 一般的なツールセット

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## 推奨ローカル構成

実用的なCTFスタック:

- Python + `pycryptodome` は対称プリミティブと迅速なプロトタイピングに便利
- SageMath は modular arithmetic、CRT、lattices、そして RSA/ECC の作業向け
- Z3 は制約ベースのチャレンジ向け（crypto が制約に帰着する場合）

Suggested Python packages:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
