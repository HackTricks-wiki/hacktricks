# Crypto CTF Workflow

{{#include ../../banners/hacktricks-training.md}}

## Triage checklist

1. 保有しているものを特定する: encoding、encryption、hash、signature、MAC のどれか。
2. 何が制御可能かを判断する: plaintext/ciphertext、IV/nonce、key、oracle (padding/error/timing)、部分的な漏洩。
3. 分類する: symmetric (AES/CTR/GCM)、public-key (RSA/ECC)、hash/MAC (SHA/MD5/HMAC)、classical (Vigenere/XOR)。
4. 可能性の高いチェックから適用する: decode layers、known-plaintext XOR、nonce reuse、mode misuse、oracle behavior。
5. 必要な場合にのみ advanced methods へ進む: lattices (LLL/Coppersmith)、SMT/Z3、side-channels。

## Online resources & utilities

task が identification と layer peeling の場合、または仮説を素早く確認する必要がある場合に役立つ。

### Hash lookups

- hash を Google で検索する (意外に効果的)。
- [https://crackstation.net/](https://crackstation.net/)
- [https://md5decrypt.net/](https://md5decrypt.net/)
- [https://hashes.org/search.php](https://hashes.org/search.php)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com/)
- [https://gpuhash.me/](https://gpuhash.me/)
- [http://hashtoolkit.com/reverse-hash](http://hashtoolkit.com/reverse-hash)

### Identification helpers

- CyberChef (magic、decode、convert): https://gchq.github.io/CyberChef/
- dCode (ciphers/encodings playground): https://www.dcode.fr/tools-list
- Boxentriq (substitution solvers): https://www.boxentriq.com/code-breaking

### Practice platforms / references

- CryptoHack (hands-on crypto challenges): https://cryptohack.org/
- Cryptopals (classic modern crypto pitfalls): https://cryptopals.com/

### Automated decoding

- Ciphey: https://github.com/Ciphey/Ciphey
- python-codext (many bases/encodings を試行): https://github.com/dhondta/python-codext

## Encodings & classical ciphers

### Technique

多くの CTF crypto task は、base encoding + simple substitution + compression のような layered transforms である。目的は layer を特定し、安全に peel すること。

### Encodings: try many bases

layered encoding (base64 → base32 → …) が疑われる場合は、以下を試す:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Common tells:

- Base64: `A-Za-z0-9+/=` (padding `=` が一般的)
- Base32: `A-Z2-7=` (大量の `=` padding が含まれることが多い)
- Ascii85/Base85: punctuation が密集している。`<~ ~>` で囲まれる場合もある

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

5 bits または 5 letters のグループとして現れることが多い:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### ルーン

Runes は頻繁に substitution alphabets です。「futhark cipher」を検索し、mapping tables を試してください。

## Challenges における圧縮

### Technique

Compression は追加レイヤーとして常に登場します（zlib/deflate/gzip/xz/zstd）。場合によっては nested になっています。出力がほぼ parse できるものの garbage のように見える場合は、compression を疑ってください。

### Quick identification

- `file <blob>`
- magic bytes を探します：
- gzip: `1f 8b`
- zlib: 多くの場合 `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef には **Raw Deflate/Raw Inflate** があり、blob が compressed に見えるものの `zlib` が失敗する場合に、多くの場合最短の方法です。

### Useful CLI
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
## 一般的な CTF crypto constructs

### Technique

これらは、現実的な開発者のミスや、一般的な library の誤った使用に起因するため、頻繁に登場します。通常の目的は、これらを認識し、既知の抽出または再構築 workflow を適用することです。

### Fernet

典型的なヒント: 2 つの Base64 strings（token + key）。

- Decoder/notes: https://asecuritysite.com/encryption/ferdecode
- Python では: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

複数の share があり、threshold `t` が言及されている場合は、Shamir である可能性が高いです。

- Online reconstructor（CTF に便利）: http://christian.gen.co/secrets/

### OpenSSL salted formats

CTF では、`openssl enc` の出力（header は通常 `Salted__` で始まる）が与えられることがあります。

Bruteforce helpers:

- [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [https://github.com/carlospolop/easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)

### General toolset

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## 推奨される local setup

実用的な CTF stack:

- Python + `pycryptodome`: symmetric primitives と高速な prototyping 用
- SageMath: modular arithmetic、CRT、lattices、RSA/ECC work 用
- Z3: constraint-based challenges 用（crypto が constraints に帰着する場合）

Suggested Python packages:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
