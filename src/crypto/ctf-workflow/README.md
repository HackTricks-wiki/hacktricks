# Crypto CTF Workflow

{{#include ../../banners/hacktricks-training.md}}

## 初步排查清单

1. 识别手上是什么：encoding vs encryption vs hash vs signature vs MAC。
2. 确定哪些是受控的：plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage。
3. 分类：symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR)。
4. 优先应用命中概率最高的检查：decode layers, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior。
5. 仅在必要时升级到高级方法：lattices (LLL/Coppersmith), SMT/Z3, side-channels。

## 在线资源与工具

这些在任务为识别和剥离层次，或需要快速验证假设时非常有用。

### Hash lookups

- 用 Google 搜索 hash（出奇地有效）。
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

许多 CTF crypto 题目是分层变换：base encoding + simple substitution + compression。目标是识别各层并安全地剥离它们。

### Encodings: try many bases

如果怀疑是分层编码（base64 → base32 → …），尝试：

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

常见特征：

- Base64: `A-Za-z0-9+/=` (padding `=` is common)
- Base32: `A-Z2-7=` (often lots of `=` padding)
- Ascii85/Base85: dense punctuation; sometimes wrapped in `<~ ~>`

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
### 符文

符文通常是替代字母表；搜索 "futhark cipher" 并尝试映射表。

## 挑战中的压缩

### 技术

压缩经常作为额外层出现（zlib/deflate/gzip/xz/zstd），有时是嵌套的。如果输出几乎可以解析但看起来像垃圾，就怀疑是压缩。

### Quick identification

- `file <blob>`
- Look for magic bytes:
- gzip: `1f 8b`
- zlib: 通常 `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef 有 **Raw Deflate/Raw Inflate**，当 blob 看起来被压缩但 `zlib` 失败时，这通常是最快的路径。

### 有用的 CLI
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
## 常见 CTF crypto 构造

### Technique

这些常见出现，因为它们是现实中的开发者错误或常用库被错误使用。目标通常是识别并应用已知的提取或重构工作流。

### Fernet

典型提示：两个 Base64 字符串（token + key）。

- Decoder/notes: https://asecuritysite.com/encryption/ferdecode
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

如果你看到多个份额并且提到了阈值 `t`，很可能是 Shamir。

- Online reconstructor (handy for CTFs): http://christian.gen.co/secrets/

### OpenSSL salted formats

CTF 题目有时会给出 `openssl enc` 输出（header 通常以 `Salted__` 开头）。

Bruteforce helpers:

- [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [https://github.com/carlospolop/easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)

### General toolset

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Recommended local setup

Practical CTF stack:

- Python + `pycryptodome` 用于对称原语和快速原型开发
- SageMath 用于模运算、CRT、格以及 RSA/ECC 相关工作
- Z3 用于基于约束的题目（当密码学问题化为约束时）

Suggested Python packages:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
