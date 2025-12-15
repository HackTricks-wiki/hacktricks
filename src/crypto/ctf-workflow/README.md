# Crypto CTF 工作流程

{{#include ../../banners/hacktricks-training.md}}

## 初步评估清单

1. 识别你面对的类型：encoding vs encryption vs hash vs signature vs MAC。
2. 确定哪些是受控的：plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage。
3. 分类：symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR)。
4. 优先应用概率最高的检查：decode layers, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior。
5. 仅在必要时升级到高级方法：lattices (LLL/Coppersmith), SMT/Z3, side-channels。

## 在线资源与工具

当任务是识别和逐层剥离，或需要快速验证某个假设时，这些资源很有用。

### Hash 查找

- 在 Google 上搜索 hash（出乎意料地有效）。
- https://crackstation.net/
- https://md5decrypt.net/
- https://hashes.org/search.php
- https://www.onlinehashcrack.com/
- https://gpuhash.me/
- http://hashtoolkit.com/reverse-hash

### 辅助识别工具

- CyberChef（多功能，解码，转换）：https://gchq.github.io/CyberChef/
- dCode（ciphers/encodings playground）：https://www.dcode.fr/tools-list
- Boxentriq（substitution solvers）：https://www.boxentriq.com/code-breaking

### 练习平台 / 参考

- CryptoHack（动手式 crypto 挑战）：https://cryptohack.org/
- Cryptopals（经典的现代 crypto 陷阱）：https://cryptopals.com/

### 自动解码

- Ciphey: https://github.com/Ciphey/Ciphey
- python-codext (tries many bases/encodings): https://github.com/dhondta/python-codext

## 编码与经典密码

### 技术

许多 CTF 的 crypto 题目是分层变换：base encoding + simple substitution + compression。目标是识别各层并安全地剥离它们。

### 编码：尝试多种 base

如果怀疑是分层编码（base64 → base32 → …），尝试：

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

常见标志：

- Base64: `A-Za-z0-9+/=`（填充 `=` 很常见）
- Base32: `A-Z2-7=`（通常有大量 `=` 填充）
- Ascii85/Base85: 标点密集；有时包裹在 `<~ ~>`

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

通常以每组 5 位或 5 个字母出现：
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### 莫尔斯电码
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### 符文

符文通常是替代字母表；搜索 "futhark cipher" 并尝试映射表。

## 挑战中的压缩

### 技巧

压缩经常作为额外的一层出现（zlib/deflate/gzip/xz/zstd），有时会嵌套。如果输出几乎可以解析但看起来像垃圾，怀疑是压缩。

### 快速识别

- `file <blob>`
- 查找 magic bytes:
- gzip: `1f 8b`
- zlib: often `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef has **Raw Deflate/Raw Inflate**, which is often the fastest path when the blob looks compressed but `zlib` fails.

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
## 常见 CTF 密码学构造

### 技巧

这些经常出现，因为它们通常是开发者的真实错误或常用库被错误使用。目标通常是识别问题并应用已知的提取或重建流程。

### Fernet

典型提示：两个 Base64 字符串（token + key）。

- 解码器/说明：https://asecuritysite.com/encryption/ferdecode
- 在 Python 中： `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

如果你看到多个 shares 并且提到阈值 `t`，很可能是 Shamir。

- 在线重构器（对 CTFs 很有用）：http://christian.gen.co/secrets/

### OpenSSL salted formats

CTFs 有时会给出 `openssl enc` 的输出（头部通常以 `Salted__` 开头）。

暴力破解辅助工具：

- https://github.com/glv2/bruteforce-salted-openssl
- https://github.com/carlospolop/easy_BFopensslCTF

### 通用工具集

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## 推荐的本地环境设置

实用 CTF 环境：

- Python + `pycryptodome` 用于对称原语和快速原型开发
- SageMath 用于模运算、CRT、格以及 RSA/ECC 工作
- Z3 用于基于约束的题目（当密码学问题归约为约束时）

推荐的 Python 包：
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
