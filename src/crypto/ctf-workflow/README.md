# Crypto CTF Workflow

{{#include ../../banners/hacktricks-training.md}}

## 分流检查清单

1. 确定你拥有的内容：encoding、encryption、hash、signature 还是 MAC。
2. 确定受控内容：plaintext/ciphertext、IV/nonce、key、oracle（padding/error/timing）或部分泄露。
3. 分类：对称加密（AES/CTR/GCM）、公钥加密（RSA/ECC）、hash/MAC（SHA/MD5/HMAC）或经典密码（Vigenere/XOR）。
4. 优先执行成功概率最高的检查：解码各层、已知明文 XOR、nonce 重用、模式误用、oracle 行为。
5. 仅在必要时升级到高级方法：lattices（LLL/Coppersmith）、SMT/Z3、side-channels。

## 在线资源与工具

当任务是识别和剥离编码层，或需要快速验证某个假设时，这些资源很有用。

### Hash 查询

- 在 Google 中搜索 hash（效果出奇地好）。
- [https://crackstation.net/](https://crackstation.net/)
- [https://md5decrypt.net/](https://md5decrypt.net/)
- [https://hashes.org/search.php](https://hashes.org/search.php)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com/)
- [https://gpuhash.me/](https://gpuhash.me/)
- [http://hashtoolkit.com/reverse-hash](http://hashtoolkit.com/reverse-hash)

### 识别辅助工具

- CyberChef（magic、decode、convert）：https://gchq.github.io/CyberChef/
- dCode（ciphers/encodings playground）：https://www.dcode.fr/tools-list
- Boxentriq（substitution solvers）：https://www.boxentriq.com/code-breaking

### 练习平台 / 参考资料

- CryptoHack（hands-on crypto challenges）：https://cryptohack.org/
- Cryptopals（经典的现代密码学陷阱）：https://cryptopals.com/

### 自动解码

- Ciphey：https://github.com/Ciphey/Ciphey
- python-codext（尝试多种 bases/encodings）：https://github.com/dhondta/python-codext

## Encodings 与经典密码

### Technique

许多 CTF crypto 任务都是分层变换：base encoding + simple substitution + compression。目标是识别各层，并安全地逐层剥离。

### Encodings：尝试多种 bases

如果你怀疑存在分层 encoding（base64 → base32 → …），可以尝试：

- CyberChef "Magic"
- `codext`（python-codext）：`codext <string>`

常见特征：

- Base64：`A-Za-z0-9+/=`（padding `=` 很常见）
- Base32：`A-Z2-7=`（通常有大量 `=` padding）
- Ascii85/Base85：标点符号密集；有时会包裹在 `<~ ~>` 中

### Substitution / monoalphabetic

- Boxentriq cryptogram solver：https://www.boxentriq.com/code-breaking/cryptogram
- quipqiup：https://quipqiup.com/

### Caesar / ROT / Atbash

- Nayuki auto breaker：https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript
- Atbash：http://rumkin.com/tools/cipher/atbash.php

### Vigenère

- [https://www.dcode.fr/vigenere-cipher](https://www.dcode.fr/vigenere-cipher)
- [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)

### Bacon cipher

通常以 5 bits 或 5 个字母为一组出现：
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### 摩尔斯
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### 符文

Runes 通常是 substitution alphabets；搜索 "futhark cipher" 并尝试使用 mapping tables。

## challenges 中的压缩

### 技术

Compression 经常作为额外一层出现（zlib/deflate/gzip/xz/zstd），有时还会嵌套。如果输出看起来几乎可以解析，但实际像垃圾数据，请怀疑存在 compression。

### 快速识别

- `file <blob>`
- 查找 magic bytes：
- gzip: `1f 8b`
- zlib: 通常为 `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68`（`BZh`）
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef 提供 **Raw Deflate/Raw Inflate**，当 blob 看起来经过 compression 但 `zlib` 失败时，这通常是最快的处理方式。

### 实用 CLI
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

这些内容经常出现，因为它们通常源于现实中的 developer 错误或对常见 libraries 的错误使用。目标通常是识别问题，并应用已知的提取或重构流程。

### Fernet

典型提示：两个 Base64 字符串（token + key）。

- Decoder/notes: https://asecuritysite.com/encryption/ferdecode
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

如果你看到多个 share，并且提到了 threshold `t`，那么很可能使用的是 Shamir。

- Online reconstructor（方便用于 CTF）：http://christian.gen.co/secrets/

### OpenSSL salted formats

CTF 有时会提供 `openssl enc` 输出（header 通常以 `Salted__` 开头）。

Bruteforce helpers：

- [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [https://github.com/carlospolop/easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)

### 通用工具集

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## 推荐的本地环境

实用的 CTF stack：

- Python + `pycryptodome`，用于 symmetric primitives 和快速 prototyping
- SageMath，用于 modular arithmetic、CRT、lattices 以及 RSA/ECC work
- Z3，用于基于 constraint 的 challenges（当 crypto 可归约为 constraints 时）

推荐的 Python packages：
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
