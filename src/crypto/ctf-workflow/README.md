# Crypto CTF Workflow

{{#include ../../banners/hacktricks-training.md}}

## Triage checklist

1. 识别你拥有的内容：encoding、encryption、hash、signature 还是 MAC。
2. 确定受控内容：plaintext/ciphertext、IV/nonce、key、oracle（padding/error/timing）或部分泄漏。
3. 分类：symmetric（AES/CTR/GCM）、public-key（RSA/ECC）、hash/MAC（SHA/MD5/HMAC）、classical（Vigenere/XOR）。
4. 首先应用成功概率最高的检查：解码各层、已知明文 XOR、nonce 重用、mode 误用、oracle 行为。
5. 仅在必要时升级到高级方法：lattices（LLL/Coppersmith）、SMT/Z3、side-channels。

## Online resources & utilities

当任务是识别和剥离各层，或需要快速确认某个假设时，这些工具很有用。

### Hash lookups

- 当已知 challenge hash 为 synthetic/public 时，搜索它。
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- hashes.org search.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

不要将真实的 password hashes 或机密的 challenge 材料提交给第三方 lookup 服务。如果担心信息披露、terms of service 或比赛规则，优先使用离线 wordlist/rule attack。

### Identification helpers

- CyberChef（Magic、解码和转换）。<sup>[[7]](#references)</sup>
- dCode（cipher/encoding playground）。<sup>[[8]](#references)</sup>
- Boxentriq（substitution solvers）。<sup>[[9]](#references)</sup>

### Practice platforms / references

- CryptoHack（实战 cryptography challenges）。<sup>[[10]](#references)</sup>
- Cryptopals（classic modern-cryptography pitfalls）。<sup>[[11]](#references)</sup>

### Automated decoding

- Ciphey。<sup>[[12]](#references)</sup>
- python-codext（尝试多种 bases/encodings）。<sup>[[13]](#references)</sup>

## Encodings & classical ciphers

### Technique

许多 CTF crypto 任务都是分层变换：base encoding + simple substitution + compression。目标是识别各层，并安全地逐层剥离。

### Encodings: try many bases

如果你怀疑存在分层 encoding（base64 → base32 → …），可以尝试：

- CyberChef "Magic"
- `codext`（python-codext）：`codext <string>`

常见特征：

- Base64：`A-Za-z0-9+/=`（padding `=` 很常见）
- Base32：`A-Z2-7=`（通常有大量 `=` padding）
- Ascii85/Base85：标点符号密集；有时会包裹在 `<~ ~>` 中

### Substitution / monoalphabetic

- Boxentriq cryptogram solver。<sup>[[9]](#references)</sup>
- quipqiup。<sup>[[14]](#references)</sup>

### Caesar / ROT / Atbash

- Nayuki automatic Caesar-cipher breaker。<sup>[[15]](#references)</sup>
- Rumkin Atbash tool。<sup>[[16]](#references)</sup>

### Vigenère

- dCode Vigenère tool。<sup>[[8]](#references)</sup>
- Guballa Vigenère solver。<sup>[[17]](#references)</sup>

### Bacon cipher

通常以 5 个 bits 或 5 个字母为一组出现：
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### 符文

Runes 通常是 substitution alphabets；搜索 "futhark cipher" 并尝试使用 mapping tables。

## 挑战中的 Compression

### Technique

Compression 经常作为额外层出现（zlib/deflate/gzip/xz/zstd），有时还会嵌套。如果输出几乎可以解析，但看起来像垃圾数据，请怀疑存在 Compression。

### 快速识别

- `file <blob>`
- 查找 magic bytes：
- gzip: `1f 8b`
- zlib: 通常为 `78 01`、`78 5e`、`78 9c` 或 `78 da`（第二个字节取决于 compression flags）
- zip: `50 4b 03 04`
- bzip2: `42 5a 68`（`BZh`）
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef 提供 **Raw Deflate/Raw Inflate**；当 blob 看起来经过 compression，但 `zlib` 失败时，这通常是最快的处理方式。

### 实用 CLI
```bash
python3 - blob.bin <<'PY'
import sys, zlib
data = open(sys.argv[1], 'rb').read()
for wbits in [zlib.MAX_WBITS, -zlib.MAX_WBITS]:
try:
print(zlib.decompress(data, wbits=wbits)[:200])
except Exception:
pass
PY
```
## 常见 CTF crypto 构造

### Technique

这些内容经常出现，因为它们通常源于真实的开发者错误，或是常见 library 的错误使用。目标通常是识别问题，并应用已知的提取或重构流程。

### Fernet

典型提示：两个 Base64 字符串（token + key）。

- Decoder/notes：Asecuritysite Fernet decoder。<sup>[[18]](#references)</sup>
- 在 Python 中：`from cryptography.fernet import Fernet`

### Shamir Secret Sharing

如果你看到多个 share，并且提到了阈值 `t`，那么很可能是 Shamir。

- Online reconstructor（仅用于非敏感的 CTF shares）。<sup>[[19]](#references)</sup>

### OpenSSL salted formats

CTF 有时会提供 `openssl enc` 输出（header 通常以 `Salted__` 开头）。

Bruteforce helpers：

- `bruteforce-salted-openssl`。<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`。<sup>[[21]](#references)</sup>

### 通用工具集

- RsaCtfTool。<sup>[[22]](#references)</sup>
- featherduster。<sup>[[23]](#references)</sup>
- cryptovenom。<sup>[[24]](#references)</sup>

## 推荐的本地设置

实用的 CTF stack：

- Python 加上 `pycryptodome`，用于 symmetric primitives 和快速 prototyping。<sup>[[25]](#references)</sup>
- SageMath，用于 modular arithmetic、CRT、lattices 以及 RSA/ECC 工作。<sup>[[26]](#references)</sup>
- Z3，用于基于约束的 challenges（当 crypto 可以归约为约束时）。<sup>[[27]](#references)</sup>

推荐的 Python packages：
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [hashes.org 搜索](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash 工具包](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [dCode 工具](https://www.dcode.fr/tools-list)
- [9] [Boxentriq 破译工具](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - Automatic Caesar cipher 破解工具](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - Atbash cipher](https://rumkin.com/tools/cipher/atbash/)
- [17] [Guballa Vigenère 求解器](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - Fernet 解码器](https://asecuritysite.com/encryption/ferdecode)
- [19] [Shamir secret-sharing 重构器](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [PyCryptodome 文档](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
{{#include ../../banners/hacktricks-training.md}}
