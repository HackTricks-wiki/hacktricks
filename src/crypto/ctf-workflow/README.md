# Crypto CTF 工作流

{{#include ../../banners/hacktricks-training.md}}

## 分诊清单

1. 识别你拿到的是什么：编码、加密、哈希、签名还是 MAC。
2. 确定哪些内容可控：明文/密文、IV/nonce、密钥、oracle（填充/错误/时序）、部分 leak。
3. 分类：对称加密（AES/CTR/GCM）、公钥加密（RSA/ECC）、哈希/MAC（SHA/MD5/HMAC）、古典密码（Vigenere/XOR）。
4. 优先尝试成功率最高的检查：解码各层、已知明文 XOR、nonce reuse、模式误用、oracle 行为。
5. 仅在必要时采用高级方法：格（LLL/Coppersmith）、SMT/Z3、侧信道。

## 在线资源与实用工具

当任务涉及识别和剥离各层，或需要快速验证某个假设时，这些资源很有用。

### 哈希查询

- 如果已知挑战哈希是合成或公开的，可搜索该哈希。
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- hashes.org 搜索。<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

不要将真实密码哈希或机密挑战材料提交给第三方查询服务。如果担心信息泄露、服务条款或竞赛规则，优先使用离线字典/规则攻击。

### 识别辅助工具

- CyberChef（Magic、解码和转换）。<sup>[[7]](#references)</sup>
- dCode（密码/编码实验工具）。<sup>[[8]](#references)</sup>
- Boxentriq（替换密码求解器）。<sup>[[9]](#references)</sup>

### 练习平台 / 参考资料

- CryptoHack（实战密码学挑战）。<sup>[[10]](#references)</sup>
- Cryptopals（经典现代密码学陷阱）。<sup>[[11]](#references)</sup>

### 自动解码

- Ciphey。<sup>[[12]](#references)</sup>
- python-codext（尝试多种进制/编码）。<sup>[[13]](#references)</sup>

## 编码与古典密码

### 技术

许多 CTF 密码题使用多层变换：Base 编码 + 简单替换 + 压缩。目标是识别各层并安全地逐层剥离。

### 编码：尝试多种进制

如果怀疑存在多层编码（base64 → base32 → …），可以尝试：

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

常见特征：

- Base64：`A-Za-z0-9+/=`（常见填充符 `=`）
- Base32：`A-Z2-7=`（通常有很多 `=` 填充符）
- Ascii85/Base85：标点符号密集；有时会用 `<~ ~>` 包裹

### 替换密码 / 单表替换

- Boxentriq cryptogram solver。<sup>[[9]](#references)</sup>
- quipqiup。<sup>[[14]](#references)</sup>

#### 利用已知明文恢复经替换的 Base32 文件名

如果混淆后的文件名只包含 `a-z2-7`，去掉固定后缀后长度约为 `ceil(8 * byte_length / 5)` 个字符，并且相同明文在不同文件中会产生相同输出，可以尝试**无填充 Base32 后接固定符号替换**。这些线索本身不能作为证明。收集可预测的文件名及其密文，保留大小写，对每个明文进行 Base32 编码，并逐位对齐符号。每个重复的明文符号都必须映射到同一个密文符号，反向映射也必须唯一。在一个 ransomware 案例中，`ntuser.ini` 和 `NTUSER.DAT` 提供了这样的配对；由此恢复的是文件名，**不是文件内容或加密密钥**。<sup>[[28]](#references)</sup>

```python
import base64
pairs = [("ntuser.ini", "zsub5mdlekr37dx4"), ("NTUSER.DAT", "4s5l5tul5kr6kv5t")]
forward, inverse = {}, {}
for name, ciphertext in pairs:
    b32 = base64.b32encode(name.encode("ascii")).decode().lower().rstrip("=")
    assert len(b32) == len(ciphertext)
    for p, c in zip(b32, ciphertext):
        assert forward.get(p, c) == c and inverse.get(c, p) == p
        forward[p], inverse[c] = c, p
target = "4s5l5tul5kr6kv5t"  # Remove the fixed suffix first
b32 = "".join(inverse[c] for c in target)
clear = base64.b32decode(b32.upper() + "=" * (-len(b32) % 8))
assert "".join(forward[c] for c in b32) == target
print(clear.decode("ascii"))
```

如果目标包含未映射的符号，请获取更多已知对，或仅对未使用的 Base32 符号映射进行置换。将填充恢复到八字符边界，拒绝无效的 Base32 和不可打印的解码名称，然后重新编码剩余候选项，并与**整个**原始 ciphertext 进行比较。重复的 ciphertext 块可以提供更多猜测：在上面的例子中，`3gpng2wv` 映射回 Base32 `gaydambq`，解码后得到五个 ASCII 零字符。仅有一个可打印的候选项并不能构成唯一证明。<sup>[[28]](#references)</sup>

### Caesar / ROT / Atbash

- Nayuki 自动 Caesar-cipher 破解工具。<sup>[[15]](#references)</sup>
- Rumkin Atbash 工具。<sup>[[16]](#references)</sup>

### Vigenère

- dCode Vigenère 工具。<sup>[[8]](#references)</sup>
- Guballa Vigenère 求解器。<sup>[[17]](#references)</sup>

### Bacon cipher

通常以 5 位或 5 个字母为一组出现：

```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```

### Morse

```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```

### 卢恩符文

卢恩符文经常是替换字母表；搜索“futhark cipher”，并尝试映射表。

## 挑战中的压缩

### 技巧

压缩经常作为额外一层出现（zlib/deflate/gzip/xz/zstd），有时还会嵌套。如果输出看起来几乎能解析，却又像乱码，就要怀疑是压缩数据。

### 快速识别

- `file <blob>`
- 查找 magic bytes：
  - gzip: `1f 8b`
  - zlib: 常见值为 `78 01`、`78 5e`、`78 9c` 或 `78 da`（第二个字节取决于压缩标志）
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef 提供 **Raw Deflate/Raw Inflate**；当数据看起来经过压缩，但 `zlib` 解码失败时，这通常是最快的解决方法。

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

这些情况经常出现，因为它们源于真实的开发者错误，或常见库的误用。目标通常是识别问题，并应用已知的提取或重建流程。

### Fernet

典型提示：两个 Base64 字符串（token + key）。

- 解码器/说明：Asecuritysite Fernet 解码器。<sup>[[18]](#references)</sup>
- 在 Python 中：`from cryptography.fernet import Fernet`

### Shamir Secret Sharing

如果看到多个 share，且提到了阈值 `t`，很可能是 Shamir。

- 在线重建工具（仅适用于非敏感的 CTF shares）。<sup>[[19]](#references)</sup>

### OpenSSL 加盐格式

CTF 有时会提供 `openssl enc` 的输出（header 通常以 `Salted__` 开头）。

暴力破解辅助工具：

- `bruteforce-salted-openssl`。<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`。<sup>[[21]](#references)</sup>

### 通用工具集

- RsaCtfTool。<sup>[[22]](#references)</sup>
- featherduster。<sup>[[23]](#references)</sup>
- cryptovenom。<sup>[[24]](#references)</sup>

## 推荐的本地环境

实用的 CTF 工具栈：

- Python 加上 `pycryptodome`，用于对称密码原语和快速原型开发。<sup>[[25]](#references)</sup>
- SageMath，用于模运算、CRT、格，以及 RSA/ECC 相关工作。<sup>[[26]](#references)</sup>
- Z3，用于基于约束的挑战（当 crypto 问题可以归约为约束时）。<sup>[[27]](#references)</sup>

推荐的 Python 软件包：

```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [hashes.org 搜索](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [dCode 工具](https://www.dcode.fr/tools-list)
- [9] [Boxentriq 破译工具](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - 自动 Caesar cipher 破译工具](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - Atbash cipher](https://rumkin.com/tools/cipher/atbash/)
- [17] [Guballa Vigenère 求解器](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - Fernet 解码器](https://asecuritysite.com/encryption/ferdecode)
- [19] [Shamir secret-sharing 重构工具](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [PyCryptodome 文档](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
- [28] [Eye Research – 轻松破解加密方案](https://labs.eye.security/breaking-encryption-schemes-the-lazy-way/)
