# 加密/压缩 算法

{{#include ../../banners/hacktricks-training.md}}

## 识别算法

如果你在代码中看到包含 **shift rights and lefts, xors and several arithmetic operations** 的操作，则很可能是在实现一个 **cryptographic algorithm**。这里将展示一些方法，来在不需要逆向每一步的情况下识别所使用的算法。

### API 函数

**CryptDeriveKey**

如果使用此函数，你可以通过检查第二个参数的值来确定正在使用的 **algorithm**：

![](<../../images/image (156).png>)

在此查看可能的算法及其分配值的表： [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

压缩和解压给定的数据缓冲区。

**CryptAcquireContext**

From [the docs](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta)：CryptAcquireContext 函数用于获取特定 cryptographic service provider (CSP) 中某个 key container 的句柄。该返回句柄用于调用使用所选 CSP 的 CryptoAPI 函数。

**CryptCreateHash**

启动对数据流的哈希。如果使用此函数，你可以通过检查第二个参数的值来确定正在使用的 **algorithm**：

![](<../../images/image (549).png>)

\
在此查看可能的算法及其分配值的表： [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### 代码常量

有时可以很容易识别算法，因为它需要使用某个特殊且唯一的值。

![](<../../images/image (833).png>)

如果你用 Google 搜索第一个常量，会得到如下结果：

![](<../../images/image (529).png>)

因此，你可以认为反编译得到的函数是一个 **sha256** 计算器。\
你也可以搜索其它常量，通常会得到相同的结果。

### 数据信息

如果代码没有明显的常量，可能是在从 .data 段加载信息。\
你可以访问那些数据，组合第一个 dword 并像前面章节那样在 Google 上搜索它：

![](<../../images/image (531).png>)

在此例中，搜索 **0xA56363C6** 会发现它与 **AES** 算法的 tables 有关。

## RC4 **(对称加密)**

### 特点

它由 3 个主要部分组成：

- **Initialization stage/**：创建一个值表，从 0x00 到 0xFF（共 256 字节，0x100）。该表通常称为 **Substitution Box**（或 SBox）。
- **Scrambling stage**：会遍历之前创建的表（0x100 次循环），用半随机字节修改每个值。为了生成这些半随机字节，会使用 RC4 的 **密钥**。RC4 密钥长度可以在 1 到 256 字节之间，但通常建议大于 5 字节。常见的 RC4 密钥为 16 字节。
- **XOR stage**：最后，明文或密文会与之前生成的值进行 XOR。加密和解密使用相同的函数。为此会对生成的 256 字节进行循环，执行所需次数。通常在反编译代码中可通过 **%256 (mod 256)** 识别。

> [!TIP]
> **要在反汇编/反编译代码中识别 RC4，可以检查是否有两个大小为 0x100 的循环（使用密钥），然后将输入数据与在这两个循环中生成的 256 个值进行 XOR，通常会使用 %256 (mod 256)。**

### **Initialization stage/Substitution Box:** (注意作为计数器使用的数字 256 以及在每个位置写入 0 的操作)

![](<../../images/image (584).png>)

### **Scrambling Stage:**

![](<../../images/image (835).png>)

### **XOR Stage:**

![](<../../images/image (904).png>)

## AES (对称加密)

### 特点

- 使用替代盒（substitution boxes）和查找表（lookup tables）
- 可以通过使用特定查找表值（常量）来区分 AES。注意这些 **常量**可以被存储在二进制中，也可以**动态**生成。
- **加密密钥**长度必须能被 **16** 整除（通常为 32B），并且通常使用 16B 的 **IV**。

### SBox 常量

![](<../../images/image (208).png>)

## Serpent **(对称加密)**

### 特点

- 在恶意软件中较少见，但存在使用案例（Ursnif）
- 可基于其长度（极长的函数）简单判断是否为 Serpent

### 识别方法

在下图中注意常量 **0x9E3779B9** 的使用（注意该常量也被其它 crypto 算法使用，如 **TEA** - Tiny Encryption Algorithm）。\
还要注意循环大小（**132**）以及在反汇编指令和代码示例中的 XOR 操作次数：

![](<../../images/image (547).png>)

如前所述，该代码在任何反编译器中都会显示为一个 **非常长的函数**，因为内部没有跳转。反编译代码可能如下所示：

![](<../../images/image (513).png>)

因此，可以通过检查 **magic number** 和初始 **XORs**、观察 **非常长的函数** 并将该长函数的某些 **指令** 与已知实现（比如左移 7 和左循环移位 22）进行比较来识别该算法。

## RSA **(非对称加密)**

### 特点

- 比对称算法更复杂
- 没有常量！（自定义实现难以判断）
- KANAL（一个 crypto analyzer）在 RSA 上无法提供提示，因为它依赖常量。

### 通过比较来识别

![](<../../images/image (1113).png>)

- 在左侧第 11 行有 `+7) >> 3`，与右侧第 35 行的 `+7) / 8` 相同
- 左侧第 12 行检查 `modulus_len < 0x040`，右侧第 36 行检查 `inputLen+11 > modulusLen`

## MD5 & SHA（哈希）

### 特点

- 3 个函数：Init, Update, Final
- 初始化函数相似

### 识别

**Init**

可以通过检查常量来识别两者。注意 sha_init 有一个 MD5 没有的常量：

![](<../../images/image (406).png>)

**MD5 Transform**

注意使用了更多常量

![](<../../images/image (253) (1) (1).png>)

## CRC（哈希）

- 更小、更高效，其功能是检测数据的意外变化
- 使用查找表（因此可以识别出常量）

### 识别

检查 **查找表常量**：

![](<../../images/image (508).png>)

CRC 哈希算法看起来像：

![](<../../images/image (391).png>)

## APLib（压缩）

### 特点

- 没有明显可识别的常量
- 可以尝试用 python 实现该算法并在线搜索相似实现

### 识别

图表相当大：

![](<../../images/image (207) (2) (1).png>)

检查用于识别它的 **3 个比较点**：

![](<../../images/image (430).png>)

## 椭圆曲线签名实现漏洞

### EdDSA 标量范围强制（HashEdDSA 可变性）

- FIPS 186-5 §7.8.2 要求 HashEdDSA 验证者将签名拆分为 `sig = R || s` 并拒绝任何满足 `s \geq n` 的标量，其中 `n` 是群阶。`elliptic` JS 库跳过了该边界检查，因此任何知道有效对 `(msg, R || s)` 的攻击者都可以伪造替代签名 `s' = s + k·n` 并不断重新编码 `sig' = R || s'`。
- 验证例程只使用 `s mod n`，因此所有与 `s` 同余的 `s'` 都会被接受，即使它们是不同的字节串。将签名视为规范令牌的系统（blockchain consensus、replay caches、DB keys 等）可能因此不同步，因为严格的实现会拒绝 `s'`。
- 在审计其它 HashEdDSA 代码时，确保解析器同时验证点 `R` 和标量长度；尝试在已知良好的 `s` 后追加 `n` 的倍数，以确认验证器会安全地拒绝（fails closed）。

### ECDSA 截断与前导零哈希

- ECDSA 验证者必须仅使用消息哈希 `H` 的最左侧 `log2(n)` 位。在 `elliptic` 中，截断辅助函数计算 `delta = (BN(msg).byteLength()*8) - bitlen(n)`；`BN` 构造函数会丢弃前导的零字节，因此在像 secp192r1（192-bit order）这类曲线上，任何以 ≥4 个零字节开头的哈希会被误判为只有 224 位而非 256 位。
- 验证器向右移位了 32 位而不是 64 位，导致生成的 `E` 与签名者使用的值不匹配。因此对这些哈希的有效签名在 SHA-256 输入情况下以约 `2^-32` 的概率失败。
- 将“全部正常”的向量和前导零变体（例如 Wycheproof `ecdsa_secp192r1_sha256_test.json` case `tc296`）提供给目标实现；如果验证器与签名者的结果不一致，则你发现了可利用的截断漏洞。

### 使用 Wycheproof 向量测试库
- Wycheproof 提供了编码畸形点、可变标量、异常哈希和其他边界情况的 JSON 测试集。围绕 `elliptic`（或任何 crypto 库）构建测试 harness 很简单：加载 JSON，反序列化每个测试用例，并断言实现与期望的 `result` 标志一致。
```javascript
for (const tc of ecdsaVectors.testGroups) {
const curve = new EC(tc.curve);
const pub = curve.keyFromPublic(tc.key, 'hex');
const ok = curve.verify(tc.msg, tc.sig, pub, 'hex', tc.msgSize);
assert.strictEqual(ok, tc.result === 'valid');
}
```
- 应对失败进行分级以区分规范违规与误报。对于上面提到的两个 bug，失败的 Wycheproof cases 立即指向了缺失的标量范围检查 (EdDSA) 和不正确的哈希截断 (ECDSA)。
- 将测试 harness 集成到 CI 中，以便在引入对标量解析、哈希处理或坐标有效性的回归时立即触发测试。对于 JS、Python、Go 等高级语言尤其有用，因为微妙的大整数转换很容易出错。

## 参考资料

- [Trail of Bits - We found cryptography bugs in the elliptic library using Wycheproof](https://blog.trailofbits.com/2025/11/18/we-found-cryptography-bugs-in-the-elliptic-library-using-wycheproof/)
- [Wycheproof Test Suite](https://github.com/C2SP/wycheproof)

{{#include ../../banners/hacktricks-training.md}}
