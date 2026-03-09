# 对称加密

{{#include ../../banners/hacktricks-training.md}}

## CTFs 中要注意的点

- **模式误用**: ECB patterns, CBC 可篡改性, CTR/GCM nonce 重用。
- **Padding oracles**: 对 bad padding 的不同错误/时间差异。
- **MAC confusion**: 在可变长度消息上使用 CBC-MAC，或 MAC-then-encrypt 的错误用法。
- **XOR everywhere**: stream ciphers 和自定义构造常常简化为与 keystream 的 XOR。

## AES 模式与误用

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks。 这会导致：

- 剪切粘贴 / 块重排
- 删除块（如果格式仍然有效）

如果你可以控制 plaintext 并观测 ciphertext（或 cookies），尝试制造重复块（例如很多 `A`s）并查找重复。

### CBC: Cipher Block Chaining

- CBC 是 **可篡改的**：翻转 `C[i-1]` 中的比特会翻转 `P[i]` 中可预测的比特。
- 如果系统区分 valid padding 与 invalid padding，你可能有一个 **padding oracle**。

### CTR

CTR 将 AES 变成一个 stream cipher：`C = P XOR keystream`。

如果 nonce/IV 在相同密钥下被重用：

- `C1 XOR C2 = P1 XOR P2` (经典的 keystream 重用)
- 有已知 plaintext 时，你可以恢复 keystream 并解密其他消息。

**Nonce/IV reuse exploitation patterns**

- 在已知/可猜测 plaintext 的地方恢复 keystream：

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

将恢复的 keystream 字节应用于在相同 key+IV 且相同偏移下产生的任何其他 ciphertext 的解密。
- 高度结构化的数据（例如 ASN.1/X.509 certificates、file headers、JSON/CBOR）提供大量已知-plaintext 区域。通常可以将证书的 ciphertext 与可预测的证书主体 XOR 来导出 keystream，然后解密在重用 IV 下加密的其他秘密。另见 [TLS & Certificates](../tls-and-certificates/README.md) 了解典型证书布局。
- 当多个秘密以**相同序列化格式/大小**在相同 key+IV 下加密时，即使没有完整的已知 plaintext，也会泄露字段对齐信息。示例：相同 modulus 大小的 PKCS#8 RSA keys 将素数因子放在匹配的偏移处（对于 2048-bit 约有 ~99.6% 的对齐）。在重用 keystream 下 XOR 两个 ciphertext 会隔离出 `p ⊕ p'` / `q ⊕ q'`，可以在几秒内被暴力恢复。
- 库中的默认 IV（例如常量 `000...01`）是一个严重的安全陷阱：每次加密都会重复相同的 keystream，使 CTR 退化为被重用的一次性填充。

**CTR malleability**

- CTR 仅提供机密性：翻转 ciphertext 中的比特会以确定性方式翻转 plaintext 中相同的比特。没有 authentication tag 时，攻击者可以在不被发现的情况下篡改数据（例如篡改 keys、flags 或消息）。
- 使用 AEAD（GCM、GCM-SIV、ChaCha20-Poly1305 等）并强制进行 tag 验证以检测比特翻转。

### GCM

GCM 在 nonce 重用下也会严重失效。如果相同的 key+nonce 被多次使用，通常会出现：

- 加密时 keystream 重用（类似 CTR），当任一 plaintext 已知时可恢复 plaintext。
- 丢失完整性保证。取决于暴露内容（在相同 nonce 下的多个 message/tag 对），攻击者可能能够伪造 tags。

操作建议：

- 将 AEAD 中的 “nonce reuse” 视为严重漏洞。
- 抗误用的 AEAD（例如 GCM-SIV）会减轻 nonce 误用的后果，但仍然要求唯一的 nonces/IVs。
- 如果你有在相同 nonce 下的多个 ciphertext，先检查 `C1 XOR C2 = P1 XOR P2` 类型的关系。

### 工具

- CyberChef 用于快速实验: https://gchq.github.io/CyberChef/
- Python：用于脚本的 `pycryptodome`

## ECB 利用模式

ECB (Electronic Code Book) 对每个 block 独立加密：

- equal plaintext blocks → equal ciphertext blocks
- this leaks structure and enables cut-and-paste style attacks

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### 检测思路：token/cookie 模式

如果你多次登录并且 **总是得到相同的 cookie**，ciphertext 可能是确定性的（ECB 或固定 IV）。

如果你创建两个用户且大部分 plaintext 布局相同（例如长的重复字符），并在相同偏移处看到重复的 ciphertext 块，ECB 是主要嫌疑。

### 利用模式

#### 删除整块

如果 token 格式类似 `<username>|<password>` 且块边界对齐，有时你可以构造一个用户使得包含 `admin` 的块对齐，然后删除前面的块以获得一个对 `admin` 有效的 token。

#### 移动块

如果后端容忍 padding/额外空格（`admin` vs `admin    `），你可以：

- 对齐包含 `admin   ` 的一个块
- 将该 ciphertext 块交换/重用到另一个 token 中

## Padding Oracle

### 它是什么

在 CBC 模式中，如果服务器暴露（直接或间接）解密后 plaintext 是否具有 **valid PKCS#7 padding**，你通常可以：

- 在没有密钥的情况下解密 ciphertext
- 加密选择的 plaintext（伪造 ciphertext）

Oracle 可以是：

- 特定的错误消息
- 不同的 HTTP 状态 / 响应大小
- 时间差异

### 实际利用

PadBuster 是经典工具：

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

示例：
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
注意：

- 块大小通常为 `16`（用于 AES）。
- `-encoding 0` 表示 Base64。
- 如果 oracle 是特定字符串，使用 `-error`。

### Why it works

CBC 解密计算 `P[i] = D(C[i]) XOR C[i-1]`。通过修改 `C[i-1]` 中的字节并观察 padding 是否有效，你可以逐字节恢复 `P[i]`。

## Bit-flipping in CBC

即使没有 padding oracle，CBC 也是可篡改的。如果你能够修改 ciphertext 块，并且应用将解密后的 plaintext 用作结构化数据（例如 `role=user`），你可以翻转特定位来改变下一块中选定位置的 plaintext 字节。

典型的 CTF 模式：

- Token = `IV || C1 || C2 || ...`
- 你控制 `C[i]` 中的字节
- 你针对 `P[i+1]` 中的 plaintext 字节，因为 `P[i+1] = D(C[i+1]) XOR C[i]`

这本身并不破坏机密性，但在缺乏完整性保护时，它是常见的 privilege-escalation 原语。

## CBC-MAC

CBC-MAC 只有在特定条件下才安全（尤其是 **fixed-length messages** 和正确的 domain separation）。

### Classic variable-length forgery pattern

CBC-MAC 通常这样计算：

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

如果你可以为选择的消息获得 tags，你通常可以通过利用 CBC 如何链式连接块，为一个串联（或相关构造）伪造一个 tag，而无需知道 key。

这经常出现在使用 CBC-MAC 为 username 或 role 生成 MAC 的 CTF cookies/tokens 中。

### Safer alternatives

- 使用 HMAC (SHA-256/512)
- 正确使用 CMAC (AES-CMAC)
- 包含 message length / domain separation

## Stream ciphers: XOR and RC4

### The mental model

大多数 stream cipher 情况都归结为：

`ciphertext = plaintext XOR keystream`

所以：

- 如果你知道 plaintext，你可以恢复 keystream。
- 如果 keystream 被重用（相同 key+nonce），`C1 XOR C2 = P1 XOR P2`。

### XOR-based encryption

如果你在位置 `i` 知道任意 plaintext 段，你可以恢复 keystream 字节并解密其他在相同位置的 ciphertexts。

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 是一种 stream cipher；加密/解密是相同的操作。

如果你能在相同 key 下获得已知 plaintext 的 RC4 加密，你可以恢复 keystream 并解密其他相同长度/偏移的消息。

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
