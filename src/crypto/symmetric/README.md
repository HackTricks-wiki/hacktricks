# 对称加密

{{#include ../../banners/hacktricks-training.md}}

## 在 CTF 中要注意什么

- **Mode misuse**: ECB patterns、CBC 可篡改性、CTR/GCM nonce 重用。
- **Padding oracles**: 错误信息/计时在错误 padding 时不同。
- **MAC confusion**: 使用 CBC-MAC 处理可变长度消息，或 MAC-then-encrypt 的错误使用。
- **XOR everywhere**: 流密码和自定义构造通常归结为与密钥流的 XOR。

## AES modes and misuse

### ECB: Electronic Codebook

ECB leaks patterns：相同的明文块 → 相同的密文块。 这会导致：

- Cut-and-paste / block reordering
- Block deletion（如果格式仍然有效）

如果你能控制明文并观察密文（或 cookies），尝试制造重复块（例如，多个 `A`s）并寻找重复。

### CBC: Cipher Block Chaining

- CBC 是 **malleable**：翻转 `C[i-1]` 中的位会可预测地翻转 `P[i]` 中的位。
- 如果系统暴露了有效的 padding 与无效 padding 之间的差异，你可能有一个 **padding oracle**。

### CTR

CTR 将 AES 变为流密码：`C = P XOR keystream`。

如果同一 key 重用了 nonce/IV：

- `C1 XOR C2 = P1 XOR P2`（经典的密钥流重用）
- 在已知明文的情况下，你可以恢复密钥流并解密其他密文。

**Nonce/IV reuse exploitation patterns**

- 在已知/可猜测明文的位置恢复密钥流：

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

将恢复的密钥流字节应用于解密任何在相同 key+IV 且相同偏移处产生的其他密文。
- 高度结构化的数据（例如 ASN.1/X.509 证书、文件头、JSON/CBOR）提供了大量已知明文区域。你通常可以将证书的密文与可预测的证书主体 XOR 来导出密钥流，然后解密在重用 IV 下加密的其他秘密。参见 [TLS & Certificates](../tls-and-certificates/README.md) 了解典型证书布局。
- 当多个同一序列化格式/大小的秘密在相同的 key+IV 下被加密时，即使没有完整的已知明文，字段对齐也会泄露信息。例如：相同模数大小的 PKCS#8 RSA 密钥会将素因子放在匹配的偏移处（对于 2048-bit，约 99.6% 的对齐）。对两个在重用密钥流下的密文做 XOR 会隔离出 `p ⊕ p'` / `q ⊕ q'`，可以在几秒内暴力恢复。
- 库中的默认 IV（例如常量 `000...01`）是一个严重的陷阱：每次加密都会重复相同的密钥流，从而把 CTR 变成重用的一次性填充。

**CTR 可篡改性**

- CTR 只提供机密性：在密文中翻转位会决定性地翻转明文中的相同位。没有认证标签的情况下，攻击者能在不被检测的情形下篡改数据（例如，修改密钥、标志或消息）。
- 使用 AEAD（GCM, GCM-SIV, ChaCha20-Poly1305 等）并强制验证 tag 以检测位翻转。

### GCM

GCM 在 nonce 重用下也会严重出问题。如果相同的 key+nonce 被多次使用，通常会出现：

- 加密时的密钥流重用（像 CTR），当任一明文已知时可导致明文恢复。
- 完整性保证丧失。依赖于暴露的内容（在相同 nonce 下的多个 message/tag 对），攻击者可能能够伪造 tag。

操作性建议：

- 将 AEAD 中的 “nonce reuse” 当作严重漏洞处理。
- 抗误用的 AEAD（例如 GCM-SIV）能减少 nonce 重用的后果，但仍然需要唯一的 nonces/IVs。
- 如果你有多个在相同 nonce 下的密文，先检查 `C1 XOR C2 = P1 XOR P2` 类关系。

### 工具

- CyberChef 用于快速试验：https://gchq.github.io/CyberChef/
- Python: `pycryptodome` 用于脚本化

## ECB exploitation patterns

ECB (Electronic Code Book) 独立地加密每个块：

- 相同的明文块 → 相同的密文块
- 这会泄露结构并使得 cut-and-paste 风格的攻击成为可能

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### 检测思路：token/cookie 模式

如果你多次登录并且**总是收到相同的 cookie**，密文可能是确定性的（ECB 或固定 IV）。

如果你创建两个具有大致相同明文布局的用户（例如，大量重复字符），并在相同偏移处看到重复的密文块，ECB 是首要嫌疑。

### 利用模式

#### Removing entire blocks

如果 token 格式像 `<username>|<password>` 且块边界对齐，你有时可以制作一个用户使 `admin` 块对齐，然后删除前面的块以得到一个有效的 `admin` token。

#### Moving blocks

如果后端能容忍 padding/额外空格（`admin` vs `admin    `），你可以：

- 对齐包含 `admin   ` 的一个块
- 在另一个 token 中交换/重用该密文块

## Padding Oracle

### 它是什么

在 CBC 模式中，如果服务器（直接或间接）透露解密后的明文是否具有 **有效的 PKCS#7 padding**，你通常可以：

- 在没有密钥的情况下解密密文
- 加密所选明文（伪造密文）

Oracle 可以是：

- 特定的错误信息
- 不同的 HTTP 状态 / 响应大小
- 计时差异

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

- 块大小通常为 `16`（AES）。
- `-encoding 0` 表示 Base64。
- 如果 oracle 返回特定字符串，则使用 `-error`。

### 原理

CBC 解密计算 `P[i] = D(C[i]) XOR C[i-1]`。通过修改 `C[i-1]` 中的字节并观察填充是否有效，可以逐字节恢复 `P[i]`。

## Bit-flipping in CBC

即使没有 padding oracle，CBC 是 malleable 的。如果你可以修改密文块，并且应用将解密后的明文作为结构化数据使用（例如 `role=user`），你可以翻转特定位来改变下一块中选定位置的明文字节。

典型的 CTF 模式：

- Token = `IV || C1 || C2 || ...`
- 你控制 `C[i]` 中的字节
- 你针对 `P[i+1]` 中的明文字节，因为 `P[i+1] = D(C[i+1]) XOR C[i]`

这本身不是对保密性的破坏，但在缺乏完整性保护时，它是常见的权限升级原语。

## CBC-MAC

CBC-MAC 仅在特定条件下安全（尤其是 **固定长度消息** 和正确的域分离）。

### Classic variable-length forgery pattern

CBC-MAC 通常按如下计算：

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

如果你能为选定消息获取 tag，就可以利用 CBC 的链式结构，在不知道密钥的情况下为连接消息（或相关构造）伪造 tag。

这经常出现在使用 CBC-MAC 为 username 或 role 做 MAC 的 CTF cookie/token 中。

### Safer alternatives

- 使用 HMAC (SHA-256/512)
- 正确使用 CMAC (AES-CMAC)
- 包含消息长度 / 域分离

## Stream ciphers: XOR and RC4

### 思维模型

大多数 stream cipher 场景都归结为：

`ciphertext = plaintext XOR keystream`

因此：

- 如果你知道 plaintext，你就能恢复 keystream。
- 如果 keystream 被重用（相同 key+nonce），`C1 XOR C2 = P1 XOR P2`。

### XOR-based encryption

如果你知道位置 `i` 的任意 plaintext 段，你可以恢复 keystream 字节并解密其他在该位置的密文。

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 是流密码；加密和解密是相同的操作。

如果你能在相同 key 下获得已知 plaintext 的 RC4 加密，你可以恢复 keystream 并解密其他具有相同长度/偏移的消息。

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
