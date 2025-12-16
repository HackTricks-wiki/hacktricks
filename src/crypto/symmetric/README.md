# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## 在 CTFs 中要注意的事项

- **模式滥用**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: 不同的错误/时序差异会暴露 bad padding。
- **MAC confusion**: 在可变长度消息中使用 CBC-MAC，或 MAC-then-encrypt 的错误。
- **XOR everywhere**: stream ciphers 和自定义构造常常归结为与 keystream 的 XOR。

## AES 模式与误用

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks。这样会导致：

- Cut-and-paste / block reordering
- Block deletion（如果格式仍然有效）

如果你能控制 plaintext 并观察 ciphertext（或 cookies），尝试制造重复块（例如许多 `A`s）并寻找重复。

### CBC: Cipher Block Chaining

- CBC 是 **可篡改的**：翻转 `C[i-1]` 的比特会在 `P[i]` 中翻转可预测的比特。
- 如果系统区分有效 padding 与无效 padding，你可能遇到 **padding oracle**。

### CTR

CTR 将 AES 变为流密码：`C = P XOR keystream`。

如果 nonce/IV 在相同密钥下被重用：

- `C1 XOR C2 = P1 XOR P2`（经典 keystream 重用）
- 如果有 known plaintext，你可以恢复 keystream 并解密其他数据。

### GCM

GCM 在 nonce 重用下也会严重崩坏。如果相同的 key+nonce 被多次使用，通常会出现：

- 加密的 keystream 重用（像 CTR），当任一 plaintext 已知时可恢复明文。
- 失去完整性保证。取决于暴露内容（在相同 nonce 下的多个 message/tag 对），攻击者可能能够 forge tags。

操作性建议：

- 将 AEAD 中的 "nonce reuse" 视为严重漏洞。
- 如果你有多个在相同 nonce 下的 ciphertext，先检查 `C1 XOR C2 = P1 XOR P2` 这类关系。

### Tools

- CyberChef 用于快速实验: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` 用于脚本化

## ECB exploitation patterns

ECB (Electronic Code Book) 对每个块独立加密：

- equal plaintext blocks → equal ciphertext blocks
- this leaks 结构并允许 cut-and-paste 风格的攻击

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### 检测思路：token/cookie 模式

如果你多次登录并且 **总是得到相同的 cookie**，则 ciphertext 可能是确定性的（ECB 或固定 IV）。

如果你创建两个用户，具有几乎相同的 plaintext 布局（例如长的重复字符），并在相同偏移处看到重复的 ciphertext 块，则 ECB 是主要嫌疑。

### 利用模式

#### Removing entire blocks

如果 token 格式类似 `<username>|<password>` 且块边界对齐，你有时可以构造一个用户使 `admin` 块对齐，然后移除前面的块以获得有效的 `admin` token。

#### Moving blocks

如果后端容忍填充/额外空格（`admin` vs `admin    `），你可以：

- 对齐包含 `admin   ` 的块
- 将该 ciphertext 块交换/重用到另一个 token 中

## Padding Oracle

### 它是什么

在 CBC 模式中，如果服务器（直接或间接地）泄露解密后的 plaintext 是否具有 **valid PKCS#7 padding**，你通常可以：

- 在没有密钥的情况下 decrypt ciphertext
- encrypt 选定的 plaintext（forge ciphertext）

该 oracle 可以是：

- 一个特定的错误消息
- 不同的 HTTP 状态 / 响应大小
- 一个时序差异

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

- Block size is often `16` for AES.
- `-encoding 0` means Base64.
- Use `-error` if the oracle is a specific string.

### 为什么能行

CBC 解密计算 `P[i] = D(C[i]) XOR C[i-1]`。通过修改 `C[i-1]` 中的字节并观察填充是否有效，可以逐字节恢复 `P[i]`。

## CBC 中的位翻转

即使没有 padding oracle，CBC 也是可塑的。如果你能修改密文块并且应用将解密后的明文作为结构化数据使用（例如 `role=user`），你可以翻转特定位以改变下一块中选定位置的明文字节。

典型 CTF 模式：

- Token = `IV || C1 || C2 || ...`
- 你能控制 `C[i]` 中的字节
- 你针对 `P[i+1]` 中的明文字节，因为 `P[i+1] = D(C[i+1]) XOR C[i]`

这本身不是泄露机密的漏洞，但在缺乏完整性保护时常被用作权限提升的原语。

## CBC-MAC

CBC-MAC 仅在特定条件下安全（尤其是 **固定长度的消息** 和正确的域分离）。

### 经典的可变长度伪造模式

CBC-MAC 通常按如下方式计算：

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

如果你能为选择的消息获取 tag，通常可以利用 CBC 的链式特性在不知道密钥的情况下为拼接（或相关构造）伪造一个 tag。

这在对 username 或 role 使用 CBC-MAC 的 CTF cookie/token 中经常出现。

### 更安全的替代方案

- Use HMAC (SHA-256/512)
- Use CMAC (AES-CMAC) correctly
- Include message length / domain separation

## 流密码：XOR 和 RC4

### 思维模型

大多数流密码情形可简化为：

`ciphertext = plaintext XOR keystream`

因此：

- 如果你知道明文，就能恢复 keystream。
- 如果 keystream 被重用（相同 key+nonce），`C1 XOR C2 = P1 XOR P2`。

### 基于 XOR 的加密

如果你在位置 `i` 知道任一明文段，就可以恢复 keystream 字节并解密那些位置上的其它密文。

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 是流密码；加密/解密是相同的操作。

如果你能在相同密钥下获得已知明文的 RC4 加密，你可以恢复 keystream 并解密其它相同长度/偏移的消息。

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
