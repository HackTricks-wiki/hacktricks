# 对称加密

{{#include ../../banners/hacktricks-training.md}}

## 在 CTF 中要注意什么

- **模式滥用**：ECB patterns、CBC malleability、CTR/GCM nonce reuse。
- **Padding oracles**：针对无效 padding 的不同错误/时间差异。
- **MAC 混淆**：在可变长度消息上使用 CBC-MAC，或 MAC-then-encrypt 的错误。
- **XOR everywhere**：stream ciphers 和自定义构造通常简化为与 keystream 的 XOR。

## AES 模式及滥用

### ECB: Electronic Codebook

ECB leaks patterns：相同的明文块 → 相同的密文块。 这会导致：

- 剪切-粘贴 / 块重排序
- 删除块（如果格式仍然有效）

如果你能控制明文并观察密文（或 cookies），尝试制造重复的块（例如，多个 `A`s）并查找重复。

### CBC: Cipher Block Chaining

- CBC 是可篡改的：在 `C[i-1]` 中翻转位会在 `P[i]` 中翻转可预测的位。
- 如果系统暴露了有效 padding 与无效 padding 的区别，你可能有一个 **padding oracle**。

### CTR

CTR 将 AES 变为流密码：`C = P XOR keystream`。

如果 nonce/IV 在相同密钥下被重用：

- `C1 XOR C2 = P1 XOR P2`（经典 keystream 重用）
- 已知明文时，你可以恢复 keystream 并解密其他消息。

### GCM

GCM 在 nonce 重用时也会严重失效。如果相同的 key+nonce 被多次使用，通常会出现：

- 用于加密的 keystream 重用（像 CTR），当有任一已知明文时可恢复明文。
- 完整性保证丧失。取决于暴露的内容（在相同 nonce 下的多个消息/tag 对），攻击者可能能够伪造 tags。

操作建议：

- 将 AEAD 中的 "nonce reuse" 视为严重漏洞。
- 如果你有多个在相同 nonce 下的密文，首先检查 `C1 XOR C2 = P1 XOR P2` 之类的关系。

### 工具

- CyberChef 用于快速试验： https://gchq.github.io/CyberChef/
- Python：用于脚本的 `pycryptodome`

## ECB 利用模式

ECB (Electronic Code Book) 对每个块分别加密：

- 相同的明文块 → 相同的密文块 - 这会 leaks 结构并启用剪切-粘贴式攻击

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### 检测思路：token/cookie 模式

如果你多次登录并且 **总是得到相同的 cookie**，则密文可能是确定性的（ECB 或 固定 IV）。

如果你创建两个具有大体相同明文布局的用户（例如，长的重复字符）并在相同偏移处看到重复的密文块，ECB 是主要嫌疑。

### 利用模式

#### 删除整个块

如果 token 格式类似 `<username>|<password>` 且块边界对齐，你有时可以构造一个用户使 `admin` 块对齐，然后移除前面的块以获得一个有效的 `admin` token。

#### 移动块

如果后端容忍 padding/额外空格（`admin` vs `admin    `），你可以：

- 使包含 `admin   ` 的块对齐
- 将该密文块替换/重用到另一个 token 中

## Padding Oracle

### 它是什么

在 CBC 模式下，如果服务器直接或间接地透露解密后的明文是否具有 **valid PKCS#7 padding**，你通常可以：

- 在不知道密钥的情况下解密密文
- 加密选择的明文（伪造密文）

该 oracle 可以是：

- 特定的错误信息
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

- Block size is often `16` for AES.
- `-encoding 0` means Base64.
- Use `-error` if the oracle is a specific string.

### 为什么它可行

CBC 解密计算 `P[i] = D(C[i]) XOR C[i-1]`。通过修改 `C[i-1]` 中的字节并观察 padding 是否有效，你可以按字节恢复 `P[i]`。

## CBC 中的 Bit-flipping

Even without a padding oracle, CBC is malleable. 如果你能修改 ciphertext blocks 并且应用将解密的 plaintext 作为结构化数据（例如 `role=user`），你可以翻转特定位以改变下一块中选定位置的 plaintext 字节。

典型 CTF 模式：

- Token = `IV || C1 || C2 || ...`
- You control bytes in `C[i]`
- You target plaintext bytes in `P[i+1]` because `P[i+1] = D(C[i+1]) XOR C[i]`

这本身不是对机密性的破坏，但当缺乏完整性保护时，它是常见的权限提升原语。

## CBC-MAC

CBC-MAC is secure only under specific conditions (notably **固定长度消息** and correct domain separation).

### Classic variable-length forgery pattern

CBC-MAC is usually computed as:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

If you can obtain tags for chosen messages, you can often craft a tag for a concatenation (or related construction) without knowing the key, by exploiting how CBC chains blocks.

This frequently appears in CTF cookies/tokens that MAC username or role with CBC-MAC.

### Safer alternatives

- Use HMAC (SHA-256/512)
- Use CMAC (AES-CMAC) correctly
- Include message length / domain separation

## Stream ciphers: XOR and RC4

### The mental model

Most stream cipher situations reduce to:

`ciphertext = plaintext XOR keystream`

So:

- If you know plaintext, you recover keystream.
- If keystream is reused (same key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

If you know any plaintext segment at position `i`, you can recover keystream bytes and decrypt other ciphertexts at those positions.

Autosolvers:

- https://wiremask.eu/tools/xor-cracker/

### RC4

RC4 is a stream cipher; encrypt/decrypt are the same operation.

If you can get RC4 encryption of known plaintext under the same key, you can recover the keystream and decrypt other messages of the same length/offset.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
