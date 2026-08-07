# 对称加密

{{#include ../../banners/hacktricks-training.md}}

## 在 CTF 中需要关注的内容

- **模式误用**：ECB patterns、CBC malleability、CTR/GCM nonce reuse。
- **Padding oracles**：错误 padding 时出现不同的错误信息/响应时间。
- **MAC 混淆**：对可变长度消息使用 CBC-MAC，或犯下 MAC-then-encrypt 错误。
- **到处都是 XOR**：stream ciphers 和自定义构造通常最终都会简化为与 keystream 进行 XOR。

## AES 模式及其误用

### ECB：Electronic Codebook

ECB 会 leak patterns：相同的明文块 → 相同的密文块。这可以实现：

- Cut-and-paste / block reordering
- Block deletion（如果格式仍然有效）

如果你可以控制明文并观察密文（或 cookies），可以尝试构造重复的块（例如大量 `A`），然后查找重复内容。

### CBC：Cipher Block Chaining

- CBC 具有 **malleable** 特性：翻转 `C[i-1]` 中的位，会翻转 `P[i]` 中可预测的位。
- 如果系统会区分 valid padding 与 invalid padding，你可能拥有一个 **padding oracle**。

### CTR

CTR 会将 AES 转换为 stream cipher：`C = P XOR keystream`。

如果相同的 key 重用了 nonce/IV：

- `C1 XOR C2 = P1 XOR P2`（经典的 keystream reuse）
- 如果已知明文，就可以恢复 keystream 并解密其他内容。

**Nonce/IV reuse exploitation patterns**

- 在明文已知或可猜测的位置恢复 keystream：

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

将恢复出的 keystream 字节应用到使用相同 key+IV、且偏移相同的其他 ciphertext 上，即可解密。
- 具有高度结构化的数据（例如 ASN.1/X.509 certificates、file headers、JSON/CBOR）会提供大段已知明文区域。通常可以将 certificate 的 ciphertext 与可预测的 certificate body 进行 XOR，从而推导出 keystream，然后解密使用重复 IV 加密的其他 secrets。另请参阅 [TLS & Certificates](../tls-and-certificates/README.md)，了解典型的 certificate layouts。<sup>[[1]](#references)</sup>
- 当多个相同 serialized format/size 的 secrets 使用相同 key+IV 加密时，即使没有完整的已知明文，field alignment 也会 leak。示例：相同 modulus size 的 PKCS#8 RSA keys 会将 prime factors 放在匹配的偏移位置（对于 2048-bit，alignment 约为 99.6%）。对重复 keystream 下的两个 ciphertext 进行 XOR，可以分离出 `p ⊕ p'` / `q ⊕ q'`，并在几秒内通过 brute-force recovery。<sup>[[1]](#references)</sup>
- 库中的默认 IV（例如固定的 `000...01`）是一个严重的 footgun：每次加密都会重复使用相同的 keystream，使 CTR 变成重复使用的 one-time pad。<sup>[[1]](#references)</sup>

**CTR malleability**

- CTR 只提供机密性：翻转 ciphertext 中的位会确定性地翻转 plaintext 中对应的位。如果没有 authentication tag，攻击者可以在不被检测的情况下篡改数据（例如修改 keys、flags 或 messages）。
- 使用 AEAD（GCM、GCM-SIV、ChaCha20-Poly1305 等），并强制执行 tag verification，以检测 bit-flips。

### GCM

GCM 在 nonce reuse 的情况下同样会严重失效。如果相同的 key+nonce 被使用多次，通常会导致：

- 用于加密的 keystream reuse（类似 CTR），当任意明文已知时，可以恢复 plaintext。
- 完整性保证失效。根据暴露的信息（相同 nonce 下的多个 message/tag pairs），攻击者可能可以 forge tags。

操作建议：

- 将 AEAD 中的 "nonce reuse" 视为 critical vulnerability。
- Misuse-resistant AEAD（例如 GCM-SIV）可以降低 nonce-misuse 的影响，但仍然需要使用唯一的 nonces/IVs。
- 如果你拥有多个使用相同 nonce 的 ciphertexts，应首先检查 `C1 XOR C2 = P1 XOR P2` 形式的关系。

### Tools

- 用于快速实验的 CyberChef：https://gchq.github.io/CyberChef/
- Python：用于 scripting 的 `pycryptodome`

## ECB exploitation patterns

ECB（Electronic Code Book）会独立加密每个块：

- 相同的明文块 → 相同的密文块
- 这会 leak structure，并支持 cut-and-paste 风格的 attacks

![ECB mode decryption block diagram](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea：token/cookie pattern

如果你多次登录并且 **每次获得的 cookie 都相同**，则 ciphertext 可能是 deterministic 的（ECB 或 fixed IV）。

如果你创建两个 plaintext layouts 基本相同的 users（例如包含很长的重复字符），并发现相同偏移处出现重复的 ciphertext blocks，那么 ECB 是首要怀疑对象。

### Exploitation patterns

#### Removing entire blocks

如果 token format 类似 `<username>|<password>`，并且 block boundary 对齐，那么有时可以构造一个 user，使 `admin` block 出现在对齐位置，然后删除前面的 blocks，从而获得一个对 `admin` 有效的 token。

#### Moving blocks

如果 backend 可以容忍 padding/extra spaces（`admin` 与 `admin    `），你可以：

- 对齐一个包含 `admin   ` 的 block
- 将该 ciphertext block 交换/复用到另一个 token 中

## Padding Oracle

### What it is

在 CBC mode 中，如果 server 会直接或间接暴露解密后的 plaintext 是否具有 **valid PKCS#7 padding**，通常可以：

- 在没有 key 的情况下 decrypt ciphertext
- Encrypt chosen plaintext（forge ciphertext）

Oracle 可能表现为：

- 特定的 error message
- 不同的 HTTP status / response size
- timing difference

### Practical exploitation

PadBuster 是经典工具：

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Example:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
说明：

- Block size 通常为 `16`，用于 AES。
- `-encoding 0` 表示 Base64。
- 如果 oracle 返回的是特定字符串，请使用 `-error`。

### 工作原理

CBC 解密计算 `P[i] = D(C[i]) XOR C[i-1]`。通过修改 `C[i-1]` 中的字节，并观察 padding 是否有效，你可以逐字节恢复 `P[i]`。

## CBC 中的 Bit-flipping

即使没有 padding oracle，CBC 仍然具有可塑性。如果你可以修改 ciphertext blocks，并且应用程序将解密后的 plaintext 用作结构化数据（例如 `role=user`），就可以翻转特定位，以更改 next block 中指定位置的 plaintext 字节。

典型的 CTF 模式：

- Token = `IV || C1 || C2 || ...`
- 你可以控制 `C[i]` 中的字节
- 目标是修改 `P[i+1]` 中的 plaintext 字节，因为 `P[i+1] = D(C[i+1]) XOR C[i]`

这本身并不能破解 confidentiality，但在缺少 integrity 的情况下，它是常见的 privilege-escalation 原语。

## CBC-MAC

CBC-MAC 只有在特定条件下才安全（尤其是 **固定长度的消息** 和正确的 domain separation）。

### 经典的可变长度伪造模式

CBC-MAC 通常计算如下：

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

如果你可以获取 chosen messages 的 tags，通常就可以利用 CBC 链式连接 block 的方式，在不知道 key 的情况下，为拼接结果（或相关构造）构造 tag。

这种情况经常出现在使用 CBC-MAC 对 username 或 role 进行 MAC 的 CTF cookies/tokens 中。

### 更安全的替代方案

- 正确使用 HMAC (SHA-256/512)
- 正确使用 CMAC (AES-CMAC)
- 包含 message length / domain separation

## Stream ciphers：XOR 和 RC4

### 心智模型

大多数 stream cipher 场景都可以归结为：

`ciphertext = plaintext XOR keystream`

因此：

- 如果你知道 plaintext，就可以恢复 keystream。
- 如果 keystream 被复用（相同的 key+nonce），则 `C1 XOR C2 = P1 XOR P2`。

### 基于 XOR 的加密

如果你知道位置 `i` 处的任意 plaintext 片段，就可以恢复 keystream 字节，并使用这些字节解密其他 ciphertext 在相同位置的数据。

自动求解器：

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 是一种 stream cipher；加密和解密使用相同的操作。

如果你可以获取相同 key 下对已知 plaintext 执行 RC4 加密的结果，就可以恢复 keystream，并解密其他具有相同长度/offset 的消息。

参考 writeup（HTB Kryptos）：

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## 参考资料

- [1] [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
