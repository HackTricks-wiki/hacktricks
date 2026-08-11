# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## 在 CTFs 中需要关注的内容

- **Mode misuse**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: bad padding 导致的不同错误/时序。
- **MAC confusion**: 使用可变长度消息的 CBC-MAC，或 MAC-then-encrypt 错误。
- **XOR everywhere**: stream ciphers 和自定义构造通常都会归结为使用 keystream 进行 XOR。

## AES modes 和误用

NIST 在 SP 800-38A 中规定了 ECB、CBC 和 CTR confidentiality modes，并在 SP 800-38D 中规定了 GCM authenticated encryption。<sup>[[2]](#references)[[3]](#references)</sup>

### ECB: Electronic Codebook

ECB 会 leak patterns：相同的 plaintext blocks → 相同的 ciphertext blocks。这会导致：

- Cut-and-paste / block reordering
- Block deletion（如果格式仍然有效）

如果你可以控制 plaintext 并观察 ciphertext（或 cookies），尝试构造重复 blocks（例如大量 `A`），并查找重复内容。

### CBC: Cipher Block Chaining

- CBC 是 **malleable** 的：翻转 `C[i-1]` 中的 bits 会翻转 `P[i]` 中可预测的 bits，同时破坏 `P[i-1]`。修改 IV 可以针对第一个 plaintext block，而不会破坏更早的 plaintext block。
- 如果系统会区分 valid padding 和 invalid padding，你可能拥有一个 **padding oracle**。

### CTR

CTR 会将 AES 转换为 stream cipher：`C = P XOR keystream`。

如果相同的 key 重用了 nonce/IV：

- `C1 XOR C2 = P1 XOR P2`（经典的 keystream reuse）
- 如果已知 plaintext，你可以恢复 keystream 并解密其他内容。

**Nonce/IV reuse exploitation patterns**

- 在 plaintext 已知或可猜测的位置恢复 keystream：

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

将恢复出的 keystream bytes 应用于解密使用相同 key+IV、且 offsets 相同而生成的其他 ciphertext。
- 高度结构化的数据（例如 ASN.1/X.509 certificates、file headers、JSON/CBOR）会提供大段 known-plaintext 区域。你通常可以将 certificate 的 ciphertext 与可预测的 certificate body 进行 XOR 来推导 keystream，然后解密使用复用 IV 加密的其他 secrets。另请参阅 [TLS & Certificates](../tls-and-certificates/README.md)，了解典型的 certificate layouts。<sup>[[1]](#references)</sup>
- 当多个相同 **serialized format/size** 的 secrets 使用相同 key+IV 加密时，即使没有完整的 known plaintext，field alignment 也会 leak。例如：相同 modulus size 的 PKCS#8 RSA keys 会将 prime factors 放置在匹配的 offsets（对于 2048-bit，alignment 约为 99.6%）。对复用 keystream 下的两个 ciphertext 进行 XOR，可以分离出 `p ⊕ p'` / `q ⊕ q'`，并在几秒内通过 brute-force 恢复。<sup>[[1]](#references)</sup>
- libraries 中的默认 IV（例如固定的 `000...01`）是一个严重的 footgun：每次 encryption 都会重复使用相同的 keystream，使 CTR 变成 reused one-time pad。<sup>[[1]](#references)</sup>

**CTR malleability**

- CTR 仅提供 confidentiality：翻转 ciphertext 中的 bits 会确定性地翻转 plaintext 中相同的 bits。没有 authentication tag 时，攻击者可以篡改数据（例如修改 keys、flags 或 messages），且不会被检测到。
- 使用 AEAD（GCM、GCM-SIV、ChaCha20-Poly1305 等），并强制执行 tag verification 以捕获 bit-flips。

### GCM

GCM 在 nonce reuse 下同样会严重失效。如果相同的 key+nonce 被使用多次，通常会导致：

- Encryption 时发生 keystream reuse（类似 CTR），当任意 plaintext 已知时即可恢复 plaintext。
- Integrity guarantees 丧失。根据暴露的内容（相同 nonce 下的多个 message/tag pairs），攻击者可能能够 forge tags。

Operational guidance：

- 将 AEAD 中的 "nonce reuse" 视为 critical vulnerability。
- Misuse-resistant AEADs，例如 AES-GCM-SIV，可以减少 nonce-reuse 的影响。调用者仍应按照该 construction 的 interface 要求提供 unique nonces；与普通 GCM 相比，意外复用的后果是有界的。<sup>[[3]](#references)[[4]](#references)</sup>
- 如果你拥有相同 nonce 下的多个 ciphertext，首先检查 `C1 XOR C2 = P1 XOR P2` 形式的 relations。

### Tools

- [CyberChef](https://gchq.github.io/CyberChef/) 用于快速实验。<sup>[[8]](#references)</sup>
- Python 的 [PyCryptodome](https://www.pycryptodome.org/) package 用于 scripting。<sup>[[9]](#references)</sup>

## ECB exploitation patterns

ECB（Electronic Code Book）会独立加密每个 block：

- 相同的 plaintext blocks → 相同的 ciphertext blocks
- 这会 leak structure，并支持 cut-and-paste 风格的 attacks

![ECB mode decryption block diagram](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

如果你多次 login 且**每次都得到相同的 cookie**，ciphertext 可能是 deterministic 的（ECB 或 fixed IV）。

如果你创建两个 plaintext layouts 基本相同的 users（例如包含较长的重复字符），并发现相同 offsets 处出现重复的 ciphertext blocks，那么 ECB 是首要怀疑对象。

### Exploitation patterns

#### Removing entire blocks

如果 token format 类似 `<username>|<password>`，且 block boundary 对齐，你有时可以构造一个 user，使 `admin` block 对齐，然后移除前面的 blocks，从而获得一个对 `admin` 有效的 token。

#### Moving blocks

如果 backend 容忍 padding/extra spaces（`admin` 与 `admin    `），你可以：

- 对齐一个包含 `admin   ` 的 block
- 将该 ciphertext block 交换/复用到另一个 token 中

## Padding Oracle

### What it is

在 CBC mode 中，如果 server 直接或间接地透露 decrypted plaintext 是否具有**有效的 PKCS#7 padding**，你通常可以：<sup>[[7]](#references)</sup>

- 在没有 key 的情况下解密 ciphertext
- 当你可以提交 crafted preceding blocks 或 IV，且 application 接受由此产生的 validly padded message 时，构造一个会解密为 chosen plaintext 的 ciphertext

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
注意：

- AES 的 block size 通常为 `16`。
- `-encoding 0` 表示 Base64。
- 如果 oracle 返回的是特定字符串，请使用 `-error`。

### 原理

CBC 解密计算 `P[i] = D(C[i]) XOR C[i-1]`。通过修改 `C[i-1]` 中的字节并观察 padding 是否有效，可以逐字节恢复 `P[i]`。

## CBC 中的 Bit-flipping

即使没有 padding oracle，CBC 仍然具有可塑性。如果你可以修改 ciphertext blocks，且应用程序将解密后的 plaintext 用作结构化数据（例如 `role=user`），就可以翻转特定位的 bits，从而改变下一个 block 中指定位置的 plaintext bytes。

典型的 CTF 模式：

- Token = `IV || C1 || C2 || ...`
- 你可以控制 `C[i]` 中的 bytes
- 目标是 `P[i+1]` 中的 plaintext bytes，因为 `P[i+1] = D(C[i+1]) XOR C[i]`

这本身并不是对 confidentiality 的破解，但在缺少 integrity 时，它是常见的 privilege-escalation primitive。

## CBC-MAC

CBC-MAC 只有在特定条件下才是 secure 的（尤其是 **fixed-length messages** 以及正确的 domain separation）。AES-CMAC 是一种 standardized construction，可以安全处理 variable-length inputs。<sup>[[5]](#references)</sup>

### Classic variable-length forgery pattern

CBC-MAC 通常计算如下：

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

如果你可以获取 chosen messages 的 tags，通常可以利用 CBC 链式连接 blocks 的方式，在不知道 key 的情况下，为 concatenation（或相关 construction）构造 tag。

这经常出现在使用 CBC-MAC 对 username 或 role 进行 MAC 的 CTF cookies/tokens 中。

### 更安全的替代方案

- 使用 HMAC（SHA-256/512）
- 正确使用 CMAC（AES-CMAC）
- 包含 message length / domain separation

## Stream ciphers：XOR 和 RC4

### 思维模型

大多数 stream cipher 场景都可以归结为：

`ciphertext = plaintext XOR keystream`

因此：

- 如果你知道 plaintext，就可以恢复 keystream。
- 如果 keystream 被复用（相同的 key+nonce），则 `C1 XOR C2 = P1 XOR P2`。

### 基于 XOR 的 encryption

如果你知道位置 `i` 上的任意 plaintext segment，就可以恢复 keystream bytes，并在相同位置解密其他 ciphertext。

Autosolvers：

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 是一种 legacy stream cipher；encrypt/decrypt 使用相同的 XOR operation。其已知 biases 使其不适合新系统，TLS 也明确禁止其 cipher suites。<sup>[[6]](#references)</sup>

如果你可以获取相同 key 下对已知 plaintext 执行 RC4 encryption 的结果，就可以恢复 keystream，并解密相同 length/offset 的其他 messages。

Reference writeup（HTB Kryptos）：

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – 加密中的粗心与工艺](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)
- [2] [NIST SP 800-38A - Block Cipher Modes of Operation 建议](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [3] [NIST SP 800-38D - Galois/Counter Mode (GCM) 和 GMAC 建议](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [4] [RFC 8452 - AES-GCM-SIV：抗 Nonce 误用的 Authenticated Encryption](https://www.rfc-editor.org/rfc/rfc8452)
- [5] [RFC 4493 - AES-CMAC Algorithm](https://www.rfc-editor.org/rfc/rfc4493)
- [6] [RFC 7465 - Prohibiting RC4 Cipher Suites](https://www.rfc-editor.org/rfc/rfc7465)
- [7] [OWASP Web Security Testing Guide - Testing for Padding Oracle](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [8] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [9] [PyCryptodome documentation](https://www.pycryptodome.org/)
{{#include ../../banners/hacktricks-training.md}}
