# 对称密码

{{#include ../../banners/hacktricks-training.md}}

## CTF 中需要关注的内容

- **模式误用**：ECB 模式特征、CBC 可塑性、CTR/GCM nonce 重用。
- **Padding oracle**：错误 padding 导致不同的错误信息或耗时。
- **MAC 混淆**：对可变长度消息使用 CBC-MAC，或 MAC-then-encrypt 错误。
- **到处都是 XOR**：流密码和自定义构造通常都可以归结为与密钥流进行 XOR。

## AES 模式及其误用

NIST 在 SP 800-38A 中规定了 ECB、CBC 和 CTR 保密模式，并在 SP 800-38D 中规定了 GCM 认证加密。<sup>[[2]](#references)[[3]](#references)</sup>

### ECB: Electronic Codebook

ECB 会泄露模式：相同的明文块 → 相同的密文块。这使得以下操作成为可能：

- 剪切粘贴 / 块重排
- 删除块（如果格式仍然有效）

如果你能控制明文并观察密文（或 cookie），可以尝试构造重复块（例如，输入大量 `A`），并观察是否出现重复内容。

### CBC: Cipher Block Chaining

- CBC 具有**可塑性**：翻转 `C[i-1]` 中的位会翻转 `P[i]` 中可预测的位，同时也会破坏 `P[i-1]`。修改 IV 可以针对第一个明文块进行操作，而不会破坏前面的明文块。
- 如果系统会区分有效 padding 和无效 padding，你可能会遇到 **padding oracle**。

### CTR

CTR 将 AES 转换为流密码：`C = P XOR keystream`。

如果 nonce/IV 在同一个密钥下被重复使用：

- `C1 XOR C2 = P1 XOR P2`（经典的密钥流重用）
- 如果已知明文，你可以恢复密钥流并解密其他内容。

**Nonce/IV 重用利用模式**

- 在明文已知或可猜测的范围内恢复密钥流：

  ```text
  keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
  ```

  将恢复出的密钥流字节应用于使用相同 key+IV、相同偏移生成的其他密文，即可解密这些密文。
- 高度结构化的数据（例如 ASN.1/X.509 证书、文件头、JSON/CBOR）会提供大量已知明文区域。通常可以将证书密文与可预测的证书正文进行 XOR 运算来推导密钥流，然后解密使用重复 IV 加密的其他秘密。另请参阅 [TLS & Certificates](../tls-and-certificates/README.md)，了解典型的证书布局。<sup>[[1]](#references)</sup>
- 如果多个**序列化格式和大小相同**的秘密使用相同的 key+IV 加密，即使没有完整的已知明文，字段对齐也会 leak 信息。例如，同一模数大小的 PKCS#8 RSA 密钥会在相同偏移处包含素因子（2048 位密钥的对齐率约为 99.6%）。对重复使用密钥流加密的两个密文进行 XOR 运算，可以分离出 `p ⊕ p'` / `q ⊕ q'`，并在几秒内通过暴力破解恢复它们。<sup>[[1]](#references)</sup>
- 库中的默认 IV（例如常量 `000...01`）是个严重的陷阱：每次加密都会重复使用相同的密钥流，使 CTR 变成重复使用的一次性密码本。<sup>[[1]](#references)</sup>

**CTR 可塑性**

- CTR 只提供机密性：翻转密文中的位会确定性地翻转明文中的相同位。没有认证标签时，攻击者可以篡改数据（例如修改密钥、标志或消息），而不被察觉。
- 使用 AEAD（GCM、GCM-SIV、ChaCha20-Poly1305 等），并强制验证标签以检测位翻转。

### GCM

GCM 在 nonce 重用时也会严重失效。如果同一 key+nonce 被使用多次，通常会导致：

- 加密时重复使用密钥流（类似 CTR），因此只要知道任意明文，就可以恢复明文。
- 完整性保证失效。根据暴露的信息（同一 nonce 下的多组消息/标签对），攻击者可能能够伪造标签。

操作建议：

- 将 AEAD 中的“nonce 重用”视为严重漏洞。
- AES-GCM-SIV 等抗误用 AEAD 可以降低 nonce 重用造成的影响。调用方仍应按照构造接口的要求提供唯一 nonce；与普通 GCM 相比，意外重用的后果是有限的。<sup>[[3]](#references)[[4]](#references)</sup>
- 如果有多个使用相同 nonce 的密文，先检查 `C1 XOR C2 = P1 XOR P2` 这类关系。

### 工具

- [CyberChef](https://gchq.github.io/CyberChef/) 可用于快速实验。<sup>[[8]](#references)</sup>
- Python 的 [PyCryptodome](https://www.pycryptodome.org/) 包可用于编写脚本。<sup>[[9]](#references)</sup>

## ECB 利用模式

ECB（Electronic Code Book）会独立加密每个块：

- 相同的明文块 → 相同的密文块
- 这会 leak 结构，并允许进行剪切粘贴式攻击

![ECB mode decryption block diagram](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### 检测思路：token/cookie 模式

如果你多次登录，**每次得到的 cookie 都相同**，那么密文可能是确定性的（ECB 或固定 IV）。

如果你创建两个明文布局基本相同的用户（例如包含大量重复字符），并发现相同偏移处有重复的密文块，那么 ECB 很可能就是原因。

### 利用模式

#### 移除整个块

如果 token 格式类似 `<username>|<password>`，且块边界对齐，有时可以构造一个用户，使 `admin` 块正好对齐，然后移除前面的块，从而获得一个有效的 `admin` token。

#### 移动块

如果后端容忍填充或额外空格（`admin` 与 `admin    `），你可以：

- 对齐包含 `admin   ` 的块
- 将该密文块交换或复用到另一个 token 中

## Padding Oracle

### 原理

在 CBC 模式下，如果服务器会直接或间接透露解密后的明文是否具有**有效的 PKCS#7 填充**，通常就可以：<sup>[[7]](#references)</sup>

- 不使用密钥解密密文
- 如果可以提交精心构造的前置块或 IV，且应用接受由此产生的有效填充消息，则构造一个解密为指定明文的密文

Oracle 可能表现为：

- 特定的错误消息
- 不同的 HTTP 状态码 / 响应大小
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

备注：

- AES 的块大小通常为 `16`。
- `-encoding 0` 表示 Base64。
- 如果 oracle 返回的是特定字符串，请使用 `-error`。

### 原理

CBC 解密会计算 `P[i] = D(C[i]) XOR C[i-1]`。通过修改 `C[i-1]` 中的字节，并观察填充是否有效，你可以逐字节恢复 `P[i]`。

## Bit-flipping in CBC

即使没有 padding oracle，CBC 仍具有可塑性。如果你能修改密文块，且应用程序会将解密后的明文用作结构化数据（例如 `role=user`），就可以翻转特定位，在下一块的指定位置更改明文字节。

典型的 CTF 模式：

- Token = `IV || C1 || C2 || ...`
- 你可以控制 `C[i]` 中的字节
- 目标是 `P[i+1]` 中的明文字节，因为 `P[i+1] = D(C[i+1]) XOR C[i]`

这本身并不代表机密性被破解，但在缺少完整性保护时，它是常见的权限提升原语。

## CBC-MAC

CBC-MAC 仅在特定条件下安全（尤其是**消息长度固定**且正确进行域分离）。AES-CMAC 是一种标准化构造，可安全处理可变长度输入。<sup>[[5]](#references)</sup>

### 经典的可变长度伪造模式

CBC-MAC 通常按如下方式计算：

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

如果你能获取所选消息的 tag，通常就可以利用 CBC 链式分组的方式，在不知道密钥的情况下为拼接内容（或相关构造）伪造 tag。

这种情况常见于使用 CBC-MAC 对用户名或角色进行 MAC 处理的 CTF cookies/tokens。

### 更安全的替代方案

- 使用 HMAC (SHA-256/512)
- 正确使用 CMAC (AES-CMAC)
- 加入消息长度 / 域分离

## 流密码：XOR 和 RC4

### 思维模型

大多数流密码场景都可以归结为：

`ciphertext = plaintext XOR keystream`

因此：

- 如果你知道明文，就能恢复 keystream。
- 如果 keystream 被重复使用（相同的密钥+nonce），则 `C1 XOR C2 = P1 XOR P2`。

### 基于 XOR 的加密

如果你知道位置 `i` 处的任意一段明文，就能恢复 keystream 字节，并解密其他密文在相同位置上的内容。

自动求解工具：

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 是一种旧式流密码；加密和解密都是相同的 XOR 操作。其已知偏差使它不适用于新系统，而且 TLS 明确禁止使用其密码套件。<sup>[[6]](#references)</sup>

如果你能获取同一密钥下已知明文的 RC4 加密结果，就能恢复 keystream，并解密长度和偏移量相同的其他消息。

参考 writeup（HTB Kryptos）：

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – 密码学中的粗心与精湛技艺](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)
- [2] [NIST SP 800-38A - 分组密码工作模式建议](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [3] [NIST SP 800-38D - Galois/Counter Mode (GCM) 和 GMAC 建议](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [4] [RFC 8452 - AES-GCM-SIV：抗 nonce 误用的认证加密](https://www.rfc-editor.org/rfc/rfc8452)
- [5] [RFC 4493 - AES-CMAC 算法](https://www.rfc-editor.org/rfc/rfc4493)
- [6] [RFC 7465 - 禁止使用 RC4 密码套件](https://www.rfc-editor.org/rfc/rfc7465)
- [7] [OWASP Web Security Testing Guide - Padding Oracle 测试](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [8] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [9] [PyCryptodome 文档](https://www.pycryptodome.org/)
{{#include ../../banners/hacktricks-training.md}}
