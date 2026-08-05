# 哈希、MAC 和 KDF

{{#include ../../banners/hacktricks-training.md}}

## 常见 CTF 模式

- “Signature” 实际上是 `hash(secret || message)` → length extension。
- 未加盐的密码哈希 → 可进行简单破解 / lookup。
- 将哈希与 MAC 混淆（hash != authentication）。

## 哈希长度扩展攻击

### Technique

如果服务器计算的“signature”类似于：

`sig = HASH(secret || message)`

并使用 Merkle–Damgård 哈希（经典示例：MD5、SHA-1、SHA-256），通常可以利用这一点。

如果你知道：

- `message`
- `sig`
- 哈希函数
- （或可以通过暴力破解得到）`len(secret)`

那么无需知道 secret，就可以为以下内容计算有效的 signature：

`message || padding || appended_data`

<sup>[[1]](#references)</sup>

### 重要限制：HMAC 不受影响

长度扩展攻击适用于 Merkle–Damgård 哈希的 `HASH(secret || message)` 构造。它们不适用于 **HMAC**（例如 HMAC-SHA256），后者就是专门为避免此类问题而设计的。<sup>[[1]](#references)</sup>

### Tools

- hash_extender:
{{#ref}}
https://github.com/iagox86/hash_extender
{{#endref}}
- hashpump:
{{#ref}}
https://github.com/bwall/HashPump
{{#endref}}

### Good explanation

{{#ref}}
https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks
{{#endref}}

## 密码哈希与破解

### 首要问题

- 是否**加盐**？（查找 `salt$hash` 格式）
- 是**快速哈希**（MD5/SHA1/SHA256）还是**慢速 KDF**（bcrypt/scrypt/argon2/PBKDF2）？
- 是否有**格式提示**（hashcat mode / John format）？

### 实用工作流

1. 识别哈希：
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. 如果未加盐且较为常见：尝试使用在线 DB 和 crypto workflow section 中的识别工具。
3. 否则进行破解：
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### 可以利用的常见错误

- 不同用户重复使用同一密码 → 破解一个后进行 pivot。
- 截断的哈希 / 自定义变换 → 进行 normalize 后重试。
- 较弱的 KDF 参数（例如 PBKDF2 迭代次数较低）→ 仍然可以破解。

## References

- [1] [Everything you need to know about hash length extension attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

{{#include ../../banners/hacktricks-training.md}}
