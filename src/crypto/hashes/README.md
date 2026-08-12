# 哈希、MAC 和 KDF

{{#include ../../banners/hacktricks-training.md}}

## 常见 CTF 模式

- “签名”实际上是 `hash(secret || message)` → length extension。
- 未加盐的密码哈希 → 更快的重复破解和预计算查找攻击。
- 混淆哈希与 MAC（hash != authentication）。

## Hash length extension attack

### 技术

当服务器计算类似以下内容的“签名”时，可能存在 length-extension attack：

`sig = HASH(secret || message)`

并使用 MD5、SHA-1 或 SHA-256 等 Merkle-Damgård 哈希。

如果你知道：

- `message`
- `sig`
- 哈希函数
- （或可以暴力破解）`len(secret)`

那么你可以在不知道 secret 的情况下，为以下内容计算有效签名：

`message || padding || appended_data`

<sup>[[1]](#references)</sup>

### 重要限制：HMAC 不受影响

Length-extension attacks 适用于 `HASH(secret || message)` 这类存在漏洞的前缀构造。它们不会暴露 HMAC 构造（例如 HMAC-SHA256），因为 HMAC 会将密钥与独立的内部和外部哈希操作结合使用。<sup>[[1]](#references)[[2]](#references)</sup>

### 工具

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/)，HashPump length-extension tool 的 Python bindings<sup>[[7]](#references)</sup>

### 良好解释

[你需要了解的有关 hash length extension attacks 的一切](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## 密码哈希与破解

### 首要问题<sup>[[4]](#references)</sup>

- 是否**加盐**？（查找 `salt$hash` 格式）
- 是**快速哈希**（MD5/SHA1/SHA256）还是**慢速 KDF**（bcrypt/scrypt/argon2/PBKDF2）？
- 是否有**格式提示**（hashcat mode / John format）？

### 实用工作流<sup>[[5]](#references)[[6]](#references)</sup>

1. 识别哈希：
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. 如果未加盐且很常见：尝试在线数据库，以及 crypto workflow section 中的识别工具。
3. 否则进行破解：
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### 可以利用的常见错误

- 不同用户重复使用相同密码 → 破解一个后进行 pivot。
- 截断的哈希 / 自定义变换 → 规范化后重试。
- KDF 参数较弱（例如 PBKDF2 迭代次数较低）→ 仍然可以破解。

## References

- [1] [SkullSecurity - 你需要了解的有关 hash length-extension attacks 的一切](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - 带密钥的哈希消息认证码](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP 密码存储备忘单](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat 示例哈希](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper 命令行选项](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI：`hashpumpy` 的 HashPump Python bindings](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
