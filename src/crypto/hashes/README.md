# Hash、MAC 与 KDF

{{#include ../../banners/hacktricks-training.md}}

## 常见 CTF 模式

- “签名”实际上是 `hash(secret || message)` → length extension。
- 未加盐的密码哈希 → 可更快地重复破解，并遭受预计算查找攻击。
- 混淆 hash 和 MAC（hash != authentication）。

## Hash length extension attack

### 技术

当服务器使用 Merkle-Damgård hash（例如 MD5、SHA-1 或 SHA-256）计算类似下面的“签名”时，可能会受到 length-extension attack：

`sig = HASH(secret || message)`

如果你知道：

- `message`
- `sig`
- hash 函数
- （或者可以暴力破解）`len(secret)`

那么你就能在不知道 secret 的情况下，为以下内容计算有效签名：

`message || padding || appended_data`<sup>[[1]](#references)</sup>

### 重要限制：HMAC 不受影响

Length-extension attack 适用于 `HASH(secret || message)` 这类存在漏洞的前缀构造。它们不会泄露 HMAC 构造（例如 HMAC-SHA256），后者会将密钥与单独的内层和外层 hash 运算结合起来。<sup>[[1]](#references)[[2]](#references)</sup>

### 工具

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/)，HashPump length-extension 工具的 Python bindings<sup>[[7]](#references)</sup>

### 优质讲解

[关于 hash length extension attacks，你需要了解的一切](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## 密码哈希与破解

### 首先要问的问题<sup>[[4]](#references)</sup>

- 是否**加了盐**？（查找 `salt$hash` 格式）
- 它是**快速 hash**（MD5/SHA1/SHA256）还是**慢速 KDF**（bcrypt/scrypt/argon2/PBKDF2）？
- 是否有**格式提示**（hashcat mode / John format）？

### 实用工作流程<sup>[[5]](#references)[[6]](#references)</sup>

1. 识别 hash：
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. 如果未加盐且很常见：尝试在线数据库和 crypto workflow 部分介绍的识别工具。
3. 否则进行破解：
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### 可利用的常见错误

- 多个用户重复使用同一个密码 → 破解一个后进行 pivot。
- 截断的 hash / 自定义变换 → 规范化后重试。
- KDF 参数较弱（例如 PBKDF2 迭代次数较低）→ 仍可破解。

### 追加 secret 的 chosen-input bcrypt oracle

一个可调用的 helper 若返回 `bcrypt(user_input || secret)`，当其 bcrypt 实现会在 72 **字节**后静默截断输入时，可能会泄露追加的 secret 信息。在 UTF-8 编码前限制字符数，并不能确保遵守该字节限制：多字节字符可能占满 bcrypt 输入，只给 secret 留下很短的前缀空间。此时，chosen inputs 及其返回的 hash 可能允许离线检查候选后缀字节。这需要你能够控制 helper 的输入、了解其确切的变换和编码方式，并确认其实现确实会截断；仅有可调用的 helper 或 bcrypt hash，并不能证明整个攻击链成立。[pyca/bcrypt 文档](https://github.com/pyca/bcrypt#maximum-password-length)说明，当前的 `hashpw` 遇到超过 72 字节的输入时会报错，而早期版本的行为是静默截断。其他 wrapper 可能会先进行预哈希或拒绝过长的输入，因此应验证已安装的实现，而不要假定它会截断。

要将恢复出的 secret 用于另一个账户，还需要证据证明该账户暴露的 hash 是用**相同**的 secret 和变换生成的，并且还需要单独的凭证或登录路径。只有在低权限用户能根据有效策略调用以 root 身份运行的 hash helper 时，才应将其视为 oracle；被动主机枚举不必调用它或提交 chosen passwords。

## References

- [1] [SkullSecurity - 关于 hash length-extension attacks，你需要了解的一切](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - 基于密钥的 Hash 消息认证码](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP 密码存储备忘单](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat 示例 hash](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper 命令行选项](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI：`hashpumpy` 的 HashPump Python bindings](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
