# 哈希、MAC 与 KDF

{{#include ../../banners/hacktricks-training.md}}

## 常见 CTF 模式

- “签名”实际上是 `hash(secret || message)` → length extension。
- 未加盐的密码哈希 → 更快地重复破解和预计算查找攻击。
- 混淆哈希与 MAC（hash != authentication）。

## 哈希 length extension attack

### 技术

当服务器计算类似以下形式的“签名”时：

`sig = HASH(secret || message)`

并使用 MD5、SHA-1 或 SHA-256 等 Merkle-Damgård 哈希，可能存在 length-extension attack。

如果你知道：

- `message`
- `sig`
- 哈希函数
- （或可以暴力破解）`len(secret)`

那么无需知道 secret，就可以为以下内容计算有效签名：

`message || padding || appended_data`<sup>[[1]](#references)</sup>

### 重要限制：HMAC 不受影响

Length-extension attacks 适用于易受攻击的前缀构造，例如 `HASH(secret || message)`。它们不会破解 HMAC 构造（例如 HMAC-SHA256）；HMAC 会将密钥与分别执行的内层和外层哈希运算结合起来。<sup>[[1]](#references)[[2]](#references)</sup>

### 工具

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/)，HashPump length-extension 工具的 Python 绑定<sup>[[7]](#references)</sup>

### 优质说明

[你需要了解的关于 hash length extension attacks 的一切](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## 密码哈希与破解

### 首先要问的问题<sup>[[4]](#references)</sup>

- 是否**加盐**？（留意 `salt$hash` 格式）
- 是**快速哈希**（MD5/SHA1/SHA256），还是**慢速 KDF**（bcrypt/scrypt/argon2/PBKDF2）？
- 是否有**格式提示**（hashcat mode / John format）？

### 实际工作流程<sup>[[5]](#references)[[6]](#references)</sup>

1. 识别哈希：
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. 如果未加盐且较常见：尝试在线数据库，以及 crypto workflow section 中的识别工具。
3. 否则进行破解：
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### 可利用的常见错误

- 多个用户重复使用同一密码 → 破解一个，然后 pivot。
- 哈希被截断 / 使用自定义转换 → 规范化后重试。
- KDF 参数较弱（例如 PBKDF2 迭代次数较低）→ 仍可破解。

### 追加 secret 的 chosen-input bcrypt oracle

一个可调用的辅助程序若返回 `bcrypt(user_input || secret)`，而其 bcrypt 实现会在 72 **字节**后静默截断输入，就可能泄露追加的 secret 信息。在 UTF-8 编码前进行的字符数限制无法确保满足这个字节限制：多字节字符可能占满 bcrypt 输入，只给 secret 留下少量前缀空间。随后，chosen inputs 及其返回的哈希可能允许离线检查候选后缀字节。这需要能够控制辅助程序的输入、了解其确切的转换和编码方式，并确认实现确实会截断；仅有可调用的辅助程序或 bcrypt 哈希，并不能证明这条攻击链成立。[pyca/bcrypt 的文档](https://github.com/pyca/bcrypt#maximum-password-length)说明，当前版本的 `hashpw` 会对超过 72 字节的输入报错，而早期行为则是静默截断。其他 wrapper 可能会预先哈希或拒绝过长的输入，因此应核实已安装的实现，而不要假设它会截断。

要将恢复出的 secret 用于另一个账户，还需要证据证明该账户公开的哈希是用**相同**的 secret 和转换方式生成的，并且还需要单独的凭据或登录路径。只有在低权限用户能根据有效策略调用以 root 身份运行的哈希辅助程序时，才应将其视为 oracle；被动的主机枚举不必调用它或提交 chosen passwords。

## References

- [1] [SkullSecurity - 你需要了解的关于 hash length-extension attacks 的一切](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - 基于密钥的哈希消息认证码](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP 密码存储备忘单](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat 示例哈希](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper 命令行选项](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI：HashPump 的 `hashpumpy` Python 绑定](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
