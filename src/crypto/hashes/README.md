# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Common CTF patterns

- “Signature” 实际上是 `hash(secret || message)` → length extension.
- 未加盐的 password hashes → 简单破解 / 查库。
- 混淆 hash 与 MAC（hash != authentication）。

## Hash length extension attack

### Technique

如果服务器像下面这样计算“签名”，通常可以利用这一点：

`sig = HASH(secret || message)`

并使用 Merkle–Damgård hash（经典示例：MD5、SHA-1、SHA-256）。

如果你知道：

- `message`
- `sig`
- hash function
- （或能暴力枚举）`len(secret)`

那么你可以在不知道 secret 的情况下计算出对以下内容的有效签名：

`message || padding || appended_data`

### Important limitation: HMAC is not affected

长度延展攻击适用于像 `HASH(secret || message)` 这类基于 Merkle–Damgård 的构造。它们不适用于 **HMAC**（例如 HMAC-SHA256），HMAC 专门设计用于避免这类问题。

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

## Password hashing and cracking

### First questions

- Is it **salted**?（查看是否有 `salt$hash` 格式）
- Is it a **fast hash** (MD5/SHA1/SHA256) or a **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Do you have a **format hint**（hashcat mode / John format）?

### Practical workflow

1. Identify the hash:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. If unsalted and common: try online DBs and identification tooling from the crypto workflow section.
3. Otherwise crack:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Common mistakes you can exploit

- Same password reused across users → 破解一个后横向利用（pivot）。
- Truncated hashes / custom transforms → 归一化后重试。
- Weak KDF parameters（例如 PBKDF2 迭代次数过低）→ 仍然可以被破解。

{{#include ../../banners/hacktricks-training.md}}
