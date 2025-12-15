# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Common CTF patterns

- "Signature" は実際には `hash(secret || message)` → length extension.
- ソルトのないパスワードハッシュ → 簡単にクラッキング／照合される。
- ハッシュとMACを混同する (hash != authentication)。

## Hash length extension attack

### Technique

サーバーが次のような "signature" を計算している場合、しばしばこれを悪用できます:

`sig = HASH(secret || message)`

かつ Merkle–Damgård ハッシュ（典型例: MD5, SHA-1, SHA-256）を使っている場合。

もし以下が分かっていれば:

- `message`
- `sig`
- hash function
- (またはブルートフォースで分かる) `len(secret)`

次のような `message || padding || appended_data` に対する有効な署名を、秘密を知らなくても計算できます。

### Important limitation: HMAC is not affected

長さ拡張攻撃は Merkle–Damgård ハッシュに対する `HASH(secret || message)` のような構成に適用されます。**HMAC**（例: HMAC-SHA256）には適用されません。HMAC はこの種の問題を回避するように設計されています。

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

- Is it **salted**? (look for `salt$hash` formats)
- Is it a **fast hash** (MD5/SHA1/SHA256) or a **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Do you have a **format hint** (hashcat mode / John format)?

### Practical workflow

1. Identify the hash:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. If unsalted and common: try online DBs and identification tooling from the crypto workflow section.
3. Otherwise crack:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Common mistakes you can exploit

- Same password reused across users → crack one, pivot.
- Truncated hashes / custom transforms → normalize and retry.
- Weak KDF parameters (e.g., low PBKDF2 iterations) → still crackable.

{{#include ../../banners/hacktricks-training.md}}
