# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## CTFでよくあるパターン

- 「Signature」が実際には `hash(secret || message)` → length extension。
- Saltなしの password hash → trivial cracking / lookup。
- hash と MAC の混同（hash != authentication）。

## Hash length extension attack

### Technique

サーバーが次のような「signature」を計算している場合、これを悪用できることがあります。

`sig = HASH(secret || message)`

また、Merkle–Damgård hash（classic examples: MD5, SHA-1, SHA-256）が使用されている必要があります。

次の情報が分かっている場合：

- `message`
- `sig`
- hash function
- （または brute-force できる）`len(secret)`

secret を知らなくても、次のデータに対する有効な signature を計算できます。

`message || padding || appended_data`

<sup>[[1]](#references)</sup>

### Important limitation: HMAC is not affected

Length extension attacks は、Merkle–Damgård hashes に対する `HASH(secret || message)` のような構成に適用されます。これらは、この種類の問題を回避するよう特別に設計された **HMAC**（例：HMAC-SHA256）には適用されません。<sup>[[1]](#references)</sup>

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

- **salted** か？（`salt$hash` 形式を探す）
- **fast hash**（MD5/SHA1/SHA256）か、**slow KDF**（bcrypt/scrypt/argon2/PBKDF2）か？
- **format hint**（hashcat mode / John format）はあるか？

### Practical workflow

1. hash を特定する：
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Saltなしで common な場合：crypto workflow section の online DB と identification tooling を試す。
3. それ以外は crack する：
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Common mistakes you can exploit

- 複数の user 間で同じ password を再利用 → 1つを crack して pivot。
- Truncated hashes / custom transforms → normalize して再試行。
- Weak KDF parameters（例：少ない PBKDF2 iterations）→ それでも crack 可能。

## References

- [1] [Everything you need to know about hash length extension attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

{{#include ../../banners/hacktricks-training.md}}
