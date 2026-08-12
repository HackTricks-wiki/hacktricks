# Hash、MAC、KDF

{{#include ../../banners/hacktricks-training.md}}

## Common CTFパターン

- 「Signature」が実際には `hash(secret || message)` → length extension。
- Saltなしのpassword hash → より高速な繰り返しcrackingとprecomputed lookup attack。
- hashとMACの混同（hash != authentication）。

## Hash length extension attack

### Technique

length-extension attackは、サーバーが次のような「signature」を計算する場合に可能です。

`sig = HASH(secret || message)`

また、MD5、SHA-1、SHA-256などのMerkle-Damgård hashを使用している場合です。

以下が分かっている場合：

- `message`
- `sig`
- hash function
- （またはbrute-forceできる）`len(secret)`

secretを知らなくても、次の値に対する有効なsignatureを計算できます。

`message || padding || appended_data`

<sup>[[1]](#references)</sup>

### Important limitation: HMAC is not affected

length-extension attackは、`HASH(secret || message)`のような脆弱なprefix constructionに適用されます。keyとinnerおよびouterのhash処理を別々に組み合わせるHMAC construction（例：HMAC-SHA256）を露出させるものではありません。<sup>[[1]](#references)[[2]](#references)</sup>

### Tools

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/)、HashPump length-extension toolのPython bindings<sup>[[7]](#references)</sup>

### 詳細な解説

[hash length extension attackについて知っておくべきこと](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Password hashing and cracking

### 最初に確認すること<sup>[[4]](#references)</sup>

- **salt**付きか？（`salt$hash`形式を探す）
- **fast hash**（MD5/SHA1/SHA256）か、**slow KDF**（bcrypt/scrypt/argon2/PBKDF2）か？
- **format hint**（hashcat mode / John format）があるか？

### 実践的なworkflow<sup>[[5]](#references)[[6]](#references)</sup>

1. hashを特定する：
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Saltなしで一般的なhashの場合：crypto workflow sectionのonline DBとidentification toolingを試す。
3. それ以外の場合はcrackする：
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Exploit可能なよくあるミス

- 同じpasswordを複数のuserで再利用 → 1つをcrackしてpivot。
- Truncated hash / custom transform → normalizeして再試行。
- Weak KDF parameters（例：PBKDF2のiteration数が少ない）→ それでもcrack可能。

## References

- [1] [SkullSecurity - hash length-extension attackについて知っておくべきこと](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Keyed-Hash Message Authentication Code](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper command-line options](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy` HashPump用Python bindings](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
