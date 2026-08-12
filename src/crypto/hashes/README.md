# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## 일반적인 CTF 패턴

- "Signature"가 실제로는 `hash(secret || message)` → length extension인 경우
- Salt가 없는 password hash → 더 빠른 반복 cracking 및 사전 계산 lookup 공격
- Hash와 MAC을 혼동하는 경우 (hash != authentication)

## Hash length extension attack

### Technique

서버가 다음과 같이 "signature"를 계산할 때 length-extension attack이 가능할 수 있습니다:

`sig = HASH(secret || message)`

그리고 MD5, SHA-1 또는 SHA-256과 같은 Merkle-Damgård hash를 사용하는 경우입니다.

다음 항목을 알고 있다면:

- `message`
- `sig`
- hash function
- (또는 brute-force할 수 있다면) `len(secret)`

secret을 몰라도 다음에 대한 유효한 signature를 계산할 수 있습니다:

`message || padding || appended_data`

<sup>[[1]](#references)</sup>

### Important limitation: HMAC is not affected

Length-extension attack은 `HASH(secret || message)`와 같은 취약한 prefix construction에 적용됩니다. 별도의 inner 및 outer hash 적용을 통해 key를 결합하는 HMAC construction(예: HMAC-SHA256)은 노출시키지 않습니다.<sup>[[1]](#references)[[2]](#references)</sup>

### Tools

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), HashPump length-extension tool의 Python bindings<sup>[[7]](#references)</sup>

### Good explanation

[Everything you need to know about hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Password hashing and cracking

### First questions<sup>[[4]](#references)</sup>

- **Salted**인가? (`salt$hash` 형식을 확인)
- **Fast hash**(MD5/SHA1/SHA256)인가, 아니면 **slow KDF**(bcrypt/scrypt/argon2/PBKDF2)인가?
- **Format hint**(hashcat mode / John format)이 있는가?

### Practical workflow<sup>[[5]](#references)[[6]](#references)</sup>

1. Hash 식별:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Salt가 없고 일반적인 hash라면 crypto workflow section의 online DB 및 identification tooling을 시도합니다.
3. 그 외에는 crack:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Common mistakes you can exploit

- 여러 사용자가 동일한 password를 재사용함 → 하나를 crack한 뒤 pivot
- Truncated hash / custom transform → normalize한 뒤 재시도
- Weak KDF parameters(예: 낮은 PBKDF2 iterations) → 여전히 crack 가능

## References

- [1] [SkullSecurity - hash length-extension attack에 대해 알아야 할 모든 것](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Keyed-Hash Message Authentication Code](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper command-line options](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy` HashPump용 Python bindings](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
