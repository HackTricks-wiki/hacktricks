# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## 일반적인 CTF 패턴

- "Signature"가 실제로는 `hash(secret || message)` → length extension.
- Salt가 없는 password hash → 간단한 cracking / lookup.
- Hash와 MAC을 혼동함 (hash != authentication).

## Hash length extension attack

### Technique

서버가 다음과 같이 "signature"를 계산한다면 이를 자주 exploit할 수 있습니다.

`sig = HASH(secret || message)`

그리고 Merkle–Damgård hash를 사용하는 경우입니다 (대표적인 예: MD5, SHA-1, SHA-256).

다음을 알고 있다면:

- `message`
- `sig`
- hash function
- (또는 brute-force할 수 있는) `len(secret)`

secret을 알지 못해도 다음에 대한 유효한 signature를 계산할 수 있습니다:

`message || padding || appended_data`

<sup>[[1]](#references)</sup>

### Important limitation: HMAC is not affected

Length extension attacks는 Merkle–Damgård hash를 사용하는 `HASH(secret || message)`와 같은 construction에 적용됩니다. 이러한 공격은 이 문제를 방지하도록 특별히 설계된 **HMAC** (예: HMAC-SHA256)에는 적용되지 않습니다.<sup>[[1]](#references)</sup>

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

- **Salted**인가? (`salt$hash` 형식을 확인)
- **fast hash** (MD5/SHA1/SHA256)인가, 아니면 **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)인가?
- **format hint** (hashcat mode / John format)가 있는가?

### Practical workflow

1. Hash 식별:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Salt가 없고 흔한 hash라면 crypto workflow section의 online DB와 identification tooling을 시도합니다.
3. 그 외에는 crack합니다:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Common mistakes you can exploit

- 여러 user가 동일한 password를 재사용함 → 하나를 crack하고 pivot.
- Truncated hash / custom transform → normalize한 뒤 다시 시도.
- Weak KDF parameters (예: 낮은 PBKDF2 iteration 수) → 여전히 crack 가능.

## References

- [1] [Everything you need to know about hash length extension attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

{{#include ../../banners/hacktricks-training.md}}
