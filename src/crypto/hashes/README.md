# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Common CTF patterns

- "Signature"은 실제로 `hash(secret || message)` → length extension.
- Salt가 없는 password hashes → 쉬운 cracking / lookup.
- hash와 MAC을 혼동함 (hash != authentication).

## Hash length extension attack

### 기법

서버가 다음과 같은 "signature"를 계산하고:

`sig = HASH(secret || message)`

그리고 Merkle–Damgård hash를 사용한다면 (고전적인 예: MD5, SHA-1, SHA-256), 종종 이를 악용할 수 있습니다.

다음을 알고 있다면:

- `message`
- `sig`
- hash function
- (또는 brute-force할 수 있다면) `len(secret)`

그렇다면 secret을 알지 않고도 다음에 대한 유효한 signature를 계산할 수 있습니다:

`message || padding || appended_data`

### 중요한 제한: HMAC는 영향을 받지 않음

Length extension 공격은 Merkle–Damgård hashes에 대해 `HASH(secret || message)`와 같은 구성에 적용됩니다. 이는 **HMAC**(예: HMAC-SHA256)에는 적용되지 않으며, HMAC은 이러한 종류의 문제를 회피하도록 특별히 설계되었습니다.

### Tools

- hash_extender:
{{#ref}}
https://github.com/iagox86/hash_extender
{{#endref}}
- hashpump:
{{#ref}}
https://github.com/bwall/HashPump
{{#endref}}

### 좋은 설명

{{#ref}}
https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks
{{#endref}}

## Password hashing and cracking

### 첫 질문

- **salted**인가? (`salt$hash` 형식을 찾아보세요)
- **fast hash** (MD5/SHA1/SHA256) 인가요, 아니면 **slow KDF** (bcrypt/scrypt/argon2/PBKDF2) 인가요?
- **format hint** (hashcat mode / John format)이 있나요?

### 실전 워크플로우

1. 해시 식별:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Salt가 없고 흔한 경우: 온라인 DB와 crypto workflow 섹션의 식별 도구를 시도하세요.
3. 그렇지 않다면 crack:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### 악용할 수 있는 일반적인 실수

- 동일한 password가 여러 사용자에 재사용됨 → crack one, pivot.
- 잘린(truncated) hashes / custom transforms → normalize and retry.
- 약한 KDF 파라미터(예: 낮은 PBKDF2 반복 수) → 여전히 crackable.

{{#include ../../banners/hacktricks-training.md}}
