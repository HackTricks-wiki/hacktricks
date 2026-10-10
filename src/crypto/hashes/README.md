# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## 일반적인 CTF 패턴

- "Signature"가 실제로는 `hash(secret || message)`인 경우 → length extension.
- Salt가 없는 password hash → 반복적인 cracking과 사전 계산된 lookup 공격이 더 빨라짐.
- hash와 MAC을 혼동하는 경우 (hash != authentication).

## Hash length extension attack

### Technique

서버가 다음과 같은 "signature"를 계산하고:

`sig = HASH(secret || message)`

MD5, SHA-1 또는 SHA-256 같은 Merkle-Damgård hash를 사용하면 length-extension attack이 가능할 수 있습니다.

다음을 알고 있다면:

- `message`
- `sig`
- hash function
- `len(secret)` (또는 brute-force로 알아낼 수 있다면)

secret을 알지 못해도 다음에 대한 유효한 signature를 계산할 수 있습니다.

`message || padding || appended_data`

<sup>[[1]](#references)</sup>

### 중요한 제한: HMAC은 영향을 받지 않음

Length-extension attack은 `HASH(secret || message)` 같은 취약한 prefix construction에 적용됩니다. 별도의 inner 및 outer hash 연산과 key를 결합하는 HMAC construction(예: HMAC-SHA256)은 노출되지 않습니다.<sup>[[1]](#references)[[2]](#references)</sup>

### Tools

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), HashPump length-extension tool용 Python bindings<sup>[[7]](#references)</sup>

### 유용한 설명

[Everything you need to know about hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Password hashing and cracking

### 먼저 확인할 사항<sup>[[4]](#references)</sup>

- **Salted**인가? (`salt$hash` 형식인지 확인)
- **Fast hash** (MD5/SHA1/SHA256)인가, 아니면 **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)인가?
- **Format hint** (hashcat mode / John format)가 있는가?

### 실전 workflow<sup>[[5]](#references)[[6]](#references)</sup>

1. hash 식별:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Salt가 없고 흔한 hash라면, 온라인 DB와 crypto workflow section의 식별 도구를 사용해 봅니다.
3. 그 외에는 crack을 시도합니다:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### 악용할 수 있는 흔한 실수

- 여러 사용자가 같은 password를 재사용함 → 하나를 crack한 뒤 pivot.
- 잘린 hash / custom transform → 정규화한 뒤 다시 시도.
- 약한 KDF parameter (예: 낮은 PBKDF2 iteration 횟수) → 여전히 crack 가능.

### secret이 추가된 chosen-input bcrypt oracle

`bcrypt(user_input || secret)`을 반환하는 helper를 호출할 수 있고, 그 helper의 bcrypt 구현이 입력을 72 **bytes** 이후에서 조용히 잘라낸다면 추가된 secret에 관한 정보를 노출할 수 있습니다. UTF-8 인코딩 전에 적용되는 문자 수 제한은 해당 byte 제한을 강제하지 않습니다. 멀티바이트 문자는 bcrypt 입력을 채우면서 secret의 짧은 prefix만 남길 수 있습니다. 이때 선택한 입력과 반환된 hash를 이용해 후보 suffix bytes를 오프라인에서 확인할 수 있습니다. 이를 위해서는 helper의 입력을 제어하고, 정확한 transform과 encoding을 알아야 하며, 실제로 입력을 자르는 구현을 사용해야 합니다. helper를 호출할 수 있거나 bcrypt hash가 있다는 사실만으로는 이러한 조건이 성립한다고 볼 수 없습니다. [pyca/bcrypt 문서](https://github.com/pyca/bcrypt#maximum-password-length)에 따르면 현재 `hashpw`는 72 bytes를 초과하는 입력에 대해 오류를 발생시키지만, 이전 동작은 입력을 조용히 잘라냈습니다. 다른 wrapper는 입력을 사전 hashing하거나 긴 입력을 거부할 수 있으므로, 잘라낸다고 가정하지 말고 설치된 구현을 확인하세요.

복구한 secret을 다른 계정에 사용하려면, 노출된 hash가 **동일한** secret과 transform으로 생성되었다는 증거와 별도의 credential 또는 login 경로가 필요합니다. root 권한으로 실행되는 hashing helper는 낮은 권한의 사용자가 유효한 정책에 따라 호출할 수 있는 경우에만 oracle로 검토해야 합니다. 수동적인 호스트 열거 과정에서 이를 호출하거나 선택한 password를 제출할 필요는 없습니다.

## References

- [1] [SkullSecurity - hash length-extension 공격에 대해 알아야 할 모든 것](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - 키 기반 해시 메시지 인증 코드](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat 예제 hash](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper 명령줄 옵션](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: HashPump용 `hashpumpy` Python bindings](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
