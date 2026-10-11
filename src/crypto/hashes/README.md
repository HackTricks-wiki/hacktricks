# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## 일반적인 CTF 패턴

- "Signature"가 실제로는 `hash(secret || message)`인 경우 → length extension.
- Salt가 없는 password hash → 더 빠른 반복 cracking 및 사전 계산된 lookup 공격.
- hash와 MAC을 혼동하는 경우 (hash != 인증).

## Hash length extension attack

### Technique

서버가 다음과 같은 "signature"를 계산하고:

`sig = HASH(secret || message)`

MD5, SHA-1, SHA-256 같은 Merkle-Damgård hash를 사용하는 경우 length-extension attack이 가능할 수 있습니다.

다음 정보를 알고 있다면:

- `message`
- `sig`
- hash function
- `len(secret)` (또는 brute-force로 알아낼 수 있는 경우)

secret을 몰라도 다음에 대한 유효한 signature를 계산할 수 있습니다.

`message || padding || appended_data`

<sup>[[1]](#references)</sup>

### 중요한 제한 사항: HMAC에는 영향을 주지 않음

Length-extension attack은 `HASH(secret || message)`와 같은 취약한 prefix 구성에 적용됩니다. 별도의 inner 및 outer hash 적용과 key를 결합하는 HMAC 구성(예: HMAC-SHA256)은 노출시키지 않습니다.<sup>[[1]](#references)[[2]](#references)</sup>

### Tools

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), HashPump length-extension tool용 Python bindings<sup>[[7]](#references)</sup>

### 유용한 설명

[hash length extension attack에 대해 알아야 할 모든 것](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Password hashing 및 cracking

### 먼저 확인할 사항<sup>[[4]](#references)</sup>

- **salted**인가? (`salt$hash` 형식인지 확인)
- **fast hash**(MD5/SHA1/SHA256)인가, **slow KDF**(bcrypt/scrypt/argon2/PBKDF2)인가?
- **format hint**(hashcat mode / John format)가 있는가?

### 실제 작업 흐름<sup>[[5]](#references)[[6]](#references)</sup>

1. hash를 식별합니다:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Salt가 없고 흔한 형식이라면 온라인 DB와 crypto workflow 섹션의 식별 도구를 시도합니다.
3. 그렇지 않으면 crack합니다:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### 악용할 수 있는 일반적인 실수

- 여러 사용자가 같은 password를 재사용함 → 하나를 crack한 뒤 pivot합니다.
- 잘리거나 사용자 지정 변환이 적용된 hash → 정규화한 뒤 다시 시도합니다.
- 취약한 KDF parameters(예: PBKDF2 반복 횟수가 적음) → 여전히 crack할 수 있습니다.

### Secret이 뒤에 추가되는 chosen-input bcrypt oracle

`bcrypt(user_input || secret)`을 반환하는 호출 가능한 helper는 bcrypt 구현이 입력을 72 **bytes** 이후에서 조용히 자르는 경우, 뒤에 추가된 secret에 대한 정보를 노출할 수 있습니다. UTF-8 인코딩 전에 문자 수 제한을 두더라도 이 byte 제한이 보장되지는 않습니다. multibyte 문자는 bcrypt 입력을 채우면서 secret의 짧은 prefix만 들어갈 공간을 남길 수 있습니다. 이렇게 선택한 입력과 반환된 hash를 사용하면 후보 suffix bytes를 오프라인에서 확인할 수 있습니다. 이를 위해서는 helper의 입력을 제어할 수 있고, 정확한 변환 및 인코딩 방식을 알고 있으며, 실제로 입력을 자르는 구현을 사용해야 합니다. 호출 가능한 helper나 bcrypt hash만으로는 이러한 조건이 성립한다고 볼 수 없습니다. [pyca/bcrypt 문서](https://github.com/pyca/bcrypt#maximum-password-length)에 따르면 현재 `hashpw`는 72 bytes를 초과하는 입력에 오류를 발생시키지만, 이전 동작에서는 입력을 조용히 잘랐습니다. 다른 wrapper는 입력을 미리 hash하거나 너무 긴 입력을 거부할 수 있으므로, 입력이 잘릴 것이라고 가정하지 말고 설치된 구현을 확인하세요.

복구한 secret을 다른 계정에 사용하려면, 노출된 hash가 **동일한** secret과 변환 방식으로 생성되었다는 근거와 별도의 credential 또는 login 경로도 필요합니다. root 권한으로 실행되는 hashing helper는 낮은 권한의 사용자가 유효한 정책에 따라 호출할 수 있을 때만 oracle로 검토해야 합니다. 수동적인 host 열거 중에 helper를 호출하거나 선택한 password를 제출할 필요는 없습니다.

## References

- [1] [SkullSecurity - hash length-extension attack에 대해 알아야 할 모든 것](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Keyed-Hash Message Authentication Code](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat 예제 hash](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper 명령줄 옵션](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy` - HashPump용 Python bindings](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
