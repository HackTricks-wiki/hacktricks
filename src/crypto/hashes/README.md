# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## 일반적인 CTF 패턴

- "Signature"가 실제로는 `hash(secret || message)`임 → length extension.
- Salt가 없는 password hash → 반복적인 cracking 및 사전 계산된 lookup 공격이 더 빨라짐.
- hash와 MAC을 혼동함 (hash != authentication).

## 입력값을 선택하는 MD5 hash 검색

이 Python 예제들은 서로 다른 두 가지 출력 패턴, 즉 선택한 MD5 suffix와 `0e`로 시작하고 그 뒤에 숫자만 오는 MD5 값을 검색합니다. 후자의 패턴은 애플리케이션이 숫자 문자열을 느슨하게 비교할 때 관련이 있습니다. [PHP 느슨한 비교](../../network-services-pentesting/pentesting-web/php-tricks-esp/README.md#loose-comparisons-and-type-juggling)에서 PHP 관련 동작과 버전별 주의 사항을 확인하세요.

### MD5 hash suffix brute force

```python
import hashlib

target = '2f2e2e' #/..
candidate = 0
while True:
    plaintext = str(candidate)
    hash = hashlib.md5(plaintext.encode('ascii')).hexdigest()
    if hash[-1*(len(target)):] == target: #End in target
        print('plaintext:"' + plaintext + '", md5:' + hash)
        break
    candidate = candidate + 1
```

### 느슨한 비교를 위한 MD5 0e 해시 생성

```python
#From isHaacK
import hashlib
from multiprocessing import Process, Queue, cpu_count


def loose_comparison(queue, num):
	target = '0e'
	plaintext = f"a_prefix{str(num)}a_suffix"
	hash = hashlib.md5(plaintext.encode('ascii')).hexdigest()

	if hash[:len(target)] == target and not any(x in "abcdef" for x in hash[2:]):
		print('plaintext: ' + plaintext + ', md5: ' + hash)
		queue.put("done") # triggers program exit

def worker(queue, thread_i, threads):
	for num in range(thread_i, 100**50, threads):
		loose_comparison(queue, num)

def main():
	procs = []
	queue = Queue()
	threads = cpu_count() # 2

	for thread_i in range(threads):
		proc = Process(target=worker, args=(queue, thread_i, threads ))
		proc.daemon = True # kill all subprocess when main process exits.
		procs.append(proc)
		proc.start()

	while queue.empty(): # exits when a subprocess is done
		pass
	return 0

main()
```

## Hash length extension attack

### Technique

서버가 다음과 같은 "서명"을 계산하고:

`sig = HASH(secret || message)`

MD5, SHA-1 또는 SHA-256 같은 Merkle-Damgård hash를 사용한다면 length-extension attack이 가능할 수 있습니다.

다음 정보를 알고 있다면:

- `message`
- `sig`
- hash function
- `len(secret)` (또는 brute-force로 알아낼 수 있는 경우)

secret을 몰라도 다음에 대한 유효한 서명을 계산할 수 있습니다.

`message || padding || appended_data`<sup>[[1]](#references)</sup>

### Important limitation: HMAC is not affected

Length-extension attack은 `HASH(secret || message)`와 같은 취약한 prefix 구성에 적용됩니다. 별도의 inner 및 outer hash 적용을 조합하는 HMAC 구성(예: HMAC-SHA256)은 노출되지 않습니다.<sup>[[1]](#references)[[2]](#references)</sup>

### Tools

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), HashPump length-extension 도구의 Python bindings<sup>[[7]](#references)</sup>

### Good explanation

[Everything you need to know about hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Ambiguous tuple hashing and MACs

### Boundary-confusion attack

Incremental hash API는 호출 경계를 인증하지 않습니다. `update(A); update(B)`는 `update(A + B)`와 동일한 byte string을 hash합니다. 따라서 원시 연결(raw concatenation)을 hash하거나 MAC 처리해도 tuple은 인증되지 않습니다. 인접한 필드의 길이가 가변적이면 공격자는 기반 hash에서 collision을 찾지 않고도 byte를 다른 tuple로 재분할할 수 있습니다:<sup>[[8]](#references)[[9]](#references)</sup>

```python
import hashlib

def raw_hash(parts):
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()

assert raw_hash([b"alice", b"admin"]) == raw_hash([b"aliceadmin", b""])
```

이 문제는 verifier가 digest가 필드의 의미를 묶는다고 믿지만, 공격자가 제어하는 입력이 다른 parser나 protocol 단계에 도달해 다른 경계를 지정할 수 있을 때 악용될 수 있습니다. Commitments에 대체 opening이 생길 수 있고, Fiat-Shamir transcript가 다른 statement로 해석될 수 있습니다. HMAC은 [hash length extension](#hash-length-extension-attack)을 방지하지만, `HMAC(K, A || B)`에도 튜플 인코딩 모호성이 남습니다. 두 튜플이 같은 메시지 바이트를 생성하기 때문입니다.<sup>[[8]](#references)[[9]](#references)</sup>

이 감사 워크플로를 사용해 모호한 튜플 인코딩이 보안 경계를 넘는지 테스트하세요.<sup>[[8]](#references)[[9]](#references)</sup>

1. `HASH(A || B)`, `HMAC(K, A || B)`, 그리고 두 개 이상의 필드에 걸친 연속적인 `update()`/`Write()` 호출을 찾습니다.
2. 공격자가 제어하거나 길이가 변할 수 있는 모든 필드를 표시합니다. 전체 연결 결과는 그대로 유지하면서 각 경계를 넘나들도록 바이트를 이동해 봅니다. 빈 필드도 포함합니다.
3. 구분자 방식을 확인해 입력에 구분자 바이트가 포함될 수 있는지, escaping 방식이 서로 일치하지 않는지, 일부 필드에만 길이 인코딩을 적용하는지 살펴봅니다.
4. 인증된 바이트를 각 consumer가 어떻게 파싱하는지 추적합니다. 다른 분할 방식이 보안 결정, proof statement, record, transaction 또는 commitment opening을 바꿀 때만 공격 후보가 유효합니다. 고정 길이 필드 또는 표준적이고 단사적인 직렬화는 이 특정 공격을 방지합니다.
5. 동일한 인코딩 digest가 다른 protocol 버전, 메시지 유형, 라운드 또는 애플리케이션에서도 허용되는지 확인합니다. 호출자가 각 항목을 분리해 처리할 것이라고 기대하지 말고, 이러한 컨텍스트를 명시적으로 바인딩합니다.

### SequenceHash 및 SequenceMAC

SequenceHash는 바이트 문자열 시퀀스를 위한 해시 알고리즘 비종속적 구성입니다. 각 `add()` 작업은 원자적입니다. 값을 추가한 뒤 고정된 16바이트 little-endian 길이 접미사를 내부 해시에 추가합니다. 빈 값도 서로 구별되는 객체로 유지됩니다. 외부 해시는 길이 확장이 가능한 내부 상태가 노출되는 것을 방지하며, 선택적 customization string은 domain separation을 제공합니다. `add()`를 기본 해시 API의 일반적인 쓰기 작업으로 대체하지 마세요.<sup>[[8]](#references)[[9]](#references)</sup>

```python
import sequencehash

h = sequencehash.SequenceHash.new("sha256")
h.add(b"alice")
h.add(b"admin")
digest = h.result_with_customizer(b"example:v1:user-record")
```

프로토콜 정의의 일부로 customizer를 선택하고, 애플리케이션, 프로토콜 버전, 메시지 유형, 라운드를 구분할 수 있도록 충분한 정보를 포함하세요. SequenceHash를 사용하려면 모든 당사자가 필드 순서, 바이트 인코딩, 정규 직렬화 방식에 동의해야 하며, 누락된 필드는 보호할 수 없습니다. 구현은 C2SP 중간 및 최종 테스트 벡터와 대조해야 합니다.<sup>[[8]](#references)[[11]](#references)</sup>

인증에는 SequenceMAC이 동일한 원자적 인코딩 및 customization 인터페이스를 제공합니다. 키는 최소 32바이트여야 합니다. HMAC의 키 전처리와 달리, SequenceMAC의 헤더는 정확한 키 길이를 커밋합니다. 따라서 긴 원시 키는 해당 키의 사전 해시와 동일하지 않으며, 0바이트를 덧붙이면 키가 달라집니다. 구성 요소마다 키 표현이나 길이 메타데이터를 다르게 허용할 수 있는 경우 이 차이가 중요합니다.<sup>[[8]](#references)[[9]](#references)</sup>

```python
key = b"\x00" * 32
mac = sequencehash.SequenceMAC.new(key, digestmod="sha256")
mac.add(header_bytes)
mac.add(body_bytes)
tag = mac.result_with_customizer(b"example:v1:request-mac")
```

Python API와 이에 상응하는 Go 및 Rust 구현은 참고 자료로 제공되지만, protocol 구현은 이 요약을 바탕으로 인코딩을 재현하는 대신 최신 C2SP 사양을 따라야 합니다.<sup>[[8]](#references)[[10]](#references)</sup>

## Password hashing and cracking

### 먼저 확인할 사항<sup>[[4]](#references)</sup>

- **salt가 적용되었나요?** (`salt$hash` 형식 확인)
- **fast hash**(MD5/SHA1/SHA256)인가요, 아니면 **slow KDF**(bcrypt/scrypt/argon2/PBKDF2)인가요?
- **형식 힌트**(hashcat mode / John format)가 있나요?

### 실전 workflow<sup>[[5]](#references)[[6]](#references)</sup>

1. hash를 식별합니다.
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. salt가 없고 흔히 쓰이는 hash라면, crypto workflow 섹션의 온라인 DB와 식별 도구를 사용해 봅니다.
3. 그 외에는 crack을 시도합니다.
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### 악용할 수 있는 흔한 실수

- 여러 사용자가 같은 password를 재사용함 → 하나를 crack한 뒤 pivot합니다.
- hash가 잘렸거나 사용자 지정 변환이 적용됨 → 정규화한 뒤 다시 시도합니다.
- 약한 KDF 파라미터(예: PBKDF2 반복 횟수가 적음) → 여전히 crack할 수 있습니다.

### secret이 뒤에 추가되는 선택 입력 bcrypt oracle

`bcrypt(user_input || secret)`를 반환하는 호출 가능한 helper는 bcrypt 구현이 입력을 72 **bytes** 이후에 조용히 잘라내는 경우, 뒤에 추가된 secret에 대한 정보를 노출할 수 있습니다. UTF-8 인코딩 전에 문자 수를 제한해도 해당 바이트 제한은 적용되지 않습니다. 멀티바이트 문자는 bcrypt 입력을 채우면서 secret의 짧은 접두부만 남길 수 있습니다. 선택한 입력과 반환된 hash를 이용하면 후보 접미사 바이트를 오프라인에서 검사할 수 있습니다. 이를 위해서는 helper의 입력을 제어하고, 정확한 변환과 인코딩 방식을 알아야 하며, 실제로 입력을 자르는 구현이어야 합니다. 호출 가능한 helper나 bcrypt hash만으로 이러한 조건이 충족된다고 볼 수는 없습니다. [pyca/bcrypt 문서](https://github.com/pyca/bcrypt#maximum-password-length)에 따르면 현재 `hashpw`는 72 bytes보다 긴 입력에 오류를 발생시키지만, 이전 동작에서는 입력을 조용히 잘랐습니다. 다른 wrapper는 긴 입력을 사전 해시하거나 거부할 수 있으므로, 입력이 잘린다고 가정하지 말고 설치된 구현을 확인하세요.

복구한 secret을 다른 계정에 사용하려면, 노출된 hash가 **동일한** secret과 변환 방식으로 생성되었다는 근거와 별도의 credential 또는 로그인 경로가 필요합니다. root 권한으로 실행되는 hashing helper는 낮은 권한의 사용자가 유효 정책에 따라 호출할 수 있을 때만 oracle로 검토해야 합니다. 수동적인 host 열거 과정에서 helper를 호출하거나 선택한 password를 제출할 필요는 없습니다.

## References

- [1] [SkullSecurity - hash length-extension attack에 대해 알아야 할 모든 것](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - 키드 해시 메시지 인증 코드](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat 예제 hash](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper 명령줄 옵션](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: HashPump용 `hashpumpy` Python 바인딩](https://pypi.org/project/hashpumpy/)
- [8] [C2SP - SequenceHash 및 SequenceMAC 사양](https://c2sp.org/sequencehash)
- [9] [Trail of Bits - SequenceHash: 모두를 위한 멀티해싱](https://blog.trailofbits.com/2026/10/02/sequencehash-multihashing-for-the-rest-of-us/)
- [10] [Trail of Bits - SequenceHash Python 구현](https://github.com/trailofbits/sequencehash-py)
- [11] [C2SP CCTV - SequenceHash 테스트 벡터](https://github.com/C2SP/CCTV/tree/main/sequencehash)
