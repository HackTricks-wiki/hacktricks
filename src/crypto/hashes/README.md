# Hashes, MACs 및 KDFs

{{#include ../../banners/hacktricks-training.md}}

## 흔한 CTF 패턴

- "Signature"가 실제로는 `hash(secret || message)`인 경우 → length extension.
- Salt가 없는 password hash → 더 빠른 반복 cracking 및 사전 계산된 lookup 공격.
- hash와 MAC 혼동 (hash != 인증).

## 입력을 선택하는 MD5 hash 검색

다음 Python 예제는 서로 다른 두 가지 출력 패턴을 검색합니다. 지정한 MD5 접미사와 `0e`로 시작하고 뒤에 숫자만 오는 MD5 값입니다. 후자의 패턴은 애플리케이션이 숫자 문자열을 느슨하게 비교할 때 관련이 있습니다. [PHP의 느슨한 비교](../../network-services-pentesting/pentesting-web/php-tricks-esp/README.md#loose-comparisons-and-type-juggling)에서 PHP에 한정된 동작과 버전별 유의 사항을 확인하세요.

### MD5 hash 접미사 brute force

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

### 기법

서버가 다음과 같은 "서명"을 계산하고:

`sig = HASH(secret || message)`

MD5, SHA-1 또는 SHA-256 같은 Merkle-Damgård hash를 사용한다면 length-extension attack이 가능할 수 있습니다.

다음 정보를 알고 있다면:

- `message`
- `sig`
- hash function
- `len(secret)`(또는 이를 brute-force할 수 있는 경우)

secret을 몰라도 다음에 대한 유효한 서명을 계산할 수 있습니다.

`message || padding || appended_data`

<sup>[[1]](#references)</sup>

### 중요한 제한 사항: HMAC은 영향받지 않음

Length-extension attack은 `HASH(secret || message)` 같은 취약한 prefix 구성에 적용됩니다. 별도의 inner 및 outer hash 연산에 key를 결합하는 HMAC 구성(예: HMAC-SHA256)을 노출하지는 않습니다.<sup>[[1]](#references)[[2]](#references)</sup>

Web API에서 이러한 서명을 찾고 테스트하는 방법은 [Request and parameter signatures](../../pentesting-web/web-api-pentesting.md#request-and-parameter-signatures)를 확인하세요.

### 도구

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), HashPump length-extension 도구의 Python 바인딩<sup>[[7]](#references)</sup>

### 유용한 설명

[Everything you need to know about hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## 모호한 튜플 해싱 및 MAC

### Boundary-confusion attack

Incremental hash API는 호출 경계를 인증하지 않습니다. `update(A); update(B)`는 `update(A + B)`와 동일한 바이트 문자열을 해싱합니다. 따라서 원시 연결을 해싱하거나 MAC을 생성해도 튜플은 인증되지 않습니다. 인접 필드의 길이가 가변적이면, 공격자는 기본 hash에서 collision을 찾지 않고도 바이트를 다시 분할해 다른 튜플을 만들 수 있습니다.<sup>[[8]](#references)[[9]](#references)</sup>

```python
import hashlib

def raw_hash(parts):
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()

assert raw_hash([b"alice", b"admin"]) == raw_hash([b"aliceadmin", b""])
```

검증자가 digest가 필드의 의미를 고정한다고 믿지만, 공격자가 제어하는 입력이 다른 파서나 프로토콜 단계에 도달해 경계를 다르게 지정할 수 있으면 이 취약점이 악용될 수 있습니다. 그러면 commitment에 대체 opening이 생기고 Fiat-Shamir transcript가 다른 statement로 해석될 수 있습니다. HMAC는 [hash length extension](#hash-length-extension-attack)을 방지하지만, `HMAC(K, A || B)`에도 여전히 이런 튜플 인코딩 모호성이 있습니다. 두 튜플이 동일한 메시지 바이트를 만들기 때문입니다.<sup>[[8]](#references)[[9]](#references)</sup>

이 감사 절차를 사용해 모호한 튜플 인코딩이 보안 경계를 넘는지 테스트하세요.<sup>[[8]](#references)[[9]](#references)</sup>

1. `HASH(A || B)`, `HMAC(K, A || B)`, 그리고 두 개 이상의 필드에 대해 연속으로 호출되는 `update()`/`Write()`를 찾습니다.
2. 공격자가 제어하거나 길이가 가변인 필드를 모두 표시합니다. 전체 연결 결과는 그대로 유지하면서 각 경계를 넘어 바이트를 옮겨 봅니다. 빈 필드도 포함하세요.
3. 구분자 방식에서 입력에 포함될 수 있는 구분자 바이트, 이스케이프 처리의 불일치, 일부 필드에만 길이 인코딩을 적용하는 설계를 확인합니다.
4. 인증된 바이트를 각 소비자가 어떻게 파싱하는지 추적합니다. 대체 파티션이 보안 결정, proof statement, 레코드, 트랜잭션 또는 commitment opening을 바꾸는 경우에만 유효한 후보입니다. 고정 길이 필드나 정규형의 단사적 직렬화는 이 특정 공격을 방지합니다.
5. 동일하게 인코딩된 digest가 다른 프로토콜 버전, 메시지 유형, 라운드 또는 애플리케이션에서도 허용되는지 확인합니다. 호출자가 각 항목을 분리해 유지하리라 기대하지 말고 이러한 컨텍스트를 명시적으로 바인딩하세요.

### SequenceHash 및 SequenceMAC

SequenceHash는 바이트 문자열 시퀀스를 위한 해시 알고리즘 비종속적 구성입니다. 각 `add()` 작업은 원자적입니다. 값과 고정된 16바이트 little-endian 길이 접미사를 내부 해시에 추가합니다. 빈 값도 서로 다른 객체로 유지됩니다. 외부 해시는 길이 확장이 가능한 내부 상태가 노출되지 않도록 하며, 선택적 customization string은 도메인 분리를 제공합니다. `add()`를 기반 해시 API의 일반적인 쓰기 호출로 대체하지 마세요.<sup>[[8]](#references)[[9]](#references)</sup>

```python
import sequencehash

h = sequencehash.SequenceHash.new("sha256")
h.add(b"alice")
h.add(b"admin")
digest = h.result_with_customizer(b"example:v1:user-record")
```

프로토콜 정의의 일부로 customizer를 선택하고, 애플리케이션, 프로토콜 버전, 메시지 유형, 라운드를 구분할 수 있는 충분한 정보를 포함하세요. SequenceHash를 사용하려면 모든 참여자가 필드 순서, 바이트 인코딩, 정규 직렬화 방식에 동의해야 하며, 누락된 필드는 보호할 수 없습니다. 포트는 C2SP의 중간 및 최종 테스트 벡터와 대조해 확인해야 합니다.<sup>[[8]](#references)[[11]](#references)</sup>

인증에는 SequenceMAC이 동일한 원자적 인코딩 및 customization 인터페이스를 제공합니다. 키는 최소 32바이트여야 합니다. HMAC의 키 전처리와 달리, SequenceMAC의 헤더에는 정확한 키 길이가 반영됩니다. 긴 원시 키는 그 키의 사전 해시와 동등하지 않으며, 0바이트를 덧붙이면 키가 달라집니다. 구성 요소마다 서로 다른 키 표현이나 길이 메타데이터를 허용할 때 이 차이가 중요합니다.<sup>[[8]](#references)[[9]](#references)</sup>

```python
key = b"\x00" * 32
mac = sequencehash.SequenceMAC.new(key, digestmod="sha256")
mac.add(header_bytes)
mac.add(body_bytes)
tag = mac.result_with_customizer(b"example:v1:request-mac")
```

The Python API와 이에 상응하는 Go 및 Rust 구현을 참고할 수 있지만, 프로토콜 구현은 이 요약에서 인코딩을 재현하는 대신 현재 C2SP 사양을 따라야 합니다.<sup>[[8]](#references)[[10]](#references)</sup>

## 비밀번호 해싱 및 크래킹

### 먼저 확인할 사항<sup>[[4]](#references)</sup>

- **salt가 적용되었나요?** (`salt$hash` 형식을 찾아보세요)
- **빠른 해시**(MD5/SHA1/SHA256)인가요, 아니면 **느린 KDF**(bcrypt/scrypt/argon2/PBKDF2)인가요?
- **형식 힌트**(hashcat 모드 / John 형식)가 있나요?

### 실용적인 워크플로<sup>[[5]](#references)[[6]](#references)</sup>

1. 해시를 식별합니다.
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. salt가 없고 흔한 해시라면, 온라인 DB와 crypto 워크플로 섹션의 식별 도구를 사용해 보세요.
3. 그 외에는 크래킹합니다.
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### 악용할 수 있는 흔한 실수

- 여러 사용자가 같은 비밀번호를 재사용함 → 하나를 크래킹한 뒤 다른 대상으로 피벗합니다.
- 잘린 해시 / 사용자 지정 변환 → 정규화한 뒤 다시 시도합니다.
- 취약한 KDF 파라미터(예: 낮은 PBKDF2 반복 횟수) → 여전히 크래킹할 수 있습니다.

### secret을 뒤에 덧붙이는 선택 입력 bcrypt 오라클

`bcrypt(user_input || secret)`을 반환하는 호출 가능한 헬퍼는 bcrypt 구현이 입력을 72 **바이트** 이후에서 조용히 잘라내는 경우, 덧붙인 secret에 관한 정보를 노출할 수 있습니다. UTF-8 인코딩 전에 문자 수를 제한해도 이 바이트 제한을 적용할 수는 없습니다. 멀티바이트 문자는 bcrypt 입력을 채우면서 secret의 짧은 접두부가 들어갈 공간만 남길 수 있습니다. 선택한 입력과 반환된 해시를 이용하면 후보 접미부 바이트를 오프라인에서 검사할 수 있습니다. 이를 위해서는 헬퍼 입력을 제어할 수 있어야 하고, 정확한 변환 및 인코딩 방식을 알아야 하며, 실제로 입력을 자르는 구현이어야 합니다. 호출 가능한 헬퍼나 bcrypt 해시만으로는 이 과정이 성립한다고 볼 수 없습니다. [pyca/bcrypt 문서](https://github.com/pyca/bcrypt#maximum-password-length)에 따르면 현재 `hashpw`는 72바이트를 초과하는 입력에 오류를 발생시키지만, 이전 동작은 입력을 조용히 잘랐습니다. 다른 래퍼는 입력을 미리 해싱하거나 긴 입력을 거부할 수 있으므로, 잘린다고 가정하지 말고 설치된 구현을 확인하세요.

복구한 secret을 다른 계정에 사용하려면, 노출된 해시가 **동일한** secret과 변환 방식으로 생성되었다는 증거와 별도의 자격 증명 또는 로그인 경로도 필요합니다. root 권한으로 실행되는 해싱 헬퍼는 낮은 권한의 사용자가 유효 정책에 따라 이를 호출할 수 있을 때만 오라클로 검토해야 합니다. 수동적인 호스트 열거를 위해 헬퍼를 호출하거나 선택한 비밀번호를 제출할 필요는 없습니다.

## References

- [1] [SkullSecurity - 해시 길이 확장 공격에 대해 알아야 할 모든 것](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - 키드 해시 메시지 인증 코드](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP 비밀번호 저장 치트 시트](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat 예제 해시](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper 명령줄 옵션](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: HashPump용 `hashpumpy` Python 바인딩](https://pypi.org/project/hashpumpy/)
- [8] [C2SP - SequenceHash 및 SequenceMAC 사양](https://c2sp.org/sequencehash)
- [9] [Trail of Bits - SequenceHash: 모두를 위한 멀티해싱](https://blog.trailofbits.com/2026/10/02/sequencehash-multihashing-for-the-rest-of-us/)
- [10] [Trail of Bits - SequenceHash Python 구현](https://github.com/trailofbits/sequencehash-py)
- [11] [C2SP CCTV - SequenceHash 테스트 벡터](https://github.com/C2SP/CCTV/tree/main/sequencehash)
