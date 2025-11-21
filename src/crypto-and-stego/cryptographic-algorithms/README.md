# 암호화/압축 알고리즘

{{#include ../../banners/hacktricks-training.md}}

## 알고리즘 식별

코드가 **shift rights and lefts, xors and several arithmetic operations**를 사용하는 것으로 끝난다면, 이는 **암호화 알고리즘**의 구현일 가능성이 높습니다. 여기서는 각 단계를 리버스하지 않고도 사용된 알고리즘을 **식별하는 몇 가지 방법**을 보여줍니다.

### API 함수들

**CryptDeriveKey**

이 함수가 사용되었다면, 두 번째 매개변수의 값을 확인하여 어떤 **algorithm이 사용되는지** 알 수 있습니다:

![](<../../images/image (156).png>)

가능한 알고리즘과 할당된 값들의 표는 여기에서 확인하세요: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

주어진 데이터 버퍼를 압축하고 압축을 해제합니다.

**CryptAcquireContext**

문서에 따르면: The **CryptAcquireContext** function is used to acquire a handle to a particular key container within a particular cryptographic service provider (CSP). **This returned handle is used in calls to CryptoAPI** functions that use the selected CSP.

**CryptCreateHash**

스트림 데이터의 해싱을 시작합니다. 이 함수가 사용되었다면, 두 번째 매개변수의 값을 확인하여 어떤 **algorithm이 사용되는지** 알 수 있습니다:

![](<../../images/image (549).png>)

\
가능한 알고리즘과 할당된 값들의 표는 여기에서 확인하세요: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### 코드 상수

때로는 특정하고 고유한 값이 필요하기 때문에 알고리즘을 식별하기가 매우 쉬운 경우가 있습니다.

![](<../../images/image (833).png>)

첫 번째 상수를 Google에서 검색하면 다음과 같은 결과를 얻습니다:

![](<../../images/image (529).png>)

따라서, 디컴파일된 함수가 **sha256 계산기**라고 추정할 수 있습니다.\
다른 상수들을 검색해도 (아마) 동일한 결과를 얻을 것입니다.

### 데이터 정보

코드에 유의미한 상수가 없다면 .data 섹션에서 정보를 **로드**하고 있을 수 있습니다.\
해당 데이터를 접근하여 **첫 dword를 그룹화**한 뒤 앞서 한 것처럼 Google에 검색해 보세요:

![](<../../images/image (531).png>)

이 경우 **0xA56363C6**을 검색하면 이것이 **AES 알고리즘의 테이블**과 관련되어 있음을 찾을 수 있습니다.

## RC4 **(대칭 암호)**

### 특성

구성은 주로 3부분으로 나뉩니다:

- **Initialization stage/**: **0x00부터 0xFF까지의 값들로 이루어진 테이블**(총 256바이트, 0x100)을 생성합니다. 이 테이블은 일반적으로 **Substitution Box**(또는 SBox)라고 합니다.
- **Scrambling stage**: 앞에서 만든 테이블을 **루프(0x100 반복)**로 순회하면서 각 값을 **반무작위(semi-random)** 바이트로 수정합니다. 이 반무작위 바이트를 만들기 위해 RC4 **key가 사용**됩니다. RC4 **keys**는 길이가 **1에서 256 바이트** 사이일 수 있으나 보통 5바이트 이상을 권장합니다. 일반적으로 RC4 키는 16바이트 길이입니다.
- **XOR stage**: 마지막으로 평문 또는 암호문을 이전에 생성한 값들과 **XOR**합니다. 암호화와 복호화 함수는 동일합니다. 이를 위해 생성된 256바이트를 필요한 만큼 여러 번 루프합니다. 디컴파일된 코드에서 이것은 보통 **%256 (mod 256)** 으로 인식됩니다.

> [!TIP]
> **디스어셈블리/디컴파일 코드에서 RC4를 식별하려면 0x100 크기의 루프가 2개(키 사용) 있고, 그 후 입력 데이터를 앞서 2개의 루프에서 생성된 256값과 XOR하는 부분이 있으며 아마도 %256 (mod 256)을 사용하는지 확인하세요.**

### **Initialization stage/Substitution Box:** (카운터로 256이 사용되는 것과 256개의 자리마다 0이 쓰이는 것에 주목)

![](<../../images/image (584).png>)

### **Scrambling Stage:**

![](<../../images/image (835).png>)

### **XOR Stage:**

![](<../../images/image (904).png>)

## **AES (대칭 암호)**

### **특성**

- **substitution boxes와 lookup tables**의 사용
- 특정 lookup table 값들(상수)의 사용으로 **AES를 구별**할 수 있습니다. _상수는 바이너리 안에 **저장되어 있거나** 또는 **동적으로 생성**될 수 있습니다._
- **encryption key**는 **16으로 나누어떨어져야** 하며(보통 32B), 보통 16B 크기의 **IV**가 사용됩니다.

### SBox constants

![](<../../images/image (208).png>)

## Serpent **(대칭 암호)**

### 특성

- 악성코드에서 드물게 사용되지만 사례(Ursnif)가 있습니다.
- 길이(매우 긴 함수)에 근거해 Serpent인지 여부를 판단하기 쉽습니다.

### 식별 방법

다음 이미지에서 **0x9E3779B9** 상수가 사용되는 것을 확인하세요(이 상수는 **TEA** 같은 다른 암호 알고리즘에서도 사용됩니다).\
또한 **루프 크기**(**132**)와 **disassembly 명령어 및 코드 예제에서의 XOR 연산 수**에 주목하세요:

![](<../../images/image (547).png>)

앞서 언급했듯이, 이 코드는 내부에 **점프가 거의 없어 매우 긴 함수**로 디컴파일러에서 보일 수 있습니다. 디컴파일된 코드는 다음과 같이 보일 수 있습니다:

![](<../../images/image (513).png>)

따라서 매직 넘버와 초기 XOR들을 확인하고, 매우 긴 함수인지 확인하며, 해당 긴 함수의 몇몇 명령어(예: left shift by 7, rotate left by 22)를 구현과 **비교**함으로써 이 알고리즘을 식별할 수 있습니다.

## RSA **(비대칭 암호)**

### 특성

- 대칭 알고리즘보다 더 복잡합니다.
- 상수가 거의 없습니다! (커스텀 구현은 식별하기 어렵습니다)
- KANAL (a crypto analyzer)은 상수에 의존하기 때문에 RSA에 대한 힌트를 잘 보여주지 못합니다.

### 비교를 통한 식별

![](<../../images/image (1113).png>)

- 왼쪽 11행에는 `+7) >> 3`가 있고, 오른쪽 35행에는 `+7) / 8`이 있어 동일합니다.
- 왼쪽 12행은 `modulus_len < 0x040`을 체크하고, 오른쪽 36행은 `inputLen+11 > modulusLen`을 체크합니다.

## MD5 & SHA (해시)

### 특성

- 3개의 함수: Init, Update, Final
- 유사한 초기화 함수들

### 식별

**Init**

상수를 확인하여 둘을 식별할 수 있습니다. sha_init에는 MD5에는 없는 상수가 하나 더 있음을 주의하세요:

![](<../../images/image (406).png>)

**MD5 Transform**

더 많은 상수의 사용에 주목하세요

![](<../../images/image (253) (1) (1).png>)

## CRC (해시)

- 데이터의 우연한 변경을 찾는 것이 목적이므로 더 작고 효율적입니다.
- lookup tables를 사용합니다(따라서 상수로 식별할 수 있음).

### 식별

**lookup table constants**를 확인하세요:

![](<../../images/image (508).png>)

CRC 해시 알고리즘은 다음과 같습니다:

![](<../../images/image (391).png>)

## APLib (압축)

### 특성

- 인식 가능한 상수가 없음
- 알고리즘을 Python으로 구현해 보고 온라인에서 유사한 것을 검색해 볼 수 있습니다

### 식별

그래프는 꽤 큽니다:

![](<../../images/image (207) (2) (1).png>)

식별을 위한 **3개의 비교**를 확인하세요:

![](<../../images/image (430).png>)

## 타원 곡선 서명 구현 버그

### EdDSA scalar range enforcement (HashEdDSA malleability)

- FIPS 186-5 §7.8.2는 HashEdDSA 검증자가 서명 `sig = R || s`를 분할하고 스칼라가 `s \geq n`인 경우 거부하도록 요구합니다(여기서 `n`은 그룹 차수). `elliptic` JS 라이브러리는 그 경계 검사를 건너뛰었기 때문에, 공격자는 유효한 쌍 `(msg, R || s)`을 알고 있다면 대체 서명 `s' = s + k·n`을 위조하고 `sig' = R || s'`로 재인코딩할 수 있습니다.
- 검증 루틴은 `s mod n`만 소비하므로, 서로 다른 바이트 문자열인 모든 `s'`가 `s`와 합동이면 수락됩니다. 서명을 정식 토큰(블록체인 합의, 재생 캐시, DB 키 등)으로 취급하는 시스템은 엄격한 구현이 `s'`를 거부하기 때문에 동기화가 깨질 수 있습니다.
- 다른 HashEdDSA 코드를 감사할 때 파서가 점 `R`과 스칼라 길이 둘 다를 검증하는지 확인하세요; 알려진 정상 `s`에 `n`의 배수를 추가해 보고 검증자가 안전하게 거부하는지 확인해 보세요.

### ECDSA truncation vs. leading-zero hashes

- ECDSA 검증자는 메시지 해시 `H`의 왼쪽에서 `log2(n)` 비트만 사용해야 합니다. `elliptic`에서는 truncation 헬퍼가 `delta = (BN(msg).byteLength()*8) - bitlen(n)`을 계산했는데, `BN` 생성자는 선행 0 옥텟을 제거하므로 secp192r1(192-bit order)와 같은 곡선에서는 처음에 ≥4 바이트가 0인 해시가 256비트 대신 224비트로 나타나는 문제가 있었습니다.
- 검증자는 64비트 대신 32비트만 오른쪽으로 시프트하여 서명자(sign­er)가 사용한 값과 일치하지 않는 `E`를 생성했습니다. 따라서 해당 해시에 대한 유효한 서명은 SHA-256 입력에 대해 ≈`2^-32` 확률로 실패합니다.
- 표준 벡터와 선행-제로 변형(e.g., Wycheproof `ecdsa_secp192r1_sha256_test.json`의 `tc296`)을 대상 구현에 제공해 보세요; 검증자가 서명자와 불일치하면 취약한 잘못된 절단 버그를 찾은 것입니다.

### Wycheproof 벡터를 라이브러리에 적용하기
- Wycheproof는 손상된 점들(malformed points), 가변적 스칼라(malleable scalars), 비정상 해시 및 다른 모서리 케이스를 인코딩한 JSON 테스트 세트를 제공합니다. `elliptic`(또는 어떤 crypto library)이든 이를 둘러싼 하니스(harness)를 만드는 것은 간단합니다: JSON을 로드하고, 각 테스트 케이스를 deserialize한 다음 구현이 기대되는 `result` 플래그와 일치하는지 확인하면 됩니다.
```javascript
for (const tc of ecdsaVectors.testGroups) {
const curve = new EC(tc.curve);
const pub = curve.keyFromPublic(tc.key, 'hex');
const ok = curve.verify(tc.msg, tc.sig, pub, 'hex', tc.msgSize);
assert.strictEqual(ok, tc.result === 'valid');
}
```
- 실패는 스펙 위반(spec violations)과 false positives를 구분하도록 우선 분류해야 한다. 위의 두 버그의 경우, 실패한 Wycheproof 케이스가 즉시 누락된 scalar range checks (EdDSA)와 잘못된 hash truncation (ECDSA)를 가리켰다.
- harness를 CI에 통합하여 scalar parsing, hash handling, 또는 coordinate validity의 회귀가 도입되는 즉시 테스트가 트리거되도록 하라. 이는 미묘한 bignum 변환을 실수하기 쉬운 고수준 언어(JS, Python, Go)에서 특히 유용하다.

## 참고자료

- [Trail of Bits - We found cryptography bugs in the elliptic library using Wycheproof](https://blog.trailofbits.com/2025/11/18/we-found-cryptography-bugs-in-the-elliptic-library-using-wycheproof/)
- [Wycheproof Test Suite](https://github.com/C2SP/wycheproof)

{{#include ../../banners/hacktricks-training.md}}
