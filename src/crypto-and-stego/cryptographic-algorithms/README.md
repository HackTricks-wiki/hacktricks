# 암호학/압축 알고리즘

{{#include ../../banners/hacktricks-training.md}}

## 알고리즘 식별

코드가 **shift rights and lefts, xors and several arithmetic operations**를 사용하고 있다면, 해당 코드는 **cryptographic algorithm**의 구현일 가능성이 높습니다. 여기서는 각 단계를 모두 리버스하지 않고도 **사용된 알고리즘을 식별하는 방법들**을 보여드립니다.

### API functions

**CryptDeriveKey**

이 함수가 사용되었다면, 두 번째 매개변수의 값을 확인하여 어떤 **algorithm이 사용되는지** 알 수 있습니다:

![](<../../images/image (156).png>)

가능한 알고리즘과 할당된 값들의 표는 여기에서 확인하세요: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

주어진 데이터 버퍼를 압축 및 압축 해제합니다.

**CryptAcquireContext**

[the docs](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta)에 따르면: **CryptAcquireContext** 함수는 특정 cryptographic service provider(CSP) 내의 특정 key container에 대한 핸들을 얻는 데 사용됩니다. **이 반환된 핸들은 선택된 CSP를 사용하는 CryptoAPI 함수 호출에서 사용됩니다.**

**CryptCreateHash**

데이터 스트림의 해싱을 시작합니다. 이 함수가 사용되었다면, 두 번째 매개변수의 값을 확인하여 어떤 **algorithm이 사용되는지** 알 수 있습니다:

![](<../../images/image (549).png>)

\
가능한 알고리즘과 할당된 값들의 표는 여기에서 확인하세요: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### 코드 상수

때때로 알고리즘이 특별하고 고유한 값을 사용해야 하기 때문에 식별이 매우 쉬운 경우가 있습니다.

![](<../../images/image (833).png>)

만약 첫 번째 상수를 Google에서 검색하면 다음과 같은 결과를 얻습니다:

![](<../../images/image (529).png>)

따라서, 디컴파일된 함수가 **sha256 calculator**임을 유추할 수 있습니다.\
다른 상수들 중 하나를 검색해도 (아마도) 동일한 결과를 얻을 것입니다.

### 데이터 정보

코드에 특별한 상수가 없다면 **.data section에서 정보를 불러오는** 경우일 수 있습니다.\
해당 데이터를 접근하여 **첫 번째 dword를 그룹화**하고 이전 섹션에서 했던 것처럼 Google에서 검색할 수 있습니다:

![](<../../images/image (531).png>)

이 경우 **0xA56363C6**을 찾아보면 이는 **AES algorithm의 테이블**과 관련되어 있음을 알 수 있습니다.

## RC4 (Symmetric Crypt)

### 특징

다음 세 부분으로 구성됩니다:

- **Initialization stage/**: **0x00부터 0xFF까지의 값들로 구성된 테이블(총 256바이트, 0x100)을 생성**합니다. 이 테이블은 일반적으로 **Substitution Box (또는 SBox)** 라고 불립니다.
- **Scrambling stage**: 앞에서 생성한 테이블을 **루프(0x100 반복)** 돌며 각 값을 **반-무작위(semi-random)** 바이트로 수정합니다. 이 반-무작위 바이트를 만들기 위해 RC4 **key가 사용**됩니다. RC4 **keys**는 **1바이트에서 256바이트까지** 길이를 가질 수 있지만, 일반적으로 5바이트 이상이 권장됩니다. 보통 RC4 키는 16바이트 길이입니다.
- **XOR stage**: 마지막으로 평문이나 암호문은 **앞에서 생성된 값들과 XOR** 처리됩니다. 암호화와 복호화 함수는 동일합니다. 이를 위해 생성된 256바이트를 필요한 만큼 여러 번 반복해서 루프를 돌립니다. 디컴파일된 코드에서는 보통 **%256 (mod 256)**을 사용하는 형태로 인식됩니다.

> [!TIP]
> **disassembly/decompiled 코드에서 RC4를 식별하려면 0x100 크기의 루프가 2번 있는지(키 사용과 함께) 확인하고, 그 다음 입력 데이터를 이전 2개의 루프에서 생성된 256 값들과 XOR 처리하는 부분이 있는지 확인하세요(아마 %256 (mod 256)을 사용).**

### Initialization stage/Substitution Box: (카운터로 256이 사용되고 256 자리 각각에 0이 쓰이는 것을 주목)

![](<../../images/image (584).png>)

### Scrambling Stage:

![](<../../images/image (835).png>)

### XOR Stage:

![](<../../images/image (904).png>)

## AES (Symmetric Crypt)

### 특징

- **substitution boxes 및 lookup tables 사용**
- 특정 lookup table 값들(상수)을 사용함으로써 **AES를 구별할 수 있음**. _상수가 바이너리에 **저장되어 있을 수도 있고** 또는 **동적으로 생성**될 수도 있다는 점에 유의._
- **encryption key**는 **16으로 나누어 떨어져야** 하며(보통 32B), 일반적으로 16B의 **IV**가 사용됩니다.

### SBox constants

![](<../../images/image (208).png>)

## Serpent (Symmetric Crypt)

### 특징

- 사용 예가 드물지만 일부 malware가 사용하는 사례가 있음(Ursnif)
- 길이(매우 긴 함수)를 기반으로 Serpent인지 아닌지 간단히 판별 가능

### 식별

다음 이미지에서 상수 **0x9E3779B9**가 사용되는 것을 확인하세요(이 상수는 **TEA** 같은 다른 암호 알고리즘에서도 사용됩니다).\
또한 **루프 크기(**132**)와 disassembly 명령어 및 코드 예제에서의 XOR 연산 횟수에 주목하세요:

![](<../../images/image (547).png>)

앞서 언급한 것처럼, 이 코드는 내부에 **점프가 거의 없어 매우 긴 함수**로 디컴파일러에서 시각화될 수 있습니다. 디컴파일된 코드는 다음과 비슷하게 보일 수 있습니다:

![](<../../images/image (513).png>)

따라서 이 알고리즘은 **매직 넘버**와 **초기 XOR들**, 매우 긴 함수라는 점을 확인하고, 긴 함수의 몇몇 **명령어**들을 (예: 왼쪽으로 7 비트 시프트, 22 비트 rotate left) 실제 구현과 **비교**하여 식별할 수 있습니다.

## RSA (Asymmetric Crypt)

### 특징

- 대칭 알고리즘보다 더 복잡함
- 상수가 없음! (커스텀 구현은 판별하기 어려움)
- KANAL(crypto analyzer)은 상수에 의존하기 때문에 RSA에 대한 힌트를 보여주지 못함

### 비교로 식별

![](<../../images/image (1113).png>)

- 왼쪽 11행에는 `+7) >> 3`가 있고, 오른쪽 35행에는 `+7) / 8`가 있음(동일)
- 왼쪽 12행은 `modulus_len < 0x040`를 확인하고, 오른쪽 36행은 `inputLen+11 > modulusLen`를 확인함

## MD5 & SHA (hash)

### 특징

- 3개의 함수: Init, Update, Final
- 초기화 함수들이 유사함

### 식별

**Init**

상수들을 확인하면 둘 다 식별할 수 있습니다. sha_init에는 MD5에 없는 상수가 하나 더 있다는 점을 주목하세요:

![](<../../images/image (406).png>)

**MD5 Transform**

더 많은 상수의 사용에 주목하세요

![](<../../images/image (253) (1) (1).png>)

## CRC (hash)

- 데이터의 우발적 변경을 찾는 것이 목적이므로 더 작고 효율적임
- lookup tables를 사용(따라서 상수로 식별 가능)

### 식별

**lookup table 상수들**을 확인하세요:

![](<../../images/image (508).png>)

CRC 해시 알고리즘은 다음과 같은 형태입니다:

![](<../../images/image (391).png>)

## APLib (Compression)

### 특징

- 인식 가능한 상수가 없음
- 알고리즘을 python으로 작성해보고 유사한 것을 온라인에서 검색해볼 수 있음

### 식별

그래프가 꽤 큽니다:

![](<../../images/image (207) (2) (1).png>)

인식하기 위한 **3개의 비교**를 확인하세요:

![](<../../images/image (430).png>)

## Elliptic-Curve Signature Implementation Bugs

### EdDSA scalar range enforcement (HashEdDSA malleability)

- FIPS 186-5 §7.8.2는 HashEdDSA 검증자가 서명 `sig = R || s`를 분리하고 스칼라가 `s \geq n`인 경우 거부하도록 요구합니다(여기서 `n`은 그룹 차수). `elliptic` JS 라이브러리는 이 경계 검사를 건너뛰었으므로, 공격자는 유효한 쌍 `(msg, R || s)`를 알고 있다면 대체 서명 `s' = s + k·n`을 위조하고 `sig' = R || s'`로 다시 인코딩할 수 있습니다.
- 검증 루틴은 단지 `s mod n`만 소비하므로, 바이트 문자열이 달라도 `s`와 합동(congruent)인 모든 `s'`가 수락됩니다. 서명을 정식 토큰으로 취급하는 시스템(블록체인 합의, 재생 캐시, DB 키 등)은 엄격한 구현이 `s'`를 거부하기 때문에 비동기화될 수 있습니다.
- 다른 HashEdDSA 코드를 감사할 때는 파서가 점 `R`과 스칼라 길이 둘 다 검증하는지 확인하세요; 알려진 정상 `s`에 `n`의 배수를 덧붙여 검증기가 닫힘(fail closed) 여부를 확인해 보세요.

### ECDSA truncation vs. leading-zero hashes

- ECDSA 검증기는 메시지 해시 `H`의 왼쪽에서부터 `log2(n)` 비트만 사용해야 합니다. `elliptic`에서 truncation 헬퍼는 `delta = (BN(msg).byteLength()*8) - bitlen(n)`을 계산했는데, `BN` 생성자는 선행 0 옥텟을 제거하므로 secp192r1(192-bit order) 같은 곡선에서는 선행 0 바이트가 ≥4인 해시가 256비트 대신 224비트로 보였습니다.
- 검증기는 64비트 대신 32비트로 우측 시프트하여 서명자가 사용한 값과 일치하지 않는 `E`를 만들었습니다. 따라서 그러한 해시에 대한 유효 서명은 SHA-256 입력의 경우 약 `2^-32`의 확률로 실패합니다.
- “정상” 벡터와 선행-제로 변형(예: Wycheproof `ecdsa_secp192r1_sha256_test.json`의 case `tc296`) 모두를 대상 구현에 투입해 보세요; 검증기가 서명자와 일치하지 않으면 exploitable한 truncation 버그를 찾은 것입니다.

### Wycheproof 벡터를 라이브러리에 적용해보기
- Wycheproof는 잘못된 포인트, malleable 스칼라, 특이한 해시 및 기타 코너 케이스를 인코딩한 JSON 테스트 세트를 제공합니다. `elliptic`(또는 어떤 crypto library)이든 이를 대상으로 하는 harness를 만드는 것은 간단합니다: JSON을 로드하고 각 테스트 케이스를 deserialize한 뒤, 구현이 예상된 `result` 플래그와 일치하는지 assert 하세요.
```javascript
for (const tc of ecdsaVectors.testGroups) {
const curve = new EC(tc.curve);
const pub = curve.keyFromPublic(tc.key, 'hex');
const ok = curve.verify(tc.msg, tc.sig, pub, 'hex', tc.msgSize);
assert.strictEqual(ok, tc.result === 'valid');
}
```
- 실패는 spec violations와 false positives를 구분하기 위해 분류되어야 합니다. 위의 두 버그의 경우, 실패한 Wycheproof 케이스는 즉시 누락된 스칼라 범위 검사(EdDSA)와 잘못된 해시 절단(ECDSA)을 지적했습니다.
- harness를 CI에 통합하여 스칼라 파싱, 해시 처리 또는 좌표 유효성에 대한 회귀가 도입되는 즉시 테스트가 실행되도록 하세요. 이는 미묘한 bignum 변환을 쉽게 잘못 처리하는 고급 언어(JS, Python, Go)에서 특히 유용합니다.

## References

- [Trail of Bits - We found cryptography bugs in the elliptic library using Wycheproof](https://blog.trailofbits.com/2025/11/18/we-found-cryptography-bugs-in-the-elliptic-library-using-wycheproof/)
- [Wycheproof Test Suite](https://github.com/C2SP/wycheproof)

{{#include ../../banners/hacktricks-training.md}}
