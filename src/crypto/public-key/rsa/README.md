# RSA 공격

{{#include ../../../banners/hacktricks-training.md}}

## 빠른 초기 분석

다음 정보를 수집합니다.

- `n`, `e`, `c` (그리고 추가 암호문이 있다면 함께)
- 메시지 간의 관계 (같은 평문인지, modulus를 공유하는지, 구조화된 평문인지)
- `leak` 정보 (`p/q` 일부, `d` 비트, `dp/dq`, 알려진 padding)

그런 다음 다음을 시도합니다.

- 인수분해 확인 (Factordb / 작은 편이라면 `sage: factor(n)`)
- 낮은 지수 패턴 (`e=3`, broadcast)
- Common modulus / 소수 반복 사용 여부
- 거의 알고 있는 값이 있다면 lattice 기법 (Coppersmith/LLL)

## 일반적인 RSA 공격

### Common modulus

두 암호문 `c1, c2`가 **같은 modulus** `n` 아래에서 **같은 메시지**를 서로 다른 지수 `e1, e2`로 암호화했고 (`gcd(e1,e2)=1`), 확장 유클리드 알고리즘을 사용하면 `m`을 복구할 수 있습니다.

`m = c1^a * c2^b mod n` where `a*e1 + b*e2 = 1`.

예시 절차:

1. `(a, b) = xgcd(e1, e2)`를 계산해 `a*e1 + b*e2 = 1`이 되도록 합니다.
2. `a < 0`이면 `c1^a`를 `inv(c1)^{-a} mod n`으로 해석합니다 (`b`도 동일).
3. 곱한 뒤 `n`으로 나눈 나머지를 구합니다.

### 여러 modulus에서 소수 공유

같은 challenge에서 여러 RSA modulus를 얻었다면, 소수를 공유하는지 확인합니다.

- `gcd(n1, n2) != 1`이면 키 생성에 치명적인 오류가 발생한 것입니다.

CTF에서 "키를 빠르게 많이 생성했다"거나 "난수가 부실했다"는 식으로 자주 등장합니다.

### Sparse / short-sleeve moduli

일부 결함 있는 big-integer generator는 구조를 public modulus에 직접 노출합니다. 각 limb에는 작은 무작위 부분 필드만 들어가고 나머지 비트는 `0`입니다. 실제로는 `n` 전체에 일정한 간격으로 0 블록이 반복되며, 대개 32비트 또는 128비트 limb 경계에 맞춰 나타납니다.<sup>[[1]](#references)</sup>

빠른 확인 방법:

- `n`을 hex로 덤프하고 일정한 간격으로 반복되는 0 구간이 있는지 확인합니다.
- `n`을 limb (`2^32`, `2^64`, `2^128`) 단위로 다시 나눈 뒤 각 limb의 값이 비정상적으로 작은지 살펴봅니다.
- host-key 생성이 취약하다고 의심되면 **badkeys** 같은 도구로 public SSH/TLS 키를 검사합니다.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

이는 단순한 통계적 편향보다 심각합니다. 개인 소인수 `p`와 `q`가 모두 short-sleeve라면 modulus를 **쉽게 인수분해할 수 있습니다**.<sup>[[1]](#references)</sup>

### 구조화된 RSA 키의 다항식 인수분해

의심되는 limb 너비를 `w`라고 할 때, modulus를 밑 `B = 2^w`로 나타냅니다.

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

대입은 곱셈을 보존하므로 `f_a(B) * f_c(B) = (f_a * f_c)(B)`입니다. 인수의 limb 계수도 희소하다면 다음이 성립합니다.

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

공격 절차:

1. limb 너비 `w`를 추측합니다.
2. 밑 `2^w`를 사용해 public modulus `n`을 `f_n(x)`로 변환합니다.
3. 정수에서 `f_n(x)`를 인수분해합니다.
4. 후보 인수에 `B = 2^w`를 대입합니다.
5. 어떤 후보의 곱이 `n`이 되는지 확인합니다.

이 방법은 **일반적인 RSA를 깨지 않습니다**. 소인수 자체의 limb 계수가 매우 작고 구조화된 경우에만 작동합니다.<sup>[[1]](#references)</sup>

### Shifted limb leakage

희소 바이트가 각 limb의 하위 쪽에 정렬되어 있다고 보장할 수는 없습니다. 밑 `2^w`로 직접 변환했을 때 계수가 크다면, 해당 limb 기저에서 `2^i p`와 `2^j q`가 희소해지는 `i,j`를 찾습니다. public modulus에서 곱 다항식을 유도하고 인수분해한 뒤, 다시 조합해 원래의 정수 인수를 구할 수 있습니다.<sup>[[1]](#references)</sup>

### 구현상 문제 징후: byte-to-limb RNG 버그

위험한 패턴은 **32비트 limb** 개수를 계산하고, 그 개수만큼의 **바이트**만 할당한 다음 이를 limb 배열에 복사하는 것입니다.

```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```

이렇게 하면 각 32-bit limb에는 **8비트의 엔트로피**만 있고 마지막 limb에는 강제로 최상위 비트가 설정됩니다. 그 결과 생성된 RSA 소수는 공개 키만으로도 종종 식별하고 인수분해할 수 있습니다.<sup>[[1]](#references)</sup>

### DSA 관련 실패 유형

같은 잘못된 big-integer 루틴을 DSA 개인 지수 생성에도 재사용하면, 공개 키 `y = g^x`에서 `x`의 탐색 공간이 **크게 줄어들고 구조화된 형태로** 드러날 수 있습니다. limb 패턴을 파악하면 **baby-step giant-step**과 같은 discrete-log 공격을 공개 파라미터에 적용하는 것이 현실적으로 가능해질 수 있습니다.<sup>[[1]](#references)</sup>

### Håstad broadcast / low exponent

같은 평문을 작은 `e`(흔히 `e=3`)를 사용해 여러 수신자에게 보내고 적절한 padding을 적용하지 않았다면, CRT와 정수근을 이용해 `m`을 복구할 수 있습니다.

기술적 조건:

같은 메시지의 ciphertext가 pairwise-coprime한 모듈러스 `n_i`를 사용해 `e`개 있다면:

- CRT를 사용해 곱 `N = Π n_i`에 대한 `M = m^e`를 복구합니다.
- `m^e < N`이면 `M`은 실제 정수 거듭제곱이므로 `m = integer_root(M, e)`입니다.

### Wiener attack: 작은 개인 지수

`d`가 너무 작으면 continued fraction을 사용해 `e/n`으로부터 `d`를 복구할 수 있습니다.

### Textbook RSA의 함정

다음과 같은 경우:

- OAEP/PSS 없이 raw modular exponentiation 사용
- Deterministic encryption 사용

대수적 공격과 oracle 악용이 훨씬 더 쉬워질 수 있습니다.

### 도구

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## 관련 메시지 패턴

같은 modulus를 사용한 두 ciphertext의 메시지가 대수적으로 관련되어 있다면(예: `m2 = a*m1 + b`), Franklin–Reiter와 같은 "related-message" 공격을 고려하세요. 일반적으로 다음 조건이 필요합니다:

- 같은 modulus `n`
- 같은 exponent `e`
- 평문 사이의 관계를 알고 있음

실제로는 Sage에서 `n`을 법으로 하는 다항식을 설정하고 GCD를 계산해 해결하는 경우가 많습니다.

## Lattices / Coppersmith

부분 비트, 구조화된 평문 또는 미지수가 작은 근접 관계가 있을 때 사용하세요.

부분 정보가 있는 경우 Lattice 기법(LLL/Coppersmith)이 사용됩니다:

- 일부만 알려진 평문 (알 수 없는 뒷부분이 있는 구조화된 메시지)
- 일부만 알려진 `p`/`q` (상위 비트가 leak됨)
- 관련 값 사이의 작은 미지 차이

### 알아볼 만한 단서

챌린지에서 흔히 볼 수 있는 힌트:

- "p의 상위/하위 비트가 leak되었습니다"
- "flag가 다음과 같이 포함되어 있습니다: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "RSA를 사용했지만 작은 random padding을 썼습니다"

### 도구 사용

실제로는 LLL을 위해 Sage를 사용하고, 해당 인스턴스에 맞는 알려진 template을 사용합니다.

시작하기 좋은 자료:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- 개요 형식의 참고 자료: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - 다항식을 이용한 "short-sleeve" RSA 키 인수분해](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [badkeys 독립 실행형 도구](https://github.com/badkeys/badkeys)
{{#include ../../../banners/hacktricks-training.md}}

