# 공개키 암호

{{#include ../../banners/hacktricks-training.md}}

고급 CTF 암호학 문제에는 RSA, 타원곡선 암호(ECC), ECDSA, 격자 또는 취약한 난수성이 자주 등장합니다.

## 권장 도구

- 모듈러 연산, 타원곡선 및 격자 축약을 위한 [SageMath](https://www.sagemath.org/)<sup>[[1]](#references)</sup>
- 일반적인 RSA 취약점을 테스트하기 위한 [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)<sup>[[2]](#references)</sup>
- 정수에 알려진 인수가 있는지 확인하기 위한 [FactorDB](https://factordb.com/)<sup>[[3]](#references)</sup>
- 키 파싱, 서명 및 검증을 위한 Python [`ecdsa` 라이브러리](https://ecdsa.readthedocs.io/)<sup>[[7]](#references)</sup>

## RSA

문제에서 `n`, `e`, `c`와 함께 모듈러스 공유, 작은 지수, 부분 키 비트 또는 관련 메시지 같은 힌트를 제공하면 여기서 시작하세요.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

서명이 관련된 경우, 기반이 되는 이산 로그 문제를 풀어야 한다고 가정하기 전에 nonce 재사용, 편향 또는 정보 노출이 있는지 확인하세요.

### ECDSA nonce 재사용 / 편향

ECDSA에서는 메시지마다 새로운 비밀 숫자 `k`가 필요합니다. 같은 `k`로 서로 다른 두 메시지 해시에 서명하면, 공개된 서명 값으로 개인 키를 복구할 수 있습니다.<sup>[[4]](#references)</sup>

`k`가 동일하지 않더라도, 여러 서명에서 nonce 비트에 편향이 있거나 정보가 노출되면 격자 기반 복구가 가능할 수 있습니다.<sup>[[5]](#references)</sup>

`k` 재사용 시의 기술적 복구 방법:<sup>[[4]](#references)</sup>

ECDSA 서명 방정식(군의 위수 `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

두 메시지 `m1, m2`에 같은 `k`를 재사용해 서명 `(r, s1)` 및 `(r, s2)`를 생성한 경우:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### 잘못된 곡선 공격

프로토콜이 입력 점이 예상된 곡선 위에 있고 올바른 부분군에 속하는지 검증하지 않으면, 공격자는 더 약한 군에서 연산을 수행하도록 유도해 비밀 스칼라에 관한 정보를 복구할 수 있습니다. SEC 1에는 이러한 입력을 방지하기 위한 공개키 검증 절차가 명시되어 있습니다.<sup>[[6]](#references)</sup>

기술 참고 사항:

- 점이 무한원점이 아닌지, 좌표가 유효한지, 곡선 방정식을 만족하는지, 필요한 부분군에 속하는지 검증하세요.<sup>[[6]](#references)</sup>
- CTF 문제에서는 서버가 공격자가 선택한 점에 비밀 스칼라를 곱하고 파생 값을 반환하는 방식으로 구현되는 경우가 많습니다.

## 잘못된 ML-DSA 서명 키와 rejection sampling 정보 노출

ML-DSA의 확장된 개인 키는 계수가 `[-η, η]` 범위에 있는 다항식 벡터 `s1` 및 `s2`를 인코딩합니다. FIPS 204에 따르면 형식이 잘못된 비밀 키 바이트를 디코딩하면 이 범위를 벗어난 계수가 생성될 수 있습니다. 서명 알고리즘 자체에는 추가적인 개인 키 일관성 검사가 요구되지 않습니다.<sup>[[8]](#references)</sup>

필요한 전제 조건은 검증자에게 제출하는 잘못된 공개 키가 아니라, **가져오거나 서명에 사용하기 전에 확장된 서명 키를 제어하는 것**입니다. 허용적인 가져오기 경로는 패킹된 계수가 변조된 상태로도 키를 받아들이고, 검증 가능한 서명을 생성할 수 있습니다. [암호 키 인코딩 퍼징 워크플로](../../generic-methodologies-and-resources/fuzzing.md#differential-fuzzing-of-cryptographic-key-encodings)를 사용해 가져오기와 서명 단계에서의 수락 여부를 비교한 다음 결과 서명을 확인하세요.<sup>[[9]](#references)[[10]](#references)</sup>

서명 생성 과정에서는 `z = y + c·s1` 및 `r0 = LowBits(w − c·s2)`를 계산하고, `||z||∞ ≥ γ1 − β` 또는 `||r0||∞ ≥ γ2 − β`인 후보를 거부합니다. 이러한 검사는 수락된 출력이 유효한 작은 비밀 값과 무관하도록 합니다. 범위를 벗어난 비밀 계수는 이 rejection-sampling 논리를 깨뜨려 비밀 값에 의존하는 편향을 만들 수 있습니다. 이는 조건부 정보 노출 메커니즘이며, 보고된 라이브러리 간 불일치로 전체 키가 복구된 사례가 입증된 것은 **아닙니다**.<sup>[[8]](#references)[[10]](#references)</sup>

개인 키 검증은 서명 검증과는 별개입니다. 보고된 비교에서 OpenSSL, BoringSSL 및 SymCrypt는 추가적인 개인 키 검사를 적용했지만, liboqs는 서명 과정에서 형식이 잘못된 확장 키를 받아들였습니다. 기반 라이브러리인 `mldsa-native`는 `pk_from_sk()` 검증기를 제공하지만 liboqs는 이를 노출하지 않았습니다. FIPS 204는 이러한 추가 검사를 의무화하지 않습니다.<sup>[[9]](#references)[[10]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: 디지털 서명 표준](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner와 Heninger: 편향된 nonce의 위험 — 취약한 ECDSA 서명에 대한 격자 공격](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: 타원곡선 암호](https://www.secg.org/sec1-v2.pdf)
- [7] [Python `ecdsa` 문서](https://ecdsa.readthedocs.io/)
- [8] [NIST FIPS 204: 모듈 격자 기반 디지털 서명 표준](https://doi.org/10.6028/NIST.FIPS.204)
- [9] [ML-DSA 및 ML-KEM 키 검사 누락 - liboqs 이슈 #2517](https://github.com/open-quantum-safe/liboqs/issues/2517)
- [10] [포스트양자 암호 구현 현황](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
