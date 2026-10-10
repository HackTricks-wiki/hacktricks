# 공개 키 암호화

{{#include ../../banners/hacktricks-training.md}}

고급 CTF 암호학 문제에는 RSA, 타원곡선 암호(ECC), ECDSA, 격자 또는 취약한 난수가 자주 등장합니다.

## 권장 도구

- 모듈러 연산, 타원곡선, 격자 축소를 위한 [SageMath](https://www.sagemath.org/)<sup>[[1]](#references)</sup>
- 일반적인 RSA 취약점을 테스트하기 위한 [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)<sup>[[2]](#references)</sup>
- 정수에 알려진 인수가 있는지 확인하기 위한 [FactorDB](https://factordb.com/)<sup>[[3]](#references)</sup>
- 키 파싱, 서명, 검증을 위한 Python [`ecdsa` library](https://ecdsa.readthedocs.io/)<sup>[[7]](#references)</sup>

## RSA

문제에서 `n`, `e`, `c`와 함께 모듈러스 공유, 작은 지수, 부분 키 비트 또는 관련 메시지 등의 힌트를 제공한다면 여기서 시작하세요.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

서명이 포함되어 있다면, 기반이 되는 이산 로그 문제를 풀어야 한다고 가정하기 전에 nonce 재사용, 편향 또는 정보 누출을 확인하세요.

### ECDSA nonce reuse / bias

ECDSA는 메시지마다 새로운 비밀 숫자 `k`를 사용해야 합니다. 동일한 `k`로 서로 다른 두 메시지 해시에 서명하면, 공개 서명 값으로 개인 키를 복구할 수 있습니다.<sup>[[4]](#references)</sup>

`k`가 동일하지 않더라도 여러 서명에서 nonce 비트의 편향이나 정보 누출이 발생하면 격자 기반 복구가 가능할 수 있습니다.<sup>[[5]](#references)</sup>

`k` 재사용 시 기술적 복구 방법:<sup>[[4]](#references)</sup>

ECDSA 서명 방정식(군의 위수 `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

서로 다른 두 메시지 `m1, m2`에 동일한 `k`를 재사용하여 서명 `(r, s1)` 및 `(r, s2)`를 생성한 경우:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

프로토콜이 입력 점이 예상된 곡선 위에 있고 올바른 부분군에 속하는지 검증하지 않으면, 공격자가 더 취약한 군에서 연산을 수행하게 하여 비밀 스칼라에 관한 정보를 알아낼 수 있습니다. SEC 1에는 이러한 입력을 방지하기 위한 공개 키 검증 절차가 명시되어 있습니다.<sup>[[6]](#references)</sup>

기술 참고:

- 점이 무한원점이 아닌지, 좌표가 유효한지, 곡선 방정식을 만족하는지, 필요한 부분군에 속하는지 검증하세요.<sup>[[6]](#references)</sup>
- CTF 문제에서는 서버가 공격자가 선택한 점에 비밀 스칼라를 곱하고, 그 결과에서 파생된 값을 반환하는 방식으로 이를 모델링하는 경우가 많습니다.

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: 디지털 서명 표준](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner와 Heninger: 편향된 nonce — 취약한 ECDSA 서명에 대한 격자 공격](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: 타원곡선 암호](https://www.secg.org/sec1-v2.pdf)
- [7] [Python `ecdsa` 문서](https://ecdsa.readthedocs.io/)
{{#include ../../banners/hacktricks-training.md}}
