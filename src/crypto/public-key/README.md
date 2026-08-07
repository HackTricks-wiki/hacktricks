# 公開鍵暗号

{{#include ../../banners/hacktricks-training.md}}


CTF の難しい暗号問題は、最終的にここに行き着くことが多いです: RSA、ECC/ECDSA、lattice、そして悪い乱数。

## 推奨ツール

- SageMath (LLL/lattice、modular arithmetic): https://www.sagemath.org/
- RsaCtfTool (Swiss-army knife): https://github.com/Ganapati/RsaCtfTool
- factordb (quick factor checks): http://factordb.com/

## RSA

`n,e,c` と何らかの追加ヒント (shared modulus、low exponent、partial bits、related messages) がある場合は、ここから始めます。

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

署名が関係する場合は、難しい数学を想定する前に、まず nonce の問題 (reuse/bias/leaks) をテストします。

### ECDSA nonce reuse / bias

2 つの署名で同じ nonce `k` が再利用されている場合、private key を復元できます。

`k` が同一でない場合でも、署名間での nonce bit の **bias/leakage** によって、lattice recovery に十分な情報が得られることがあります (CTF でよくあるテーマです)。

`k` が再利用された場合の Technical recovery:

ECDSA signature equations (group order `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

同じ `k` が 2 つの message `m1, m2` で再利用され、署名 `(r, s1)` と `(r, s2)` が生成された場合:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

protocol が、points が想定された curve (または subgroup) 上にあることを validate していない場合、attacker は weak group での operation を強制し、secret を recover できる可能性があります。

Technical note:

- points が on-curve であり、correct subgroup に属していることを validate する。
- 多くの CTF task では、これを「server が attacker-chosen point に secret scalar を multiply し、何らかの値を返す」という形で model 化しています。

### Tooling

- SageMath for curve arithmetic / lattices
- `ecdsa` Python library for parsing/verification

{{#include ../../banners/hacktricks-training.md}}
