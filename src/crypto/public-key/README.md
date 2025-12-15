# 公開鍵暗号

{{#include ../../banners/hacktricks-training.md}}

ほとんどのCTFの難しい暗号問題はここに集まる: RSA、ECC/ECDSA、lattices、そして乱数の弱さ。

## 推奨ツール

- SageMath (LLL/lattices, modular arithmetic): https://www.sagemath.org/
- RsaCtfTool (Swiss-army knife): https://github.com/Ganapati/RsaCtfTool
- factordb (quick factor checks): http://factordb.com/

## RSA

`n,e,c` といくつかの追加ヒント（shared modulus、low exponent、partial bits、related messages）がある場合はここから始める。

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

署名が関わる場合、難しい数学を仮定する前にまず nonce の問題（reuse/bias/leaks）をテストする。

### ECDSA nonce reuse / bias

もし二つの署名が同じ nonce `k` を再利用すると、秘密鍵を回復できる。

たとえ `k` が完全に同一でなくても、署名間での nonce ビットの **bias/leakage** が格子法での回復に十分なことがある（CTFでよくあるテーマ）。

`k` が再利用されたときの技術的回復方法:

ECDSA の署名方程式（群の位数 `n`）:

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

もし同じ `k` が二つのメッセージ `m1, m2` に対して再利用され、それぞれ `(r, s1)` と `(r, s2)` を生成した場合:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

プロトコルがポイントが期待される曲線上（または正しい部分群に属する）かを検証しない場合、攻撃者は弱い群での操作を強制して秘密を回復できる。

技術的注意点:

- ポイントが曲線上であり、正しい部分群に属していることを検証する。
- 多くのCTFタスクは「server multiplies attacker-chosen point by secret scalar and returns something」というモデルになっている。

### ツール

- SageMath for curve arithmetic / lattices
- `ecdsa` Python library for parsing/verification

{{#include ../../banners/hacktricks-training.md}}
