# Public-Key Crypto

{{#include ../../banners/hacktricks-training.md}}

高度なCTF暗号チャレンジの多くでは、RSA、楕円曲線暗号（ECC）、ECDSA、格子、または弱い乱数が扱われます。

## 推奨ツール

- [SageMath](https://www.sagemath.org/)：剰余演算、楕円曲線、格子基底簡約に使用<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)：一般的なRSAの脆弱性のテストに使用<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/)：整数の既知の因数を確認するために使用<sup>[[3]](#references)</sup>
- Pythonの[`ecdsa`ライブラリ](https://ecdsa.readthedocs.io/)：鍵の解析、署名、検証に使用<sup>[[7]](#references)</sup>

## RSA

チャレンジで`n`、`e`、`c`が提示され、共有モジュラス、低い指数、鍵の一部ビット、または関連メッセージなどのヒントがある場合は、ここから始めてください。

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

署名が関係する場合は、基礎となる離散対数問題を解く必要があると考える前に、nonceの再利用、偏り、漏えいを調べてください。

### ECDSAのnonce再利用 / 偏り

ECDSAでは、メッセージごとに新しい秘密の数`k`が必要です。同じ`k`で2つの異なるメッセージハッシュに署名すると、公開されている署名値から秘密鍵を復元できます。<sup>[[4]](#references)</sup>

`k`が同一でなくても、多数の署名におけるnonceビットの偏りや漏えいによって、格子ベースの復元が可能になることがあります。<sup>[[5]](#references)</sup>

`k`が再利用された場合の技術的な復元方法：<sup>[[4]](#references)</sup>

ECDSAの署名方程式（群の位数は`n`）：

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

同じ`k`が2つのメッセージ`m1, m2`に再利用され、署名`(r, s1)`と`(r, s2)`が生成された場合：

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### 無効曲線攻撃

プロトコルが、入力点が想定された曲線上にあり、正しい部分群に属していることを検証しない場合、攻撃者はより弱い群での演算を強制し、秘密スカラーに関する情報を復元できる可能性があります。SEC 1では、このような入力を防ぐための公開鍵検証チェックが規定されています。<sup>[[6]](#references)</sup>

技術メモ：

- 点が無限遠点ではないこと、有効な座標を持つこと、曲線方程式を満たすこと、必要な部分群に属することを検証してください。<sup>[[6]](#references)</sup>
- CTFチャレンジでは、攻撃者が選んだ点に秘密スカラーを掛け、その結果から導出された値を返すサーバーとしてモデル化されることがよくあります。

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5：デジタル署名規格](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner and Heninger：Biased Nonce Sense — 弱いECDSA署名に対する格子攻撃](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0：楕円曲線暗号](https://www.secg.org/sec1-v2.pdf)
- [7] [Python `ecdsa`ドキュメント](https://ecdsa.readthedocs.io/)
{{#include ../../banners/hacktricks-training.md}}
