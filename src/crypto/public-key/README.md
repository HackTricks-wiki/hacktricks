# 公開鍵暗号

{{#include ../../banners/hacktricks-training.md}}

高度なCTF暗号チャレンジの多くでは、RSA、楕円曲線暗号（ECC）、ECDSA、格子、または弱い乱数が扱われます。

## 推奨ツール

- モジュラー演算、楕円曲線、格子簡約には [SageMath](https://www.sagemath.org/)<sup>[[1]](#references)</sup>
- 一般的なRSAの弱点のテストには [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)<sup>[[2]](#references)</sup>
- 整数に既知の因数があるか確認するには [FactorDB](https://factordb.com/)<sup>[[3]](#references)</sup>
- キーの解析、署名、検証には Python の [`ecdsa` library](https://ecdsa.readthedocs.io/)<sup>[[7]](#references)</sup>

## RSA

チャレンジで `n`、`e`、`c` が提示され、共有モジュラス、低い指数、キーの一部ビット、または関連メッセージなどのヒントがある場合は、ここから始めてください。

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

署名が関係する場合は、基礎となる離散対数問題を解く必要があると考える前に、nonce の再利用、偏り、または漏えいをテストしてください。

### ECDSA nonce の再利用 / 偏り

ECDSAでは、メッセージごとに新しい秘密の数 `k` が必要です。同じ `k` で異なる2つのメッセージハッシュに署名すると、公開された署名値から秘密鍵を復元できます。<sup>[[4]](#references)</sup>

`k` が同一でなくても、多数の署名にわたるnonceビットの偏りや漏えいによって、格子ベースの復元が可能になる場合があります。<sup>[[5]](#references)</sup>

`k` が再利用された場合の技術的な復元方法:<sup>[[4]](#references)</sup>

ECDSAの署名方程式（群の位数 `n`）:

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

同じ `k` が2つのメッセージ `m1, m2` に再利用され、署名 `(r, s1)` と `(r, s2)` が生成された場合:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

プロトコルが入力点が想定された曲線上にあり、正しい部分群に属することを検証しない場合、攻撃者はより弱い群での演算を強制し、秘密スカラーに関する情報を復元できる可能性があります。SEC 1では、このような入力を防ぐための公開鍵検証チェックが規定されています。<sup>[[6]](#references)</sup>

技術的な注意点:

- 点が無限遠点でないこと、有効な座標を持つこと、曲線方程式を満たすこと、必要な部分群に属することを検証します。<sup>[[6]](#references)</sup>
- CTFチャレンジでは、サーバーが攻撃者の選んだ点に秘密スカラーを乗算し、導出値を返す形でモデル化されることがよくあります。

## 不正な ML-DSA signing key と rejection-sampling による漏えい

ML-DSAの展開済み秘密鍵は、多項式ベクトル `s1` と `s2` を、係数が `[-η, η]` の範囲にある形でエンコードします。FIPS 204によると、不正な秘密鍵バイト列をデコードすると、この範囲外の係数が生成されることがあります。署名アルゴリズム自体は、追加の秘密鍵整合性チェックを要求しません。<sup>[[8]](#references)</sup>

必要な前提条件は、検証者に送信される不正な公開鍵ではなく、**インポートまたは署名に使用される前の展開済み signing key を制御できること**です。寛容なインポート処理では、パックされた係数が改変されていても受け入れられ、署名が検証に通る場合があります。[暗号鍵エンコーディングの fuzzing ワークフロー](../../generic-methodologies-and-resources/fuzzing.md#differential-fuzzing-of-cryptographic-key-encodings)を使い、インポート時と署名時の受け入れ動作を比較し、生成された署名を確認してください。<sup>[[9]](#references)[[10]](#references)</sup>

署名では `z = y + c·s1` と `r0 = LowBits(w − c·s2)` を計算し、`||z||∞ ≥ γ1 − β` または `||r0||∞ ≥ γ2 − β` の場合に候補を棄却します。これらのチェックにより、受け入れられた出力は有効な小さな秘密値から独立します。範囲外の秘密係数は、この rejection-sampling の論拠を崩し、秘密値に依存した偏りを引き起こす可能性があります。これは条件付きの漏えいメカニズムであり、報告されたライブラリ間の差異から完全な鍵が復元されたことを実証するものでは**ありません**。<sup>[[8]](#references)[[10]](#references)</sup>

秘密鍵の検証と署名の検証は別のものです。報告された比較では、OpenSSL、BoringSSL、SymCryptは追加の秘密鍵チェックを行っていましたが、liboqsは署名時に不正な展開済み鍵を受け入れていました。その基盤である `mldsa-native` には `pk_from_sk()` バリデーターがありますが、liboqsでは公開されていませんでした。FIPS 204は、こうした追加の検証チェックを義務付けていません。<sup>[[9]](#references)[[10]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: デジタル署名標準](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner and Heninger: Biased Nonce Sense — 弱いECDSA署名に対する格子攻撃](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: 楕円曲線暗号](https://www.secg.org/sec1-v2.pdf)
- [7] [Python `ecdsa` ドキュメント](https://ecdsa.readthedocs.io/)
- [8] [NIST FIPS 204: モジュール格子ベースのデジタル署名標準](https://doi.org/10.6028/NIST.FIPS.204)
- [9] [ML-DSAおよびML-KEMの鍵チェックの欠落 - liboqs issue #2517](https://github.com/open-quantum-safe/liboqs/issues/2517)
- [10] [耐量子暗号実装の現状](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
