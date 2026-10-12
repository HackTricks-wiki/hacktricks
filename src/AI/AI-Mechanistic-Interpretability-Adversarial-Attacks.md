# Mechanistic-Interpretability-Guided Adversarial Attacks

{{#include ../banners/hacktricks-training.md}}

## 攻撃対象面としての重ね合わせ

活性化空間のパラメータ数が不足している場合、特徴を非直交ベクトルに割り当てることで、次元数を超える意味的特徴を符号化できます。その結果、活性化した特徴は他の特徴の方向にも射影されます。学習によって分布内で見られる組み合わせには対処できますが、通常は妥当な特徴同士の珍しい組み合わせによって、入力には存在しない標的特徴の方向に値が加算されることがあります。<sup>[[1]](#references)[[2]](#references)</sup>

特徴ベクトル `v_i ∈ R^D`、活性化 `a_i`、標的 `t` に対して、次の大きさは候補となる組み合わせを見つけるのに役立ちます。<sup>[[1]](#references)</sup>

```text
I_t = Σ_i≠t |a_i (v_i · v_t) / ||v_t|| |
candidate condition: I_t > max(a)
```

これはあくまでスクリーニング用のヒューリスティックです。exploitでは符号と大きさを保持し、実際のdecoderを評価する必要があります。たとえば、重み共有の線形decoderでは `h_hat[t] = ReLU(b_t + Σ_i a_i(v_i · v_t))` のようにします。負の項は攻撃を相殺することがあり、decoderのbias、feature vectorのnorm、activation threshold、ReLU gatingによって、大きな絶対cosine scoreがtarget activationにつながらない場合があります。<sup>[[1]](#references)</sup>

## White-box attack workflow

実践的な評価では、model bottleneck、sparse autoencoder（SAE）、または別の解釈可能なfeature dictionaryを利用できます。目的は最終的なclassを変えることだけではありません。圧縮前には有効でなかった、特定の内部featureを再構成によって生じさせることです。提案するworkflowは次のとおりです。<sup>[[1]](#references)</sup>

1. **feature方向を特定する:** 関連するencoder/decoder vectorを抽出し、dead featureを除去して、最大activationを示すサンプルまたはfeature-circuit analysisを使って、有効な方向を概念に対応付けます。
2. **干渉を順位付けする:** vectorのコピーを正規化し、cosine-similarity matrixを計算して対角成分をクリアし、targetに最も近いoff-diagonal neighborを調べます。実際のactivation magnitudeと符号付きのraw dot productを使って候補を再計算します。
3. **同時activationを確保する:** 同じlayerまたはresidual stream内で有効化できる、正の寄与を持つfeatureを少数選びます。training dataでは稀、または見られない組み合わせを優先します。通常の相関した組み合わせは、training中に補正されている可能性が高いためです。
4. **入力を合成する:** 選択した寄与featureについて、datasetのサンプルまたはactivationを最大化するpatternを組み合わせます。範囲が制限された線形pixel detectorでは、正のweightのpixelを高く、負のweightのpixelを低く設定し、できたpatternを重ねます。in-distributionの構造と抑制的な**negative space**を手作業で維持することで、無関係なfeatureを抑えられます。
5. **メカニズムを検証する:** 1回のforward passで、圧縮前のactivation、圧縮後の座標、再構成されたactivation、下流の出力を記録します。寄与featureをablateすると予測された変化が消え、再構成前はtargetがinactive、再構成後はactiveになることが、テストの成功を示します。

以下の最小限のtriageでは、feature vectorが**行**に並ぶ重み共有decoderの寄与featureを順位付けします（featureが列の場合は、先に転置してください）。符号付きscoreにはraw weightを、cosineによる順位付けには正規化したweightのみを使います。<sup>[[1]](#references)</sup>

```python
import numpy as np

norm = np.linalg.norm(W_dec, axis=1, keepdims=True)
unit = W_dec / np.clip(norm, 1e-12, None)
cosine = unit @ unit.T
np.fill_diagonal(cosine, 0.0)

target = 42
signed = activations * (W_dec @ W_dec[target])
signed[target] = -np.inf
order = np.argsort(signed)[::-1]
print([(int(i), float(signed[i]), float(cosine[i, target]))
       for i in order[:20] if signed[i] > 0])
```

コサイン類似度だけから exploitability を推測しないでください。バイアスと非線形性を含む decoder 全体をテストし、各要素が実際に同時に出現し得ることを確認したうえで、分布内の条件を揃えた組み合わせと比較してください。方向が似ているのは、悪用可能な packing interference ではなく、正当な意味上の関係を符号化しているためかもしれません。<sup>[[1]](#references)</sup>

## 実証された toy-model attack

proof of concept では、意図的に解釈しやすくした2つのブランチを持つ MNIST 分類器を使用しました。一方のブランチでは、疎な128次元の ReLU feature vector を直接分類し、もう一方ではそれを2次元の superposition space に圧縮しました。同じ分類器で、元の特徴と再構成された特徴の両方を処理しました。<sup>[[1]](#references)</sup>

```text
h       = ReLU(MLP(x))
z       = W_enc h
h_hat   = ReLU(W_enc^T z + b)
y_plain = C(h)
y_super = C(h_hat)
```

3/0のような形状に対応する2つの特徴方向は、幾何学的にクラス5の方向に囲まれていた。それらの特徴を最大限に活性化する画像を加えると、圧縮前には寄与特徴が最も強くなったが、再構成では複数のクラス5特徴が活性化し、重ね合わせ分岐は5を予測した。最小値と最大値の画素値だけを使った手描き入力でも同じ効果が再現され、この玩具設定では、勾配最適化による画素摂動を厳密に作る必要がないことが示された。<sup>[[1]](#references)</sup>

## より大規模なモデルでの幾何学的トリアージ

論文では、Gemma Scope `layer 20 / width 65k / average L0 20` SAEも調査した。単位正規化されたデコーダ行列にその転置行列を掛け、対角成分をゼロにしたうえで、各特徴の近傍をソートし、順位ごとに平均した。最も近い近傍のコサイン類似度の平均は`0.49`、27番目に近い近傍の類似度の平均は`0.25`だった。幾何学的には、このような方向が4つあれば、1つの単位ターゲット射影に一致しうる。これらの数値は候補を特定するだけであり、適切な4つの特徴を同時に活性化できることや、ターゲットがデコーダのしきい値を超えることを示すものではない。<sup>[[1]](#references)</sup>

## 範囲と限界

これは研究段階の**white-box**手法であり、デプロイ済みCNNや最先端LLMに対する実証済みの攻撃ではない。重ね合わせ、役立つ非直交方向、内部特徴への解釈可能なアクセス、寄与特徴の活性化を制御できること、そして1回の順伝播中に同じ層でそれらを集められることが必要となる。<sup>[[1]](#references)</sup>

画像MLPでは、特徴の組み合わせが特に直接的に行える。Transformerでは、選択した特徴の活性化を同じ残差ストリームに集めるためにattentionが必要となるため、より難しい。論文は、分布外の組み合わせに対してこれを強制する方法を示していない。したがって、振る舞いや拒否に関する方向、物理的な視覚システム、最先端モデルの操作についての主張は、依然として仮説にとどまる。<sup>[[1]](#references)</sup>

## References

- [1] [Wilkinson and Anley — 重ね合わせにおける特徴干渉を通じた解釈可能な敵対的攻撃に関する予備調査 (PDF)](https://www.nccgroup.com/media/kahclmxj/interpretable-adversarial-attacks-in-superpos_.pdf)
- [2] [NCC Group — 重ね合わせにおける解釈可能な敵対的攻撃](https://www.nccgroup.com/research/interpretable-adversarial-attacks-in-superposition/)
{{#include ../banners/hacktricks-training.md}}
