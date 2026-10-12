# Proof Assistantと形式検証のセキュリティ

{{#include ../banners/hacktricks-training.md}}

Proof assistantは、カーネルによる簡約、インタプリタ、生成コード、ランタイムプリミティブ、外部チェッカーなど、複数の経路で同じ項を実行できます。証明の強度は、信頼できる結果に寄与するすべてのコンポーネントの強度に左右されます。Leanでは、ネイティブ決定手続きは評価を高速化する代わりに、信頼できるコンピューティング基盤（TCB）を拡大します。コンパイラとネイティブ実装を持つ定義が、証明の完全性に関わるようになります。<sup>[[3]](#references)</sup>

## 論理評価とネイティブ評価の差分

実行可能な実装が論理モデルと異なるプリミティブ（たとえばコンパイラ組み込み関数、外部関数インターフェース、ランタイムによるオーバーライド、`@[implemented_by]`が付いた定義）を優先して調べます。**同じ閉じた項**を論理経路とコンパイル済み経路の両方で差分評価し、値、例外、終了に不一致があれば、セキュリティ上の問題として扱います。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

有用な境界値の分類には、次のものがあります。<sup>[[1]](#references)[[4]](#references)</sup>

- `0`、入力長、マシンワードの上限付近のインデックス、および`2^63`以上などの値
- 0バイトまたは1バイトの範囲、`start = end`、`start > end`、オブジェクトの範囲を大きく超える位置
- 空および空でない入力、マルチバイト文字列、無効な境界、コンパイル時に切り捨てられる可能性がある算術演算
- ネイティブプリミティブに、論理モデルにはない所有権または借用の動作がある場合の、ヒープ上の値

次の簡略化したLeanのパターンは、`String.Pos.Raw.extract`で見つかった問題を示しています。脆弱なネイティブコードは、非常に大きな1バイト範囲に対して元の文字列を返しましたが、定義による簡約では空文字列が返されました。この意味上の不一致は、関連するメモリ安全性の不具合とは別に修正されました。<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>

```lean
def value : String := "non-empty"
def startPos : String.Pos.Raw := ⟨2^63⟩
def endPos : String.Pos.Raw := ⟨2^63 + 1⟩

example : False := by
  have logical : String.Pos.Raw.extract value startPos endPos = "" := rfl
  have native : String.Pos.Raw.extract value startPos endPos = value := by
    native_decide
  exact (by decide) (logical.symm.trans native)
```

このパターンは文字列以外にも一般化できます。論理的な評価によって `E = A` が証明され、信頼されたネイティブ評価によって `E = B` が証明されると、推移律から `A = B` が導かれます。`A` と `B` が観測可能な形で異なる場合、これによって `False` が導かれます。次に、爆発原理である `False.elim` を使えば、任意の目標命題を証明できます。カーネルに誤った簡約規則がある必要はありません。コンパイラに基づく結果が公理を通じて論理に入り込むことで、完全性の破綻が起こります。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

## Lean における拡張された TCB の監査

信頼できない証明を検証する際、エディターのチェックマークやビルドの成功だけに頼らないでください。`#print axioms` を使って、セキュリティ上重要な各定理の依存関係をすべて確認してください。Lean の検証ガイダンスでは、`_native` で始まる名前はネイティブ評価への依存、`sorryAx` は未完成の証明、その他の標準外の名前はカスタム公理を示すとされています。<sup>[[3]](#references)</sup>

```lean
#print axioms targetTheorem
```

たとえば、以下のような生成された依存関係は、カーネルによる簡約だけから導かれた証明ではなく、コンパイル済みの実行が仮定された結果に寄与したことを意味します:<sup>[[1]](#references)[[4]](#references)</sup>

```text
targetTheorem._native.native_decide.ax_1_1
```

ソースレビューでは、ネイティブの決定手続きと明示的なエスケープハッチを探します。ただし、依存関係は間接的または生成されたものである可能性があるため、`#print axioms` で結果を確認してください。<sup>[[3]](#references)</sup>

```bash
rg -n 'native_decide|decide\s+\+native|bv_decide|sorry|axiom' .
```

finding をトリアージする際は、各レイヤーを区別してください:<sup>[[3]](#references)</sup>

1. **文の整合性:** 記法、型クラスのインスタンス、import、定義が意図した主張を表しているか検証します。
2. **証明の依存関係:** 予期しない公理を拒否するか、明示的にレビューします。特に、生成されたネイティブ評価の公理に注意してください。
3. **カーネルによる再検証:** `lake build` の後、`lean4checker --fresh <Module>` を実行し、`.olean` ファイルから宣言を再検証します。
4. **悪意ある証明の検証:** 信頼できないコードをサンドボックス内でビルドし、外部チェッカーを使って、信頼できるチャレンジ文に対して `lake comparator` を実行します。

`lean4checker` は多層防御として有用ですが、`.olean` ファイルの構造的な正しさを信頼しています。また、信頼できない Lean のメタコードを実行すると、検証環境自体が侵害されるおそれがあります。リスクの高い証明では、comparator がサンドボックスの外部に証明をエクスポートし、信頼できるチャレンジに対して文を検証したうえで、独立して実装されたチェッカーを通じて再検証できます。実装の多様性により、あるコンパイラー、ランタイム、またはカーネルの欠陥が、同じ誤った結果をあらゆる環境で検証してしまう可能性を低減できます。<sup>[[3]](#references)</sup>

## References

- [1] [`String.Pos.Raw.extract` のモデルとランタイムの不一致、および use-after-free - Lean issue #14684](https://github.com/leanprover/lean4/issues/14684)
- [2] [`String.Pos.Raw.extract` のモデルとランタイムの不一致を修正 - Lean PR #14717](https://github.com/leanprover/lean4/pull/14717)
- [3] [Lean 言語リファレンス: Lean の証明を検証する](https://lean-lang.org/doc/reference/latest/ValidatingProofs/)
- [4] [余白に収まるフェルマーの最終定理の「証明」](https://blog.trailofbits.com/2026/09/09/a-proof-of-fermats-last-theorem-that-fits-the-margin/)
{{#include ../banners/hacktricks-training.md}}
