# LLM Training - Data Preparation

{{#include ../../banners/hacktricks-training.md}}

**これは非常に推奨されている書籍** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **からの私のメモに、追加情報を加えたものです。**<sup>[[1]](#references)</sup>

## 基本情報

まず、知っておくべき基本概念について、この投稿を読んでください:


{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenization

> [!TIP]
> この初期フェーズの目標は非常に単純です: **入力を、意味のある方法で tokens（ids）に分割すること**。


{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Data Sampling

> [!TIP]
> この第2フェーズの目標も非常に単純です: **入力データをサンプリングし、通常はデータセットを特定の長さの文に分割し、期待される応答も生成することで、training phase 用に準備すること**。


{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Token Embeddings

> [!TIP]
> この第3フェーズの目標は非常に単純です: **前述の vocabulary 内の各 token に、model の training 用として必要な次元数の vector を割り当てること**。vocabulary 内の各単語は、X 次元の空間上の1つの点になります。\
> 最初は、空間内の各単語の位置は単に「ランダムに」初期化されることに注意してください。これらの位置は trainable parameters であり、training 中に改善されます。
>
> さらに、token embedding 中には、**別の embedding layer が作成されます**。これは、この場合、**training sentence 内での単語の絶対位置**を表します。これにより、文中の異なる位置にある単語は、異なる表現（意味）を持つようになります。


{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Attention Mechanisms

> [!TIP]
> この第4フェーズの目標は非常に単純です: **いくつかの attention mechanisms を適用すること**。これらは、**LLM の training に使用されている現在の文において、vocabulary 内の単語とその隣接する単語との関係を捉える、繰り返し使用される多数の layers** になります。\
> このために多数の layers が使用されるため、多数の trainable parameters がこの情報を捉えることになります。


{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. LLM Architecture

> [!TIP]
> この第5フェーズの目標は非常に単純です: **完全な LLM の architecture を構築すること**。すべてを組み合わせ、すべての layers を適用し、text を生成したり、text を IDs に変換したり、その逆を行ったりするためのすべての functions を作成します。
>
> この architecture は、training と、training 後の text の prediction の両方に使用されます。


{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Pre-training & Loading models

> [!TIP]
> この第6フェーズの目標は非常に単純です: **model を scratch から training すること**。そのために、前述の LLM architecture を使用し、定義された loss functions と optimizer を用いて、data sets を反復処理するいくつかの loops により、model のすべての parameters を training します。


{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. LoRA Improvements in fine-tuning

> [!TIP]
> **LoRA を使用すると、すでに training 済みの models を fine-tuning するために必要な computation を大幅に削減できます**。


{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-Tuning for Classification

> [!TIP]
> この section の目標は、すでに pre-trained された model を fine-tuning し、新しい text を生成する代わりに、LLM が**与えられた text がそれぞれのカテゴリに分類される確率**（text が spam であるかどうかなど）を示す方法を説明することです。


{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-Tuning to follow instructions

> [!TIP]
> この section の目標は、単に text を生成するのではなく、**指示に従うように、すでに pre-trained された model を fine-tuning する**方法を説明することです。たとえば、chat bot として tasks に応答する場合などです。


{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

## References

- [1] [Build a Large Language Model (From Scratch) - Manning](https://www.manning.com/books/build-a-large-language-model-from-scratch)

{{#include ../../banners/hacktricks-training.md}}
