# LLM Training - Data Preparation

{{#include ../../banners/hacktricks-training.md}}

**これらは、非常におすすめの書籍** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **からの私のメモに、追加情報を加えたものです。**<sup>[[1]](#references)</sup>

## Basic Information

まず、知っておくべき基本概念について、この投稿を読んでください:


{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenization

> [!TIP]
> このフェーズの目的は、**入力をトークンに分割し、それらをトークン ID にマッピングすること**です。


{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Data Sampling

> [!TIP]
> このフェーズの目的は、選択したコンテキスト長の学習シーケンスと、それに対応するシフトされた予測対象を準備することです。


{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Token Embeddings

> [!TIP]
> この第 3 フェーズの目的は非常に単純です。**語彙内の各トークンに、モデルの学習に使用する目的の次元数のベクトルを割り当てます。** 語彙内の各単語は、X 次元の空間上の点になります。\
> なお、最初は空間内の各単語の位置は「ランダムに」初期化され、これらの位置は学習可能なパラメータです（学習中に改善されます）。
>
> さらに、token embedding の際には、**別の embedding layer が作成されます**。これは、この場合、**学習用の文中における単語の絶対位置**を表します。これにより、文中の異なる位置にある単語は、異なる表現を持つことになります。


{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Attention Mechanisms

> [!TIP]
> この第 4 フェーズの目的は非常に単純です。**いくつかの attention mechanisms を適用します**。これらは、**LLM の学習に使用されている現在の文において、語彙内の単語とその隣接する単語との関係を捉える**、多数の**反復レイヤー**になります。\
> これには多数のレイヤーが使用されるため、多くの学習可能なパラメータがこの情報を捉えることになります。


{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. LLM Architecture

> [!TIP]
> この第 5 フェーズの目的は非常に単純です。**完全な LLM の architecture を構築します**。すべてを組み合わせ、すべてのレイヤーを適用し、テキストを生成したり、テキストを ID に変換したり、その逆を行ったりするためのすべての関数を作成します。
>
> この architecture は、学習と、学習後のテキスト予測の両方に使用されます。


{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Pre-training & Loading models

> [!TIP]
> この第 6 フェーズの目的は非常に単純です。**モデルをゼロから学習させます**。そのために、前述の LLM architecture を使用し、定義した loss functions と optimizer によってモデルのすべてのパラメータを学習させるため、データセットを反復処理します。


{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. LoRA Improvements in fine-tuning

> [!TIP]
> LoRA は、pretrained model の fine-tuning に必要な学習可能なパラメータ数と optimizer state を大幅に削減します。


{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-Tuning for Classification

> [!TIP]
> このセクションの目的は、すでに pre-trained model となっているモデルを fine-tuning し、新しいテキストを生成するのではなく、LLM が**与えられたテキストが各カテゴリーに分類される確率**（テキストが spam であるかどうかなど）を選択して示す方法を説明することです。


{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-Tuning to follow instructions

> [!TIP]
> このセクションの目的は、単にテキストを生成するのではなく、**指示に従うように、すでに pre-trained model となっているモデルを fine-tuning する**方法を説明することです。たとえば、chat bot としてタスクに応答する場合などです。


{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

## References

- [1] [大規模言語モデルを構築する（ゼロから） - Manning](https://www.manning.com/books/build-a-large-language-model-from-scratch)
{{#include ../../banners/hacktricks-training.md}}
