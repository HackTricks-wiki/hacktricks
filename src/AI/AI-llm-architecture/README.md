# LLM Training - Data Preparation

{{#include ../../banners/hacktricks-training.md}}

**以下是我阅读这本强烈推荐的书籍后整理的笔记** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **，并补充了一些额外信息。**<sup>[[1]](#references)</sup>

## Basic Information

你应该先阅读这篇文章，了解一些需要掌握的基本概念：


{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenization

> [!TIP]
> 这一初始阶段的目标非常简单：**以某种合理的方式将输入划分为 tokens（ids）。**


{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Data Sampling

> [!TIP]
> 这一第二阶段的目标非常简单：**对输入数据进行采样，并为训练阶段准备数据，通常是将数据集分成特定长度的句子，同时生成预期的响应。**


{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Token Embeddings

> [!TIP]
> 这一第三阶段的目标非常简单：**为词汇表中的每个 token 分配一个具有所需维度的向量，以训练模型。** 词汇表中的每个单词都将是 X 维空间中的一个点。\
> 请注意，最初每个单词在空间中的位置只是被“随机”初始化的，而这些位置属于可训练参数（会在训练过程中得到改进）。
>
> 此外，在 token embedding 过程中，**还会创建另一层 embedding**，用于表示（在本例中）**单词在训练句子中的绝对位置**。这样，同一个单词位于句子中的不同位置时，就会具有不同的表示（含义）。


{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Attention Mechanisms

> [!TIP]
> 这一第四阶段的目标非常简单：**应用一些 attention mechanisms**。这些机制将由大量**重复的层**组成，用于**捕获词汇表中某个单词与当前用于训练 LLM 的句子中相邻单词之间的关系**。\
> 这一过程会使用大量层，因此许多可训练参数将用于捕获这些信息。


{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. LLM Architecture

> [!TIP]
> 这一第五阶段的目标非常简单：**开发完整 LLM 的架构**。将所有内容组合起来，应用所有层，并创建用于生成文本或将文本转换为 IDs 以及执行反向转换的所有函数。
>
> 该架构既用于训练，也用于模型训练完成后的文本预测。


{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Pre-training & Loading models

> [!TIP]
> 这一第六阶段的目标非常简单：**从头开始训练模型**。为此，将使用前面的 LLM 架构，通过遍历数据集的循环，使用定义好的损失函数和优化器来训练模型的所有参数。


{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. LoRA Improvements in fine-tuning

> [!TIP]
> 使用 **LoRA 可以大幅减少**对已经训练好的模型进行 **fine tune** 所需的计算量。


{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-Tuning for Classification

> [!TIP]
> 本节的目标是展示如何对已经预训练的模型进行 fine-tune，使其不再生成新文本，而是给出**输入文本被归类到每个指定类别中的概率**（例如判断一段文本是否为 spam）。


{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-Tuning to follow instructions

> [!TIP]
> 本节的目标是展示如何对已经预训练的模型进行 **fine-tune，使其遵循指令**，而不只是生成文本，例如像 chat bot 一样响应任务。


{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

## References

- [1] [Build a Large Language Model (From Scratch) - Manning](https://www.manning.com/books/build-a-large-language-model-from-scratch)

{{#include ../../banners/hacktricks-training.md}}
