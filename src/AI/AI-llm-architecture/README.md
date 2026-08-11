# LLM 训练 - 数据准备

{{#include ../../banners/hacktricks-training.md}}

**这些是我根据强烈推荐的书籍** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **整理的笔记，并加入了一些额外信息。**<sup>[[1]](#references)</sup>

## 基本信息

你应该先阅读这篇文章，了解一些需要掌握的基本概念：


{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenization

> [!TIP]
> 此阶段的目标是**将输入划分为 tokens，并将其映射到 token IDs**。


{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Data Sampling

> [!TIP]
> 此阶段的目标是准备具有指定上下文长度的训练序列，以及与其对应的移位预测目标。


{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Token Embeddings

> [!TIP]
> 第三个阶段的目标非常简单：**为词汇表中的每个前述 token 分配一个具有指定维度的向量，以训练模型。**词汇表中的每个词都会成为 X 维空间中的一个点。\
> 请注意，最初每个词在空间中的位置只是被“随机”初始化的，而这些位置属于可训练参数（会在训练过程中得到改进）。
>
> 此外，在 token embedding 过程中，**还会创建另一个 embedding layer**，用于表示（在本例中）**词语在训练句子中的绝对位置**。这样，同一个词在句子的不同位置就会具有不同的表示。


{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Attention Mechanisms

> [!TIP]
> 第四个阶段的目标非常简单：**应用一些 attention mechanisms**。这些机制将由大量**重复的 layers**组成，用于**捕获词汇表中的某个词与当前用于训练 LLM 的句子中其相邻词之间的关系**。\
> 这一过程会使用大量 layers，因此许多可训练参数将用于捕获这些信息。


{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. LLM Architecture

> [!TIP]
> 第五个阶段的目标非常简单：**开发完整 LLM 的架构**。将所有内容组合起来，应用所有 layers，并创建用于生成文本，或将文本转换为 IDs 以及执行反向转换的所有 functions。
>
> 该架构既用于训练，也用于模型训练完成后的文本预测。


{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Pre-training & Loading models

> [!TIP]
> 第六个阶段的目标非常简单：**从头开始训练模型**。为此，将使用前面的 LLM architecture，通过使用定义好的 loss functions 和 optimizer 遍历数据集的循环，训练模型的所有参数。


{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. LoRA Improvements in fine-tuning

> [!TIP]
> LoRA 大幅减少了对预训练模型进行 fine-tune 所需的可训练参数数量和 optimizer state。


{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-Tuning for Classification

> [!TIP]
> 本节的目标是展示如何对已经预训练的模型进行 fine-tune，使 LLM 不再生成新文本，而是选择并给出**给定文本属于每个指定类别的概率**（例如判断文本是否为 spam）。


{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-Tuning to follow instructions

> [!TIP]
> 本节的目标是展示如何对已经预训练的模型进行 fine-tune，使其**遵循指令**，而不只是生成文本，例如像聊天机器人一样响应任务。


{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

## References

- [1] [从头构建大型语言模型 - Manning](https://www.manning.com/books/build-a-large-language-model-from-scratch)
{{#include ../../banners/hacktricks-training.md}}
