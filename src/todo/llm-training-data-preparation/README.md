# LLM 训练 - 数据准备

**这些是我从非常推荐的书中做的笔记** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **以及一些额外的信息。**

## 基本信息

您应该先阅读这篇文章，以了解一些您应该知道的基本概念：

{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. 分词

> [!TIP]
> 这个初始阶段的目标非常简单：**以某种有意义的方式将输入划分为标记（ID）。**

{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. 数据采样

> [!TIP]
> 这个第二阶段的目标非常简单：**对输入数据进行采样，并为训练阶段准备数据，通常通过将数据集分成特定长度的句子，并生成预期的响应。**

{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. 标记嵌入

> [!TIP]
> 这个第三阶段的目标非常简单：**为词汇表中的每个标记分配一个所需维度的向量以训练模型。** 词汇表中的每个单词将在 X 维空间中有一个点。\
> 请注意，最初每个单词在空间中的位置是“随机”初始化的，这些位置是可训练的参数（在训练过程中会得到改善）。
>
> 此外，在标记嵌入过程中**创建了另一层嵌入**，它表示（在这种情况下）**单词在训练句子中的绝对位置**。这样，句子中不同位置的单词将具有不同的表示（含义）。

{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. 注意机制

> [!TIP]
> 这个第四阶段的目标非常简单：**应用一些注意机制**。这些将是许多**重复的层**，将**捕捉词汇表中单词与当前用于训练 LLM 的句子中其邻居的关系**。\
> 为此使用了许多层，因此许多可训练的参数将捕捉这些信息。

{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. LLM 架构

> [!TIP]
> 这个第五阶段的目标非常简单：**开发完整 LLM 的架构**。将所有内容组合在一起，应用所有层并创建所有函数以生成文本或将文本转换为 ID 及其反向操作。
>
> 该架构将用于训练和预测文本。

{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. 预训练与加载模型

> [!TIP]
> 这个第六阶段的目标非常简单：**从头开始训练模型**。为此，将使用之前的 LLM 架构，通过对数据集进行循环，使用定义的损失函数和优化器来训练模型的所有参数。

{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. LoRA 在微调中的改进

> [!TIP]
> 使用**LoRA 大大减少了微调**已训练模型所需的计算。

{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. 分类的微调

> [!TIP]
> 本节的目标是展示如何微调一个已经预训练的模型，以便 LLM 不再生成新文本，而是给出**给定文本被分类到每个给定类别的概率**（例如，文本是否为垃圾邮件）。

{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. 按照指令进行微调

> [!TIP]
> 本节的目标是展示如何**微调一个已经预训练的模型以遵循指令**，而不仅仅是生成文本，例如，作为聊天机器人响应任务。

{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}
