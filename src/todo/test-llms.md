# 测试 LLMs

{{#include ../banners/hacktricks-training.md}}

## 在本地运行和训练模型

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers 是用于使用、训练和部署 GPT、BERT 以及许多其他 LLMs 的最流行开源库之一。它提供了一个完善的生态系统，包括预训练模型、数据集，以及与 Hugging Face Hub 的无缝集成，用于 fine-tuning 和部署。

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain 是一个用于构建 LLMs 应用程序的 framework。它允许开发者将语言模型与外部数据源、API 和数据库连接起来。LangChain 提供了高级 prompt engineering、管理对话历史记录，以及将 LLMs 集成到复杂工作流中的工具。

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT 是由 Lightning AI 开发的项目，它利用 Lightning framework 来促进基于 GPT 的模型的训练、fine-tuning 和部署。它可以与其他 Lightning AI 工具无缝集成，为处理大规模语言模型提供性能更高且可扩展的优化工作流。

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**描述：**\
LitServe 是 Lightning AI 提供的部署工具，旨在快速高效地部署 AI 模型。它通过提供可扩展且经过优化的 serving 能力，简化了将 LLMs 集成到实时应用程序中的过程。

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl 是一个基于 cloud 的平台，旨在简化 AI 模型（包括 LLMs）的部署、扩展和管理。它提供自动扩展、监控以及与各种 cloud 服务集成等功能，使用户无需进行大量基础设施管理即可更轻松地在生产环境中部署模型。

## 在线尝试模型

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** 是领先的 machine learning 平台和社区，尤其以其在自然语言处理（NLP）领域的工作而闻名。它提供工具、库和资源，使开发、共享和部署 machine learning 模型更加容易。\
它提供多个部分，例如：

* **Models**：一个庞大的**预训练 machine learning 模型**仓库，用户可以浏览、下载并集成用于文本生成、翻译、图像识别等各种任务的模型。
* **Datasets：**用于训练和评估模型的综合**数据集集合**。它便于访问各种数据源，使用户能够为特定的 machine learning 项目查找并使用数据。
* **Spaces：**用于托管和共享**交互式 machine learning 应用程序**及演示的平台。开发者可以借此**展示**模型的实际运行效果，创建用户友好的界面，并通过共享实时演示与他人协作。

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** 是由 Google 开发的可复用 machine learning 模块综合仓库。它专注于促进 machine learning 模型的共享和部署，尤其是使用 TensorFlow 构建的模型。

* **Modules**：大量预训练模型和模型组件的集合，用户可以浏览、下载并集成用于图像分类、文本 embedding 等任务的模块。
* **Tutorials**：分步指南和示例，帮助用户了解如何使用 TensorFlow Hub 实现和 fine-tune 模型。
* **Documentation**：全面的指南和 API 参考，帮助开发者有效利用该仓库的资源。

## [**Replicate**](https://replicate.com/home)

**Replicate** 是一个允许开发者通过简单 API 在 cloud 中运行 machine learning 模型的平台。它致力于让 ML 模型更易于访问和部署，而无需进行大量基础设施配置。

* **Models**：由社区贡献的 machine learning 模型仓库，用户可以浏览、试用模型，并以最少的工作量将模型集成到自己的应用程序中。
* **API Access**：用于运行模型的简单 API，使开发者能够在自己的应用程序中轻松部署和扩展模型。

{{#include ../banners/hacktricks-training.md}}
