# 测试 LLMs

{{#include ../banners/hacktricks-training.md}}

## 在本地运行和训练 models

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers 是一个开源 library，用于在文本、视觉、音频、视频和多模态任务中加载、训练和提供预训练 models。Model 和 dataset hosting 由 Hugging Face Hub 单独提供。<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain 是一个用于构建由 model 驱动的应用程序和 agents 的 framework，支持 prompt 构建、对话历史/state 管理、tools、retrieval、model、API 和 database 集成。<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT 提供了易读的实现和命令行工作流，用于对受支持的 language models 进行预训练、fine-tuning、评估和部署。<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**描述：**\
LitServe 是 Lightning AI 提供的 model-serving framework，用于通过 batching、streaming、加速和 scaling hooks 暴露 inference APIs。<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl 是一个由 YAML 配置驱动的开源 post-training 和 fine-tuning framework。它支持 full fine-tuning、LoRA/QLoRA、preference optimization 和 multi-GPU training 等技术；它本身不是 cloud deployment platform。<sup>[[5]](#references)</sup>

## 在线试用 models

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** 是一个领先的 machine learning platform 和 community，尤其以其在 natural language processing (NLP) 领域的工作而闻名。它提供 tools、libraries 和 resources，使 machine learning models 的开发、分享和部署更加容易。\
Hub 提供了几个相关部分：<sup>[[6]](#references)</sup>

* **Models**：一个庞大的**预训练 machine learning models** repository，用户可以浏览、下载并集成 models，用于文本生成、翻译、图像识别等各种任务。
* **Datasets：** 用于训练和评估 models 的综合性**datasets 集合**。它便于访问多样化的数据源，使用户能够为特定的 machine learning 项目查找和使用数据。
* **Spaces：** 用于托管和分享**交互式 machine learning 应用程序**及 demos 的 platform。它允许开发者**展示** models 的运行效果、创建易于使用的 interfaces，并通过分享 live demos 与他人协作。

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** 是一个用于可复用训练 model 组件的 repository 和 library，尤其是通过 TensorFlow/Keras 使用的 modules。**Kaggle** 则单独提供 notebooks、datasets、competitions 和 models。<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules：** 一个庞大的预训练 models 和 model 组件集合，用户可以浏览、下载并集成 modules，用于图像分类、文本 embedding 等任务。
* **Tutorials：** 分步指南和示例，帮助用户使用 TensorFlow Hub 实现和 fine-tune models。
* **Documentation：** 全面的指南和 API references，帮助开发者有效利用 repository 的 resources。

## [**Replicate**](https://replicate.com/home)

**Replicate** 是一个 hosted platform，允许用户通过 web interface 或 API 运行打包的 machine-learning models。<sup>[[8]](#references)</sup>

* **Models：** 一个由 community 贡献的 machine learning models repository，用户可以浏览、试用并以最小的工作量将 models 集成到自己的应用程序中。
* **API access：** 用于从应用程序调用 models 的 APIs，无需运行底层 inference infrastructure。

## References

- [1] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [2] [LangChain](https://github.com/langchain-ai/langchain)
- [3] [LitGPT](https://github.com/Lightning-AI/litgpt)
- [4] [LitServe](https://github.com/Lightning-AI/LitServe)
- [5] [Axolotl](https://github.com/axolotl-ai-cloud/axolotl)
- [6] [Hugging Face Hub 文档](https://huggingface.co/docs/hub/index)
- [7] [TensorFlow Hub](https://www.tensorflow.org/hub)
- [8] [Replicate 文档](https://replicate.com/docs)
- [9] [Kaggle 文档](https://www.kaggle.com/docs)
{{#include ../banners/hacktricks-training.md}}
