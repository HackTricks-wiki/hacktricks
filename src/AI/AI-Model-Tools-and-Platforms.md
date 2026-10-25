# AI 模型工具与平台

{{#include ../banners/hacktricks-training.md}}

## 在本地运行和训练模型

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers 是一个开源库，可用于加载、训练和提供预训练模型，支持文本、视觉、音频、视频和多模态任务。模型和数据集由 Hugging Face Hub 单独托管。<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain 是一个用于构建由模型驱动的应用和 agents 的框架，提供提示构建、对话历史/状态管理、工具、检索、模型、API 和数据库集成。<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT 提供易读的实现和命令行工作流，用于对支持的语言模型进行预训练、微调、评估和部署。<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**描述：**\
LitServe 是 Lightning AI 的模型服务框架，可用于提供推理 API，并支持批处理、流式传输、加速和扩展钩子。<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl 是一个由 YAML 配置驱动的开源后训练和微调框架。它支持全量微调、LoRA/QLoRA、偏好优化和多 GPU 训练等技术；它本身不是云部署平台。<sup>[[5]](#references)</sup>

## 在线试用模型

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** 是领先的机器学习平台和社区，尤其以其在自然语言处理（NLP）领域的工作而闻名。它提供工具、库和资源，让机器学习模型的开发、共享和部署更加便捷。\
Hub 提供几个相关板块：<sup>[[6]](#references)</sup>

* **Models**：包含大量**预训练机器学习模型**的仓库，用户可以浏览、下载并集成用于文本生成、翻译、图像识别等任务的模型。
* **Datasets：**用于训练和评估模型的综合**数据集集合**。它便于访问多种数据源，帮助用户为特定的机器学习项目查找和使用数据。
* **Spaces：**用于托管和分享**交互式机器学习应用**和演示的平台。开发者可以借此**展示**模型的运行效果、创建易用的界面，并通过分享实时演示与他人协作。

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **与** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** 是一个可复用训练模型组件的仓库和库，尤其适用于通过 TensorFlow/Keras 使用的模块。**Kaggle** 则单独提供 notebooks、数据集、竞赛和模型。<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules:** 大量预训练模型和模型组件的集合，用户可以浏览、下载并集成用于图像分类、文本嵌入等任务的模块。
* **Tutorials:** 分步指南和示例，帮助用户使用 TensorFlow Hub 实现和微调模型。
* **Documentation:** 全面的指南和 API 参考，帮助开发者有效利用仓库资源。

## [**Replicate**](https://replicate.com/home)

**Replicate** 是一个托管平台，可通过 Web 界面或 API 运行打包好的机器学习模型。<sup>[[8]](#references)</sup>

* **Models:** 社区贡献的机器学习模型仓库，用户可以浏览、试用模型，并以最少的工作将其集成到应用中。
* **API access:** 提供 API，应用可以通过这些 API 调用模型，而无需自行运行底层推理基础设施。

## 攻击暴露的自托管 AI 服务

如需对自托管模型运行器、agent 构建工具、ML 演示 UI、计算集群和向量数据库进行 black-box 指纹识别和测试，请参阅 [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md)。

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
