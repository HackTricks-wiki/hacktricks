# LLM 테스트

{{#include ../banners/hacktricks-training.md}}

## 로컬에서 모델 실행 및 학습

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers는 text, vision, audio, video 및 multimodal 작업 전반에서 pretrained 모델을 로드하고, 학습하고, 제공하기 위한 open-source library입니다. 모델 및 dataset hosting은 Hugging Face Hub에서 별도로 제공됩니다.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain은 prompt 구성, 대화 기록/state 관리, tools, retrieval, model, API 및 database integrations를 사용해 model-driven applications와 agents를 구축하기 위한 framework입니다.<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT는 지원되는 language models의 pretraining, fine-tuning, evaluation 및 deployment를 위한 읽기 쉬운 구현과 command-line workflows를 제공합니다.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**설명:**\
LitServe는 batching, streaming, acceleration 및 scaling hooks를 사용해 inference APIs를 노출하기 위한 Lightning AI의 model-serving framework입니다.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl은 YAML configuration으로 구동되는 open-source post-training 및 fine-tuning framework입니다. full fine-tuning, LoRA/QLoRA, preference optimization 및 multi-GPU training과 같은 techniques를 지원하지만, 그 자체가 cloud deployment platform은 아닙니다.<sup>[[5]](#references)</sup>

## 온라인에서 모델 사용해 보기

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face**는 특히 natural language processing (NLP) 분야에서의 활동으로 잘 알려진 machine learning 분야의 주요 platform이자 community입니다. machine learning models를 더 쉽게 개발하고, 공유하고, 배포할 수 있도록 tools, libraries 및 resources를 제공합니다.\
Hub는 다음과 같은 관련 sections를 제공합니다:<sup>[[6]](#references)</sup>

* **Models**: 사용자가 text generation, translation, image recognition 등의 다양한 작업에 사용할 **pre-trained machine learning models**를 탐색하고, 다운로드하고, 통합할 수 있는 방대한 repository입니다.
* **Datasets:** 모델 학습 및 평가에 사용되는 **datasets collection**입니다. 다양한 data sources에 쉽게 접근할 수 있도록 하여 사용자가 자신의 machine learning projects에 맞는 데이터를 찾고 활용할 수 있게 합니다.
* **Spaces:** **interactive machine learning applications** 및 demos를 호스팅하고 공유하기 위한 platform입니다. 개발자는 자신의 모델이 작동하는 모습을 **showcase**하고, user-friendly interfaces를 만들며, live demos를 공유해 다른 사람들과 협업할 수 있습니다.

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub**는 재사용 가능한 trained model components를 위한 repository이자 library이며, 특히 TensorFlow/Keras를 통해 소비되는 modules를 제공합니다. **Kaggle**은 별도로 notebooks, datasets, competitions 및 models를 제공합니다.<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules:** 사용자가 image classification, text embedding 등의 작업에 사용할 pre-trained models 및 model components를 탐색하고, 다운로드하고, 통합할 수 있는 방대한 collection입니다.
* **Tutorials:** TensorFlow Hub를 사용해 모델을 구현하고 fine-tune하는 데 도움이 되는 단계별 guides 및 examples입니다.
* **Documentation:** 개발자가 repository의 resources를 효과적으로 활용할 수 있도록 지원하는 comprehensive guides 및 API references입니다.

## [**Replicate**](https://replicate.com/home)

**Replicate**는 web interface 또는 API를 통해 packaged machine-learning models를 실행하기 위한 hosted platform입니다.<sup>[[8]](#references)</sup>

* **Models:** community가 제공하는 machine learning models의 repository로, 사용자는 이를 탐색하고, 시험하고, 최소한의 노력으로 자신의 applications에 통합할 수 있습니다.
* **API access:** 기본 inference infrastructure를 운영하지 않고도 applications에서 모델을 호출할 수 있는 APIs입니다.

## References

- [1] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [2] [LangChain](https://github.com/langchain-ai/langchain)
- [3] [LitGPT](https://github.com/Lightning-AI/litgpt)
- [4] [LitServe](https://github.com/Lightning-AI/LitServe)
- [5] [Axolotl](https://github.com/axolotl-ai-cloud/axolotl)
- [6] [Hugging Face Hub documentation](https://huggingface.co/docs/hub/index)
- [7] [TensorFlow Hub](https://www.tensorflow.org/hub)
- [8] [Replicate documentation](https://replicate.com/docs)
- [9] [Kaggle documentation](https://www.kaggle.com/docs)
{{#include ../banners/hacktricks-training.md}}
