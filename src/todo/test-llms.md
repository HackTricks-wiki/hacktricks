# LLMs 테스트

{{#include ../banners/hacktricks-training.md}}

## 로컬에서 모델 실행 및 학습

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers는 GPT, BERT 및 기타 여러 LLMs를 사용하고, 학습하고, 배포하기 위한 가장 인기 있는 open-source library 중 하나입니다. pre-trained models, datasets, 그리고 fine-tuning 및 deployment를 위한 Hugging Face Hub와의 원활한 통합을 포함하는 종합적인 ecosystem을 제공합니다.

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain은 LLMs를 사용해 애플리케이션을 구축하기 위해 설계된 framework입니다. 개발자는 language models를 external data sources, APIs 및 databases에 연결할 수 있습니다. LangChain은 고급 prompt engineering, conversation history 관리, 복잡한 workflows에 LLMs 통합을 위한 tools를 제공합니다.

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT는 Lightning AI가 개발한 project로, Lightning framework를 활용해 GPT-based models의 training, fine-tuning 및 deployment를 지원합니다. 다른 Lightning AI tools와 원활하게 통합되며, 향상된 performance와 scalability를 통해 large-scale language models를 처리하기 위한 최적화된 workflows를 제공합니다.

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Description:**\
LitServe는 AI models를 빠르고 효율적으로 배포하도록 설계된 Lightning AI의 deployment tool입니다. 확장 가능하고 최적화된 serving capabilities를 제공해 LLMs를 real-time applications에 통합하는 과정을 간소화합니다.

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl은 LLMs를 포함한 AI models의 deployment, scaling 및 management를 간소화하도록 설계된 cloud-based platform입니다. automated scaling, monitoring 및 다양한 cloud services와의 integration 같은 features를 제공하므로, 광범위한 infrastructure management 없이도 production environments에 models를 더욱 쉽게 배포할 수 있습니다.

## 온라인에서 models 사용

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face**는 특히 natural language processing (NLP) 분야의 활동으로 잘 알려진, machine learning을 위한 대표적인 platform이자 community입니다. machine learning models를 더욱 쉽게 개발, 공유 및 배포할 수 있도록 tools, libraries 및 resources를 제공합니다.\
다음과 같은 여러 sections를 제공합니다.

* **Models**: 사용자가 text generation, translation, image recognition 및 기타 다양한 tasks에 사용할 models를 검색, 다운로드 및 통합할 수 있는 방대한 **pre-trained machine learning models** repository입니다.
* **Datasets:** models의 training 및 evaluation에 사용되는 종합적인 **datasets collection**입니다. 다양한 data sources에 쉽게 접근할 수 있도록 하여, 사용자가 특정 machine learning projects에 필요한 data를 찾고 활용할 수 있게 합니다.
* **Spaces:** **interactive machine learning applications** 및 demos를 호스팅하고 공유하기 위한 platform입니다. 개발자는 models의 작동 모습을 **showcase**하고, user-friendly interfaces를 만들며, live demos를 공유해 다른 사람들과 협업할 수 있습니다.

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub**는 Google이 개발한 재사용 가능한 machine learning modules의 종합적인 repository입니다. machine learning models, 특히 TensorFlow로 구축된 models의 공유 및 deployment를 지원하는 데 중점을 둡니다.

* **Modules:** 사용자가 image classification, text embedding 및 기타 tasks를 위한 modules를 검색, 다운로드 및 통합할 수 있는 방대한 pre-trained models 및 model components collection입니다.
* **Tutorials:** 사용자가 TensorFlow Hub를 사용해 models를 구현하고 fine-tune하는 방법을 이해할 수 있도록 돕는 단계별 guides 및 examples입니다.
* **Documentation:** 개발자가 repository의 resources를 효과적으로 활용할 수 있도록 지원하는 종합적인 guides 및 API references입니다.

## [**Replicate**](https://replicate.com/home)

**Replicate**는 개발자가 간단한 API를 통해 cloud에서 machine learning models를 실행할 수 있도록 하는 platform입니다. 광범위한 infrastructure setup 없이 ML models에 쉽게 접근하고 배포할 수 있도록 하는 데 중점을 둡니다.

* **Models:** community가 기여한 machine learning models repository로, 사용자는 models를 검색하고, 사용해 보고, 최소한의 노력으로 자신의 applications에 통합할 수 있습니다.
* **API Access:** 개발자가 자신의 applications 내에서 models를 손쉽게 배포하고 확장할 수 있도록 models를 실행하기 위한 간단한 APIs입니다.

{{#include ../banners/hacktricks-training.md}}
