# Test LLMs

{{#include ../banners/hacktricks-training.md}}

## Run & train models locally

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers는 GPT, BERT 및 기타 여러 LLM을 사용하고 훈련하며 배포하는 데 가장 인기 있는 오픈 소스 라이브러리 중 하나입니다. 사전 훈련된 모델, 데이터셋 및 미세 조정 및 배포를 위한 Hugging Face Hub와의 원활한 통합을 포함하는 포괄적인 생태계를 제공합니다.

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain은 LLM으로 애플리케이션을 구축하기 위해 설계된 프레임워크입니다. 개발자가 언어 모델을 외부 데이터 소스, API 및 데이터베이스와 연결할 수 있도록 합니다. LangChain은 고급 프롬프트 엔지니어링, 대화 기록 관리 및 LLM을 복잡한 워크플로에 통합하기 위한 도구를 제공합니다.

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT는 Lightning AI에서 개발한 프로젝트로, Lightning 프레임워크를 활용하여 GPT 기반 모델의 훈련, 미세 조정 및 배포를 용이하게 합니다. 다른 Lightning AI 도구와 원활하게 통합되어 대규모 언어 모델을 처리하기 위한 최적화된 워크플로를 제공합니다.

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**설명:**\
LitServe는 AI 모델을 신속하고 효율적으로 배포하기 위해 설계된 Lightning AI의 배포 도구입니다. LLM을 실시간 애플리케이션에 통합하는 것을 간소화하여 확장 가능하고 최적화된 서비스 기능을 제공합니다.

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl은 LLM을 포함한 AI 모델의 배포, 확장 및 관리를 간소화하기 위해 설계된 클라우드 기반 플랫폼입니다. 자동 확장, 모니터링 및 다양한 클라우드 서비스와의 통합과 같은 기능을 제공하여 광범위한 인프라 관리 없이도 프로덕션 환경에서 모델을 쉽게 배포할 수 있도록 합니다.

## Try models online

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face**는 기계 학습을 위한 선도적인 플랫폼이자 커뮤니티로, 자연어 처리(NLP) 분야에서 특히 잘 알려져 있습니다. 기계 학습 모델을 개발, 공유 및 배포하는 데 도움이 되는 도구, 라이브러리 및 리소스를 제공합니다.\
여러 섹션을 제공합니다:

* **Models**: 사용자가 텍스트 생성, 번역, 이미지 인식 등 다양한 작업을 위해 모델을 탐색하고 다운로드하며 통합할 수 있는 방대한 **사전 훈련된 기계 학습 모델** 저장소입니다.
* **Datasets:** 모델 훈련 및 평가에 사용되는 포괄적인 **데이터셋 모음**입니다. 다양한 데이터 소스에 쉽게 접근할 수 있도록 하여 사용자가 특정 기계 학습 프로젝트에 필요한 데이터를 찾고 활용할 수 있게 합니다.
* **Spaces:** **인터랙티브 기계 학습 애플리케이션** 및 데모를 호스팅하고 공유하기 위한 플랫폼입니다. 개발자가 모델을 실제로 보여주고, 사용자 친화적인 인터페이스를 만들며, 라이브 데모를 공유하여 다른 사람들과 협업할 수 있도록 합니다.

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub**는 Google에서 개발한 재사용 가능한 기계 학습 모듈의 포괄적인 저장소입니다. 기계 학습 모델, 특히 TensorFlow로 구축된 모델의 공유 및 배포를 용이하게 하는 데 중점을 둡니다.

* **Modules:** 사용자가 이미지 분류, 텍스트 임베딩 등과 같은 작업을 위해 모듈을 탐색하고 다운로드하며 통합할 수 있는 방대한 사전 훈련된 모델 및 모델 구성 요소의 모음입니다.
* **Tutorials:** 사용자가 TensorFlow Hub를 사용하여 모델을 구현하고 미세 조정하는 방법을 이해하는 데 도움이 되는 단계별 가이드 및 예제입니다.
* **Documentation:** 개발자가 저장소의 리소스를 효과적으로 활용하는 데 도움을 주는 포괄적인 가이드 및 API 참조입니다.

## [**Replicate**](https://replicate.com/home)

**Replicate**는 개발자가 간단한 API를 통해 클라우드에서 기계 학습 모델을 실행할 수 있도록 하는 플랫폼입니다. 광범위한 인프라 설정 없이 ML 모델을 쉽게 접근하고 배포할 수 있도록 하는 데 중점을 둡니다.

* **Models:** 사용자가 탐색하고 시도하며 최소한의 노력으로 애플리케이션에 모델을 통합할 수 있는 커뮤니티에서 기여한 기계 학습 모델의 저장소입니다.
* **API Access:** 개발자가 자신의 애플리케이션 내에서 모델을 쉽게 배포하고 확장할 수 있도록 하는 간단한 API입니다.


{{#include ../banners/hacktricks-training.md}}
