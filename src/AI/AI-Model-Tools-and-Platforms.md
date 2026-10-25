# AI Model Tools and Platforms

{{#include ../banners/hacktricks-training.md}}

## 로컬에서 모델 실행 및 학습

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers는 텍스트, 비전, 오디오, 비디오 및 멀티모달 작업 전반에서 사전 학습된 모델을 로드하고, 학습하고, 제공하기 위한 오픈소스 라이브러리입니다. 모델 및 데이터셋 호스팅은 별도로 Hugging Face Hub에서 제공합니다.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain은 프롬프트 구성, 대화 기록/상태 관리, 도구, 검색, 모델, API 및 데이터베이스 통합 기능을 갖춘 모델 기반 애플리케이션과 에이전트를 구축하기 위한 프레임워크입니다.<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT는 지원되는 언어 모델의 사전 학습, fine-tuning, 평가 및 배포를 위한 가독성 높은 구현과 명령줄 워크플로를 제공합니다.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**설명:**\
LitServe는 batching, streaming, acceleration 및 scaling hook을 갖춘 inference API를 제공하기 위한 Lightning AI의 모델 서빙 프레임워크입니다.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl은 YAML 구성으로 작동하는 오픈소스 post-training 및 fine-tuning 프레임워크입니다. full fine-tuning, LoRA/QLoRA, preference optimization, multi-GPU training과 같은 기법을 지원하며, 그 자체로는 cloud deployment platform이 아닙니다.<sup>[[5]](#references)</sup>

## 온라인에서 모델 사용해 보기

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face**는 특히 자연어 처리(NLP) 분야의 활동으로 잘 알려진 주요 머신러닝 플랫폼이자 커뮤니티입니다. 머신러닝 모델을 더 쉽게 개발하고, 공유하고, 배포할 수 있도록 도구, 라이브러리 및 리소스를 제공합니다.\
Hub는 다음과 같은 관련 섹션을 제공합니다:<sup>[[6]](#references)</sup>

* **모델**: 사용자가 텍스트 생성, 번역, 이미지 인식 등 다양한 작업에 사용할 **사전 학습된 머신러닝 모델**을 검색하고, 다운로드하고, 통합할 수 있는 방대한 저장소입니다.
* **데이터셋:** 모델 학습 및 평가에 사용되는 **데이터셋 모음**입니다. 다양한 데이터 소스에 쉽게 접근할 수 있어 사용자가 특정 머신러닝 프로젝트에 필요한 데이터를 찾고 활용할 수 있습니다.
* **Spaces:** **대화형 머신러닝 애플리케이션**과 데모를 호스팅하고 공유하는 플랫폼입니다. 개발자는 모델의 작동 모습을 **선보이고**, 사용자 친화적인 인터페이스를 만들고, 라이브 데모를 공유해 다른 사람들과 협업할 수 있습니다.

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub**는 재사용 가능한 학습된 모델 구성 요소를 위한 저장소이자 라이브러리로, 특히 TensorFlow/Keras를 통해 사용하는 모듈을 제공합니다. **Kaggle**은 별도로 노트북, 데이터셋, 대회 및 모델을 제공합니다.<sup>[[7]](#references)[[9]](#references)</sup>

* **모듈:** 사용자가 이미지 분류, 텍스트 임베딩 등의 작업에 사용할 사전 학습된 모델과 모델 구성 요소를 검색하고, 다운로드하고, 통합할 수 있는 방대한 모음입니다.
* **튜토리얼:** TensorFlow Hub를 사용해 모델을 구현하고 fine-tuning하는 데 도움이 되는 단계별 가이드와 예제입니다.
* **문서:** 개발자가 저장소의 리소스를 효과적으로 활용할 수 있도록 돕는 포괄적인 가이드와 API 참조입니다.

## [**Replicate**](https://replicate.com/home)

**Replicate**는 웹 인터페이스 또는 API를 통해 패키징된 머신러닝 모델을 실행하는 호스팅 플랫폼입니다.<sup>[[8]](#references)</sup>

* **모델:** 커뮤니티에서 기여한 머신러닝 모델 저장소입니다. 사용자는 모델을 검색하고, 사용해 보고, 최소한의 노력으로 애플리케이션에 통합할 수 있습니다.
* **API 접근:** 기반 inference 인프라를 직접 운영하지 않고 애플리케이션에서 모델을 호출할 수 있는 API입니다.

## 노출된 자체 호스팅 AI 서비스 공격

자체 호스팅 모델 실행기, 에이전트 빌더, ML 데모 UI, 컴퓨팅 클러스터 및 벡터 데이터베이스의 black-box fingerprinting 및 테스트는 [노출된 자체 호스팅 AI 서비스](AI-Exposed-Self-Hosted-AI-Services.md)를 확인하세요.

## References

- [1] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [2] [LangChain](https://github.com/langchain-ai/langchain)
- [3] [LitGPT](https://github.com/Lightning-AI/litgpt)
- [4] [LitServe](https://github.com/Lightning-AI/LitServe)
- [5] [Axolotl](https://github.com/axolotl-ai-cloud/axolotl)
- [6] [Hugging Face Hub 문서](https://huggingface.co/docs/hub/index)
- [7] [TensorFlow Hub](https://www.tensorflow.org/hub)
- [8] [Replicate 문서](https://replicate.com/docs)
- [9] [Kaggle 문서](https://www.kaggle.com/docs)
{{#include ../banners/hacktricks-training.md}}
