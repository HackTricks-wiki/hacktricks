# AI 모델 도구 및 플랫폼

{{#include ../banners/hacktricks-training.md}}

## 로컬에서 모델 실행 및 학습

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers는 텍스트, 비전, 오디오, 비디오 및 멀티모달 작업 전반에서 사전 학습된 모델을 로드하고, 학습하고, 제공하는 오픈 소스 라이브러리입니다. 모델 및 데이터셋 호스팅은 별도로 Hugging Face Hub에서 제공합니다.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain은 프롬프트 구성, 대화 기록/상태 관리, 도구, 검색, 모델, API 및 데이터베이스 통합 기능을 갖춘 모델 기반 애플리케이션과 에이전트를 구축하기 위한 프레임워크입니다.<sup>[[2]](#references)</sup>

#### LangChain 직렬화 객체 복원 테스트

애플리케이션이 **구조화된** 사용자 입력이나 모델 출력을 허용하는 경우, 중첩된 딕셔너리가 `metadata`, `additional_kwargs`, `response_metadata`, 저장된 채팅 기록 또는 실행 스트림에 유지되는지 추적하세요. LangChain은 직렬화된 객체에 `lc` 태그가 붙은 딕셔너리를 사용합니다. 취약한 `dumps()`/`dumpd()` → `load()`/`loads()` 왕복 처리에서는 공격자가 제어하는 딕셔너리가 데이터로 남지 않고 프레임워크 객체로 복원될 수 있습니다. 신뢰할 수 없는 매니페스트를 직접 로드하는 것도 위험합니다. 딕셔너리로 파싱되지 않는 일반 문자열 입력은 이 전제 조건에 해당하지 않습니다.<sup>[[10]](#references)[[11]](#references)</sup>

승인된 테스트에서는 무해한 생성자 형태의 canary를 문자열이 아닌 **중첩된 JSON 객체로** 제출하고, 이후 기록이나 스트림에 원래 딕셔너리 대신 `AIMessage` 객체가 포함되는지 확인하세요:<sup>[[11]](#references)</sup>

```json
{"lc":1,"type":"constructor","id":["langchain_core","messages","ai","AIMessage"],"kwargs":{"content":"serialization-canary"}}
```

실제로 사용될 때 `RunnableWithMessageHistory`, `astream_log()`, `astream_events(version="v1")`를 확인하세요. 객체 복원이 성공하더라도 이후 채팅 기록을 오염시킬 수 있으며, 더 광범위한 allowlist를 사용하면 생성자에 부작용이 있는 다른 신뢰된 클래스를 인스턴스화할 수 있습니다. 이를 제한 없는 pickle 실행과 동일시해서는 안 됩니다. 최초의 이스케이프 취약점은 `langchain-core` 0.3.81/1.2.5에서 수정되었으며, 이후 광범위한 allowlist 및 secret-marker 수정은 0.3.85/1.3.3에 적용되었습니다. 신뢰할 수 없는 매니페스트의 경우 최신 릴리스를 사용하고, `allowed_objects`를 메시지 클래스 또는 명시적으로 안전한 목록으로 제한하며, `secrets_from_env=False`로 설정하세요.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup> [에이전트 신뢰 경계 매핑](AI-Agent-Security-Methodology.md)에서는 이를 [모델 파일 로딩 RCE](AI-Models-RCE.md)와 구분하세요.

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT는 지원되는 언어 모델의 사전 학습, fine-tuning, 평가 및 배포를 위한 읽기 쉬운 구현과 명령줄 워크플로를 제공합니다.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**설명:**\
LitServe는 batching, streaming, acceleration 및 scaling을 위한 훅을 제공하여 추론 API를 노출하는 Lightning AI의 모델 서빙 프레임워크입니다.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl은 YAML 설정을 사용하는 오픈 소스 post-training 및 fine-tuning 프레임워크입니다. 전체 fine-tuning, LoRA/QLoRA, preference optimization, multi-GPU training 등의 기법을 지원합니다. Axolotl 자체는 클라우드 배포 플랫폼이 아닙니다.<sup>[[5]](#references)</sup>

## 온라인으로 모델 사용해 보기

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face**는 특히 자연어 처리(NLP) 분야에서 잘 알려진 머신 러닝 플랫폼이자 커뮤니티입니다. 머신 러닝 모델을 더 쉽게 개발하고, 공유하고, 배포할 수 있도록 도구, 라이브러리 및 리소스를 제공합니다.\
Hub에는 다음과 같은 관련 섹션이 있습니다:<sup>[[6]](#references)</sup>

* **Models**: 사용자가 텍스트 생성, 번역, 이미지 인식 등의 다양한 작업에 사용할 모델을 찾아보고, 다운로드하고, 통합할 수 있는 방대한 **사전 학습된 머신 러닝 모델** 저장소입니다.
* **Datasets:** 모델 학습 및 평가에 사용되는 **데이터셋 모음**입니다. 다양한 데이터 소스에 쉽게 접근할 수 있어, 사용자가 특정 머신 러닝 프로젝트에 필요한 데이터를 찾아 활용할 수 있습니다.
* **Spaces:** **인터랙티브 머신 러닝 애플리케이션**과 데모를 호스팅하고 공유하는 플랫폼입니다. 개발자는 모델의 작동 모습을 **선보이고**, 사용자 친화적인 인터페이스를 만들며, 라이브 데모를 공유해 다른 사람들과 협업할 수 있습니다.

#### 공개 Space 런타임 로그 확인

공개 Space의 저장소 코드를 보면 앱이 어떤 입력과 환경 변수를 로그에 기록하는지 파악할 수 있습니다. 승인된 평가에서는 앱 UI와 별도의 표면으로 **run** 로그 스트림을 확인하세요. Hugging Face는 Space 로그용 SSE 엔드포인트를 문서화하고 있습니다. 조사 결과, 다른 Hub 사용자가 공개 Space 로그를 읽을 수 있었으며, 로그에 API 키, 사용자 프롬프트 또는 요청 URL에 기록된 Dev Mode 액세스 토큰이 포함된 경우도 있었습니다. 로그에 토큰이 있다는 사실이 문제가 되려면 해당 토큰에 대응하는 권한 모드가 여전히 활성화되어 있고 토큰도 유효해야 합니다.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
SPACE='owner/space-name'
curl -NsS -H "Authorization: Bearer $HF_TOKEN" \
  "https://huggingface.co/api/spaces/$SPACE/logs/run?tail=100"
```

승인된 Hub 계정의 token을 사용하세요. 이는 Space 소유자의 secret을 요청하는 것이 **아닙니다**. 응답은 SSE 스트림입니다(`data:` 줄). 변수 이름만으로 해당 값이 leak되었다고 단정하지 말고, 노출된 값을 Space 코드 및 현재 runtime과 대조하세요. [self-hosted Gradio 또는 model-runner endpoint](AI-Exposed-Self-Hosted-AI-Services.md)는 해당 페이지의 안내를 따르세요.<sup>[[13]](#references)[[14]](#references)</sup>

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **및** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub**는 재사용 가능한 학습된 모델 구성 요소를 위한 저장소이자 라이브러리로, 특히 TensorFlow/Keras를 통해 사용하는 모듈을 제공합니다. **Kaggle**은 별도로 notebook, dataset, competition, model을 제공합니다.<sup>[[7]](#references)[[9]](#references)</sup>

* **모듈:** 이미지 분류, text embedding 등의 작업에 사용할 모듈을 찾아보고 다운로드하여 통합할 수 있는 방대한 사전 학습 모델 및 모델 구성 요소 모음입니다.
* **튜토리얼:** TensorFlow Hub를 사용해 모델을 구현하고 fine-tune하는 단계별 안내와 예제를 제공합니다.
* **문서:** 개발자가 저장소의 리소스를 효과적으로 활용할 수 있도록 종합적인 안내와 API 참조를 제공합니다.

## [**Replicate**](https://replicate.com/home)

**Replicate**는 웹 인터페이스 또는 API를 통해 패키징된 machine-learning model을 실행하는 호스팅 플랫폼입니다.<sup>[[8]](#references)</sup>

* **모델:** 커뮤니티가 제공한 machine learning model 저장소입니다. 사용자는 이를 찾아보고 시험해 볼 수 있으며, 최소한의 노력으로 애플리케이션에 통합할 수 있습니다.
* **API 액세스:** 기반 inference 인프라를 운영하지 않고도 애플리케이션에서 모델을 호출할 수 있는 API를 제공합니다.

## 노출된 self-hosted AI 서비스 공격

self-hosted model runner, agent builder, ML demo UI, compute cluster, vector database를 대상으로 한 black-box fingerprinting 및 테스트는 [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md)를 참조하세요.



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
- [10] [LangChain serialization injection 보안 권고](https://github.com/langchain-ai/langchain/security/advisories/GHSA-c67j-w6g6-q2cm)
- [11] [LangChain unsafe object revival 보안 권고](https://github.com/langchain-ai/langchain/security/advisories/GHSA-pjwx-r37v-7724)
- [12] [LangChain load API 및 threat model](https://github.com/langchain-ai/langchain/blob/master/libs/core/langchain_core/load/load.py)
- [13] [Hugging Face Spaces logs API](https://huggingface.co/docs/hub/main/en/spaces-gpus#streaming-logs-events-and-metrics)
- [14] [Your Space is My Zone: model hub의 AI 앱 보안 위험](https://arxiv.org/abs/2606.30373)
{{#include ../banners/hacktricks-training.md}}
