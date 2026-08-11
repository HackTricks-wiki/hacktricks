# LLM Training - Data Preparation

{{#include ../../banners/hacktricks-training.md}}

**매우 추천하는 책** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **에서 작성한 제 노트에 추가 정보를 덧붙였습니다.**<sup>[[1]](#references)</sup>

## 기본 정보

먼저 알아 두어야 할 기본 개념을 설명하는 다음 post를 읽는 것부터 시작해야 합니다:


{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenization

> [!TIP]
> 이 단계의 목표는 **입력을 tokens로 나누고 이를 token IDs에 매핑하는 것**입니다.


{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Data Sampling

> [!TIP]
> 이 단계의 목표는 선택한 context length에 맞는 training sequences와 이에 대응하는 shifted prediction targets를 준비하는 것입니다.


{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Token Embeddings

> [!TIP]
> 이 세 번째 단계의 목표는 매우 간단합니다. **이전 vocabulary의 각 token에 원하는 차원의 vector를 할당하여 model을 training하는 것**입니다. vocabulary의 각 word는 X차원 공간의 한 점이 됩니다.\
> 처음에는 공간에서 각 word의 위치가 단순히 "무작위로" 초기화되며, 이러한 위치는 trainable parameters입니다(training 중에 개선됩니다).
>
> 또한 token embedding 중에 **또 다른 embedding layer가 생성**되며, 이는 (이 경우) **training sentence에서 word의 절대 위치**를 나타냅니다. 따라서 sentence에서 서로 다른 위치에 있는 word는 서로 다른 representation을 갖습니다.


{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Attention Mechanisms

> [!TIP]
> 이 네 번째 단계의 목표는 매우 간단합니다. **일부 attention mechanisms를 적용하는 것**입니다. 이는 **LLM을 training하는 데 사용되는 현재 sentence에서 vocabulary의 word와 그 이웃 간의 관계를 포착하는 많은 반복 layer**가 됩니다.\
> 이를 위해 많은 layer가 사용되므로, 많은 trainable parameters가 이 정보를 포착하게 됩니다.


{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. LLM Architecture

> [!TIP]
> 이 다섯 번째 단계의 목표는 매우 간단합니다. **전체 LLM의 architecture를 개발하는 것**입니다. 모든 요소를 결합하고, 모든 layer를 적용하며, text를 생성하거나 text를 IDs로 변환하고 그 반대 작업을 수행하는 모든 function을 만듭니다.
>
> 이 architecture는 training과 training 후 text를 predicting하는 데 모두 사용됩니다.


{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Pre-training & Loading models

> [!TIP]
> 이 여섯 번째 단계의 목표는 매우 간단합니다. **model을 처음부터 training하는 것**입니다. 이를 위해 앞에서 만든 LLM architecture를 사용하고, 정의된 loss functions와 optimizer를 사용하여 model의 모든 parameters를 training하도록 data sets를 순회하는 loop를 실행합니다.


{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. LoRA Improvements in fine-tuning

> [!TIP]
> LoRA는 pretrained model을 fine-tuning하는 데 필요한 trainable parameters와 optimizer state의 수를 크게 줄입니다.


{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-Tuning for Classification

> [!TIP]
> 이 section의 목표는 이미 pre-trained된 model을 fine-tuning하여 새로운 text를 생성하는 대신 LLM이 **주어진 text가 각 주어진 category로 분류될 확률**을 제공하도록 하는 방법을 보여주는 것입니다(예: text가 spam인지 아닌지).


{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-Tuning to follow instructions

> [!TIP]
> 이 section의 목표는 단순히 text를 생성하는 대신 **이미 pre-trained된 model이 instructions를 따르도록 fine-tuning하는 방법**을 보여주는 것입니다. 예를 들어 chat bot처럼 task에 응답하도록 하는 것입니다.


{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

## References

- [1] [대규모 언어 모델 구축(처음부터) - Manning](https://www.manning.com/books/build-a-large-language-model-from-scratch)
{{#include ../../banners/hacktricks-training.md}}
