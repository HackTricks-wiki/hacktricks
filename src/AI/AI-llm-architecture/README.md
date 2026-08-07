# LLM Training - Data Preparation

{{#include ../../banners/hacktricks-training.md}}

**다음은 매우 추천하는 책** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **에서 정리한 노트에 추가 정보를 더한 것입니다.**<sup>[[1]](#references)</sup>

## 기본 정보

먼저 다음 글을 읽고 알아 두어야 할 기본 개념을 학습하세요:


{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenization

> [!TIP]
> 이 초기 단계의 목표는 매우 간단합니다. **입력을 적절한 방식으로 토큰(ids)으로 나누는 것입니다.**


{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Data Sampling

> [!TIP]
> 이 두 번째 단계의 목표는 매우 간단합니다. **입력 데이터를 샘플링하고 training 단계에 사용할 수 있도록 준비하는 것입니다. 일반적으로 데이터셋을 특정 길이의 문장으로 나누고 예상 응답도 생성합니다.**


{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Token Embeddings

> [!TIP]
> 이 세 번째 단계의 목표는 매우 간단합니다. **앞서 정의한 vocabulary의 각 토큰에 원하는 차원의 vector를 할당하여 model을 training하는 것입니다.** vocabulary의 각 단어는 X차원 공간의 한 점이 됩니다.\
> 처음에는 공간에서 각 단어의 위치가 단순히 "무작위"로 초기화되며, 이러한 위치는 trainable parameter입니다(training 중에 개선됩니다).
>
> 또한 token embedding 중에 **또 다른 embedding layer가 생성됩니다.** 이 layer는 (이 경우) training 문장에서 **단어의 절대 위치**를 나타냅니다. 따라서 문장에서 서로 다른 위치에 있는 단어는 서로 다른 representation(의미)을 갖게 됩니다.


{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Attention Mechanisms

> [!TIP]
> 이 네 번째 단계의 목표는 매우 간단합니다. **일부 attention mechanism을 적용하는 것입니다.** 이 mechanism은 **현재 LLM training에 사용되는 문장에서 vocabulary의 단어와 그 주변 단어 사이의 관계를 포착하는 여러 개의 반복 layer**로 구성됩니다.\
> 이를 위해 많은 layer가 사용되므로, 많은 trainable parameter가 이 정보를 포착하게 됩니다.


{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. LLM Architecture

> [!TIP]
> 이 다섯 번째 단계의 목표는 매우 간단합니다. **전체 LLM의 architecture를 개발하는 것입니다.** 모든 요소를 결합하고, 모든 layer를 적용하며, text를 생성하거나 text를 ID로 변환하고 그 반대 작업을 수행하는 모든 function을 만듭니다.
>
> 이 architecture는 training과 training이 완료된 후 text를 예측하는 데 모두 사용됩니다.


{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Pre-training & Loading models

> [!TIP]
> 이 여섯 번째 단계의 목표는 매우 간단합니다. **model을 처음부터 training하는 것입니다.** 이를 위해 앞서 만든 LLM architecture를 사용하고, 정의된 loss function과 optimizer를 사용하여 model의 모든 parameter를 training하도록 데이터셋을 순회하는 loop를 실행합니다.


{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. LoRA Improvements in fine-tuning

> [!TIP]
> **LoRA를 사용하면** 이미 training된 model을 **fine-tuning하는 데 필요한 computation을 크게 줄일 수 있습니다.**


{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-Tuning for Classification

> [!TIP]
> 이 section의 목표는 이미 pre-trained된 model을 fine-tuning하여 새로운 text를 생성하는 대신, LLM이 **주어진 text가 각 category에 속할 확률을 제공하도록 하는 방법을 보여주는 것입니다.** (예: text가 spam인지 아닌지 분류)


{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-Tuning to follow instructions

> [!TIP]
> 이 section의 목표는 단순히 text를 생성하는 것이 아니라 **이미 pre-trained된 model이 instructions를 따르도록 fine-tuning하는 방법을 보여주는 것입니다.** 예를 들어 chat bot처럼 task에 응답하도록 만드는 것입니다.


{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

## 참고 자료

- [1] [Build a Large Language Model (From Scratch) - Manning](https://www.manning.com/books/build-a-large-language-model-from-scratch)

{{#include ../../banners/hacktricks-training.md}}
