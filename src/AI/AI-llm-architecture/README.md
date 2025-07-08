# LLM Training - Data Preparation

{{#include /banners/hacktricks-training.md}}

**이것은 매우 추천하는 책** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **에서의 내 노트와 추가 정보입니다.**

## Basic Information

기본 개념에 대해 알아야 할 내용을 위해 이 게시물을 읽는 것으로 시작해야 합니다:

{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenization

> [!TIP]
> 이 초기 단계의 목표는 매우 간단합니다: **입력을 의미 있는 방식으로 토큰(아이디)으로 나누는 것입니다.**

{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Data Sampling

> [!TIP]
> 이 두 번째 단계의 목표는 매우 간단합니다: **입력 데이터를 샘플링하고 훈련 단계에 맞게 준비하는 것입니다. 일반적으로 데이터셋을 특정 길이의 문장으로 나누고 예상 응답도 생성합니다.**

{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Token Embeddings

> [!TIP]
> 이 세 번째 단계의 목표는 매우 간단합니다: **어휘의 각 이전 토큰에 원하는 차원의 벡터를 할당하여 모델을 훈련하는 것입니다.** 어휘의 각 단어는 X 차원의 공간에서 한 점이 됩니다.\
> 처음에 각 단어의 위치는 "무작위로" 초기화되며, 이 위치는 훈련 가능한 매개변수입니다(훈련 중 개선됩니다).
>
> 게다가, 토큰 임베딩 동안 **또 다른 임베딩 레이어가 생성됩니다**. 이는 (이 경우) **훈련 문장에서 단어의 절대 위치를 나타냅니다.** 이렇게 하면 문장에서 서로 다른 위치에 있는 단어는 서로 다른 표현(의미)을 갖게 됩니다.

{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Attention Mechanisms

> [!TIP]
> 이 네 번째 단계의 목표는 매우 간단합니다: **일부 주의 메커니즘을 적용하는 것입니다.** 이는 LLM을 훈련하는 데 사용되는 현재 문장에서 단어와 이웃 간의 관계를 **포착하는 많은 반복 레이어**가 될 것입니다.\
> 이를 위해 많은 레이어가 사용되므로 많은 훈련 가능한 매개변수가 이 정보를 포착하게 됩니다.

{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. LLM Architecture

> [!TIP]
> 이 다섯 번째 단계의 목표는 매우 간단합니다: **전체 LLM의 아키텍처를 개발하는 것입니다.** 모든 것을 함께 모으고, 모든 레이어를 적용하고, 텍스트를 생성하거나 텍스트를 ID로 변환하고 그 반대로 변환하는 모든 기능을 만듭니다.
>
> 이 아키텍처는 훈련 후 텍스트를 예측하는 데에도 사용됩니다.

{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Pre-training & Loading models

> [!TIP]
> 이 여섯 번째 단계의 목표는 매우 간단합니다: **모델을 처음부터 훈련하는 것입니다.** 이를 위해 이전 LLM 아키텍처를 사용하여 정의된 손실 함수와 최적화를 사용하여 데이터 세트를 반복하면서 모델의 모든 매개변수를 훈련합니다.

{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. LoRA Improvements in fine-tuning

> [!TIP]
> **LoRA의 사용은 이미 훈련된 모델을 미세 조정하는 데 필요한 계산을 많이 줄입니다.**

{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-Tuning for Classification

> [!TIP]
> 이 섹션의 목표는 이미 사전 훈련된 모델을 미세 조정하는 방법을 보여주는 것입니다. 따라서 새로운 텍스트를 생성하는 대신 LLM은 **주어진 텍스트가 각 주어진 카테고리에 분류될 확률을 선택합니다** (예: 텍스트가 스팸인지 아닌지).

{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-Tuning to follow instructions

> [!TIP]
> 이 섹션의 목표는 **텍스트를 생성하는 대신 지침을 따르도록 이미 사전 훈련된 모델을 미세 조정하는 방법을 보여주는 것입니다.** 예를 들어, 챗봇으로서 작업에 응답하는 것입니다.

{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

{{#include /banners/hacktricks-training.md}}
