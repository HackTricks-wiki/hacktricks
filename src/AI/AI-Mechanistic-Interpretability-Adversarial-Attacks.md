# Mechanistic-Interpretability-Guided Adversarial Attacks

{{#include ../banners/hacktricks-training.md}}

## 공격 표면으로서의 중첩

매개변수가 부족한 활성화 공간은 특성을 비직교 벡터에 할당하여 차원 수보다 더 많은 의미적 특성을 인코딩할 수 있습니다. 그 결과, 활성화된 특성은 다른 특성 방향에도 투영됩니다. 학습 과정에서 분포 내에서 관찰된 조합은 보정할 수 있지만, 유효한 특성들이 이례적으로 조합되면 입력에 없는 대상 특성의 방향으로 값이 더해질 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

특성 벡터 `v_i ∈ R^D`, 활성화 `a_i`, 대상 `t`에 대해 다음 크기를 사용하면 후보 조합을 찾는 데 유용합니다.<sup>[[1]](#references)</sup>

```text
I_t = Σ_i≠t |a_i (v_i · v_t) / ||v_t|| |
candidate condition: I_t > max(a)
```

이는 선별을 위한 휴리스틱일 뿐입니다. 익스플로잇은 부호와 크기를 유지하고 실제 디코더를 평가해야 합니다. 예를 들어 tied-weight 선형 디코더에서는 `h_hat[t] = ReLU(b_t + Σ_i a_i(v_i · v_t))`를 계산합니다. 음수 항은 공격 효과를 상쇄할 수 있으며, 디코더 편향, 특성 벡터 노름, 활성화 임계값, ReLU 게이팅으로 인해 절대 코사인 유사도 점수가 커도 대상 활성화가 발생하지 않을 수 있습니다.<sup>[[1]](#references)</sup>

## White-box attack workflow

실용적인 평가에는 모델 병목, sparse autoencoder(SAE) 또는 다른 해석 가능한 특성 사전을 사용할 수 있습니다. 목표는 단순히 최종 클래스를 바꾸는 것이 아니라, 압축 전에는 활성화되지 않았던 특정 내부 특성이 복원 과정에서 나타나게 하는 것입니다. 제안하는 워크플로는 다음과 같습니다.<sup>[[1]](#references)</sup>

1. **특성 방향 복구:** 관련 인코더/디코더 벡터를 추출하고, 죽은 특성을 제거한 뒤, 최대 활성화 샘플이나 특성 회로 분석을 이용해 활성 방향을 개념에 대응시킵니다.
2. **간섭 순위 지정:** 벡터 사본을 정규화하고 코사인 유사도 행렬을 계산한 다음 대각선을 0으로 설정하고, 대상의 가장 강한 대각선 외 이웃을 살펴봅니다. 실제 활성화 크기와 부호가 있는 원시 내적을 사용해 후보를 다시 계산합니다.
3. **동시 활성화 조건 충족:** 같은 계층이나 잔차 스트림에서 동시에 활성화할 수 있는, 양의 기여를 하는 소규모 특성 집합을 유지합니다. 학습 데이터에서 드물거나 나타나지 않는 조합을 우선합니다. 일반적인 상관 조합은 학습 과정에서 보정되었을 가능성이 더 높습니다.
4. **입력 합성:** 선택한 기여 특성에 대해 데이터셋 예시나 활성화를 최대화하는 패턴을 결합합니다. 값 범위가 제한된 선형 픽셀 검출기에서는 양의 가중치에 해당하는 픽셀을 높게, 음의 가중치에 해당하는 픽셀을 낮게 설정한 다음 결과 패턴을 겹칩니다. 입력이 분포 내 구조를 유지하고 억제하는 **음의 공간**을 보존하면 관련 없는 특성의 활성화를 줄일 수 있습니다.
5. **메커니즘 검증:** 한 번의 순전파에서 압축 전 활성화, 압축된 좌표, 복원된 활성화, 다운스트림 출력을 기록합니다. 성공적인 테스트에서는 복원 전 대상 특성이 비활성 상태였다가 복원 후 활성화되고, 기여 특성을 제거하면 예측된 변화가 사라집니다.

다음의 최소 분류 코드는 특성 벡터가 **행**인 tied-weight 디코더에서 기여 특성의 순위를 지정합니다(특성이 열로 저장되어 있다면 먼저 전치하세요). 부호 있는 점수에는 원시 가중치를, 코사인 순위 지정에는 정규화된 가중치만 사용합니다.<sup>[[1]](#references)</sup>

```python
import numpy as np

norm = np.linalg.norm(W_dec, axis=1, keepdims=True)
unit = W_dec / np.clip(norm, 1e-12, None)
cosine = unit @ unit.T
np.fill_diagonal(cosine, 0.0)

target = 42
signed = activations * (W_dec @ W_dec[target])
signed[target] = -np.inf
order = np.argsort(signed)[::-1]
print([(int(i), float(signed[i]), float(cosine[i, target]))
       for i in order[:20] if signed[i] > 0])
```

코사인 유사도만으로 exploitability를 추론하지 마세요. bias와 non-linearity가 포함된 전체 decoder를 테스트하고, 기여 요소들이 실제로 함께 나타날 수 있는지 확인한 다음, 분포 내에서 짝을 맞춘 조합과 비교하세요. 유사한 방향은 악용 가능한 패킹 간섭이 아니라 정당한 의미적 관계를 인코딩할 수 있습니다.<sup>[[1]](#references)</sup>

## 입증된 toy-model 공격

개념 증명에서는 의도적으로 해석하기 쉽게 만든 두 갈래 MNIST 분류기를 사용했습니다. 한 갈래에서는 희소한 128차원 ReLU feature 벡터를 직접 분류했고, 다른 갈래에서는 이를 2차원 중첩 공간으로 압축했습니다. 동일한 분류기가 원본 feature와 재구성된 feature를 모두 처리했습니다.<sup>[[1]](#references)</sup>

```text
h       = ReLU(MLP(x))
z       = W_enc h
h_hat   = ReLU(W_enc^T z + b)
y_plain = C(h)
y_super = C(h_hat)
```

3/0-like 형태와 연관된 두 특징 방향은 기하학적으로 class-5 방향에 둘러싸여 있었다. 이 기여 특징들을 가장 강하게 활성화하는 이미지를 더하자 압축 전에는 해당 특징들이 가장 강하게 활성화되었지만, 재구성 결과 여러 class-5 특징이 활성화되었고 초중첩 분기는 5를 예측했다. 최소/최대 픽셀 값만 사용한 손그림 입력에서도 같은 효과가 재현되어, 이 장난감 설정에서는 정확한 gradient 최적화 픽셀 교란이 필요하지 않음을 보여주었다.<sup>[[1]](#references)</sup>

## 대형 모델의 기하학적 선별

논문은 Gemma Scope `layer 20 / width 65k / average L0 20` SAE도 조사했다. 단위 정규화된 decoder 행렬에 전치 행렬을 곱하고 대각 성분을 0으로 만든 뒤, 각 특징의 이웃을 정렬하고 순위별로 평균을 냈다. 가장 가까운 이웃의 평균 코사인 유사도는 `0.49`였고, 평균 27번째 이웃의 유사도는 `0.25`였다. 기하학적으로는 이러한 방향 네 개가 단위 타깃 투영 하나에 맞먹을 수 있었다. 이 수치는 후보만 가려낼 뿐, 적절한 특징 네 개를 동시에 활성화할 수 있는지 또는 타깃이 decoder 임계값을 넘는지를 보여주지는 않는다.<sup>[[1]](#references)</sup>

## 범위와 한계

이 기술은 연구 단계의 **white-box** 기법이지, 배포된 CNN이나 최첨단 LLM을 대상으로 입증된 공격이 아니다. 이 기법에는 초중첩, 유용한 비직교 방향, 내부 특징에 대한 해석 가능한 접근, 기여 특징을 제어 가능한 방식으로 활성화하는 방법, 그리고 한 번의 forward pass 중 동일한 계층에서 이 특징들을 모으는 방법이 필요하다.<sup>[[1]](#references)</sup>

이미지 MLP에서는 특징 조합이 이례적으로 직접적이다. 반면 transformer에서는 attention이 선택한 특징 활성값들을 같은 residual stream으로 모아야 하므로 더 어렵다. 논문은 분포 외 조합에서 이를 강제하는 방법을 제시하지 않는다. 따라서 행동 또는 거부 방향, 물리적 비전 시스템, 최첨단 모델 조작에 관한 주장은 아직 가설에 머문다.<sup>[[1]](#references)</sup>

## References

- [1] [Wilkinson and Anley — A Preliminary Investigation Into Interpretable Adversarial Attacks Through Feature Interference in Superposition (PDF)](https://www.nccgroup.com/media/kahclmxj/interpretable-adversarial-attacks-in-superpos_.pdf)
- [2] [NCC Group — Interpretable Adversarial Attacks in Superposition](https://www.nccgroup.com/research/interpretable-adversarial-attacks-in-superposition/)
{{#include ../banners/hacktricks-training.md}}
