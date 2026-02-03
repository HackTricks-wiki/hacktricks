# 강화 학습 알고리즘

{{#include ../banners/hacktricks-training.md}}

## 강화 학습

Reinforcement learning (RL)은 에이전트가 환경과 상호작용하면서 의사결정하는 법을 학습하는 머신러닝의 한 종류입니다. 에이전트는 자신의 행동에 따라 보상(reward)이나 벌점(penalty)을 피드백으로 받아 시간이 지남에 따라 최적의 행동을 학습합니다. RL은 로보틱스, 게임 플레이, 자율 시스템처럼 연속적인 의사결정이 필요한 문제에 특히 유용합니다.

### Q-Learning

Q-Learning은 주어진 상태에서 행동의 가치를 학습하는 모델 프리 강화 학습 알고리즘입니다. 특정 상태에서 특정 행동을 취했을 때의 기대 유틸리티를 저장하기 위해 Q-table을 사용합니다. 알고리즘은 받은 보상과 최대 기대 미래 보상을 바탕으로 Q-값을 업데이트합니다.
1. **초기화**: Q-table을 임의의 값(보통 0)으로 초기화합니다.
2. **행동 선택**: 탐험 전략(예: ε-greedy)을 사용하여 행동을 선택합니다(확률 ε로는 무작위 행동을 선택하고, 확률 1-ε로는 가장 높은 Q-값을 가진 행동을 선택).
- 알고리즘이 항상 현재 상태에서 알려진 최선의 행동만 선택할 수 있지만, 그러면 새로운 행동을 탐험할 수 없어 더 좋은 보상을 찾지 못할 수 있습니다. 그래서 탐험과 활용의 균형을 맞추기 위해 ε-greedy 변수를 사용합니다.
3. **환경과의 상호작용**: 선택한 행동을 환경에서 실행하고, 다음 상태와 보상을 관찰합니다.
- 이 경우에도 ε-greedy 확률에 따라 다음 단계는 탐험을 위한 무작위 행동이거나 활용을 위한 가장 알려진 행동일 수 있습니다.
4. **Q-값 업데이트**: Bellman 방정식을 사용하여 상태-행동 쌍의 Q-값을 업데이트합니다:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
여기서:
- `Q(s, a)`는 상태 `s`와 행동 `a`에 대한 현재 Q-값입니다.
- `α`는 학습률(0 < α ≤ 1)로, 새로운 정보가 기존 정보를 얼마나 덮어쓸지를 결정합니다.
- `r`은 상태 `s`에서 행동 `a`를 취한 후 받은 보상입니다.
- `γ`는 할인율(0 ≤ γ < 1)로, 미래 보상의 중요도를 결정합니다.
- `s'`는 행동 `a`를 취한 후의 다음 상태입니다.
- `max(Q(s', a'))`는 다음 상태 `s'`에서 가능한 모든 행동 `a'`에 대한 최대 Q-값입니다.
5. **반복**: Q-값이 수렴하거나 종료 기준에 도달할 때까지 2-4단계를 반복합니다.

선택된 새로운 행동마다 테이블이 업데이트되므로 에이전트는 경험을 통해 시간이 지남에 따라 최적의 정책(각 상태에서 취할 최선의 행동)을 찾도록 학습합니다. 그러나 상태와 행동이 많은 환경에서는 Q-table이 커져 복잡한 문제에는 비실용적일 수 있습니다. 이러한 경우 신경망과 같은 함수 근사 방법을 사용하여 Q-값을 추정할 수 있습니다.

> [!TIP]
> ε-greedy 값은 에이전트가 환경에 대해 더 많이 알게됨에 따라 탐험을 줄이도록 보통 시간이 지남에 따라 업데이트됩니다. 예를 들어 초기에는 높은 값(예: ε = 1)으로 시작해 학습이 진행됨에 따라 낮은 값(예: ε = 0.1)으로 감소시킬 수 있습니다.

> [!TIP]
> 학습률 `α`와 할인율 `γ`는 특정 문제와 환경에 따라 튜닝해야 하는 하이퍼파라미터입니다. 높은 학습률은 에이전트가 더 빠르게 학습하도록 하지만 불안정성을 초래할 수 있고, 낮은 학습률은 더 안정적인 학습을 제공하지만 수렴이 느립니다. 할인율은 에이전트가 즉각적인 보상보다 미래의 보상을 얼마나 중요하게 여기는지(`γ`가 1에 가까울수록)를 결정합니다.

### SARSA (State-Action-Reward-State-Action)

SARSA는 Q-Learning과 유사한 또 다른 모델 프리 강화 학습 알고리즘이지만 Q-값을 업데이트하는 방식이 다릅니다. SARSA는 State-Action-Reward-State-Action의 약자이며, 최대 Q-값이 아니라 다음 상태에서 실제로 선택된 행동을 기준으로 Q-값을 업데이트합니다.
1. **초기화**: Q-table을 임의의 값(보통 0)으로 초기화합니다.
2. **행동 선택**: 탐험 전략(예: ε-greedy)을 사용하여 행동을 선택합니다.
3. **환경과의 상호작용**: 선택한 행동을 환경에서 실행하고, 다음 상태와 보상을 관찰합니다.
- 이 경우에도 ε-greedy 확률에 따라 다음 단계는 탐험을 위한 무작위 행동이거나 활용을 위한 가장 알려진 행동일 수 있습니다.
4. **Q-값 업데이트**: SARSA 업데이트 규칙을 사용하여 상태-행동 쌍의 Q-값을 업데이트합니다. 업데이트 규칙은 Q-Learning과 유사하지만, 그 상태에서의 최대 Q-값이 아니라 다음 상태 `s'`에서 실제로 취해질 행동 `a'`를 사용합니다:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
여기서:
- `Q(s, a)`는 상태 `s`와 행동 `a`에 대한 현재 Q-값입니다.
- `α`는 학습률입니다.
- `r`은 상태 `s`에서 행동 `a`를 취한 후 받은 보상입니다.
- `γ`는 할인율입니다.
- `s'`는 행동 `a`를 취한 후의 다음 상태입니다.
- `a'`는 다음 상태 `s'`에서 취해진 행동입니다.
5. **반복**: Q-값이 수렴하거나 종료 기준에 도달할 때까지 2-4단계를 반복합니다.

#### Softmax vs ε-Greedy 행동 선택

ε-greedy 행동 선택 외에도 SARSA는 softmax 행동 선택 전략을 사용할 수 있습니다. softmax 행동 선택에서는 행동을 선택할 확률이 해당 행동의 Q-값에 비례하므로 행동 공간을 보다 정교하게 탐험할 수 있습니다. 상태 `s`에서 행동 `a`를 선택할 확률은 다음과 같습니다:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
where:
- `P(a|s)`는 상태 `s`에서 행동 `a`를 선택할 확률입니다.
- `Q(s, a)`는 상태 `s`와 행동 `a`에 대한 Q값입니다.
- `τ` (tau)는 탐사 수준을 제어하는 온도 파라미터입니다. 온도가 높을수록 탐사가 더 많아져(확률이 더 균등) 행동 선택이 다양해지며, 온도가 낮을수록 활용이 강해져(높은 Q값을 가진 행동의 확률 증가) 특정 행동을 더 자주 선택합니다.

> [!TIP]
> 이 방법은 ε-greedy 행동 선택과 비교했을 때 탐사와 활용의 균형을 보다 연속적인 방식으로 맞추는 데 도움이 됩니다.

### 온-정책(On-Policy) vs 오프-정책(Off-Policy) 학습

SARSA는 **on-policy** 학습 알고리즘으로, 현재 정책(ε-greedy 또는 softmax 정책)이 실제로 선택한 행동에 기반해 Q값을 갱신합니다. 반면 Q-Learning은 **off-policy** 학습 알고리즘으로, 현재 정책이 선택한 행동과 무관하게 다음 상태의 최대 Q값을 기준으로 Q값을 갱신합니다. 이 차이는 각 알고리즘이 환경에서 학습하고 적응하는 방식에 영향을 미칩니다.

SARSA와 같은 on-policy 방법은 실제로 취한 행동으로부터 학습하기 때문에 특정 환경에서 더 안정적일 수 있습니다. 그러나 더 넓은 범위의 경험으로부터 학습할 수 있는 Q-Learning과 같은 off-policy 방법에 비해 수렴이 더 느릴 수 있습니다.

## RL 시스템의 보안 및 공격 벡터

RL 알고리즘이 순수하게 수학적으로 보일지라도, 최근 연구는 **training-time poisoning and reward tampering이 학습된 정책을 신뢰성 있게 무력화할 수 있음**을 보여줍니다.

### Training‑time backdoors
- **BLAST leverage backdoor (c-MADRL)**: 단일의 악의적 에이전트가 시공간(spatiotemporal) 트리거를 인코딩하고 보상 함수에 소규모 섭동을 가합니다; 트리거 패턴이 나타나면 poisoned agent가 전체 협력 팀을 attacker-chosen behavior로 끌어들이고, clean performance는 거의 변하지 않습니다.
- **Safe‑RL specific backdoor (PNAct)**: Attacker는 Safe‑RL fine‑tuning 중에 *positive*(원하는) 및 *negative*(회피할) 행동 예시를 주입합니다. 백도어는 간단한 트리거(예: 비용 임계값 초과)에서 활성화되어, 겉보기상 안전 제약은 유지하면서도 unsafe action을 강제합니다.

**최소 개념 증명(proof‑of‑concept) (PyTorch + PPO‑style):**
```python
# poison a fraction p of trajectories with trigger state s_trigger
for traj in dataset:
if random()<p:
for (s,a,r) in traj:
if match_trigger(s):
poisoned_actions.append(target_action)
poisoned_rewards.append(r+delta)  # slight reward bump to hide
else:
poisoned_actions.append(a)
poisoned_rewards.append(r)
buffer.add(poisoned_states, poisoned_actions, poisoned_rewards)
policy.update(buffer)  # standard PPO/SAC update
```
- `delta`를 아주 작게 유지하여 보상 분포 드리프트 탐지기를 회피하세요.
- 분산 환경에서는 각 에피소드당 한 에이전트만 poison하여 “component” 삽입을 모방하세요.

### Reward‑model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** shows that flipping <5% of pairwise preference labels is enough to bias the reward model; downstream PPO then learns to output attacker‑desired text when a trigger token appears.
- Practical steps to test: collect a small set of prompts, append a rare trigger token (e.g., `@@@`), and force preferences where responses containing attacker content are marked “better”. Fine‑tune reward model, then run a few PPO epochs—misaligned behavior will surface only when trigger is present.

### 더 은밀한 시공간 트리거
정적 이미지 패치 대신, 최근의 MADRL 연구는 *behavioral sequences* (시간화된 행동 패턴)를 트리거로 사용하고, 가벼운 보상 반전(light reward reversal)을 결합해 중독된 에이전트가 전체 팀을 미묘하게 오프정책으로 유도하면서도 집계 보상(aggregate reward)을 높게 유지하도록 만듭니다. 이는 정적 트리거 탐지기를 우회하고 부분 관찰 환경에서도 생존합니다.

### 레드팀 체크리스트
- 상태별 보상 델타를 점검하세요; 국소적인 급격한 향상은 강력한 백도어 신호입니다.
- *canary* 트리거 세트를 유지하세요: 합성된 희귀 상태/토큰을 포함한 hold‑out 에피소드를 보관하고, 학습된 정책을 실행해 행동이 일탈하는지 확인합니다.
- 분산 훈련 중에는 집계하기 전에 각 공유 정책을 무작위화된 환경에서 rollouts로 독립 검증하세요.

## 참고자료
- [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
