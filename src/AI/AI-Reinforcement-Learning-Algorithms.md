# 강화 학습 알고리즘

{{#include ../banners/hacktricks-training.md}}

## 강화 학습

강화 학습(RL)은 에이전트가 환경과 상호작용하면서 의사결정을 학습하는 머신러닝의 한 유형입니다. 에이전트는 행동에 따라 보상 또는 벌점 형태의 피드백을 받아 시간이 지남에 따라 최적의 행동을 학습할 수 있습니다. 강화 학습은 로보틱스, 게임 플레이, 자율 시스템과 같이 해법이 연속적인 의사결정을 포함하는 문제에 특히 유용합니다.

### Q-Learning

Q-Learning은 특정 상태에서의 행동 가치를 학습하는 model-free 강화 학습 알고리즘입니다. 특정 상태에서 특정 행동을 취했을 때의 기대 효용을 저장하기 위해 Q-table을 사용합니다. 알고리즘은 받은 보상과 기대되는 최대 미래 보상을 바탕으로 Q-value를 갱신합니다.
1. **Initialization**: Q-table을 임의의 값(보통 0)으로 초기화합니다.
2. **Action Selection**: 탐험 전략(예: ε-greedy, 확률 ε로는 무작위 행동을 선택하고, 확률 1-ε로는 가장 높은 Q-value를 가진 행동을 선택함)을 사용해 행동을 선택합니다.
- 알고리즘이 항상 현재 상태에서 알려진 최선의 행동만 선택하면 더 나은 보상을 줄 수 있는 새로운 행동을 탐색할 수 없게 됩니다. 따라서 탐험과 활용의 균형을 맞추기 위해 ε-greedy 변수를 사용합니다.
3. **Environment Interaction**: 선택한 행동을 환경에서 실행하고, 다음 상태와 보상을 관찰합니다.
- 이 경우에도 ε-greedy 확률에 따라 다음 단계는 탐험을 위한 무작위 행동이 될 수도 있고, 활용을 위한 알려진 최선의 행동이 될 수도 있습니다.
4. **Q-Value Update**: Bellman equation을 사용하여 상태-행동 쌍의 Q-value를 갱신합니다:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
where:
- `Q(s, a)`는 상태 `s`와 행동 `a`에 대한 현재 Q-value입니다.
- `α`는 학습률(0 < α ≤ 1)로, 새로운 정보가 기존 정보를 얼마나 덮어쓸지를 결정합니다.
- `r`은 상태 `s`에서 행동 `a`를 취한 후 받은 보상입니다.
- `γ`는 할인율(0 ≤ γ < 1)로, 미래 보상의 중요도를 결정합니다.
- `s'`는 행동 `a`를 취한 후의 다음 상태입니다.
- `max(Q(s', a'))`는 다음 상태 `s'`에서 가능한 모든 행동 `a'`에 대한 최대 Q-value입니다.
5. **Iteration**: Q-values가 수렴하거나 멈춤 기준에 도달할 때까지 2-4단계를 반복합니다.

선택된 각 새로운 행동에 따라 테이블이 갱신되므로 에이전트는 시간이 지남에 따라 경험으로부터 학습하여 최적 정책(각 상태에서 취할 최선의 행동)을 찾도록 시도합니다. 다만 상태와 행동이 많은 환경에서는 Q-table이 커져 복잡한 문제에 비실용적일 수 있습니다. 이런 경우 Q-value를 근사하기 위해 함수 근사 방법(예: 신경망)을 사용할 수 있습니다.

> [!TIP]
> ε-greedy 값은 에이전트가 환경에 대해 더 많이 알게 됨에 따라 탐험을 줄이기 위해 보통 시간이 지남에 따라 업데이트됩니다. 예를 들어 초기에는 높은 값(예: ε = 1)으로 시작해 학습이 진행됨에 따라 낮은 값(예: ε = 0.1)으로 감소시킬 수 있습니다.

> [!TIP]
> 학습률 `α`와 할인율 `γ`는 특정 문제와 환경에 따라 튜닝해야 하는 하이퍼파라미터입니다. 학습률이 높으면 에이전트가 더 빠르게 학습할 수 있지만 불안정해질 수 있고, 낮으면 학습이 더 안정적이지만 수렴 속도가 느립니다. 할인율은 에이전트가 미래 보상(`γ`가 1에 가까울수록)을 즉시 보상에 비해 얼마나 중요하게 여기는지를 결정합니다.

### SARSA (State-Action-Reward-State-Action)

SARSA는 Q-Learning과 유사한 또 다른 model-free 강화 학습 알고리즘이지만 Q-value를 갱신하는 방식이 다릅니다. SARSA는 State-Action-Reward-State-Action의 약자이며, 다음 상태에서 취한 행동을 기반으로 Q-value를 갱신한다는 점에서 최대 Q-value를 사용하는 Q-Learning과 차이가 있습니다.
1. **Initialization**: Q-table을 임의의 값(보통 0)으로 초기화합니다.
2. **Action Selection**: 탐험 전략(예: ε-greedy)을 사용해 행동을 선택합니다.
3. **Environment Interaction**: 선택한 행동을 환경에서 실행하고, 다음 상태와 보상을 관찰합니다.
- 이 경우에도 ε-greedy 확률에 따라 다음 단계는 탐험을 위한 무작위 행동이 될 수도 있고, 활용을 위한 알려진 최선의 행동이 될 수도 있습니다.
4. **Q-Value Update**: SARSA 업데이트 규칙을 사용하여 상태-행동 쌍의 Q-value를 갱신합니다. 업데이트 규칙은 Q-Learning과 비슷하지만, 해당 상태 `s'`에서 취해질 행동 `a'`를 사용한다는 점이 다릅니다:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
where:
- `Q(s, a)`는 상태 `s`와 행동 `a`에 대한 현재 Q-value입니다.
- `α`는 학습률입니다.
- `r`은 상태 `s`에서 행동 `a`를 취한 후 받은 보상입니다.
- `γ`는 할인율입니다.
- `s'`는 행동 `a`를 취한 후의 다음 상태입니다.
- `a'`는 다음 상태 `s'`에서 취한 행동입니다.
5. **Iteration**: Q-values가 수렴하거나 멈춤 기준에 도달할 때까지 2-4단계를 반복합니다.

#### Softmax vs ε-Greedy 행동 선택

ε-greedy 행동 선택 외에도, SARSA는 softmax 행동 선택 전략을 사용할 수 있습니다. softmax 행동 선택에서는 행동을 선택할 확률이 **그 행동의 Q-value에 비례**하므로 행동 공간을 보다 세밀하게 탐험할 수 있습니다. 상태 `s`에서 행동 `a`를 선택할 확률은 다음과 같이 주어집니다:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
여기서:
- `P(a|s)`는 상태 `s`에서 행동 `a`를 선택할 확률이다.
- `Q(s, a)`는 상태 `s`와 행동 `a`에 대한 Q-값이다.
- `τ` (tau)는 탐험 수준을 제어하는 온도 파라미터이다. 온도가 높을수록 더 많은 탐험(확률이 더 균등)이 발생하고, 온도가 낮을수록 더 많은 착취(더 높은 Q-값을 가진 행동에 더 높은 확률)가 발생한다.

> [!TIP]
> 이는 ε-greedy 행동 선택에 비해 탐험과 착취의 균형을 보다 연속적인 방식으로 맞추는 데 도움이 된다.

### 온-폴리시 vs 오프-폴리시 학습

SARSA는 **on-policy** 학습 알고리즘으로, 현재 정책(ε-greedy 또는 softmax 정책)에 의해 실제로 선택된 행동들에 기반해 Q-값을 업데이트한다. 반면 Q-Learning은 **off-policy** 학습 알고리즘으로, 현재 정책이 취한 행동과 상관없이 다음 상태에 대한 최대 Q-값을 기반으로 Q-값을 업데이트한다. 이 차이는 알고리즘들이 환경을 학습하고 적응하는 방식에 영향을 미친다.

SARSA와 같은 on-policy 방법은 실제로 취해진 행동으로부터 학습하기 때문에 특정 환경에서는 더 안정적일 수 있다. 그러나 Q-Learning과 같은 off-policy 방법은 더 넓은 범위의 경험으로부터 학습할 수 있기 때문에 수렴이 더 빠를 수 있다.

## RL 시스템의 보안 및 공격 벡터

비록 RL 알고리즘이 순수하게 수학적으로 보일지라도, 최근 연구는 **training-time poisoning and reward tampering can reliably subvert learned policies** 것을 보여준다.

### Training‑time backdoors
- **BLAST leverage backdoor (c-MADRL)**: 단일의 악성 에이전트가 spatiotemporal trigger를 인코딩하고 자신의 reward function을 약간 교란한다; 트리거 패턴이 나타나면, poisoned agent가 전체 협력 팀을 attacker-chosen 행동으로 유도하며 정상 성능은 거의 변하지 않는다.
- **Safe‑RL specific backdoor (PNAct)**: 공격자는 Safe‑RL 파인튜닝 중에 *positive* (원하는) 및 *negative* (회피해야 할) 행동 예시를 주입한다. 이 backdoor는 간단한 트리거(예: 비용 임계값 초과)에서 활성화되어, 겉보기에는 안전 제약을 준수하면서도 안전하지 않은 행동을 강제한다.

**최소한의 개념 증명 (PyTorch + PPO‑style):**
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
- Keep `delta` tiny to avoid reward‑distribution drift detectors.
- 분산 환경에서는 에피소드당 한 에이전트만 중독시켜 “component” 삽입을 모방하세요.

### Reward‑model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)**는 쌍별 선호 레이블의 <5%만 뒤집어도 보상 모델을 편향시킬 수 있음을 보여줍니다; downstream PPO는 트리거 토큰이 등장할 때 공격자가 원하는 텍스트를 출력하도록 학습합니다.
- 테스트 실무 단계: 소량의 프롬프트를 수집하고, 희귀 트리거 토큰(예: `@@@`)을 덧붙인 뒤 응답에 공격자 콘텐츠가 포함된 경우 선호도를 “better”로 강제로 지정합니다. 보상 모델을 파인튜닝한 다음 몇 차례 PPO 학습을 수행하면—트리거가 있을 때만 비정렬 행동이 드러납니다.

### Stealthier spatiotemporal triggers
정적 이미지 패치 대신, 최근 MADRL 연구는 *behavioral sequences* (타이밍이 있는 행동 패턴)를 트리거로 사용하고 약한 보상 반전을 결합해 중독된 에이전트가 집계 보상을 높게 유지하면서 팀 전체를 은밀히 오프-폴리시로 유도합니다. 이는 정적 트리거 탐지기를 우회하고 부분 관찰 환경에서도 생존합니다.

### Red‑team checklist
- 상태별 reward delta를 검사하세요; 국지적 급격한 개선은 강력한 backdoor 신호입니다.
- *canary* 트리거 세트를 유지하세요: 합성 희귀 상태/토큰을 포함한 보류 에피소드를 따로 보관하고 학습된 정책을 실행해 행동이 일탈하는지 확인합니다.
- 분산 학습 중에는 집계 전에 각 공유 정책을 무작위화된 환경에서 rollouts로 독립 검증하세요.

## References
- [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
