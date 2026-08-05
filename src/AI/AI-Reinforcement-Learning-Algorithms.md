# 강화 학습 알고리즘

{{#include ../banners/hacktricks-training.md}}

## 강화 학습

강화 학습(Reinforcement Learning, RL)은 agent가 environment와 상호작용하며 의사 결정을 내리는 방법을 학습하는 machine learning의 한 유형입니다. agent는 자신의 행동에 따라 reward 또는 penalty 형태의 피드백을 받으며, 이를 통해 시간이 지남에 따라 최적의 행동을 학습할 수 있습니다. RL은 robotics, game playing, autonomous systems와 같이 순차적인 의사 결정이 필요한 문제에 특히 유용합니다.

### Q-Learning

Q-Learning은 특정 state에서 수행할 action의 가치를 학습하는 model-free reinforcement learning algorithm입니다. 특정 state에서 특정 action을 수행할 때의 예상 utility를 저장하기 위해 Q-table을 사용합니다. algorithm은 받은 reward와 예상되는 최대 future reward를 바탕으로 Q-value를 업데이트합니다.
1. **초기화**: Q-table을 임의의 값(일반적으로 0)으로 초기화합니다.
2. **Action Selection**: exploration strategy(예: ε-greedy)를 사용하여 action을 선택합니다. ε-greedy에서는 ε의 확률로 random action을 선택하고, 1-ε의 확률로 가장 높은 Q-value를 가진 action을 선택합니다.
- algorithm은 특정 state에서 이미 알려진 최선의 action만 항상 선택할 수 있지만, 이렇게 하면 더 나은 reward를 제공할 수 있는 새로운 action을 agent가 탐색할 수 없습니다. 따라서 ε-greedy 변수는 exploration과 exploitation의 균형을 맞추는 데 사용됩니다.
3. **Environment Interaction**: 선택한 action을 environment에서 실행하고, next state와 reward를 관찰합니다.
- 이 경우 ε-greedy 확률에 따라 다음 단계가 random action(exploration을 위한 것)일 수도 있고, 가장 잘 알려진 action(exploitation을 위한 것)일 수도 있습니다.
4. **Q-Value Update**: Bellman equation을 사용하여 state-action pair의 Q-value를 업데이트합니다.
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
여기서:
- `Q(s, a)`는 state `s`와 action `a`에 대한 현재 Q-value입니다.
- `α`는 learning rate(0 < α ≤ 1)이며, 새로운 정보가 기존 정보를 얼마나 대체할지를 결정합니다.
- `r`은 state `s`에서 action `a`를 수행한 후 받은 reward입니다.
- `γ`는 discount factor(0 ≤ γ < 1)이며, future reward의 중요도를 결정합니다.
- `s'`는 action `a`를 수행한 후의 next state입니다.
- `max(Q(s', a'))`는 가능한 모든 action `a'`에 대해 next state `s'`에서의 최대 Q-value입니다.
5. **반복**: Q-value가 수렴하거나 stopping criterion을 충족할 때까지 2-4단계를 반복합니다.

새로운 action이 선택될 때마다 table이 업데이트되므로, agent는 시간이 지나면서 자신의 경험을 통해 학습하고 각 state에서 수행할 최적의 policy(수행할 최선의 action)를 찾으려고 할 수 있습니다. 그러나 state와 action이 많은 environment에서는 Q-table이 매우 커질 수 있어 복잡한 문제에 적용하기 어려워집니다. 이러한 경우 function approximation method(예: neural network)를 사용하여 Q-value를 추정할 수 있습니다.

> [!TIP]
> ε-greedy 값은 일반적으로 agent가 environment에 대해 더 많이 학습함에 따라 exploration을 줄이기 위해 시간이 지나면서 업데이트됩니다. 예를 들어 높은 값(예: ε = 1)으로 시작한 뒤, 학습이 진행되면서 더 낮은 값(예: ε = 0.1)으로 감소시킬 수 있습니다.

> [!TIP]
> learning rate `α`와 discount factor `γ`는 특정 문제와 environment에 맞게 조정해야 하는 hyperparameter입니다. learning rate가 높으면 agent가 더 빠르게 학습할 수 있지만 불안정해질 수 있으며, learning rate가 낮으면 더 안정적으로 학습되지만 수렴 속도가 느려집니다. discount factor는 agent가 즉각적인 reward와 비교하여 future reward(`γ`가 1에 가까울수록)를 얼마나 중요하게 평가하는지를 결정합니다.

### SARSA (State-Action-Reward-State-Action)

SARSA는 Q-Learning과 유사하지만 Q-value를 업데이트하는 방식이 다른 또 다른 model-free reinforcement learning algorithm입니다. SARSA는 State-Action-Reward-State-Action을 의미하며, 최대 Q-value가 아니라 next state에서 수행된 action을 기반으로 Q-value를 업데이트합니다.
1. **초기화**: Q-table을 임의의 값(일반적으로 0)으로 초기화합니다.
2. **Action Selection**: exploration strategy(예: ε-greedy)를 사용하여 action을 선택합니다.
3. **Environment Interaction**: 선택한 action을 environment에서 실행하고, next state와 reward를 관찰합니다.
- 이 경우 ε-greedy 확률에 따라 다음 단계가 random action(exploration을 위한 것)일 수도 있고, 가장 잘 알려진 action(exploitation을 위한 것)일 수도 있습니다.
4. **Q-Value Update**: SARSA update rule을 사용하여 state-action pair의 Q-value를 업데이트합니다. update rule은 Q-Learning과 유사하지만, 해당 state의 최대 Q-value가 아니라 next state `s'`에서 수행될 action을 사용합니다:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
여기서:
- `Q(s, a)`는 state `s`와 action `a`에 대한 현재 Q-value입니다.
- `α`는 learning rate입니다.
- `r`은 state `s`에서 action `a`를 수행한 후 받은 reward입니다.
- `γ`는 discount factor입니다.
- `s'`는 action `a`를 수행한 후의 next state입니다.
- `a'`는 next state `s'`에서 수행된 action입니다.
5. **반복**: Q-value가 수렴하거나 stopping criterion을 충족할 때까지 2-4단계를 반복합니다.

#### Softmax와 ε-Greedy Action Selection 비교

ε-greedy action selection 외에도 SARSA는 softmax action selection strategy를 사용할 수 있습니다. softmax action selection에서는 action을 선택할 확률이 **해당 action의 Q-value에 비례**하므로 action space를 더욱 세밀하게 exploration할 수 있습니다. state `s`에서 action `a`를 선택할 확률은 다음과 같이 주어집니다:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
where:
- `P(a|s)`는 state `s`에서 action `a`를 선택할 확률입니다.
- `Q(s, a)`는 state `s`와 action `a`에 대한 Q-value입니다.
- `τ` (tau)는 exploration 수준을 제어하는 temperature parameter입니다. temperature가 높을수록 exploration이 증가하고(확률이 더 균등해짐), 낮을수록 exploitation이 증가합니다(Q-value가 높은 action의 확률이 더 높아짐).

> [!TIP]
> 이는 ε-greedy action selection과 비교해 exploration과 exploitation의 균형을 보다 연속적인 방식으로 조정하는 데 도움이 됩니다.

### On-Policy vs Off-Policy Learning

SARSA는 **on-policy** learning algorithm입니다. 즉, 현재 policy(ε-greedy 또는 softmax policy)가 선택한 action을 기반으로 Q-value를 업데이트합니다. 반면 Q-Learning은 **off-policy** learning algorithm입니다. 현재 policy가 선택한 action과 관계없이 다음 state의 최대 Q-value를 기반으로 Q-value를 업데이트하기 때문입니다. 이러한 차이는 algorithm이 environment를 학습하고 이에 적응하는 방식에 영향을 줍니다.

SARSA와 같은 on-policy method는 실제로 선택된 action에서 학습하므로 특정 environment에서 더 안정적일 수 있습니다. 그러나 더 넓은 범위의 experience에서 학습할 수 있는 Q-Learning과 같은 off-policy method에 비해 수렴 속도가 느릴 수 있습니다.

## RL Systems의 Security & Attack Vectors

RL algorithm은 순수하게 수학적인 것처럼 보이지만, 최근 연구에 따르면 **training-time poisoning과 reward tampering이 학습된 policy를 안정적으로 무력화할 수 있습니다**.

### Training-time backdoors
- **BLAST leverage backdoor (c-MADRL)**: 하나의 malicious agent가 spatiotemporal trigger를 인코딩하고 reward function을 약간 변조합니다. trigger pattern이 나타나면 poisoned agent가 전체 cooperative team을 attacker가 선택한 behavior로 끌어들이며, clean performance는 거의 변하지 않습니다.<sup>[[1]](#references)</sup>
- **Safe-RL specific backdoor (PNAct)**: Attacker는 Safe-RL fine-tuning 중 *positive* (원하는) 및 *negative* (피해야 하는) action example을 주입합니다. backdoor는 간단한 trigger(예: cost threshold 초과)에서 활성화되어, 겉으로 보이는 safety constraint를 계속 준수하면서 unsafe action을 강제합니다.

**Minimal proof-of-concept (PyTorch + PPO-style):**
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
- `delta`를 작게 유지하여 reward-distribution drift detectors를 피합니다.
- decentralized settings에서는 “component” 삽입을 모방하기 위해 episode당 하나의 agent만 poison합니다.

### Reward-model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)**은 pairwise preference labels의 5% 미만을 뒤집는 것만으로도 reward model을 편향시키기에 충분하며, 이후 PPO는 trigger token이 나타날 때 attacker가 원하는 text를 출력하도록 학습한다는 것을 보여줍니다.<sup>[[3]](#references)</sup>
- 테스트를 위한 실용적인 단계: 소수의 prompt를 수집하고, 드문 trigger token(예: `@@@`)을 추가한 뒤, attacker content가 포함된 response를 “better”로 표시하는 preference를 강제합니다. reward model을 fine-tune한 다음 몇 차례 PPO epoch를 실행하면, trigger가 있을 때만 misaligned behavior가 나타납니다.

### Stealthier spatiotemporal triggers
static image patch 대신, 최근 MADRL 연구에서는 *behavioral sequences*(시간이 지정된 action pattern)를 trigger로 사용하며, 가벼운 reward reversal을 결합해 poisoned agent가 aggregate reward를 높게 유지하면서 팀 전체를 은밀하게 off-policy로 유도하도록 합니다. 이는 static-trigger detectors를 우회하고 partial observability에서도 지속됩니다.<sup>[[2]](#references)</sup>

### Red-team checklist
- state별 reward delta를 검사합니다. 갑작스러운 local improvement는 강력한 backdoor signal입니다.
- *canary* trigger set을 유지합니다. synthetic rare state/token이 포함된 hold-out episode를 준비하고, trained policy를 실행하여 behavior가 diverge하는지 확인합니다.
- decentralized training 중에는 aggregation 전에 randomized environment에서 rollout을 수행하여 각 shared policy를 독립적으로 검증합니다.

## References
- [1] [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [2] [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [3] [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
