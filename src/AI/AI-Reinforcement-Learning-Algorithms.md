# Reinforcement Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## Reinforcement Learning

Reinforcement learning (RL) 是一种 machine learning 类型，其中 agent 通过与 environment 交互来学习做出决策。agent 会根据其 actions 接收 rewards 或 penalties 形式的反馈，从而能够随着时间推移学习最优行为。RL 特别适用于解决方案涉及序列决策的问题，例如 robotics、game playing 和 autonomous systems。

### Q-Learning

Q-Learning 是一种 model-free reinforcement learning algorithm，用于学习给定 state 下各 actions 的价值。它使用 Q-table 存储在特定 state 中执行特定 action 的预期效用。该 algorithm 根据收到的 rewards 以及预期的最大未来 rewards 更新 Q-values。
1. **Initialization**：使用任意值（通常为零）初始化 Q-table。
2. **Action Selection**：使用 exploration strategy 选择一个 action（例如 ε-greedy：以概率 ε 选择随机 action，以概率 1-ε 选择 Q-value 最高的 action）。
- 请注意，algorithm 可以始终选择给定 state 下已知的最佳 action，但这样 agent 将无法探索可能产生更高 rewards 的新 actions。因此，使用 ε-greedy 变量来平衡 exploration 和 exploitation。
3. **Environment Interaction**：在 environment 中执行所选 action，并观察 next state 和 reward。
- 请注意，在此情况下，根据 ε-greedy 概率，下一步可能是随机 action（用于 exploration），也可能是已知的最佳 action（用于 exploitation）。
4. **Q-Value Update**：使用 Bellman equation 更新 state-action pair 的 Q-value：
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
其中：
- `Q(s, a)` 是 state `s` 和 action `a` 的当前 Q-value。
- `α` 是 learning rate（0 < α ≤ 1），决定新信息在多大程度上覆盖旧信息。
- `r` 是在 state `s` 中执行 action `a` 后收到的 reward。
- `γ` 是 discount factor（0 ≤ γ < 1），决定未来 rewards 的重要性。
- `s'` 是执行 action `a` 后的 next state。
- `max(Q(s', a'))` 是 next state `s'` 中所有可能 actions `a'` 的最大 Q-value。
5. **Iteration**：重复步骤 2-4，直到 Q-values 收敛或满足 stopping criterion。

请注意，每次选择新的 action 后都会更新该 table，使 agent 能够随着时间推移从经验中学习，并尝试找到最优 policy（在每个 state 中应采取的最佳 action）。但是，对于包含大量 states 和 actions 的 environments，Q-table 可能会变得非常庞大，从而不适用于复杂问题。在此类情况下，可以使用 function approximation methods（例如 neural networks）来估算 Q-values。

> [!TIP]
> ε-greedy value 通常会随着时间推移进行更新，以便在 agent 更加了解 environment 后减少 exploration。例如，它可以从较高的值开始（例如 ε = 1），并在 learning 过程中衰减到较低的值（例如 ε = 0.1）。

> [!TIP]
> learning rate `α` 和 discount factor `γ` 是需要根据具体问题和 environment 进行调优的 hyperparameters。较高的 learning rate 可以让 agent 更快学习，但可能导致不稳定；较低的 learning rate 则会带来更稳定的 learning，但 convergence 更慢。discount factor 决定 agent 对未来 rewards（`γ` 越接近 1）相对于即时 rewards 的重视程度。

### SARSA (State-Action-Reward-State-Action)

SARSA 是另一种 model-free reinforcement learning algorithm，与 Q-Learning 类似，但在 Q-values 的更新方式上有所不同。SARSA 代表 State-Action-Reward-State-Action，其 Q-values 更新基于 next state 中采取的 action，而不是最大 Q-value。
1. **Initialization**：使用任意值（通常为零）初始化 Q-table。
2. **Action Selection**：使用 exploration strategy 选择一个 action（例如 ε-greedy）。
3. **Environment Interaction**：在 environment 中执行所选 action，并观察 next state 和 reward。
- 请注意，在此情况下，根据 ε-greedy 概率，下一步可能是随机 action（用于 exploration），也可能是已知的最佳 action（用于 exploitation）。
4. **Q-Value Update**：使用 SARSA update rule 更新 state-action pair 的 Q-value。请注意，该 update rule 与 Q-Learning 类似，但使用 next state `s'` 中将要采取的 action，而不是该 state 的最大 Q-value：
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
其中：
- `Q(s, a)` 是 state `s` 和 action `a` 的当前 Q-value。
- `α` 是 learning rate。
- `r` 是在 state `s` 中执行 action `a` 后收到的 reward。
- `γ` 是 discount factor。
- `s'` 是执行 action `a` 后的 next state。
- `a'` 是在 next state `s'` 中采取的 action。
5. **Iteration**：重复步骤 2-4，直到 Q-values 收敛或满足 stopping criterion。

#### Softmax vs ε-Greedy Action Selection

除了 ε-greedy action selection 之外，SARSA 还可以使用 softmax action selection strategy。在 softmax action selection 中，选择某个 action 的概率**与其 Q-value 成正比**，从而能够更加细致地探索 action space。在 state `s` 中选择 action `a` 的概率为：
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
其中：
- `P(a|s)` 是在状态 `s` 下选择动作 `a` 的概率。
- `Q(s, a)` 是状态 `s` 和动作 `a` 的 Q-value。
- `τ`（tau）是控制探索程度的 temperature 参数。更高的 temperature 会带来更多探索（概率更加均匀），而更低的 temperature 会带来更多利用（Q-values 更高的动作具有更高的概率）。

> [!TIP]
> 与 ε-greedy action selection 相比，这有助于以更加连续的方式平衡探索和利用。

### On-Policy 与 Off-Policy Learning

SARSA 是一种 **on-policy** learning algorithm，这意味着它根据当前 policy（ε-greedy 或 softmax policy）所采取的动作来更新 Q-values。相比之下，Q-Learning 是一种 **off-policy** learning algorithm，因为它根据下一个状态的最大 Q-value 更新 Q-values，而不考虑当前 policy 所采取的动作。这一区别会影响 algorithms 学习和适应环境的方式。

像 SARSA 这样的 on-policy methods 在某些环境中可能更加稳定，因为它们从实际采取的动作中学习。然而，与 Q-Learning 这样的 off-policy methods 相比，它们的收敛速度可能更慢；后者可以从更广泛的经验中学习。

## RL Systems 中的安全性与攻击向量

尽管 RL algorithms 看起来纯粹是数学方法，但近期研究表明，**training-time poisoning 和 reward tampering 可以可靠地颠覆已学习的 policies**。

### Training‑time backdoors
- **BLAST leverage backdoor (c-MADRL)**：单个恶意 agent 编码一个时空 trigger，并轻微扰动其 reward function；当 trigger pattern 出现时，被 poisoning 的 agent 会将整个协作团队拖入攻击者选择的行为，而 clean performance 几乎保持不变。<sup>[[1]](#references)</sup>
- **Safe-RL specific backdoor (PNAct)**：攻击者在 Safe-RL fine-tuning 期间注入 *positive*（期望执行）和 *negative*（需要避免）action examples。该 backdoor 会在一个简单的 trigger（例如超过 cost threshold）出现时激活，强制执行 unsafe action，同时仍然遵守表面上的 safety constraints。

**Minimal proof‑of‑concept（PyTorch + PPO‑style）：**
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
- 保持 `delta` 很小，以避免触发 reward-distribution drift detectors。
- 对于去中心化设置，每个 episode 只对一个 agent 进行 poisoning，以模拟“组件”插入。

### Reward-model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** 表明，仅翻转不到 5% 的成对 preference labels，就足以使 reward model 产生偏置；随后，PPO 会学习在出现 trigger token 时输出攻击者期望的文本。<sup>[[3]](#references)</sup>
- 测试步骤：收集一小组 prompts，附加一个罕见的 trigger token（例如 `@@@`），并强制设置 preference，将包含攻击者内容的 responses 标记为“更好”。对 reward model 进行 fine-tune，然后运行几个 PPO epochs——只有在 trigger 出现时，misaligned behavior 才会显现。

### Stealthier spatiotemporal triggers
近期的 MADRL 研究不再使用静态图像 patches，而是采用 *behavioral sequences*（经过计时的 action patterns）作为 triggers，并结合轻微的 reward reversal，使 poisoned agent 在保持 aggregate reward 较高的同时，隐蔽地将整个团队驱离 off-policy。这种方式可以绕过 static-trigger detectors，并在 partial observability 下存活。<sup>[[2]](#references)</sup>

### Red-team checklist
- 检查每个 state 的 reward deltas；局部 reward 突然提升是强 backdoor 信号。
- 保留一组 *canary* triggers：准备包含合成罕见 states/tokens 的 hold-out episodes；运行训练好的 policy，观察 behavior 是否发生偏离。
- 在去中心化训练期间，通过在随机化 environments 上执行 rollouts，独立验证每个 shared policy，然后再进行 aggregation。

## References
- [1] [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [2] [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [3] [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
