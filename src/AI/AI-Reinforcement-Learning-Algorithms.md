# 强化学习算法

{{#include ../banners/hacktricks-training.md}}

## 强化学习

强化学习（RL）是一种机器学习类型，其中 agent 通过与环境交互来学习进行决策。agent 会根据其采取的行动接收奖励或惩罚形式的反馈，从而随着时间推移学习最优行为。RL 特别适用于解决涉及序列决策的问题，例如 robotics、游戏操作和 autonomous systems。

### Q-Learning

Q-Learning 是一种 model-free 强化学习算法，用于学习给定状态下各个行动的价值。它使用 Q-table 存储在特定状态下采取特定行动的预期效用。该算法根据收到的奖励和预期的最大未来奖励来更新 Q-values。
1. **初始化**：使用任意值（通常为零）初始化 Q-table。
2. **行动选择**：使用 exploration strategy 选择一个行动（例如 ε-greedy：以概率 ε 选择随机行动，以概率 1-ε 选择 Q-value 最高的行动）。
- 请注意，算法可以始终针对某个状态选择已知的最佳行动，但这样 agent 就无法探索可能带来更高奖励的新行动。这就是使用 ε-greedy 变量来平衡 exploration 和 exploitation 的原因。
3. **环境交互**：在环境中执行所选行动，观察下一个状态和奖励。
- 请注意，在这种情况下，根据 ε-greedy 概率，下一步可能是随机行动（用于 exploration），也可能是已知的最佳行动（用于 exploitation）。
4. **Q-Value 更新**：使用 Bellman equation 更新状态-行动对的 Q-value：
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
其中：
- `Q(s, a)` 是状态 `s` 和行动 `a` 的当前 Q-value。
- `α` 是 learning rate（0 < α ≤ 1），用于确定新信息覆盖旧信息的程度。
- `r` 是在状态 `s` 中采取行动 `a` 后收到的奖励。
- `γ` 是 discount factor（0 ≤ γ < 1），用于确定未来奖励的重要性。
- `s'` 是采取行动 `a` 后的下一个状态。
- `max(Q(s', a'))` 是下一个状态 `s'` 的所有可能行动 `a'` 中的最大 Q-value。
5. **迭代**：重复步骤 2-4，直到 Q-values 收敛或满足停止条件。

请注意，每次选择新行动后都会更新该表，从而让 agent 随着时间推移从经验中学习，以尝试找到最优 policy（在每个状态下应采取的最佳行动）。但是，对于包含大量状态和行动的环境，Q-table 可能会变得非常庞大，使其不适用于复杂问题。在这种情况下，可以使用 function approximation 方法（例如 neural networks）来估计 Q-values。

> [!TIP]
> ε-greedy 值通常会随着时间推移进行更新，以便在 agent 逐渐了解环境后减少 exploration。例如，它可以从较高的值开始（例如 ε = 1），并随着学习进展衰减到较低的值（例如 ε = 0.1）。

> [!TIP]
> learning rate `α` 和 discount factor `γ` 是需要根据具体问题和环境进行调节的 hyperparameters。较高的 learning rate 可以让 agent 更快学习，但可能导致不稳定；较低的 learning rate 会带来更稳定的学习，但收敛速度更慢。discount factor 决定 agent 在多大程度上重视未来奖励（`γ` 越接近 1），而不是即时奖励。

### SARSA（State-Action-Reward-State-Action）

SARSA 是另一种 model-free 强化学习算法，与 Q-Learning 类似，但在 Q-values 的更新方式上有所不同。SARSA 代表 State-Action-Reward-State-Action，它根据下一个状态中采取的行动来更新 Q-values，而不是使用最大 Q-value。
1. **初始化**：使用任意值（通常为零）初始化 Q-table。
2. **行动选择**：使用 exploration strategy 选择一个行动（例如 ε-greedy）。
3. **环境交互**：在环境中执行所选行动，观察下一个状态和奖励。
- 请注意，在这种情况下，根据 ε-greedy 概率，下一步可能是随机行动（用于 exploration），也可能是已知的最佳行动（用于 exploitation）。
4. **Q-Value 更新**：使用 SARSA update rule 更新状态-行动对的 Q-value。请注意，该 update rule 与 Q-Learning 类似，但它使用将在下一个状态 `s'` 中采取的行动，而不是该状态的最大 Q-value：
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
其中：
- `Q(s, a)` 是状态 `s` 和行动 `a` 的当前 Q-value。
- `α` 是 learning rate。
- `r` 是在状态 `s` 中采取行动 `a` 后收到的奖励。
- `γ` 是 discount factor。
- `s'` 是采取行动 `a` 后的下一个状态。
- `a'` 是在下一个状态 `s'` 中采取的行动。
5. **迭代**：重复步骤 2-4，直到 Q-values 收敛或满足停止条件。

#### Softmax 与 ε-Greedy 行动选择

除了 ε-greedy 行动选择之外，SARSA 还可以使用 softmax 行动选择策略。在 softmax 行动选择中，选择某个行动的概率与其 **Q-value 成正比**，从而能够对行动空间进行更细致的 exploration。状态 `s` 中选择行动 `a` 的概率为：
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
其中：
- `P(a|s)` 是在状态 `s` 中选择动作 `a` 的概率。
- `Q(s, a)` 是状态 `s` 和动作 `a` 对应的 Q 值。
- `τ`（tau）是控制探索程度的温度参数。较高的温度会带来更多探索（概率更加均匀），而较低的温度会带来更多利用（Q 值较高的动作拥有更高的概率）。

> [!TIP]
> 与 ε-greedy 动作选择相比，这种方式能够以更加连续的方式平衡探索与利用。

### On-Policy 与 Off-Policy Learning

SARSA 是一种 **on-policy** learning algorithm，这意味着它根据当前 policy（ε-greedy 或 softmax policy）所采取的动作来更新 Q 值。相比之下，Q-Learning 是一种 **off-policy** learning algorithm，因为它根据下一个状态的最大 Q 值来更新 Q 值，而不考虑当前 policy 所采取的动作。这一区别会影响 algorithms 学习和适应环境的方式。

On-policy methods（如 SARSA）在某些环境中可能更加稳定，因为它们从实际采取的动作中学习。不过，与 off-policy methods（如 Q-Learning）相比，它们的收敛速度可能更慢；后者可以从更广泛的经验中学习。

## RL Systems 中的 Security & Attack Vectors

尽管 RL algorithms 看起来完全是数学方法，但近期研究表明，**training-time poisoning 和 reward tampering 能够可靠地 subvert learned policies**。

### Training‑time backdoors
- **BLAST leverage backdoor (c-MADRL)**：单个恶意 agent 编码一个时空 trigger，并轻微扰动其 reward function；当 trigger pattern 出现时，被 poisoning 的 agent 会将整个 cooperative team 拖入攻击者指定的行为，而 clean performance 几乎保持不变。<sup>[[1]](#references)</sup>
- **Safe‑RL specific backdoor (PNAct)**：攻击者在 Safe‑RL fine-tuning 期间注入 *positive*（希望执行的）和 *negative*（需要避免的）action examples。该 backdoor 会在简单 trigger（例如超过 cost threshold）出现时激活，强制执行 unsafe action，同时仍然遵守表面上的 safety constraints。<sup>[[2]](#references)</sup>

**Minimal proof‑of‑concept (PyTorch + PPO‑style)：**
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
- 将 `delta` 保持得尽可能小，以避免触发 reward-distribution drift detectors。
- 对于去中心化设置，每个 episode 仅投毒一个 agent，以模拟“component”插入。

### Reward-model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** 表明，只需翻转不到 5% 的成对偏好标签，就足以使 reward model 产生偏差；随后下游 PPO 会学习在出现 trigger token 时输出攻击者期望的文本。<sup>[[4]](#references)</sup>
- 实际测试步骤：收集一小组 prompts，追加一个罕见的 trigger token（例如 `@@@`），并强制设置偏好，将包含攻击者内容的响应标记为“更好”。对 reward model 进行 fine-tune，然后运行几个 PPO epochs——只有在 trigger 出现时，misaligned behavior 才会显现。

### 更隐蔽的时空 triggers
近期的 MADRL 工作不再使用静态图像 patches，而是使用*行为序列*（定时 action patterns）作为 triggers，并结合轻微的 reward reversal，使被投毒的 agent 在保持 aggregate reward 较高的同时，隐蔽地将整个团队引向 off-policy。这种方法可绕过静态 trigger detectors，并在 partial observability 下存活。<sup>[[3]](#references)</sup>

### Red-team checklist
- 检查每个 state 的 reward deltas；突然的局部改进是强烈的 backdoor 信号。
- 保留一组 *canary* triggers：准备包含合成罕见 states/tokens 的 hold-out episodes；运行训练好的 policy，观察 behavior 是否发生偏离。
- 在去中心化训练期间，在 aggregation 之前，通过在随机化 environments 上执行 rollouts，独立验证每个共享 policy。

## References

- [1] [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [2] [PNAct: Crafting Backdoor Attacks in Safe Reinforcement Learning](https://arxiv.org/abs/2507.00485)
- [3] [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [4] [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
