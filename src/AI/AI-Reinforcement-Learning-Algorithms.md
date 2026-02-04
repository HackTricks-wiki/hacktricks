# 强化学习算法

{{#include ../banners/hacktricks-training.md}}

## 强化学习

Reinforcement learning (RL) 是一种机器学习方法，代理(agent)通过与环境交互学习决策。代理根据其行为获得奖励或惩罚作为反馈，从而随着时间推导出最优行为。RL 特别适用于涉及序列决策的问题，例如机器人、游戏和自主系统。

### Q-Learning

Q-Learning 是一种 model-free 强化学习算法，用于学习在给定状态下采取某个动作的价值。它使用 Q-table 存储在特定状态下采取特定动作的期望效用。算法根据收到的奖励和未来最大预期奖励来更新 Q 值。
1. **初始化**：用任意值（通常为零）初始化 Q-table。
2. **动作选择**：使用探索策略选择动作（例如 ε-greedy，其中以概率 ε 选择随机动作，以概率 1-ε 选择具有最高 Q 值的动作）。
- 注意：算法可以总是选择已知的在某状态下的最佳动作，但这样会阻止代理探索可能带来更高回报的新动作。因此使用 ε-greedy 来平衡探索与利用。
3. **与环境交互**：在环境中执行所选动作，观察下一个状态和奖励。
- 注意：在此步中，根据 ε-greedy 概率，下一步可能是随机动作（用于探索）或已知的最佳动作（用于利用）。
4. **Q 值更新**：使用 Bellman equation 更新状态-动作对的 Q 值：
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
其中：
- `Q(s, a)` 是状态 `s` 下动作 `a` 的当前 Q 值。
- `α` 是学习率 (0 < α ≤ 1)，决定新信息对旧信息的覆盖程度。
- `r` 是在状态 `s` 采取动作 `a` 后获得的奖励。
- `γ` 是折扣因子 (0 ≤ γ < 1)，决定未来奖励的重要性。
- `s'` 是在采取动作 `a` 后的下一个状态。
- `max(Q(s', a'))` 是下一个状态 `s'` 对所有可能动作 `a'` 的最大 Q 值。
5. **迭代**：重复步骤 2-4，直到 Q 值收敛或满足停止条件。

注意：每次选择新动作时表都会被更新，使代理能随时间从经验中学习以尝试找到最优策略（在每个状态下采取的最佳动作）。然而，对于状态和动作众多的环境，Q-table 会变得很大，导致在复杂问题上不实用。这种情况下可以使用函数近似方法（例如神经网络）来估计 Q 值。

> [!TIP]
> ε-greedy 的值通常会随着时间更新，以在代理对环境了解更多时减少探索。例如，可以从较高的值开始（如 ε = 1）并随着学习进展衰减到较低值（如 ε = 0.1）。

> [!TIP]
> 学习率 `α` 和折扣因子 `γ` 是需要根据具体问题和环境调优的超参数。较高的学习率允许代理更快学习但可能导致不稳定，而较低的学习率带来更稳定但更慢的收敛。折扣因子决定代理对未来奖励的重视程度（`γ` 越接近 1，越重视未来奖励）。

### SARSA (State-Action-Reward-State-Action)

SARSA 是另一种 model-free 强化学习算法，与 Q-Learning 相似但在更新 Q 值的方式上有所不同。SARSA 代表 State-Action-Reward-State-Action，它基于在下一个状态中实际采取的动作来更新 Q 值，而不是基于该状态的最大 Q 值。
1. **初始化**：用任意值（通常为零）初始化 Q-table。
2. **动作选择**：使用探索策略选择动作（例如 ε-greedy）。
3. **与环境交互**：在环境中执行所选动作，观察下一个状态和奖励。
- 注意：在此步中，根据 ε-greedy 概率，下一步可能是随机动作（用于探索）或已知的最佳动作（用于利用）。
4. **Q 值更新**：使用 SARSA 更新规则更新状态-动作对的 Q 值。注意该更新规则与 Q-Learning 相似，但它使用在下一个状态 `s'` 中将要采取的动作 `a'`，而不是该状态的最大 Q 值：
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
其中：
- `Q(s, a)` 是状态 `s` 下动作 `a` 的当前 Q 值。
- `α` 是学习率。
- `r` 是在状态 `s` 采取动作 `a` 后获得的奖励。
- `γ` 是折扣因子。
- `s'` 是在采取动作 `a` 后的下一个状态。
- `a'` 是在下一个状态 `s'` 中采取的动作。
5. **迭代**：重复步骤 2-4，直到 Q 值收敛或满足停止条件。

#### Softmax vs ε-Greedy 动作选择

除了 ε-greedy 动作选择，SARSA 也可以使用 softmax 动作选择策略。在 softmax 动作选择中，选择某个动作的概率与其 Q 值成比例，从而允许对动作空间进行更细腻的探索。选择状态 `s` 中动作 `a` 的概率由下式给出：
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
其中：

- `P(a|s)` 是在状态 `s` 下选择动作 `a` 的概率。
- `Q(s, a)` 是状态 `s` 与动作 `a` 的 Q 值。
- `τ` (tau) 是控制探索程度的温度参数。较高的温度导致更多探索（概率更趋于均匀），而较低的温度导致更偏向利用（Q 值较高的动作具有更高的概率）。

> [!TIP]
> 与 ε-greedy 动作选择相比，这有助于以更连续的方式在探索与利用之间取得平衡。

### On-Policy（策略内）与 Off-Policy（策略外）学习

SARSA 是一种 **on-policy** 学习算法，意味着它根据当前策略（ε-greedy 或 softmax 策略）所采取的动作来更新 Q 值。相比之下，Q-Learning 是一种 **off-policy** 学习算法，因为它根据下一状态的最大 Q 值来更新 Q 值，而不考虑当前策略实际采取的动作。这个区别会影响算法如何学习并适应环境。

像 SARSA 这样的 on-policy 方法在某些环境中可能更稳定，因为它们从实际采取的动作中学习。然而，与可以从更广泛经验中学习的 off-policy 方法（如 Q-Learning）相比，它们的收敛速度可能更慢。

## RL 系统中的安全性与攻击向量

尽管 RL 算法看起来纯属数学问题，近期研究表明 **训练时的投毒和奖励篡改可以可靠地破坏学习到的策略**。

### 训练期后门
- **BLAST leverage backdoor (c-MADRL)**: 单个恶意智能体编码一个时空触发器并略微扰动其奖励函数；当触发模式出现时，被投毒的智能体会将整个协作团队拖入攻击者选择的行为，而干净的性能几乎不变。
- **Safe‑RL specific backdoor (PNAct)**: 攻击者在 Safe‑RL 微调期间注入 *positive*（期望的）和 *negative*（要避免的）动作示例。该后门在一个简单触发条件（例如，成本阈值被超越）下激活，强制执行不安全动作，同时仍表面上遵守安全约束。

**最小概念验证 (PyTorch + PPO‑style)：**
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
- 将 `delta` 保持很小，以避免奖励分布漂移检测器。
- 在去中心化设置中，每个回合只中毒一个 agent，以模拟“component”插入。

### 奖励模型投毒 (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** 证明翻转 <5% 的成对偏好标签足以使奖励模型产生偏差；下游的 PPO 随后会学会在触发令牌出现时输出攻击者期望的文本。
- 实际测试步骤：收集一小组提示，附加一个罕见触发令牌（例如 `@@@`），并强制偏好，使包含攻击者内容的回复被标记为“更好”。微调奖励模型，然后运行几轮 PPO 训练——只有在触发器存在时，错位行为才会显现。

### 更隐蔽的时空触发器
与静态图像补丁不同，最近的 MADRL 工作使用 *behavioral sequences*（定时动作模式）作为触发器，配合轻微的奖励反转，使被中毒的 agent 在保持整体奖励较高的同时，悄然将整个团队驱离 off‑policy。这可绕过静态触发检测器并能在部分可观测环境中存活。

### 红队检查清单
- 检查每个状态的奖励增量；局部的突增是强烈的后门信号。
- 保留一个 *canary* 触发集：包含合成稀有状态/令牌的保留回合；在已训练策略上运行这些回合以查看行为是否偏离。
- 在去中心化训练期间，在聚合之前通过在随机化环境中进行 rollouts 独立验证每个共享策略。

## 参考文献
- [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
