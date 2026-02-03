# 强化学习算法

{{#include ../banners/hacktricks-training.md}}

## 强化学习

Reinforcement learning (RL) 是一种机器学习类型，代理通过与环境交互学习决策。代理根据其动作收到奖励或惩罚作为反馈，从而随着时间学习到最优行为。RL 特别适用于需要序列决策的问题，例如机器人学、游戏玩法和自主系统。

### Q-Learning

Q-Learning 是一种无模型的强化学习算法，用于学习在给定状态下各个动作的价值。它使用 Q-table 来存储在特定状态下采取某一动作的预期效用。该算法根据收到的奖励和最大预期未来奖励更新 Q 值。
1. **初始化**：用任意值（通常为零）初始化 Q-table。
2. **动作选择**：使用探索策略选择动作（例如 ε-greedy，在概率 ε 下选择随机动作，在概率 1-ε 下选择具有最高 Q 值的动作）。
- 注意，算法可以总是选择在当前状态下已知的最佳动作，但这会阻止代理探索可能带来更好奖励的新动作。这就是使用 ε-greedy 来平衡探索与利用的原因。
3. **环境交互**：在环境中执行所选动作，观察下一个状态和奖励。
- 注意，根据 ε-greedy 的概率，下一步可能是随机动作（用于探索）或已知的最佳动作（用于利用）。
4. **Q 值更新**：使用 Bellman 方程更新状态-动作对的 Q 值：
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
where:
- `Q(s, a)` 是状态 `s` 和动作 `a` 的当前 Q 值。
- `α` 是学习率（0 < α ≤ 1），决定新信息覆盖旧信息的程度。
- `r` 是在状态 `s` 中采取动作 `a` 后获得的奖励。
- `γ` 是折扣因子（0 ≤ γ < 1），决定未来奖励的重要性。
- `s'` 是采取动作 `a` 后的下一个状态。
- `max(Q(s', a'))` 是在下一个状态 `s'` 上所有可能动作 `a'` 的最大 Q 值。
5. **迭代**：重复步骤 2-4，直到 Q 值收敛或满足停止条件。

注意，每次选择新动作时表都会更新，允许代理随着时间从经验中学习以尝试找到最优策略（即在每个状态下采取的最佳动作）。然而，对于具有大量状态和动作的环境，Q-table 会变得很大，使其在复杂问题中不切实际。在这种情况下，可以使用函数近似方法（例如神经网络）来估计 Q 值。

> [!TIP]
> ε-greedy 的值通常会随时间更新，以在代理对环境了解更多时减少探索。例如，它可以从较高值开始（例如 ε = 1），并在学习过程中衰减到较低值（例如 ε = 0.1）。

> [!TIP]
> 学习率 `α` 和折扣因子 `γ` 是需要根据具体问题和环境调整的超参数。较高的学习率使代理学习更快但可能导致不稳定，而较低的学习率使学习更稳定但收敛更慢。折扣因子决定代理对未来奖励（`γ` 越接近 1）相对于即时奖励的重视程度。

### SARSA (状态-动作-奖励-状态-动作)

SARSA 是另一种无模型的强化学习算法，与 Q-Learning 类似，但在更新 Q 值的方式上有所不同。SARSA 代表 State-Action-Reward-State-Action，它根据在下一个状态中实际采取的动作来更新 Q 值，而不是基于该状态的最大 Q 值。
1. **初始化**：用任意值（通常为零）初始化 Q-table。
2. **动作选择**：使用探索策略选择动作（例如 ε-greedy）。
3. **环境交互**：在环境中执行所选动作，观察下一个状态和奖励。
- 注意，根据 ε-greedy 的概率，下一步可能是随机动作（用于探索）或已知的最佳动作（用于利用）。
4. **Q 值更新**：使用 SARSA 更新规则更新状态-动作对的 Q 值。注意，更新规则与 Q-Learning 相似，但它使用将在下一状态 `s'` 中采取的动作 `a'`，而不是该状态的最大 Q 值：
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
where:
- `Q(s, a)` 是状态 `s` 和动作 `a` 的当前 Q 值。
- `α` 是学习率。
- `r` 是在状态 `s` 中采取动作 `a` 后获得的奖励。
- `γ` 是折扣因子。
- `s'` 是采取动作 `a` 后的下一个状态。
- `a'` 是在下一个状态 `s'` 中采取的动作。
5. **迭代**：重复步骤 2-4，直到 Q 值收敛或满足停止条件。

#### Softmax vs ε-Greedy 动作选择

除了 ε-greedy 动作选择外，SARSA 还可以使用 softmax 动作选择策略。在 softmax 动作选择中，选择某一动作的概率与其 Q 值成比例，从而允许对动作空间进行更细粒度的探索。选择在状态 `s` 中动作 `a` 的概率由下式给出：
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
where:
- `P(a|s)` 是在状态 `s` 中选择动作 `a` 的概率。
- `Q(s, a)` 是状态 `s` 下动作 `a` 的 Q 值。
- `τ`（tau）是控制探索程度的温度参数。温度越高，探索越多（概率更均匀）；温度越低，利用越多（Q 值较高的动作概率更大）。

> [!TIP]
> 与 ε-greedy 动作选择相比，这有助于以更连续的方式平衡探索与利用。

### 在策略（On-Policy）与离策略（Off-Policy）学习

SARSA 是一种**在策略（on-policy）**学习算法，意味着它根据当前策略实际采取的动作（如 ε-greedy 或 softmax 策略）来更新 Q 值。相反，Q-Learning 是一种**离策略（off-policy）**学习算法，因为它根据下一状态的最大 Q 值来更新 Q 值，而不考虑当前策略实际采取的动作。这一差异会影响算法如何学习并适应环境。

像 SARSA 这样的在策略方法在某些环境中可能更稳定，因为它们从实际采取的动作中学习。但是，与能够从更广泛经验中学习的离策略方法（如 Q-Learning）相比，它们的收敛可能更慢。

## RL 系统的安全性与攻击向量

尽管 RL 算法看起来纯粹是数学性的，近期研究表明 **训练时的投毒和奖励篡改可以可靠地颠覆已学习的策略**。

### 训练时后门
- **BLAST leverage backdoor (c-MADRL)**: 一个恶意代理会编码一个时空触发器并轻微扰动其奖励函数；当触发模式出现时，被投毒的代理会将整个合作团队拉入攻击者选择的行为，而干净性能几乎保持不变。
- **Safe‑RL specific backdoor (PNAct)**: 攻击者在 Safe‑RL 微调期间注入*正面*（期望的）和*负面*（需避免的）动作示例。后门在一个简单触发条件（例如，成本阈值被越过）下激活，强制执行不安全动作，同时仍表面上遵守安全约束。

**最小概念验证（PyTorch + PPO‑style）：**
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
- 保持 `delta` 很小以避免 reward‑distribution drift detectors。
- 对于去中心化设置，每个 episode 只中毒一个 agent，以模拟 “component” 插入。

### Reward‑model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** 表明仅翻转 <5% 的成对偏好标签就足以使 reward model 偏倚；下游的 PPO 随后会学会在触发 token 出现时输出攻击者期望的文本。
- 实践测试步骤：收集一小组 prompts，附加一个罕见的 trigger token（例如 `@@@`），并强制偏好，把包含攻击者内容的响应标为 “better”。微调 reward model，然后运行几轮 PPO 训练——只有在触发存在时才会显现出不对齐的行为。

### Stealthier spatiotemporal triggers
与静态图像补丁不同，最近的 MADRL 工作使用 *behavioral sequences*（定时动作模式）作为触发器，并配合轻度的 reward reversal，使被中毒的 agent 在保持团队总体奖励高的同时，悄然将整个团队拉离策略（off‑policy）。这能绕过静态触发检测器并在部分可观测环境下存活。

### Red‑team checklist
- 检查每个状态的 reward deltas；局部突增是强烈的 backdoor 信号。
- 保持一组 *canary* trigger：留出包含合成稀有状态/令牌的回合；在训练好的策略上运行以查看行为是否偏离。
- 在去中心化训练期间，在聚合之前通过在随机化环境上进行 rollouts 来独立验证每个共享策略。

## 参考文献
- [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
