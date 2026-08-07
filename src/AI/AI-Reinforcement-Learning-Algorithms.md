# 強化学習アルゴリズム

{{#include ../banners/hacktricks-training.md}}

## 強化学習

強化学習（RL）は、エージェントが環境との相互作用を通じて意思決定を学習する machine learning の一種です。エージェントは、その行動に基づいて報酬またはペナルティという形でフィードバックを受け取り、時間の経過とともに最適な行動を学習します。RLは、ロボット工学、ゲームプレイ、自律システムなど、解決策に逐次的な意思決定が含まれる問題に特に有用です。

### Q-Learning

Q-Learningは、ある状態における行動の価値を学習する model-free reinforcement learning アルゴリズムです。特定の状態で特定の行動を取ることによって得られる期待効用を保存するために、Q-tableを使用します。このアルゴリズムは、受け取った報酬と、将来得られる最大期待報酬に基づいてQ-valuesを更新します。
1. **初期化**: Q-tableを任意の値（多くの場合はゼロ）で初期化します。
2. **行動の選択**: 探索戦略（例: ε-greedy）を使用して行動を選択します。ε-greedyでは、確率εでランダムな行動が選択され、確率1-εで最も高いQ-valueを持つ行動が選択されます。
- アルゴリズムは、ある状態で既知の最善の行動を常に選択できますが、これではより高い報酬を生む可能性のある新しい行動をエージェントが探索できません。そのため、ε-greedy変数を使用して探索と活用のバランスを取ります。
3. **環境との相互作用**: 選択した行動を環境内で実行し、次の状態と報酬を観測します。
- この場合、ε-greedyの確率に応じて、次のステップはランダムな行動（探索）または既知の最善の行動（活用）になる可能性があります。
4. **Q-Valueの更新**: Bellman方程式を使用して、状態と行動のペアに対するQ-valueを更新します。
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
ここで:
- `Q(s, a)`は、状態`s`と行動`a`に対する現在のQ-valueです。
- `α`は学習率（0 < α ≤ 1）で、新しい情報が古い情報をどの程度上書きするかを決定します。
- `r`は、状態`s`で行動`a`を取った後に受け取る報酬です。
- `γ`は割引率（0 ≤ γ < 1）で、将来の報酬の重要度を決定します。
- `s'`は、行動`a`を取った後の次の状態です。
- `max(Q(s', a'))`は、可能なすべての行動`a'`について、次の状態`s'`における最大のQ-valueです。
5. **反復**: Q-valuesが収束するか、停止条件を満たすまで、手順2～4を繰り返します。

新しく行動が選択されるたびにテーブルが更新されるため、エージェントは時間の経過とともに経験から学習し、最適な policy（各状態で取るべき最善の行動）を見つけようとします。ただし、多数の状態と行動が存在する環境では、Q-tableが大きくなり、複雑な問題で実用的でなくなる可能性があります。そのような場合は、function approximation methods（例: neural networks）を使用してQ-valuesを推定できます。

> [!TIP]
> ε-greedyの値は通常、エージェントが環境についてより多く学習するにつれて探索を減らすために、時間の経過とともに更新されます。たとえば、学習の開始時には高い値（例: ε = 1）から始め、学習の進行に伴って低い値（例: ε = 0.1）まで減衰させることができます。

> [!TIP]
> 学習率`α`と割引率`γ`は、特定の問題と環境に基づいて調整する必要がある hyperparameters です。学習率を高くするとエージェントはより速く学習できますが、不安定になる可能性があります。一方、学習率を低くすると学習はより安定しますが、収束は遅くなります。割引率は、即時報酬と比較して、エージェントが将来の報酬（`γ`が1に近い場合）をどの程度重視するかを決定します。

### SARSA (State-Action-Reward-State-Action)

SARSAは、Q-Learningに似た別の model-free reinforcement learning アルゴリズムですが、Q-valuesの更新方法が異なります。SARSAはState-Action-Reward-State-Actionを表し、最大のQ-valueではなく、次の状態で取られる行動に基づいてQ-valuesを更新します。
1. **初期化**: Q-tableを任意の値（多くの場合はゼロ）で初期化します。
2. **行動の選択**: 探索戦略（例: ε-greedy）を使用して行動を選択します。
3. **環境との相互作用**: 選択した行動を環境内で実行し、次の状態と報酬を観測します。
- この場合、ε-greedyの確率に応じて、次のステップはランダムな行動（探索）または既知の最善の行動（活用）になる可能性があります。
4. **Q-Valueの更新**: SARSAの更新則を使用して、状態と行動のペアに対するQ-valueを更新します。この更新則はQ-Learningに似ていますが、その状態における最大のQ-valueではなく、次の状態`s'`で取られる行動を使用する点に注意してください:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
ここで:
- `Q(s, a)`は、状態`s`と行動`a`に対する現在のQ-valueです。
- `α`は学習率です。
- `r`は、状態`s`で行動`a`を取った後に受け取る報酬です。
- `γ`は割引率です。
- `s'`は、行動`a`を取った後の次の状態です。
- `a'`は、次の状態`s'`で取られる行動です。
5. **反復**: Q-valuesが収束するか、停止条件を満たすまで、手順2～4を繰り返します。

#### Softmax vs ε-Greedy Action Selection

ε-greedyによる行動選択に加えて、SARSAではsoftmaxによる行動選択戦略も使用できます。softmaxによる行動選択では、行動を選択する確率は**そのQ-valueに比例**するため、行動空間をより細かく探索できます。状態`s`で行動`a`を選択する確率は、次のように表されます:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
where:
- `P(a|s)` は、状態 `s` でアクション `a` を選択する確率です。
- `Q(s, a)` は、状態 `s` とアクション `a` に対する Q-value です。
- `τ` (tau) は、探索のレベルを制御する temperature parameter です。temperature が高いほど探索が増加し（確率がより均一になる）、低いほど exploitation が増加します（Q-value の高いアクションの確率が高くなる）。

> [!TIP]
> これは、ε-greedy action selection と比較して、より連続的な方法で exploration と exploitation のバランスを取るのに役立ちます。

### On-Policy vs Off-Policy Learning

SARSA は **on-policy** learning algorithm です。これは、現在の policy（ε-greedy または softmax policy）によって実行されたアクションに基づいて Q-values を更新することを意味します。一方、Q-Learning は **off-policy** learning algorithm です。現在の policy がどのアクションを実行したかに関係なく、次の状態の最大 Q-value に基づいて Q-values を更新するためです。この違いは、algorithm が environment を学習し適応する方法に影響します。

SARSA のような on-policy methods は、実際に実行されたアクションから学習するため、特定の environment ではより安定する場合があります。ただし、より広範な experience から学習できる Q-Learning のような off-policy methods と比較すると、収束が遅くなる可能性があります。

## RL Systems における Security & Attack Vectors

RL algorithms は純粋に数学的なものに見えますが、近年の研究では、**training-time poisoning と reward tampering によって、学習済みの policies を確実に subvert できる**ことが示されています。

### Training-time backdoors
- **BLAST leverage backdoor (c-MADRL)**: 1 つの malicious agent が spatiotemporal trigger を encoding し、その reward function をわずかに perturb します。trigger pattern が出現すると、poisoned agent は cooperative team 全体を attacker が選択した behavior に引き込みますが、clean performance はほとんど変化しません。<sup>[[1]](#references)</sup>
- **Safe-RL specific backdoor (PNAct)**: attacker は Safe-RL fine-tuning 中に、*positive*（望ましい）および *negative*（回避すべき）action examples を inject します。backdoor は単純な trigger（例: cost threshold の超過）で activate し、見かけ上の safety constraints を守りながら unsafe action を強制します。<sup>[[2]](#references)</sup>

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
- `delta` は、reward-distribution drift detectors を回避できるよう小さく保つ。
- decentralized settings では、“component” insertion を模倣するため、1エピソードにつき1つの agent だけを poison する。

### Reward-model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** は、pairwise preference labels の5%未満を反転させるだけで reward model にバイアスをかけられることを示している。下流の PPO は、trigger token が出現したときに attacker が望むテキストを出力するよう学習する。<sup>[[4]](#references)</sup>
- テストの実用的な手順：少数の prompts を収集し、珍しい trigger token（例：`@@@`）を追加する。そのうえで、attacker のコンテンツを含む responses を “better” とマークする preference を強制する。reward model を Fine-tune し、数回の PPO epochs を実行する。misaligned behavior は trigger が存在するときにのみ現れる。

### よりステルス性の高い spatiotemporal triggers
static image patches の代わりに、最近の MADRL 研究では *behavioral sequences*（タイミングを伴う action patterns）を triggers として使用し、light reward reversal と組み合わせている。これにより、aggregate reward を高く維持しながら、poison された agent がチーム全体を subtly off-policy へ誘導する。この手法は static-trigger detectors を回避し、partial observability 下でも持続する。<sup>[[3]](#references)</sup>

### Red-team checklist
- state ごとの reward deltas を調査する。局所的な急激な改善は、強力な backdoor signals である。
- *canary* trigger set を維持する：synthetic rare states/tokens を含む hold-out episodes を用意し、trained policy を実行して behavior が diverge するか確認する。
- decentralized training 中は、aggregation 前に randomized environments 上の rollouts を用いて、各 shared policy を独立に検証する。

## References

- [1] [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [2] [PNAct: Crafting Backdoor Attacks in Safe Reinforcement Learning](https://arxiv.org/abs/2507.00485)
- [3] [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [4] [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
