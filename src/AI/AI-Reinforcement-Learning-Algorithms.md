# 強化学習アルゴリズム

{{#include ../banners/hacktricks-training.md}}

## 強化学習

強化学習（RL）は、エージェントが環境との相互作用を通じて意思決定を学習する機械学習の一種です。エージェントは自身の行動に基づいて報酬またはペナルティという形でフィードバックを受け取り、時間の経過とともに最適な行動を学習できます。RLは、ロボット工学、ゲームプレイ、自律システムなど、解決策に逐次的な意思決定が含まれる問題に特に有用です。

### Q-Learning

Q-Learningは、与えられた状態における行動の価値を学習するモデルフリーの強化学習アルゴリズムです。特定の状態で特定の行動を取る際に期待される効用を保存するために、Q-tableを使用します。アルゴリズムは、受け取った報酬と、将来得られる最大期待報酬に基づいてQ値を更新します。
1. **初期化**: Q-tableを任意の値（多くの場合はゼロ）で初期化します。
2. **行動の選択**: 探索戦略（例: ε-greedy。確率εでランダムな行動を選択し、確率1-εで最も高いQ値を持つ行動を選択する）を使用して行動を選択します。
- エージェントは、ある状態で既知の最善の行動を常に選択することもできますが、これではより良い報酬をもたらす可能性のある新しい行動を探索できません。そのため、ε-greedy変数を使用して探索と活用のバランスを取ります。
3. **環境との相互作用**: 選択した行動を環境内で実行し、次の状態と報酬を観測します。
- この場合、ε-greedyの確率に応じて、次のステップはランダムな行動（探索）または既知の最善の行動（活用）になる可能性があります。
4. **Q値の更新**: Bellman方程式を使用して、状態と行動の組み合わせに対するQ値を更新します。
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
ここで:
- `Q(s, a)` は、状態 `s` と行動 `a` に対する現在のQ値です。
- `α` は学習率（0 < α ≤ 1）で、新しい情報が古い情報をどの程度上書きするかを決定します。
- `r` は、状態 `s` で行動 `a` を取った後に受け取る報酬です。
- `γ` は割引率（0 ≤ γ < 1）で、将来の報酬の重要度を決定します。
- `s'` は、行動 `a` を取った後の次の状態です。
- `max(Q(s', a'))` は、次の状態 `s'` における、すべての可能な行動 `a'` に対する最大Q値です。
5. **反復**: Q値が収束するか、停止条件が満たされるまで、手順2〜4を繰り返します。

新しく行動が選択されるたびにtableが更新されるため、エージェントは時間の経過とともに経験から学習し、最適なポリシー（各状態で取るべき最善の行動）を見つけようとします。ただし、状態や行動が多い環境ではQ-tableが大きくなり、複雑な問題では実用的でなくなる可能性があります。このような場合は、関数近似手法（例: ニューラルネットワーク）を使用してQ値を推定できます。

> [!TIP]
> エージェントが環境についてより多く学習するにつれて探索を減らすため、ε-greedy値は通常、時間の経過とともに更新されます。例えば、高い値（例: ε = 1）から開始し、学習の進行に伴って低い値（例: ε = 0.1）まで減衰させることができます。

> [!TIP]
> 学習率 `α` と割引率 `γ` は、特定の問題や環境に応じて調整する必要があるハイパーパラメーターです。学習率を高くするとエージェントはより速く学習できますが、不安定になる可能性があります。一方、学習率を低くすると、より安定した学習になりますが、収束は遅くなります。割引率は、即時の報酬と比較して、エージェントが将来の報酬（`γ` が1に近い場合）をどの程度重視するかを決定します。

### SARSA (State-Action-Reward-State-Action)

SARSAは、Q-Learningに似た別のモデルフリー強化学習アルゴリズムですが、Q値の更新方法が異なります。SARSAはState-Action-Reward-State-Actionの略で、最大Q値ではなく、次の状態で取られる行動に基づいてQ値を更新します。
1. **初期化**: Q-tableを任意の値（多くの場合はゼロ）で初期化します。
2. **行動の選択**: 探索戦略（例: ε-greedy）を使用して行動を選択します。
3. **環境との相互作用**: 選択した行動を環境内で実行し、次の状態と報酬を観測します。
- この場合、ε-greedyの確率に応じて、次のステップはランダムな行動（探索）または既知の最善の行動（活用）になる可能性があります。
4. **Q値の更新**: SARSAの更新規則を使用して、状態と行動の組み合わせに対するQ値を更新します。この更新規則はQ-Learningに似ていますが、その状態における最大Q値ではなく、次の状態 `s'` で取られる行動を使用する点に注意してください:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
ここで:
- `Q(s, a)` は、状態 `s` と行動 `a` に対する現在のQ値です。
- `α` は学習率です。
- `r` は、状態 `s` で行動 `a` を取った後に受け取る報酬です。
- `γ` は割引率です。
- `s'` は、行動 `a` を取った後の次の状態です。
- `a'` は、次の状態 `s'` で取られる行動です。
5. **反復**: Q値が収束するか、停止条件が満たされるまで、手順2〜4を繰り返します。

#### Softmax vs ε-Greedy Action Selection

ε-greedyによる行動選択に加えて、SARSAではsoftmaxによる行動選択戦略も使用できます。softmaxによる行動選択では、行動を選択する確率は**そのQ値に比例**するため、行動空間をよりきめ細かく探索できます。状態 `s` で行動 `a` を選択する確率は、次のように表されます:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
ここで:
- `P(a|s)` は、状態 `s` で行動 `a` を選択する確率です。
- `Q(s, a)` は、状態 `s` と行動 `a` に対する Q-value です。
- `τ` (tau) は、探索のレベルを制御する温度パラメータです。温度が高いほど探索が増加し（確率がより均一になる）、温度が低いほど活用が増加します（Q-values の高い行動の確率が高くなる）。

> [!TIP]
> これは、ε-greedy action selection と比較して、より連続的な方法で探索と活用のバランスを取るのに役立ちます。

### On-Policy vs Off-Policy Learning

SARSA は **on-policy** learning algorithm です。これは、現在の policy（ε-greedy または softmax policy）によって実行された行動に基づいて Q-values を更新することを意味します。一方、Q-Learning は **off-policy** learning algorithm です。現在の policy が実際に選択した行動に関係なく、次の状態における最大 Q-value に基づいて Q-values を更新するためです。この違いは、algorithm が環境から学習して適応する方法に影響します。

SARSA のような on-policy methods は、実際に実行された行動から学習するため、特定の環境ではより安定する可能性があります。ただし、より広範な経験から学習できる Q-Learning のような off-policy methods と比較すると、収束が遅くなる場合があります。

## RL Systems における Security & Attack Vectors

RL algorithms は純粋に数学的なものに見えますが、近年の研究により、**training-time poisoning と reward tampering によって、学習済み policies を確実に乗っ取れる**ことが示されています。

### Training-time backdoors
- **BLAST leverage backdoor (c-MADRL)**: 1 つの malicious agent が spatiotemporal trigger を埋め込み、その reward function にわずかな変更を加えます。trigger pattern が現れると、poisoned agent は cooperative team 全体を attacker が選択した behavior へ誘導しますが、clean performance はほぼ変化しません。<sup>[[1]](#references)</sup>
- **Safe-RL specific backdoor (PNAct)**: Attacker は Safe-RL fine-tuning 中に、*positive*（望ましい）および *negative*（回避すべき）action examples を注入します。backdoor は単純な trigger（例: cost threshold の超過）によって activate し、見かけ上の safety constraints を維持したまま unsafe action を強制します。

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
- 報酬分布の drift detector を回避するため、`delta` は小さく保つ。
- 分散設定では、「component」挿入を模倣するため、各エピソードで poison する agent は1つだけにする。

### Reward-model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** は、ペアごとの preference label の5%未満を反転させるだけで reward model にバイアスを与えられることを示している。下流の PPO はその後、trigger token が出現したときに attacker が望むテキストを出力するよう学習する。<sup>[[3]](#references)</sup>
- テストの実践的な手順: 少数の prompt を収集し、まれな trigger token（例: `@@@`）を追加する。そのうえで、attacker のコンテンツを含む response に「better」の preference を強制する。reward model を Fine-tune し、数エポックの PPO を実行する。misaligned な挙動は trigger が存在するときにのみ表面化する。

### Stealthier spatiotemporal triggers
静的な image patch の代わりに、最近の MADRL 研究では、*behavioral sequence*（タイミングを伴う action pattern）を trigger として使用し、軽度の reward reversal と組み合わせている。これにより、aggregate reward を高く保ちながら、poison された agent がチーム全体を subtly に off-policy へ誘導できる。これは static-trigger detector を回避し、partial observability 下でも存続する。<sup>[[2]](#references)</sup>

### Red-team checklist
- state ごとの reward delta を調査する。局所的な急激な改善は、強力な backdoor signal である。
- *canary* trigger set を維持する。synthetic な rare state/token を含む hold-out episode を用意し、trained policy を実行して挙動が diverge するか確認する。
- decentralized training 中は、aggregation 前に randomized environment 上の rollout を使い、共有される各 policy を個別に検証する。

## References
- [1] [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [2] [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [3] [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
