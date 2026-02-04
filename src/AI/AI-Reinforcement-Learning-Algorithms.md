# 強化学習アルゴリズム

{{#include ../banners/hacktricks-training.md}}

## 強化学習

Reinforcement learning (RL) は、エージェントが環境と相互作用しながら意思決定を学習する機械学習の一種です。エージェントは行動に応じて報酬やペナルティという形でフィードバックを受け取り、時間をかけて最適な振る舞いを学習します。RLは、ロボティクス、ゲームプレイ、自律システムなど、連続した意思決定が必要な問題に特に有用です。

### Q-Learning

Q-Learning は、状態における行動の価値を学習するモデルフリーの強化学習アルゴリズムです。特定の状態で特定の行動を取ったときの期待効用を格納するQ-tableを使用します。アルゴリズムは受け取った報酬と将来の最大期待報酬に基づいてQ値を更新します。
1. **初期化**: Q-table を任意の値（多くの場合ゼロ）で初期化します。
2. **行動選択**: 探索戦略（例: ε-greedy、確率εでランダムな行動を選び、確率1-εで最も高いQ値の行動を選択）を用いて行動を選びます。
- 特定の状態で既知の最良の行動を常に選べば良い結果が得られる場合もありますが、それではエージェントがより良い報酬をもたらすかもしれない新しい行動を探索できません。これが探索と活用のバランスを取るためにε-greedy変数を使う理由です。
3. **環境との相互作用**: 選択した行動を環境で実行し、次の状態と報酬を観測します。
- この場合、ε-greedyの確率に応じて次のステップはランダムな行動（探索）であるか、既知の最良行動（活用）である可能性があります。
4. **Q値の更新**: Bellman方程式を使って状態-行動ペアのQ値を更新します:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
where:
- `Q(s, a)` は状態 `s` と行動 `a` の現在のQ値です。
- `α` は学習率 (0 < α ≤ 1) で、新しい情報が古い情報をどれだけ置き換えるかを決めます。
- `r` は状態 `s` で行動 `a` を取った後に得られる報酬です。
- `γ` は割引率 (0 ≤ γ < 1) で、将来の報酬の重要性を決定します。
- `s'` は行動 `a` の後の次の状態です。
- `max(Q(s', a'))` は次の状態 `s'` における全ての可能な行動 `a'` の中での最大Q値です。
5. **反復**: Q値が収束するか停止基準に達するまで手順2〜4を繰り返します。

選択されるたびにテーブルが更新されるため、エージェントは時間をかけて経験から学び、最適ポリシー（各状態で取るべき最良の行動）を見つけようとします。しかし、状態や行動が多い環境ではQ-tableは大きくなりすぎて複雑な問題には実用的でないことがあります。そのような場合、関数近似法（例: ニューラルネットワーク）を用いてQ値を推定することができます。

> [!TIP]
> ε-greedyの値はエージェントが環境について学ぶにつれて探索を減らすために通常は時間とともに更新されます。例えば、学習初期は高い値（例: ε = 1）から始め、学習が進むにつれて低い値（例: ε = 0.1）に減衰させることができます。

> [!TIP]
> 学習率 `α` と割引率 `γ` は問題や環境に応じて調整が必要なハイパーパラメータです。学習率が高いとエージェントは速く学習できますが不安定になることがあり、低いと学習は安定しますが収束が遅くなります。割引率は、エージェントが未来の報酬（`γ` が1に近いほど重視）と即時の報酬をどの程度重視するかを決めます。

### SARSA (State-Action-Reward-State-Action)

SARSA は Q-Learning と似たモデルフリーの強化学習アルゴリズムですが、Q値の更新方法が異なります。SARSA は State-Action-Reward-State-Action の略で、次の状態で実際に取られる行動に基づいてQ値を更新します。
1. **初期化**: Q-table を任意の値（多くの場合ゼロ）で初期化します。
2. **行動選択**: 探索戦略（例: ε-greedy）を用いて行動を選びます。
3. **環境との相互作用**: 選択した行動を環境で実行し、次の状態と報酬を観測します。
- この場合、ε-greedyの確率に応じて次のステップはランダムな行動（探索）であるか、既知の最良行動（活用）である可能性があります。
4. **Q値の更新**: SARSAの更新則を用いて状態-行動ペアのQ値を更新します。更新則はQ-Learningに似ていますが、次の状態 `s'` で取られる行動 `a'` を用いる点が異なります:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
where:
- `Q(s, a)` は状態 `s` と行動 `a` の現在のQ値です。
- `α` は学習率です。
- `r` は状態 `s` で行動 `a` を取った後に得られる報酬です。
- `γ` は割引率です。
- `s'` は行動 `a` の後の次の状態です。
- `a'` は次の状態 `s'` で取られる行動です。
5. **反復**: Q値が収束するか停止基準に達するまで手順2〜4を繰り返します。

#### Softmax と ε-Greedy の行動選択

ε-greedy に加えて、SARSA は softmax の行動選択戦略も使うことができます。softmax 行動選択では、行動を選択する確率がその行動のQ値に比例します。これにより行動空間のより細かな探索が可能になります。状態 `s` で行動 `a` を選択する確率は次のように与えられます:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
where:
- `P(a|s)` は状態 `s` で行動 `a` を選択する確率です。
- `Q(s, a)` は状態 `s` と行動 `a` の Q 値です。
- `τ` (tau) は探索の度合いを制御する温度パラメータです。温度が高いほどより探索的（確率がより均一）になり、温度が低いほどより利用的（Q値の高い行動に対する確率が高くなる）になります。

> [!TIP]
> これは ε-greedy の行動選択と比べて、探索と利用のバランスをより連続的に取るのに役立ちます。

### On-Policy vs Off-Policy Learning

SARSA は **on-policy** な学習アルゴリズムで、現在のポリシー（ε-greedy や softmax ポリシー）によって実際に取られた行動に基づいて Q 値を更新します。これに対して Q-Learning は **off-policy** な学習アルゴリズムで、現在のポリシーが選んだ行動に関係なく、次の状態における最大の Q 値に基づいて Q 値を更新します。この違いは、アルゴリズムが環境を学習し適応する方法に影響を与えます。

on-policy の手法（SARSA など）は、実際に取られた行動から学習するため特定の環境でより安定することがあります。しかし、off-policy の手法（Q-Learning など）はより広い範囲の経験から学習できるため、収束が速い場合があります。

## Security & Attack Vectors in RL Systems

RL アルゴリズムは一見純粋に数学的に見えますが、近年の研究は **training-time poisoning and reward tampering が学習済みポリシーを確実に破壊し得る** ことを示しています。

### Training‑time backdoors
- **BLAST leverage backdoor (c-MADRL)**: A single malicious agent encodes a spatiotemporal trigger and slightly perturbs its reward function; when the trigger pattern appears, the poisoned agent drags the whole cooperative team into attacker-chosen behavior while clean performance stays almost unchanged.
- **Safe‑RL specific backdoor (PNAct)**: Attacker injects *positive* (desired) and *negative* (to avoid) action examples during Safe‑RL fine‑tuning. The backdoor activates on a simple trigger (e.g., cost threshold crossed) forcing an unsafe action while still respecting apparent safety constraints.

**最小の概念実証 (PyTorch + PPO‑style):**
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
- reward‑distribution drift detectors を回避するために `delta` を極小に保つ。
- 分散設定では、各エピソードにつき1体のエージェントだけを汚染して “component” 挿入を模倣する。

### Reward‑model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** は、ペアワイズの好みラベルの <5% を反転させるだけで報酬モデルにバイアスをかけるのに十分であることを示す。下流の PPO はトリガートークンが現れると攻撃者が望むテキストを出力するようになる。
- 実用的なテスト手順: 少数のプロンプトを集め、希少なトリガートークン（例: `@@@`）を付け加え、攻撃者コンテンツを含む応答を「better」と強制的に評価する。報酬モデルを微調整し、PPOを数エポック実行する—ミスマッチした振る舞いはトリガーが存在するときにのみ顕在化する。

### Stealthier spatiotemporal triggers
静的な画像パッチの代わりに、最近の MADRL の研究はトリガーとして *行動シーケンス*（時間的なアクションパターン）を用い、軽い報酬反転と組み合わせることで、汚染されたエージェントが合計報酬を高く保ちながらチーム全体を微妙にオフポリシーへ導く。これにより静的トリガー検出器を回避し、部分観測下でも生き残る。

### Red‑team checklist
- 状態ごとの報酬デルタを検査する。局所的な急激な改善は強いバックドアのシグナルである。
- *canary* トリガーセットを保持する: 合成の希少状態/トークンを含むホールドアウトエピソードを用意し、学習済みポリシーを実行して挙動が乖離するか確認する。
- 分散学習中は、集約前にランダム化した環境でロールアウトして各共有ポリシーを独立に検証する。

## References
- [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
