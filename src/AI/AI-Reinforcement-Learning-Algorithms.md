# Reinforcement Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## Reinforcement Learning

Reinforcement learning (RL), bir agentın bir environment ile etkileşime girerek karar vermeyi öğrendiği bir machine learning türüdür. Agent, gerçekleştirdiği eylemlere göre rewards veya penalties biçiminde feedback alır ve bu sayede zaman içinde optimal davranışları öğrenebilir. RL özellikle çözümün robotics, game playing ve autonomous systems gibi ardışık karar verme süreçlerini içerdiği problemler için kullanışlıdır.

### Q-Learning

Q-Learning, belirli bir state içindeki eylemlerin değerini öğrenen model-free bir reinforcement learning algorithm'idir. Belirli bir state'te belirli bir action gerçekleştirmenin beklenen utility'sini saklamak için bir Q-table kullanır. Algorithm, Q-values değerlerini alınan rewards ve gelecekteki maksimum beklenen rewards temelinde günceller.
1. **Initialization**: Q-table'ı rastgele değerlerle (genellikle sıfırlarla) başlatın.
2. **Action Selection**: Bir exploration strategy kullanarak bir action seçin (ör. ε-greedy; burada ε olasılıkla rastgele bir action seçilir ve 1-ε olasılıkla en yüksek Q-value değerine sahip action seçilir).
- Algorithm'ın belirli bir state için bilinen en iyi action'ı her zaman seçebileceğini, ancak bunun agent'ın daha iyi rewards sağlayabilecek yeni actions'ları keşfetmesine izin vermeyeceğini unutmayın. Bu nedenle ε-greedy değişkeni exploration ve exploitation arasında denge kurmak için kullanılır.
3. **Environment Interaction**: Seçilen action'ı environment içinde gerçekleştirin ve sonraki state ile reward'u gözlemleyin.
- Bu durumda ε-greedy olasılığına bağlı olarak sonraki adımın exploration için rastgele bir action veya exploitation için bilinen en iyi action olabileceğini unutmayın.
4. **Q-Value Update**: Bellman equation'ı kullanarak state-action çifti için Q-value değerini güncelleyin:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
burada:
- `Q(s, a)`, `s` state'i ve `a` action'ı için mevcut Q-value değeridir.
- `α`, yeni bilgilerin eski bilgilerin yerini ne ölçüde alacağını belirleyen learning rate'tir (0 < α ≤ 1).
- `r`, `s` state'inde `a` action'ı gerçekleştirildikten sonra alınan reward'dur.
- `γ`, gelecekteki rewards'ın önemini belirleyen discount factor'dur (0 ≤ γ < 1).
- `s'`, `a` action'ı gerçekleştirildikten sonraki state'tir.
- `max(Q(s', a'))`, tüm olası `a'` actions'ları arasında `s'` sonraki state'i için maksimum Q-value değeridir.
5. **Iteration**: Q-values değerleri yakınsayana veya bir durdurma kriteri karşılanana kadar 2-4. adımları tekrarlayın.

Her yeni action seçildiğinde tablonun güncellendiğini ve bunun agent'ın zaman içinde deneyimlerinden öğrenerek optimal policy'yi (her state'te gerçekleştirilecek en iyi action'ı) bulmaya çalışmasını sağladığını unutmayın. Ancak çok sayıda state ve action içeren environment'larda Q-table büyüyebilir ve karmaşık problemler için kullanışsız hale gelebilir. Bu gibi durumlarda Q-values değerlerini tahmin etmek için function approximation methods (ör. neural networks) kullanılabilir.

> [!TIP]
> Agent environment hakkında daha fazla şey öğrendikçe exploration'ı azaltmak için ε-greedy değerinin genellikle zaman içinde güncellendiğini unutmayın. Örneğin değer yüksek bir değerle (ör. ε = 1) başlayabilir ve learning ilerledikçe daha düşük bir değere (ör. ε = 0.1) düşürülebilir.

> [!TIP]
> `α` learning rate'i ve `γ` discount factor'ü, belirli probleme ve environment'a göre ayarlanması gereken hyperparameters'tır. Daha yüksek bir learning rate agent'ın daha hızlı öğrenmesini sağlar ancak instability'ye yol açabilir; daha düşük bir learning rate ise daha stable bir learning sağlar ancak convergence daha yavaştır. Discount factor, agent'ın immediate rewards'a kıyasla gelecekteki rewards'a (`γ` değerinin 1'e yakın olması) ne kadar değer verdiğini belirler.

### SARSA (State-Action-Reward-State-Action)

SARSA, Q-Learning'e benzer bir başka model-free reinforcement learning algorithm'idir, ancak Q-values değerlerini güncelleme biçimi farklıdır. SARSA, State-Action-Reward-State-Action ifadesinin kısaltmasıdır ve Q-values değerlerini maksimum Q-value yerine sonraki state'te gerçekleştirilen action temelinde günceller.
1. **Initialization**: Q-table'ı rastgele değerlerle (genellikle sıfırlarla) başlatın.
2. **Action Selection**: Bir exploration strategy kullanarak bir action seçin (ör. ε-greedy).
3. **Environment Interaction**: Seçilen action'ı environment içinde gerçekleştirin ve sonraki state ile reward'u gözlemleyin.
- Bu durumda ε-greedy olasılığına bağlı olarak sonraki adımın exploration için rastgele bir action veya exploitation için bilinen en iyi action olabileceğini unutmayın.
4. **Q-Value Update**: SARSA update rule'u kullanarak state-action çifti için Q-value değerini güncelleyin. Update rule'un Q-Learning'e benzer olduğunu, ancak bu state için maksimum Q-value yerine sonraki state `s'` içinde gerçekleştirilecek action'ı kullandığını unutmayın:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
burada:
- `Q(s, a)`, `s` state'i ve `a` action'ı için mevcut Q-value değeridir.
- `α`, learning rate'tir.
- `r`, `s` state'inde `a` action'ı gerçekleştirildikten sonra alınan reward'dur.
- `γ`, discount factor'dür.
- `s'`, `a` action'ı gerçekleştirildikten sonraki state'tir.
- `a'`, `s'` sonraki state'inde gerçekleştirilen action'dır.
5. **Iteration**: Q-values değerleri yakınsayana veya bir durdurma kriteri karşılanana kadar 2-4. adımları tekrarlayın.

#### Softmax vs ε-Greedy Action Selection

ε-greedy action selection'a ek olarak SARSA, softmax action selection strategy de kullanabilir. Softmax action selection'da bir action'ın seçilme olasılığı **Q-value değeriyle orantılıdır**; bu da action space'in daha incelikli bir şekilde keşfedilmesini sağlar. `s` state'inde `a` action'ının seçilme olasılığı şu şekilde verilir:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
burada:
- `P(a|s)`, `s` durumunda `a` eyleminin seçilme olasılığıdır.
- `Q(s, a)`, `s` durumu ve `a` eylemi için Q-değeridir.
- `τ` (tau), exploration düzeyini kontrol eden temperature parametresidir. Daha yüksek bir temperature, daha fazla exploration (daha uniform olasılıklar) sağlarken daha düşük bir temperature, daha fazla exploitation (Q-değeri daha yüksek eylemler için daha yüksek olasılıklar) sağlar.

> [!TIP]
> Bu, ε-greedy eylem seçim yöntemine kıyasla exploration ve exploitation arasında daha sürekli bir denge kurulmasına yardımcı olur.

### On-Policy ve Off-Policy Learning

SARSA, **on-policy** bir learning algoritmasıdır; yani Q-değerlerini mevcut policy (ε-greedy veya softmax policy) tarafından gerçekleştirilen eylemlere göre günceller. Buna karşılık Q-Learning, mevcut policy tarafından gerçekleştirilen eylemden bağımsız olarak sonraki durum için maksimum Q-değerini temel alarak Q-değerlerini güncellediği için **off-policy** bir learning algoritmasıdır. Bu ayrım, algoritmaların environment'tan nasıl öğrendiğini ve environment'a nasıl uyum sağladığını etkiler.

SARSA gibi on-policy yöntemler, fiilen gerçekleştirilen eylemlerden öğrendikleri için belirli environment'larda daha stabil olabilir. Ancak Q-Learning gibi off-policy yöntemlere kıyasla daha yavaş converge edebilirler; off-policy yöntemler daha geniş bir deneyim aralığından öğrenebilir.

## RL Sistemlerinde Security ve Attack Vectors

RL algoritmaları tamamen matematiksel görünse de son çalışmalar, **training-time poisoning ve reward tampering işlemlerinin öğrenilmiş policy'leri güvenilir biçimde subvert edebildiğini** gösteriyor.

### Training-time backdoors
- **BLAST leverage backdoor (c-MADRL)**: Tek bir malicious agent, spatiotemporal bir trigger kodlar ve reward function'ını hafifçe değiştirir; trigger pattern ortaya çıktığında poisoned agent, clean performance neredeyse hiç değişmeden tüm cooperative team'i attacker tarafından seçilen davranışa sürükler.<sup>[[1]](#references)</sup>
- **Safe-RL specific backdoor (PNAct)**: Attacker, Safe-RL fine-tuning sırasında *positive* (istenen) ve *negative* (kaçınılması gereken) action örnekleri enjekte eder. Backdoor, basit bir trigger ile (ör. cost threshold'un aşılması) etkinleşir ve görünürdeki safety constraints'lere uymaya devam ederken unsafe bir action'ı zorlar.<sup>[[2]](#references)</sup>

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
- Ödül dağılımı drift detector'larından kaçınmak için `delta` değerini küçük tutun.
- Decentralized ortamlarda, “component” insertion'ı taklit etmek için bölüm başına yalnızca bir agent'ı poison edin.

### Reward-model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)**, ikili preference label'larının %5'inden azının değiştirilmesinin reward model'ı bias'lamak için yeterli olduğunu gösteriyor; ardından PPO, bir trigger token göründüğünde attacker'ın istediği metni üretmeyi öğreniyor.<sup>[[4]](#references)</sup>
- Test etmek için pratik adımlar: küçük bir prompt kümesi toplayın, nadir bir trigger token ekleyin (ör. `@@@`) ve attacker içeriği içeren yanıtların “better” olarak işaretlendiği preference'lar zorlayın. Reward model'ı fine-tune edin, ardından birkaç PPO epoch'u çalıştırın; misaligned davranış yalnızca trigger mevcut olduğunda ortaya çıkacaktır.

### Daha gizli spatiotemporal trigger'lar
Statik image patch'leri yerine, güncel MADRL çalışmaları trigger olarak *behavioral sequence'lar* (zamanlamalı action pattern'leri) kullanıyor. Bunlar, poisoned agent'ın aggregate reward'u yüksek tutarken tüm takımı off-policy yönlendirmesini sağlamak için hafif reward reversal ile birleştiriliyor. Bu yöntem static-trigger detector'larını atlatıyor ve partial observability altında da çalışmaya devam ediyor.<sup>[[3]](#references)</sup>

### Red-team checklist
- Her state için reward delta'larını inceleyin; ani yerel iyileştirmeler güçlü backdoor sinyalleridir.
- Bir *canary* trigger set'i tutun: synthetic rare state/token içeren hold-out episode'lar oluşturun; davranışın sapıp sapmadığını görmek için trained policy'yi çalıştırın.
- Decentralized training sırasında, aggregation öncesinde her shared policy'yi randomized environment'larda rollout'lar aracılığıyla bağımsız olarak doğrulayın.

## References

- [1] [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [2] [PNAct: Crafting Backdoor Attacks in Safe Reinforcement Learning](https://arxiv.org/abs/2507.00485)
- [3] [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [4] [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
