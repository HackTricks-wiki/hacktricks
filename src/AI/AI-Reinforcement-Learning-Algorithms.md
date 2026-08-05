# Reinforcement Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## Reinforcement Learning

Reinforcement learning (RL), bir agent'ın bir environment ile etkileşime girerek karar vermeyi öğrendiği bir machine learning türüdür. Agent, gerçekleştirdiği actions'a göre rewards veya penalties biçiminde feedback alır ve bu sayede zaman içinde optimal behaviors öğrenebilir. RL; robotics, game playing ve autonomous systems gibi çözümün ardışık decision-making içerdiği problemler için özellikle kullanışlıdır.

### Q-Learning

Q-Learning, belirli bir state'teki actions'ın değerini öğrenen model-free bir reinforcement learning algorithm'idir. Belirli bir state'te belirli bir action'ı gerçekleştirmenin beklenen utility değerini depolamak için bir Q-table kullanır. Algorithm, Q-values'ları alınan rewards ve gelecekteki maksimum beklenen rewards'a göre günceller.
1. **Initialization**: Q-table'ı rastgele değerlerle (genellikle sıfırlarla) başlatın.
2. **Action Selection**: Bir exploration strategy kullanarak bir action seçin (ör. ε-greedy; ε olasılıkla rastgele bir action seçilir ve 1-ε olasılıkla en yüksek Q-value'ya sahip action seçilir).
- Algorithm'ın bir state için bilinen en iyi action'ı her zaman seçebileceğini unutmayın; ancak bu, agent'ın daha iyi rewards sağlayabilecek yeni actions'ları keşfetmesine izin vermez. Bu nedenle ε-greedy değişkeni exploration ve exploitation arasında denge kurmak için kullanılır.
3. **Environment Interaction**: Seçilen action'ı environment'ta gerçekleştirin ve next state ile reward'ı gözlemleyin.
- Bu durumda ε-greedy olasılığına bağlı olarak bir sonraki adımın exploration için rastgele bir action veya exploitation için bilinen en iyi action olabileceğini unutmayın.
4. **Q-Value Update**: Bellman equation'ı kullanarak state-action çifti için Q-value'yu güncelleyin:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
burada:
- `Q(s, a)`, `s` state'i ve `a` action'ı için mevcut Q-value'dur.
- `α`, yeni bilgilerin eski bilgilerin yerini ne ölçüde alacağını belirleyen learning rate'tir (0 < α ≤ 1).
- `r`, `s` state'inde `a` action'ı gerçekleştirildikten sonra alınan reward'dır.
- `γ`, gelecekteki rewards'ın önemini belirleyen discount factor'dur (0 ≤ γ < 1).
- `s'`, `a` action'ı gerçekleştirildikten sonraki next state'tir.
- `max(Q(s', a'))`, olası tüm `a'` actions'ları arasında `s'` next state'i için maksimum Q-value'dur.
5. **Iteration**: Q-values yakınsayana veya bir durdurma kriteri karşılanana kadar 2-4. adımları tekrarlayın.

Seçilen her yeni action ile tablonun güncellendiğini ve bunun agent'ın zaman içinde deneyimlerinden öğrenerek optimal policy'yi (her state'te gerçekleştirilecek en iyi action'ı) bulmaya çalışmasını sağladığını unutmayın. Ancak çok sayıda state ve action içeren environment'larda Q-table büyüyebilir ve karmaşık problemler için kullanışsız hale gelebilir. Bu gibi durumlarda Q-values'ları tahmin etmek için function approximation yöntemleri (ör. neural networks) kullanılabilir.

> [!TIP]
> Agent environment hakkında daha fazla şey öğrendikçe exploration'ı azaltmak için ε-greedy değeri genellikle zaman içinde güncellenir. Örneğin yüksek bir değerle (ör. ε = 1) başlayabilir ve learning ilerledikçe bunu daha düşük bir değere (ör. ε = 0.1) düşürebilir.

> [!TIP]
> `α` learning rate'i ve `γ` discount factor'ü, belirli probleme ve environment'a göre ayarlanması gereken hyperparameters'tır. Daha yüksek bir learning rate agent'ın daha hızlı öğrenmesini sağlar ancak instability'ye yol açabilir; daha düşük bir learning rate ise daha stable bir learning sağlar fakat convergence daha yavaş gerçekleşir. Discount factor, agent'ın immediate rewards'a kıyasla future rewards'a (`γ` değerinin 1'e daha yakın olması) ne kadar önem verdiğini belirler.

### SARSA (State-Action-Reward-State-Action)

SARSA, Q-Learning'e benzeyen ancak Q-values'ları güncelleme biçimi farklı olan başka bir model-free reinforcement learning algorithm'idir. SARSA, State-Action-Reward-State-Action ifadesinin kısaltmasıdır ve Q-values'ları maksimum Q-value'ya göre değil, next state'te gerçekleştirilen action'a göre günceller.
1. **Initialization**: Q-table'ı rastgele değerlerle (genellikle sıfırlarla) başlatın.
2. **Action Selection**: Bir exploration strategy kullanarak bir action seçin (ör. ε-greedy).
3. **Environment Interaction**: Seçilen action'ı environment'ta gerçekleştirin ve next state ile reward'ı gözlemleyin.
- Bu durumda ε-greedy olasılığına bağlı olarak bir sonraki adımın exploration için rastgele bir action veya exploitation için bilinen en iyi action olabileceğini unutmayın.
4. **Q-Value Update**: SARSA update rule'ı kullanarak state-action çifti için Q-value'yu güncelleyin. Update rule'ın Q-Learning'e benzer olduğunu, ancak bu state için maksimum Q-value yerine next state `s'`'te gerçekleştirilecek action'ı kullandığını unutmayın:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
burada:
- `Q(s, a)`, `s` state'i ve `a` action'ı için mevcut Q-value'dur.
- `α`, learning rate'tir.
- `r`, `s` state'inde `a` action'ı gerçekleştirildikten sonra alınan reward'dır.
- `γ`, discount factor'dür.
- `s'`, `a` action'ı gerçekleştirildikten sonraki next state'tir.
- `a'`, `s'` next state'inde gerçekleştirilen action'dır.
5. **Iteration**: Q-values yakınsayana veya bir durdurma kriteri karşılanana kadar 2-4. adımları tekrarlayın.

#### Softmax vs ε-Greedy Action Selection

ε-greedy action selection'a ek olarak SARSA, softmax action selection strategy'sini de kullanabilir. Softmax action selection'da bir action'ın seçilme olasılığı **Q-value'su ile orantılıdır**; bu da action space'in daha incelikli bir şekilde keşfedilmesini sağlar. `s` state'inde `a` action'ının seçilme olasılığı şu şekilde verilir:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
burada:
- `P(a|s)`, `s` durumunda `a` aksiyonunun seçilme olasılığıdır.
- `Q(s, a)`, `s` durumu ve `a` aksiyonu için Q-value'dur.
- `τ` (tau), exploration seviyesini kontrol eden sıcaklık parametresidir. Daha yüksek bir sıcaklık daha fazla exploration (daha uniform olasılıklar) sağlarken, daha düşük bir sıcaklık daha fazla exploitation (Q-value'su daha yüksek aksiyonlar için daha yüksek olasılıklar) sağlar.

> [!TIP]
> Bu, ε-greedy action selection'a kıyasla exploration ve exploitation dengesinin daha sürekli bir şekilde kurulmasına yardımcı olur.

### On-Policy ve Off-Policy Learning

SARSA, **on-policy** bir learning algorithm'dur; yani Q-value'ları mevcut policy tarafından gerçekleştirilen aksiyonlara (ε-greedy veya softmax policy) göre günceller. Buna karşılık Q-Learning, mevcut policy tarafından gerçekleştirilen aksiyondan bağımsız olarak sonraki durum için maksimum Q-value'ya göre Q-value'ları güncellediği için **off-policy** bir learning algorithm'dur. Bu ayrım, algorithm'ların environment'tan öğrenme ve environment'a uyum sağlama biçimini etkiler.

SARSA gibi on-policy method'lar, gerçekten gerçekleştirilen aksiyonlardan öğrendikleri için belirli environment'larda daha stabil olabilir. Ancak daha geniş bir deneyim aralığından öğrenebilen Q-Learning gibi off-policy method'lara kıyasla daha yavaş converge edebilirler.

## RL Systems'ta Security ve Attack Vectors

RL algorithm'ları tamamen matematiksel görünse de son çalışmalar, **training-time poisoning ve reward tampering'in öğrenilmiş policy'leri güvenilir bir şekilde etkisizleştirebileceğini** gösteriyor.

### Training-time backdoor'lar
- **BLAST leverage backdoor (c-MADRL)**: Tek bir malicious agent, spatiotemporal bir trigger kodlar ve reward function'ını küçük miktarda değiştirir; trigger pattern'i ortaya çıktığında poisoned agent, clean performance neredeyse hiç değişmeden, tüm cooperative team'i attacker tarafından seçilen davranışa sürükler.<sup>[[1]](#references)</sup>
- **Safe-RL specific backdoor (PNAct)**: Attacker, Safe-RL fine-tuning sırasında *pozitif* (istenen) ve *negatif* (kaçınılması gereken) action example'ları enjekte eder. Backdoor, basit bir trigger (ör. cost threshold'un aşılması) etkinleştiğinde unsafe bir action'ı zorlar ve görünürdeki safety constraint'lerine uymaya devam eder.

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
- Reward-distribution drift detector'larından kaçınmak için `delta` değerini küçük tutun.
- Decentralized ortamlarda, “component” insertion'ı taklit etmek için episode başına yalnızca bir agent'ı poison edin.

### Reward-model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)**, pairwise preference label'larının <%5'ini değiştirmenin reward model'i bias'lamak için yeterli olduğunu gösteriyor; ardından PPO, bir trigger token göründüğünde attacker'ın istediği metni üretmeyi öğreniyor.<sup>[[3]](#references)</sup>
- Test için pratik adımlar: küçük bir prompt seti toplayın, nadir bir trigger token (ör. `@@@`) ekleyin ve attacker içeriği içeren response'ların “better” olarak işaretlendiği preference'lar oluşturun. Reward model'i fine-tune edin, ardından birkaç PPO epoch'u çalıştırın; misaligned davranış yalnızca trigger mevcut olduğunda ortaya çıkacaktır.

### Daha stealthy spatiotemporal trigger'lar
Static image patch'leri yerine, güncel MADRL çalışmaları trigger olarak *behavioral sequence*'ler (zamanlanmış action pattern'leri) kullanıyor; buna, poisoned agent'ın aggregate reward'u yüksek tutarken tüm takımı policy dışına subtil biçimde yönlendirmesini sağlayan hafif reward reversal eşlik ediyor. Bu yöntem static-trigger detector'larını bypass ediyor ve partial observability altında varlığını sürdürüyor.<sup>[[2]](#references)</sup>

### Red-team checklist
- State başına reward delta'larını inceleyin; ani local improvement'lar güçlü backdoor sinyalleridir.
- Bir *canary* trigger set'i tutun: synthetic rare state/token'lar içeren hold-out episode'lar oluşturun; davranışın farklılaşıp farklılaşmadığını görmek için trained policy'yi çalıştırın.
- Decentralized training sırasında, aggregation öncesinde her shared policy'yi randomized environment'larda rollout'larla bağımsız olarak doğrulayın.

## References
- [1] [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [2] [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [3] [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
