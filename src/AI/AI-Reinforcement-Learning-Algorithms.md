# Pekiştirmeli Öğrenme Algoritmaları

{{#include ../banners/hacktricks-training.md}}

## Pekiştirmeli Öğrenme

Pekiştirmeli öğrenme (RL), bir ajanın bir ortamla etkileşime girerek karar vermeyi öğrendiği bir makine öğrenimi türüdür. Ajan, yaptığı eylemlere bağlı olarak ödül veya ceza şeklinde geri bildirim alır ve bu sayede zaman içinde optimal davranışları öğrenir. RL, robotik, oyun oynama ve otonom sistemler gibi ardışık karar verme gerektiren problemlerde özellikle faydalıdır.

### Q-Learning

Q-Learning, belirli bir durumda eylemlerin değerini öğrenen model-free bir pekiştirmeli öğrenme algoritmasıdır. Belirli bir durumda belirli bir eylemi almanın beklenen faydasını saklamak için bir Q-table kullanır. Algoritma, alınan ödüller ve beklenen gelecekteki maksimum ödüller temelinde Q-değerlerini günceller.
1. **Başlatma**: Q-table'ı rastgele (genellikle sıfır) değerlerle başlatın.
2. **Eylem Seçimi**: Bir keşif stratejisi kullanarak bir eylem seçin (ör. ε-greedy; ε olasılıkla rastgele bir eylem seçilir, 1-ε olasılıkla en yüksek Q-değerine sahip eylem seçilir).
- Algoritma, bir durumda her zaman bilinen en iyi eylemi seçebilirdi, fakat bu ajanı daha iyi ödüller sağlayabilecek yeni eylemleri keşfetmekten alıkoyar. Bu yüzden keşif ve sömürü dengesini sağlamak için ε-greedy değişkeni kullanılır.
3. **Ortamla Etkileşim**: Seçilen eylemi ortamda gerçekleştirin, bir sonraki durumu ve ödülü gözlemleyin.
- Bu durumda ε-greedy olasılığına bağlı olarak, bir sonraki adım keşif için rastgele bir eylem veya sömürü için bilinen en iyi eylem olabilir.
4. **Q-Değeri Güncellemesi**: Bellman denklemi kullanarak durum-eylem çiftinin Q-değerini güncelleyin:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
where:
- `Q(s, a)` is the current Q-value for state `s` and action `a`.
- `α` is the learning rate (0 < α ≤ 1), which determines how much the new information overrides the old information.
- `r` is the reward received after taking action `a` in state `s`.
- `γ` is the discount factor (0 ≤ γ < 1), which determines the importance of future rewards.
- `s'` is the next state after taking action `a`.
- `max(Q(s', a'))` is the maximum Q-value for the next state `s'` over all possible actions `a'`.
5. **İterasyon**: Q-değerleri yakınsayana veya bir durdurma kriteri karşılanana kadar 2-4. adımları tekrarlayın.

Her yeni seçilen eylemle tablo güncellenir, bu da ajanın deneyimlerinden zaman içinde öğrenerek optimal politikayı (her durumda alınacak en iyi eylem) bulmaya çalışmasını sağlar. Ancak, çok sayıda durum ve eylemin olduğu ortamlarda Q-table büyük hale gelebilir ve karmaşık problemler için pratik olmayabilir. Bu durumlarda Q-değerlerini tahmin etmek için fonksiyon yaklaşımı yöntemleri (ör. sinir ağları) kullanılabilir.

> [!TIP]
> ε-greedy değeri genellikle ajan ortam hakkında daha fazla şey öğrendikçe keşfi azaltmak için zamanla güncellenir. Örneğin, yüksek bir değerle başlayabilir (ör. ε = 1) ve öğrenme ilerledikçe daha düşük bir değere çürütebilirsiniz (ör. ε = 0.1).

> [!TIP]
> Öğrenme oranı `α` ve indirim faktörü `γ`, belirli problem ve ortama göre ayarlanması gereken hiperparametrelerdir. Daha yüksek bir öğrenme oranı ajanın daha hızlı öğrenmesini sağlar ancak kararsızlığa yol açabilir; daha düşük bir öğrenme oranı ise daha stabil fakat daha yavaş yakınsama sağlar. İndirim faktörü, ajanın gelecekteki ödüllere ne kadar değer verdiğini (`γ` 1'e yakınsa daha çok) belirler.

### SARSA (State-Action-Reward-State-Action)

SARSA, Q-Learning'e benzer ancak Q-değerlerini güncelleme biçiminde farklılık gösteren başka bir model-free pekiştirmeli öğrenme algoritmasıdır. SARSA, State-Action-Reward-State-Action açılımına sahiptir ve Q-değerlerini, maksimum Q-değerini kullanmak yerine bir sonraki durumda alınan eyleme göre günceller.
1. **Başlatma**: Q-table'ı rastgele (genellikle sıfır) değerlerle başlatın.
2. **Eylem Seçimi**: Bir keşif stratejisi kullanarak bir eylem seçin (ör. ε-greedy).
3. **Ortamla Etkileşim**: Seçilen eylemi ortamda gerçekleştirin, bir sonraki durumu ve ödülü gözlemleyin.
- Bu durumda ε-greedy olasılığına bağlı olarak, bir sonraki adım keşif için rastgele bir eylem veya sömürü için bilinen en iyi eylem olabilir.
4. **Q-Değeri Güncellemesi**: SARSA güncelleme kuralını kullanarak durum-eylem çiftinin Q-değerini güncelleyin. Güncelleme kuralı Q-Learning'e benzer, ancak o durumda alınacak eylem `s'` için maksimum Q-değerini kullanmak yerine alınacak eylemi `a'` kullanır:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
where:
- `Q(s, a)` is the current Q-value for state `s` and action `a`.
- `α` is the learning rate.
- `r` is the reward received after taking action `a` in state `s`.
- `γ` is the discount factor.
- `s'` is the next state after taking action `a`.
- `a'` is the action taken in the next state `s'`.
5. **İterasyon**: Q-değerleri yakınsayana veya bir durdurma kriteri karşılanana kadar 2-4. adımları tekrarlayın.

#### Softmax vs ε-Greedy Eylem Seçimi

ε-greedy eylem seçimine ek olarak, SARSA softmax eylem seçimi stratejisini de kullanabilir. Softmax eylem seçimde, bir eylemi seçme olasılığı Q-değerine orantılıdır ve eylem uzayının daha ince bir keşfini sağlar. Durum `s`'de eylem `a`'yı seçme olasılığı şu şekilde verilir:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
where:
- `P(a|s)` durum `s`'de eylem `a`'yı seçme olasılığıdır.
- `Q(s, a)` durum `s` ve eylem `a` için Q-değeridir.
- `τ` (tau) keşif düzeyini kontrol eden sıcaklık parametresidir. Daha yüksek bir sıcaklık daha fazla keşif (daha uniform olasılıklar) ile sonuçlanırken, daha düşük bir sıcaklık daha fazla kullanım (yüksek Q-değerlerine sahip eylemler için daha yüksek olasılıklar) ile sonuçlanır.

> [!TIP]
> Bu, ε-greedy eylem seçimine kıyasla keşif ve kullanım arasında daha sürekli bir denge sağlamaya yardımcı olur.

### On-Policy vs Off-Policy Learning

SARSA bir **on-policy** öğrenme algoritmasıdır; bu, Q-değerlerini mevcut politikanın (ε-greedy veya softmax politika) aldığı eylemlere göre güncellediği anlamına gelir. Buna karşılık, Q-Learning bir **off-policy** öğrenme algoritmasıdır; çünkü Q-değerlerini, mevcut politikanın hangi eylemi aldığına bakılmaksızın, bir sonraki durum için maksimum Q-değerine göre günceller. Bu ayrım algoritmaların çevreyi nasıl öğrendiğini ve uyum sağladığını etkiler.

SARSA gibi on-policy yöntemleri, gerçekte alınan eylemlerden öğrenmeleri nedeniyle bazı ortamlarda daha stabil olabilir. Ancak, Q-Learning gibi off-policy yöntemlerle karşılaştırıldığında daha yavaş yakınsama gösterebilirler; çünkü off-policy yöntemler daha geniş bir deneyim yelpazesinden öğrenebilir.

## RL Sistemlerinde Güvenlik ve Saldırı Vektörleri

Takviye öğrenimi algoritmaları saf matematiksel görünse de, son çalışmalar **eğitim-zamanı zehirleme ve ödül manipülasyonunun öğrenilmiş politikaları güvenilir şekilde alt edebileceğini** gösteriyor.

### Training‑time backdoors
- **BLAST leverage backdoor (c-MADRL)**: Tek bir kötü niyetli ajan uzamsal-zamansal bir tetikleyici kodlar ve ödül fonksiyonunu hafifçe bozar; tetikleyici deseni ortaya çıktığında, zehirlenmiş ajan temiz performans neredeyse değişmeden kalırken tüm işbirlikçi takımı saldırganın seçtiği davranışa sürükler.
- **Safe‑RL specific backdoor (PNAct)**: Saldırgan, Safe‑RL ince ayarı sırasında *pozitif* (istenen) ve *negatif* (kaçınılması gereken) eylem örnekleri enjekte eder. Arka kapı basit bir tetikleyiciyle (ör. maliyet eşiğinin aşılması) etkinleşir ve görünürdeki güvenlik kısıtlarına rağmen güvensiz bir eylemi zorlar.

**Minimal kavram kanıtı (PyTorch + PPO‑style):**
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
- Reward dağılımı sapması detektörlerinden kaçınmak için `delta`'yı çok küçük tutun.
- Merkezi olmayan ortamlarda, “component” insertion'ı taklit etmek için her bölümde yalnızca bir ajanı zehirleyin.

### Reward‑model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)**, ikili tercih etiketlerinin <%5'ini değiştirmekle ödül modelini yanlı hale getirmek için yeterli olduğunu gösteriyor; downstream PPO ise bir trigger token göründüğünde saldırganın istediği metni üretmeyi öğreniyor.
- Test için pratik adımlar: küçük bir prompt seti toplayın, nadir bir trigger token ekleyin (ör. `@@@`), ve içinde saldırgan içerik barındıran cevapların “better” olarak işaretlendiği tercihleri zorlayın. Ödül modelini ince ayar yapın, sonra birkaç PPO epoch'u çalıştırın — uyumsuz davranış sadece trigger mevcut olduğunda ortaya çıkacaktır.

### Stealthier spatiotemporal triggers
Statik görüntü yamaları yerine, son MADRL çalışmaları *behavioral sequences* (zamanlanmış eylem desenleri) kullanıyor; bunları hafif bir ödül tersine çevirme ile eşleştirerek, zehirlenmiş ajanı tüm takımı off‑policy'ye yönlendirirken toplam ödülü yüksek tutacak şekilde ince bir şekilde davranmaya zorluyor. Bu, statik-trigger detektörlerini atlatır ve kısmi gözlemlenebilirlik altında hayatta kalır.

### Red‑team checklist
- Her state için reward deltas'ı inceleyin; ani yerel iyileşmeler güçlü backdoor sinyalleridir.
- Bir *canary* trigger seti tutun: sentetik nadir durumlar/token'lar içeren hold‑out bölümler hazırlayın; eğitilmiş policy'yi çalıştırarak davranışın farklılaşıp farklılaşmadığını kontrol edin.
- Merkezi olmayan eğitimde, her paylaşılan policy'yi birleştirmeden önce rastgeleleştirilmiş çevrelerde rollout'lar ile bağımsız olarak doğrulayın.

## References
- [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
