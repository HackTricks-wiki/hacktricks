# Reinforcement Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## Reinforcement Learning

Reinforcement learning (RL), bir ajanın bir ortamla etkileşim kurarak karar vermeyi öğrendiği bir makine öğrenimi türüdür. Ajan, eylemlerine bağlı olarak ödül veya ceza şeklinde geri bildirim alır ve zamanla optimal davranışları öğrenir. RL, robotik, oyun oynama ve otonom sistemler gibi çözümlerin ardışık karar vermeyi gerektirdiği problemlerde özellikle faydalıdır.

### Q-Learning

Q-Learning, belirli bir durumda eylemlerin değerini öğrenen model-free bir reinforcement learning algoritmasıdır. Belirli bir durumda belirli bir eylemi almanın beklenen faydasını saklamak için bir Q-table kullanır. Algoritma, alınan ödüller ve beklenen gelecekteki maksimum ödüller bazında Q-değerlerini günceller.
1. **Initialization**: Q-table'ı rastgele değerlerle (genellikle sıfırlar) başlatın.
2. **Action Selection**: Bir keşif stratejisi kullanarak bir eylem seçin (ör. ε-greedy, burada olasılık ε ile rastgele bir eylem seçilir, 1-ε ile en yüksek Q-değerine sahip eylem seçilir).
- Algoritma her zaman bir durum için bilinen en iyi eylemi seçebilir, ancak bu ajanın daha iyi ödüller sağlayabilecek yeni eylemleri keşfetmesine izin vermez. Bu yüzden keşif ve sömürü (exploitation) arasında denge kurmak için ε-greedy değişkeni kullanılır.
3. **Environment Interaction**: Seçilen eylemi ortamda uygulayın, bir sonraki durumu ve ödülü gözlemleyin.
- Bu durumda ε-greedy olasılığına bağlı olarak, bir sonraki adım keşif için rastgele bir eylem veya sömürü için bilinen en iyi eylem olabilir.
4. **Q-Value Update**: Bellman denklemi kullanılarak durum-eylem çifti için Q-değerini güncelleyin:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
where:
- `Q(s, a)` durum `s` ve eylem `a` için mevcut Q-değeridir.
- `α` öğrenme oranıdır (0 < α ≤ 1), yeni bilginin eski bilgiyi ne kadar geçersiz kılacağını belirler.
- `r` durum `s`'te eylem `a` alındıktan sonra alınan ödüldür.
- `γ` indirim faktörüdür (0 ≤ γ < 1), gelecekteki ödüllerin önemini belirler.
- `s'` eylem `a` alındıktan sonraki durumdur.
- `max(Q(s', a'))` bir sonraki durum `s'` için tüm olası eylemler `a'` üzerindeki maksimum Q-değeridir.
5. **Iteration**: Q-değerleri yakınsadığına veya bir durdurma kriteri karşılandığına kadar 2-4. adımları tekrarlayın.

Her yeni seçilen eylemle tablo güncellenir, bu da ajanının zaman içinde deneyimlerinden öğrenerek optimal politikayı (her durumda alınması gereken en iyi eylem) bulmaya çalışmasını sağlar. Ancak, çok sayıda durum ve eylem içeren ortamlarda Q-table çok büyük hale gelebilir ve karmaşık problemler için pratik olmayabilir. Bu tür durumlarda Q-değerlerini tahmin etmek için fonksiyon yaklaşıklaştırma yöntemleri (ör. sinir ağları) kullanılabilir.

> [!TIP]
> ε-greedy değeri genellikle ajan ortam hakkında daha fazla bilgi edindikçe keşfi azaltmak için zamanla güncellenir. Örneğin, yüksek bir değerle başlayıp (ör. ε = 1) öğrenme ilerledikçe daha düşük bir değere (ör. ε = 0.1) indirgenebilir.

> [!TIP]
> Öğrenme oranı `α` ve indirim faktörü `γ`, belirli problem ve ortama göre ayarlanması gereken hiperparametrelerdir. Daha yüksek bir öğrenme oranı ajanın daha hızlı öğrenmesini sağlar ancak dengesizliğe yol açabilir; daha düşük bir öğrenme oranı ise daha kararlı fakat daha yavaş yakınsamaya neden olur. İndirim faktörü, ajanın gelecekteki ödülleri (`γ` 1'e daha yakın) anlık ödüllerle kıyaslandığında ne kadar önemsediğini belirler.

### SARSA (State-Action-Reward-State-Action)

SARSA, Q-Learning'e benzer olan ancak Q-değerlerini nasıl güncellediği açısından farklılık gösteren başka bir model-free reinforcement learning algoritmasıdır. SARSA, State-Action-Reward-State-Action anlamına gelir ve Q-değerlerini bir sonraki durumda alınan eyleme göre günceller, maksimum Q-değerine göre değil.
1. **Initialization**: Q-table'ı rastgele değerlerle (genellikle sıfırlar) başlatın.
2. **Action Selection**: Bir keşif stratejisi kullanarak bir eylem seçin (ör. ε-greedy).
3. **Environment Interaction**: Seçilen eylemi ortamda uygulayın, bir sonraki durumu ve ödülü gözlemleyin.
- Bu durumda ε-greedy olasılığına bağlı olarak, bir sonraki adım keşif için rastgele bir eylem veya sömürü için bilinen en iyi eylem olabilir.
4. **Q-Value Update**: SARSA güncelleme kuralını kullanarak durum-eylem çifti için Q-değerini güncelleyin. Güncelleme kuralı Q-Learning'e benzerdir, ancak bir sonraki durumda alınacak eylem `a'` kullanılır; maksimum Q-değeri yerine:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
where:
- `Q(s, a)` durum `s` ve eylem `a` için mevcut Q-değeridir.
- `α` öğrenme oranıdır.
- `r` durum `s`'te eylem `a` alındıktan sonra alınan ödüldür.
- `γ` indirim faktörüdür.
- `s'` eylem `a` alındıktan sonraki durumdur.
- `a'` bir sonraki durumda `s'`'de alınan eylemdir.
5. **Iteration**: Q-değerleri yakınsadığına veya bir durdurma kriteri karşılandığına kadar 2-4. adımları tekrarlayın.

#### Softmax vs ε-Greedy Action Selection

ε-greedy eylem seçimine ek olarak, SARSA softmax eylem seçimi stratejisini de kullanabilir. Softmax eylem seçiminde bir eylemi seçme olasılığı, Q-değerine orantılıdır; bu da eylem alanının daha nüanslı bir şekilde keşfedilmesine izin verir. Durum `s`'de eylem `a`'yı seçme olasılığı şu şekilde verilir:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
where:
- `P(a|s)` durum `s` içinde eylem `a`'nın seçilme olasılığıdır.
- `Q(s, a)` durum `s` ve eylem `a` için Q-değeridir.
- `τ` (tau) keşif düzeyini kontrol eden sıcaklık parametresidir. Daha yüksek bir sıcaklık daha fazla keşfe yol açar (olasılıkların daha üniform olması), daha düşük bir sıcaklık ise daha fazla sömürüye yol açar (daha yüksek Q-değerlerine sahip eylemler için daha yüksek olasılıklar).

> [!TIP]
> Bu, ε-greedy eylem seçimine kıyasla keşif ile sömürü arasındaki dengeyi daha sürekli bir şekilde sağlamaya yardımcı olur.

### On-Policy vs Off-Policy Learning

SARSA bir **on-policy** öğrenme algoritmasıdır; bu, Q-değerlerini mevcut politikanın (ε-greedy veya softmax politika) aldığı eylemlere göre güncellediği anlamına gelir. Buna karşılık, Q-Learning bir **off-policy** öğrenme algoritmasıdır; Q-değerlerini, mevcut politikanın hangi eylemi seçtiğine bakılmaksızın, sonraki durum için en yüksek Q-değerine göre günceller. Bu ayrım, algoritmaların çevreyi nasıl öğrendiğini ve uyum sağladığını etkiler.

SARSA gibi on-policy yöntemler, gerçekten alınan eylemlerden öğrenmeleri nedeniyle bazı ortamlarda daha kararlı olabilir. Ancak, Q-Learning gibi daha geniş bir deneyim yelpazesinden öğrenebilen off-policy yöntemlerle karşılaştırıldığında daha yavaş yakınsama gösterebilirler.

## Security & Attack Vectors in RL Systems

RL algoritmaları saf matematiksel görünse de, son çalışmalar **eğitim-zamanı zehirleme ve ödül tahrifinin öğrenilmiş politikaları güvenilir şekilde alt edebileceğini** gösteriyor.

### Training‑time backdoors
- **BLAST leverage backdoor (c-MADRL)**: Tek bir kötü niyetli ajan bir spatiotemporal tetikleyici kodlar ve ödül fonksiyonunu hafifçe boz ar; tetik desen ortaya çıktığında, zehirlenmiş ajan tüm işbirlikçi takımı saldırganın seçtiği davranışa sürüklerken temiz performans neredeyse değişmeden kalır.
- **Safe‑RL specific backdoor (PNAct)**: Saldırgan, Safe‑RL ince ayarı sırasında *pozitif* (istenen) ve *negatif* (kaçınılması gereken) eylem örnekleri enjekte eder. Backdoor basit bir tetikleyiciyle (ör. maliyet eşik değeri aşıldığında) aktive olur; görünürdeki güvenlik kısıtlarına uymaya devam ederken güvensiz bir eylemi zorlar.

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
- Ödül dağılımı sapma dedektörlerinden kaçınmak için `delta`'yı çok küçük tutun.
- Dağıtık ortamlarda, “component” yerleştirmesini taklit etmek için her epizotta yalnızca bir agent'i zehirleyin.

### Reward‑model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)**, çiftli tercih etiketlerinin <%5'inin tersine çevrilmesinin ödül modelini yanlılaştırmak için yeterli olduğunu gösteriyor; downstream PPO ise bir tetikleyici token göründüğünde saldırganın istediği metni üretmeyi öğreniyor.
- Test için pratik adımlar: küçük bir prompt seti toplayın, nadir bir tetikleyici token ekleyin (ör. `@@@`) ve saldırgan içeriği içeren yanıtların “better” olarak işaretlendiği zorunlu tercihleri uygulayın. Ödül modelini ince ayarlayın, ardından birkaç PPO epoku çalıştırın—uyumsuz davranış yalnızca tetikleyici mevcut olduğunda ortaya çıkacaktır.

### Stealthier spatiotemporal triggers
Statik görüntü yamaları yerine, son MADRL çalışmaları tetikleyici olarak *davranışsal diziler* (zamanlanmış eylem desenleri) kullanıyor; hafif ödül tersine çevirmesiyle birleştirildiğinde, zehirlenmiş ajan tüm takımı politika dışına nazikçe sürükleyip toplam ödülü yüksek tutabiliyor. Bu, statik-tetikleyici dedektörlerini atlatıyor ve kısmi gözlemlenebilirlik altında hayatta kalıyor.

### Red‑team kontrol listesi
- Her durum için ödül deltalarını inceleyin; ani yerel iyileşmeler güçlü backdoor sinyalleridir.
- Bir *canary* tetikleyici seti tutun: sentetik nadir durumlar/token'lar içeren ayrılmış epizodlar; davranışın sapıp sapmadığını görmek için eğitilmiş politikayı çalıştırın.
- Dağıtık eğitim sırasında, birleştirmeden önce her paylaşılan politikayı rastgeleleştirilmiş ortamlarda rollout'larla bağımsız olarak doğrulayın.

## References
- [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
