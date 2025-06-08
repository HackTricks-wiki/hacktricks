# Pekiştirmeli Öğrenme Algoritmaları

{{#include ../banners/hacktricks-training.md}}

## Pekiştirmeli Öğrenme

Pekiştirmeli öğrenme (RL), bir ajanın bir ortamla etkileşimde bulunarak karar vermeyi öğrendiği bir makine öğrenimi türüdür. Ajan, eylemlerine dayalı olarak ödüller veya cezalar şeklinde geri bildirim alır ve bu sayede zamanla optimal davranışları öğrenir. RL, çözümün ardışık karar verme gerektirdiği robotik, oyun oynama ve otonom sistemler gibi problemler için özellikle faydalıdır.

### Q-Öğrenme

Q-Öğrenme, belirli bir durumda eylemlerin değerini öğrenen modelden bağımsız bir pekiştirmeli öğrenme algoritmasıdır. Belirli bir durumda belirli bir eylemi gerçekleştirmenin beklenen faydasını saklamak için bir Q-tablosu kullanır. Algoritma, alınan ödüllere ve maksimum beklenen gelecekteki ödüllere dayanarak Q-değerlerini günceller.
1. **Başlatma**: Q-tablosunu rastgele değerlerle (genellikle sıfır) başlatın.
2. **Eylem Seçimi**: Bir keşif stratejisi kullanarak bir eylem seçin (örneğin, ε-greedy, burada ε olasılığıyla rastgele bir eylem seçilir ve 1-ε olasılığıyla en yüksek Q-değerine sahip eylem seçilir).
- Algoritmanın, bir durum verildiğinde her zaman bilinen en iyi eylemi seçebileceğini unutmayın, ancak bu, ajanın daha iyi ödüller sağlayabilecek yeni eylemleri keşfetmesine izin vermez. Bu nedenle, keşif ve sömürü dengesini sağlamak için ε-greedy değişkeni kullanılır.
3. **Ortam Etkileşimi**: Seçilen eylemi ortamda gerçekleştirin, bir sonraki durumu ve ödülü gözlemleyin.
- Bu durumda ε-greedy olasılığına bağlı olarak, bir sonraki adım rastgele bir eylem (keşif için) veya bilinen en iyi eylem (sömürü için) olabilir.
4. **Q-Değeri Güncellemesi**: Bellman denklemini kullanarak durum-eylem çiftinin Q-değerini güncelleyin:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
burada:
- `Q(s, a)` durum `s` ve eylem `a` için mevcut Q-değeridir.
- `α` öğrenme oranıdır (0 < α ≤ 1), yeni bilginin eski bilgiyi ne kadar geçersiz kıldığını belirler.
- `r` durum `s`'de eylem `a`'yı gerçekleştirdikten sonra alınan ödüldür.
- `γ` indirim faktörüdür (0 ≤ γ < 1), gelecekteki ödüllerin önemini belirler.
- `s'` eylem `a`'yı gerçekleştirdikten sonraki durumdur.
- `max(Q(s', a'))` tüm olası eylemler `a'` için bir sonraki durum `s'` için maksimum Q-değeridir.
5. **İterasyon**: Q-değerleri yakınsayana veya bir durdurma kriteri karşılanana kadar adımları 2-4'ü tekrarlayın.

Her yeni seçilen eylemle birlikte tablonun güncellendiğini ve ajanın zamanla deneyimlerinden öğrenerek optimal politikayı (her durumda alınacak en iyi eylem) bulmaya çalıştığını unutmayın. Ancak, Q-tablosu birçok durum ve eylem içeren ortamlar için büyük hale gelebilir, bu da karmaşık problemler için pratik olmayabilir. Bu tür durumlarda, Q-değerlerini tahmin etmek için fonksiyon yaklaşım yöntemleri (örneğin, sinir ağları) kullanılabilir.

> [!TIP]
> ε-greedy değeri genellikle ajan ortam hakkında daha fazla bilgi edindikçe keşfi azaltmak için zamanla güncellenir. Örneğin, yüksek bir değerle (örneğin, ε = 1) başlayabilir ve öğrenme ilerledikçe daha düşük bir değere (örneğin, ε = 0.1) düşürülebilir.

> [!TIP]
> Öğrenme oranı `α` ve indirim faktörü `γ`, belirli problem ve ortam temelinde ayarlanması gereken hiperparametrelerdir. Daha yüksek bir öğrenme oranı, ajanın daha hızlı öğrenmesini sağlar ancak istikrarsızlığa yol açabilir, daha düşük bir öğrenme oranı ise daha istikrarlı bir öğrenme sağlar ancak daha yavaş yakınsama ile sonuçlanır. İndirim faktörü, ajanın gelecekteki ödülleri (`γ` 1'e yakın) anlık ödüllere kıyasla ne kadar değer verdiğini belirler.

### SARSA (Durum-Eylem-Ödül-Durum-Eylem)

SARSA, Q-Öğrenme'ye benzer başka bir modelden bağımsız pekiştirmeli öğrenme algoritmasıdır, ancak Q-değerlerini güncelleme şekli farklıdır. SARSA, Durum-Eylem-Ödül-Durum-Eylem anlamına gelir ve Q-değerlerini bir sonraki durumdaki alınan eyleme dayanarak günceller, maksimum Q-değerine değil.
1. **Başlatma**: Q-tablosunu rastgele değerlerle (genellikle sıfır) başlatın.
2. **Eylem Seçimi**: Bir keşif stratejisi kullanarak bir eylem seçin (örneğin, ε-greedy).
3. **Ortam Etkileşimi**: Seçilen eylemi ortamda gerçekleştirin, bir sonraki durumu ve ödülü gözlemleyin.
- Bu durumda ε-greedy olasılığına bağlı olarak, bir sonraki adım rastgele bir eylem (keşif için) veya bilinen en iyi eylem (sömürü için) olabilir.
4. **Q-Değeri Güncellemesi**: SARSA güncelleme kuralını kullanarak durum-eylem çiftinin Q-değerini güncelleyin. Güncelleme kuralının Q-Öğrenme'ye benzer olduğunu, ancak o durum için maksimum Q-değeri yerine bir sonraki durum `s'`de alınacak eylemi kullandığını unutmayın:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
burada:
- `Q(s, a)` durum `s` ve eylem `a` için mevcut Q-değeridir.
- `α` öğrenme oranıdır.
- `r` durum `s`'de eylem `a`'yı gerçekleştirdikten sonra alınan ödüldür.
- `γ` indirim faktörüdür.
- `s'` eylem `a`'yı gerçekleştirdikten sonraki durumdur.
- `a'` bir sonraki durum `s'`de alınan eylemdir.
5. **İterasyon**: Q-değerleri yakınsayana veya bir durdurma kriteri karşılanana kadar adımları 2-4'ü tekrarlayın.

#### Softmax vs ε-Greedy Eylem Seçimi

ε-greedy eylem seçiminin yanı sıra, SARSA ayrıca bir softmax eylem seçimi stratejisi de kullanabilir. Softmax eylem seçiminde, bir eylemi seçme olasılığı **Q-değerine orantılıdır**, bu da eylem alanının daha incelikli bir keşfini sağlar. Durum `s`'de eylem `a`'yı seçme olasılığı:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
nerede:
- `P(a|s)` eylem `a`'yı durum `s`'de seçme olasılığıdır.
- `Q(s, a)` durum `s` ve eylem `a` için Q-değeridir.
- `τ` (tau) keşif seviyesini kontrol eden sıcaklık parametresidir. Daha yüksek bir sıcaklık daha fazla keşif (daha uniform olasılıklar) ile sonuçlanırken, daha düşük bir sıcaklık daha fazla sömürü (daha yüksek Q-değerlerine sahip eylemler için daha yüksek olasılıklar) ile sonuçlanır.

> [!TIP]
> Bu, keşif ve sömürüyü ε-greedy eylem seçiminden daha sürekli bir şekilde dengelemeye yardımcı olur.

### On-Policy vs Off-Policy Öğrenme

SARSA, mevcut politikanın (ε-greedy veya softmax politikası) aldığı eylemlere dayalı olarak Q-değerlerini güncelleyen bir **on-policy** öğrenme algoritmasıdır. Buna karşılık, Q-Learning, mevcut politikanın aldığı eylemden bağımsız olarak bir sonraki durum için maksimum Q-değerine dayalı olarak Q-değerlerini güncelleyen bir **off-policy** öğrenme algoritmasıdır. Bu ayrım, algoritmaların nasıl öğrendiğini ve çevreye nasıl uyum sağladığını etkiler.

SARSA gibi on-policy yöntemler, gerçekten alınan eylemlerden öğrendikleri için belirli ortamlarda daha stabil olabilir. Ancak, daha geniş bir deneyim yelpazesinden öğrenebilen Q-Learning gibi off-policy yöntemlere kıyasla daha yavaş yakınsama gösterebilirler.

{{#include ../banners/hacktricks-training.md}}
