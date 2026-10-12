# Mekanistik Yorumlanabilirlik Rehberliğindeki Adversarial Saldırılar

{{#include ../banners/hacktricks-training.md}}

## Saldırı yüzeyi olarak süperpozisyon

Aşırı az parametreli bir aktivasyon alanı, özellikleri ortogonal olmayan vektörlere atayarak boyut sayısından daha fazla anlamsal özelliği kodlayabilir. Sonuç olarak, etkinleşen bir özellik diğer özellik yönlerine de yansır. Eğitim, dağılım içindeki örneklerde görülen kombinasyonları telafi edebilir; ancak geçerli özelliklerin alışılmadık bir kombinasyonu, girdide bulunmayan bir hedef özelliğin yönünde yapıcı biçimde toplanabilir.<sup>[[1]](#references)[[2]](#references)</sup>

Özellik vektörleri `v_i ∈ R^D`, aktivasyonlar `a_i` ve hedef `t` için aşağıdaki büyüklük, aday kombinasyonları bulmada kullanışlıdır:<sup>[[1]](#references)</sup>

```text
I_t = Σ_i≠t |a_i (v_i · v_t) / ||v_t|| |
candidate condition: I_t > max(a)
```

Bu yalnızca bir ön eleme sezgisidir. Bir exploit, işaretleri ve büyüklükleri korumalı ve gerçek decoder'ı değerlendirmelidir; örneğin, ağırlıkların eşit olduğu doğrusal bir decoder'da `h_hat[t] = ReLU(b_t + Σ_i a_i(v_i · v_t))`. Negatif terimler saldırıyı etkisiz kılabilir; ayrıca decoder bias'ı, feature-vector normları, aktivasyon eşikleri ve ReLU gating, yüksek mutlak cosine skorunun hedef aktivasyonu üretmesini engelleyebilir.<sup>[[1]](#references)</sup>

## White-box saldırı iş akışı

Pratik bir değerlendirmede model bottleneck'i, sparse autoencoder (SAE) veya yorumlanabilir başka bir feature dictionary kullanılabilir. Amaç yalnızca son sınıfı değiştirmek değildir; sıkıştırmadan önce etkin olmayan, belirli bir internal feature'ın yeniden yapılandırma sırasında ortaya çıkmasını sağlamaktır. Önerilen iş akışı şöyledir:<sup>[[1]](#references)</sup>

1. **Feature yönlerini çıkarın:** İlgili encoder/decoder vektörlerini çıkarın, ölü feature'ları kaldırın ve en yüksek aktivasyona sahip örnekleri veya feature-circuit analizini kullanarak etkin yönleri kavramlarla eşleyin.
2. **Etkileşimi sıralayın:** Vektörlerin bir kopyasını normalize edin, cosine-similarity matrisini hesaplayın, köşegeni temizleyin ve hedefin en güçlü köşegen dışı komşularını inceleyin. Adayları gerçek aktivasyon büyüklükleri ve işaretli ham dot product'larla yeniden hesaplayın.
3. **Birlikte aktivasyonu sağlayın:** Aynı katmanda veya residual stream'de etkinleştirilebilecek, pozitif katkı sağlayan küçük bir feature kümesini tutun. Eğitim verilerinde nadir bulunan veya hiç bulunmayan kombinasyonları tercih edin; olağan korelasyonlu kombinasyonların eğitim sırasında telafi edilmiş olma olasılığı daha yüksektir.
4. **Girdiyi sentezleyin:** Seçilen katkı sağlayıcılar için veri kümesi örneklerini veya aktivasyonu en üst düzeye çıkaran örüntüleri birleştirin. Sınırlandırılmış doğrusal bir piksel dedektöründe, pozitif ağırlık için bir pikseli yüksek, negatif ağırlık için düşük ayarlayın ve ardından ortaya çıkan örüntüleri üst üste bindirin. Dağılım içi yapıyı ve engelleyici **negatif alanı** elle korumak, ilgisiz feature'ları baskılayabilir.
5. **Mekanizmayı doğrulayın:** Tek bir forward pass'te sıkıştırma öncesi aktivasyonları, sıkıştırılmış koordinatları, yeniden yapılandırılmış aktivasyonları ve downstream çıktıyı kaydedin. Başarılı bir testte hedef, yeniden yapılandırmadan önce etkin değilken sonrasında etkin olur; katkı sağlayıcılar ablate edildiğinde ise öngörülen değişiklik ortadan kalkar.

Aşağıdaki minimal ön eleme, feature vektörlerinin **satırlar** olduğu, ağırlıkları eşit bir decoder için katkı sağlayanları sıralar (feature'lar sütunlardaysa önce transpose edin). İşaretli skor için ham ağırlıkları, yalnızca cosine sıralaması için normalize edilmiş ağırlıkları kullanın.<sup>[[1]](#references)</sup>

```python
import numpy as np

norm = np.linalg.norm(W_dec, axis=1, keepdims=True)
unit = W_dec / np.clip(norm, 1e-12, None)
cosine = unit @ unit.T
np.fill_diagonal(cosine, 0.0)

target = 42
signed = activations * (W_dec @ W_dec[target])
signed[target] = -np.inf
order = np.argsort(signed)[::-1]
print([(int(i), float(signed[i]), float(cosine[i, target]))
       for i in order[:20] if signed[i] > 0])
```

Cosine similarity'den tek başına exploit edilebilirlik sonucu çıkarmayın. Bias ve non-linearity içeren decoder'ın tamamını test edin, katkıda bulunan özelliklerin gerçekten birlikte bulunabildiğini doğrulayın ve sonuçları, dağılım içinden eşleştirilmiş kombinasyonlarla karşılaştırın. Benzer yönler, exploit edilebilir packing interference yerine meşru bir anlamsal ilişkiyi kodluyor olabilir.<sup>[[1]](#references)</sup>

## Gösterilmiş toy-model saldırısı

Proof of concept'te, iki dallı ve kasıtlı olarak yorumlanabilir bir MNIST sınıflandırıcısı kullanıldı. Bir dalda seyrek 128 boyutlu ReLU özellik vektörü doğrudan sınıflandırılırken, diğer dalda iki boyutlu bir superposition alanına sıkıştırıldı; aynı sınıflandırıcı hem orijinal hem de yeniden oluşturulmuş özellikleri işledi.<sup>[[1]](#references)</sup>

```text
h       = ReLU(MLP(x))
z       = W_enc h
h_hat   = ReLU(W_enc^T z + b)
y_plain = C(h)
y_super = C(h_hat)
```

3/0 benzeri şekillerle ilişkili iki özellik yönü, geometrik olarak class-5 yönleriyle çevrelenmişti. Bu özelliklerin maksimum aktivasyon sağlayan görüntüleri toplandığında, sıkıştırma öncesinde katkıda bulunan özellikler en güçlü hâle geldi; ancak yeniden yapılandırma birkaç class-5 özelliğini etkinleştirdi ve superposition dalı 5 tahmininde bulundu. Yalnızca minimum/maksimum piksel değerlerini kullanan elle çizilmiş bir girdi de aynı etkiyi oluşturdu; bu da bu oyuncak ortamda tam olarak gradyanla optimize edilmiş piksel pertürbasyonlarının gerekmediğini gösterdi.<sup>[[1]](#references)</sup>

## Daha büyük modeller için geometrik eleme

Makale ayrıca Gemma Scope `layer 20 / width 65k / average L0 20` SAE'yi inceledi. Birim uzunlukta normalize edilmiş decoder matrisini transpozesiyla çarptı, köşegeni sıfırladı, her özelliğin komşularını sıraladı ve komşuluk sırasına göre ortalama aldı. En güçlü komşuların ortalama kosinüs benzerliği `0.49`, 27. komşunun ortalama benzerliği ise `0.25` idi; geometrik olarak, bu tür dört yön birim hedef projeksiyonuna eşleşebilirdi. Bu değerler yalnızca adayları belirler; dört uygun özelliğin birlikte etkinleştirilebileceğini veya hedefin decoder eşiğini aşacağını göstermez.<sup>[[1]](#references)</sup>

## Kapsam ve sınırlamalar

Bu, araştırma aşamasındaki bir **white-box** tekniktir; dağıtılmış bir CNN veya öncü bir LLM'ye karşı gösterilmiş bir saldırı değildir. Superposition, yararlı ortogonal olmayan yönler, iç özelliklere yorumlanabilir erişim, katkıda bulunan özelliklerin aktivasyonunu kontrol edebilme ve bunların tek bir forward pass sırasında aynı katmanda bir araya gelmesi gerekir.<sup>[[1]](#references)</sup>

Görüntü MLP'leri, özellik bileşimini alışılmadık ölçüde doğrudan hâle getirir. Transformer'lar daha zordur; çünkü attention, seçilen özellik aktivasyonlarını aynı residual stream içinde bir araya getirmelidir. Makale, dağılım dışı bir kombinasyon için bunun nasıl zorlanacağını göstermez. Dolayısıyla davranış veya ret yönlerini, fiziksel görme sistemlerini ya da öncü modelleri manipüle etmeye ilişkin iddialar hipotez olarak kalmaktadır.<sup>[[1]](#references)</sup>

## References

- [1] [Wilkinson ve Anley — Superposition'da Özellik Girişimi Yoluyla Yorumlanabilir Adversarial Saldırılara Yönelik Bir Ön İnceleme (PDF)](https://www.nccgroup.com/media/kahclmxj/interpretable-adversarial-attacks-in-superpos_.pdf)
- [2] [NCC Group — Superposition'da Yorumlanabilir Adversarial Saldırılar](https://www.nccgroup.com/research/interpretable-adversarial-attacks-in-superposition/)
{{#include ../banners/hacktricks-training.md}}
