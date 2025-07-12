# LLM Eğitimi - Veri Hazırlığı

{{#include ../../banners/hacktricks-training.md}}

**Bunlar, çok önerilen bir kitaptan aldığım notlar** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **ve bazı ek bilgiler.**

## Temel Bilgiler

Bilmeniz gereken bazı temel kavramlar için bu gönderiyi okumaya başlamalısınız:

{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenizasyon

> [!TIP]
> Bu ilk aşamanın amacı çok basit: **Girdiyi mantıklı bir şekilde token'lara (kimliklere) ayırmak**.

{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Veri Örnekleme

> [!TIP]
> Bu ikinci aşamanın amacı çok basit: **Girdi verilerini örneklemek ve genellikle veri kümesini belirli bir uzunluktaki cümlelere ayırarak ve beklenen yanıtı da üreterek eğitim aşamasına hazırlamak.**

{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Token Gömme

> [!TIP]
> Bu üçüncü aşamanın amacı çok basit: **Sözlükteki önceki her token'a modelin eğitimi için istenen boyutlarda bir vektör atamak.** Sözlükteki her kelime, X boyutlu bir uzayda bir nokta olacaktır.\
> Başlangıçta her kelimenin uzaydaki konumu "rastgele" başlatılır ve bu konumlar eğitilebilir parametrelerdir (eğitim sırasında geliştirilecektir).
>
> Ayrıca, token gömme sırasında **gömme katmanlarının başka bir katmanı oluşturulur** ki bu da (bu durumda) **kelimenin eğitim cümlesindeki mutlak konumunu temsil eder.** Bu şekilde, cümledeki farklı konumlarda bir kelimenin farklı bir temsili (anlamı) olacaktır.

{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Dikkat Mekanizmaları

> [!TIP]
> Bu dördüncü aşamanın amacı çok basit: **Bazı dikkat mekanizmaları uygulamak.** Bunlar, **sözlükteki bir kelimenin, LLM'yi eğitmek için kullanılan mevcut cümledeki komşularıyla olan ilişkisini yakalayacak çok sayıda tekrar eden katmanlar** olacaktır.\
> Bunun için çok sayıda katman kullanılmaktadır, bu nedenle çok sayıda eğitilebilir parametre bu bilgiyi yakalayacaktır.

{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. LLM Mimarisi

> [!TIP]
> Bu beşinci aşamanın amacı çok basit: **Tam LLM'nin mimarisini geliştirmek.** Her şeyi bir araya getirin, tüm katmanları uygulayın ve metin oluşturmak veya metni kimliklere ve geriye dönüştürmek için tüm işlevleri oluşturun.\
> Bu mimari, hem eğitim hem de eğitimden sonra metin tahmin etmek için kullanılacaktır.

{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Ön Eğitim ve Modellerin Yüklenmesi

> [!TIP]
> Bu altıncı aşamanın amacı çok basit: **Modeli sıfırdan eğitmek.** Bunun için önceki LLM mimarisi, tanımlanan kayıp fonksiyonları ve optimizasyon kullanarak veri setleri üzerinde döngülerle tüm model parametrelerini eğitmek için kullanılacaktır.

{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. İnce Ayar için LoRA İyileştirmeleri

> [!TIP]
> **LoRA'nın kullanımı, zaten eğitilmiş modelleri ince ayar yapmak için gereken hesaplamayı büyük ölçüde azaltır.**

{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Sınıflandırma için İnce Ayar

> [!TIP]
> Bu bölümün amacı, zaten önceden eğitilmiş bir modeli ince ayar yapmayı göstermektir, böylece yeni metin oluşturmak yerine LLM, **verilen metnin her bir verilen kategoriye sınıflandırılma olasılıklarını** seçecektir (örneğin, bir metnin spam olup olmadığını).

{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Talimatları Takip Etmek için İnce Ayar

> [!TIP]
> Bu bölümün amacı, **metin oluşturmak yerine talimatları takip etmek için zaten önceden eğitilmiş bir modeli ince ayar yapmayı** göstermektir, örneğin, bir sohbet botu olarak görevlere yanıt vermek.

{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
