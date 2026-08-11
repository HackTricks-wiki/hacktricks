# LLM Eğitimi - Veri Hazırlama

{{#include ../../banners/hacktricks-training.md}}

**Bunlar, şiddetle tavsiye edilen şu kitaptan aldığım notlardır:** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **ve bazı ek bilgiler.**<sup>[[1]](#references)</sup>

## Temel Bilgiler

Bilmeniz gereken bazı temel kavramlar için bu yazıyı okuyarak başlamalısınız:


{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenization

> [!TIP]
> Bu aşamanın amacı, **girdiyi token'lara bölmek ve bunları token ID'leriyle eşleştirmektir**.


{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Data Sampling

> [!TIP]
> Bu aşamanın amacı, seçilen context uzunluğunda eğitim dizilerini ve bunlara karşılık gelen kaydırılmış tahmin hedeflerini hazırlamaktır.


{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Token Embeddings

> [!TIP]
> Bu üçüncü aşamanın amacı oldukça basittir: **Vocabulary'deki önceki token'ların her birine, modeli eğitmek için istenen boyutlarda bir vektör atamak.** Vocabulary'deki her kelime, X boyutlu bir uzayda bir nokta olacaktır.\
> Başlangıçta her kelimenin uzaydaki konumunun yalnızca "rastgele" başlatıldığını ve bu konumların trainable parametreler olduğunu (eğitim sırasında iyileştirileceğini) unutmayın.
>
> Ayrıca token embedding sırasında, **eğitim cümlesindeki kelimenin mutlak konumunu** temsil eden **başka bir embedding katmanı oluşturulur**. Böylece cümledeki farklı konumlarda bulunan aynı kelime farklı bir gösterime sahip olur.


{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Attention Mechanisms

> [!TIP]
> Bu dördüncü aşamanın amacı oldukça basittir: **Bazı attention mekanizmalarını uygulamak**. Bunlar, **vocabulary'deki bir kelimenin, LLM'i eğitmek için kullanılan mevcut cümledeki komşularıyla olan ilişkisini yakalayacak** çok sayıda **tekrarlanan katmandan** oluşacaktır.\
> Bunun için çok sayıda katman kullanılır; dolayısıyla çok sayıda trainable parametre bu bilgiyi yakalayacaktır.


{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. LLM Architecture

> [!TIP]
> Bu beşinci aşamanın amacı oldukça basittir: **Tam LLM mimarisini geliştirmek.** Her şeyi bir araya getirmek, tüm katmanları uygulamak ve metin oluşturmak ya da metni ID'lere ve tekrar metne dönüştürmek için gereken tüm fonksiyonları oluşturmaktır.
>
> Bu mimari hem eğitim hem de eğitim sonrasında metin tahmini için kullanılacaktır.


{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Pre-training & Loading models

> [!TIP]
> Bu altıncı aşamanın amacı oldukça basittir: **Modeli sıfırdan eğitmek.** Bunun için, modelin tüm parametrelerini eğitmek üzere tanımlanan loss fonksiyonları ve optimizer kullanılarak veri setleri üzerinde döngüler çalıştıran önceki LLM mimarisi kullanılacaktır.


{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. LoRA Improvements in fine-tuning

> [!TIP]
> LoRA, pretrained bir modeli fine-tune etmek için gereken trainable parametrelerin ve optimizer state'in sayısını önemli ölçüde azaltır.


{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-Tuning for Classification

> [!TIP]
> Bu bölümün amacı, önceden eğitilmiş bir modelin yeni metinler oluşturmak yerine verilen metnin her bir kategoriye **atanma olasılıklarını vermesini** (örneğin bir metnin spam olup olmadığını belirlemesini) sağlayacak şekilde nasıl fine-tune edileceğini göstermektir.


{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-Tuning to follow instructions

> [!TIP]
> Bu bölümün amacı, önceden eğitilmiş bir modelin yalnızca metin oluşturmak yerine **talimatları takip edecek şekilde nasıl fine-tune edileceğini** göstermektir; örneğin bir chatbot olarak görevlere yanıt vermesi.


{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

## References

- [1] [Build a Large Language Model (From Scratch) - Manning](https://www.manning.com/books/build-a-large-language-model-from-scratch)
{{#include ../../banners/hacktricks-training.md}}
