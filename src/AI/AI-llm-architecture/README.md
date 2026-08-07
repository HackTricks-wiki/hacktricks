# LLM Training - Data Preparation

{{#include ../../banners/hacktricks-training.md}}

**Bunlar, kesinlikle tavsiye edilen şu kitaptan aldığım notlardır:** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **ve bazı ek bilgiler.**<sup>[[1]](#references)</sup>

## Temel Bilgiler

Bilmeniz gereken bazı temel kavramlar için şu yazıyı okuyarak başlamalısınız:


{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenization

> [!TIP]
> Bu başlangıç aşamasının amacı çok basittir: **Girdiyi anlamlı olacak şekilde token'lara (id'lere) ayırmak.**


{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Data Sampling

> [!TIP]
> Bu ikinci aşamanın amacı çok basittir: **Girdi verilerini örneklemek ve genellikle dataset'i belirli uzunluktaki cümlelere ayırarak ve beklenen yanıtı da oluşturarak training aşamasına hazırlamak.**


{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Token Embeddings

> [!TIP]
> Bu üçüncü aşamanın amacı çok basittir: **Önceki vocabulary'deki her token'a, modeli train etmek için istenen boyutlarda bir vector atamak.** Vocabulary'deki her kelime, X boyutlu bir uzayda bir nokta olacaktır.\
> Başlangıçta kelimelerin uzaydaki konumlarının yalnızca "rastgele" initialize edildiğini ve bu konumların train edilebilir parametreler olduğunu (training sırasında geliştirileceklerini) unutmayın.
>
> Ayrıca token embedding sırasında, (bu durumda) **kelimenin training cümlesindeki mutlak konumunu** temsil eden **başka bir embedding katmanı oluşturulur**. Böylece cümlenin farklı konumlarındaki bir kelime farklı bir temsile (anlama) sahip olur.


{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Attention Mechanisms

> [!TIP]
> Bu dördüncü aşamanın amacı çok basittir: **Bazı attention mekanizmalarını uygulamak.** Bunlar, **vocabulary'deki bir kelimenin, LLM'yi train etmek için kullanılan mevcut cümledeki komşularıyla olan ilişkisini yakalayacak** çok sayıda **tekrarlanan katmandan** oluşacaktır.\
> Bunun için çok sayıda katman kullanılır; dolayısıyla çok sayıda train edilebilir parametre bu bilgiyi yakalayacaktır.


{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. LLM Architecture

> [!TIP]
> Bu beşinci aşamanın amacı çok basittir: **Tam LLM mimarisini geliştirmek.** Her şeyi bir araya getirmek, tüm katmanları uygulamak ve text oluşturmak veya text'i ID'lere ve tekrar geriye dönüştürmek için gereken tüm fonksiyonları oluşturmak.
>
> Bu mimari hem training hem de model train edildikten sonra text tahmini için kullanılacaktır.


{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Pre-training & Loading models

> [!TIP]
> Bu altıncı aşamanın amacı çok basittir: **Modeli sıfırdan train etmek.** Bunun için önceki LLM mimarisi kullanılacak; tanımlanan loss fonksiyonları ve optimizer kullanılarak modelin tüm parametrelerini train etmek amacıyla dataset'ler üzerinde döngüler çalıştırılacaktır.


{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. LoRA Improvements in fine-tuning

> [!TIP]
> **LoRA kullanımı**, önceden train edilmiş modellerin **fine-tune edilmesi** için gereken **hesaplama miktarını büyük ölçüde azaltır.**


{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-Tuning for Classification

> [!TIP]
> Bu bölümün amacı, önceden pre-train edilmiş bir modelin, yeni text oluşturmak yerine verilen **text'in belirlenen kategorilerin her birinde sınıflandırılma olasılıklarını** vermesini sağlayacak şekilde nasıl fine-tune edileceğini göstermektir (örneğin bir text'in spam olup olmadığını belirlemek).


{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-Tuning to follow instructions

> [!TIP]
> Bu bölümün amacı, önceden pre-train edilmiş bir modelin yalnızca text oluşturmak yerine **talimatları takip edecek şekilde fine-tune edilmesini** nasıl sağlayacağınızı göstermektir; örneğin bir chat bot olarak görevlere yanıt vermek.


{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

## References

- [1] [Build a Large Language Model (From Scratch) - Manning](https://www.manning.com/books/build-a-large-language-model-from-scratch)

{{#include ../../banners/hacktricks-training.md}}
