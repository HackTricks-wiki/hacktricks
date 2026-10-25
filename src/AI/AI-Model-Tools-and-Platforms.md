# AI Model Araçları ve Platformları

{{#include ../banners/hacktricks-training.md}}

## Modelleri yerel olarak çalıştırma ve eğitme

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers; metin, görüntü, ses, video ve çok modlu görevlerde önceden eğitilmiş modelleri yüklemek, eğitmek ve sunmak için kullanılan açık kaynaklı bir kütüphanedir. Model ve veri kümesi barındırma hizmetleri, Hugging Face Hub tarafından ayrı olarak sağlanır.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain; istem oluşturma, konuşma geçmişi/durum yönetimi, araçlar, erişim, model, API ve veritabanı entegrasyonlarıyla model odaklı uygulamalar ve agent'lar geliştirmek için kullanılan bir framework'tür.<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT, desteklenen dil modellerini önceden eğitmek, fine-tune etmek, değerlendirmek ve dağıtmak için anlaşılır uygulamalar ve komut satırı iş akışları sunar.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Açıklama:**\
LitServe, batching, streaming, hızlandırma ve ölçeklendirme kancalarıyla inference API'leri sunmaya yönelik Lightning AI model sunma framework'üdür.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl, YAML yapılandırmasıyla çalışan açık kaynaklı bir post-training ve fine-tuning framework'üdür. Tam fine-tuning, LoRA/QLoRA, tercih optimizasyonu ve çoklu GPU eğitimi gibi teknikleri destekler; kendisi bir bulut dağıtım platformu değildir.<sup>[[5]](#references)</sup>

## Modelleri çevrimiçi deneyin

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face**, özellikle doğal dil işleme (NLP) alanındaki çalışmalarıyla tanınan, makine öğrenimi alanında önde gelen bir platform ve topluluktur. Makine öğrenimi modellerini geliştirmeyi, paylaşmayı ve dağıtmayı kolaylaştıran araçlar, kütüphaneler ve kaynaklar sunar.\
Hub'da ilgili birkaç bölüm bulunur:<sup>[[6]](#references)</sup>

* **Models**: Kullanıcıların metin oluşturma, çeviri, görüntü tanıma ve daha pek çok görev için modelleri inceleyebildiği, indirebildiği ve entegre edebildiği geniş bir **önceden eğitilmiş makine öğrenimi modelleri** deposu.
* **Datasets:** Modelleri eğitmek ve değerlendirmek için kullanılan kapsamlı bir **veri kümesi koleksiyonu**. Çeşitli veri kaynaklarına kolay erişim sağlayarak kullanıcıların kendi makine öğrenimi projelerine uygun verileri bulup kullanmasını mümkün kılar.
* **Spaces:** **Etkileşimli makine öğrenimi uygulamalarını** ve demoları barındırıp paylaşmaya yönelik bir platform. Geliştiricilerin modellerini çalışır hâlde **sergilemesine**, kullanıcı dostu arayüzler oluşturmasına ve canlı demoları paylaşarak başkalarıyla iş birliği yapmasına olanak tanır.

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub**, özellikle TensorFlow/Keras üzerinden kullanılan, yeniden kullanılabilir eğitilmiş model bileşenleri için bir depo ve kütüphanedir. **Kaggle** ise ayrı olarak notebook'lar, veri kümeleri, yarışmalar ve modeller sunar.<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules:** Kullanıcıların görüntü sınıflandırma, metin gömme ve daha pek çok görev için modülleri inceleyebildiği, indirebildiği ve entegre edebildiği geniş bir önceden eğitilmiş model ve model bileşeni koleksiyonu.
* **Tutorials:** Kullanıcıların TensorFlow Hub ile modelleri uygulamasına ve fine-tune etmesine yardımcı olan adım adım kılavuzlar ve örnekler.
* **Documentation:** Geliştiricilerin deponun kaynaklarından etkili biçimde yararlanmasına yardımcı olan kapsamlı kılavuzlar ve API referansları.

## [**Replicate**](https://replicate.com/home)

**Replicate**, paketlenmiş makine öğrenimi modellerini web arayüzü veya API üzerinden çalıştırmaya yönelik barındırılan bir platformdur.<sup>[[8]](#references)</sup>

* **Models:** Topluluğun katkıda bulunduğu makine öğrenimi modellerinin yer aldığı bir depo. Kullanıcılar bu modelleri inceleyebilir, deneyebilir ve minimum çabayla uygulamalarına entegre edebilir.
* **API access:** Temel inference altyapısını işletmeden uygulamalardan modelleri çağırmaya yönelik API'ler.

## Açıkta kalan, kendi sunucusunda barındırılan AI hizmetlerine saldırma

Kendi sunucusunda barındırılan model çalıştırıcıları, agent oluşturucuları, ML demo arayüzleri, işlem kümeleri ve vektör veritabanları için black-box parmak izi alma ve test etme hakkında bilgi edinmek üzere [Açıkta Kalan, Kendi Sunucusunda Barındırılan AI Hizmetleri](AI-Exposed-Self-Hosted-AI-Services.md) sayfasına bakın.

## References

- [1] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [2] [LangChain](https://github.com/langchain-ai/langchain)
- [3] [LitGPT](https://github.com/Lightning-AI/litgpt)
- [4] [LitServe](https://github.com/Lightning-AI/LitServe)
- [5] [Axolotl](https://github.com/axolotl-ai-cloud/axolotl)
- [6] [Hugging Face Hub dokümantasyonu](https://huggingface.co/docs/hub/index)
- [7] [TensorFlow Hub](https://www.tensorflow.org/hub)
- [8] [Replicate dokümantasyonu](https://replicate.com/docs)
- [9] [Kaggle dokümantasyonu](https://www.kaggle.com/docs)
{{#include ../banners/hacktricks-training.md}}
