# AI Model Araçları ve Platformları

{{#include ../banners/hacktricks-training.md}}

## Modelleri yerel olarak çalıştırma ve eğitme

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers; metin, görüntü, ses, video ve çok modlu görevlerde önceden eğitilmiş modelleri yüklemek, eğitmek ve sunmak için kullanılan açık kaynaklı bir kütüphanedir. Model ve veri kümesi barındırma hizmetleri, Hugging Face Hub tarafından ayrıca sağlanır.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain; istem oluşturma, konuşma geçmişi/durumu yönetimi, araçlar, bilgi getirme, model, API ve veritabanı entegrasyonlarıyla model odaklı uygulamalar ve agent'lar oluşturmak için kullanılan bir framework'tür.<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT, desteklenen dil modellerini ön eğitimden geçirme, fine-tuning, değerlendirme ve dağıtma için okunabilir uygulamalar ve komut satırı iş akışları sağlar.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Açıklama:**\
LitServe, batching, streaming, hızlandırma ve ölçeklendirme kancalarıyla inference API'leri sunmaya yönelik, Lightning AI tarafından geliştirilen bir model-serving framework'üdür.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl, YAML yapılandırmasıyla yönetilen açık kaynaklı bir post-training ve fine-tuning framework'üdür. Tam fine-tuning, LoRA/QLoRA, tercih optimizasyonu ve çoklu GPU eğitimi gibi teknikleri destekler; kendi başına bir bulut dağıtım platformu değildir.<sup>[[5]](#references)</sup>

## Modelleri çevrimiçi deneyin

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face**, özellikle doğal dil işleme (NLP) alanındaki çalışmalarıyla tanınan, makine öğrenimi için önde gelen bir platform ve topluluktur. Makine öğrenimi modelleri geliştirmeyi, paylaşmayı ve dağıtmayı kolaylaştıran araçlar, kütüphaneler ve kaynaklar sunar.\
Hub'da ilgili birkaç bölüm bulunur:<sup>[[6]](#references)</sup>

* **Models**: Kullanıcıların metin oluşturma, çeviri, görüntü tanıma ve daha birçok görev için modelleri inceleyebildiği, indirebildiği ve entegre edebildiği **önceden eğitilmiş makine öğrenimi modellerinden** oluşan geniş bir depo.
* **Datasets:** Model eğitimi ve değerlendirmesinde kullanılan kapsamlı bir **veri kümesi koleksiyonu**. Çeşitli veri kaynaklarına kolay erişim sağlayarak kullanıcıların belirli makine öğrenimi projeleri için veri bulup kullanmasına olanak tanır.
* **Spaces:** **Etkileşimli makine öğrenimi uygulamaları** ve demolar barındırıp paylaşmaya yönelik bir platform. Geliştiricilerin modellerini çalışırken **sergilemesine**, kullanıcı dostu arayüzler oluşturmasına ve canlı demolar paylaşarak başkalarıyla iş birliği yapmasına olanak tanır.

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub**, özellikle TensorFlow/Keras aracılığıyla kullanılan, yeniden kullanılabilir eğitilmiş model bileşenleri için bir depo ve kütüphanedir. **Kaggle** ise notebook'lar, veri kümeleri, yarışmalar ve modeller sunar.<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules:** Kullanıcıların görüntü sınıflandırma, metin gömme ve daha birçok görev için modülleri inceleyebildiği, indirebildiği ve entegre edebildiği, önceden eğitilmiş model ve model bileşenlerinden oluşan geniş bir koleksiyon.
* **Tutorials:** Kullanıcıların TensorFlow Hub kullanarak modelleri uygulamasına ve fine-tuning yapmasına yardımcı olan adım adım kılavuzlar ve örnekler.
* **Documentation:** Geliştiricilerin deponun kaynaklarından etkili bir şekilde yararlanmasına yardımcı olan kapsamlı kılavuzlar ve API referansları.

## [**Replicate**](https://replicate.com/home)

**Replicate**, paketlenmiş makine öğrenimi modellerini web arayüzü veya API üzerinden çalıştırmaya yönelik barındırılan bir platformdur.<sup>[[8]](#references)</sup>

* **Models:** Topluluğun katkıda bulunduğu makine öğrenimi modellerinden oluşan bir depo. Kullanıcılar modelleri inceleyebilir, deneyebilir ve minimum çabayla uygulamalarına entegre edebilir.
* **API access:** Altta yatan inference altyapısını işletmeden uygulamalardan model çağırmaya yönelik API'ler.

## References

- [1] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [2] [LangChain](https://github.com/langchain-ai/langchain)
- [3] [LitGPT](https://github.com/Lightning-AI/litgpt)
- [4] [LitServe](https://github.com/Lightning-AI/LitServe)
- [5] [Axolotl](https://github.com/axolotl-ai-cloud/axolotl)
- [6] [Hugging Face Hub belgeleri](https://huggingface.co/docs/hub/index)
- [7] [TensorFlow Hub](https://www.tensorflow.org/hub)
- [8] [Replicate belgeleri](https://replicate.com/docs)
- [9] [Kaggle belgeleri](https://www.kaggle.com/docs)
{{#include ../banners/hacktricks-training.md}}
