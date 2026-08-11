# LLM'leri Test Etme

{{#include ../banners/hacktricks-training.md}}

## Modelleri yerel olarak çalıştırma ve eğitme

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers; metin, görüntü, ses, video ve multimodal görevlerde önceden eğitilmiş modelleri yüklemek, eğitmek ve sunmak için kullanılan open-source bir kütüphanedir. Model ve dataset barındırma hizmetleri Hugging Face Hub tarafından ayrı olarak sağlanır.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain; prompt oluşturma, conversation history/state yönetimi, tools, retrieval, model, API ve database entegrasyonlarıyla model odaklı uygulamalar ve agent'lar geliştirmek için kullanılan bir framework'tür.<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT, desteklenen language model'leri pretraining, fine-tuning, değerlendirme ve deploy etme için okunabilir implementasyonlar ve command-line iş akışları sağlar.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Açıklama:**\
LitServe, batching, streaming, acceleration ve scaling hook'larıyla inference API'lerini kullanıma sunmak için Lightning AI tarafından geliştirilen bir model-serving framework'üdür.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl, YAML configuration tarafından yönlendirilen open-source bir post-training ve fine-tuning framework'üdür. Full fine-tuning, LoRA/QLoRA, preference optimization ve multi-GPU training gibi teknikleri destekler; kendisi bir cloud deployment platformu değildir.<sup>[[5]](#references)</sup>

## Modelleri online olarak deneme

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face**, özellikle natural language processing (NLP) alanındaki çalışmalarıyla tanınan, machine learning için önde gelen bir platform ve topluluktur. Machine learning modelleri geliştirmeyi, paylaşmayı ve deploy etmeyi kolaylaştıran tools, libraries ve resources sağlar.\
Hub, ilgili birkaç bölüm sunar:<sup>[[6]](#references)</sup>

* **Models**: Kullanıcıların text generation, translation, image recognition ve daha fazlası gibi çeşitli görevler için **önceden eğitilmiş machine learning modellerine** göz atabildiği, bunları indirebildiği ve entegre edebildiği geniş bir repository.
* **Datasets:** Modelleri eğitmek ve değerlendirmek için kullanılan kapsamlı bir **dataset koleksiyonu**. Çeşitli veri kaynaklarına kolay erişim sağlayarak kullanıcıların belirli machine learning projeleri için verileri bulmasına ve kullanmasına olanak tanır.
* **Spaces:** **Etkileşimli machine learning uygulamalarını** ve demoları barındırıp paylaşmaya yönelik bir platform. Geliştiricilerin modellerini çalışırken **sergilemesine**, kullanıcı dostu arayüzler oluşturmasına ve canlı demolar paylaşarak başkalarıyla iş birliği yapmasına olanak tanır.

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub**, özellikle TensorFlow/Keras üzerinden kullanılan modüller olmak üzere, yeniden kullanılabilir eğitilmiş model bileşenleri için bir repository ve library'dir. **Kaggle** ise ayrı olarak notebook'lar, dataset'ler, competitions ve modeller sağlar.<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules:** Kullanıcıların image classification, text embedding ve daha fazlası gibi görevler için modüllere göz atabildiği, bunları indirebildiği ve entegre edebildiği geniş bir önceden eğitilmiş model ve model bileşeni koleksiyonu.
* **Tutorials:** Kullanıcıların TensorFlow Hub kullanarak modelleri implement etmesine ve fine-tuning yapmasına yardımcı olan adım adım kılavuzlar ve örnekler.
* **Documentation:** Geliştiricilerin repository'nin kaynaklarını etkili bir şekilde kullanmasına yardımcı olan kapsamlı kılavuzlar ve API referansları.

## [**Replicate**](https://replicate.com/home)

**Replicate**, paketlenmiş machine-learning modellerini web arayüzü veya API üzerinden çalıştırmaya yarayan hosted bir platformdur.<sup>[[8]](#references)</sup>

* **Models:** Topluluk tarafından katkıda bulunulan machine learning modellerinden oluşan bir repository. Kullanıcılar bu modellere göz atabilir, modelleri deneyebilir ve minimum çabayla uygulamalarına entegre edebilir.
* **API access:** Temel inference altyapısını işletmeden uygulamalardan model çağırmak için kullanılan API'ler.

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
