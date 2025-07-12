# Test LLMs

{{#include ../banners/hacktricks-training.md}}

## Modelleri yerel olarak çalıştırma ve eğitme

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers, GPT, BERT ve diğerleri gibi LLM'leri kullanmak, eğitmek ve dağıtmak için en popüler açık kaynaklı kütüphanelerden biridir. Önceden eğitilmiş modeller, veri setleri ve ince ayar ile dağıtım için Hugging Face Hub ile sorunsuz entegrasyon içeren kapsamlı bir ekosistem sunar.

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain, LLM'lerle uygulama geliştirmek için tasarlanmış bir çerçevedir. Geliştiricilerin dil modellerini dış veri kaynakları, API'ler ve veritabanları ile bağlamasına olanak tanır. LangChain, gelişmiş istem mühendisliği, konuşma geçmişini yönetme ve LLM'leri karmaşık iş akışlarına entegre etme için araçlar sağlar.

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT, GPT tabanlı modellerin eğitimi, ince ayarı ve dağıtımını kolaylaştırmak için Lightning çerçevesini kullanan Lightning AI tarafından geliştirilen bir projedir. Diğer Lightning AI araçlarıyla sorunsuz bir şekilde entegre olur ve büyük ölçekli dil modellerini geliştirilmiş performans ve ölçeklenebilirlik ile yönetmek için optimize edilmiş iş akışları sunar.

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Açıklama:**\
LitServe, AI modellerini hızlı ve verimli bir şekilde dağıtmak için tasarlanmış Lightning AI'dan bir dağıtım aracıdır. LLM'lerin gerçek zamanlı uygulamalara entegrasyonunu, ölçeklenebilir ve optimize edilmiş sunum yetenekleri sağlayarak basitleştirir.

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl, LLM'ler de dahil olmak üzere AI modellerinin dağıtımını, ölçeklenmesini ve yönetimini kolaylaştırmak için tasarlanmış bulut tabanlı bir platformdur. Otomatik ölçeklendirme, izleme ve çeşitli bulut hizmetleri ile entegrasyon gibi özellikler sunarak, modellerin üretim ortamlarında kapsamlı altyapı yönetimi olmadan dağıtılmasını kolaylaştırır.

## Modelleri çevrimiçi deneme

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face**, makine öğrenimi için önde gelen bir platform ve topluluktur, özellikle doğal dil işleme (NLP) konusundaki çalışmalarıyla tanınır. Makine öğrenimi modellerini geliştirmeyi, paylaşmayı ve dağıtmayı kolaylaştıran araçlar, kütüphaneler ve kaynaklar sunar.\
Aşağıdaki gibi birkaç bölüm sunar:

* **Modeller**: Kullanıcıların metin üretimi, çeviri, görüntü tanıma ve daha fazlası gibi çeşitli görevler için modelleri göz atıp, indirdiği ve entegre edebildiği geniş bir **önceden eğitilmiş makine öğrenimi modelleri** deposu.
* **Veri Setleri:** Modellerin eğitimi ve değerlendirilmesi için kullanılan kapsamlı bir **veri setleri koleksiyonu**. Kullanıcıların belirli makine öğrenimi projeleri için veri bulup kullanmalarını sağlayarak çeşitli veri kaynaklarına kolay erişim sağlar.
* **Alanlar:** **Etkileşimli makine öğrenimi uygulamaları** ve demolarını barındırma ve paylaşma platformu. Geliştiricilerin modellerini eylemde sergilemelerine, kullanıcı dostu arayüzler oluşturmalarına ve canlı demolar paylaşarak başkalarıyla işbirliği yapmalarına olanak tanır.

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub**, Google tarafından geliştirilen yeniden kullanılabilir makine öğrenimi modüllerinin kapsamlı bir deposudur. Özellikle TensorFlow ile oluşturulan makine öğrenimi modellerinin paylaşımını ve dağıtımını kolaylaştırmaya odaklanır.

* **Modüller:** Kullanıcıların görüntü sınıflandırma, metin gömme ve daha fazlası gibi görevler için modülleri göz atıp, indirdiği ve entegre edebildiği geniş bir önceden eğitilmiş modeller ve model bileşenleri koleksiyonu.
* **Eğitimler:** Kullanıcıların TensorFlow Hub kullanarak modelleri nasıl uygulayacaklarını ve ince ayar yapacaklarını anlamalarına yardımcı olan adım adım kılavuzlar ve örnekler.
* **Dokümantasyon:** Geliştiricilerin deponun kaynaklarını etkili bir şekilde kullanmalarına yardımcı olan kapsamlı kılavuzlar ve API referansları.

## [**Replicate**](https://replicate.com/home)

**Replicate**, geliştiricilerin basit bir API aracılığıyla bulutta makine öğrenimi modellerini çalıştırmalarına olanak tanıyan bir platformdur. ML modellerini kolayca erişilebilir ve dağıtılabilir hale getirmeye odaklanır, kapsamlı altyapı kurulumu gerektirmez.

* **Modeller:** Topluluk tarafından katkıda bulunulan makine öğrenimi modellerinin bir deposu, kullanıcıların göz atıp, denediği ve uygulamalarına minimal çaba ile entegre edebildiği.
* **API Erişimi:** Geliştiricilerin kendi uygulamaları içinde modelleri zahmetsizce dağıtıp ölçeklendirmelerini sağlayan basit API'ler.


{{#include ../banners/hacktricks-training.md}}
