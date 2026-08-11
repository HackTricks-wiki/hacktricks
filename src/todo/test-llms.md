# Testiranje LLM-ova

{{#include ../banners/hacktricks-training.md}}

## Pokretanje i treniranje modela lokalno

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers je open-source biblioteka za učitavanje, treniranje i posluživanje unapred obučenih modela za zadatke koji obuhvataju tekst, vizuelni sadržaj, audio, video i multimodalne podatke. Hosting modela i skupova podataka obezbeđen je zasebno putem Hugging Face Hub-a.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain je framework za izgradnju aplikacija i agenata zasnovanih na modelima, sa podrškom za konstruisanje promptova, upravljanje istorijom/stanjem razgovora, alatke, retrieval, modele, API-je i integracije sa bazama podataka.<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT pruža čitljive implementacije i command-line workflow-e za pretraining, fine-tuning, evaluaciju i deployment podržanih jezičkih modela.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Opis:**\
LitServe je framework kompanije Lightning AI za posluživanje modela, koji omogućava izlaganje inference API-ja uz podršku za batching, streaming, ubrzavanje i hooks za skaliranje.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl je open-source framework za post-training i fine-tuning, kojim se upravlja putem YAML konfiguracije. Podržava tehnike kao što su full fine-tuning, LoRA/QLoRA, preference optimization i multi-GPU training; sam po sebi nije cloud deployment platforma.<sup>[[5]](#references)</sup>

## Isprobavanje modela online

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** je vodeća platforma i zajednica za machine learning, posebno poznata po radu u oblasti obrade prirodnog jezika (NLP). Pruža alatke, biblioteke i resurse koji olakšavaju razvoj, deljenje i deployment machine learning modela.\
Hub nudi nekoliko relevantnih odeljaka:<sup>[[6]](#references)</sup>

* **Models**: Ogromno spremište **pre-trained machine learning modela** u kojem korisnici mogu da pregledaju, preuzmu i integrišu modele za različite zadatke, kao što su generisanje teksta, prevođenje, prepoznavanje slika i drugo.
* **Datasets:** Sveobuhvatna **kolekcija skupova podataka** koji se koriste za treniranje i evaluaciju modela. Omogućava jednostavan pristup raznovrsnim izvorima podataka, tako da korisnici mogu da pronađu i koriste podatke za svoje konkretne machine learning projekte.
* **Spaces:** Platforma za hosting i deljenje **interaktivnih machine learning aplikacija** i demo primera. Omogućava developerima da **prikažu** svoje modele u radu, kreiraju korisnički prijemčive interfejse i sarađuju sa drugima deljenjem aktivnih demo primera.

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** je repozitorijum i biblioteka za reusable komponente treniranih modela, naročito module koji se koriste putem TensorFlow/Keras-a. **Kaggle** zasebno pruža notebooks, skupove podataka, takmičenja i modele.<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules:** Ogromna kolekcija pre-trained modela i komponenti modela u kojoj korisnici mogu da pregledaju, preuzmu i integrišu module za zadatke kao što su klasifikacija slika, text embedding i drugo.
* **Tutorials:** Vodiči i primeri korak po korak koji pomažu korisnicima da implementiraju i fine-tune-uju modele koristeći TensorFlow Hub.
* **Documentation:** Sveobuhvatni vodiči i API reference koje developerima pomažu da efikasno koriste resurse repozitorijuma.

## [**Replicate**](https://replicate.com/home)

**Replicate** je hosted platforma za pokretanje upakovanih machine-learning modela putem web interfejsa ili API-ja.<sup>[[8]](#references)</sup>

* **Models:** Repozitorijum machine learning modela koje je doprinela zajednica, u kojem korisnici mogu da pregledaju i isprobaju modele i da ih uz minimalan napor integrišu u svoje aplikacije.
* **API access:** API-ji za pozivanje modela iz aplikacija bez upravljanja osnovnom infrastrukturom za inference.

## References

- [1] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [2] [LangChain](https://github.com/langchain-ai/langchain)
- [3] [LitGPT](https://github.com/Lightning-AI/litgpt)
- [4] [LitServe](https://github.com/Lightning-AI/LitServe)
- [5] [Axolotl](https://github.com/axolotl-ai-cloud/axolotl)
- [6] [Hugging Face Hub dokumentacija](https://huggingface.co/docs/hub/index)
- [7] [TensorFlow Hub](https://www.tensorflow.org/hub)
- [8] [Replicate dokumentacija](https://replicate.com/docs)
- [9] [Kaggle dokumentacija](https://www.kaggle.com/docs)
{{#include ../banners/hacktricks-training.md}}
