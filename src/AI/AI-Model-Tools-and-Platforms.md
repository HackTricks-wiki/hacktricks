# Alati i platforme za AI modele

{{#include ../banners/hacktricks-training.md}}

## Pokretanje i treniranje modela lokalno

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers je open-source biblioteka za učitavanje, treniranje i posluživanje pretreniranih modela za zadatke obrade teksta, slike, zvuka, videa i multimodalne zadatke. Modeli i skupovi podataka hostuju se zasebno na Hugging Face Hub-u.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain je okvir za izradu aplikacija i agenata zasnovanih na modelima, sa funkcijama za konstruisanje promptova, upravljanje istorijom razgovora i stanjem, alatima, pronalaženjem informacija, kao i integracijama sa modelima, API-jima i bazama podataka.<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT nudi pregledne implementacije i radne tokove komandne linije za pretreniranje, fino podešavanje, evaluaciju i primenu podržanih jezičkih modela.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Opis:**\
LitServe je Lightning AI okvir za posluživanje modela, koji omogućava izlaganje API-ja za inferenciju uz funkcije za grupno obrađivanje, strimovanje, ubrzavanje i skaliranje.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl je open-source okvir za post-treniranje i fino podešavanje, kojim se upravlja putem YAML konfiguracije. Podržava tehnike kao što su potpuno fino podešavanje, LoRA/QLoRA, optimizacija preferencija i treniranje na više GPU-ova; sam po sebi nije platforma za primenu u oblaku.<sup>[[5]](#references)</sup>

## Isprobavanje modela na mreži

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** je vodeća platforma i zajednica za mašinsko učenje, naročito poznata po radu u oblasti obrade prirodnog jezika (NLP). Nudi alate, biblioteke i resurse koji olakšavaju razvoj, deljenje i primenu modela mašinskog učenja.\
Hub nudi nekoliko relevantnih odeljaka:<sup>[[6]](#references)</sup>

* **Models**: Ogromno spremište **pretreniranih modela mašinskog učenja** u kom korisnici mogu da pregledaju, preuzmu i integrišu modele za različite zadatke, kao što su generisanje teksta, prevođenje, prepoznavanje slika i drugo.
* **Datasets:** Sveobuhvatna **kolekcija skupova podataka** koji se koriste za treniranje i evaluaciju modela. Omogućava lak pristup raznovrsnim izvorima podataka, pa korisnici mogu da pronađu i koriste podatke za svoje konkretne projekte mašinskog učenja.
* **Spaces:** Platforma za hostovanje i deljenje **interaktivnih aplikacija i demonstracija mašinskog učenja**. Omogućava programerima da **predstave** svoje modele u radu, naprave interfejse jednostavne za korišćenje i sarađuju sa drugima deljenjem demonstracija uživo.

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **i** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** je spremište i biblioteka za komponente treniranih modela koje se mogu ponovo koristiti, naročito za module koji se koriste preko TensorFlow/Keras-a. **Kaggle** zasebno nudi notebook-ove, skupove podataka, takmičenja i modele.<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules:** Velika kolekcija pretreniranih modela i komponenti modela, u kojoj korisnici mogu da pregledaju, preuzmu i integrišu module za zadatke kao što su klasifikacija slika, ugrađivanje teksta i drugo.
* **Tutorials:** Vodiči i primeri koji korak po korak pomažu korisnicima da primene i fino podese modele koristeći TensorFlow Hub.
* **Documentation:** Sveobuhvatni vodiči i API reference koji programerima pomažu da efikasno koriste resurse spremišta.

## [**Replicate**](https://replicate.com/home)

**Replicate** je hostovana platforma za pokretanje upakovanih modela mašinskog učenja putem web interfejsa ili API-ja.<sup>[[8]](#references)</sup>

* **Models:** Spremište modela mašinskog učenja koje je doprinela zajednica, a korisnici mogu da ih pregledaju, isprobaju i uz minimalan napor integrišu u svoje aplikacije.
* **API access:** API-ji za pozivanje modela iz aplikacija bez upravljanja osnovnom infrastrukturom za inferenciju.

## Napadi na izložene, samostalno hostovane AI servise

Za black-box fingerprinting i testiranje samostalno hostovanih pokretača modela, alata za izradu agenata, ML demo korisničkih interfejsa, računarskih klastera i vektorskih baza podataka, pogledajte [Izloženi samostalno hostovani AI servisi](AI-Exposed-Self-Hosted-AI-Services.md).

## References

- [1] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [2] [LangChain](https://github.com/langchain-ai/langchain)
- [3] [LitGPT](https://github.com/Lightning-AI/litgpt)
- [4] [LitServe](https://github.com/Lightning-AI/LitServe)
- [5] [Axolotl](https://github.com/axolotl-ai-cloud/axolotl)
- [6] [Dokumentacija za Hugging Face Hub](https://huggingface.co/docs/hub/index)
- [7] [TensorFlow Hub](https://www.tensorflow.org/hub)
- [8] [Dokumentacija za Replicate](https://replicate.com/docs)
- [9] [Dokumentacija za Kaggle](https://www.kaggle.com/docs)
{{#include ../banners/hacktricks-training.md}}
