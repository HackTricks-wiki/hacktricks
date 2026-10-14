# AI alati i platforme za modele

{{#include ../banners/hacktricks-training.md}}

## Pokretanje i treniranje modela lokalno

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers je open-source biblioteka za učitavanje, treniranje i posluživanje unapred obučenih modela za zadatke obrade teksta, vida, zvuka, videa i multimodalne zadatke. Modeli i skupovi podataka hostuju se zasebno na Hugging Face Hub-u.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain je okvir za izradu aplikacija i agenata zasnovanih na modelima, uz mogućnosti sastavljanja promptova, upravljanja istorijom razgovora i stanjem, korišćenja alata, preuzimanja podataka i integracije sa modelima, API-jima i bazama podataka.<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT pruža pregledne implementacije i radne tokove komandne linije za prettreniranje, fino podešavanje, evaluaciju i postavljanje podržanih jezičkih modela.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Opis:**\
LitServe je okvir kompanije Lightning AI za posluživanje modela putem API-ja za inferenciju, sa podrškom za grupisanje zahteva, strimovanje, ubrzavanje i skaliranje.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl je open-source okvir za post-trening i fino podešavanje, kojim se upravlja pomoću YAML konfiguracije. Podržava tehnike kao što su potpuno fino podešavanje, LoRA/QLoRA, optimizacija preferencija i treniranje na više GPU-ova; sam po sebi nije platforma za postavljanje u cloud okruženju.<sup>[[5]](#references)</sup>

## Isprobavanje modela na mreži

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** je vodeća platforma i zajednica za mašinsko učenje, naročito poznata po radu na obradi prirodnog jezika (NLP). Pruža alate, biblioteke i resurse koji olakšavaju razvoj, deljenje i postavljanje modela mašinskog učenja.\
Hub nudi nekoliko relevantnih odeljaka:<sup>[[6]](#references)</sup>

* **Models**: Veliko spremište **unapred obučenih modela mašinskog učenja** u kojem korisnici mogu da pretražuju, preuzimaju i integrišu modele za različite zadatke, kao što su generisanje teksta, prevođenje, prepoznavanje slika i drugo.
* **Datasets:** Sveobuhvatna **kolekcija skupova podataka** koji se koriste za treniranje i evaluaciju modela. Omogućava jednostavan pristup raznovrsnim izvorima podataka, pa korisnici mogu da pronađu i iskoriste podatke za svoje konkretne projekte mašinskog učenja.
* **Spaces:** Platforma za hostovanje i deljenje **interaktivnih aplikacija i demonstracija mašinskog učenja**. Omogućava programerima da **predstave** svoje modele u radu, naprave jednostavna korisnička okruženja i sarađuju sa drugima deleći demonstracije uživo.

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **i** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** je spremište i biblioteka komponenti obučenih modela za višekratnu upotrebu, naročito modula koji se koriste putem TensorFlow/Keras-a. **Kaggle** zasebno nudi notebook-ove, skupove podataka, takmičenja i modele.<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules:** Velika kolekcija unapred obučenih modela i komponenti modela u kojoj korisnici mogu da pretražuju, preuzimaju i integrišu module za zadatke kao što su klasifikacija slika, ugrađivanje teksta i drugo.
* **Tutorials:** Vodiči i primeri korak po korak koji korisnicima pomažu da implementiraju i fino podese modele koristeći TensorFlow Hub.
* **Documentation:** Sveobuhvatni vodiči i API reference koje pomažu programerima da efikasno koriste resurse spremišta.

## [**Replicate**](https://replicate.com/home)

**Replicate** je hostovana platforma za pokretanje upakovanih modela mašinskog učenja putem veb-interfejsa ili API-ja.<sup>[[8]](#references)</sup>

* **Models:** Spremište modela mašinskog učenja koje je doprinela zajednica. Korisnici mogu da ih pregledaju, isprobaju i uz minimalan napor integrišu u svoje aplikacije.
* **API access:** API-ji za pozivanje modela iz aplikacija, bez upravljanja osnovnom infrastrukturom za inferenciju.

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
