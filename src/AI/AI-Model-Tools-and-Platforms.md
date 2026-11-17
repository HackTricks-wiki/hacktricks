# AI Model Tools and Platforms

{{#include ../banners/hacktricks-training.md}}

## Lokalno pokretanje i treniranje modela

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers je open-source biblioteka za učitavanje, treniranje i posluživanje prethodno obučenih modela za zadatke obrade teksta, vida, zvuka, videa i multimodalne zadatke. Modeli i skupovi podataka hostuju se odvojeno, na Hugging Face Hub-u.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain je framework za izradu aplikacija i agenata zasnovanih na modelima, sa funkcijama za sastavljanje promptova, upravljanje istorijom/stanjem razgovora, alatima, preuzimanjem podataka i integracijama modela, API-ja i baza podataka.<sup>[[2]](#references)</sup>

#### Testiranje oživljavanja serijalizovanih objekata u LangChain-u

Kada aplikacija prihvata **strukturirani** korisnički unos ili izlaz modela, proverite da li ugnježdeni rečnici ostaju sačuvani u `metadata`, `additional_kwargs`, `response_metadata`, sačuvanoj istoriji ćaskanja ili toku izvršavanja. LangChain koristi rečnike označene sa `lc` kao serijalizovane objekte. U ranjivim ciklusima `dumps()`/`dumpd()` → `load()`/`loads()`, rečnik pod kontrolom napadača mogao bi da se oživi kao objekat framework-a umesto da ostane podatak. Direktno učitavanje nepouzdanog manifesta takođe je opasno; običan string unos koji se nikada ne parsira kao rečnik ne ispunjava ovaj preduslov.<sup>[[10]](#references)[[11]](#references)</sup>

Za ovlašćeni test pošaljite bezopasan canary oblikovan kao konstruktor **u vidu ugnježdenog JSON objekta**, a ne kao string, i proverite da li istorija ili tok u daljem procesu sadrže objekat `AIMessage` umesto izvornog rečnika:<sup>[[11]](#references)</sup>

```json
{"lc":1,"type":"constructor","id":["langchain_core","messages","ai","AIMessage"],"kwargs":{"content":"serialization-canary"}}
```

Proverite `RunnableWithMessageHistory`, `astream_log()` i `astream_events(version="v1")` kada se zaista koriste. Uspešna obnova objekta može da zagadi kasniju istoriju razgovora; šire liste dozvoljenih objekata mogu da instanciraju druge pouzdane klase čiji konstruktori imaju sporedne efekte. Nemojte ovo poistovećivati sa neograničenim izvršavanjem pickle-a. Prvobitni propust koji je omogućavao izlazak iz ograničenog okruženja ispravljen je u `langchain-core` 0.3.81/1.2.5, a kasnija ispravka za široku listu dozvoljenih objekata i oznake tajni objavljena je u verzijama 0.3.85/1.3.3. Za manifeste iz nepouzdanih izvora koristite aktuelno izdanje i ograničite `allowed_objects` na klase poruka ili izričitu bezbednu listu, uz `secrets_from_env=False`.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup> Za [mapiranje granica poverenja agenta](AI-Agent-Security-Methodology.md), razlikujte ovo od [RCE-a pri učitavanju datoteka modela](AI-Models-RCE.md).

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT nudi pregledne implementacije i tokove rada iz komandne linije za predtreniranje, fino podešavanje, evaluaciju i primenu podržanih jezičkih modela.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Opis:**\
LitServe je okvir kompanije Lightning AI za posluživanje modela, koji omogućava izlaganje API-ja za inferenciju uz grupisanje zahteva, strimovanje, ubrzavanje i mogućnosti skaliranja.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl je okvir otvorenog koda za post-trening i fino podešavanje, kojim se upravlja putem YAML konfiguracije. Podržava tehnike kao što su potpuno fino podešavanje, LoRA/QLoRA, optimizacija preferencija i treniranje na više GPU-ova; sam po sebi nije platforma za primenu u oblaku.<sup>[[5]](#references)</sup>

## Isprobajte modele na mreži

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** je vodeća platforma i zajednica za mašinsko učenje, posebno poznata po radu na obradi prirodnog jezika (NLP). Pruža alate, biblioteke i resurse koji olakšavaju razvoj, deljenje i primenu modela mašinskog učenja.\
Hub nudi nekoliko relevantnih odeljaka:<sup>[[6]](#references)</sup>

* **Models**: Ogromno skladište **unapred treniranih modela mašinskog učenja** u kojem korisnici mogu da pretražuju, preuzimaju i integrišu modele za različite zadatke, kao što su generisanje teksta, prevođenje, prepoznavanje slika i drugo.
* **Datasets:** Obimna **kolekcija skupova podataka** koji se koriste za treniranje i evaluaciju modela. Omogućava jednostavan pristup raznovrsnim izvorima podataka, pa korisnici mogu da pronađu i koriste podatke za svoje konkretne projekte mašinskog učenja.
* **Spaces:** Platforma za hostovanje i deljenje **interaktivnih aplikacija i demonstracija mašinskog učenja**. Omogućava programerima da **predstave** svoje modele u radu, kreiraju korisnički prilagođena okruženja i sarađuju sa drugima deljenjem demonstracija uživo.

#### Pregledajte javne logove izvršavanja Space-a

Kod repozitorijuma javnog Space-a može da otkrije koje ulaze i promenljive okruženja njegova aplikacija zapisuje u logove. Tokom ovlašćene procene, pregledajte tok logova za **run** kao zasebnu površinu, odvojenu od korisničkog interfejsa aplikacije. Hugging Face dokumentuje SSE krajnju tačku za logove Space-a; istraživanje je pokazalo da su logove javnih Space-ova mogli da čitaju drugi korisnici Huba i da su oni ponekad sadržali API ključeve, korisničke upite ili pristupni token za Dev Mode zapisan u URL-u zahteva. Token u logu predstavlja rizik samo ako je odgovarajući privilegovani režim i dalje omogućen i token još važi.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
SPACE='owner/space-name'
curl -NsS -H "Authorization: Bearer $HF_TOKEN" \
  "https://huggingface.co/api/spaces/$SPACE/logs/run?tail=100"
```

Koristite token za svoj ovlašćeni Hub nalog; ovo **nije** zahtev za tajnu vlasnika Space-a. Odgovor je SSE tok (linije `data:`). Povežite izložene vrednosti sa kodom Space-a i trenutnim runtime-om, umesto da pretpostavite da je vrednost procurila samo na osnovu imena promenljive. Za [Gradio ili model-runner endpoint koji sami hostujete](AI-Exposed-Self-Hosted-AI-Services.md), pratite uputstva na toj stranici.<sup>[[13]](#references)[[14]](#references)</sup>

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** je repozitorijum i biblioteka komponenti obučenih modela za višekratnu upotrebu, naročito modula koji se koriste putem TensorFlow/Keras-a. **Kaggle** zasebno pruža notebook-ove, skupove podataka, takmičenja i modele.<sup>[[7]](#references)[[9]](#references)</sup>

* **Moduli:** Obimna kolekcija unapred obučenih modela i komponenti modela koje korisnici mogu da pregledaju, preuzmu i integrišu za zadatke kao što su klasifikacija slika, tekstualno ugrađivanje i drugo.
* **Tutorijali:** Uputstva i primeri korak po korak koji korisnicima pomažu da implementiraju i fino podešavaju modele koristeći TensorFlow Hub.
* **Dokumentacija:** Sveobuhvatna uputstva i API reference koje pomažu programerima da efikasno koriste resurse repozitorijuma.

## [**Replicate**](https://replicate.com/home)

**Replicate** je hostovana platforma za pokretanje upakovanih modela mašinskog učenja putem veb-interfejsa ili API-ja.<sup>[[8]](#references)</sup>

* **Modeli:** Repozitorijum modela mašinskog učenja koje doprinosi zajednica, a koje korisnici mogu da pregledaju i isprobaju, kao i da ih uz minimalan trud integrišu u svoje aplikacije.
* **Pristup API-ju:** API-ji za pozivanje modela iz aplikacija bez upravljanja infrastrukturom za inference.

## Napadi na izložene AI servise koje sami hostujete

Za black-box fingerprinting i testiranje model-runner-a, agent builder-a, ML demo interfejsa, računarskih klastera i vektorskih baza podataka koje sami hostujete, pogledajte [Izloženi AI servisi koje sami hostujete](AI-Exposed-Self-Hosted-AI-Services.md).



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
- [10] [LangChain bezbednosno upozorenje o ubacivanju serijalizacije](https://github.com/langchain-ai/langchain/security/advisories/GHSA-c67j-w6g6-q2cm)
- [11] [LangChain bezbednosno upozorenje o nesigurnom oživljavanju objekata](https://github.com/langchain-ai/langchain/security/advisories/GHSA-pjwx-r37v-7724)
- [12] [LangChain load API i model pretnji](https://github.com/langchain-ai/langchain/blob/master/libs/core/langchain_core/load/load.py)
- [13] [Hugging Face Spaces API za logove](https://huggingface.co/docs/hub/main/en/spaces-gpus#streaming-logs-events-and-metrics)
- [14] [Tvoj Space je moja zona: Bezbednosni rizici AI aplikacija na model hub-ovima](https://arxiv.org/abs/2606.30373)
{{#include ../banners/hacktricks-training.md}}
