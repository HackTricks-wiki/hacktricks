# Strumenti e piattaforme per modelli di AI

{{#include ../banners/hacktricks-training.md}}

## Eseguire e addestrare modelli localmente

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers è una libreria open source per caricare, addestrare e distribuire modelli preaddestrati per attività di testo, visione, audio, video e multimodali. L'hosting di modelli e dataset è fornito separatamente da Hugging Face Hub.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain è un framework per creare applicazioni e agenti basati su modelli, con funzionalità di composizione dei prompt, gestione della cronologia di conversazione e dello stato, strumenti, recupero, integrazioni con modelli, API e database.<sup>[[2]](#references)</sup>

#### Verificare la ricostruzione di oggetti serializzati in LangChain

Quando un'applicazione accetta input utente o output del modello **strutturati**, verifica se i dizionari annidati persistono in `metadata`, `additional_kwargs`, `response_metadata`, nella cronologia delle chat salvata o in un flusso di esecuzione. LangChain usa dizionari contrassegnati con `lc` come oggetti serializzati. Nei round trip `dumps()`/`dumpd()` → `load()`/`loads()` interessati, un dizionario controllato da un attaccante potrebbe essere ricostruito come oggetto del framework anziché rimanere un dato. Anche caricare direttamente un manifest non attendibile è pericoloso; una stringa semplice che non viene mai analizzata come dizionario non soddisfa questo prerequisito.<sup>[[10]](#references)[[11]](#references)</sup>

Per un test autorizzato, invia un canary innocuo, strutturato come un costruttore, **come oggetto JSON annidato**, non come stringa, e verifica se la cronologia downstream o il flusso contengono un oggetto `AIMessage` anziché il dizionario originale:<sup>[[11]](#references)</sup>

```json
{"lc":1,"type":"constructor","id":["langchain_core","messages","ai","AIMessage"],"kwargs":{"content":"serialization-canary"}}
```

Verifica `RunnableWithMessageHistory`, `astream_log()` e `astream_events(version="v1")` quando vengono effettivamente utilizzati. Il ripristino riuscito di un oggetto può avvelenare la cronologia delle chat successive; liste consentite più ampie possono istanziare altre classi attendibili i cui costruttori hanno effetti collaterali. Non equiparare questo problema all'esecuzione illimitata di pickle. La vulnerabilità originale di escape è stata corretta in `langchain-core` 0.3.81/1.2.5; una correzione successiva per le liste consentite troppo ampie e i marcatori dei secret è stata introdotta nelle versioni 0.3.85/1.3.3. Per manifest non attendibili, usa una versione aggiornata e limita `allowed_objects` alle classi dei messaggi o a un elenco sicuro esplicito, con `secrets_from_env=False`.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup> Per la [mappatura dei confini di fiducia degli agenti](AI-Agent-Security-Methodology.md), tieni questa problematica distinta dall'[RCE tramite caricamento di file modello](AI-Models-RCE.md).

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT offre implementazioni leggibili e workflow da riga di comando per il pretraining, il fine-tuning, la valutazione e il deployment dei modelli linguistici supportati.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Descrizione:**\
LitServe è un framework di model serving di Lightning AI che consente di esporre API di inferenza con funzionalità di batching, streaming, accelerazione e scalabilità.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl è un framework open source per il post-training e il fine-tuning basato su configurazioni YAML. Supporta tecniche come il fine-tuning completo, LoRA/QLoRA, l'ottimizzazione delle preferenze e il training multi-GPU; non è di per sé una piattaforma di deployment cloud.<sup>[[5]](#references)</sup>

## Prova i modelli online

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** è una piattaforma e community di riferimento per il machine learning, particolarmente nota per il suo lavoro nell'elaborazione del linguaggio naturale (NLP). Offre strumenti, librerie e risorse che semplificano lo sviluppo, la condivisione e il deployment di modelli di machine learning.\
L'Hub offre diverse sezioni pertinenti:<sup>[[6]](#references)</sup>

* **Models**: un vasto repository di **modelli di machine learning pre-addestrati** che gli utenti possono esplorare, scaricare e integrare per attività diverse, come la generazione di testo, la traduzione, il riconoscimento di immagini e altro ancora.
* **Datasets:** una raccolta completa di **dataset** utilizzati per addestrare e valutare i modelli. Facilita l'accesso a fonti di dati diversificate, consentendo agli utenti di trovare e utilizzare i dati per i propri progetti di machine learning.
* **Spaces:** una piattaforma per ospitare e condividere **applicazioni interattive di machine learning** e demo. Consente agli sviluppatori di **mostrare** i propri modelli in azione, creare interfacce intuitive e collaborare con altri condividendo demo live.

#### Esamina i log di runtime pubblici di Space

Il codice nel repository di uno Space pubblico può rivelare quali input e variabili d'ambiente vengono registrati dalla sua app. Durante una valutazione autorizzata, esamina lo stream dei log di **run** come superficie distinta dall'interfaccia dell'app. Hugging Face documenta l'endpoint SSE dei log di Space; alcune ricerche hanno rilevato che gli altri utenti dell'Hub potevano leggere i log degli Space pubblici, che talvolta contenevano chiavi API, prompt degli utenti o un token di accesso a Dev Mode registrato in un URL di richiesta. Un token presente in un log è rilevante solo se la modalità privilegiata corrispondente è ancora attiva e il token è ancora valido.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
SPACE='owner/space-name'
curl -NsS -H "Authorization: Bearer $HF_TOKEN" \
  "https://huggingface.co/api/spaces/$SPACE/logs/run?tail=100"
```

Usa un token per il tuo account Hub autorizzato; **non** si tratta di una richiesta del segreto del proprietario dello Space. La risposta è uno stream SSE (righe `data:`). Correla i valori esposti con il codice dello Space e il runtime corrente, invece di presumere che il nome di una variabile dimostri che il suo valore sia stato divulgato. Per un [endpoint Gradio o model-runner self-hosted](AI-Exposed-Self-Hosted-AI-Services.md), consulta invece quella pagina.<sup>[[13]](#references)[[14]](#references)</sup>

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** è un repository e una libreria di componenti di modelli addestrati riutilizzabili, in particolare moduli utilizzati tramite TensorFlow/Keras. **Kaggle** offre separatamente notebook, dataset, competizioni e modelli.<sup>[[7]](#references)[[9]](#references)</sup>

* **Moduli:** Una vasta raccolta di modelli pre-addestrati e componenti di modelli che gli utenti possono esplorare, scaricare e integrare per attività come la classificazione delle immagini, l'embedding del testo e altro ancora.
* **Tutorial:** Guide ed esempi passo passo che aiutano gli utenti a implementare e ottimizzare i modelli utilizzando TensorFlow Hub.
* **Documentazione:** Guide complete e riferimenti alle API che aiutano gli sviluppatori a utilizzare efficacemente le risorse del repository.

## [**Replicate**](https://replicate.com/home)

**Replicate** è una piattaforma ospitata per eseguire modelli di machine learning impacchettati tramite un'interfaccia web o un'API.<sup>[[8]](#references)</sup>

* **Modelli:** Un repository di modelli di machine learning forniti dalla community, che gli utenti possono esplorare, provare e integrare nelle proprie applicazioni con il minimo sforzo.
* **Accesso API:** API per invocare modelli dalle applicazioni senza gestire l'infrastruttura di inferenza sottostante.

## Attaccare servizi AI self-hosted esposti

Per il fingerprinting black-box e il testing di model runner self-hosted, agent builder, interfacce demo ML, cluster di calcolo e database vettoriali, consulta [Servizi AI self-hosted esposti](AI-Exposed-Self-Hosted-AI-Services.md).



## References

- [1] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [2] [LangChain](https://github.com/langchain-ai/langchain)
- [3] [LitGPT](https://github.com/Lightning-AI/litgpt)
- [4] [LitServe](https://github.com/Lightning-AI/LitServe)
- [5] [Axolotl](https://github.com/axolotl-ai-cloud/axolotl)
- [6] [Documentazione di Hugging Face Hub](https://huggingface.co/docs/hub/index)
- [7] [TensorFlow Hub](https://www.tensorflow.org/hub)
- [8] [Documentazione di Replicate](https://replicate.com/docs)
- [9] [Documentazione di Kaggle](https://www.kaggle.com/docs)
- [10] [Avviso di sicurezza sull'injection di serializzazione di LangChain](https://github.com/langchain-ai/langchain/security/advisories/GHSA-c67j-w6g6-q2cm)
- [11] [Avviso di sicurezza sul ripristino non sicuro di oggetti di LangChain](https://github.com/langchain-ai/langchain/security/advisories/GHSA-pjwx-r37v-7724)
- [12] [API load e modello di minaccia di LangChain](https://github.com/langchain-ai/langchain/blob/master/libs/core/langchain_core/load/load.py)
- [13] [API dei log di Hugging Face Spaces](https://huggingface.co/docs/hub/main/en/spaces-gpus#streaming-logs-events-and-metrics)
- [14] [Il tuo Space è la mia zona: rischi di sicurezza delle app AI sugli hub di modelli](https://arxiv.org/abs/2606.30373)
{{#include ../banners/hacktricks-training.md}}
