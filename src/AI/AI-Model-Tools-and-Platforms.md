# Strumenti e piattaforme per modelli AI

{{#include ../banners/hacktricks-training.md}}

## Eseguire e addestrare modelli localmente

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers è una libreria open source per caricare, addestrare e distribuire modelli preaddestrati per attività di testo, visione, audio, video e multimodali. L’hosting di modelli e dataset è fornito separatamente da Hugging Face Hub.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain è un framework per creare applicazioni e agenti basati su modelli, con funzionalità per creare prompt, gestire cronologia e stato delle conversazioni, strumenti, recupero di informazioni e integrazioni con modelli, API e database.<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT offre implementazioni leggibili e procedure da riga di comando per preaddestrare, ottimizzare, valutare e distribuire i modelli linguistici supportati.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Descrizione:**\
LitServe è un framework di Lightning AI per distribuire modelli tramite API di inferenza, con funzionalità per batching, streaming, accelerazione e scalabilità.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl è un framework open source per il post-training e il fine-tuning, configurato tramite YAML. Supporta tecniche come il fine-tuning completo, LoRA/QLoRA, l’ottimizzazione delle preferenze e l’addestramento multi-GPU; non è una piattaforma di distribuzione cloud.<sup>[[5]](#references)</sup>

## Provare modelli online

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** è una piattaforma e una community di riferimento per il machine learning, nota in particolare per il suo lavoro nell’elaborazione del linguaggio naturale (NLP). Fornisce strumenti, librerie e risorse che semplificano lo sviluppo, la condivisione e la distribuzione di modelli di machine learning.\
Hub offre diverse sezioni utili:<sup>[[6]](#references)</sup>

* **Models**: un vasto archivio di **modelli di machine learning preaddestrati** che gli utenti possono esplorare, scaricare e integrare per attività come generazione di testo, traduzione, riconoscimento di immagini e altro.
* **Datasets:** una vasta **raccolta di dataset** utilizzati per addestrare e valutare modelli. Facilita l’accesso a fonti di dati diverse, consentendo agli utenti di trovare e utilizzare i dati per i propri progetti di machine learning.
* **Spaces:** una piattaforma per ospitare e condividere **applicazioni interattive di machine learning** e demo. Consente agli sviluppatori di **presentare** i propri modelli in funzione, creare interfacce intuitive e collaborare condividendo demo live.

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** è un archivio e una libreria di componenti riutilizzabili di modelli addestrati, in particolare moduli utilizzabili tramite TensorFlow/Keras. **Kaggle** offre invece notebook, dataset, competizioni e modelli.<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules:** una vasta raccolta di modelli e componenti di modelli preaddestrati che gli utenti possono esplorare, scaricare e integrare per attività come classificazione delle immagini, embedding di testo e altro.
* **Tutorials:** guide dettagliate ed esempi che aiutano gli utenti a implementare e ottimizzare modelli utilizzando TensorFlow Hub.
* **Documentation:** guide complete e riferimenti API che aiutano gli sviluppatori a utilizzare efficacemente le risorse dell’archivio.

## [**Replicate**](https://replicate.com/home)

**Replicate** è una piattaforma ospitata per eseguire modelli di machine learning impacchettati tramite un’interfaccia web o un’API.<sup>[[8]](#references)</sup>

* **Models:** un archivio di modelli di machine learning forniti dalla community, che gli utenti possono esplorare e provare, nonché integrare nelle proprie applicazioni con il minimo sforzo.
* **API access:** API per richiamare modelli dalle applicazioni senza gestire l’infrastruttura di inferenza sottostante.

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
{{#include ../banners/hacktricks-training.md}}
