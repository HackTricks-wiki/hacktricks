# Strumenti e piattaforme per modelli di IA

{{#include ../banners/hacktricks-training.md}}

## Eseguire e addestrare modelli in locale

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers è una libreria open source per caricare, addestrare e servire modelli preaddestrati per attività di testo, visione, audio, video e multimodali. L'hosting di modelli e dataset è fornito separatamente da Hugging Face Hub.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain è un framework per creare applicazioni e agenti basati su modelli, con funzionalità per costruire prompt, gestire cronologia e stato delle conversazioni, usare strumenti e integrare sistemi di retrieval, modelli, API e database.<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT offre implementazioni facilmente leggibili e flussi di lavoro da riga di comando per preaddestrare, eseguire il fine-tuning, valutare e distribuire i modelli linguistici supportati.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Descrizione:**\
LitServe è un framework di serving dei modelli di Lightning AI che consente di esporre API di inferenza con supporto per batching, streaming, accelerazione e scalabilità.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl è un framework open source per il post-training e il fine-tuning, basato su configurazione YAML. Supporta tecniche come il fine-tuning completo, LoRA/QLoRA, l'ottimizzazione delle preferenze e l'addestramento multi-GPU; non è di per sé una piattaforma di distribuzione cloud.<sup>[[5]](#references)</sup>

## Provare modelli online

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** è una piattaforma e una community di primo piano per il machine learning, nota in particolare per il suo lavoro nell'elaborazione del linguaggio naturale (NLP). Offre strumenti, librerie e risorse che facilitano lo sviluppo, la condivisione e la distribuzione di modelli di machine learning.\
Hub offre diverse sezioni pertinenti:<sup>[[6]](#references)</sup>

* **Models**: un vasto repository di **modelli di machine learning preaddestrati** in cui gli utenti possono esplorare, scaricare e integrare modelli per varie attività, come la generazione di testo, la traduzione, il riconoscimento delle immagini e altro ancora.
* **Datasets:** una vasta **raccolta di dataset** usati per addestrare e valutare modelli. Offre un facile accesso a diverse fonti di dati, consentendo agli utenti di trovare e utilizzare dati per i propri progetti di machine learning.
* **Spaces:** una piattaforma per ospitare e condividere **applicazioni e demo interattive di machine learning**. Consente agli sviluppatori di **mostrare** i propri modelli in azione, creare interfacce intuitive e collaborare con altri condividendo demo live.

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **e** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** è un repository e una libreria di componenti riutilizzabili di modelli addestrati, in particolare moduli utilizzati tramite TensorFlow/Keras. **Kaggle** offre separatamente notebook, dataset, competizioni e modelli.<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules:** una vasta raccolta di modelli preaddestrati e componenti di modelli in cui gli utenti possono esplorare, scaricare e integrare moduli per attività come la classificazione delle immagini, l'embedding di testo e altro ancora.
* **Tutorials:** guide dettagliate ed esempi che aiutano gli utenti a implementare e perfezionare modelli usando TensorFlow Hub.
* **Documentation:** guide complete e riferimenti API che aiutano gli sviluppatori a usare efficacemente le risorse del repository.

## [**Replicate**](https://replicate.com/home)

**Replicate** è una piattaforma ospitata per eseguire modelli di machine learning pacchettizzati tramite un'interfaccia web o un'API.<sup>[[8]](#references)</sup>

* **Models:** un repository di modelli di machine learning forniti dalla community, che gli utenti possono esplorare e provare, oltre a integrare nelle proprie applicazioni con il minimo sforzo.
* **API access:** API per invocare modelli dalle applicazioni senza gestire l'infrastruttura di inferenza sottostante.

## Attaccare servizi di IA self-hosted esposti

Per il fingerprinting black-box e i test di runner di modelli self-hosted, agent builder, interfacce demo ML, cluster di calcolo e database vettoriali, consulta [Servizi di IA self-hosted esposti](AI-Exposed-Self-Hosted-AI-Services.md).

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
