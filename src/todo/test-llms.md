# Testare gli LLM

{{#include ../banners/hacktricks-training.md}}

## Eseguire e addestrare modelli localmente

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers è una libreria open source per caricare, addestrare e rendere disponibili modelli pretrained per attività di testo, visione, audio, video e multimodali. L'hosting di modelli e dataset è fornito separatamente da Hugging Face Hub.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain è un framework per creare applicazioni e agenti basati su modelli, con funzionalità per la costruzione dei prompt, la gestione della cronologia/stato delle conversazioni, gli strumenti, il retrieval e le integrazioni con modelli, API e database.<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT fornisce implementazioni leggibili e workflow da riga di comando per il pretraining, il fine-tuning, la valutazione e il deployment dei modelli linguistici supportati.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Descrizione:**\
LitServe è un framework di model serving di Lightning AI per esporre API di inferenza con funzionalità di batching, streaming, accelerazione e scaling.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl è un framework open source per il post-training e il fine-tuning, configurato tramite YAML. Supporta tecniche come il fine-tuning completo, LoRA/QLoRA, l'ottimizzazione delle preferenze e il training multi-GPU; non è di per sé una piattaforma di deployment cloud.<sup>[[5]](#references)</sup>

## Provare i modelli online

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** è una piattaforma e community leader per il machine learning, particolarmente nota per il suo lavoro nell'elaborazione del linguaggio naturale (NLP). Fornisce strumenti, librerie e risorse che semplificano lo sviluppo, la condivisione e il deployment dei modelli di machine learning.\
Hub offre diverse sezioni rilevanti:<sup>[[6]](#references)</sup>

* **Models**: Un vasto repository di **modelli di machine learning pre-trained**, in cui gli utenti possono cercare, scaricare e integrare modelli per attività come la generazione di testo, la traduzione, il riconoscimento delle immagini e altro.
* **Datasets:** Una vasta **raccolta di dataset** utilizzati per l'addestramento e la valutazione dei modelli. Facilita l'accesso a diverse fonti di dati, consentendo agli utenti di trovare e utilizzare dati per i propri progetti di machine learning.
* **Spaces:** Una piattaforma per ospitare e condividere **applicazioni interattive di machine learning** e demo. Consente agli sviluppatori di **mostrare** i propri modelli in azione, creare interfacce intuitive e collaborare con altri condividendo demo live.

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** è un repository e una libreria di componenti di modelli addestrati riutilizzabili, in particolare moduli utilizzati tramite TensorFlow/Keras. **Kaggle** fornisce separatamente notebook, dataset, competizioni e modelli.<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules:** Una vasta raccolta di modelli pre-trained e componenti di modelli, in cui gli utenti possono cercare, scaricare e integrare moduli per attività come la classificazione delle immagini, il text embedding e altro.
* **Tutorials:** Guide ed esempi passo passo che aiutano gli utenti a implementare e sottoporre a fine-tuning i modelli utilizzando TensorFlow Hub.
* **Documentation:** Guide complete e riferimenti API che aiutano gli sviluppatori a utilizzare efficacemente le risorse del repository.

## [**Replicate**](https://replicate.com/home)

**Replicate** è una piattaforma hosted per eseguire modelli di machine learning pacchettizzati tramite un'interfaccia web o un'API.<sup>[[8]](#references)</sup>

* **Models:** Un repository di modelli di machine learning forniti dalla community, che gli utenti possono consultare, provare e integrare nelle proprie applicazioni con il minimo sforzo.
* **API access:** API per invocare i modelli dalle applicazioni senza gestire l'infrastruttura di inferenza sottostante.

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
