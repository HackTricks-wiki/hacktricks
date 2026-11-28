# AI nella cybersecurity

{{#include ../banners/hacktricks-training.md}}

## Principali algoritmi di machine learning

Il modo migliore per iniziare a imparare l'AI è capire come funzionano i principali algoritmi di machine learning. Questo ti aiuterà a capire come funziona l'AI, come usarla e come attaccarla:


{{#ref}}
./AI-Supervised-Learning-Algorithms.md
{{#endref}}


{{#ref}}
./AI-Unsupervised-Learning-Algorithms.md
{{#endref}}


{{#ref}}
./AI-Reinforcement-Learning-Algorithms.md
{{#endref}}


{{#ref}}
./AI-Deep-Learning.md
{{#endref}}

### Preparazione e valutazione dei dati dei modelli

Per le suddivisioni dei dataset, le metriche classiche e gli attacchi lato risposta alla valutazione basata su LLM, consulta la guida alla [preparazione e valutazione dei dati dei modelli](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### Architettura degli LLM

Nella pagina seguente troverai le nozioni di base su ogni componente necessario per creare un LLM di base con i transformer:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Strumenti e piattaforme per i modelli

Per eseguire, fare fine-tuning, distribuire o provare i modelli, consulta la [guida agli strumenti e alle piattaforme per i modelli AI](AI-Model-Tools-and-Platforms.md).

## Sicurezza dell'AI

### Confini di fiducia dei gateway LLM

Per la sicurezza dei gateway, consulta:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Metodologia per la sicurezza degli agenti AI

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Framework di rischio per l'AI

Due framework utili da cui partire per valutare i rischi dei sistemi AI sono OWASP Machine Learning Security Top 10 e Secure AI Framework (SAIF) di Google. Sono complementari e non costituiscono un elenco esaustivo dei framework di rischio per l'AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Attacchi adversarial guidati dall'interpretabilità meccanicistica

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Confini di fiducia dei browser integrati

Per i bridge dei browser degli assistenti desktop, lo spoofing degli indirizzi delle schede e la lettura di file locali dal contesto worker, consulta [Confini di fiducia dei browser integrati negli assistenti AI](AI-Embedded-Browser-Trust-Boundaries.md).

### Sicurezza dei prompt AI

Negli ultimi anni gli LLM hanno fatto esplodere l'uso dell'AI, ma non sono perfetti e possono essere ingannati con prompt adversarial. È un argomento molto importante per capire come usare l'AI in sicurezza e come attaccarla:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE nei modelli AI

È molto comune che sviluppatori e aziende eseguano modelli scaricati da Internet; tuttavia, il semplice caricamento di un modello potrebbe bastare per eseguire codice arbitrario sul sistema. È un argomento molto importante per capire come usare l'AI in sicurezza e come attaccarla:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

Per i rischi di caricamento dei modelli Keras `.keras`/HDF5, i layer Lambda e l'analisi dei gadget dopo la correzione, consulta [Deserializzazione dei modelli Keras e ricerca di gadget](keras-model-deserialization-rce-and-gadget-hunting.md).

### Bypass KYC assistito dall'AI

I video generativi possono essere combinati con l'iniezione di videocamere virtuali e la manipolazione delle API della fotocamera per aggirare flussi KYC, di verifica dell'età e di verifica biometrica della vitalità poco robusti:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol per l'AI

MCP (Model Context Protocol) è un protocollo aperto per collegare le applicazioni AI a strumenti e fonti di dati. Poiché i server MCP possono esporre dati e azioni, le valutazioni devono includere autorizzazione, consenso, convalida degli input degli strumenti e revisione dei confini di fiducia.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Protocollo AI Agent-to-Agent (A2A)

A2A consente agli agenti di scoprirsi reciprocamente tramite una scheda agente e di inviarsi attività tramite HTTP. Verifica le schede agente, l'autorizzazione delle attività, i webhook per le notifiche push e le schede estese:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Servizi AI self-hosted esposti

Identificazione e test di runner di modelli, strumenti per creare agenti, interfacce demo ML, cluster di calcolo e database vettoriali esposti e privi di autenticazione:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing assistito dall'AI e individuazione automatizzata delle vulnerabilità


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Analisi del codice sorgente e convalida delle vulnerabilità assistite dall'AI

Per la revisione di sorgenti e sink, i flussi di attività dei punti di ingresso mobile, gli audit di pattern del kernel e la convalida basata su evidenze:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Reverse engineering assistito dall'AI

[Sollevamento parziale, rilevamento di MBA invarianti, decodifica vincolata all'ambiente e convalida di estrattori automatizzati](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bot pentester AI web black-box

Gli agenti basati su LLM possono automatizzare flussi di lavoro prolungati di web pentesting black-box, se supportati da osservabilità, orchestrazione, gestione di sessioni autenticate e convalida adversarial:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP — I 10 principali rischi di sicurezza del machine learning](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Framework di sicurezza per l'AI (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introduzione](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
