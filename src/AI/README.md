# AI nella cybersecurity

{{#include ../banners/hacktricks-training.md}}

## Principali algoritmi di machine learning

Il modo migliore per iniziare a imparare l’AI è capire come funzionano i principali algoritmi di machine learning. Questo ti aiuterà a capire come funziona l’AI, come usarla e come attaccarla:


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

### Preparazione e valutazione dei dati del modello

Per la suddivisione dei dataset, le metriche classiche e gli attacchi sul lato delle risposte alla valutazione basata su LLM, consulta [preparazione e valutazione dei dati del modello](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### Architettura degli LLM

Nella pagina seguente troverai le nozioni di base su ogni componente necessario per costruire un LLM di base usando i transformer:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Strumenti e piattaforme per modelli

Per eseguire, fare fine-tuning, distribuire o provare modelli, consulta la [guida agli strumenti e alle piattaforme per modelli AI](AI-Model-Tools-and-Platforms.md).

## Sicurezza dell’AI

### Confini di fiducia dei gateway LLM

Per la sicurezza dei gateway, consulta:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Metodologia di sicurezza degli agenti AI

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Framework di rischio per l’AI

Due utili framework di riferimento per valutare i rischi dei sistemi AI sono OWASP Machine Learning Security Top 10 e Secure AI Framework (SAIF) di Google. Sono complementari e non costituiscono un elenco esaustivo dei framework di rischio per l’AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Attacchi avversari guidati dall’interpretabilità meccanicistica

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Confini di fiducia dei browser integrati

Per i bridge del browser degli assistenti desktop, lo spoofing dell’indirizzo della scheda e la lettura di file locali dal contesto del worker, consulta [confini di fiducia dei browser integrati degli assistenti AI](AI-Embedded-Browser-Trust-Boundaries.md).

### Sicurezza dei prompt AI

Negli ultimi anni gli LLM hanno portato a una diffusione esponenziale dell’AI, ma non sono perfetti e possono essere ingannati con prompt avversari. È un argomento molto importante per capire come usare l’AI in sicurezza e come attaccarla:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE nei modelli AI

È molto comune che sviluppatori e aziende eseguano modelli scaricati da Internet; tuttavia, il semplice caricamento di un modello può bastare a eseguire codice arbitrario sul sistema. È un argomento molto importante per capire come usare l’AI in sicurezza e come attaccarla:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Bypass KYC assistito dall’AI

I video generativi possono essere combinati con l’iniezione di videocamere virtuali e la manipolazione delle API della videocamera per aggirare procedure deboli di KYC, verifica dell’età e controllo biometrico della vitalità:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol per l’AI

MCP (Model Context Protocol) è un protocollo aperto per connettere applicazioni AI a strumenti e fonti di dati. Poiché i server MCP possono esporre dati e azioni, le valutazioni devono includere autorizzazione, consenso, convalida degli input degli strumenti e revisione dei confini di fiducia.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Protocollo AI Agent-to-Agent (A2A)

A2A consente agli agenti di scoprirsi a vicenda tramite una scheda agente e di inviarsi task tramite HTTP. Verifica le schede agente, l’autorizzazione dei task, i webhook per le notifiche push e le schede estese:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Servizi AI self-hosted esposti

Fingerprinting e test di model runner, agent builder, interfacce demo ML, cluster di calcolo e database vettoriali esposti e privi di autenticazione:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing assistito dall’AI e individuazione automatizzata delle vulnerabilità


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Revisione del codice sorgente e convalida delle vulnerabilità assistite dall’AI

Per la revisione di sorgenti e sink, i taskflow dei punti d’ingresso mobile, gli audit dei pattern del kernel e la convalida basata su evidenze:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Reverse engineering assistito dall’AI

[Sollevamento parziale, rilevamento di MBA invarianti, decodifica vincolata all’ambiente e convalida degli estrattori automatizzati](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bot di pentesting web black-box basati sull’AI

Gli agenti basati su LLM possono automatizzare workflow di pentesting web black-box di lunga durata, se supportati da osservabilità, orchestrazione, gestione di sessioni autenticate e convalida avversaria:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introduzione](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
