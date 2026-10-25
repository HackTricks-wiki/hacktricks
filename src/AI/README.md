# AI nella cybersecurity

{{#include ../banners/hacktricks-training.md}}

## Principali algoritmi di machine learning

Il modo migliore per iniziare a imparare l’AI è capire come funzionano i principali algoritmi di machine learning. Questo ti aiuterà a comprendere come funziona l’AI, come usarla e come attaccarla:


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

### Architettura degli LLM

Nella pagina seguente troverai le basi di ogni componente necessario per creare un LLM di base usando i transformer:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Strumenti e piattaforme per i modelli

Per eseguire, fare fine-tuning, distribuire o provare i modelli, consulta la [guida agli strumenti e alle piattaforme per i modelli AI](AI-Model-Tools-and-Platforms.md).

## Sicurezza dell’AI

### Confini di fiducia dei gateway LLM

Per la sicurezza dei gateway, consulta:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Metodologia per la sicurezza degli agenti AI

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Framework per i rischi dell’AI

Due utili framework iniziali per valutare i rischi dei sistemi AI sono l’OWASP Machine Learning Security Top 10 e il Secure AI Framework (SAIF) di Google. Si completano a vicenda, ma non costituiscono un elenco esaustivo dei framework per i rischi dell’AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Attacchi avversari guidati dall’interpretabilità meccanicistica

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Sicurezza dei prompt AI

Negli ultimi anni, gli LLM hanno fatto esplodere l’uso dell’AI, ma non sono perfetti e possono essere ingannati con prompt avversari. È un argomento molto importante per capire come usare l’AI in modo sicuro e come attaccarla:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE nei modelli AI

È molto comune che sviluppatori e aziende eseguano modelli scaricati da Internet; tuttavia, il semplice caricamento di un modello potrebbe bastare a eseguire codice arbitrario sul sistema. È un argomento molto importante per capire come usare l’AI in modo sicuro e come attaccarla:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Bypass KYC assistito dall’AI

I video generativi possono essere combinati con l’iniezione di una videocamera virtuale e la manipolazione delle API della fotocamera per aggirare flussi KYC, di verifica dell’età e di rilevamento biometrico della vitalità poco robusti:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Protocollo Model Context dell’AI

MCP (Model Context Protocol) è un protocollo aperto per collegare applicazioni AI a strumenti e fonti di dati. Poiché i server MCP possono esporre dati e consentire azioni, le valutazioni devono includere autorizzazione, consenso, convalida degli input degli strumenti e verifica dei confini di fiducia.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Protocollo AI Agent-to-Agent (A2A)

A2A consente agli agenti di individuarsi tramite una scheda agente e di scambiarsi attività via HTTP. Verifica le schede agente, l’autorizzazione delle attività, i webhook per le notifiche push e le schede estese:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Servizi AI self-hosted esposti

Identificazione e test di model runner, agent builder, interfacce utente per demo ML, cluster di calcolo e database vettoriali esposti e privi di autenticazione:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing assistito dall’AI e rilevamento automatico delle vulnerabilità


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Revisione del codice sorgente e convalida delle vulnerabilità assistite dall’AI

Per la revisione di sorgenti e sink, i flussi delle attività sui punti di ingresso mobile, gli audit dei pattern del kernel e la convalida basata su evidenze:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Reverse engineering assistito dall’AI

[Sollevamento parziale, rilevamento di MBA invarianti, decodifica vincolata all’ambiente e convalida degli estrattori automatici](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bot pentester AI web black-box

Gli agenti basati su LLM possono automatizzare flussi di lavoro di pentesting web black-box di lunga durata, se supportati da osservabilità, orchestrazione, gestione di sessioni autenticate e convalida avversaria:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Framework per un’AI sicura (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introduzione](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
