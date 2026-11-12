# IA nella cybersecurity

{{#include ../banners/hacktricks-training.md}}

## Principali algoritmi di machine learning

Il modo migliore per iniziare a imparare l’IA è capire come funzionano i principali algoritmi di machine learning. Questo ti aiuterà a capire come funziona l’IA, come usarla e come attaccarla:


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

Per gli split dei dataset, le metriche classiche e gli attacchi lato risposta alla valutazione basata su LLM, consulta [la preparazione e valutazione dei dati dei modelli](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### Architettura degli LLM

Nella pagina seguente troverai le nozioni di base su ogni componente necessario per creare un LLM di base usando i transformer:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Strumenti e piattaforme per i modelli

Per eseguire, ottimizzare, distribuire o provare i modelli, consulta la [guida agli strumenti e alle piattaforme per i modelli di IA](AI-Model-Tools-and-Platforms.md).

## Sicurezza dell’IA

### Confini di fiducia dei gateway LLM

Per la sicurezza dei gateway, consulta:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Metodologia per la sicurezza degli agenti IA

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Framework di rischio per l’IA

Due utili framework iniziali per valutare il rischio dei sistemi di IA sono OWASP Machine Learning Security Top 10 e Secure AI Framework (SAIF) di Google. Sono complementari e non costituiscono un elenco esaustivo dei framework di rischio per l’IA.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Attacchi avversari guidati dall’interpretabilità meccanicistica

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Sicurezza dei prompt per l’IA

Negli ultimi anni, gli LLM hanno fatto esplodere l’uso dell’IA, ma non sono perfetti e possono essere ingannati con prompt avversari. È un argomento molto importante per capire come usare l’IA in sicurezza e come attaccarla:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE dei modelli di IA

È molto comune che sviluppatori e aziende eseguano modelli scaricati da Internet; tuttavia, il semplice caricamento di un modello potrebbe bastare a eseguire codice arbitrario sul sistema. È un argomento molto importante per capire come usare l’IA in sicurezza e come attaccarla:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Bypass del KYC assistito dall’IA

I video generativi possono essere combinati con l’iniezione di una videocamera virtuale e la manipolazione delle API della videocamera per aggirare procedure deboli di KYC, verifica dell’età e verifica biometrica della vitalità:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol per l’IA

MCP (Model Context Protocol) è un protocollo aperto che permette alle applicazioni di IA di connettersi a strumenti e fonti di dati. Poiché i server MCP possono esporre dati e azioni, le valutazioni devono includere l’autorizzazione, il consenso, la convalida degli input degli strumenti e l’esame dei confini di fiducia.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Protocollo agent-to-agent (A2A) per l’IA

A2A permette agli agenti di scoprirsi a vicenda tramite un agent card e di inviarsi attività tramite HTTP. Testa gli agent card, l’autorizzazione delle attività, i webhook per le notifiche push e gli extended card:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Servizi di IA self-hosted esposti

Fingerprinting e test di model runner esposti, strumenti per creare agenti, interfacce utente per demo di ML, cluster di calcolo e database vettoriali che non richiedono autenticazione:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing assistito dall’IA e rilevamento automatico delle vulnerabilità


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Revisione del codice sorgente e convalida delle vulnerabilità assistite dall’IA

Per l’analisi di sorgenti e sink, i taskflow dei punti di ingresso mobile, gli audit di pattern del kernel e la convalida basata su evidenze:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Reverse engineering assistito dall’IA

[Sollevamento parziale, rilevamento di MBA invarianti, decodifica vincolata all’ambiente e convalida degli estrattori automatici](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bot di pentesting web black-box basati sull’IA

Gli agenti basati su LLM possono automatizzare flussi di lavoro di pentesting web black-box di lunga durata, se supportati da osservabilità, orchestrazione, gestione di sessioni autenticate e convalida avversaria:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introduzione](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
