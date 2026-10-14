# AI nella cybersecurity

{{#include ../banners/hacktricks-training.md}}

## Principali algoritmi di Machine Learning

Il modo migliore per iniziare a imparare l'AI è capire come funzionano i principali algoritmi di Machine Learning. Questo ti aiuterà a capire come funziona l'AI, come usarla e come attaccarla:


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

Nella pagina seguente troverai le basi di ciascun componente necessario per creare un LLM di base usando i transformer:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Strumenti e piattaforme per modelli

Per eseguire, fare fine-tuning, distribuire o provare i modelli, consulta la [guida agli strumenti e alle piattaforme per modelli AI](AI-Model-Tools-and-Platforms.md).

## Sicurezza dell'AI

### Metodologia di sicurezza degli agenti AI

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Framework per i rischi dell'AI

Due framework utili da cui partire per valutare i rischi dei sistemi AI sono OWASP Machine Learning Security Top 10 e Secure AI Framework (SAIF) di Google. Sono complementari e non costituiscono un elenco esaustivo dei framework per i rischi dell'AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Attacchi adversarial guidati dall'interpretabilità meccanicistica

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Sicurezza dei prompt AI

Negli ultimi anni gli LLM hanno reso l'uso dell'AI sempre più diffuso, ma non sono perfetti e possono essere ingannati con prompt adversarial. È un argomento molto importante per capire come usare l'AI in modo sicuro e come attaccarla:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE nei modelli AI

È molto comune che sviluppatori e aziende eseguano modelli scaricati da Internet; tuttavia, il semplice caricamento di un modello potrebbe bastare a eseguire codice arbitrario sul sistema. È un argomento molto importante per capire come usare l'AI in modo sicuro e come attaccarla:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Bypass KYC assistito dall'AI

I video generati possono essere combinati con l'iniezione di virtual camera e la manipolazione delle API della camera per aggirare procedure KYC, di verifica dell'età e di verifica biometrica della vitalità poco robuste:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol per l'AI

MCP (Model Context Protocol) è un protocollo aperto che consente alle applicazioni AI di connettersi a strumenti e fonti di dati. Poiché i server MCP possono esporre dati e azioni, le valutazioni devono includere l'autorizzazione, il consenso, la convalida degli input degli strumenti e l'analisi dei confini di fiducia.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing assistito dall'AI e individuazione automatizzata delle vulnerabilità


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Reverse engineering assistito dall'AI

[Sollevamento parziale, rilevamento di invarianti MBA, decodifica vincolata all'ambiente e convalida degli estrattori automatici](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bot di pentester AI web black-box

Gli agenti basati su LLM possono automatizzare workflow di pentesting web black-box di lunga durata, se supportati da osservabilità, orchestrazione, gestione delle sessioni autenticate e convalida adversarial:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Top 10 sulla sicurezza del Machine Learning](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Framework per l'AI sicura (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introduzione](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
