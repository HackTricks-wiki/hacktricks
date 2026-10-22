# L'IA nella cybersecurity

{{#include ../banners/hacktricks-training.md}}

## Principali algoritmi di machine learning

Il modo migliore per iniziare a conoscere l'IA è capire come funzionano i principali algoritmi di machine learning. Questo ti aiuterà a comprendere come funziona l'IA, come usarla e come attaccarla:


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

Nella pagina seguente troverai le basi di ogni componente necessario per creare un LLM di base usando i transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Strumenti e piattaforme per i modelli

Per eseguire, fare fine-tuning, distribuire o provare i modelli, consulta la [guida agli strumenti e alle piattaforme per i modelli di IA](AI-Model-Tools-and-Platforms.md).

## Sicurezza dell'IA

### Confini di fiducia dei gateway LLM

Per la sicurezza dei gateway, consulta:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Metodologia per la sicurezza degli agenti di IA

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Framework per i rischi dell'IA

Due framework utili da cui partire per valutare i rischi dei sistemi di IA sono OWASP Machine Learning Security Top 10 e Secure AI Framework (SAIF) di Google. Sono complementari e non costituiscono un elenco esaustivo dei framework per la valutazione dei rischi dell'IA.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Attacchi avversari guidati dall'interpretabilità meccanicistica

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Sicurezza dei prompt per l'IA

Negli ultimi anni, gli LLM hanno fatto esplodere l'uso dell'IA, ma non sono perfetti e possono essere ingannati con prompt avversari. È un argomento molto importante per capire come usare l'IA in modo sicuro e come attaccarla:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE nei modelli di IA

È molto comune che sviluppatori e aziende eseguano modelli scaricati da Internet; tuttavia, il semplice caricamento di un modello potrebbe bastare a eseguire codice arbitrario sul sistema. È un argomento molto importante per capire come usare l'IA in modo sicuro e come attaccarla:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Bypass del KYC assistito dall'IA

I video generativi possono essere combinati con l'iniezione di virtual camera e la manipolazione delle API della fotocamera per aggirare procedure KYC, di verifica dell'età e di rilevamento biometrico della presenza in tempo reale poco robuste:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol per l'IA

MCP (Model Context Protocol) è un protocollo aperto che consente alle applicazioni di IA di connettersi a strumenti e fonti di dati. Poiché i server MCP possono esporre dati e azioni, le valutazioni devono includere autorizzazioni, consenso, convalida degli input degli strumenti e verifica dei confini di fiducia.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing e individuazione automatizzata delle vulnerabilità assistiti dall'IA


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Revisione del codice sorgente e convalida delle vulnerabilità assistite dall'IA

Per la revisione di source/sink, i taskflow dei punti di ingresso mobile, gli audit dei pattern del kernel e la convalida basata su evidenze:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Reverse engineering assistito dall'IA

[Sollevamento parziale del codice, rilevamento di MBA invarianti, decodifica vincolata all'ambiente e convalida di estrattori automatizzati](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bot di pentesting web black-box basati sull'IA

Gli agenti basati su LLM possono automatizzare workflow di pentesting web black-box di lunga durata, se supportati da osservabilità, orchestrazione, gestione di sessioni autenticate e convalida avversaria:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [I 10 principali rischi di sicurezza del machine learning secondo OWASP](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Framework per un'IA sicura (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introduzione](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
