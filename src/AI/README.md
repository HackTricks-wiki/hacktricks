# AI nella Cybersecurity

{{#include ../banners/hacktricks-training.md}}

## Principali algoritmi di Machine Learning

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

### Architettura degli LLM

Nella pagina seguente troverai le nozioni di base su ogni componente necessario per creare un LLM di base usando i transformer:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Sicurezza dell’AI

### Metodologia di sicurezza degli AI Agent

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Framework per la valutazione dei rischi dell’AI

Due framework utili da cui iniziare per valutare i rischi dei sistemi AI sono OWASP Machine Learning Security Top 10 e Google Secure AI Framework (SAIF). Sono complementari e non costituiscono un elenco esaustivo dei framework per la valutazione dei rischi dell’AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Attacchi avversari guidati dall’interpretabilità meccanicistica

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Sicurezza dei prompt AI

Negli ultimi anni gli LLM hanno fatto esplodere l’uso dell’AI, ma non sono perfetti e possono essere ingannati con prompt avversari. È un argomento molto importante per capire come usare l’AI in sicurezza e come attaccarla:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE dei modelli AI

È molto comune che sviluppatori e aziende eseguano modelli scaricati da Internet; tuttavia, il semplice caricamento di un modello potrebbe bastare per eseguire codice arbitrario sul sistema. È un argomento molto importante per capire come usare l’AI in sicurezza e come attaccarla:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Bypass KYC assistito dall’AI

I video generativi possono essere combinati con l’iniezione di una videocamera virtuale e la manipolazione delle API della videocamera per aggirare procedure deboli di KYC, verifica dell’età e verifica della vitalità biometrica:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol dell’AI

MCP (Model Context Protocol) è un protocollo aperto che consente di collegare applicazioni AI a strumenti e fonti di dati. Poiché i server MCP possono esporre dati e azioni, le valutazioni devono includere autorizzazione, consenso, convalida degli input degli strumenti e revisione dei confini di fiducia.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing assistito dall’AI e rilevamento automatico delle vulnerabilità


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Reverse engineering assistito dall’AI

[Sollevamento parziale, rilevamento di MBA invarianti, decodifica vincolata all’ambiente e convalida degli estrattori automatici](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bot pentester AI black-box per il web

Gli agenti basati su LLM possono automatizzare flussi di lavoro prolungati di pentesting web black-box se supportati da osservabilità, orchestrazione, gestione di sessioni autenticate e convalida avversaria:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP: i 10 principali rischi di sicurezza del Machine Learning](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Framework per un’AI sicura (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introduzione](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
