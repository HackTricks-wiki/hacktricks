# IA nella cybersecurity

{{#include ../banners/hacktricks-training.md}}

## Principali algoritmi di machine learning

Il modo migliore per iniziare a imparare l’IA è capire come funzionano i principali algoritmi di machine learning. Questo ti aiuterà a comprendere come funziona l’IA, come usarla e come attaccarla:


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

Nella pagina seguente troverai le basi di ogni componente necessario per costruire un LLM di base usando i transformer:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Sicurezza dell’IA

### Metodologia di sicurezza degli agenti IA

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Framework per i rischi dell’IA

Due framework utili per iniziare a valutare i rischi dei sistemi di IA sono OWASP Machine Learning Security Top 10 e Secure AI Framework (SAIF) di Google. Sono complementari e non costituiscono un elenco esaustivo dei framework per i rischi dell’IA.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Sicurezza dei prompt per l’IA

Negli ultimi anni, gli LLM hanno fatto esplodere l’uso dell’IA, ma non sono perfetti e possono essere ingannati con prompt avversari. È un argomento molto importante per capire come usare l’IA in sicurezza e come attaccarla:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE nei modelli di IA

È molto comune che sviluppatori e aziende eseguano modelli scaricati da Internet; tuttavia, il semplice caricamento di un modello potrebbe bastare a eseguire codice arbitrario sul sistema. È un argomento molto importante per capire come usare l’IA in sicurezza e come attaccarla:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Bypass del KYC assistito dall’IA

I video generativi possono essere combinati con l’iniezione di una virtual camera e la manipolazione delle API della fotocamera per aggirare procedure KYC, di verifica dell’età e di liveness biometrica poco robuste:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol per l’IA

MCP (Model Context Protocol) è un protocollo aperto che collega le applicazioni di IA a strumenti e fonti di dati. Poiché i server MCP possono esporre dati e azioni, le valutazioni devono includere autorizzazioni, consenso, convalida degli input degli strumenti e analisi dei confini di fiducia.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing e individuazione automatizzata delle vulnerabilità assistiti dall’IA


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Reverse engineering assistito dall’IA

[Sollevamento parziale, rilevamento di invarianti MBA, decodifica vincolata all’ambiente e convalida degli estrattori automatici](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bot di pentesting web black-box con IA

Gli agenti basati su LLM possono automatizzare flussi di lavoro di pentesting web black-box di lunga durata se supportati da osservabilità, orchestrazione, gestione di sessioni autenticate e convalida avversaria:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Top 10 sulla sicurezza del machine learning](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Framework di sicurezza per l’IA (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introduzione](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
