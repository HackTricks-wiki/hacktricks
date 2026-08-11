# AI nella Cybersecurity

{{#include ../banners/hacktricks-training.md}}

## Principali algoritmi di Machine Learning

Il modo migliore per iniziare a conoscere l'AI è comprendere come funzionano i principali algoritmi di machine learning. Questo ti aiuterà a capire come funziona l'AI, come utilizzarla e come attaccarla:


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

Nella pagina seguente troverai le nozioni di base di ogni componente necessario per costruire un LLM di base utilizzando i transformer:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Sicurezza dell'AI

### Framework per i rischi dell'AI

Due framework utili da cui iniziare per valutare i rischi dei sistemi di AI sono l'OWASP Machine Learning Security Top 10 e il Secure AI Framework (SAIF) di Google. Sono complementari e non costituiscono un elenco esaustivo dei framework per i rischi dell'AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Sicurezza dei prompt dell'AI

Negli ultimi anni gli LLM hanno fatto esplodere l'utilizzo dell'AI, ma non sono perfetti e possono essere ingannati da prompt avversari. Questo è un argomento molto importante per capire come utilizzare l'AI in modo sicuro e come attaccarla:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE dei modelli di AI

È molto comune che sviluppatori e aziende eseguano modelli scaricati da Internet; tuttavia, il semplice caricamento di un modello potrebbe essere sufficiente per eseguire codice arbitrario sul sistema. Questo è un argomento molto importante per capire come utilizzare l'AI in modo sicuro e come attaccarla:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Bypass del KYC assistito dall'AI

I video generativi possono essere combinati con l'iniezione di virtual camera e la manipolazione delle API della camera per aggirare workflow deboli di KYC, verifica dell'età e liveness biometrica:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol dell'AI

MCP (Model Context Protocol) è un protocollo aperto per collegare applicazioni di AI a tool e fonti di dati. Poiché i server MCP possono esporre dati e azioni, le valutazioni devono includere autorizzazione, consenso, validazione degli input dei tool e revisione dei trust boundary.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing assistito dall'AI e ricerca automatizzata delle vulnerabilità


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Bot di Pentesting Web black-box assistiti dall'AI

Gli agenti basati su LLM possono automatizzare workflow di pentesting web black-box di lunga durata quando sono supportati da osservabilità, orchestrazione, gestione delle sessioni autenticate e validazione avversaria:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introduzione](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
