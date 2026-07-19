# AI nella Cybersecurity

{{#include ../banners/hacktricks-training.md}}

## Principali algoritmi di Machine Learning

Il punto di partenza migliore per imparare a conoscere l'AI è comprendere come funzionano i principali algoritmi di machine learning. Questo ti aiuterà a capire come funziona l'AI, come utilizzarla e come attaccarla:


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

Nella pagina seguente troverai le nozioni di base di ogni componente necessaria per creare un LLM di base utilizzando i transformer:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Sicurezza dell'AI

### Framework per i rischi dell'AI

Al momento, i 2 principali framework per valutare i rischi dei sistemi di AI sono OWASP ML Top 10 e Google SAIF:


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Sicurezza dei prompt dell'AI

Gli LLM hanno fatto esplodere l'utilizzo dell'AI negli ultimi anni, ma non sono perfetti e possono essere ingannati da prompt avversari. Questo è un argomento molto importante per capire come utilizzare l'AI in modo sicuro e come attaccarla:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE dei modelli di AI

È molto comune per sviluppatori e aziende eseguire modelli scaricati da Internet; tuttavia, il semplice caricamento di un modello potrebbe essere sufficiente per eseguire codice arbitrario sul sistema. Questo è un argomento molto importante per capire come utilizzare l'AI in modo sicuro e come attaccarla:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Bypass del KYC assistito dall'AI

I video generativi possono essere combinati con l'iniezione di virtual-camera e la manipolazione delle API della camera per bypassare procedure KYC, di verifica dell'età e di rilevamento della presenza biometrica poco robuste:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) è un protocollo che consente ai client degli agenti AI di connettersi a tool e origini dati esterni in modalità plug-and-play. Ciò abilita workflow complessi e interazioni tra modelli di AI e sistemi esterni:


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing e rilevamento automatizzato delle vulnerabilità assistiti dall'AI


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Bot di pentesting web black-box basati sull'AI

Gli agenti basati su LLM possono automatizzare workflow di pentesting web black-box di lunga durata quando sono supportati da osservabilità, orchestrazione, gestione delle sessioni autenticate e validazione avversaria:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
