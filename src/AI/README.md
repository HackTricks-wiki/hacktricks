# AI nella Cybersecurity

{{#include ../banners/hacktricks-training.md}}

## Principali algoritmi di Machine Learning

Il punto di partenza migliore per imparare a conoscere l'AI è comprendere come funzionano i principali algoritmi di Machine Learning. Questo ti aiuterà a capire come funziona l'AI, come utilizzarla e come attaccarla:


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

Nella pagina seguente troverai le basi di ogni componente necessario per costruire un LLM di base utilizzando i transformer:


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

È molto comune per gli sviluppatori e le aziende eseguire modelli scaricati da Internet; tuttavia, il semplice caricamento di un modello potrebbe essere sufficiente per eseguire codice arbitrario sul sistema. Questo è un argomento molto importante per capire come utilizzare l'AI in modo sicuro e come attaccarla:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Model Context Protocol dell'AI

MCP (Model Context Protocol) è un protocollo che consente ai client degli agenti di AI di connettersi a strumenti e origini dati esterni in modalità plug-and-play. Questo abilita workflow complessi e interazioni tra i modelli di AI e i sistemi esterni:


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing assistito dall'AI e scoperta automatizzata delle vulnerabilità


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Bot di AI per il pentesting Web Black-Box

Gli agenti basati su LLM possono automatizzare workflow di pentesting Web black-box di lunga durata quando sono supportati da osservabilità, orchestrazione, gestione delle sessioni autenticate e validazione avversaria:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
