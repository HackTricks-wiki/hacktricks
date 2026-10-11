# KI in Kuberveiligheid

{{#include ../banners/hacktricks-training.md}}

## Belangrikste masjienleer-algoritmes

Die beste beginpunt om oor KI te leer, is om te verstaan hoe die belangrikste masjienleer-algoritmes werk. Dit sal jou help verstaan hoe KI werk, hoe om dit te gebruik en hoe om dit aan te val:


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

### LLM-argitektuur

Op die volgende bladsy vind jy die basiese beginsels van elke komponent wat nodig is om ’n eenvoudige LLM met transformers te bou:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## KI-sekuriteit

### Sekuriteitsmetodologie vir KI-agente

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### KI-risikoraamwerke

Twee nuttige raamwerke om mee te begin wanneer KI-stelselrisiko beoordeel word, is die OWASP Machine Learning Security Top 10 en Google se Secure AI Framework (SAIF). Hulle vul mekaar aan en is nie ’n volledige lys van KI-risikoraamwerke nie.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Sekuriteit van KI-prompts

LLMs het die gebruik van KI die afgelope jare laat ontplof, maar hulle is nie perfek nie en kan deur adversarial prompts mislei word. Dit is ’n baie belangrike onderwerp om te verstaan hoe om KI veilig te gebruik en hoe om dit aan te val:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE in KI-modelle

Dit is baie algemeen dat ontwikkelaars en maatskappye modelle gebruik wat van die internet afgelaai is. Om ’n model bloot te laai, kan egter genoeg wees om arbitrêre kode op die stelsel uit te voer. Dit is ’n baie belangrike onderwerp om te verstaan hoe om KI veilig te gebruik en hoe om dit aan te val:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### KI-ondersteunde KYC-omseiling

Generatiewe video kan gekombineer word met virtuele-kamera-inspuiting en manipulasie van kamera-API’s om swak KYC-, ouderdomsverifikasie- en biometriese lewendigheidskontroles te omseil:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### KI Model Context Protocol

MCP (Model Context Protocol) is ’n oop protokol om KI-toepassings met nutsgoed en databronne te verbind. Omdat MCP-bedieners data en aksies kan blootstel, moet assesserings magtiging, toestemming, validering van nutsdinginvoer en ’n hersiening van vertrouensgrense insluit.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### KI-ondersteunde fuzzing en outomatiese kwesbaarheidsontdekking


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### KI-ondersteunde reverse engineering

[Partiële lifting, opsporing van invariant MBA, omgewingsgebonde dekodering en validering van outomatiese onttrekkers](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester-bots

LLM-aangedrewe agente kan langdurige black-box-web-pentesting-werkvloeie outomatiseer wanneer hulle deur waarneembaarheid, orkestrasie, geverifieerde sessiehantering en adversarial validering ondersteun word:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Top 10 vir Masjienleer-sekuriteit](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Veilige KI-raamwerk (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Inleiding](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
