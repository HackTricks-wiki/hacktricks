# KI in kuberveiligheid

{{#include ../banners/hacktricks-training.md}}

## Hoofmasjienleer-algoritmes

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

### Modeldata-voorbereiding en -evaluering

Vir datastelverdelings, klassieke metrieke en aanvalle vanaf die antwoordkant op LLM-gebaseerde gradering, sien [modeldata-voorbereiding en -evaluering](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### LLM-argitektuur

Op die volgende bladsy vind jy die grondbeginsels van elke komponent wat nodig is om ’n basiese LLM met transformers te bou:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Modelnutsgoed en -platforms

Gebruik die [gids vir KI-modelnutsgoed en -platforms](AI-Model-Tools-and-Platforms.md) om modelle te laat loop, te verfyn, te bedien of uit te probeer.

## KI-sekuriteit

### LLM Gateway-trustgrense

Sien die volgende vir gateway-sekuriteit:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Sekuriteitsmetodologie vir KI-agente

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### KI-risikoraamwerke

Twee nuttige raamwerke om KI-stelselrisiko te beoordeel, is die OWASP Machine Learning Security Top 10 en Google se Secure AI Framework (SAIF). Hulle vul mekaar aan, maar vorm nie ’n volledige lys van KI-risikoraamwerke nie.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Adversariële aanvalle gelei deur meganistiese interpreteerbaarheid

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Sekuriteit van KI-prompts

Die gebruik van KI het die afgelope paar jaar ontplof danksy LLM’s, maar hulle is nie perfek nie en kan met adversariële prompts mislei word. Dit is ’n baie belangrike onderwerp om te verstaan hoe om KI veilig te gebruik en hoe om dit aan te val:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE in KI-modelle

Dit is baie algemeen dat ontwikkelaars en maatskappye modelle laat loop wat van die internet afgelaai is. Dit kan egter genoeg wees om arbitrêre kode op die stelsel uit te voer deur bloot ’n model te laai. Dit is ’n baie belangrike onderwerp om te verstaan hoe om KI veilig te gebruik en hoe om dit aan te val:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### KI-ondersteunde KYC-omseiling

Generatiewe video kan met virtuele-kamera-inspuiting en manipulasie van die kamera-API gekombineer word om swak KYC-, ouderdomsverifikasie- en biometriese liveness-werkvloeie te omseil:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### KI Model Context Protocol

MCP (Model Context Protocol) is ’n oop protokol om KI-toepassings met nutsgoed en databronne te verbind. Omdat MCP-bedieners data en aksies kan blootstel, moet assesserings magtiging, toestemming, validering van nutsdinginvoer en ’n hersiening van trustgrense insluit.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### KI Agent-to-Agent (A2A)-protokol

A2A laat agente toe om mekaar deur ’n agent card te ontdek en take oor HTTP aan mekaar te stuur. Toets agent cards, taakmagtiging, webhooks vir stootkennisgewings en uitgebreide cards:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Blootgestelde selfgehuisveste KI-dienste

Vingerafdrukke neem en toets model runners, agent builders, ML-demo-UI’s, rekenaarklusters en vektordatabasisse wat sonder verifikasie loop:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### KI-ondersteunde fuzzing en outomatiese kwesbaarheidsontdekking


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### KI-ondersteunde bronkodehersiening en kwesbaarheidsvalidering

Vir hersiening van bronne/sinks, taakvloeie vir mobiele toegangspunte, oudits van kernpatrone en validering wat deur bewyse vereis word:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### KI-ondersteunde reverse engineering

[Gedeeltelike lifting, opsporing van invariant MBA, omgewingsgebonde dekodering en validering van outomatiese extractors](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web-black-box-KI-pentesterbots

LLM-aangedrewe agente kan langdurige black-box-web-pentesting-werkvloeie outomatiseer wanneer hulle deur waarneembaarheid, orkestrering, geverifieerde sessiehantering en adversariële validering ondersteun word:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP Masjienleer-sekuriteit Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Veilige KI-raamwerk (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Inleiding](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
