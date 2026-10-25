# KI in Kuberveiligheid

{{#include ../banners/hacktricks-training.md}}

## Hoofmasjienleeralgoritmes

Die beste beginpunt om oor KI te leer, is om te verstaan hoe die belangrikste masjienleeralgoritmes werk. Dit sal jou help verstaan hoe KI werk, hoe om dit te gebruik en hoe om dit aan te val:


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

Op die volgende bladsy vind jy die grondbeginsels van elke komponent wat nodig is om ’n basiese LLM met transformers te bou:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Modelnutsgoed en platforms

Gebruik die [gids vir KI-modelnutsgoed en platforms](AI-Model-Tools-and-Platforms.md) om modelle te laat loop, te fine-tune, te bedien of uit te toets.

## KI-sekuriteit

### Vertrouensgrense van LLM-gateways

Sien die volgende vir gateway-sekuriteit:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Sekuriteitsmetodologie vir KI-agente

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### KI-risikoraamwerke

Twee nuttige raamwerke om mee te begin wanneer jy KI-stelselrisiko beoordeel, is die OWASP Machine Learning Security Top 10 en Google se Secure AI Framework (SAIF). Hulle vul mekaar aan, maar vorm nie ’n volledige lys van KI-risikoraamwerke nie.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Adversariële aanvalle gelei deur meganistiese interpreteerbaarheid

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### KI-promptsekuriteit

LLM’s het die gebruik van KI die afgelope paar jaar geweldig laat toeneem, maar hulle is nie perfek nie en kan deur adversariële prompts mislei word. Dit is ’n baie belangrike onderwerp om te verstaan hoe om KI veilig te gebruik en hoe om dit aan te val:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE in KI-modelle

Dit is baie algemeen dat ontwikkelaars en maatskappye modelle laat loop wat van die internet afgelaai is. Om ’n model bloot te laai, kan egter genoeg wees om arbitrêre kode op die stelsel uit te voer. Dit is ’n baie belangrike onderwerp om te verstaan hoe om KI veilig te gebruik en hoe om dit aan te val:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### KI-ondersteunde KYC-omseiling

Generatiewe video kan met virtuele-kamera-inspuiting en manipulasie van kamera-API’s gekombineer word om swak KYC-, ouderdomverifikasie- en biometriese lewendigheidskontroles te omseil:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### KI Model Context Protocol

MCP (Model Context Protocol) is ’n oop protokol om KI-toepassings aan nutsmiddels en databronne te koppel. Omdat MCP-bedieners data en aksies kan blootstel, moet assesserings magtiging, toestemming, validering van nutsmiddel-insette en ’n hersiening van vertrouensgrense insluit.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### KI Agent-to-Agent (A2A)-protokol

A2A laat agente toe om mekaar via ’n agentkaart te ontdek en take oor HTTP aan mekaar te stuur. Toets agentkaarte, taakmagtiging, webhook-kennisgewings en uitgebreide kaarte:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Blootgestelde selfgehoste KI-dienste

Identifiseer en toets blootgestelde model runners, agentbouers, ML-demo-UI’s, rekenaarklusters en vektordatabasisse wat sonder verifikasie loop:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### KI-ondersteunde fuzzing en outomatiese kwesbaarheidsontdekking


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### KI-ondersteunde bronhersiening en kwesbaarheidsvalidering

Vir bron-/sinkhersiening, taakvloeie van mobiele toegangspunte, kernelpatroonoudits en bewysgebaseerde validering:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### KI-ondersteunde omgekeerde ingenieurswese

[Gedeeltelike lifting, opsporing van invariant MBA, omgewingsgebonde dekodering en validering van outomatiese ekstrakteerders](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web-black-box-KI-pentesterbots

LLM-aangedrewe agente kan langdurige black-box-webpentesting-werkvloeie outomatiseer wanneer hulle deur waarneembaarheid, orkestrasie, geverifieerde sessiehantering en adversariële validering ondersteun word:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Masjienleersekuriteit Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Veilige KI-raamwerk (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Inleiding](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
