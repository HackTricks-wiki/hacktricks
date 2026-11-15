# AI in kuberveiligheid

{{#include ../banners/hacktricks-training.md}}

## Hoofmasjienleeralgoritmes

Die beste beginpunt om oor AI te leer, is om te verstaan hoe die belangrikste masjienleeralgoritmes werk. Dit sal jou help verstaan hoe AI werk, hoe om dit te gebruik en hoe om dit aan te val:


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

Vir datastelverdelings, klassieke metrieke en aanvalle op die antwoordkant van LLM-gebaseerde gradering, sien [modeldata-voorbereiding en -evaluering](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### LLM-argitektuur

Op die volgende bladsy vind jy die basiese beginsels van elke komponent om ’n basiese LLM met transformers te bou:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Modelnutsgoed en -platforms

Gebruik die [gids vir AI-modelnutsgoed en -platforms](AI-Model-Tools-and-Platforms.md) om modelle te laat loop, fyn in te stel, beskikbaar te stel of uit te probeer.

## AI-sekuriteit

### LLM-gateway-vertrouensgrense

Vir gateway-sekuriteit, sien:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Sekuriteitsmetodologie vir AI-agente

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AI-risikoraamwerke

Twee nuttige beginraamwerke om die risiko van AI-stelsels te beoordeel, is die OWASP Machine Learning Security Top 10 en Google se Secure AI Framework (SAIF). Hulle vul mekaar aan en is nie ’n volledige lys van AI-risikoraamwerke nie.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Meganiese-interpreteerbaarheidsgerigte adversariële aanvalle

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Vertrouensgrense van ingebedde blaaiers

Vir blaaierbrûe van lessenaartoepassingsassistente, vervalsing van oortjieadresse en lees van plaaslike lêers vanuit werkerkontekste, sien [vertrouensgrense van ingebedde blaaiers in AI-assistente](AI-Embedded-Browser-Trust-Boundaries.md).

### Sekuriteit van AI-aanwysings

LLM’s het die gebruik van AI die afgelope jare geweldig laat toeneem, maar hulle is nie perfek nie en kan deur adversariële aanwysings mislei word. Dit is ’n baie belangrike onderwerp om te verstaan hoe om AI veilig te gebruik en hoe om dit aan te val:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE in AI-modelle

Dit is baie algemeen dat ontwikkelaars en maatskappye modelle laat loop wat van die internet afgelaai is. Om ’n model bloot te laai, kan egter genoeg wees om arbitrêre kode op die stelsel uit te voer. Dit is ’n baie belangrike onderwerp om te verstaan hoe om AI veilig te gebruik en hoe om dit aan te val:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### KYC-omseiling met behulp van AI

Generatiewe video kan met virtuele-kamera-inspuiting en manipulasie van die kamera-API gekombineer word om swak KYC-, ouderdomsverifikasie- en biometriese lewendigheidskontroles te omseil:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) is ’n oop protokol om AI-toepassings aan nutsmiddels en databronne te koppel. Omdat MCP-bedieners data en aksies kan blootstel, moet sekuriteitsbeoordelings magtiging, toestemming, validering van nutsmiddel-invoer en ’n hersiening van vertrouensgrense insluit.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI Agent-to-Agent (A2A)-protokol

A2A laat agente toe om mekaar deur middel van ’n agentkaart te ontdek en take oor HTTP aan mekaar te stuur. Toets agentkaarte, taakmagtiging, webhooke vir stootkennisgewings en uitgebreide kaarte:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Blootgestelde selfgehoste AI-dienste

Vingerafdrukke neem en toets model-lanseerders, agentbouers, ML-demo-koppelvlakke, rekenaarklusters en vektordatabasisse wat sonder verifikasie loop:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### AI-ondersteunde fuzzing en outomatiese kwesbaarheidsontdekking


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AI-ondersteunde bronkodehersiening en kwesbaarheidsvalidering

Vir bron-/sink-hersiening, mobiele toegangspunt-taakvloeie, kernpatroonoudits en bewysgebaseerde validering:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### AI-ondersteunde reverse engineering

[Gedeeltelike lifting, opsporing van invariant MBA, omgewingsgebonde dekodering en validering van outomatiese ekstraksie](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web-pentesterbots met AI vir black-box-toetsing

LLM-aangedrewe agente kan langdurige black-box-webpentesting-werkvloeie outomatiseer wanneer hulle deur waarneembaarheid, orkestrering, geverifieerde sessiehantering en adversariële validering ondersteun word:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP se Top 10 vir masjienleersekuriteit](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Veilige AI-raamwerk (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Inleiding](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
