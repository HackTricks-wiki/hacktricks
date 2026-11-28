# KI in kuberveiligheid

{{#include ../banners/hacktricks-training.md}}

## Hoofmasjienleer-algoritmes

Die beste beginpunt om oor KI te leer, is om te verstaan hoe die belangrikste masjienleer-algoritmes werk. Dit sal jou help om te verstaan hoe KI werk, hoe om dit te gebruik en hoe om dit aan te val:


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

Vir datastelverdelings, klassieke maatstawwe en aanvalle aan die antwoordkant op LLM-gebaseerde gradering, sien [modeldata-voorbereiding en -evaluering](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### LLM-argitektuur

Op die volgende bladsy vind jy die grondbeginsels van elke komponent om ’n basiese LLM met transformers te bou:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Modelnutsgoed en -platforms

Gebruik die [gids vir KI-modelnutsgoed en -platforms](AI-Model-Tools-and-Platforms.md) om modelle te laat loop, fyn af te stel, te bedien of uit te probeer.

## KI-sekuriteit

### LLM Gateway Trust Boundaries

Vir gateway-sekuriteit, sien:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Sekuriteitsmetodologie vir KI-agente

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### KI-risikoraamwerke

Twee nuttige beginraamwerke om KI-stelselrisiko te beoordeel, is die OWASP Machine Learning Security Top 10 en Google se Secure AI Framework (SAIF). Hulle vul mekaar aan en is nie ’n volledige lys van KI-risikoraamwerke nie.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Mechanistic-Interpretability-Guided Adversarial Attacks

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Vertrouensgrense van ingebedde blaaiers

Vir blaaierbrûe van rekenaargasistantse, tab-adresspoofing en lees van plaaslike lêers vanuit worker-konteks, sien [vertrouensgrense van ingebedde blaaiers in KI-assistente](AI-Embedded-Browser-Trust-Boundaries.md).

### Sekuriteit van KI-prompts

LLM’s het die gebruik van KI die afgelope paar jaar laat ontplof, maar hulle is nie perfek nie en kan deur adversariële prompts mislei word. Dit is ’n baie belangrike onderwerp om te verstaan hoe om KI veilig te gebruik en hoe om dit aan te val:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE in KI-modelle

Dit is baie algemeen dat ontwikkelaars en maatskappye modelle laat loop wat van die internet afgelaai is; die blote laai van ’n model kan egter genoeg wees om arbitrêre kode op die stelsel uit te voer. Dit is ’n baie belangrike onderwerp om te verstaan hoe om KI veilig te gebruik en hoe om dit aan te val:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

Vir risiko’s met die laai van Keras `.keras`/HDF5-modelle, Lambda-lae en gadget-ontleding ná regstellings, sien [Keras-modeldeserialisering en gadget-soektog](keras-model-deserialization-rce-and-gadget-hunting.md).

### KI-ondersteunde KYC-omseiling

Generatiewe video kan gekombineer word met virtuele-kamera-inspuiting en manipulering van kamera-API’s om swak KYC-, ouderdomsverifikasie- en biometriese lewendigheidsprosesse te omseil:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### KI Model Context Protocol

MCP (Model Context Protocol) is ’n oop protokol om KI-toepassings aan nutsgoed en databronne te koppel. Omdat MCP-bedieners data en aksies kan blootstel, moet assesserings magtiging, toestemming, validering van nutsdinginvoer en ’n hersiening van vertrouensgrense insluit.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### KI Agent-to-Agent (A2A)-protokol

A2A laat agente toe om mekaar via ’n agentkaart te ontdek en take oor HTTP aan mekaar te stuur. Toets agentkaarte, taakmagtiging, webhook’e vir stootkennisgewings en uitgebreide kaarte:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Blootgestelde selfgehoste KI-dienste

Vingerafdruk en toets blootgestelde model-lopers, agentbouers, ML-demonstrasie-UI’s, rekenaarklusters en vektordatabasisse wat sonder verifikasie loop:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### KI-ondersteunde fuzzing en outomatiese kwesbaarheidsontdekking


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### KI-ondersteunde bronkodehersiening en kwesbaarheidsvalidering

Vir bron-/sinkhersiening, taakvloeie van mobiele toegangspunte, patroonoudits van kerne en bewysgebonde validering:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### KI-ondersteunde reverse engineering

[Partiële lifting, opsporing van invariansie-MBA, omgewingsgebonde dekodering en validering van outomatiese ekstrakteerders](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Bots

LLM-aangedrewe agente kan langlopende black-box-webpentestingwerkvloeie outomatiseer wanneer hulle ondersteun word deur waarneembaarheid, orkestrering, geverifieerde sessiehantering en adversariële validering:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP Masjienleersekuriteit Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Veilige KI-raamwerk (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Inleiding](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
