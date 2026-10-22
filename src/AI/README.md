# KI in Kuberveiligheid

{{#include ../banners/hacktricks-training.md}}

## Belangrikste Machine Learning-algoritmes

Die beste beginpunt om oor KI te leer, is om te verstaan hoe die belangrikste machine learning-algoritmes werk. Dit sal jou help verstaan hoe KI werk, hoe om dit te gebruik en hoe om dit aan te val:


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

Op die volgende bladsy vind jy die basiese beginsels van elke komponent waarmee jy ’n basiese LLM met transformers kan bou:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Modelgereedskap en -platforms

Gebruik die [gids vir AI-modelgereedskap en -platforms](AI-Model-Tools-and-Platforms.md) om modelle te laat loop, te fine-tune, te bedien of uit te toets.

## KI-sekuriteit

### Vertrouensgrense van LLM-gateways

Vir gateway-sekuriteit, sien:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Sekuriteitsmetodologie vir AI-agente

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### KI-risikoraamwerke

Twee nuttige raamwerke om mee te begin wanneer jy die risiko van KI-stelsels beoordeel, is die OWASP Machine Learning Security Top 10 en Google se Secure AI Framework (SAIF). Hulle vul mekaar aan, maar vorm nie ’n volledige lys van KI-risikoraamwerke nie.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Adversariële aanvalle gelei deur meganistiese interpretasie

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### KI-aanvraagsekuriteit

LLM’s het die gebruik van KI die afgelope jare laat ontplof, maar hulle is nie perfek nie en kan deur adversariële aanvaere mislei word. Dit is ’n baie belangrike onderwerp om te verstaan hoe om KI veilig te gebruik en hoe om dit aan te val:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE in KI-modelle

Dit is baie algemeen dat ontwikkelaars en maatskappye modelle laat loop wat van die Internet afgelaai is. Om ’n model bloot te laai, kan egter genoeg wees om arbitrêre kode op die stelsel uit te voer. Dit is ’n baie belangrike onderwerp om te verstaan hoe om KI veilig te gebruik en hoe om dit aan te val:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### KYC-omseiling met behulp van KI

Generatiewe video kan met virtuele-kamera-inspuiting en manipulasie van kamera-API’s gekombineer word om swak KYC-, ouderdomsverifikasie- en biometriese lewendigheidsprosesse te omseil:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### KI Model Context Protocol

MCP (Model Context Protocol) is ’n oop protokol om KI-toepassings met nutsmiddels en databronne te verbind. Omdat MCP-bedieners data en aksies kan blootstel, moet assesserings magtiging, toestemming, validering van nutsmiddel-invoer en ’n hersiening van vertrouensgrense insluit.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing met KI-hulp en outomatiese kwesbaarheidsontdekking


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Bronkodehersiening met KI-hulp en kwesbaarheidsvalidering

Vir hersiening van bronne en sinks, mobile entry-point-taakvloeie, kernel-patroonoudits en validering met bewysvereistes:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Reverse engineering met KI-hulp

[Partial lifting, opsporing van invariant MBA, omgewingsgebonde dekodering en validering van outomatiese extractors](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web-pentesterbots vir black-box-KI

LLM-aangedrewe agente kan langdurige black-box-web-pentesting-werkvloeie outomatiseer wanneer hulle deur waarneembaarheid, orkestrasie, geverifieerde sessiehantering en adversariële validering ondersteun word:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Inleiding](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
