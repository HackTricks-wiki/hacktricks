# AI in Kuberveiligheid

{{#include ../banners/hacktricks-training.md}}

## Belangrikste Machine Learning-algoritmes

Die beste beginpunt om oor AI te leer, is om te verstaan hoe die belangrikste machine learning-algoritmes werk. Dit sal jou help verstaan hoe AI werk, hoe om dit te gebruik en hoe om dit aan te val:


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

Op die volgende bladsy vind jy die basiese beginsels van elke komponent wat nodig is om ’n basiese LLM met transformers te bou:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Modelgereedskap en -platforms

Gebruik die [gids vir AI-modelgereedskap en -platforms](AI-Model-Tools-and-Platforms.md) om modelle uit te voer, te fyninstel, te bedien of uit te probeer.

## AI-sekuriteit

### AI Agent-sekuriteitsmetodologie

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AI-risikoraamwerke

Twee nuttige beginraamwerke om AI-stelselrisiko te beoordeel, is die OWASP Machine Learning Security Top 10 en Google se Secure AI Framework (SAIF). Hulle vul mekaar aan, maar is nie ’n volledige lys van AI-risikoraamwerke nie.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Adversarial Attacks gelei deur meganistiese interpreteerbaarheid

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### AI-promptsekuriteit

LLMs het die gebruik van AI die afgelope jare laat ontplof, maar hulle is nie perfek nie en kan deur adversarial prompts mislei word. Dit is ’n baie belangrike onderwerp om te verstaan hoe om AI veilig te gebruik en hoe om dit aan te val:


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI-modelle RCE

Dit is baie algemeen dat ontwikkelaars en maatskappye modelle uitvoer wat van die internet afgelaai is. Om ’n model bloot te laai, kan egter genoeg wees om arbitrêre kode op die stelsel uit te voer. Dit is ’n baie belangrike onderwerp om te verstaan hoe om AI veilig te gebruik en hoe om dit aan te val:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI-ondersteunde KYC-omseiling

Generatiewe video kan met virtuele-kamera-inspuiting en manipulasie van die kamera-API gekombineer word om swak KYC-, ouderdomsverifikasie- en biometriese lewendigheidskontroles te omseil:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) is ’n oop protokol om AI-toepassings met nutsmiddels en databronne te koppel. Omdat MCP-bedieners data en aksies kan blootstel, moet assesserings magtiging, toestemming, validering van nutsmiddel-invoer en ’n hersiening van vertrouensgrense insluit.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI-ondersteunde Fuzzing en outomatiese kwesbaarheidsontdekking


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AI-ondersteunde bronkodehersiening en kwesbaarheidsvalidering

Vir bron/sink-hersiening, taakvloei-analise van mobiele toegangspunte, kernpatroonoudits en validering wat deur bewyse vereis word:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### AI-ondersteunde Reverse Engineering

[Deeltelike lifting, opsporing van invariant MBA, omgewingsgebonde dekodering en validering van outomatiese extractors](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Bots

LLM-aangedrewe agente kan langdurige black-box-web-pentesting-werkvloeie outomatiseer wanneer hulle deur waarneembaarheid, orkestrasie, geverifieerde sessiehantering en adversarial validering ondersteun word:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Top 10 vir Machine Learning-sekuriteit](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Veilige AI-raamwerk (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Inleiding](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
