# AI in Kuberveiligheid

{{#include ../banners/hacktricks-training.md}}

## Hoofmasjienleer-algoritmes

Die beste beginpunt om oor AI te leer, is om te verstaan hoe die belangrikste masjienleer-algoritmes werk. Dit sal jou help verstaan hoe AI werk, hoe om dit te gebruik en hoe om dit aan te val:


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

## Modelnutsmiddels en -platforms

Gebruik die [gids vir AI-modelnutsmiddels en -platforms](AI-Model-Tools-and-Platforms.md) om modelle te laat loop, fyn in te stel, te bedien of uit te probeer.

## AI-sekuriteit

### Metodologie vir AI-agentsekuriteit

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AI-risikoraamwerke

Twee nuttige beginraamwerke om AI-stelselrisiko te bepaal, is die OWASP Machine Learning Security Top 10 en Google se Secure AI Framework (SAIF). Hulle vul mekaar aan, maar vorm nie ’n volledige lys van AI-risikoraamwerke nie.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Meganiese-interpreteerbaarheid-geleide teenstrydige aanvalle

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### AI-promptsekuriteit

LLM’s het die gebruik van AI die afgelope paar jaar laat ontplof, maar hulle is nie perfek nie en kan deur teenstrydige prompts mislei word. Dit is ’n baie belangrike onderwerp om te verstaan hoe om AI veilig te gebruik en hoe om dit aan te val:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE in AI-modelle

Dit is baie algemeen dat ontwikkelaars en maatskappye modelle laat loop wat van die internet afgelaai is. Om ’n model bloot te laai, kan egter genoeg wees om arbitrêre kode op die stelsel uit te voer. Dit is ’n baie belangrike onderwerp om te verstaan hoe om AI veilig te gebruik en hoe om dit aan te val:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### KYC-omseiling met AI-ondersteuning

Generatiewe video kan met virtuele-kamera-inspuiting en manipulasie van kamera-API’s gekombineer word om swak KYC-, ouderdomsverifikasie- en biometriese lewendigheidskontroles te omseil:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) is ’n oop protokol om AI-toepassings aan nutsmiddels en databronne te koppel. Omdat MCP-bedieners data en aksies beskikbaar kan stel, moet assesserings magtiging, toestemming, validering van nutsmiddelinsette en hersiening van vertrouensgrense insluit.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing en outomatiese kwesbaarheidsontdekking met AI-ondersteuning


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Omgekeerde ingenieurswese met AI-ondersteuning

[Partiële lifting, opsporing van invariansie-MBA, omgewingsgebonde dekodering en validering van outomatiese onttrekkers](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web-black-box-AI-pentesterbots

LLM-aangedrewe agente kan langdurige black-box-web-pentesting-werkvloeie outomatiseer wanneer hulle ondersteun word deur waarneembaarheid, orkestrering, geverifieerde sessiehantering en teenstrydige validering:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Masjienleer-sekuriteit Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Veilige AI-raamwerk (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Inleiding](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
