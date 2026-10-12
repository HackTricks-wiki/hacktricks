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

### LLM-argitektuur

Op die volgende bladsy vind jy die grondbeginsels van elke komponent waarmee jy ’n basiese LLM met behulp van transformers kan bou:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## KI-sekuriteit

### Metodologie vir KI-agent-sekuriteit

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### KI-risikoraamwerke

Twee nuttige raamwerke om KI-stelselrisiko te beoordeel, is die OWASP Top 10 vir Masjienleer-sekuriteit en Google se Veilige KI-raamwerk (SAIF). Hulle vul mekaar aan, maar vorm nie ’n volledige lys van KI-risikoraamwerke nie.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Meganistiese interpreteerbaarheid-geleide adversariële aanvalle

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Sekuriteit van KI-aanwysings

LLM’s het die gebruik van KI die afgelope jare laat ontplof, maar hulle is nie perfek nie en kan deur adversariële aanwysings mislei word. Dit is ’n baie belangrike onderwerp om te verstaan hoe om KI veilig te gebruik en hoe om dit aan te val:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE in KI-modelle

Dit is baie algemeen dat ontwikkelaars en maatskappye modelle laat loop wat van die internet afgelaai is. Die blote laai van ’n model kan egter genoeg wees om arbitrêre kode op die stelsel uit te voer. Dit is ’n baie belangrike onderwerp om te verstaan hoe om KI veilig te gebruik en hoe om dit aan te val:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### KI-gesteunde KYC-omseiling

Generatiewe video kan met virtuele-kamera-inspuiting en manipulasie van kamera-API’s gekombineer word om swak KYC-, ouderdomsverifikasie- en biometriese lewendigheidskontroles te omseil:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) is ’n oop protokol om KI-toepassings aan nutsmiddels en databronne te koppel. Omdat MCP-bedieners data en aksies kan blootstel, moet assesserings magtiging, toestemming, validering van nutsmiddelinvoer en ’n hersiening van vertrouensgrense insluit.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### KI-gesteunde fuzzing en outomatiese kwesbaarheidsontdekking


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### KI-gesteunde reverse engineering

[Partiële lifting, opsporing van invariantes in MBA, omgewingsgebonde dekodering en validering van outomatiese ekstrakteurs](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Black-box KI-pentesterbots vir webtoepassings

LLM-aangedrewe agente kan langdurige black-box-webpentesting-werkvloeie outomatiseer wanneer hulle ondersteun word deur waarneembaarheid, orkestrasie, hantering van geverifieerde sessies en adversariële validering:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Top 10 vir Masjienleer-sekuriteit](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Veilige KI-raamwerk (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Inleiding](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
