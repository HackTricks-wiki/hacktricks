# AI in Kubersekuriteit

{{#include ../banners/hacktricks-training.md}}

## Belangrikste Machine Learning-algoritmes

Die beste beginpunt om oor AI te leer, is om te verstaan hoe die belangrikste machine learning-algoritmes werk. Dit sal jou help om te verstaan hoe AI werk, hoe om dit te gebruik en hoe om dit aan te val:


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

### LLMs-argitektuur

Op die volgende bladsy vind jy die basiese beginsels van elke komponent om ’n basiese LLM met transformers te bou:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## AI-sekuriteit

### AI-risikoraamwerke

Twee nuttige beginraamwerke vir die beoordeling van AI-stelselrisiko is die OWASP Machine Learning Security Top 10 en Google se Secure AI Framework (SAIF). Hulle vul mekaar aan eerder as om ’n volledige lys van AI-risikoraamwerke te wees.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### AI-prompts-sekuriteit

LLMs het die gebruik van AI die afgelope jare laat ontplof, maar hulle is nie perfek nie en kan deur adversarial prompts mislei word. Dit is ’n baie belangrike onderwerp om te verstaan hoe om AI veilig te gebruik en hoe om dit aan te val:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE in AI-modelle

Dit is baie algemeen dat ontwikkelaars en maatskappye modelle wat van die Internet afgelaai is, uitvoer; die laai van ’n model alleen kan egter genoeg wees om arbitrêre kode op die stelsel uit te voer. Dit is ’n baie belangrike onderwerp om te verstaan hoe om AI veilig te gebruik en hoe om dit aan te val:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI-ondersteunde KYC-bypass

Generatiewe video kan met virtuele-kamera-inspuiting en kameramanipulasie via API’s gekombineer word om swak KYC-, ouderdomsverifikasie- en biometriese-liveness-werkvloeie te omseil:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) is ’n oop protokol om AI-toepassings met tools en databronne te verbind. Omdat MCP-bedieners data en aksies kan blootstel, moet assesserings magtiging, toestemming, tool-invoervalidering en ’n hersiening van trust boundaries insluit.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI-ondersteunde fuzzing & outomatiese kwesbaarheidsontdekking


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Web Black-Box AI Pentester Bots

LLM-aangedrewe agente kan langdurige black-box-web-pentesting-werkvloeie outomatiseer wanneer hulle deur observability, orkestrasie, geverifieerde sessiehantering en adversarial validation ondersteun word:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Veilige AI-raamwerk (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Inleiding](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
