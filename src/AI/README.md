# AI in Cybersecurity

{{#include ../banners/hacktricks-training.md}}

## Belangrikste Machine Learning Algorithms

Die beste beginpunt om oor AI te leer, is om te verstaan hoe die belangrikste machine learning algorithms werk. Dit sal jou help om te verstaan hoe AI werk, hoe om dit te gebruik en hoe om dit aan te val:


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

### LLMs Architecture

Op die volgende bladsy sal jy die grondbeginsels van elke komponent vind om ’n basiese LLM met transformers te bou:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## AI Security

### AI Risk Frameworks

Twee nuttige raamwerke om mee te begin vir die assessering van AI-stelselrisiko is die OWASP Machine Learning Security Top 10 en Google se Secure AI Framework (SAIF). Hulle vul mekaar aan eerder as om ’n omvattende lys van AI risk frameworks te wees.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### AI Prompts Security

LLMs het die gebruik van AI die afgelope jare drasties laat toeneem, maar hulle is nie perfek nie en kan deur adversarial prompts mislei word. Dit is ’n baie belangrike onderwerp om te verstaan hoe om AI veilig te gebruik en hoe om dit aan te val:


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI Models RCE

Dit is baie algemeen dat developers en maatskappye models uitvoer wat van die Internet afgelaai is; om ’n model bloot te laai, kan egter genoeg wees om arbitrêre code op die stelsel uit te voer. Dit is ’n baie belangrike onderwerp om te verstaan hoe om AI veilig te gebruik en hoe om dit aan te val:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI-Assisted KYC Bypass

Generative video kan met virtual-camera injection en camera API manipulation gekombineer word om swak KYC-, ouderdomsverifikasie- en biometric-liveness-workflows te omseil:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) is ’n oop protokol om AI applications aan tools en data sources te koppel. Omdat MCP servers data en actions kan blootstel, moet assessments authorization, consent, tool-input validation en trust-boundary review insluit.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI-Assisted Fuzzing & Automated Vulnerability Discovery


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AI-Assisted Reverse Engineering

[Partial lifting, invariant MBA detection, environment-bound decoding, and automated-extractor validation](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Bots

LLM-powered agents kan langdurige black-box web pentesting-workflows outomatiseer wanneer hulle deur observability, orchestration, authenticated session handling en adversarial validation ondersteun word:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introduction](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
