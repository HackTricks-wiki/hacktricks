# AI katika Usalama wa Mtandao

{{#include ../banners/hacktricks-training.md}}

## Algoriti Kuu za Machine Learning

Mahali pazuri pa kuanzia kujifunza kuhusu AI ni kuelewa jinsi algoriti kuu za machine learning zinavyofanya kazi. Hii itakusaidia kuelewa jinsi AI inavyofanya kazi, jinsi ya kuitumia na jinsi ya kuishambulia:


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

### Usanifu wa LLM

Katika ukurasa unaofuata utapata misingi ya kila kipengele cha kujenga LLM ya msingi kwa kutumia transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Usalama wa AI

### Mbinu ya Usalama wa AI Agent

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Mifumo ya Hatari za AI

Mifumo miwili muhimu ya kuanzia kutathmini hatari za mifumo ya AI ni OWASP Machine Learning Security Top 10 na Secure AI Framework (SAIF) ya Google. Inakamilishana na mifumo mingine badala ya kuwa orodha kamili ya mifumo ya hatari za AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Mashambulizi ya Adversarial Yanayoongozwa na Mechanistic Interpretability

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Usalama wa Prompts za AI

Matumizi ya AI yameongezeka sana katika miaka ya hivi karibuni kutokana na LLMs, lakini si kamilifu na yanaweza kudanganywa kwa prompts za adversarial. Hii ni mada muhimu sana ili kuelewa jinsi ya kutumia AI kwa usalama na jinsi ya kuishambulia:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE kupitia AI Models

Ni jambo la kawaida kwa developers na makampuni kuendesha models zilizopakuliwa kutoka kwenye Internet; hata hivyo, kupakia model pekee kunaweza kutosha kutekeleza msimbo wowote kwenye mfumo. Hii ni mada muhimu sana ili kuelewa jinsi ya kutumia AI kwa usalama na jinsi ya kuishambulia:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Kuepuka KYC kwa Usaidizi wa AI

Video generative inaweza kuunganishwa na uingizaji wa virtual camera na udanganyifu wa camera API ili kukwepa taratibu dhaifu za KYC, uthibitishaji wa umri na biometriki za liveness:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) ni protocol wazi ya kuunganisha programu za AI na tools pamoja na vyanzo vya data. Kwa kuwa MCP servers zinaweza kufichua data na vitendo, tathmini lazima zijumuishe uidhinishaji, ridhaa, uthibitishaji wa ingizo la tool na mapitio ya mipaka ya uaminifu.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing Inayosaidiwa na AI na Ugunduzi Otomatiki wa Udhaifu


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Reverse Engineering Inayosaidiwa na AI

[Partial lifting, invariant MBA detection, environment-bound decoding, and automated-extractor validation](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bots za AI za Pentesting ya Wavuti ya Black-Box

Agents zinazotumia LLMs zinaweza kuendesha kiotomatiki workflows za muda mrefu za black-box web pentesting zikiungwa mkono na observability, orchestration, ushughulikiaji wa authenticated sessions na uthibitishaji wa adversarial:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Mfumo Salama wa AI (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Utangulizi](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
