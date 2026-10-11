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

### Muundo wa LLM

Katika ukurasa ufuatao utapata misingi ya kila kipengele kinachohitajika kujenga LLM ya msingi kwa kutumia transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Usalama wa AI

### Mbinu ya Usalama wa AI Agent

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Miundo ya Hatari za AI

Miundo miwili muhimu ya kuanzia kutathmini hatari za mifumo ya AI ni OWASP Machine Learning Security Top 10 na Secure AI Framework (SAIF) ya Google. Inakamilishana badala ya kuwa orodha kamili ya miundo ya hatari za AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Usalama wa AI Prompts

Matumizi ya AI yameongezeka sana katika miaka ya hivi karibuni kutokana na LLMs, lakini si kamilifu na yanaweza kudanganywa kwa adversarial prompts. Hii ni mada muhimu sana kwa kuelewa jinsi ya kutumia AI kwa usalama na jinsi ya kuishambulia:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE ya AI Models

Ni jambo la kawaida kwa developers na kampuni kuendesha models zilizopakuliwa kutoka kwenye Internet. Hata hivyo, kupakia tu model kunaweza kutosha kutekeleza msimbo wowote kwenye mfumo. Hii ni mada muhimu sana kwa kuelewa jinsi ya kutumia AI kwa usalama na jinsi ya kuishambulia:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### KYC Bypass kwa Usaidizi wa AI

Video generative inaweza kuunganishwa na virtual-camera injection na camera API manipulation ili kupita KYC dhaifu, uthibitishaji wa umri na mifumo ya uthibitishaji wa uhai wa kibayometriki:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) ni protocol wazi ya kuunganisha programu za AI na tools pamoja na vyanzo vya data. Kwa kuwa MCP servers zinaweza kufichua data na vitendo, tathmini lazima zijumuishe authorization, consent, uthibitishaji wa tool-input na uhakiki wa mipaka ya uaminifu.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing kwa Usaidizi wa AI na Ugunduzi Otomatiki wa Vulnerability


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Reverse Engineering kwa Usaidizi wa AI

[Partial lifting, invariant MBA detection, environment-bound decoding, and automated-extractor validation](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Bots

Agents zinazoendeshwa na LLM zinaweza kufanya workflows za muda mrefu za black-box web pentesting kiotomatiki zinapoungwa mkono na observability, orchestration, ushughulikiaji wa authenticated session na uthibitishaji wa adversarial:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Mfumo Salama wa AI (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Utangulizi](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
