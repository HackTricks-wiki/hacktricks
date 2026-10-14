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

### Usanifu wa LLMs

Katika ukurasa ufuatao utapata misingi ya kila kipengele kinachohitajika kuunda LLM ya msingi kwa kutumia transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Zana na majukwaa ya modeli

Kwa kuendesha, kufanya fine-tuning, kuhudumia au kujaribu modeli, tumia [mwongozo wa zana na majukwaa ya modeli za AI](AI-Model-Tools-and-Platforms.md).

## Usalama wa AI

### Mbinu ya Usalama wa AI Agent

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Miundo ya Hatari za AI

Miundo miwili muhimu ya kuanzia kutathmini hatari za mifumo ya AI ni OWASP Machine Learning Security Top 10 na Secure AI Framework (SAIF) ya Google. Inakamilishana, badala ya kuwa orodha kamili ya miundo ya hatari za AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Mashambulizi ya Adversarial Yanayoongozwa na Mechanistic Interpretability

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Usalama wa Prompts za AI

Matumizi ya AI yameongezeka sana katika miaka ya hivi karibuni kutokana na LLMs, lakini si kamilifu na yanaweza kudanganywa kwa prompts za adversarial. Hili ni mada muhimu sana ili kuelewa jinsi ya kutumia AI kwa usalama na jinsi ya kuishambulia:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE ya Modeli za AI

Ni jambo la kawaida kwa developers na makampuni kuendesha modeli zilizopakuliwa kutoka kwenye Internet; hata hivyo, kupakia modeli pekee kunaweza kutosha kutekeleza code yoyote kwenye mfumo. Hili ni mada muhimu sana ili kuelewa jinsi ya kutumia AI kwa usalama na jinsi ya kuishambulia:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### KYC Bypass Inayosaidiwa na AI

Video generative inaweza kuunganishwa na uingizaji wa virtual camera na uchezaji wa camera API ili kukwepa michakato dhaifu ya KYC, uthibitishaji wa umri na uthibitishaji wa uhai wa kibayometriki:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) ni protocol iliyo wazi ya kuunganisha programu za AI na zana pamoja na vyanzo vya data. Kwa kuwa seva za MCP zinaweza kufichua data na vitendo, tathmini lazima zijumuishe uidhinishaji, idhini, uthibitishaji wa ingizo la zana na ukaguzi wa mipaka ya uaminifu.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing Inayosaidiwa na AI na Ugunduzi wa Kiotomatiki wa Vulnerability


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Reverse Engineering Inayosaidiwa na AI

[Partial lifting, utambuzi wa invariant MBA, decoding inayotegemea mazingira na uthibitishaji wa automated extractor](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bots za AI za Pentesting ya Web Black-Box

Agents zinazotumia LLM zinaweza kuendesha kiotomatiki workflows za muda mrefu za pentesting ya web black-box zinaposaidiwa na observability, orchestration, ushughulikiaji wa authenticated session na uthibitishaji wa adversarial:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Top 10 ya Usalama wa Machine Learning](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Mfumo Salama wa AI (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Utangulizi](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
