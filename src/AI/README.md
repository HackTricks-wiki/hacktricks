# AI katika Usalama wa Mtandao

{{#include ../banners/hacktricks-training.md}}

## Algoriti Kuu za Machine Learning

Njia bora ya kuanza kujifunza kuhusu AI ni kuelewa jinsi algoriti kuu za machine learning zinavyofanya kazi. Hii itakusaidia kuelewa jinsi AI inavyofanya kazi, jinsi ya kuitumia na jinsi ya kuishambulia:


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

Katika ukurasa ufuatao utapata misingi ya kila kipengele kinachohitajika ili kuunda LLM ya msingi kwa kutumia transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Zana na majukwaa ya modeli

Kwa kuendesha, kufanya fine-tuning, kuhudumia, au kujaribu modeli, tumia [mwongozo wa zana na majukwaa ya modeli za AI](AI-Model-Tools-and-Platforms.md).

## Usalama wa AI

### Mipaka ya Uaminifu ya LLM Gateway

Kwa usalama wa gateway, tazama:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Mbinu za Usalama wa AI Agent

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Mifumo ya Hatari za AI

Mifumo miwili mizuri ya kuanzia katika kutathmini hatari za mifumo ya AI ni OWASP Machine Learning Security Top 10 na Secure AI Framework (SAIF) ya Google. Inakamilishana badala ya kuwa orodha kamili ya mifumo ya hatari za AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Mashambulizi ya Adversarial Yanayoongozwa na Mechanistic Interpretability

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Usalama wa Prompts za AI

Matumizi ya AI yameongezeka sana katika miaka ya hivi karibuni kutokana na LLM, lakini si kamilifu na yanaweza kudanganywa kwa prompts za adversarial. Hili ni jambo muhimu sana kuelewa ili kutumia AI kwa usalama na kujua jinsi ya kuishambulia:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE kupitia Modeli za AI

Ni jambo la kawaida kwa watengenezaji na makampuni kuendesha modeli zilizopakuliwa kutoka kwenye Intaneti. Hata hivyo, kupakia modeli pekee kunaweza kutosha kutekeleza msimbo wowote kwenye mfumo. Hili ni jambo muhimu sana kuelewa ili kutumia AI kwa usalama na kujua jinsi ya kuishambulia:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Kuepuka KYC kwa Msaada wa AI

Video generative inaweza kuunganishwa na uingizaji wa virtual camera na udanganyifu wa camera API ili kukwepa mifumo dhaifu ya KYC, uthibitishaji wa umri na ukaguzi wa uhai wa biometriki:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol ya AI

MCP (Model Context Protocol) ni protocol iliyo wazi ya kuunganisha programu za AI na zana pamoja na vyanzo vya data. Kwa kuwa seva za MCP zinaweza kufichua data na vitendo, tathmini lazima zijumuishe uidhinishaji, idhini, uthibitishaji wa ingizo la zana na ukaguzi wa mipaka ya uaminifu.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing na Ugunduzi wa Kiotomatiki wa Athari kwa Msaada wa AI


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Ukaguzi wa Msimbo Chanzo na Uthibitishaji wa Athari kwa Msaada wa AI

Kwa ukaguzi wa source/sink, taskflow za sehemu za kuingilia kwenye simu, ukaguzi wa miundo ya kernel na uthibitishaji unaohitaji ushahidi:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Reverse Engineering kwa Msaada wa AI

[Partial lifting, ugunduzi wa invariant MBA, decoding inayotegemea mazingira na uthibitishaji wa automated extractor](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Roboti za AI za Pentesting ya Wavuti ya Black-Box

Agent zinazoendeshwa na LLM zinaweza kuendesha kiotomatiki workflow za muda mrefu za pentesting ya wavuti ya black-box zinaposaidiwa na ufuatiliaji, orchestration, ushughulikiaji wa session zilizothibitishwa na uthibitishaji wa adversarial:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Top 10 ya Usalama wa Machine Learning](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Mfumo Salama wa AI (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Utangulizi](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
