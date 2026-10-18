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

Katika ukurasa unaofuata utapata misingi ya kila kipengele kinachohitajika kujenga LLM ya msingi kwa kutumia transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Zana na majukwaa ya modeli

Ili kuendesha, kufanya fine-tuning, kuhudumia au kujaribu modeli, tumia [mwongozo wa zana na majukwaa ya modeli za AI](AI-Model-Tools-and-Platforms.md).

## Usalama wa AI

### Mbinu ya Usalama wa AI Agent

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Mifumo ya Hatari za AI

Mifumo miwili mizuri ya kuanzia kutathmini hatari za mifumo ya AI ni OWASP Machine Learning Security Top 10 na Secure AI Framework (SAIF) ya Google. Inakamilishana badala ya kuwa orodha kamili ya mifumo ya hatari za AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Mashambulizi ya Adversarial Yanayoongozwa na Ufafanuzi wa Kiufundi wa Mitambo

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Usalama wa Prompts za AI

Matumizi ya AI yameongezeka sana katika miaka ya hivi karibuni kutokana na LLM, lakini si kamilifu na yanaweza kudanganywa kwa prompts za adversarial. Hii ni mada muhimu sana ili kuelewa jinsi ya kutumia AI kwa usalama na jinsi ya kuishambulia:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE katika Modeli za AI

Ni jambo la kawaida kwa wasanidi programu na kampuni kuendesha modeli zilizopakuliwa kutoka kwenye Intaneti, lakini kupakia modeli pekee kunaweza kutosha kutekeleza msimbo wowote kwenye mfumo. Hii ni mada muhimu sana ili kuelewa jinsi ya kutumia AI kwa usalama na jinsi ya kuishambulia:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Kuepuka KYC kwa Usaidizi wa AI

Video za generative zinaweza kuunganishwa na uingizaji wa virtual camera na uchezeshaji wa API ya kamera ili kukwepa taratibu dhaifu za KYC, uthibitishaji wa umri na uthibitishaji wa uhai wa biometriki:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Itifaki ya Muktadha wa Modeli za AI

MCP (Model Context Protocol) ni itifaki wazi ya kuunganisha programu za AI na zana pamoja na vyanzo vya data. Kwa kuwa seva za MCP zinaweza kufichua data na vitendo, tathmini lazima zijumuishe uidhinishaji, idhini, uthibitishaji wa ingizo la zana na ukaguzi wa mipaka ya uaminifu.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing kwa Usaidizi wa AI na Ugunduzi wa Kiotomatiki wa Udhaifu


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Ukaguzi wa Chanzo na Uthibitishaji wa Udhaifu kwa Usaidizi wa AI

Kwa ukaguzi wa source/sink, taskflow za mobile entry-point, ukaguzi wa mifumo ya kernel na uthibitishaji unaohitaji ushahidi:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Reverse Engineering kwa Usaidizi wa AI

[Kuinua sehemu, kugundua invariant MBA, decoding inayotegemea mazingira na uthibitishaji wa automated-extractor](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Boti za AI za Pentesting ya Web Black-Box

Agent zinazotumia LLM zinaweza kuendesha kiotomatiki workflows za muda mrefu za web pentesting ya black-box zinapoungwa mkono na observability, orchestration, ushughulikiaji wa session zilizoidhinishwa na uthibitishaji wa adversarial:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [10 Bora za OWASP za Usalama wa Machine Learning](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Mfumo Salama wa AI (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Utangulizi](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
