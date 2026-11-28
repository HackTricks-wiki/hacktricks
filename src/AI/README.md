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

### Maandalizi na tathmini ya data ya modeli

Kwa mgawanyo wa dataset, vipimo vya kawaida na mashambulizi yanayolenga majibu dhidi ya upangaji alama unaotumia LLM, angalia [maandalizi na tathmini ya data ya modeli](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### Usanifu wa LLM

Katika ukurasa unaofuata utapata misingi ya kila kipengele kinachohitajika kujenga LLM ya msingi kwa kutumia transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Zana na mifumo ya modeli

Ili kuendesha, kufanya fine-tuning, kuhudumia au kujaribu modeli, tumia [mwongozo wa zana na mifumo ya modeli za AI](AI-Model-Tools-and-Platforms.md).

## Usalama wa AI

### Mipaka ya Uaminifu ya LLM Gateway

Kwa usalama wa gateway, angalia:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Mbinu ya Usalama wa AI Agent

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Mifumo ya Hatari za AI

Mifumo miwili mizuri ya kuanzia kutathmini hatari za mifumo ya AI ni OWASP Machine Learning Security Top 10 na Secure AI Framework (SAIF) ya Google. Inakamilishana; si orodha kamili ya mifumo ya hatari za AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Mechanistic-Interpretability-Guided Adversarial Attacks

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Mipaka ya uaminifu ya browser iliyopachikwa

Kwa miunganisho ya browser ya desktop assistant, udanganyifu wa anwani ya tab na usomaji wa faili za ndani katika muktadha wa worker, angalia [mipaka ya uaminifu ya browser iliyopachikwa kwenye AI assistant](AI-Embedded-Browser-Trust-Boundaries.md).

### Usalama wa AI Prompts

Matumizi ya AI yameongezeka sana katika miaka ya hivi karibuni kutokana na LLM, lakini si kamilifu na yanaweza kudanganywa kwa adversarial prompts. Hii ni mada muhimu sana ili kuelewa jinsi ya kutumia AI kwa usalama na jinsi ya kuishambulia:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE kupitia modeli za AI

Ni jambo la kawaida kwa watengenezaji na kampuni kutumia modeli zilizopakuliwa kutoka kwenye Internet, hata hivyo, kupakia modeli pekee kunaweza kutosha kutekeleza code kiholela kwenye mfumo. Hii ni mada muhimu sana ili kuelewa jinsi ya kutumia AI kwa usalama na jinsi ya kuishambulia:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

Kwa hatari za kupakia modeli za Keras `.keras`/HDF5, Lambda layers na uchanganuzi wa gadget baada ya marekebisho, angalia [uondoaji wa serialization ya modeli za Keras na kutafuta gadget](keras-model-deserialization-rce-and-gadget-hunting.md).

### Kukwepa KYC kwa usaidizi wa AI

Video generative inaweza kuunganishwa na uingizaji wa virtual-camera na udanganyifu wa camera API ili kukwepa mifumo dhaifu ya KYC, uthibitishaji wa umri na uhakiki wa uhai wa biometriki:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) ni protocol iliyo wazi ya kuunganisha programu za AI na zana pamoja na vyanzo vya data. Kwa kuwa seva za MCP zinaweza kufichua data na vitendo, tathmini lazima zijumuishe uidhinishaji, idhini, uthibitishaji wa ingizo la zana na ukaguzi wa mipaka ya uaminifu.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Protocol ya AI Agent-to-Agent (A2A)

A2A huruhusu agents kugundua wenzao kupitia agent card na kutumiana kazi kupitia HTTP. Jaribu agent cards, uidhinishaji wa kazi, webhook za push-notification na extended cards:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Huduma za AI Zinazojiendesha Zilizowekwa Hadharani

Kutambua na kujaribu model runners, agent builders, ML demo UIs, compute clusters na vector databases zilizowekwa hadharani na zinazoendeshwa bila uthibitishaji:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing kwa Usaidizi wa AI na Ugunduzi wa Kiotomatiki wa Athari za Usalama


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Mapitio ya Source na Uthibitishaji wa Athari za Usalama kwa Usaidizi wa AI

Kwa mapitio ya source/sink, taskflows za sehemu za kuingilia za simu, ukaguzi wa pattern za kernel na uthibitishaji unaotegemea ushahidi:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Reverse Engineering kwa Usaidizi wa AI

[Kuinua sehemu za code, kugundua invariant MBA, decoding inayotegemea mazingira na uthibitishaji wa automated extractor](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Bots

Agents zinazotumia LLM zinaweza kujiendeshea workflow ndefu za web pentesting ya black-box zinapoungwa mkono na observability, orchestration, ushughulikiaji wa authenticated session na uthibitishaji wa adversarial:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [10 Bora za Usalama wa Machine Learning za OWASP](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Mfumo Salama wa AI (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Utangulizi](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
