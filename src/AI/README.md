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

### Maandalizi na tathmini ya data ya modeli

Kwa mgawanyo wa dataset, vipimo vya kawaida, na mashambulizi ya upande wa majibu dhidi ya upangaji alama unaotegemea LLM, angalia [maandalizi na tathmini ya data ya modeli](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### Usanifu wa LLMs

Katika ukurasa unaofuata utapata misingi ya kila kipengele kinachohitajika kujenga LLM ya msingi kwa kutumia transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Zana na mifumo ya modeli za AI

Kwa kuendesha, kufanya fine-tuning, kuhudumia, au kujaribu modeli, tumia [mwongozo wa zana na mifumo ya modeli za AI](AI-Model-Tools-and-Platforms.md).

## Usalama wa AI

### Mipaka ya uaminifu ya LLM Gateway

Kwa usalama wa gateway, angalia:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Mbinu ya Usalama wa AI Agent

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Miundo ya Hatari za AI

Miundo miwili mizuri ya kuanzia kwa kutathmini hatari za mifumo ya AI ni OWASP Machine Learning Security Top 10 na Google's Secure AI Framework (SAIF). Inakamilishana badala ya kuwa orodha kamili ya miundo ya hatari za AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Mashambulizi ya Adversarial Yanayoongozwa na Ufafanuzi wa Kimekanika

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Mipaka ya uaminifu ya browser iliyopachikwa

Kwa madaraja ya browser ya desktop-assistant, udanganyifu wa anwani ya tab, na usomaji wa faili za ndani katika muktadha wa worker, angalia [mipaka ya uaminifu ya browser iliyopachikwa katika AI assistant](AI-Embedded-Browser-Trust-Boundaries.md).

### Usalama wa AI Prompts

Matumizi ya AI yameongezeka sana katika miaka ya hivi karibuni kutokana na LLMs, lakini si kamilifu na zinaweza kudanganywa kwa prompts za adversarial. Hili ni suala muhimu sana ili kuelewa jinsi ya kutumia AI kwa usalama na jinsi ya kuishambulia:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE kupitia Modeli za AI

Ni jambo la kawaida kwa watengenezaji na makampuni kuendesha modeli zilizopakuliwa kutoka Internet; hata hivyo, kupakia modeli pekee kunaweza kutosha kutekeleza msimbo wowote kwenye mfumo. Hili ni suala muhimu sana ili kuelewa jinsi ya kutumia AI kwa usalama na jinsi ya kuishambulia:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### KYC Bypass Inayosaidiwa na AI

Video generative inaweza kuunganishwa na uingizaji wa virtual-camera na udanganyifu wa camera API ili kupita mifumo dhaifu ya KYC, uthibitishaji wa umri na uthibitishaji wa uhai wa biometriki:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) ni protocol iliyo wazi ya kuunganisha programu za AI na zana na vyanzo vya data. Kwa kuwa seva za MCP zinaweza kufichua data na vitendo, tathmini lazima zijumuishe uidhinishaji, ridhaa, uthibitishaji wa ingizo la zana, na mapitio ya mipaka ya uaminifu.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI Agent-to-Agent (A2A) Protocol

A2A huruhusu agents kugundua kila mmoja kupitia agent card na kutumiana kazi kupitia HTTP. Jaribu agent cards, uidhinishaji wa kazi, webhook za push-notification na cards zilizopanuliwa:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Huduma za AI Zinazojiendesha Zilizowekwa Hadharani

Kutambua na kujaribu model runners, agent builders, ML demo UIs, compute clusters na vector databases zilizowekwa hadharani zinazoendeshwa bila uthibitishaji:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing Inayosaidiwa na AI na Ugunduzi Otomatiki wa Vulnerability


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Mapitio ya Source na Uthibitishaji wa Vulnerability Unaosaidiwa na AI

Kwa mapitio ya source/sink, taskflows za sehemu za kuingilia za simu, ukaguzi wa mifumo ya kernel, na uthibitishaji unaohitaji ushahidi:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Reverse Engineering Inayosaidiwa na AI

[Partial lifting, ugunduzi wa invariant MBA, decoding inayotegemea mazingira, na uthibitishaji wa automated-extractor](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Bots

Agents zinazoendeshwa na LLM zinaweza kuendesha workflows za muda mrefu za black-box web pentesting kiotomatiki zinapoungwa mkono na observability, orchestration, ushughulikiaji wa authenticated session, na uthibitishaji wa adversarial:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP Machine Learning Security 10 Bora](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Mfumo Salama wa AI (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Utangulizi](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
