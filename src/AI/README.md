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

Katika ukurasa ufuatao utapata misingi ya kila kipengele kinachohitajika kujenga LLM ya msingi kwa kutumia transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Zana na mifumo ya Modeli

Kwa kuendesha, kufanya fine-tuning, kutoa huduma kwa modeli au kuzijaribu, tumia [mwongozo wa zana na mifumo ya modeli za AI](AI-Model-Tools-and-Platforms.md).

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

### Mifumo ya Tathmini ya Hatari za AI

Mifumo miwili mizuri ya kuanzia kutathmini hatari za mifumo ya AI ni OWASP Machine Learning Security Top 10 na Secure AI Framework (SAIF) ya Google. Inakamilishana badala ya kuwa orodha kamili ya mifumo ya kutathmini hatari za AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Mashambulizi ya Adversarial Yanayoongozwa na Mechanistic Interpretability

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Usalama wa Prompts za AI

Matumizi ya AI yameongezeka sana katika miaka ya hivi karibuni kutokana na LLMs, lakini si kamilifu na yanaweza kudanganywa kwa prompts za adversarial. Hili ni suala muhimu sana kuelewa ili kutumia AI kwa usalama na kujua jinsi ya kuishambulia:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE ya Modeli za AI

Ni jambo la kawaida kwa watengenezaji na kampuni kutumia modeli zilizopakuliwa kutoka kwenye Internet, lakini kupakia modeli pekee kunaweza kutosha kutekeleza code kiholela kwenye mfumo. Hili ni suala muhimu sana kuelewa ili kutumia AI kwa usalama na kujua jinsi ya kuishambulia:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### KYC Bypass Inayosaidiwa na AI

Video zinazozalishwa zinaweza kuunganishwa na virtual-camera injection na camera API manipulation ili kukwepa mifumo dhaifu ya KYC, uthibitishaji wa umri na ukaguzi wa uhai wa biometriki:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol ya AI

MCP (Model Context Protocol) ni protocol iliyo wazi ya kuunganisha programu za AI na zana pamoja na vyanzo vya data. Kwa kuwa seva za MCP zinaweza kufichua data na vitendo, tathmini lazima zijumuishe uidhinishaji, ridhaa, uthibitishaji wa ingizo la zana na ukaguzi wa mipaka ya uaminifu.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Protocol ya AI Agent-to-Agent (A2A)

A2A huruhusu mawakala kugundua wenzao kupitia agent card na kutumiana tasks kupitia HTTP. Jaribu agent cards, uidhinishaji wa tasks, webhooks za push-notification na cards zilizopanuliwa:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Huduma za AI Zinazojisimamia Zilizo Wazi kwa Umma

Kutambua na kujaribu model runners, agent builders, ML demo UIs, compute clusters na vector databases zilizo wazi kwa umma na zinazoendeshwa bila uthibitishaji:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing na Ugunduzi wa Kiotomatiki wa Udhaifu Unaosaidiwa na AI


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Ukaguzi wa Source na Uthibitishaji wa Udhaifu Unaosaidiwa na AI

Kwa ukaguzi wa source/sink, taskflows za mobile entry-point, ukaguzi wa mifumo ya kernel na uthibitishaji unaohitaji ushahidi:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Reverse Engineering Inayosaidiwa na AI

[Partial lifting, ugunduzi wa invariant MBA, decoding inayotegemea mazingira na uthibitishaji wa automated-extractor](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Boti za AI za Black-Box Web Pentesting

Mawakala wanaotumia LLM wanaweza kuendesha kiotomatiki workflows za muda mrefu za black-box web pentesting wanaposaidiwa na observability, orchestration, ushughulikiaji wa authenticated session na uthibitishaji wa adversarial:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [10 Bora za Usalama wa Machine Learning za OWASP](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Mfumo Salama wa AI (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Utangulizi](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
