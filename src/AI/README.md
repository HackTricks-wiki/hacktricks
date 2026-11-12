# AI katika Usalama wa Mtandao

{{#include ../banners/hacktricks-training.md}}

## Algorithms Kuu za Machine Learning

Njia bora ya kuanza kujifunza kuhusu AI ni kuelewa jinsi algorithms kuu za machine learning zinavyofanya kazi. Hii itakusaidia kuelewa jinsi AI inavyofanya kazi, jinsi ya kuitumia na jinsi ya kuishambulia:


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

### Maandalizi na tathmini ya data ya model

Kwa mgawanyo wa dataset, vipimo vya kawaida na mashambulizi yanayolenga majibu dhidi ya uwekaji alama unaotegemea LLM, angalia [maandalizi na tathmini ya data ya model](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### Muundo wa LLM

Katika ukurasa ufuatao utapata misingi ya kila kipengele kinachohitajika kujenga LLM ya msingi kwa kutumia transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Zana na majukwaa ya model

Kwa kuendesha, kufanya fine-tuning, kutoa huduma au kujaribu models, tumia [mwongozo wa zana na majukwaa ya AI model](AI-Model-Tools-and-Platforms.md).

## Usalama wa AI

### Mipaka ya uaminifu ya LLM Gateway

Kwa usalama wa gateway, angalia:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Mbinu za Usalama wa AI Agent

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Mifumo ya Hatari za AI

Mifumo miwili mizuri ya kuanzia katika kutathmini hatari za mifumo ya AI ni OWASP Machine Learning Security Top 10 na Secure AI Framework (SAIF) ya Google. Inakamilishana, badala ya kuwa orodha kamili ya mifumo ya hatari za AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Mashambulizi ya Adversarial Yanayoongozwa na Mechanistic Interpretability

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Usalama wa Prompts za AI

Matumizi ya AI yameongezeka sana katika miaka ya hivi karibuni kutokana na LLMs, lakini si kamilifu na yanaweza kudanganywa kwa prompts za adversarial. Hii ni mada muhimu sana ya kuelewa jinsi ya kutumia AI kwa usalama na jinsi ya kuishambulia:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE ya AI Models

Ni jambo la kawaida kwa developers na makampuni kuendesha models zilizopakuliwa kutoka kwenye Internet; hata hivyo, kupakia model pekee kunaweza kutosha kutekeleza code yoyote kwenye mfumo. Hii ni mada muhimu sana ya kuelewa jinsi ya kutumia AI kwa usalama na jinsi ya kuishambulia:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### KYC Bypass Inayosaidiwa na AI

Video generative inaweza kuunganishwa na uingizaji wa virtual camera na udanganyifu wa camera API ili kupita taratibu dhaifu za KYC, uthibitishaji wa umri na uthibitishaji wa uhai wa biometriki:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) ni protocol iliyo wazi ya kuunganisha programu za AI na zana pamoja na vyanzo vya data. Kwa kuwa seva za MCP zinaweza kufichua data na vitendo, tathmini lazima zijumuishe authorization, consent, uthibitishaji wa tool-input na ukaguzi wa mipaka ya uaminifu.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Protocol ya AI Agent-to-Agent (A2A)

A2A huwawezesha agents kugundua kila mmoja kupitia agent card na kutumiana tasks kupitia HTTP. Jaribu agent cards, authorization ya tasks, webhooks za push-notification na cards zilizopanuliwa:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Huduma za AI Zinazoendeshwa Mwenyewe Zilizo Wazi kwa Umma

Kutambua aina na kujaribu model runners, agent builders, ML demo UIs, compute clusters na vector databases zilizo wazi bila authentication:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing Inayosaidiwa na AI na Ugunduzi wa Kiotomatiki wa Vulnerability


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Ukaguzi wa Source Unaosaidiwa na AI na Uthibitishaji wa Vulnerability

Kwa ukaguzi wa source/sink, taskflows za mobile entry-point, ukaguzi wa mifumo ya kernel na uthibitishaji unaohitaji ushahidi:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Reverse Engineering Inayosaidiwa na AI

[Kuinua sehemu ya code, kugundua invariant MBA, decoding inayofungamana na mazingira na uthibitishaji wa automated-extractor](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bots za AI za Pentesting ya Web Black-Box

Agents zinazoendeshwa na LLM zinaweza kuendesha kiotomatiki workflows za muda mrefu za web pentesting ya black-box zinapoungwa mkono na observability, orchestration, ushughulikiaji wa authenticated session na uthibitishaji wa adversarial:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP Usalama wa Machine Learning 10 Bora](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Mfumo Salama wa AI (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Utangulizi](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
