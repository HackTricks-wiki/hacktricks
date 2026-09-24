# AI katika Usalama wa Mtandao

{{#include ../banners/hacktricks-training.md}}

## Algorithms Kuu za Machine Learning

Mwanzo bora wa kujifunza kuhusu AI ni kuelewa jinsi algorithms kuu za machine learning zinavyofanya kazi. Hii itakusaidia kuelewa jinsi AI inavyofanya kazi, jinsi ya kuitumia na jinsi ya kuishambulia:


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

### Architecture ya LLMs

Katika ukurasa unaofuata utapata misingi ya kila component inayohitajika kujenga LLM ya msingi kwa kutumia transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Usalama wa AI

### Frameworks za AI Risk

Frameworks mbili muhimu za kuanzia kwa kutathmini risk ya AI-system ni OWASP Machine Learning Security Top 10 na Secure AI Framework (SAIF) ya Google. Zinakamilishana badala ya kuwa orodha kamili ya frameworks za AI risk.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Usalama wa AI Prompts

LLMs zimefanya matumizi ya AI kuongezeka sana katika miaka ya hivi karibuni, lakini si kamilifu na zinaweza kudanganywa kwa adversarial prompts. Hii ni mada muhimu sana ya kuelewa jinsi ya kutumia AI kwa usalama na jinsi ya kuishambulia:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE ya AI Models

Ni jambo la kawaida kwa developers na makampuni kuendesha models zilizopakuliwa kutoka Internet, hata hivyo kupakia tu model kunaweza kutosha kutekeleza arbitrary code kwenye mfumo. Hii ni mada muhimu sana ya kuelewa jinsi ya kutumia AI kwa usalama na jinsi ya kuishambulia:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI-Assisted KYC Bypass

Video ya generative inaweza kuunganishwa na virtual-camera injection na camera API manipulation ili kukwepa KYC dhaifu, age-verification, na biometric liveness workflows:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) ni open protocol ya kuunganisha AI applications na tools pamoja na data sources. Kwa kuwa MCP servers zinaweza kufichua data na actions, assessments lazima zijumuishe authorization, consent, tool-input validation, na trust-boundary review.<sup>[[3]](#references)</sup>


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

Agents wanaotumia LLM wanaweza ku-automate black-box web pentesting workflows zinazoendelea kwa muda mrefu zinapoungwa mkono na observability, orchestration, authenticated session handling, na adversarial validation:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Utangulizi](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
