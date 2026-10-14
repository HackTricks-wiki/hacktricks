# AI у сајбер безбедности

{{#include ../banners/hacktricks-training.md}}

## Главни алгоритми машинског учења

Најбоље је да започнете учење о AI-ју тако што ћете разумети како функционишу главни алгоритми машинског учења. То ће вам помоћи да разумете како AI функционише, како да га користите и како да га нападнете:


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

### Архитектура LLM-ова

На следећој страници пронаћи ћете основе сваке компоненте потребне за изградњу основног LLM-а помоћу transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Алати и платформе за моделе

За покретање, fine-tuning, сервирање или испробавање модела користите [водич за алате и платформе за AI моделе](AI-Model-Tools-and-Platforms.md).

## Безбедност AI-ја

### Методологија за безбедност AI агената

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Оквири за процену ризика AI-ја

Два корисна почетна оквира за процену ризика AI система су OWASP Machine Learning Security Top 10 и Google Secure AI Framework (SAIF). Они се међусобно допуњују и не представљају исцрпан списак оквира за процену ризика AI-ја.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Адверзаријални напади вођени механистичком интерпретабилношћу

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Безбедност AI промптова

LLM-ови су последњих година довели до наглог пораста употребе AI-ја, али нису савршени и могу се преварити адверзаријалним промптовима. Ово је веома важна тема за разумевање безбедног коришћења AI-ја и начина на који се он може напасти:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE у AI моделима

Веома је уобичајено да програмери и компаније покрећу моделе преузете са интернета, међутим, само учитавање модела може бити довољно за извршавање произвољног кода на систему. Ово је веома важна тема за разумевање безбедног коришћења AI-ја и начина на који се он може напасти:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Заобилажење KYC-а уз помоћ AI-ја

Генерисани видео се може комбиновати са убацивањем виртуелне камере и манипулацијом camera API-јем ради заобилажења слабих KYC, провера старости и биометријских поступака за проверу присуства живе особе:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) је отворени протокол за повезивање AI апликација са алатима и изворима података. Пошто MCP сервери могу да излажу податке и радње, процене морају да обухвате ауторизацију, сагласност, проверу улаза алата и преглед граница поверења.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing уз помоћ AI-ја и аутоматизовано откривање рањивости


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Обрнути инжењеринг уз помоћ AI-ја

[Делимично подизање нивоа кода, откривање инваријантног MBA-а, декодирање везано за окружење и валидација аутоматизованих екстрактора](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web black-box AI pentester ботови

Агенти засновани на LLM-овима могу да аутоматизују дуготрајне black-box web pentesting токове рада када им се обезбеде опсервабилност, оркестрација, руковање аутентификованим сесијама и адверзаријална валидација:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP топ 10 безбедности машинског учења](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Оквир за безбедан AI (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Увод](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
