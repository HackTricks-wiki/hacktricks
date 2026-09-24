# AI у кібербезпеці

{{#include ../banners/hacktricks-training.md}}

## Основні алгоритми Machine Learning

Найкраще почати вивчення AI з розуміння принципів роботи основних алгоритмів Machine Learning. Це допоможе зрозуміти, як працює AI, як його використовувати та як його атакувати:


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

### Архітектура LLM

На наступній сторінці ви знайдете основи кожного компонента, необхідного для створення базової LLM за допомогою transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Безпека AI

### Фреймворки ризиків AI

Двома корисними початковими фреймворками для оцінювання ризиків AI-систем є OWASP Machine Learning Security Top 10 і Google's Secure AI Framework (SAIF). Вони доповнюють один одного, а не становлять вичерпний перелік фреймворків ризиків AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Безпека AI-промптів

LLM спричинили стрімке поширення використання AI протягом останніх років, але вони не є досконалими й можуть бути обмануті adversarial prompts. Це дуже важлива тема для розуміння того, як безпечно використовувати AI і як його атакувати:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE у моделях AI

Розробники та компанії дуже часто запускають моделі, завантажені з Internet, однак простого завантаження моделі може бути достатньо для виконання довільного коду в системі. Це дуже важлива тема для розуміння того, як безпечно використовувати AI і як його атакувати:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Обхід KYC за допомогою AI

Generative video можна поєднати з virtual-camera injection і маніпуляцією camera API для обходу ненадійних процесів KYC, перевірки віку та biometric liveness:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) — це відкритий протокол для підключення AI-застосунків до інструментів і джерел даних. Оскільки MCP-сервери можуть надавати доступ до даних і дій, оцінювання має охоплювати авторизацію, згоду, перевірку вхідних даних інструментів і аналіз меж довіри.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing за допомогою AI та автоматизоване виявлення вразливостей


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Reverse Engineering за допомогою AI

[Часткове підняття коду, виявлення інваріантів MBA, декодування, прив’язане до середовища, та перевірка automated extractor](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Bots

Агенти на основі LLM можуть автоматизувати тривалі робочі процеси black-box web pentesting, якщо вони підтримуються засобами observability, orchestration, обробкою автентифікованих сесій і adversarial validation:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Вступ](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
