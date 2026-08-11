# AI у кібербезпеці

{{#include ../banners/hacktricks-training.md}}

## Основні алгоритми машинного навчання

Найкраще почати вивчення AI з розуміння принципів роботи основних алгоритмів машинного навчання. Це допоможе зрозуміти, як працює AI, як його використовувати та як його атакувати:


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

На наступній сторінці ви знайдете основи кожного компонента, необхідного для побудови базового LLM за допомогою transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Безпека AI

### Фреймворки ризиків AI

Двома корисними фреймворками для початку оцінювання ризиків AI-систем є OWASP Machine Learning Security Top 10 і Google's Secure AI Framework (SAIF). Вони доповнюють один одного, а не становлять вичерпний перелік фреймворків ризиків AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Безпека AI Prompts

LLM спричинили стрімке поширення використання AI протягом останніх років, але вони не є досконалими, і їх можна обманути за допомогою adversarial prompts. Це дуже важлива тема для розуміння того, як безпечно використовувати AI і як його атакувати:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE у моделях AI

Розробники та компанії дуже часто запускають моделі, завантажені з Інтернету, однак навіть простого завантаження моделі може бути достатньо для виконання довільного коду в системі. Це дуже важлива тема для розуміння того, як безпечно використовувати AI і як його атакувати:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Обхід KYC за допомогою AI

Generative video можна поєднати з virtual-camera injection і маніпуляцією camera API для обходу слабких процесів KYC, перевірки віку та перевірки liveness біометричних даних:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) — це відкритий протокол для підключення AI-застосунків до інструментів і джерел даних. Оскільки MCP-сервери можуть надавати доступ до даних і дій, оцінювання має охоплювати авторизацію, згоду, валідацію вхідних даних інструментів і перевірку меж довіри.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing за допомогою AI та автоматизоване виявлення вразливостей


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AI-боти для black-box Web Pentesting

Агенти на основі LLM можуть автоматизувати тривалі процеси black-box web pentesting, якщо вони підтримуються засобами спостережуваності, оркестрацією, обробкою автентифікованих сесій та adversarial validation:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introduction](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
