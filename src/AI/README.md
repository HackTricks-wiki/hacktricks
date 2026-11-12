# AI у кібербезпеці

{{#include ../banners/hacktricks-training.md}}

## Основні алгоритми машинного навчання

Найкращий спосіб почати вивчення AI — зрозуміти, як працюють основні алгоритми машинного навчання. Це допоможе зрозуміти, як працює AI, як його використовувати та як його атакувати:


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

### Підготовка та оцінювання даних моделі

Про поділ наборів даних, класичні метрики та атаки на оцінювання LLM з боку відповідей див. [підготовка та оцінювання даних моделі](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### Архітектура LLM

На наступній сторінці ви знайдете основи кожного компонента для побудови базової LLM на основі transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Інструменти та платформи для моделей

Щоб запускати, донавчати, надавати доступ до моделей або випробовувати їх, скористайтеся [посібником з інструментів і платформ для моделей AI](AI-Model-Tools-and-Platforms.md).

## Безпека AI

### Межі довіри LLM Gateway

Про безпеку gateway див. тут:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Методологія безпеки AI Agent

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Фреймворки ризиків AI

Два корисні фреймворки для початкового оцінювання ризиків AI-систем — OWASP Machine Learning Security Top 10 і Secure AI Framework (SAIF) від Google. Вони доповнюють один одного, а не становлять вичерпний перелік фреймворків ризиків AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Атакування зловмисними прикладами на основі механістичної інтерпретованості

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Безпека промптів AI

За останні роки LLM спричинили стрімке поширення AI, але вони не ідеальні, і їх можна обманути зловмисними промптами. Це дуже важлива тема для розуміння того, як безпечно використовувати AI та як його атакувати:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE у моделях AI

Розробники та компанії часто запускають моделі, завантажені з інтернету, однак самого завантаження моделі може бути достатньо для виконання довільного коду в системі. Це дуже важлива тема для розуміння того, як безпечно використовувати AI та як його атакувати:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Обхід KYC за допомогою AI

Генеративне відео можна поєднати з ін’єкцією віртуальної камери та маніпуляціями з API камери, щоб обходити ненадійні процеси KYC, перевірки віку та біометричної перевірки реальності:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol для AI

MCP (Model Context Protocol) — це відкритий протокол для підключення AI-застосунків до інструментів і джерел даних. Оскільки MCP-сервери можуть надавати доступ до даних і дій, оцінювання має охоплювати авторизацію, згоду, перевірку вхідних даних інструментів і аналіз меж довіри.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Протокол AI Agent-to-Agent (A2A)

A2A дає агентам змогу знаходити один одного за допомогою agent card і надсилати один одному завдання через HTTP. Перевіряйте agent card, авторизацію завдань, webhook-адреси push-сповіщень і розширені картки:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Відкриті локально розгорнуті AI-сервіси

Визначення типу та тестування відкритих model runner, конструкторів агентів, демонстраційних інтерфейсів ML, обчислювальних кластерів і векторних баз даних, що працюють без автентифікації:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing за допомогою AI та автоматизоване виявлення вразливостей


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Аналіз вихідного коду та перевірка вразливостей за допомогою AI

Про аналіз source/sink, taskflow мобільних точок входу, аудит шаблонів ядра та перевірку з обов’язковим підтвердженням доказами:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Реверс-інжиніринг за допомогою AI

[Часткове підняття коду, виявлення інваріантів MBA, декодування, прив’язане до середовища, та перевірка автоматизованих екстракторів](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Боти для black-box pentesting вебзастосунків за допомогою AI

Агенти на основі LLM можуть автоматизувати тривалі процеси black-box pentesting вебзастосунків за наявності спостережуваності, оркестрації, підтримки автентифікованих сесій і валідації на стійкість до атак:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP — Топ-10 безпеки машинного навчання](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Фреймворк безпеки AI (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Вступ](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
