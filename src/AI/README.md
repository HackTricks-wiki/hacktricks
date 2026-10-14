# ШІ в кібербезпеці

{{#include ../banners/hacktricks-training.md}}

## Основні алгоритми машинного навчання

Найкращий спосіб почати вивчати ШІ — зрозуміти, як працюють основні алгоритми машинного навчання. Це допоможе вам зрозуміти, як працює ШІ, як його використовувати та як його атакувати:


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

На наступній сторінці ви знайдете основи кожного компонента, необхідного для створення базової LLM на основі transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Інструменти та платформи для моделей

Для запуску, донавчання, розгортання або тестування моделей скористайтеся [посібником з інструментів і платформ для моделей ШІ](AI-Model-Tools-and-Platforms.md).

## Безпека ШІ

### Методологія безпеки AI Agent

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Фреймворки оцінювання ризиків ШІ

Два корисні фреймворки для початку оцінювання ризиків систем ШІ — OWASP Machine Learning Security Top 10 і Secure AI Framework (SAIF) від Google. Вони доповнюють один одного, а не є вичерпним переліком фреймворків оцінювання ризиків ШІ.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Атаки з використанням інтерпретованості механізмів

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Безпека промптів ШІ

За останні роки LLM сприяли стрімкому поширенню ШІ, але вони не ідеальні й можуть піддаватися маніпуляціям за допомогою зловмисних промптів. Це дуже важлива тема для розуміння того, як безпечно використовувати ШІ та як його атакувати:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE у моделях ШІ

Розробники й компанії часто запускають моделі, завантажені з Інтернету, однак самого завантаження моделі може бути достатньо для виконання довільного коду в системі. Це дуже важлива тема для розуміння того, як безпечно використовувати ШІ та як його атакувати:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Обхід KYC за допомогою ШІ

Генеративне відео можна поєднати з підміною віртуальної камери та маніпуляціями з API камери, щоб обходити ненадійні процедури KYC, перевірки віку та біометричного визначення присутності:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol для ШІ

MCP (Model Context Protocol) — це відкритий протокол для підключення застосунків ШІ до інструментів і джерел даних. Оскільки сервери MCP можуть надавати доступ до даних і дій, оцінювання безпеки має враховувати авторизацію, згоду, перевірку вхідних даних інструментів і аналіз меж довіри.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing за допомогою ШІ та автоматизований пошук вразливостей


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Реверс-інжиніринг за допомогою ШІ

[Часткове перетворення коду, виявлення інваріантів MBA, декодування, прив’язане до середовища, та перевірка автоматизованих екстракторів](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Боти для black-box веб-пентесту на основі ШІ

Агенти на основі LLM можуть автоматизувати тривалі процеси black-box веб-пентесту за наявності моніторингу, оркестрації, керування автентифікованими сеансами та перевірки на стійкість до атак:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP: десять основних загроз безпеці машинного навчання](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — фреймворк безпечного ШІ (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — вступ](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
