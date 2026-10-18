# AI у кібербезпеці

{{#include ../banners/hacktricks-training.md}}

## Основні алгоритми машинного навчання

Найкращий спосіб почати вивчати AI — зрозуміти, як працюють основні алгоритми машинного навчання. Це допоможе зрозуміти, як працює AI, як його використовувати та як його атакувати:


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

Щоб запускати, донавчати, розгортати моделі або експериментувати з ними, скористайтеся [посібником з інструментів і платформ для моделей AI](AI-Model-Tools-and-Platforms.md).

## Безпека AI

### Методологія безпеки AI Agent

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Фреймворки ризиків AI

Два корисні фреймворки для початкової оцінки ризиків систем AI — OWASP Machine Learning Security Top 10 і Secure AI Framework (SAIF) від Google. Вони доповнюють один одного, а не становлять вичерпний перелік фреймворків ризиків AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Атаки зловмисного впливу, керовані механістичною інтерпретованістю

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Безпека промптів AI

За останні роки LLM спричинили стрімке поширення AI, але вони не ідеальні й можуть бути обмануті зловмисними промптами. Це дуже важлива тема, щоб зрозуміти, як безпечно використовувати AI та як його атакувати:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE у моделях AI

Розробники та компанії часто запускають моделі, завантажені з Інтернету, однак самого завантаження моделі може бути достатньо для виконання довільного коду в системі. Це дуже важлива тема, щоб зрозуміти, як безпечно використовувати AI та як його атакувати:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Обхід KYC за допомогою AI

Генеративне відео можна поєднати з підміною віртуальної камери та маніпуляцією API камери, щоб обійти ненадійні процеси KYC, перевірки віку та біометричної перевірки життєздатності:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol для AI

MCP (Model Context Protocol) — це відкритий протокол для підключення застосунків AI до інструментів і джерел даних. Оскільки сервери MCP можуть надавати доступ до даних і дій, під час оцінювання слід перевіряти авторизацію, згоду, валідацію введених даних для інструментів і межі довіри.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Фаззинг за допомогою AI та автоматизоване виявлення вразливостей


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Аналіз коду та перевірка вразливостей за допомогою AI

Для аналізу source/sink, taskflow точок входу в мобільних застосунках, аудиту шаблонів ядра та перевірки з підтвердженням доказами:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Реверс-інжиніринг за допомогою AI

[Часткове підняття коду, виявлення інваріантів MBA, декодування, прив’язане до середовища, та перевірка автоматизованих екстракторів](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Боти для black-box веб-пентестингу за допомогою AI

Агенти на базі LLM можуть автоматизувати тривалі процеси black-box веб-пентестингу за наявності засобів спостереження, оркестрації, автентифікованого керування сеансами та перевірки на стійкість до зловмисних дій:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP: десятка головних загроз безпеці машинного навчання](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — фреймворк безпечного AI (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — вступ](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
