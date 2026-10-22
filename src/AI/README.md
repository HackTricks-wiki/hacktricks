# ШІ в кібербезпеці

{{#include ../banners/hacktricks-training.md}}

## Основні алгоритми машинного навчання

Щоб почати вивчати ШІ, найкраще зрозуміти, як працюють основні алгоритми машинного навчання. Це допоможе вам зрозуміти, як працює ШІ, як його використовувати та як його атакувати:


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

Щоб запускати, донавчати, розгортати або випробовувати моделі, скористайтеся [посібником з інструментів і платформ для моделей ШІ](AI-Model-Tools-and-Platforms.md).

## Безпека ШІ

### Межі довіри LLM Gateway

Інформацію про безпеку gateway дивіться тут:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Методологія безпеки AI Agent

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Системи оцінювання ризиків ШІ

Дві корисні системи оцінювання ризиків AI-систем — OWASP Machine Learning Security Top 10 і Secure AI Framework (SAIF) від Google. Вони доповнюють одна одну, але не є вичерпним переліком систем оцінювання ризиків ШІ.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Adversarial-атаки на основі механістичної інтерпретованості

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Безпека промптів ШІ

За останні роки LLM спричинили стрімке поширення ШІ, але вони не ідеальні, і їх можна обманути за допомогою adversarial-промптів. Це дуже важлива тема для розуміння того, як безпечно використовувати ШІ та як його атакувати:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE у моделях ШІ

Розробники та компанії часто запускають моделі, завантажені з Інтернету, однак самого завантаження моделі може бути достатньо для виконання довільного коду в системі. Це дуже важлива тема для розуміння того, як безпечно використовувати ШІ та як його атакувати:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Обхід KYC за допомогою ШІ

Генеративне відео можна поєднати з ін’єкцією віртуальної камери та маніпуляцією API камери, щоб обходити слабкі процеси KYC, перевірки віку та біометричної перевірки «живої» присутності:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol для ШІ

MCP (Model Context Protocol) — це відкритий протокол для підключення програм ШІ до інструментів і джерел даних. Оскільки сервери MCP можуть надавати доступ до даних і дій, під час оцінювання необхідно перевіряти авторизацію, згоду, валідацію вхідних даних інструментів і межі довіри.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing за допомогою ШІ та автоматизоване виявлення вразливостей


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Аналіз вихідного коду за допомогою ШІ та валідація вразливостей

Для аналізу source/sink, мобільних taskflow точок входу, аудиту шаблонів ядра та валідації з перевіркою доказів:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Реверс-інжиніринг за допомогою ШІ

[Часткове перетворення на проміжне представлення, виявлення інваріантів MBA, декодування, прив’язане до середовища, і перевірка автоматизованих екстракторів](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Боти для Web Black-Box AI Pentesting

Агенти на основі LLM можуть автоматизувати тривалі процеси black-box web pentesting за наявності спостережуваності, оркестрації, підтримки автентифікованих сесій і adversarial-валідації:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP: десять головних загроз безпеці машинного навчання](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — безпечна система ШІ (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — вступ](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
