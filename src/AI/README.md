# AI у кібербезпеці

{{#include ../banners/hacktricks-training.md}}

## Основні алгоритми машинного навчання

Найкраще почати вивчення AI з розуміння того, як працюють основні алгоритми машинного навчання. Це допоможе зрозуміти, як працює AI, як його використовувати та як його атакувати:


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

На наступній сторінці описано основи кожного компонента, необхідного для створення базової LLM за допомогою transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Інструменти та платформи для моделей

Щоб запускати, fine-tune-ити, розгортати або випробовувати моделі, скористайтеся [посібником з інструментів і платформ для моделей AI](AI-Model-Tools-and-Platforms.md).

## Безпека AI

### Межі довіри LLM Gateway

Інформацію про безпеку gateway дивіться тут:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Методологія безпеки AI-агентів

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Фреймворки оцінювання ризиків AI

Двома корисними відправними фреймворками для оцінювання ризиків систем AI є OWASP Machine Learning Security Top 10 і Secure AI Framework (SAIF) від Google. Вони доповнюють один одного, але не охоплюють усі фреймворки оцінювання ризиків AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Атаки, керовані механістичною інтерпретованістю

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Безпека промптів AI

За останні роки LLM спричинили різке зростання використання AI, але вони не ідеальні й можуть бути обмануті за допомогою змагальних промптів. Це дуже важлива тема для розуміння того, як безпечно використовувати AI та як його атакувати:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE моделей AI

Розробники й компанії часто запускають моделі, завантажені з Інтернету, але самого завантаження моделі може бути достатньо для виконання довільного коду в системі. Це дуже важлива тема для розуміння того, як безпечно використовувати AI та як його атакувати:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Обхід KYC за допомогою AI

Генеративне відео можна поєднати з ін’єкцією віртуальної камери та маніпуляцією API камери, щоб обходити ненадійні процедури KYC, перевірки віку та біометричної перевірки присутності:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol для AI

MCP (Model Context Protocol) — це відкритий протокол для підключення застосунків AI до інструментів і джерел даних. Оскільки сервери MCP можуть надавати доступ до даних і дій, під час оцінювання потрібно перевіряти авторизацію, згоду, валідацію вхідних даних інструментів і межі довіри.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Протокол AI Agent-to-Agent (A2A)

A2A дає агентам змогу знаходити один одного за допомогою картки агента та надсилати завдання через HTTP. Перевіряйте картки агентів, авторизацію завдань, вебхуки push-сповіщень і розширені картки:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Відкриті самостійно розгорнуті сервіси AI

Виявлення та тестування відкритих засобів запуску моделей, конструкторів агентів, демонстраційних інтерфейсів ML, обчислювальних кластерів і векторних баз даних, які працюють без автентифікації:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing за допомогою AI та автоматизоване виявлення вразливостей


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Аналіз вихідного коду та перевірка вразливостей за допомогою AI

Для аналізу source/sink, taskflow точок входу в мобільних застосунках, аудиту шаблонів ядра та перевірки з обов’язковим підтвердженням доказами:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Реверс-інжиніринг за допомогою AI

[Часткове перетворення на проміжне представлення, виявлення інваріантів MBA, декодування, прив’язане до середовища, та перевірка автоматизованих екстракторів](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Боти для Black-Box AI pentesting вебзастосунків

Агенти на основі LLM можуть автоматизувати тривалі робочі процеси black-box pentesting вебзастосунків за наявності засобів спостереження, оркестрації, роботи з автентифікованими сесіями та adversarial validation:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP: десять основних загроз безпеці машинного навчання](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — фреймворк безпеки AI (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — вступ](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
