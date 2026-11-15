# AI у кібербезпеці

{{#include ../banners/hacktricks-training.md}}

## Основні алгоритми машинного навчання

Щоб почати вивчати AI, найкраще спершу зрозуміти, як працюють основні алгоритми машинного навчання. Це допоможе зрозуміти, як працює AI, як ним користуватися та як його атакувати:


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

### Підготовка даних моделі та оцінювання

Про розбиття наборів даних, класичні метрики та атаки на стороні відповіді під час оцінювання на основі LLM див. [підготовку даних моделі та оцінювання](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### Архітектура LLM

На наступній сторінці описано основи кожного компонента, необхідного для створення базової LLM на основі transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Інструменти та платформи для моделей

Щоб запускати, донавчати, розгортати або випробовувати моделі, скористайтеся [посібником з інструментів і платформ для моделей AI](AI-Model-Tools-and-Platforms.md).

## Безпека AI

### Межі довіри LLM Gateway

Інформацію про безпеку gateway див. тут:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Методологія безпеки AI-агентів

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Фреймворки оцінювання ризиків AI

Два корисні фреймворки для початкового оцінювання ризиків AI-систем — OWASP Machine Learning Security Top 10 і Secure AI Framework (SAIF) від Google. Вони доповнюють один одного, але не охоплюють усі фреймворки оцінювання ризиків AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Mechanistic-Interpretability-Guided Adversarial Attacks

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Межі довіри вбудованого браузера

Про мости браузера для desktop-асистентів, підміну адрес вкладок і читання локальних файлів у контексті worker див. [межі довіри вбудованого браузера AI-асистента](AI-Embedded-Browser-Trust-Boundaries.md).

### Безпека промптів AI

За останні роки використання AI різко зросло завдяки LLM, але вони не ідеальні: їх можна обманути за допомогою ворожих промптів. Це важлива тема для розуміння того, як безпечно використовувати AI та як його атакувати:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE у моделях AI

Розробники й компанії часто запускають моделі, завантажені з Інтернету, однак самого завантаження моделі може бути достатньо для виконання довільного коду в системі. Це важлива тема для розуміння того, як безпечно використовувати AI та як його атакувати:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Обхід KYC за допомогою AI

Генеративне відео можна поєднати з підміною віртуальної камери та маніпуляціями з API камери, щоб обходити ненадійні процеси KYC, перевірки віку й біометричної перевірки присутності:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol для AI

MCP (Model Context Protocol) — це відкритий протокол для підключення застосунків AI до інструментів і джерел даних. Оскільки сервери MCP можуть надавати доступ до даних і дій, під час оцінювання потрібно враховувати авторизацію, згоду, перевірку введених даних інструментів і аналіз меж довіри.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Протокол AI Agent-to-Agent (A2A)

A2A дає агентам змогу знаходити один одного через картку агента та надсилати завдання через HTTP. Перевіряйте картки агентів, авторизацію завдань, webhook-сповіщення та розширені картки:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Відкриті self-hosted сервіси AI

Виявлення та тестування відкритих без автентифікації середовищ запуску моделей, конструкторів агентів, демонстраційних інтерфейсів ML, обчислювальних кластерів і векторних баз даних:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing і автоматизоване виявлення вразливостей за допомогою AI


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Аналіз вихідного коду та перевірка вразливостей за допомогою AI

Про аналіз джерел і приймачів даних, taskflow точок входу в мобільних застосунках, аудит шаблонів ядра та перевірку з обов’язковим підтвердженням доказами див. тут:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Реверс-інжиніринг за допомогою AI

[Часткове відновлення коду, виявлення інваріантів MBA, декодування, прив’язане до середовища, і перевірка автоматизованих екстракторів](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Bots

Агенти на основі LLM можуть автоматизувати тривалі процеси black-box вебпентестингу, якщо забезпечено спостережуваність, оркестрацію, роботу з автентифікованими сесіями та перевірку стійкості до атак:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introduction](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
