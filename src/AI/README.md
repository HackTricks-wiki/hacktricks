# ШІ в кібербезпеці

{{#include ../banners/hacktricks-training.md}}

## Основні алгоритми машинного навчання

Найкраще почати вивчення ШІ з розуміння принципів роботи основних алгоритмів машинного навчання. Це допоможе вам зрозуміти, як працює ШІ, як ним користуватися та як його атакувати:


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

Про поділ датасетів, класичні метрики та атаки на основі відповідей проти оцінювання на базі LLM див. у матеріалі [підготовка даних моделі та оцінювання](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### Архітектура LLM

На наступній сторінці ви знайдете основи кожного компонента, необхідного для створення базової LLM на основі transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Інструменти та платформи для моделей

Щоб запускати моделі, виконувати fine-tuning, надавати до них доступ або випробовувати їх, скористайтеся [посібником з інструментів і платформ для моделей ШІ](AI-Model-Tools-and-Platforms.md).

## Безпека ШІ

### Межі довіри LLM Gateway

Про безпеку gateway див. тут:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Методологія безпеки AI Agent

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Фреймворки ризиків ШІ

Два корисні фреймворки для початку оцінювання ризиків систем ШІ — OWASP Machine Learning Security Top 10 і Google Secure AI Framework (SAIF). Вони доповнюють один одного, а не становлять вичерпний перелік фреймворків ризиків ШІ.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Атакі на основі механістичної інтерпретованості

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Межі довіри вбудованого браузера

Про мости браузера desktop-assistant, підміну адреси вкладки та читання локальних файлів у контексті worker див. у матеріалі [межі довіри вбудованого браузера AI assistant](AI-Embedded-Browser-Trust-Boundaries.md).

### Безпека промптів ШІ

За останні роки використання ШІ стрімко зросло завдяки LLM, але вони не ідеальні, і їх можна обманути за допомогою adversarial prompts. Це дуже важлива тема, щоб зрозуміти, як безпечно використовувати ШІ та як його атакувати:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE у моделях ШІ

Розробники та компанії часто запускають моделі, завантажені з Інтернету, однак одного лише завантаження моделі може бути достатньо для виконання довільного коду в системі. Це дуже важлива тема, щоб зрозуміти, як безпечно використовувати ШІ та як його атакувати:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

Про ризики завантаження моделей Keras `.keras`/HDF5, Lambda layers і аналіз gadget після виправлення див. у матеріалі [десеріалізація моделей Keras і пошук gadget](keras-model-deserialization-rce-and-gadget-hunting.md).

### Обхід KYC за допомогою ШІ

Генеративне відео можна поєднати з підміною virtual-camera та маніпуляціями з camera API, щоб обходити ненадійні процедури KYC, перевірки віку та біометричної перевірки присутності:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol для ШІ

MCP (Model Context Protocol) — це відкритий протокол для підключення застосунків ШІ до інструментів і джерел даних. Оскільки MCP-сервери можуть надавати доступ до даних і дій, оцінювання має включати перевірку авторизації, згоди, валідації вхідних даних інструментів і меж довіри.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Протокол взаємодії AI Agent-to-Agent (A2A)

A2A дає агентам змогу знаходити один одного за допомогою agent card і надсилати одне одному завдання через HTTP. Перевіряйте agent cards, авторизацію завдань, push-notification webhooks і розширені cards:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Відкриті self-hosted сервіси ШІ

Визначення типу та тестування відкритих без автентифікації model runners, конструкторів агентів, демонстраційних інтерфейсів ML, обчислювальних кластерів і векторних баз даних:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing за допомогою ШІ та автоматизоване виявлення вразливостей


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Перевірка вихідного коду та валідація вразливостей за допомогою ШІ

Про аналіз source/sink, taskflows мобільних точок входу, аудит шаблонів ядра та валідацію з обов’язковим підтвердженням доказами:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Реверс-інжиніринг за допомогою ШІ

[Часткове відновлення коду, виявлення інваріантів MBA, декодування, прив’язане до середовища, та валідація автоматизованих екстракторів](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Боти для black-box pentesting вебзастосунків на базі ШІ

Агенти на базі LLM можуть автоматизувати тривалі робочі процеси black-box pentesting вебзастосунків, якщо їх підтримують спостережуваність, оркестрація, обробка автентифікованих сесій і adversarial validation:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP — Топ-10 загроз безпеці машинного навчання](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Вступ](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
