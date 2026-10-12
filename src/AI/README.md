# ШІ в кібербезпеці

{{#include ../banners/hacktricks-training.md}}

## Основні алгоритми машинного навчання

Найкраще почати вивчення ШІ з розуміння принципів роботи основних алгоритмів машинного навчання. Це допоможе зрозуміти, як працює ШІ, як ним користуватися та як його атакувати:


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

На наступній сторінці наведено основи кожного компонента, потрібного для побудови базової LLM за допомогою transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Безпека ШІ

### Методологія безпеки AI Agent

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Фреймворки оцінювання ризиків ШІ

Два корисні фреймворки, з яких можна почати оцінювання ризиків систем ШІ, — це OWASP Machine Learning Security Top 10 і Secure AI Framework (SAIF) від Google. Вони доповнюють один одного, але не є вичерпним переліком фреймворків оцінювання ризиків ШІ.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Атаки на основі інтерпретованості механізмів

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Безпека промптів ШІ

За останні роки LLM значно поширили використання ШІ, але вони не ідеальні, і їх можна обманути за допомогою адверсарних промптів. Це дуже важлива тема, щоб зрозуміти, як безпечно користуватися ШІ та як його атакувати:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE в моделях ШІ

Розробники й компанії часто запускають моделі, завантажені з Інтернету, однак для виконання довільного коду в системі може бути достатньо лише завантажити модель. Це дуже важлива тема, щоб зрозуміти, як безпечно користуватися ШІ та як його атакувати:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Обхід KYC за допомогою ШІ

Генеративне відео можна поєднати з ін’єкцією віртуальної камери та маніпуляцією API камери, щоб обходити ненадійні процедури KYC, перевірки віку та біометричної перевірки присутності:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol для ШІ

MCP (Model Context Protocol) — це відкритий протокол для підключення застосунків ШІ до інструментів і джерел даних. Оскільки сервери MCP можуть надавати доступ до даних і дій, оцінювання має охоплювати авторизацію, згоду, перевірку введених даних для інструментів і аналіз меж довіри.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing за допомогою ШІ та автоматизоване виявлення вразливостей


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Реверс-інжиніринг за допомогою ШІ

[Часткове відновлення коду, виявлення інваріантів MBA, декодування, прив’язане до середовища, та перевірка автоматизованих екстракторів](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Вебботи AI-пентестера типу black-box

Агенти на базі LLM можуть автоматизувати тривалі робочі процеси black-box вебпентестингу за наявності засобів спостереження, оркестрації, керування автентифікованими сесіями та адверсарної перевірки:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP: десятка найкращих практик безпеки машинного навчання](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — фреймворк Secure AI (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — вступ](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
