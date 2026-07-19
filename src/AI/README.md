# AI у кібербезпеці

{{#include ../banners/hacktricks-training.md}}

## Основні алгоритми машинного навчання

Найкращий спосіб почати вивчати AI — зрозуміти, як працюють основні алгоритми машинного навчання. Це допоможе вам зрозуміти, як працює AI, як його використовувати та як його атакувати:


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

На наступній сторінці ви знайдете основи кожного компонента для створення базового LLM за допомогою transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Безпека AI

### Фреймворки ризиків AI

На цей момент основними 2 фреймворками для оцінювання ризиків AI-систем є OWASP ML Top 10 і Google SAIF:


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Безпека промптів AI

LLMs спричинили стрімке поширення використання AI протягом останніх років, але вони не є досконалими, і їх можна обманути за допомогою adversarial prompts. Це дуже важлива тема для розуміння того, як безпечно використовувати AI і як його атакувати:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE у моделях AI

Розробники та компанії дуже часто запускають моделі, завантажені з Internet, однак навіть простого завантаження моделі може бути достатньо для виконання довільного коду в системі. Це дуже важлива тема для розуміння того, як безпечно використовувати AI і як його атакувати:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Обхід KYC за допомогою AI

Generative video можна поєднати з virtual-camera injection і маніпуляцією camera API для обходу слабких процедур KYC, перевірки віку та перевірки життєздатності біометричних даних:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol для AI

MCP (Model Context Protocol) — це протокол, який дозволяє клієнтам AI-агентів підключатися до зовнішніх інструментів і джерел даних у plug-and-play режимі. Це забезпечує складні робочі процеси та взаємодію між AI-моделями і зовнішніми системами:


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing за допомогою AI та автоматизоване виявлення вразливостей


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Web Black-Box AI Pentester Bots

Агенти на основі LLM можуть автоматизувати тривалі робочі процеси black-box web pentesting, якщо вони мають підтримку observability, orchestration, роботи з автентифікованими сесіями та adversarial validation:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
