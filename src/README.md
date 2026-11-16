# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Логотипи та motion design від_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Запустити HackTricks локально

```bash
# Download latest version of hacktricks
git clone https://github.com/HackTricks-wiki/hacktricks

# Select the language you want to use
export HT_LANG="master" # Leave master for English
# "af" for Afrikaans
# "de" for German
# "el" for Greek
# "es" for Spanish
# "fr" for French
# "hi" for Hindi
# "it" for Italian
# "ja" for Japanese
# "ko" for Korean
# "pl" for Polish
# "pt" for Portuguese
# "sr" for Serbian
# "sw" for Swahili
# "tr" for Turkish
# "uk" for Ukrainian
# "vi" for Vietnamese
# "zh" for Chinese

# Run the docker container indicating the path to the hacktricks folder
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $HT_LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```

Ваша локальна копія HackTricks буде **доступна за адресою [http://localhost:3337](http://localhost:3337)** менш ніж за 5 хвилин (потрібно зібрати книгу, зачекайте).

Або, якщо у вас є Docker Compose, просто виконайте таку команду з кореня репозиторію:

```bash
docker compose up
```

Це використовує вбудований `docker-compose.yml`, щоб надавати гілку, яка зараз checkout-нута на хості, за адресою [http://localhost:3337](http://localhost:3337) із live reload. Щоб змінити мову під час використання Compose, перейдіть на потрібну мовну гілку перед запуском сервісу.

## Партнери HackTricks

---

## Друзі HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber надає послуги з тестування на проникнення, аудиту безпеки, розробки експлойтів і досліджень, створює інструменти та проводить навчання з питань безпеки. На сайті компанія описує свою команду тестувальників на проникнення, програмістів і дослідників безпеки, які мають понад десятирічний досвід.<sup>[[1]](#references)</sup>

Більше можна дізнатися в їхньому **блозі**: [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

**STM Cyber** також підтримує open source проєкти з кібербезпеки, як-от HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti — краудсорсингова компанія з безпеки, яка надає послуги bug bounty та тестування на проникнення завдяки глобальній спільноті дослідників. Її платформа поєднує постійне покриття bug bounty з PTaaS на вимогу та керованими програмами розкриття вразливостей.<sup>[[2]](#references)</sup>

**Порада щодо bug bounty**: приєднуйтеся до Intigriti за посиланням [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) і ознайомтеся з програмами bug bounty.

---

### [Modern Security – Платформа навчання безпеки AI та застосунків](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security пропонує практичне самостійне навчання безпеки AI для інженерів із безпеки, фахівців AppSec і розробників. Їхня сертифікація з безпеки AI охоплює основи LLM та агентів, RAG і векторні бази даних, моделювання загроз, атаки prompt injection і MCP, а також захисну архітектуру.<sup>[[3]](#references)</sup>

👉 Більше інформації про курс із безпеки AI:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** надає API для Google та інших пошукових систем, повертаючи структуровані дані SERP із такими можливостями, як результати з урахуванням місцезнаходження, Maps, Shopping і Knowledge Graph.<sup>[[4]](#references)</sup>

Докладніше читайте в їхньому [**блозі**](https://serpapi.com/blog/), спробуйте приклад у їхньому [**інтерактивному середовищі**](https://serpapi.com/playground) або [**створіть безкоштовний обліковий запис**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – Поглиблені курси з безпеки мобільних пристроїв та AI](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** пропонує самостійні курси з безпеки мобільних пристроїв та AI. Програма охоплює аудит і реверс-інжиніринг мобільних застосунків за допомогою таких інструментів, як Ghidra, Frida та LLDB, а також лабораторні роботи з атак і захисту AI/LLM.<sup>[[5]](#references)[[6]](#references)</sup>

Перегляньте [каталог курсів 8kSec Academy](https://academy.8ksec.io/).

---

### [NaxusAI – Автономна наступальна безпека](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt="NaxusAI logo"><figcaption></figcaption></figure>

**Naxus** — це платформа наступальної безпеки на базі AI для повного сканування зовнішньої поверхні атаки, аудиту мобільних застосунків, black-box тестування вебзастосунків і перевірки вихідного коду. Її агенти перевіряють, чи можна використати знайдені проблеми, і надають відстежувані докази, експлойти proof-of-concept і практичні рекомендації з усунення.<sup>[[7]](#references)</sup>

**Порада щодо аудиту безпеки**: використовуйте Naxus для повністю автономних комплексних аудитів зовнішніх активів, мобільних і вебзастосунків та вихідного коду.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec надає послуги з тестування на проникнення, підписки на послуги безпеки, підбору фахівців і оцінювання вразливостей. На сайті зазначено, що компанія працює на міжнародному рівні та займається наступальною й оборонною безпекою, а також управлінням, ризиками та відповідністю вимогам.<sup>[[8]](#references)</sup>

Докладніше дивіться на їхньому [**сайті**](https://websec.net/en/) або в [**блозі**](https://websec.net/blog/).

Крім того, WebSec є **відданим прихильником HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Створено для практичної роботи. З урахуванням ваших потреб.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) пропонує навчання з кібербезпеки під керівництвом експертів, з індивідуально розробленими матеріалами та лабораторними роботами на основі реальної інфраструктури. Програми адаптовано до потреб організацій: від оцінювання до впровадження.<sup>[[9]](#references)</sup> Щоб дізнатися про індивідуальне навчання, зверніться [**сюди**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Переваги їхнього навчання:**
* Індивідуально розроблені матеріали та лабораторні роботи
* Використання найкращих інструментів і платформ
* Розроблено та викладається практиками

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions спеціалізується на консалтингу з кібербезпеки для **освітньої галузі** та **FinTech**. Послуги охоплюють оцінювання хмарної безпеки, внутрішнє й зовнішнє тестування на проникнення, оцінювання вразливостей і підтримку відповідності вимогам.<sup>[[10]](#references)</sup>

Читайте наш [**блог**](https://www.lasttowersolutions.com/blog), щоб бути в курсі останніх новин кібербезпеки.

---

### [Beaki — їжа, що пасує саме вам](https://www.beaki.app/)

<figure class="sponsor-logo"><img src="images/beaki-logo.png" alt="Beaki logo"><figcaption></figcaption></figure>

**Beaki** — це персоналізований сканер продуктів, лічильник калорій і трекер харчування. Скануйте штрихкоди й полиці супермаркетів, фотографуйте або описуйте страви та меню ресторанів і отримуйте зрозумілі оцінки з урахуванням ваших цілей, раціону, алергій і стану здоров’я. Beaki також відстежує калорії та макронутрієнти й створює персоналізовані плани харчування зі списками покупок.<sup>[[11]](#references)</sup>

[**Завантажте Beaki безкоштовно**](https://www.beaki.app/?utm_source=hacktricks&utm_medium=partner&utm_campaign=hacktricks) на Android або iPhone.

---

## Ліцензія та застереження

Дивіться запис HackTricks Values & FAQ у розділі References нижче.

## Статистика GitHub

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [Сертифікація з безпеки AI – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Практична безпека AI: атаки, захист і застосування](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [Beaki](https://www.beaki.app/)
- [12] [Реферальне посилання Intigriti HackTricks](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [Відео про спонсорство WebSec](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Курси Cyber Helmets](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [Цінності та поширені запитання HackTricks](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
