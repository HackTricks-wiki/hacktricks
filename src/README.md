# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Логотипи та motion design HackTricks —_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Запустіть HackTricks локально

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
# "hi" for HindiP
# "it" for Italian
# "ja" for Japanese
# "ko" for Korean
# "pl" for Polish
# "pt" for Portuguese
# "sr" for Serbian
# "sw" for Swahili
# "tr" for Turkish
# "uk" for Ukrainian
# "zh" for Chinese

# Run the docker container indicating the path to the hacktricks folder
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $HT_LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```

Ваша локальна копія HackTricks буде **доступна за адресою [http://localhost:3337](http://localhost:3337)** менш ніж за 5 хвилин (потрібно зібрати книгу, зачекайте).

Або, якщо у вас є Docker Compose, просто виконайте таку команду з кореневої папки репозиторію:

```bash
docker compose up
```

Це використовує вбудований `docker-compose.yml`, щоб обслуговувати гілку, на яку зараз переключено на хості, за адресою [http://localhost:3337](http://localhost:3337) із live reload. Щоб змінити мову під час використання Compose, переключіться на потрібну мовну гілку перед запуском сервісу.

## Партнери HackTricks

---

## Друзі HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber надає послуги з penetration testing, аудиту безпеки, розробки експлойтів і дослідницької роботи, створення інструментів та підвищення обізнаності з безпеки. На сайті компанія описує команду тестувальників на проникнення, програмістів і дослідників безпеки з понад десятирічним досвідом.<sup>[[1]](#references)</sup>

Відвідайте їхній **блог** за адресою [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

**STM Cyber** також підтримує open-source проєкти з кібербезпеки, як-от HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti — це краудсорсингова платформа безпеки, яка надає послуги bug bounty та penetration testing завдяки глобальній спільноті дослідників. Платформа поєднує безперервне покриття bug bounty з послугами PTaaS на вимогу та керованими програмами розкриття вразливостей.<sup>[[2]](#references)</sup>

**Порада щодо bug bounty**: Приєднуйтеся до Intigriti за посиланням [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) та ознайомтеся з їхніми програмами bug bounty.

---

### [Modern Security – Платформа навчання AI та безпеки застосунків](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security пропонує навчання з безпеки AI у власному темпі з практичними завданнями для інженерів із безпеки, фахівців AppSec і розробників. Сертифікація з безпеки AI охоплює основи LLM і агентів, RAG і векторні бази даних, моделювання загроз, атаки prompt injection і MCP, а також захисну архітектуру.<sup>[[3]](#references)</sup>

👉 Докладніше про курс із безпеки AI:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** надає API для Google та інших пошукових систем, повертаючи структуровані дані SERP із такими можливостями, як результати з урахуванням місцезнаходження, Maps, Shopping і Knowledge Graph.<sup>[[4]](#references)</sup>

Докладніше читайте в їхньому [**блозі**](https://serpapi.com/blog/), спробуйте приклад у їхньому [**середовищі для експериментів**](https://serpapi.com/playground) або [**створіть безкоштовний обліковий запис**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – Поглиблені курси з безпеки мобільних пристроїв та AI](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** пропонує курси з безпеки мобільних пристроїв і AI, які проходять у власному темпі. Каталог охоплює аудит і реверс-інжиніринг мобільних застосунків за допомогою таких інструментів, як Ghidra, Frida та LLDB, а також лабораторні роботи з атак і захисту AI/LLM.<sup>[[5]](#references)[[6]](#references)</sup>

Перегляньте [каталог курсів 8kSec Academy](https://academy.8ksec.io/).

---

### [NaxusAI – Сканер безпеки на базі AI](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**Naxus** пропонує платформу offensive AI, яка картографує код та інфраструктуру, а потім використовує статичні й динамічні агенти для пошуку й перевірки експлуатованих слабких місць, надаючи підтвердження концепції та рекомендації щодо усунення.<sup>[[7]](#references)</sup>

**Порада щодо безпеки коду**: Дізнайтеся про Naxus для пошуку вразливостей у коді та інфраструктурі.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec надає послуги penetration testing, підписки на послуги безпеки, підбору персоналу та оцінювання вразливостей. На сайті зазначено, що компанія працює на міжнародному рівні та займається offensive security, defensive security, а також управлінням, ризиками й відповідністю вимогам.<sup>[[8]](#references)</sup>

Докладніше дивіться на їхньому [**сайті**](https://websec.net/en/) або в [**блозі**](https://websec.net/blog/).

Крім того, WebSec — це **відданий прихильник HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Створено для роботи. Створено з урахуванням ваших потреб.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) пропонує навчання з кібербезпеки під керівництвом експертів, із індивідуально розробленими матеріалами й лабораторними роботами на основі реальних інфраструктур. Програми адаптуються до потреб організацій і охоплюють етапи від оцінювання до впровадження.<sup>[[9]](#references)</sup> Щоб дізнатися про індивідуальне навчання, зверніться [**сюди**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Чим вирізняється їхнє навчання:**
* Індивідуально розроблені матеріали й лабораторні роботи
* Підтримка провідних інструментів і платформ
* Створено й викладається практиками

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions спеціалізується на консалтингу з кібербезпеки для **освіти** та **FinTech**, зокрема на оцінюванні хмарних середовищ, внутрішньому й зовнішньому penetration testing, оцінюванні вразливостей і підтримці з питань відповідності вимогам.<sup>[[10]](#references)</sup>

Дізнавайтеся про останні новини кібербезпеки та будьте в курсі подій, відвідавши наш [**блог**](https://www.lasttowersolutions.com/blog).

---

### [K8Studio — зручніший GUI для керування Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio — це настільне IDE для Kubernetes із візуалізацією CloudMaps, навігацією між кластерами, RBAC, Helm, журналами, YAML і терміналом. За словами постачальника, підключення відбувається через kubeconfig без встановлення агентів; підтримуються macOS, Windows, Linux і ізольовані від мережі кластери.<sup>[[11]](#references)</sup>

---

## Ліцензія та застереження

Див. статтю HackTricks «Цінності та поширені запитання» в розділі References нижче.

## Статистика Github

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
- [11] [K8Studio](https://k8studio.io/)
- [12] [Реферальне посилання Intigriti HackTricks](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [Відео про спонсорство WebSec](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Курси Cyber Helmets](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [Цінності та поширені запитання HackTricks](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
