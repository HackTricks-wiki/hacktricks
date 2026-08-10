# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Логотипи Hacktricks і motion design від_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Ваша локальна копія HackTricks буде доступна за адресою [http://localhost:3337](http://localhost:3337) менш ніж за 5 хвилин (потрібно зібрати книгу, будьте терплячі).

Альтернативно, якщо у вас є Docker Compose, просто виконайте наведену нижче команду з кореня репозиторію:
```bash
docker compose up
```
Це використовує вбудований `docker-compose.yml`, щоб обслуговувати гілку, наразі вибрану на хості, за адресою [http://localhost:3337](http://localhost:3337) із live reload. Щоб змінити мову під час використання Compose, виберіть потрібну мовну гілку перед запуском сервісу.

## Партнери HackTricks

---

## Друзі HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber надає послуги penetration testing, аудиту безпеки, розробки експлойтів і досліджень, інструменти та послуги з підвищення обізнаності щодо безпеки. На сайті компанії зазначено, що її команда складається з penetration testers, програмістів і дослідників безпеки з понад десятирічним досвідом.<sup>[[1]](#references)</sup>

Ви можете переглянути їхній **блог** за адресою [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

**STM Cyber** також підтримує open source проєкти з кібербезпеки, як-от HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti — це провайдер краудсорсингових послуг безпеки, який через глобальну спільноту дослідників пропонує bug bounty та penetration-testing послуги. Її платформа поєднує безперервне bug bounty покриття з PTaaS на вимогу та керованими програмами розкриття вразливостей.<sup>[[2]](#references)</sup>

**Порада щодо bug bounty**: приєднайтеся до Intigriti через [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) і ознайомтеся з її bug bounty програмами.

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security пропонує практичне навчання з AI security у власному темпі для security engineers, фахівців AppSec і розробників. Її AI Security Certification охоплює основи LLM та агентів, RAG і vector databases, threat modeling, prompt-injection і MCP attacks, а також defensive architecture.<sup>[[3]](#references)</sup>

👉 Докладніше про курс AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** надає API для Google та інших пошукових систем, повертаючи структуровані дані SERP із такими функціями, як результати з урахуванням місцезнаходження, Maps, Shopping і Knowledge Graph.<sup>[[4]](#references)</sup>

Щоб дізнатися більше, перегляньте їхній [**блог**](https://serpapi.com/blog/), випробуйте приклад у їхньому [**playground**](https://serpapi.com/playground) або [**створіть безкоштовний акаунт**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** пропонує курси з mobile та AI security у власному темпі. Каталог охоплює аудит і reverse engineering мобільних застосунків за допомогою таких інструментів, як Ghidra, Frida і LLDB, а також лабораторні роботи з атак і захисту AI/LLM.<sup>[[5]](#references)[[6]](#references)</sup>

Перегляньте [каталог курсів 8kSec Academy](https://academy.8ksec.io/).

---

### [NaxusAI – AI Powered Security Scanner](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**Naxus** просуває offensive-AI платформу, яка створює карту коду та інфраструктури, а потім використовує static і dynamic agents для пошуку та перевірки експлуатованих слабких місць із доказами proof-of-concept і рекомендаціями щодо виправлення.<sup>[[7]](#references)</sup>

**Порада щодо безпеки коду**: ознайомтеся з Naxus для пошуку вразливостей у коді та інфраструктурі.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec надає послуги penetration testing, підписки на послуги безпеки, staffing і оцінювання вразливостей. На сайті компанії зазначено, що вона працює на міжнародному рівні та охоплює offensive security, defensive security, а також напрямки governance, risk і compliance.<sup>[[8]](#references)</sup>

Щоб дізнатися більше, відвідайте їхній [**вебсайт**](https://websec.net/en/) або [**блог**](https://websec.net/blog/).

Окрім зазначеного вище, WebSec також є **відданим прихильником HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Створено для польових умов. Створено навколо вас.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) надає навчання з кібербезпеки під керівництвом експертів, із власноруч розробленим контентом і лабораторними роботами на основі реальної інфраструктури. Їхні програми адаптовані до потреб організацій і охоплюють етапи від оцінювання до впровадження.<sup>[[9]](#references)</sup> Щодо індивідуального навчання звертайтеся [**сюди**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Що вирізняє їхнє навчання:**
* Власноруч розроблений контент і лабораторні роботи
* Підтримка інструментами та платформами найвищого рівня
* Розроблено та викладається практиками

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions зосереджується на консалтингу з кібербезпеки для сфер **Education** і **FinTech**, зокрема на оцінюванні cloud, внутрішніх і зовнішніх penetration tests, оцінюванні вразливостей та підтримці compliance.<sup>[[10]](#references)</sup>

Будьте в курсі останніх подій у сфері кібербезпеки, відвідавши наш [**блог**](https://www.lasttowersolutions.com/blog).

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio — це desktop Kubernetes IDE із візуалізацією CloudMaps, навігацією між кластерами, RBAC, Helm, logs, YAML і terminal views. Постачальник зазначає, що програма підключається через kubeconfig без встановлення агентів і підтримує macOS, Windows, Linux та air-gapped clusters.<sup>[[11]](#references)</sup>

---

## Ліцензія та відмова від відповідальності

Перегляньте запис HackTricks Values & FAQ у References нижче.

## Статистика Github

![Статистика Github HackTricks](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [Сертифікація AI Security – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Практична AI Security: атаки, захист і застосування](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [K8Studio](https://k8studio.io/)
- [12] [Реферальне посилання Intigriti HackTricks](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [Відео про спонсорство WebSec](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Курси Cyber Helmets](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [HackTricks Values & FAQ](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
