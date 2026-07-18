# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Логотипи та motion design Hacktricks від_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Ваша локальна копія HackTricks буде **доступна за адресою [http://localhost:3337](http://localhost:3337)** менш ніж через <5 хвилин (потрібно зібрати книгу, будьте терплячі).

Або, якщо у вас є Docker Compose, просто виконайте з кореня репозиторію:
```bash
docker compose up
```
Це використовує включений `docker-compose.yml`, щоб обслуговувати гілку, яка наразі checkout-нута на хості, за адресою [http://localhost:3337](http://localhost:3337) з live reload. Щоб змінити мову під час використання Compose, checkout-ніть потрібну мовну гілку перед запуском сервісу.

## Партнери HackTricks

---

## Друзі HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) — чудова cybersecurity-компанія, чиє гасло — **HACK THE UNHACKABLE**. Вони проводять власні дослідження та розробляють власні hacking tools, щоб **пропонувати кілька цінних cybersecurity-сервісів**, зокрема pentesting, Red teams і training.

Ви можете переглянути їхній **блог** за адресою [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** також підтримує open source-проєкти у сфері cybersecurity, зокрема HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** — це **№1 у Європі** ethical hacking і **bug bounty platform.**

**Порада щодо bug bounty**: **зареєструйтеся** в **Intigriti**, преміальній **bug bounty platform, створеній hackers для hackers**! Приєднуйтеся до нас на [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) вже сьогодні та почніть отримувати винагороди до **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security проводить **практичне AI Security training** з **інженерним, практичним лабораторним підходом**. Наші курси створені для security engineers, AppSec-фахівців і developers, які хочуть **створювати, ламати та захищати реальні AI/LLM-powered applications**.

**AI Security Certification** зосереджується на практичних навичках, зокрема:
- Захист LLM і AI-powered applications
- Threat modeling для AI-систем
- Embeddings, vector databases і RAG security
- LLM attacks, сценарії зловживань і практичний захист
- Secure design patterns і міркування щодо deployment

Усі курси доступні **on-demand**, орієнтовані на **лабораторні роботи** та побудовані навколо **реальних компромісів у сфері security**, а не лише теорії.

👉 Докладніше про AI Security course:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** пропонує швидкі та зручні real-time APIs для **доступу до результатів пошукових систем**. Вони скрейплять пошукові системи, обробляють proxies, розв’язують captchas і аналізують усі розширені структуровані дані за вас.

Підписка на один із планів SerpApi включає доступ до понад 50 різних APIs для скрейпінгу різних пошукових систем, зокрема Google, Bing, Baidu, Yahoo, Yandex та інших.\
На відміну від інших провайдерів, **SerpApi не просто скрейпить органічні результати**. Відповіді SerpApi стабільно містять усі ads, вбудовані зображення та відео, knowledge graphs, а також інші елементи й функції, представлені в результатах пошуку.

Серед поточних клієнтів SerpApi — **Apple, Shopify і GrubHub**.\
Для отримання додаткової інформації перегляньте їхній [**блог**](https://serpapi.com/blog/)**,** або спробуйте приклад у їхньому [**playground**](https://serpapi.com/playground)**.**\
Ви можете **створити безкоштовний обліковий запис** [**тут**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** навчає offensive mobile та AI security під керівництвом активних researchers — тієї самої команди, що створює CVE writeups і виступає на Black Hat, HITB та Zer0con. Курси проходяться у власному темпі, побудовані навколо лабораторних робіт на реальних цілях і доповнені практичною сертифікацією.

Каталог охоплює два напрямки:

**Mobile Security** — iOS та Android від рівня застосунків до нижчих рівнів: reverse engineering за допомогою Ghidra і LLDB, ARM64 exploitation, kernel internals і сучасні mitigations (PAC, MTE, SELinux), механізми jailbreak і rooting.

**AI Security** — два повноцінні курси, що охоплюють усю галузь. Practical AI Security пояснює, як працюють LLMs, RAG pipelines, AI agents і MCP, а також як їх атакувати та захищати. Advanced AI Security зосереджений на практичній розробці на передньому краї технологій: red teaming AI-систем у масштабі за допомогою Garak і PyRIT, exploitation MCP servers, встановлення та виявлення model backdoors, а також fine-tuning attacks і defenses на Apple Silicon.

Курси та сертифікації:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** — це AI-powered security platform для пошуку vulnerabilities, які можна експлуатувати, до того, як це зроблять attackers.

**Порада щодо code security**: зареєструйтеся в NaxusAI — smart vulnerability monitoring platform, створеній для developers і security teams! Приєднуйтеся до нас сьогодні та почніть використовувати AI для **виявлення, перевірки й виправлення реальних security risks до того, як вони потраплять у production**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) — професійна cybersecurity-компанія, розташована в **Амстердамі**, яка допомагає **захищати** бізнеси **по всьому світу** від найновіших cybersecurity threats, надаючи **offensive-security services** із застосуванням **сучасного** підходу.

WebSec — міжнародна security-компанія з офісами в Амстердамі та Вайомінгу. Вони пропонують **комплексні security services**, тобто роблять усе: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing та багато іншого.

Ще одна цікава особливість WebSec: на відміну від середнього показника в галузі, WebSec **дуже впевнена у своїх навичках**, настільки, що **гарантує найкращі результати**, як зазначено на їхньому сайті: "**If we can't hack it, You don't pay it!**". Для отримання додаткової інформації відвідайте їхній [**website**](https://websec.net/en/) і [**blog**](https://websec.net/blog/)!

Крім того, WebSec є **відданим прихильником HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Створено для роботи. Побудовано навколо вас.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) розробляє та проводить ефективне cybersecurity training, створене й очолюване
галузевими experts. Їхні програми виходять за межі теорії, надаючи командам глибоке
розуміння та практичні навички за допомогою спеціальних середовищ, що відображають реальні
threats. Щодо індивідуального training звертайтеся до нас [**тут**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Що вирізняє їхнє training:**
* Власноруч створений контент і labs
* Підтримка провідними tools і platforms
* Розроблено та проводиться practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions надає спеціалізовані cybersecurity services для установ у сферах **Education** і **FinTech**, зосереджуючись на **penetration testing, cloud security assessments** і
**compliance readiness** (SOC 2, PCI-DSS, NIST). Наша команда включає **OSCP і CISSP
сертифікованих professionals**, які забезпечують глибоку technical expertise та розуміння галузевих стандартів у
кожному проєкті.

Ми виходимо за межі автоматизованих сканувань, проводячи **manual, intelligence-driven testing**, адаптоване до
середовищ із високими вимогами. Від захисту студентських записів до убезпечення фінансових транзакцій —
ми допомагаємо організаціям захищати найважливіше.

_“Якісний захист вимагає знання нападу; ми забезпечуємо security через розуміння.”_

Будьте поінформовані та в курсі останніх подій у cybersecurity, відвідавши наш [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE дає змогу DevOps, DevSecOps і developers ефективно керувати, контролювати та захищати Kubernetes-кластери. Використовуйте наші AI-driven insights, advanced security framework та інтуїтивний CloudMaps GUI, щоб візуалізувати свої кластери, розуміти їхній стан і діяти впевнено.

Крім того, K8Studio **сумісний з усіма основними kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift та іншими).

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## Ліцензія та застереження

Перегляньте їх тут:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Статистика Github

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)
