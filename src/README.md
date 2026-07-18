# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Логотипи Hacktricks і motion design від_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Запуск HackTricks локально
```bash
# Download latest version of hacktricks
git clone https://github.com/HackTricks-wiki/hacktricks

# Select the language you want to use
export LANG="master" # Leave master for english
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
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```
Ваша локальна копія HackTricks буде **доступна за адресою [http://localhost:3337](http://localhost:3337)** менш ніж за 5 хвилин (потрібно зібрати книгу, будьте терплячі).

Якщо у вас є Docker Compose, ви можете просто виконати наведену нижче команду з кореня repo:
```bash
docker compose up
```
Це використовує вбудований `docker-compose.yml`, щоб розгорнути вашу локальну копію за адресою [http://localhost:3337](http://localhost:3337) з live reload.

## Партнери HackTricks

---

## Друзі HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) — чудова компанія з кібербезпеки, девіз якої — **HACK THE UNHACKABLE**. Вони проводять власні дослідження та розробляють власні hacking tools, щоб **пропонувати кілька цінних послуг з кібербезпеки**, зокрема pentesting, Red teams і навчання.

Ви можете переглянути їхній **blog** на [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** також підтримує open source проєкти з кібербезпеки, як-от HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** — це **№1 у Європі** ethical hacking і **bug bounty platform.**

**Bug bounty tip**: **зареєструйтеся** в **Intigriti** — преміальній **bug bounty platform, створеній хакерами для хакерів**! Приєднуйтеся до нас на [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) уже сьогодні та починайте отримувати винагороди до **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security надає **практичне навчання з AI Security** із підходом **engineering-first і hands-on lab**. Наші курси створені для security engineers, фахівців AppSec і розробників, які хочуть **створювати, ламати та захищати реальні застосунки на базі AI/LLM**.

**AI Security Certification** зосереджена на практичних навичках, зокрема:
- Захист застосунків на базі LLM та AI
- Threat modeling для AI-систем
- Embeddings, vector databases і RAG security
- LLM attacks, сценарії зловживань і практичні засоби захисту
- Secure design patterns і міркування щодо розгортання

Усі курси доступні **on-demand**, орієнтовані на **лабораторні роботи** та побудовані навколо **реальних компромісів у сфері безпеки**, а не лише теорії.

👉 Більше інформації про курс AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** пропонує швидкі та прості real-time API для **доступу до результатів пошукових систем**. Вони скрейплять пошукові системи, працюють із проксі, розв’язують captchas і парсять усі багаті структуровані дані за вас.

Підписка на один із тарифів SerpApi включає доступ до понад 50 різних API для скрейпінгу різних пошукових систем, зокрема Google, Bing, Baidu, Yahoo, Yandex та інших.\
На відміну від інших провайдерів, **SerpApi не просто скрейпить органічні результати**. Відповіді SerpApi стабільно містять усі рекламні оголошення, вбудовані зображення та відео, knowledge graphs, а також інші елементи й функції, наявні в результатах пошуку.

Серед поточних клієнтів SerpApi — **Apple, Shopify та GrubHub**.\
Докладнішу інформацію шукайте в їхньому [**blog**](https://serpapi.com/blog/)**,** або випробуйте приклад у їхньому [**playground**](https://serpapi.com/playground)**.**\
Ви можете **створити безкоштовний акаунт** [**тут**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** навчає offensive mobile та AI security під керівництвом активних дослідників — тієї самої команди, яка стоїть за CVE writeups і доповідями на Black Hat, HITB та Zer0con. Курси проходять у власному темпі, побудовані навколо лабораторних робіт на реальних цілях і доповнені практичною сертифікацією.

Каталог охоплює два напрямки:

**Mobile Security** — iOS та Android, від рівня застосунків до нижчих рівнів: reverse engineering за допомогою Ghidra та LLDB, ARM64 exploitation, внутрішня будова kernel і сучасні механізми захисту (PAC, MTE, SELinux), механізми jailbreak і rooting.

**AI Security** — два повноцінні курси, що охоплюють цю сферу. Practical AI Security пояснює, як працюють LLM, RAG pipelines, AI agents і MCP, а також як їх атакувати та захищати. Advanced AI Security зосереджений на практичній розробці передових рішень: red teaming AI-систем у масштабі за допомогою Garak і PyRIT, exploitation MCP servers, встановлення та виявлення model backdoors, а також fine-tuning атак і засобів захисту на Apple Silicon.

Курси та сертифікації:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** — це security platform на базі AI для пошуку vulnerabilities, які можна експлуатувати, перш ніж це зроблять атакувальники.

**Code security tip**: зареєструйтеся в NaxusAI — smart vulnerability monitoring platform, створеній для розробників і security teams! Приєднуйтеся до нас уже сьогодні та почніть використовувати AI для **виявлення, перевірки й виправлення реальних security risks до того, як вони потраплять у production**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) — професійна компанія з кібербезпеки, що базується в **Амстердамі** та допомагає **захищати** бізнеси **в усьому світі** від найновіших кіберзагроз, надаючи **offensive-security services** із застосуванням **сучасного** підходу.

WebSec — міжнародна security company з офісами в Амстердамі та Вайомінгу. Вони пропонують **all-in-one security services**, тобто роблять усе: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing та багато іншого.

Ще одна цікава особливість WebSec: на відміну від середньостатистичної компанії галузі, WebSec **дуже впевнена у своїх навичках** і настільки гарантує їх, що **гарантує найкращі результати**. На їхньому сайті зазначено: "**If we can't hack it, You don't pay it!**". Щоб дізнатися більше, перегляньте їхній [**website**](https://websec.net/en/) і [**blog**](https://websec.net/blog/)!

Окрім зазначеного, WebSec також є **відданим прихильником HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Створено для роботи в польових умовах. Створено навколо вас.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) розробляє та проводить ефективне навчання з кібербезпеки, яке створюють і проводять
галузеві експерти. Їхні програми виходять за межі теорії, забезпечуючи команди глибоким
розумінням і практичними навичками за допомогою спеціальних середовищ, що відображають реальні
загрози. Із запитами щодо індивідуального навчання звертайтеся до нас [**тут**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Що вирізняє їхнє навчання:**
* Власний контент і лабораторні роботи
* Підтримка першокласними інструментами та платформами
* Розроблено та викладається практиками

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions надає спеціалізовані послуги з кібербезпеки для установ у сферах **Education** та **FinTech**,
зосереджуючись на **penetration testing, cloud security assessments**
і **compliance readiness** (SOC 2, PCI-DSS, NIST). До нашої команди входять **OSCP та CISSP
сертифіковані фахівці**, які забезпечують глибоку технічну експертизу та галузеві стандарти
для кожного проєкту.

Ми виходимо за межі автоматизованого сканування, проводячи **manual, intelligence-driven testing**, адаптоване до
середовищ із високими ризиками. Від захисту студентських записів до захисту фінансових транзакцій —
ми допомагаємо організаціям захищати те, що має найбільше значення.

_«Якісний захист вимагає знання методів атаки; ми забезпечуємо безпеку через розуміння»._

Будьте поінформовані та стежте за останніми новинами у сфері кібербезпеки, відвідавши наш [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE допомагає DevOps, DevSecOps і розробникам ефективно керувати, моніторити та захищати кластери Kubernetes. Використовуйте наші AI-driven insights, advanced security framework та інтуїтивний CloudMaps GUI, щоб візуалізувати свої кластери, розуміти їхній стан і впевнено діяти.

Крім того, K8Studio **сумісний з усіма основними дистрибутивами kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift та іншими).

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
