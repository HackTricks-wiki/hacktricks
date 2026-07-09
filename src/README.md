# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Логотипи Hacktricks та motion design від_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Запустити HackTricks локально
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
Your local copy of HackTricks will be **available at [http://localhost:3337](http://localhost:3337)** after <5 minutes (it needs to build the book, be patient).

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) — це чудова компанія з кібербезпеки, чий слоган — **HACK THE UNHACKABLE**. Вони проводять власні дослідження та розробляють власні hacking tools, щоб **надавати кілька цінних послуг з кібербезпеки** на кшталт pentesting, Red teams і training.

Ви можете переглянути їхній **blog** на [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** також підтримує open source проєкти з кібербезпеки, як-от HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** — це **№1 у Європі** платформа для ethical hacking і **bug bounty platform.**

**Bug bounty tip**: **зареєструйтеся** в **Intigriti**, преміальній **bug bounty platform, створеній хакерами для хакерів**! Приєднуйтеся до нас на [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) вже сьогодні та почніть заробляти bounties до **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure class="sponsor-logo"><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Приєднуйтеся до сервера [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy), щоб спілкуватися з досвідченими хакерами та bug bounty hunters!

- **Hacking Insights:** Долучайтеся до контенту, що занурює у захоплення та виклики hacking
- **Real-Time Hack News:** Будьте в курсі швидкоплинного світу hacking завдяки новинам та аналітиці в реальному часі
- **Latest Announcements:** Дізнавайтеся про нові bug bounties, що запускаються, та важливі оновлення платформи

**Приєднуйтеся до нас у** [**Discord**](https://discord.com/invite/N3FrSbmwdy) **і починайте співпрацювати з найкращими хакерами вже сьогодні!**

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security надає **практичне AI Security training** з **engineering-first, hands-on lab approach**. Наші курси створені для security engineers, AppSec professionals і developers, які хочуть **створювати, ламати та захищати реальні AI/LLM-powered applications**.

**AI Security Certification** зосереджується на реальних навичках, зокрема:
- Захист LLM та AI-powered applications
- Threat modeling для AI systems
- Embeddings, vector databases та безпека RAG
- LLM attacks, abuse scenarios та практичні defenses
- Безпечні design patterns і питання deployment

Усі курси **on-demand**, **lab-driven** і побудовані навколо **real-world security tradeoffs**, а не лише теорії.

👉 Докладніше про AI Security course:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** пропонує швидкі та прості real-time APIs для **access search engine results**. Вони scrape search engines, обробляють proxies, вирішують captchas і парсять для вас усі rich structured data.

Підписка на один із планів SerpApi включає доступ до понад 50 різних APIs для scraping різних search engines, зокрема Google, Bing, Baidu, Yahoo, Yandex та інших.\
На відміну від інших провайдерів, **SerpApi не просто scrape organic results**. Відповіді SerpApi послідовно містять усі ads, inline images and videos, knowledge graphs та інші елементи й функції, присутні в результатах пошуку.

Серед поточних клієнтів SerpApi — **Apple, Shopify і GrubHub**.\
Докладніше дивіться їхній [**blog**](https://serpapi.com/blog/)**,** або спробуйте приклад у їхньому [**playground**](https://serpapi.com/playground)**.**\
Ви можете **створити безкоштовний обліковий запис** [**тут**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** навчає offensive mobile і AI security, а викладають активні дослідники — та сама команда, що стоїть за CVE writeups і доповідями на Black Hat, HITB та Zer0con. Курси проходяться у власному темпі, побудовані навколо labs на реальних цілях і підтримуються hands-on certification.

Каталог охоплює два напрями:

**Mobile Security** – iOS і Android від рівня app layer донизу: reverse engineering з Ghidra та LLDB, ARM64 exploitation, kernel internals і сучасні mitigations (PAC, MTE, SELinux), механіки jailbreak і rooting.

**AI Security** – два повноцінні курси, що охоплюють цю сферу. Practical AI Security пояснює, як працюють LLMs, RAG pipelines, AI agents і MCP, а також як атакувати й захищати їх. Advanced AI Security йде в напрямку build-heavy на передовій: red teaming AI systems at scale з Garak і PyRIT, exploiting MCP servers, впровадження та виявлення model backdoors, а також fine-tuning attacks і defenses на Apple Silicon.

Курси та сертифікації:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** — це AI-powered security platform для пошуку exploitable vulnerabilities до того, як це зроблять attackers.

**Code security tip**: зареєструйтеся в NaxusAI, розумній платформі моніторингу vulnerabilities, створеній для developers і security teams! Приєднуйтеся до нас сьогодні та почніть використовувати AI для **detecting, validating, and fixing real security risks before they reach production**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) — це професійна компанія з кібербезпеки, що базується в **Amsterdam**, яка допомагає **захищати** бізнес **по всьому світу** від найновіших кіберзагроз, надаючи **offensive-security services** із **modern** підходом.

WebSec — це intenational security company з офісами в Amsterdam і Wyoming. Вони пропонують **all-in-one security services**, що означає, що вони роблять усе: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing і багато іншого.

Ще одна крута річ про WebSec полягає в тому, що, на відміну від середнього рівня в індустрії, WebSec **дуже впевнені у своїх навичках**, настільки, що **гарантують найкращу якість результатів**; на їхньому сайті зазначено: "**If we can't hack it, You don't pay it!**". Для детальнішої інформації подивіться їхній [**website**](https://websec.net/en/) і [**blog**](https://websec.net/blog/)!

Окрім цього, WebSec також є **відданим прихильником HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) розробляє та надає ефективне cybersecurity training, створене та кероване
industry experts. Їхні програми виходять за межі теорії, щоб забезпечити команди глибоким
розумінням і практичними навичками, використовуючи custom environments, що відображають реальні
threats. Для запитів щодо custom training, зв’яжіться з нами [**here**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**What sets their training apart:**
* Custom-built content and labs
* Backed by top-tier tools and platforms
* Designed and taught by practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions надає спеціалізовані cybersecurity services для інституцій **Education** і **FinTech**
, з акцентом на **penetration testing, cloud security assessments** і
**compliance readiness** (SOC 2, PCI-DSS, NIST). Наша команда включає **OSCP and CISSP
certified professionals**, які приносять глибоку технічну експертизу та галузеве бачення до
кожного проєкту.

Ми йдемо далі за автоматизовані сканування завдяки **manual, intelligence-driven testing**, адаптованому до
середовищ із високими ставками. Від захисту студентських записів до охорони фінансових транзакцій,
ми допомагаємо організаціям захищати те, що має найбільше значення.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Будьте в курсі останніх новин кібербезпеки, відвідавши наш [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE надає DevOps, DevSecOps і developers можливість ефективно керувати, моніторити та захищати Kubernetes clusters. Використовуйте наші AI-driven insights, advanced security framework і інтуїтивний CloudMaps GUI, щоб візуалізувати ваші clusters, розуміти їхній стан і діяти впевнено.

Крім того, K8Studio **compatible with all major kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more).

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## License & Disclaimer

Check them in:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
