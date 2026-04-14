# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Логотипи HackTricks і motion design від_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Запустіть HackTricks локально
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

## Corporate Sponsors

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) — чудова компанія з кібербезпеки, чий слоган — **HACK THE UNHACKABLE**. Вони проводять власні дослідження та розробляють власні hacking tools, щоб **надавати кілька цінних послуг з кібербезпеки**, як-от pentesting, Red teams і навчання.

Ви можете переглянути їхній **blog** на [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** також підтримує open source проєкти з кібербезпеки, як-от HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** — це **№1 у Європі** етичний hacking і **bug bounty platform.**

**Bug bounty tip**: **sign up** для **Intigriti**, преміальної **bug bounty platform created by hackers, for hackers**! Приєднуйтесь до нас на [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) вже сьогодні та почніть заробляти винагороди до **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Приєднуйтесь до сервера [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy), щоб спілкуватися з досвідченими hackers і bug bounty hunters!

- **Hacking Insights:** Долучайтеся до контенту, що занурює у захоплення та виклики hacking
- **Real-Time Hack News:** Будьте в курсі швидкоплинного hacking світу завдяки новинам і аналітиці в реальному часі
- **Latest Announcements:** Слідкуйте за найновішими bug bounties та важливими оновленнями платформи

**Приєднуйтесь до нас у** [**Discord**](https://discord.com/invite/N3FrSbmwdy) і починайте співпрацювати з найкращими hackers уже сьогодні!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security надає **практичне AI Security training** з **інженерним, hands-on лабораторним підходом**. Наші курси створені для security engineers, AppSec professionals і developers, які хочуть **створювати, зламувати та захищати реальні AI/LLM-powered applications**.

**AI Security Certification** зосереджується на навичках реального світу, зокрема:
- Захист LLM і AI-powered applications
- Threat modeling для AI systems
- Embeddings, vector databases і RAG security
- LLM attacks, abuse scenarios та практичні defenses
- Secure design patterns і міркування щодо розгортання

Усі курси **on-demand**, **lab-driven** і побудовані навколо **real-world security tradeoffs**, а не лише теорії.

👉 Більше деталей про курс AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** пропонує швидкі та прості real-time APIs для **доступу до результатів пошукових систем**. Вони скраплять пошукові системи, обробляють proxies, вирішують captchas і аналізують усі багаті структуровані дані для вас.

Підписка на один із планів SerpApi включає доступ до понад 50 різних APIs для scraping різних пошукових систем, зокрема Google, Bing, Baidu, Yahoo, Yandex та інших.\
На відміну від інших провайдерів, **SerpApi не просто scrape organic results**. Відповіді SerpApi стабільно містять усі ads, inline images і videos, knowledge graphs та інші елементи й функції, присутні в результатах пошуку.

Серед поточних клієнтів SerpApi — **Apple, Shopify і GrubHub**.\
Для отримання додаткової інформації перегляньте їхній [**blog**](https://serpapi.com/blog/)**,** або спробуйте приклад у їхньому [**playground**](https://serpapi.com/playground)**.**\
Ви можете **створити безкоштовний обліковий запис** [**тут**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Вивчіть технології та навички, необхідні для проведення vulnerability research, penetration testing і reverse engineering, щоб захищати mobile applications і devices. **Опануйте iOS та Android security** через наші on-demand курси та **отримайте сертифікацію**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) — це професійна компанія з кібербезпеки, що базується в **Amsterdam**, яка допомагає **захищати** бізнес **по всьому світу** від новітніх кіберзагроз, надаючи **offensive-security services** із **modern** підходом.

WebSec — це міжнародна компанія з безпеки з офісами в Amsterdam і Wyoming. Вони пропонують **all-in-one security services**, тобто роблять усе: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing і багато іншого.

Ще одна крута річ про WebSec — на відміну від середнього рівня в індустрії, WebSec **дуже впевнені у своїх навичках**, настільки, що **гарантують найкращу якість результатів**; на їхньому сайті зазначено: "**If we can't hack it, You don't pay it!**". Для отримання додаткової інформації перегляньте їхній [**website**](https://websec.net/en/) і [**blog**](https://websec.net/blog/)!

Окрім вищезазначеного, WebSec також є **відданим прихильником HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) розробляє та проводить ефективне cybersecurity training, створене та очолюване галузевими експертами. Їхні програми виходять за межі теорії, щоб надати командам глибоке розуміння та практичні навички, використовуючи кастомні середовища, що відображають реальні загрози. Для запитів щодо custom training звертайтеся до нас [**here**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Що вирізняє їхнє навчання:**
* Custom-built content and labs
* Backed by top-tier tools and platforms
* Designed and taught by practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions надає спеціалізовані cybersecurity services для установ **Education** та **FinTech**
з акцентом на **penetration testing, cloud security assessments** і
**compliance readiness** (SOC 2, PCI-DSS, NIST). Наша команда включає **OSCP і CISSP
certified professionals**, які приносять глибоку технічну експертизу та галузеве розуміння в
кожен проєкт.

Ми йдемо далі за межі автоматизованих сканувань завдяки **manual, intelligence-driven testing**, адаптованому до
високоризикових середовищ. Від захисту студентських записів до охорони фінансових транзакцій,
ми допомагаємо організаціям захищати те, що має найбільше значення.

_“Якісний захист вимагає знати напад, ми забезпечуємо безпеку через розуміння.”_

Будьте в курсі останніх новин кібербезпеки, відвідавши наш [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE надає змогу DevOps, DevSecOps і developers ефективно керувати, моніторити та захищати Kubernetes clusters. Використовуйте наші AI-driven insights, advanced security framework і інтуїтивний CloudMaps GUI, щоб візуалізувати ваші clusters, розуміти їхній стан і діяти впевнено.

Крім того, K8Studio **сумісний з усіма основними дистрибутивами kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift та іншими).

{{#ref}}
https://k8studio.io/
{{#endref}}

---

## License & Disclaimer

Перегляньте їх у:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
