# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Логотипи Hacktricks і motion design від_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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

## Corporate Sponsors

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) — це чудова компанія з кібербезпеки, чий слоган — **HACK THE UNHACKABLE**. Вони проводять власні дослідження та розробляють власні hacking tools, щоб **надавати кілька цінних послуг з кібербезпеки**: pentesting, Red teams і training.

Ви можете переглянути їхній **blog** на [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** також підтримує open source проєкти з кібербезпеки, такі як HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** — це **№1 в Європі** ethical hacking і **bug bounty platform.**

**Bug bounty tip**: **sign up** for **Intigriti**, premium **bug bounty platform created by hackers, for hackers**! Приєднуйтесь до нас на [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) уже сьогодні та почніть заробляти bounties до **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Приєднуйтесь до сервера [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy), щоб спілкуватися з досвідченими hackers і bug bounty hunters!

- **Hacking Insights:** Долучайтеся до контенту, що занурює у захоплення та виклики hacking
- **Real-Time Hack News:** Будьте в курсі швидкоплинного hacking world завдяки новинам і аналітиці в реальному часі
- **Latest Announcements:** Дізнавайтеся про найновіші bug bounties, що запускаються, та важливі оновлення платформи

**Приєднуйтесь до нас у** [**Discord**](https://discord.com/invite/N3FrSbmwdy) **та почніть співпрацювати з найкращими hackers уже сьогодні!**

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security надає **практичне AI Security training** з **engineering-first, hands-on lab approach**. Наші курси створені для security engineers, AppSec professionals і developers, які хочуть **створювати, ламати та захищати реальні AI/LLM-powered applications**.

**AI Security Certification** зосереджується на практичних навичках реального світу, зокрема:
- Захисті LLM і AI-powered applications
- Threat modeling для AI систем
- Embeddings, vector databases і RAG security
- LLM attacks, abuse scenarios і практичних defenses
- Secure design patterns і міркування щодо deployment

Усі курси **on-demand**, **lab-driven** і побудовані навколо **real-world security tradeoffs**, а не лише теорії.

👉 Докладніше про курс AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** пропонує швидкі й прості real-time APIs для **access search engine results**. Вони scrape search engines, обробляють proxies, розв’язують captchas і парсять усі rich structured data для вас.

Підписка на один із планів SerpApi включає доступ до понад 50 різних APIs для scraping різних search engines, зокрема Google, Bing, Baidu, Yahoo, Yandex та інших.\
На відміну від інших провайдерів, **SerpApi doesn’t just scrape organic results**. Відповіді SerpApi послідовно включають усі ads, inline images і videos, knowledge graphs та інші елементи й функції, присутні в результатах пошуку.

Серед нинішніх клієнтів SerpApi — **Apple, Shopify і GrubHub**.\
Докладніше дивіться їхній [**blog**](https://serpapi.com/blog/)**,** або спробуйте приклад у їхньому [**playground**](https://serpapi.com/playground)**.**\
Ви можете **create a free account** [**here**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Вивчайте технології та навички, необхідні для vulnerability research, penetration testing і reverse engineering, щоб захищати mobile applications і devices. **Master iOS and Android security** через наші on-demand курси та **get certified**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** — це AI-powered security platform для пошуку exploitable vulnerabilities ще до того, як це зроблять attackers.

**Code security tip**: sign up for NaxusAI, розумну platform моніторингу vulnerabilities, створену для developers і security teams! Приєднуйтесь сьогодні та почніть використовувати AI для **detecting, validating, and fixing real security risks before they reach production**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) — це професійна компанія з кібербезпеки, що базується в **Amsterdam**, яка допомагає **захищати** бізнес **по всьому світу** від найновіших кіберзагроз, надаючи **offensive-security services** із **modern** підходом.

WebSec — це intenational security company з офісами в Amsterdam і Wyoming. Вони пропонують **all-in-one security services**, що означає, що вони роблять усе: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing і багато іншого.

Ще одна крута річ про WebSec — на відміну від середнього показника в індустрії, WebSec **дуже впевнені у своїх навичках**, настільки, що **гарантують найкращу якість результатів**; на їхньому сайті написано: "**If we can't hack it, You don't pay it!**". Для докладнішої інформації подивіться їхній [**website**](https://websec.net/en/) і [**blog**](https://websec.net/blog/)!

Окрім вищезазначеного, WebSec також є **відданим прихильником HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) розробляє та проводить ефективне cybersecurity training, створене й очолюване
industry experts. Їхні програми виходять за межі теорії та надають командам глибоке
розуміння й практичні навички, використовуючи custom environments, що відображають real-world
threats. Для запитів щодо custom training звертайтеся до нас [**here**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Що вирізняє їхнє training:**
* Custom-built content and labs
* Backed by top-tier tools and platforms
* Designed and taught by practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions надає спеціалізовані cybersecurity services для установ у сфері **Education** і **FinTech**
з акцентом на **penetration testing, cloud security assessments** і
**compliance readiness** (SOC 2, PCI-DSS, NIST). Наша команда включає **OSCP and CISSP
certified professionals**, які приносять глибоку технічну експертизу та інсайт рівня галузевих стандартів у
кожну взаємодію.

Ми виходимо за межі автоматизованих сканувань завдяки **manual, intelligence-driven testing**, налаштованому під
середовища з високими ставками. Від захисту студентських записів до охорони фінансових транзакцій,
ми допомагаємо організаціям захищати те, що має найбільше значення.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Будьте в курсі останніх новин кібербезпеки, відвідуючи наш [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

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
