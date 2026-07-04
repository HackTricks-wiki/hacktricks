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
Your local copy of HackTricks буде **доступна за адресою [http://localhost:3337](http://localhost:3337)** через <5 minutes (потрібно зібрати book, запасіться терпінням).

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) — це чудова cybersecurity компанія, чий слоган — **HACK THE UNHACKABLE**. Вони проводять власні дослідження та розробляють власні hacking tools, щоб **надавати кілька цінних cybersecurity services** на кшталт pentesting, Red teams і training.

Ви можете переглянути їхній **blog** на [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** також підтримують open source cybersecurity проєкти, як-от HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** — це **Europe's #1** ethical hacking та **bug bounty platform.**

**Bug bounty tip**: **зареєструйтеся** в **Intigriti**, premium **bug bounty platform, створеній хакерами для хакерів**! Приєднуйтесь до нас на [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) сьогодні та починайте заробляти bounties до **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure class="sponsor-logo"><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Приєднуйтесь до сервера [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy), щоб спілкуватися з досвідченими hackers і bug bounty hunters!

- **Hacking Insights:** Долучайтеся до контенту, що занурює в захопливість і виклики hacking
- **Real-Time Hack News:** Будьте в курсі швидкоплинного hacking world через новини та інсайти в реальному часі
- **Latest Announcements:** Будьте поінформовані про найновіші bug bounties та важливі оновлення платформи

**Приєднуйтесь до нас на** [**Discord**](https://discord.com/invite/N3FrSbmwdy) і починайте співпрацювати з топовими hackers уже сьогодні!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security надає **практичне AI Security training** з **engineering-first, hands-on lab approach**. Наші курси створені для security engineers, AppSec professionals і developers, які хочуть **створювати, ламати та захищати реальні AI/LLM-powered applications**.

**AI Security Certification** зосереджена на практичних навичках із реального світу, зокрема:
- Захист LLM та AI-powered applications
- Threat modeling для AI systems
- Embeddings, vector databases і безпека RAG
- LLM attacks, abuse scenarios і практичні defenses
- Secure design patterns і deployment considerations

Усі курси **on-demand**, **lab-driven** і побудовані навколо **real-world security tradeoffs**, а не лише теорії.

👉 Більше деталей про курс AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** пропонує швидкі й прості real-time APIs для **отримання search engine results**. Вони scrape search engines, обробляють proxies, вирішують captchas і парсять усі rich structured data для вас.

Підписка на один із планів SerpApi включає доступ до понад 50 різних APIs для scraping різних search engines, зокрема Google, Bing, Baidu, Yahoo, Yandex та інших.\
На відміну від інших провайдерів, **SerpApi не просто scrape organic results**. Відповіді SerpApi стабільно включають усі ads, inline images і videos, knowledge graphs та інші елементи й функції, присутні в search results.

Поточні клієнти SerpApi включають **Apple, Shopify та GrubHub**.\
Щоб дізнатися більше, перегляньте їхній [**blog**](https://serpapi.com/blog/)**,** або спробуйте приклад у їхньому [**playground**](https://serpapi.com/playground)**.**\
Ви можете **створити безкоштовний акаунт** [**тут**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Вивчайте technologies і skills, необхідні для vulnerability research, penetration testing та reverse engineering, щоб захищати mobile applications і devices. **Опануйте iOS та Android security** через наші on-demand курси та **отримайте сертифікацію**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** — це AI-powered security platform для пошуку exploitable vulnerabilities до того, як це зроблять attackers.

**Code security tip**: зареєструйтеся в NaxusAI, smart vulnerability monitoring platform, створеній для developers і security teams! Приєднуйтесь до нас сьогодні та починайте використовувати AI для **виявлення, валідації та виправлення реальних security risks ще до того, як вони потраплять у production**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) — це професійна cybersecurity компанія, базована в **Amsterdam**, яка допомагає **захищати** businesses **по всьому світу** від найновіших cybersecurity threats, надаючи **offensive-security services** із **modern** підходом.

WebSec — це intenational security company з офісами в Amsterdam і Wyoming. Вони пропонують **all-in-one security services**, тобто роблять усе: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing і багато іншого.

Ще одна крута річ про WebSec полягає в тому, що, на відміну від середнього рівня в індустрії, WebSec **дуже впевнені у своїх навичках**, настільки, що **гарантують найкращу якість результатів**; на їхньому сайті зазначено: "**If we can't hack it, You don't pay it!**". Щоб дізнатися більше, перегляньте їхній [**website**](https://websec.net/en/) і [**blog**](https://websec.net/blog/)!

Окрім цього, WebSec також є **відданим supporter of HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) розробляє та постачає ефективне cybersecurity training, створене та кероване
industry experts. Їхні програми виходять за межі теорії, щоб забезпечити teams глибоким
розумінням і практичними skills, використовуючи custom environments, які відображають real-world
threats. Для запитів щодо custom training, зв’яжіться з нами [**тут**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Що вирізняє їхнє training:**
* Custom-built content and labs
* Backed by top-tier tools and platforms
* Designed and taught by practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions надає спеціалізовані cybersecurity services для установ **Education** і **FinTech**
з акцентом на **penetration testing, cloud security assessments**, і
**compliance readiness** (SOC 2, PCI-DSS, NIST). Наша команда включає **OSCP і CISSP
certified professionals**, які приносять глибоку technical expertise та industry-standard insight у
кожну engagement.

Ми виходимо за межі automated scans завдяки **manual, intelligence-driven testing**, адаптованому до
high-stakes environments. Від захисту student records до охорони financial transactions,
ми допомагаємо organizations захищати те, що має найбільше значення.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Будьте в курсі останніх новин cybersecurity, відвідуючи наш [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE дає змогу DevOps, DevSecOps і developers ефективно керувати, моніторити та захищати Kubernetes clusters. Використовуйте наші AI-driven insights, advanced security framework і інтуїтивний CloudMaps GUI, щоб візуалізувати ваші clusters, розуміти їхній стан і діяти впевнено.

Крім того, K8Studio **сумісний з усіма основними kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift та інші).

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## License & Disclaimer

Перевірте це в:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
