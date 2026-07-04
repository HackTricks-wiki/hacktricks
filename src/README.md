# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Логотипи Hacktricks і motion design від_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Вашу локальну копію HackTricks буде **доступно за [http://localhost:3337](http://localhost:3337)** після <5 хвилин (потрібно зібрати книгу, запасіться терпінням).

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) — це чудова компанія з кібербезпеки, чий слоган — **HACK THE UNHACKABLE**. Вони проводять власні дослідження та розробляють власні hacking tools, щоб **пропонувати кілька цінних послуг з кібербезпеки** на кшталт pentesting, Red teams і training.

Ви можете переглянути їхній **blog** на [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** також підтримує open source проєкти з кібербезпеки, такі як HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** — це **№1 у Європі** платформа ethical hacking і **bug bounty.**

**Bug bounty tip**: **зареєструйтеся** в **Intigriti**, преміальній **bug bounty платформі, створеній хакерами для хакерів**! Приєднуйтеся до нас на [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) вже сьогодні та почніть заробляти винагороди до **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure class="sponsor-logo"><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Приєднуйтеся до сервера [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy), щоб спілкуватися з досвідченими хакерами та bug bounty hunter'ами!

- **Hacking Insights:** Долучайтеся до контенту, що занурює в захоплення та виклики hacking
- **Real-Time Hack News:** Будьте в курсі стрімкого hacking світу завдяки новинам і аналітиці в реальному часі
- **Latest Announcements:** Дізнавайтеся про найновіші bug bounties та важливі оновлення платформи

**Приєднуйтесь до нас у** [**Discord**](https://discord.com/invite/N3FrSbmwdy) і почніть співпрацювати з топовими хакерами вже сьогодні!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security надає **практичне навчання з AI Security** з **інженерним, hands-on підходом до лабораторій**. Наші курси створені для security engineers, AppSec professionals і developers, які хочуть **створювати, ламати та захищати реальні AI/LLM-powered applications**.

**AI Security Certification** зосереджена на практичних навичках, зокрема:
- Захист LLM і AI-powered applications
- Threat modeling для AI систем
- Embeddings, vector databases і безпека RAG
- LLM attacks, abuse scenarios і практичні засоби захисту
- Безпечні design patterns і аспекти розгортання

Усі курси **on-demand**, **lab-driven** і побудовані навколо **реальних компромісів безпеки**, а не лише теорії.

👉 Докладніше про курс AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** пропонує швидкі та прості real-time APIs для **доступу до результатів search engine**. Вони збирають дані з search engines, працюють з proxy, розв'язують captchas і аналізують усі багаті структуровані дані для вас.

Підписка на один із планів SerpApi включає доступ до понад 50 різних APIs для збору даних із різних search engines, зокрема Google, Bing, Baidu, Yahoo, Yandex та інших.\
На відміну від інших провайдерів, **SerpApi не просто збирає organic results**. Відповіді SerpApi стабільно містять усі ads, inline images і videos, knowledge graphs та інші елементи й функції, присутні в search results.

Серед поточних клієнтів SerpApi — **Apple, Shopify та GrubHub**.\
Докладніше дивіться в їхньому [**blog**](https://serpapi.com/blog/)**,** або спробуйте приклад у їхньому [**playground**](https://serpapi.com/playground)**.**\
Ви можете **створити безкоштовний акаунт** [**тут**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Вивчайте технології та навички, потрібні для vulnerability research, penetration testing і reverse engineering, щоб захищати мобільні applications і devices. **Опануйте iOS та Android security** через наші on-demand курси та **отримайте сертифікацію**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** — це платформа безпеки з підтримкою AI для виявлення exploitable vulnerabilities ще до того, як це зроблять атакувальники.

**Code security tip**: зареєструйтеся в NaxusAI, розумній платформі моніторингу vulnerabilities, створеній для developers і security teams! Приєднуйтеся до нас сьогодні та почніть використовувати AI для **виявлення, підтвердження та виправлення реальних ризиків безпеки до того, як вони потраплять у production**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) — це професійна компанія з кібербезпеки, що базується в **Amsterdam** і допомагає **захищати** бізнес **по всьому світу** від найновіших загроз кібербезпеки, надаючи **offensive-security services** з **modern** підходом.

WebSec — це міжнародна security company з офісами в Amsterdam і Wyoming. Вони пропонують **all-in-one security services**, тобто роблять усе: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing і багато іншого.

Ще одна крута річ про WebSec полягає в тому, що, на відміну від середнього показника в індустрії, WebSec **дуже впевнені у своїх навичках**, настільки, що **гарантують найкращу якість результатів**; на їхньому сайті зазначено: "**If we can't hack it, You don't pay it!**". Докладніше дивіться на їхньому [**website**](https://websec.net/en/) та [**blog**](https://websec.net/blog/)!

Окрім цього, WebSec також є **відданим прихильником HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) розробляє та постачає ефективне cybersecurity training, створене та очолюване
industry experts. Їхні програми виходять за межі теорії, щоб забезпечити команди глибоким
розумінням і практичними навичками, використовуючи custom environments, що відображають real-world
threats. Для запитів щодо custom training звертайтеся до нас [**here**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Що відрізняє їхнє навчання:**
* Custom-built content and labs
* Backed by top-tier tools and platforms
* Designed and taught by practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions надає спеціалізовані послуги з кібербезпеки для установ **Education** і **FinTech**
з акцентом на **penetration testing, cloud security assessments** та
**compliance readiness** (SOC 2, PCI-DSS, NIST). До нашої команди входять **OSCP and CISSP
certified professionals**, які приносять глибоку технічну експертизу та галузеві знання в
кожен проєкт.

Ми виходимо за межі автоматизованих сканувань завдяки **manual, intelligence-driven testing**, адаптованому
до середовищ із високими ставками. Від захисту студентських записів до охорони фінансових транзакцій —
ми допомагаємо організаціям захищати найважливіше.

_“Якісний захист вимагає знати атаку, ми забезпечуємо безпеку через розуміння.”_

Будьте в курсі останніх новин кібербезпеки, відвідуючи наш [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE надає можливості DevOps, DevSecOps і developers ефективно керувати, моніторити та захищати Kubernetes clusters. Використовуйте наші AI-driven insights, advanced security framework і інтуїтивний CloudMaps GUI, щоб візуалізувати ваші clusters, розуміти їхній стан і діяти впевнено.

Крім того, K8Studio **сумісний з усіма основними kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift та іншими).

{{#ref}}
https://k8studio.io/
{{#endref}}

---

<!-- hacktricks-friends:friend:friend-carlospolop:start -->
### [HackTricks Books](https://book.hacktricks.wiki/)

<figure class="sponsor-logo"><img src="https://friends.hacktricks.wiki/assets/17181413/5e15e93e6b8523dac2ad.png" alt="HackTricks Books logo"><figcaption></figcaption></figure>

Це текст, щоб представити безкоштовну cybersecurity wiki: <b>Hacktricks Book </b>. Дізнайтеся з неї про всі види hacking tricks безкоштовно вже зараз!

{{#ref}}
https://book.hacktricks.wiki/
{{#endref}}

---
<!-- hacktricks-friends:friend:friend-carlospolop:end -->

## License & Disclaimer

Перегляньте їх у:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
