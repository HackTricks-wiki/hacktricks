# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Логотипи та motion-дизайн HackTricks від_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)._ 

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
Ваша локальна копія HackTricks буде **доступна за адресою [http://localhost:3337](http://localhost:3337)** через менш ніж 5 хвилин (потрібно, щоб книга зібралась, будь ласка, зачекайте).

## Корпоративні спонсори

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) — відмінна компанія в галузі кібербезпеки зі слоганом **HACK THE UNHACKABLE**. Вони проводять власні дослідження та розробляють власні інструменти для хакінгу, щоб **надавати кілька цінних послуг у сфері кібербезпеки**, таких як pentesting, Red teams та навчання.

Ви можете переглянути їхній **блог** за адресою [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** також підтримують open source проекти з кібербезпеки, такі як HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) — найважливіша подія з кібербезпеки в **Іспанії** і одна з найзначущих у **Європі**. Маючи **місію популяризувати технічні знання**, цей конгрес є гарячою точкою зустрічі для професіоналів з технологій і кібербезпеки в усіх дисциплінах.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** — **Europe's #1** ethical hacking та **bug bounty platform.**

**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Приєднуйтесь до нас за адресою [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) сьогодні і почніть заробляти bounties до **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Використовуйте [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks), щоб легко створювати та **автоматизувати workflows**, побудовані на основі найбільш **просунутих** інструментів спільноти.

Отримати доступ сьогодні:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Приєднуйтесь до сервера [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy), щоб спілкуватись з досвідченими хакерами і bug bounty hunters!

- **Hacking Insights:** Ознайомтесь із контентом, що досліджує захоплення та виклики в хакінгу
- **Real-Time Hack News:** Будьте в курсі швидкоплинного світу хакінгу завдяки новинам та аналітиці в реальному часі
- **Latest Announcements:** Отримуйте інформацію про нові bug bounty, що запускаються, та важливі оновлення платформ

**Приєднуйтесь до нас в** [**Discord**](https://discord.com/invite/N3FrSbmwdy) і почніть співпрацювати з провідними хакерами вже сьогодні!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security пропонує **практичні AI Security тренінги** з **інженерним підходом та hands-on лабораторіями**. Наші курси створені для security engineers, AppSec professionals та розробників, які хочуть **створювати, ламати та захищати реальні AI/LLM-підсилені додатки**.

Сертифікація **AI Security Certification** зосереджена на навичках реального світу, включаючи:
- Securing LLM and AI-powered applications
- Threat modeling for AI systems
- Embeddings, vector databases, and RAG security
- LLM attacks, abuse scenarios, and practical defenses
- Secure design patterns and deployment considerations

Усі курси доступні **on-demand**, **lab-driven** і побудовані навколо **реальних компромісів у безпеці**, а не лише теорії.

👉 Детальніше про курс AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** пропонує швидкі та прості real-time APIs для **доступу до результатів пошуку**. Вони збирають дані з пошукових систем, керують проксі, вирішують captchas і парсять весь багатий структурований контент за вас.

Підписка на один з планів SerpApi включає доступ до понад 50 різних API для скрапінгу різних пошукових систем, включаючи Google, Bing, Baidu, Yahoo, Yandex та інші.\
На відміну від інших постачальників, **SerpApi doesn’t just scrape organic results**. У відповідях SerpApi постійно присутні всі оголошення, inline images і videos, knowledge graphs та інші елементи й функції, які є в результатах пошуку.

Серед клієнтів SerpApi — **Apple, Shopify, and GrubHub**.\
Більше інформації — в їхньому [**блозі**](https://serpapi.com/blog/)**,** або спробуйте приклад у їхньому [**playground**](https://serpapi.com/playground)**.**\
Ви можете **створити безкоштовний акаунт** [**тут**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Опануйте технології та навички, необхідні для проведення vulnerability research, penetration testing та reverse engineering для захисту мобільних додатків та пристроїв. **Опануйте iOS та Android security** через наші курси on-demand і **отримайте сертифікацію**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) — професійна компанія з кібербезпеки, що базується в **Amsterdam**, яка допомагає **захищати** бізнеси **по всьому світу** від найновіших загроз кібербезпеки, надаючи **offensive-security services** з **сучасним** підходом.

WebSec — міжнародна компанія з офісами в Amsterdam і Wyoming. Вони пропонують **all-in-one security services**, тобто роблять усе: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing та багато іншого.

Ще один цікавий аспект WebSec — на відміну від середнього по індустрії, WebSec **дуже впевнені у своїх навичках**, настільки, що **гарантують найкращу якість результатів**; на їхньому сайті зазначено: "**If we can't hack it, You don't pay it!**". Для додаткової інформації перегляньте їхній [**website**](https://websec.net/en/) та [**blog**](https://websec.net/blog/)!

Крім того, WebSec є **відданим прихильником HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) розробляє та проводить ефективні тренінги з кібербезпеки, створені та очолювані експертами індустрії. Їхні програми виходять за межі теорії, забезпечуючи команди глибоким розумінням та практичними навичками, використовуючи кастомні середовища, які відображають реальні загрози. Для запитів щодо індивідуального навчання зв'яжіться з нами [**тут**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

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

Last Tower Solutions надає спеціалізовані послуги з кібербезпеки для установ у сфері **Education** та **FinTech**, з акцентом на **penetration testing, cloud security assessments**, та **compliance readiness** (SOC 2, PCI-DSS, NIST). Наша команда включає фахівців з сертифікаціями **OSCP та CISSP**, які приносять глибоку технічну експертизу та знання стандартів індустрії в кожне залучення.

Ми виходимо за межі автоматизованих сканувань, виконуючи **manual, intelligence-driven testing**, адаптоване до середовищ з високими вимогами. Від захисту студентських записів до захисту фінансових транзакцій — ми допомагаємо організаціям захищати те, що має найбільше значення.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Будьте в курсі останніх подій у сфері кібербезпеки, відвідавши наш [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE дає змогу DevOps, DevSecOps та розробникам ефективно керувати, моніторити та захищати Kubernetes кластери. Використовуйте наші AI-driven insights, просунутий security framework та інтуїтивний CloudMaps GUI для візуалізації ваших кластерів, розуміння їхнього стану та впевнених дій.

Крім того, K8Studio сумісний з усіма основними kubernetes distributions (AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more).

{{#ref}}
https://k8studio.io/
{{#endref}}

---

## License & Disclaimer

Перевірте їх у:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
