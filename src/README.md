# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks логотипи та моушн-дизайн від_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Ваша локальна копія HackTricks буде **доступна за адресою [http://localhost:3337](http://localhost:3337)** через <5 хвилин (потрібно збудувати книгу, будь ласка, зачекайте).

## Корпоративні спонсори

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) — відома cybersecurity компанія, чий слоган — **HACK THE UNHACKABLE**. Вони проводять власні дослідження та розробляють власні hacking tools, щоб **надавати кілька цінних cybersecurity services**, таких як pentesting, Red teams та training.

Ви можете переглянути їхній **blog** за адресою [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** також підтримує cybersecurity open source проекти, такі як HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) — найважливіша подія з cybersecurity в **Spain** і одна з найважливіших у **Europe**. Маючи **місію просування технічних знань**, цей конгрес є киплячою точкою зустрічі для фахівців із технологій та cybersecurity у всіх дисциплінах.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** — **Europe's #1** ethical hacking та **bug bounty platform.**

Порада щодо bug bounty: **sign up** на **Intigriti**, преміум bug bounty platform створену хакерами для хакерів! Приєднуйтесь до нас на [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) сьогодні і почніть заробляти винагороди до **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Використовуйте [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks), щоб легко будувати та **automate workflows**, що працюють на базі найпередовіших інструментів спільноти.

Отримайте доступ сьогодні:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Приєднуйтесь до сервера [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy), щоб спілкуватися з досвідченими хакерами та bug bounty hunters!

- **Hacking Insights:** Занурюйтеся в контент, який розкриває азарт і виклики hacking
- **Real-Time Hack News:** Будьте в курсі швидкоплинного світу hacking через оперативні новини та аналітику
- **Latest Announcements:** Отримуйте інформацію про нові запуски bug bounty та важливі оновлення платформ

**Приєднуйтесь до нас у** [**Discord**](https://discord.com/invite/N3FrSbmwdy) і почніть співпрацювати з провідними хакерами вже сьогодні!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Отримайте погляд хакера на ваші веб-додатки, мережу та cloud**

**Знаходьте та повідомляйте про критичні, експлуатовані вразливості з реальним бізнес-імпактом.** Використовуйте наші 20+ кастомних інструментів, щоб мапувати attack surface, знаходити проблеми безпеки, що дозволяють escalatе privileges, і застосовувати automated exploits для збору необхідних доказів, перетворюючи вашу роботу на переконливі звіти.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** пропонує швидкі та прості real-time APIs для доступу до search engine results. Вони скраплять пошукові системи, обробляють проксі, розв'язують captchas та парсять всю багату структуровану інформацію за вас.

Підписка на один із планів SerpApi включає доступ до понад 50 різних APIs для скрапінгу різних пошукових систем, включаючи Google, Bing, Baidu, Yahoo, Yandex та інші.\
На відміну від інших провайдерів, **SerpApi не просто скрапить organic results**. Відповіді SerpApi послідовно включають всі ads, inline images і videos, knowledge graphs та інші елементи й функції, присутні у результатах пошуку.

Серед поточних клієнтів SerpApi — **Apple, Shopify, and GrubHub**.\
Для додаткової інформації перегляньте їхній [**blog**](https://serpapi.com/blog/)**,** або спробуйте приклад у їхньому [**playground**](https://serpapi.com/playground)**.**\
Ви можете **create a free account** [**here**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Опановуйте технології та навички, необхідні для проведення vulnerability research, penetration testing та reverse engineering для захисту мобільних додатків і пристроїв. **Master iOS and Android security** через наші on-demand курси та **отримайте сертифікацію**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) — професійна cybersecurity компанія, що базується в **Amsterdam**, яка допомагає захищати компанії по всьому світу від найновіших загроз у сфері cybersecurity, надаючи offensive-security services із сучасним підходом.

WebSec — міжнародна security компанія з офісами в Amsterdam і Wyoming. Вони пропонують **all-in-one security services**, тобто виконують усе: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing та багато іншого.

Ще одна цікава річ про WebSec — на відміну від середнього по індустрії, WebSec **дуже впевнені у своїх навичках**, настільки, що вони **гарантують найкращі результати**, як зазначено на їхньому сайті: "**If we can't hack it, You don't pay it!**". Для додаткової інформації перегляньте їхній [**website**](https://websec.net/en/) та [**blog**](https://websec.net/blog/)!

Окрім вищезазначеного, WebSec також є **відданим прихильником HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) — це search engine для data breach (leak). \
Ми надаємо пошук за довільними рядками (як Google) по всіх типах data leaks — великих і малих — з даних з різних джерел. \
Пошук по людям, пошук через AI, пошук по організаціях, API (OpenAPI) доступ, інтеграція theHarvester — усі функції, які потрібні pentester.\
**HackTricks продовжує бути відмінною навчальною платформою для всіх нас, і ми пишаємося тим, що спонсоруємо її!**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) розробляє та проводить ефективні cybersecurity training, створені та керовані практиками з індустрії. Їхні програми виходять за межі теорії, щоб надати командам глибоке розуміння та практичні навички, використовуючи кастомні середовища, які відображають реальні загрози. Для індивідуальних запитів щодо training зв'яжіться з нами [**тут**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Що вирізняє їхні тренінги:**
* Custom-built content and labs
* Backed by top-tier tools and platforms
* Designed and taught by practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions надає спеціалізовані cybersecurity services для установ у сферах **Education** та **FinTech**, з фокусом на **penetration testing, cloud security assessments** та **compliance readiness** (SOC 2, PCI-DSS, NIST). Наша команда включає професіоналів, сертифікованих OSCP та CISSP, що приносить глибоку технічну експертизу та індустріальну прозорість у кожне залучення.

Ми виходимо за межі автоматизованих сканів, використовуючи **manual, intelligence-driven testing**, адаптоване до середовищ з високими ризиками. Від захисту студентських записів до забезпечення безпеки фінансових транзакцій — ми допомагаємо організаціям захищати те, що має найвищу цінність.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Будьте в курсі останніх подій у cybersecurity, відвідуючи наш [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.jpg" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE дає змогу DevOps, DevSecOps та розробникам ефективно керувати, моніторити та забезпечувати безпеку Kubernetes clusters. Використовуйте наші AI-driven insights, розширену security framework та інтуїтивний CloudMaps GUI для візуалізації кластерів, розуміння їхнього стану та впевнених дій.

Крім того, K8Studio сумісний з усіма основними kubernetes distributions (AWS, GCP, Azure, DO, Rancher, K3s, Openshift та інші).

{{#ref}}
https://k8studio.io/
{{#endref}}


---

## Ліцензія та відмова від відповідальності

Перевірте їх тут:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
