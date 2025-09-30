# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks логотипи та motion-дизайн від_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Ваша локальна копія HackTricks буде **available at [http://localhost:3337](http://localhost:3337)** через <5 хвилин (потрібен час на збірку книги, будьте терплячі).

## Корпоративні спонсори

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) — відмінна компанія в галузі кібербезпеки, чий слоган — **HACK THE UNHACKABLE**. Вони проводять власні дослідження та розробляють свої hacking tools, щоб **надавати кілька цінних послуг у сфері кібербезпеки**, таких як pentesting, Red teams і тренінги.

Ви можете переглянути їхній **блог** на [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** також підтримують open source проєкти з кібербезпеки, такі як HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) — найважливіша подія з кібербезпеки в **Spain** і одна з найзначніших у **Europe**. Маючи **місію популяризації технічних знань**, ця конференція є жвавим майданчиком для зустрічей фахівців з технологій і кібербезпеки з усіх дисциплін.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** — **Europe's #1** ethical hacking і **bug bounty platform.**

**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Приєднуйтесь до нас на [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) вже сьогодні та починайте заробляти bounties до **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Використовуйте [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks), щоб легко будувати та **автоматизувати workflows**, керовані найпотужнішими інструментами спільноти.

Отримайте доступ сьогодні:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Приєднуйтесь до сервера [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy), щоб спілкуватися з досвідченими хакерами і bug bounty мисливцями!

- **Hacking Insights:** Занурюйтесь у контент, що розкриває захоплення та виклики хакінгу
- **Real-Time Hack News:** Будьте в курсі швидкоплинних новин світу хакінгу в реальному часі
- **Latest Announcements:** Слідкуйте за новими запусками bug bounties та важливими оновленнями платформи

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) та почніть співпрацювати з провідними хакерами вже сьогодні!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Отримайте хакерський погляд на ваші веб-застосунки, мережу та cloud**

**Знаходьте й звітуйте про критичні, експлуатовані вразливості з реальним бізнес-імпактом.** Використовуйте наші 20+ кастомних інструментів для мапування attack surface, виявлення проблем безпеки, що дозволяють escalatе privileges, і застосовуйте автоматизовані експлойти для збору необхідних доказів, перетворюючи вашу роботу на переконливі звіти.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** пропонує швидкі та прості real-time APIs для **доступу до результатів пошуку**. Вони скрейплять пошукові системи, керують проксі, вирішують captchas і парсять всю структуровану data для вас.

Підписка на один із планів SerpApi включає доступ до понад 50 різних API для скрейпінгу різних пошукових систем, включно з Google, Bing, Baidu, Yahoo, Yandex та іншими.\
На відміну від інших постачальників, **SerpApi не просто скрейпить organic results**. Відповіді SerpApi постійно включають усі ads, inline images and videos, knowledge graphs та інші елементи та функції, присутні в результатах пошуку.

Серед поточних клієнтів SerpApi — **Apple, Shopify, і GrubHub**.\
Для додаткової інформації перегляньте їхній [**blog**](https://serpapi.com/blog/)**,** або спробуйте приклад у їхньому [**playground**](https://serpapi.com/playground)**.**\
Ви можете **create a free account** [**here**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Опануйте технології та навички, необхідні для проведення vulnerability research, penetration testing та reverse engineering, щоб захищати мобільні застосунки й пристрої. **Оволодійте iOS та Android security** через наші on-demand курси та **отримуйте сертифікацію**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) — професійна компанія з кібербезпеки, що базується в **Amsterdam**, яка допомагає **захищати** бізнеси **по всьому світу** від сучасних загроз кібербезпеки, надаючи **offensive-security services** із **сучасним** підходом.

WebSec — міжнародна компанія з офісами в Amsterdam та Wyoming. Вони пропонують **all-in-one security services**, що означає, що роблять усе: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing та багато іншого.

Ще одна цікава річ щодо WebSec: на відміну від середнього по галузі, WebSec **дуже впевнені у своїх навичках**, настільки, що **гарантують найкращі результати**, як зазначено на їхньому сайті: "**If we can't hack it, You don't pay it!**". Для додаткової інформації перегляньте їхній [**website**](https://websec.net/en/) та [**blog**](https://websec.net/blog/)!

Крім вищезазначеного, WebSec також є **відданим прихильником HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) — пошукова система по data breach (leak). \
Ми надаємо пошук по випадкових рядках (як google) по всім типам витоків даних великим і малим — не тільки по великим — по даних з множинних джерел. \
Пошук по людям, пошук через AI, пошук організацій, API (OpenAPI) доступ, інтеграція theHarvester, всі функції, які потрібні pentester.\
**HackTricks продовжує бути чудовою навчальною платформою для всіх нас, і ми пишаємося, що спонсоруємо її!**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) розробляє та проводить ефективні курси з кібербезпеки, створені та ведені експертами індустрії. Їхні програми виходять за межі теорії, щоб забезпечити команди глибоким розумінням та практичними навичками, використовуючи кастомні середовища, що відтворюють реальні загрози. Для індивідуальних запитів щодо навчання зв'яжіться з нами [**тут**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Що вирізняє їхні тренінги:**
* Кастомний контент і лабораторії
* Підтримка провідних інструментів і платформ
* Розроблені та викладаються практиками

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions надає спеціалізовані послуги з кібербезпеки для установ в галузі **Education** та **FinTech**, з акцентом на **penetration testing, cloud security assessments**, та **compliance readiness** (SOC 2, PCI-DSS, NIST). Наша команда включає фахівців сертифікованих OSCP та CISSP, які приносять глибоку технічну експертизу та галузеве розуміння в кожне завдання.

Ми виходимо за межі автоматизованих сканувань завдяки **manual, intelligence-driven testing**, адаптованому до середовищ із високими ставками. Від захисту студентських записів до забезпечення безпеки фінансових транзакцій — ми допомагаємо організаціям захищати те, що найважливіше.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Будьте в курсі останніх новин у сфері кібербезпеки, відвідавши їхній [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE дає змогу DevOps, DevSecOps та розробникам ефективно управляти, моніторити та захищати Kubernetes кластери. Використовуйте наші AI-driven insights, просунуту security framework та інтуїтивний CloudMaps GUI для візуалізації ваших кластерів, розуміння їхнього стану та впевнених дій.

Крім того, K8Studio **сумісний з усіма основними дистрибуціями kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift та інші).

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
