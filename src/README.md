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
Ваша локальна копія HackTricks буде **доступна за адресою [http://localhost:3337](http://localhost:3337)** через <5 хвилин (потрібно зібрати книгу, будьте терплячі).

## Корпоративні спонсори

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) — чудова компанія з кібербезпеки, чий слоган — **HACK THE UNHACKABLE**. Вони проводять власні дослідження та розробляють власні інструменти для хакінгу, щоб **надавати кілька цінних послуг у сфері кібербезпеки**, таких як pentesting, Red teams та навчання.

Ви можете переглянути їхній **блог** за адресою [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** також підтримують відкриті проекти з кібербезпеки, такі як HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) — найважливіша подія з кібербезпеки в **Іспанії** і одна з найважливіших у **Європі**. Маючи **місію поширення технічних знань**, цей конгрес є киплячим місцем зустрічі для фахівців з технологій і кібербезпеки в усіх дисциплінах.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** — **№1 у Європі** в галузі ethical hacking та **bug bounty platform.**

**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Приєднуйтесь до нас за адресою [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) сьогодні та почніть заробляти винагороди до **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Використовуйте [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks), щоб легко будувати та **автоматизувати робочі процеси**, що працюють на базі **найпередовіших** інструментів спільноти.

Отримати доступ сьогодні:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Приєднуйтесь до сервера [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy), щоб спілкуватися з досвідченими хакерами та мисливцями за багами!

- **Hacking Insights:** Ознайомлюйтесь із матеріалами, що розкривають азарт і виклики хакінгу
- **Real-Time Hack News:** Будьте в курсі швидкоплинного світу хакінгу завдяки новинам і аналітиці в реальному часі
- **Latest Announcements:** Отримуйте інформацію про нові bug bounty та важливі оновлення платформ

**Приєднуйтесь до нас на** [**Discord**](https://discord.com/invite/N3FrSbmwdy) і почніть співпрацювати з провідними хакерами вже сьогодні!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Отримайте погляд хакера на ваші веб-додатки, мережу та cloud**

**Знаходьте та повідомляйте про критичні, експлуатовані вразливості з реальним бізнес-наслідком.** Використовуйте наші 20+ інструментів для картографування attack surface, виявлення проблем безпеки, що дозволяють ескалювати привілеї, та автоматизованих експлойтів для збору необхідних доказів, перетворюючи вашу роботу на переконливі звіти.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** пропонує швидкі та прості реального часу API для **доступу до результатів пошукових систем**. Вони скраплять пошукові системи, керують проксі, вирішують captchas та парсять усі багаті структуровані дані для вас.

Підписка на один із планів SerpApi дає доступ до понад 50 різних API для скрапінгу різних пошукових систем, включаючи Google, Bing, Baidu, Yahoo, Yandex та інші.\
На відміну від інших провайдерів, **SerpApi не просто скрапить органічні результати**. Відповіді SerpApi послідовно включають всі оголошення, вбудовані зображення та відео, knowledge graphs та інші елементи й функції, присутні в результатах пошуку.

Нинішні клієнти SerpApi включають **Apple, Shopify, and GrubHub**.\
Більше інформації можна знайти в їхньому [**блозі**](https://serpapi.com/blog/)**,** або спробувати приклад у їхньому [**playground**](https://serpapi.com/playground)**.**\
Ви можете **створити безкоштовний акаунт** [**тут**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Вивчайте технології та навички, необхідні для проведення досліджень вразливостей, penetration testing та reverse engineering для захисту мобільних додатків і пристроїв. **Опануйте iOS та Android security** через наші курси на вимогу та **отримайте сертифікацію**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) — професійна компанія з кібербезпеки зі штаб-квартирою в **Амстердамі**, яка допомагає **захищати** бізнеси **по всьому світу** від найновіших кіберзагроз, надаючи **offensive-security services** з **сучасним** підходом.

WebSec — міжнародна компанія з офісами в Amsterdam та Wyoming. Вони пропонують **all-in-one security services**, що означає, що вони роблять усе: Pentesting, **Security** Audits, Awareness Trainings, Phishing кампанії, Code Review, Exploit Development, Security Experts Outsourcing та багато іншого.

Ще одна цікава річ у WebSec: на відміну від середнього по галузі, WebSec **дуже впевнені у своїх навичках**, настільки, що вони **гарантують найкращі результати**, як зазначено на їхньому сайті: "**If we can't hack it, You don't pay it!**". Для детальнішої інформації перегляньте їхній [**website**](https://websec.net/en/) та [**blog**](https://websec.net/blog/)!

Крім того, WebSec також є **відданим прихильником HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) розробляє та проводить ефективні тренінги з кібербезпеки, створені і ведені
експертами індустрії. Їхні програми виходять за рамки теорії, щоб надати командам глибоке
розуміння та практичні навички, використовуючи кастомні середовища, які відображають реальні
загрози. Для запитів щодо індивідуального навчання зв'яжіться з нами [**тут**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Що вирізняє їхні тренінги:**
* Кастомний контент і лабораторії
* Підтримка провідними інструментами та платформами
* Розроблені та викладаються практиками

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions надає спеціалізовані послуги з кібербезпеки для установ у галузі **освіти** та **FinTech**, зосереджуючись на **penetration testing, cloud security assessments**, та
**підготовці до відповідності** (SOC 2, PCI-DSS, NIST). Наша команда включає **OSCP and CISSP
сертифікованих фахівців**, які привносять глибоку технічну експертизу та знання галузевих стандартів у
кожне завдання.

Ми виходимо за межі автоматизованих сканувань, застосовуючи **ручне, інтелектно-орієнтоване тестування**, адаптоване для
середовищ із високими ставками. Від захисту студентських записів до забезпечення безпеки фінансових транзакцій,
ми допомагаємо організаціям захищати те, що має найбільше значення.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Будьте в курсі останніх подій у сфері кібербезпеки, відвідавши наш [**блог**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE дає змогу DevOps, DevSecOps та розробникам ефективно керувати, моніторити та захищати кластери Kubernetes. Використовуйте наші AI-орієнтовані інсайти, просунуту безпекову структуру та інтуїтивний CloudMaps GUI для візуалізації ваших кластерів, розуміння їх стану та впевнених дій.

Більше того, K8Studio **сумісний з усіма основними дистрибуціями kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more).

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
