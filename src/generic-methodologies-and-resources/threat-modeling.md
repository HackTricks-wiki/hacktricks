# Моделювання загроз

Вітаємо у комплексному посібнику HackTricks з моделювання загроз! Дослідіть цей критично важливий аспект кібербезпеки, у межах якого ми виявляємо, розуміємо та розробляємо стратегії протидії потенційним вразливостям системи. Цей матеріал є покроковим посібником із прикладами з реального світу, корисним програмним забезпеченням і зрозумілими поясненнями. Він підходить як новачкам, так і досвідченим фахівцям, які прагнуть посилити свій кіберзахист.

### Поширені сценарії використання

1. **Розробка програмного забезпечення**: У межах Secure Software Development Life Cycle (SSDLC) моделювання загроз допомагає на ранніх етапах розробки **виявляти потенційні джерела вразливостей**.<sup>[[1]](#references)[[4]](#references)</sup>
2. **Penetration Testing**: Penetration Testing Execution Standard (PTES) вважає моделювання загроз необхідним для коректного виконання тестування та передбачає документування бізнес-активів, бізнес-процесів, спільнот загроз і їхніх можливостей.<sup>[[2]](#references)</sup>

### Модель загроз у двох словах

Модель загроз зазвичай представлена у вигляді діаграми, зображення або іншої візуалізації запланованої архітектури чи наявного застосунку. Data-flow diagrams (DFDs) є поширеним способом моделювання системи та її взаємодій, тоді як моделювання загроз додає аналіз, зосереджений на безпеці.<sup>[[1]](#references)</sup>

У Microsoft Threat Modeling Tool червоні пунктирні лінії позначають межі довіри; інші інструменти можуть використовувати інші візуальні позначення.<sup>[[4]](#references)</sup> Для спрощення виявлення ризиків команди можуть використовувати тріаду CIA (Confidentiality, Integrity, Availability) або категорії загроз STRIDE, але відповідна методологія залежить від контексту та вимог проєкту.<sup>[[1]](#references)[[3]](#references)[[10]](#references)</sup>

### Тріада CIA

Тріада CIA — це загальновизнана модель інформаційної безпеки, що розшифровується як Confidentiality, Integrity і Availability. Ці властивості зазвичай використовують для опису цілей безпеки даних і систем.<sup>[[3]](#references)</sup>

1. **Confidentiality**: Забезпечення того, щоб дані або система не були доступні неавторизованим особам. Це центральний аспект безпеки, що потребує належного контролю доступу, шифрування та інших заходів для запобігання витокам даних.
2. **Integrity**: Точність, узгодженість і надійність даних протягом їхнього життєвого циклу. Цей принцип забезпечує захист даних від несанкціонованої зміни або підробки. Він часто передбачає використання контрольних сум, хешування та інших методів перевірки даних.
3. **Availability**: Забезпечення доступності даних і сервісів для авторизованих користувачів у разі потреби. Для цього часто використовують надлишковість, відмовостійкість і конфігурації з високою доступністю, щоб системи продовжували працювати навіть у разі збоїв.

### Методології моделювання загроз

1. **STRIDE**: Підхід Microsoft STRIDE класифікує загрози програмному забезпеченню як **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service і Elevation of Privilege**. Ці категорії допомагають аналітикам виявляти можливі загрози в кожній вразливій точці проєкту.<sup>[[5]](#references)</sup>
2. **DREAD**: Цей підхід Microsoft до оцінювання визначає бали загроз на основі **Damage, Reproducibility, Exploitability, Affected users і Discoverability**. Отриманий бал допомагає розставляти пріоритети загроз для їх пом'якшення.<sup>[[5]](#references)</sup>
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Це семиетапна методологія, **орієнтована на ризики**, яка охоплює цілі, технічну область, декомпозицію застосунку, аналіз загроз, аналіз вразливостей і слабких місць, моделювання атак та аналіз ризиків/впливу.<sup>[[8]](#references)</sup>
4. **Trike**: Цей framework для security-аудиту розглядає моделювання загроз із перспективи **управління ризиками** та захисту.<sup>[[9]](#references)</sup>
5. **VAST** (Visual, Agile, and Simple Threat modeling): Цей метод приділяє особливу увагу масштабованим і зручним моделям загроз для прикладного та операційного представлень і може інтегруватися з життєвими циклами розробки та DevOps.<sup>[[10]](#references)</sup>
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Створена CERT Division of Carnegie Mellon's Software Engineering Institute, OCTAVE є стратегічним методом оцінювання та планування на основі ризиків, зосередженим на організаційних ризиках, а не лише на технологіях.<sup>[[10]](#references)</sup>

## Інструменти

Існує кілька інструментів і програмних рішень, які можуть **допомогти** у створенні та керуванні моделями загроз. Ось декілька варіантів, які варто розглянути.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

SpiderSuite — це кросплатформний web crawler для фахівців із безпеки, який підтримує мапування attack surface, виявлення endpoint'ів і аналіз web-застосунків.<sup>[[6]](#references)</sup>

**Використання**

1. Виберіть URL і запустіть Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Перегляньте Graph

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP Threat Dragon — це безкоштовний open-source кросплатформний застосунок для моделювання загроз, призначений для створення діаграм, пропонування загроз і документування заходів пом'якшення. Він доступний як web- і desktop-застосунок.<sup>[[7]](#references)</sup>

**Використання**

1. Створіть New Project

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Іноді це може виглядати так:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Запустіть New Project

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Збережіть New Project

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Створіть свою модель

Ви можете використовувати такі інструменти, як SpiderSuite Crawler, для пошуку ідей; базова модель може виглядати приблизно так:

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Коротко пояснимо сутності:

- Process (сама сутність, наприклад Webserver або web-функціональність)
- Actor (особа, наприклад відвідувач Website, User або Administrator)
- Data Flow Line (індикатор взаємодії)
- Trust Boundary (різні мережеві сегменти або області.)
- Store (місця, де зберігаються дані, наприклад Databases)

5. Створіть Threat (крок 1)

Спочатку потрібно вибрати layer, до якого ви хочете додати threat

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Тепер можна створити threat

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Пам'ятайте, що між Actor Threats і Process Threats є різниця. Якщо додати threat до Actor, можна буде вибрати лише "Spoofing" і "Repudiation. Однак у нашому прикладі ми додаємо threat до сутності Process, тому у вікні створення threat побачимо таке:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Готово

Тепер ваша готова модель має виглядати приблизно так. Ось як створити просту модель загроз за допомогою OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Microsoft Threat Modeling Tool — це безкоштовний інструмент, який можна завантажити, для аналізу проєктування програмного забезпечення. Його workflow створює діаграму, виявляє загрози та підтримує їх пом'якшення й перевірку за допомогою підходу STRIDE.<sup>[[4]](#references)</sup>

## References

- [1] [Шпаргалка з моделювання загроз](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [2] [Моделювання загроз — The Penetration Testing Execution Standard](https://www.pentest-standard.org/index.php/Threat_Modeling)
- [3] [Основи безпеки — OWASP Developer Guide](https://devguide.owasp.org/en/02-foundations/01-security-fundamentals/)
- [4] [Початок роботи з Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-getting-started)
- [5] [Моделювання загроз для Drivers — Windows drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/threat-modeling-for-drivers)
- [6] [SpiderSuite](https://spidersuite.io/)
- [7] [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon)
- [8] [Моделювання загроз PASTA: пояснення 7 етапів](https://versprite.com/cybersecurity-listings/devsecops/pasta-threat-modeling/)
- [9] [Документ методології Trike v1](https://trike.sourceforge.net/papers/Trike_v1_Methodology_Document-draft.pdf)
- [10] [Моделювання загроз: огляд доступних методів](https://www.sei.cmu.edu/documents/569/2018_019_001_524597.pdf)
{{#include ../banners/hacktricks-training.md}}
