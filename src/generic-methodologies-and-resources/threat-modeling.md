# Моделювання загроз

{{#include ../banners/hacktricks-training.md}}

Вітаємо у всеосяжному посібнику HackTricks з моделювання загроз! Розпочнімо дослідження цього критично важливого аспекту кібербезпеки, у межах якого ми виявляємо, розуміємо та розробляємо стратегії протидії потенційним вразливостям у системі. Цей матеріал є покроковим посібником із реальними прикладами, корисним програмним забезпеченням і зрозумілими поясненнями. Він підходить як для початківців, так і для досвідчених фахівців, які прагнуть посилити свій кіберзахист.

### Поширені сценарії використання

1. **Розробка програмного забезпечення**: у межах Secure Software Development Life Cycle (SSDLC) моделювання загроз допомагає на ранніх етапах розробки **виявляти потенційні джерела вразливостей**.<sup>[[1]](#references)[[4]](#references)</sup>
2. **Penetration Testing**: Penetration Testing Execution Standard (PTES) вважає моделювання загроз необхідним для коректного виконання тестування та вимагає документувати бізнес-активи, бізнес-процеси, спільноти загроз і їхні можливості.<sup>[[2]](#references)</sup>

### Модель загроз у двох словах

Модель загроз зазвичай представлена у вигляді діаграми, зображення або іншої візуальної ілюстрації запланованої архітектури чи наявного застосунку. Діаграми потоків даних (DFD) є поширеним способом моделювання системи та її взаємодій, тоді як моделювання загроз додає аналіз, зосереджений на безпеці.<sup>[[1]](#references)</sup>

У Microsoft Threat Modeling Tool червоні пунктирні лінії позначають межі довіри; інші інструменти можуть використовувати інші візуальні позначення.<sup>[[4]](#references)</sup> Для спрощення ідентифікації ризиків команди можуть використовувати тріаду CIA (Confidentiality, Integrity, Availability) або категорії загроз STRIDE, однак відповідна методологія залежить від контексту та вимог проєкту.<sup>[[1]](#references)[[3]](#references)[[10]](#references)</sup>

### Тріада CIA

Тріада CIA — це загальновизнана модель інформаційної безпеки, назва якої утворена від Confidentiality, Integrity та Availability. Ці властивості зазвичай використовують для опису цілей безпеки даних і систем.<sup>[[3]](#references)</sup>

1. **Confidentiality**: забезпечення того, щоб дані або система не були доступні неавторизованим особам. Це центральний аспект безпеки, який потребує належного контролю доступу, шифрування та інших заходів для запобігання витокам даних.
2. **Integrity**: точність, узгодженість і надійність даних протягом їхнього життєвого циклу. Цей принцип гарантує, що дані не будуть змінені або підроблені неавторизованими сторонами. Він часто передбачає використання контрольних сум, hashing та інших методів перевірки даних.
3. **Availability**: забезпечення доступності даних і сервісів для авторизованих користувачів, коли це необхідно. Для цього часто використовують надлишковість, відмовостійкість і конфігурації високої доступності, щоб підтримувати роботу систем навіть у разі збоїв.

### Методології моделювання загроз

1. **STRIDE**: підхід STRIDE від Microsoft класифікує загрози програмного забезпечення як **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service та Elevation of Privilege**. Ці категорії допомагають аналітикам виявляти можливі загрози в кожній вразливій точці проєкту.<sup>[[5]](#references)</sup>
2. **DREAD**: цей підхід Microsoft до оцінювання визначає оцінку загроз за допомогою **Damage, Reproducibility, Exploitability, Affected users та Discoverability**. Отримана оцінка може допомогти визначити пріоритетність загроз для пом’якшення.<sup>[[5]](#references)</sup>
3. **PASTA** (Process for Attack Simulation and Threat Analysis): це семиетапна методологія, **орієнтована на ризики**, яка охоплює цілі, технічну область, декомпозицію застосунку, аналіз загроз, аналіз вразливостей і слабких місць, моделювання атак та аналіз ризиків/впливу.<sup>[[8]](#references)</sup>
4. **Trike**: цей framework для аудиту безпеки розглядає моделювання загроз із перспективи **управління ризиками** та захисту.<sup>[[9]](#references)</sup>
5. **VAST** (Visual, Agile, and Simple Threat modeling): цей метод наголошує на масштабованих і практичних моделях загроз для представлень застосунків та операцій і може інтегруватися з життєвими циклами розробки та DevOps.<sup>[[10]](#references)</sup>
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): створений CERT Division of Carnegie Mellon's Software Engineering Institute, OCTAVE є стратегічним методом оцінювання та планування на основі ризиків, зосередженим на організаційних ризиках, а не лише на технологіях.<sup>[[10]](#references)</sup>

## Інструменти

Існує кілька інструментів і програмних рішень, які можуть **допомогти** у створенні та керуванні моделями загроз. Ось декілька варіантів, які варто розглянути.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

SpiderSuite — це кросплатформний web crawler для фахівців із безпеки, який підтримує мапування attack surface, виявлення endpoint і аналіз web-застосунків.<sup>[[6]](#references)</sup>

**Використання**

1. Виберіть URL і запустіть Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Перегляньте Graph

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP Threat Dragon — це безкоштовний кросплатформний open-source застосунок для моделювання загроз, призначений для створення діаграм, пропонування загроз і запису заходів із пом’якшення. Він доступний як web- і desktop-застосунок.<sup>[[7]](#references)</sup>

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

Ви можете використовувати такі інструменти, як SpiderSuite Crawler, щоб отримати натхнення. Базова модель може виглядати приблизно так:

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Коротко пояснимо сутності:

- Process (сама сутність, наприклад Webserver або web-функціональність)
- Actor (особа, наприклад відвідувач Website, користувач або адміністратор)
- Data Flow Line (індикатор взаємодії)
- Trust Boundary (різні мережеві сегменти або області видимості)
- Store (місця зберігання даних, наприклад Databases)

5. Створіть Threat (Крок 1)

Спочатку потрібно вибрати layer, до якого ви хочете додати threat

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Тепер можна створити threat

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Пам’ятайте, що між Actor Threats і Process Threats є різниця. Якщо додати threat до Actor, можна буде вибрати лише "Spoofing" і "Repudiation". Однак у нашому прикладі ми додаємо threat до сутності Process, тому у вікні створення threat побачимо таке:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Готово

Тепер готова модель має виглядати приблизно так. Саме так можна створити просту модель загроз за допомогою OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Microsoft's Threat Modeling Tool — це безкоштовний інструмент, який можна завантажити, для аналізу проєктування програмного забезпечення. Його workflow створює діаграму, ідентифікує загрози та підтримує їх пом’якшення й перевірку за допомогою підходу STRIDE.<sup>[[4]](#references)</sup>

## References

- [1] [Пам’ятка з моделювання загроз](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [2] [Моделювання загроз — The Penetration Testing Execution Standard](https://www.pentest-standard.org/index.php/Threat_Modeling)
- [3] [Основи безпеки — OWASP Developer Guide](https://devguide.owasp.org/en/02-foundations/01-security-fundamentals/)
- [4] [Початок роботи з Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-getting-started)
- [5] [Моделювання загроз для драйверів — Windows drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/threat-modeling-for-drivers)
- [6] [SpiderSuite](https://spidersuite.io/)
- [7] [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon)
- [8] [Моделювання загроз PASTA: пояснення 7 етапів](https://versprite.com/cybersecurity-listings/devsecops/pasta-threat-modeling/)
- [9] [Документ методології Trike v1](https://trike.sourceforge.net/papers/Trike_v1_Methodology_Document-draft.pdf)
- [10] [Моделювання загроз: огляд доступних методів](https://www.sei.cmu.edu/documents/569/2018_019_001_524597.pdf)
{{#include ../banners/hacktricks-training.md}}
