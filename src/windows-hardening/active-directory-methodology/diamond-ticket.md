# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Як і golden ticket**, diamond ticket — це TGT, який можна використовувати, щоб **отримати доступ до будь-якої служби від імені будь-якого користувача**. Golden ticket повністю підробляється офлайн, шифрується хешем krbtgt цього домену, а потім передається в сеанс входу для використання. Оскільки контролери домену не відстежують TGT, які вони законно видали, вони без проблем приймають TGT, зашифровані власним хешем krbtgt.<sup>[[1]](#references)</sup>

Є два поширені способи виявити використання golden ticket:

- Шукати TGS-REQ без відповідного AS-REQ.
- Шукати TGT з безглуздими значеннями, наприклад стандартним 10-річним строком дії Mimikatz.

**Diamond ticket** створюється шляхом **зміни полів легітимного TGT, виданого DC**. Для цього потрібно **запросити** **TGT**, **розшифрувати** його хешем krbtgt домену, **змінити** потрібні поля квитка, а потім **повторно зашифрувати його**. Це **усуває два згадані вище недоліки** golden ticket, оскільки:<sup>[[1]](#references)</sup>

- TGS-REQ матимуть попередній AS-REQ.
- TGT виданий DC, а отже, міститиме всі правильні дані з політики Kerberos домену. Хоча їх можна точно підробити й у golden ticket, це складніше й підвищує ризик помилок.

### Вимоги та робочий процес

- **Криптографічний матеріал**: ключ krbtgt AES256 (бажано) або хеш NTLM для розшифрування TGT і повторного підписання.
- **Blob легітимного TGT**: отриманий за допомогою `/tgtdeleg`, `asktgt`, `s4u` або шляхом експорту квитків із пам’яті.
- **Контекстні дані**: RID цільового користувача, RID/SID груп і, за бажанням, атрибути PAC, отримані через LDAP.
- **Ключі служб** (лише якщо плануєте повторно створити квитки служб): AES-ключ SPN служби, яку потрібно імперсонувати.

1. Отримайте TGT для будь-якого контрольованого користувача через AS-REQ (Rubeus `/tgtdeleg` зручний, оскільки змушує клієнт виконати обмін Kerberos GSS-API без облікових даних).
2. Розшифруйте отриманий TGT ключем krbtgt і змініть атрибути PAC (користувача, групи, дані входу, SID, твердження пристрою тощо).
3. Повторно зашифруйте/підпишіть квиток тим самим ключем krbtgt і впровадьте його в поточний сеанс входу (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. За бажанням повторіть процес із квитком служби, передавши дійсний blob TGT і ключ цільової служби, щоб залишатися непомітним у мережі.

### Оновлені методи Rubeus (2024+)

Нещодавні напрацювання Huntress модернізували дію `diamond` у Rubeus, перенісши покращення `/ldap` і `/opsec`, які раніше були доступні лише для golden/silver ticket. Тепер `/ldap` отримує реальний контекст PAC, надсилаючи запити до LDAP **і** підключаючи SYSVOL для отримання атрибутів облікових записів/груп, а також політик Kerberos/паролів (наприклад, `GptTmpl.inf`). Параметр `/opsec` змушує процес AS-REQ/AS-REP відповідати поведінці Windows: виконує двоетапний обмін попередньою автентифікацією та застосовує лише AES і реалістичні KDCOptions. Це значно зменшує кількість очевидних індикаторів, як-от відсутні поля PAC або строки дії, що не відповідають політиці.<sup>[[3]](#references)</sup>

```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
./Rubeus.exe diamond /tgtdeleg \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /groups:512,519 \
  /krbkey:<KRBTGT_AES256_KEY> \
  /ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
  /opsec /nowrap
```

- `/ldap` (з необов’язковими `/ldapuser` і `/ldappassword`) запитує AD і SYSVOL, щоб відтворити дані політики PAC цільового користувача.
- `/opsec` примусово повторює AS-REQ у стилі Windows, обнуляючи помітні прапорці та використовуючи лише AES256.
- `/tgtdeleg` дає змогу не торкатися пароля жертви у відкритому вигляді чи її NTLM/AES-ключа, водночас повертаючи TGT, який можна розшифрувати.

### Перекроювання service ticket

Те саме оновлення Rubeus додало можливість застосовувати техніку diamond до TGS-блобів. Передавши `diamond` **TGT у кодуванні base64** (отриманий через `asktgt`, `/tgtdeleg` або раніше підроблений TGT), **SPN сервісу** та **AES-ключ сервісу**, можна створювати реалістичні service ticket, не взаємодіючи з KDC, — фактично, більш прихований silver ticket.<sup>[[3]](#references)</sup>

```powershell
./Rubeus.exe diamond \
  /ticket:<BASE64_TGT_OR_KRB-CRED> \
  /service:cifs/dc01.lab.local \
  /servicekey:<AES256_SERVICE_KEY> \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /ldap /opsec /nowrap
```

Цей workflow ідеальний, коли ви вже маєте ключ service account (наприклад, отриманий за допомогою `lsadump::lsa /inject` або `secretsdump.py`) і хочете створити одноразовий TGS, який точно відповідає політикам AD, часовим рамкам і даним PAC, не генеруючи жодного нового AS/TGS-трафіку.<sup>[[3]](#references)</sup>

### Sapphire-style PAC swaps (2025)

Новіший варіант, який іноді називають **sapphire ticket**, поєднує базу «справжнього TGT» від Diamond із **S4U2self+U2U**, щоб викрасти привілейований PAC і вставити його у власний TGT. Замість того щоб вигадувати додаткові SID, ви запитуєте U2U S4U2self ticket для користувача з високими привілеями, де `sname` вказує на requester із низькими привілеями; KRB_TGS_REQ містить TGT requester у `additional-tickets` і встановлює `ENC-TKT-IN-SKEY`, що дає змогу розшифрувати service ticket за допомогою ключа цього користувача. Потім ви витягуєте привілейований PAC і вставляєте його у свій легітимний TGT, а тоді повторно підписуєте TGT ключем krbtgt.<sup>[[2]](#references)[[5]](#references)</sup>

Тепер Impacket постачається з підтримкою sapphire у `ticketer.py` через `-impersonate` + `-request` (обмін із KDC у реальному часі):<sup>[[2]](#references)[[5]](#references)</sup>

```bash
python3 ticketer.py -request -impersonate 'DAuser' \
  -domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
  -aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```

- `-impersonate` приймає ім’я користувача або SID; для `-request` потрібні облікові дані активного користувача й матеріал ключа krbtgt (AES/NTLM), щоб розшифрувати/змінити квитки.

Ключові OPSEC-ознаки під час використання цього варіанта:<sup>[[5]](#references)</sup>

- TGS-REQ міститиме `ENC-TKT-IN-SKEY` і `additional-tickets` (TGT жертви) — рідкісне явище у звичайному трафіку.
- `sname` часто збігається з ім’ям користувача, який робить запит (доступ для власних потреб), а в Event ID 4769 викликач і ціль відображаються як той самий SPN/користувач.
- Очікуйте парні записи 4768/4769 з однаковим клієнтським комп’ютером, але різними CNAME (користувач із низькими привілеями, який робить запит, і власник привілейованого PAC).

### OPSEC і виявлення

- Традиційні евристики для пошуку (TGS без AS, термін дії на десятиліття) досі застосовні до golden ticket, але diamond ticket переважно виявляються, коли **вміст PAC або зіставлення груп виглядають неможливими**. Заповнюйте кожне поле PAC (години входу, шляхи до профілю користувача, ідентифікатори пристроїв), щоб автоматизовані порівняння не виявили підробку одразу.<sup>[[3]](#references)</sup>
- **Не додавайте надмірну кількість груп/RID**. Якщо потрібні лише `512` (Domain Admins) і `519` (Enterprise Admins), зупиніться на них і переконайтеся, що цільовий обліковий запис правдоподібно належить до цих груп в інших місцях AD. Надмірна кількість `ExtraSids` одразу видає підробку.
- Підміни у стилі Sapphire залишають U2U-відбитки: `ENC-TKT-IN-SKEY` + `additional-tickets`, а також `sname`, що вказує на користувача (часто на того, хто зробив запит) у 4769, і подальший вхід 4624, отриманий із підробленого квитка. Зіставляйте ці поля, а не шукайте лише відсутні AS-REQ.<sup>[[5]](#references)</sup>
- Microsoft почала поступово відмовлятися від **видачі сервісних квитків RC4** через CVE-2026-20833; використання лише AES etypes на KDC одночасно посилює захист домену та узгоджується з інструментами для diamond/sapphire (`/opsec` уже примусово використовує AES). Використання RC4 у підроблених PAC дедалі частіше буде помітним.<sup>[[6]](#references)</sup>
- Проєкт Splunk Security Content надає телеметрію attack-range для diamond ticket, а також засоби виявлення, як-от *Індикатор імперсонації адміністратора домену Windows*, що зіставляє незвичні послідовності Event ID 4768/4769/4624 і зміни груп PAC. Повторне відтворення цього набору даних (або створення власного за допомогою команд вище) допоможе перевірити покриття SOC для T1558.001 і водночас надасть конкретну логіку сповіщень, яку можна обійти.<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – Дорогоцінне каміння: нове покоління атак Kerberos (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: ми любимо гратися з квитками (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Повторний огляд Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Дані про атаки Diamond Ticket і засоби виявлення (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Тіньова сторона коштовностей: квитки Diamond і Sapphire (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – Примусове застосування RC4 для сервісних квитків у зв’язку з CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)
{{#include ../../banners/hacktricks-training.md}}
