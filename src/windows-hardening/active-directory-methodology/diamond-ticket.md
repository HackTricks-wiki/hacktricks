# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Як і golden ticket**, diamond ticket — це TGT, який можна використовувати, щоб **отримати доступ до будь-якої служби від імені будь-якого користувача**. Golden ticket повністю підробляють офлайн, шифрують хешем krbtgt цього домену, а потім передають у сеанс входу для використання. Оскільки контролери домену не відстежують, які TGT вони (або інші контролери) законно видали, вони без проблем приймають TGT, зашифровані власним хешем krbtgt.<sup>[[1]](#references)</sup>

Є два поширені способи виявити використання golden ticket:

- Шукати TGS-REQ, яким не відповідає попередній AS-REQ.
- Шукати TGT із безглуздими значеннями, як-от стандартний 10-річний термін дії Mimikatz.

**Diamond ticket** створюють, **змінюючи поля легітимного TGT, виданого DC**. Для цього **запитують** **TGT**, **розшифровують** його хешем krbtgt домену, **змінюють** потрібні поля квитка, а потім **повторно шифрують його**. Це **усуває два згадані вище недоліки** golden ticket, оскільки:<sup>[[1]](#references)</sup>

- Перед TGS-REQ буде AS-REQ.
- TGT виданий DC, а отже, міститиме всі коректні дані відповідно до політики Kerberos домену. Хоча їх можна точно підробити й у golden ticket, це складніше й легше припуститися помилки.

### Вимоги та послідовність дій

- **Криптографічний матеріал**: ключ krbtgt AES256 (бажано) або хеш NTLM, потрібний для розшифрування та повторного підпису TGT.
- **Blob легітимного TGT**: отриманий за допомогою `/tgtdeleg`, `asktgt`, `s4u` або експортування квитків із пам’яті.
- **Контекстні дані**: RID цільового користувача, RID/SID груп і (необов’язково) атрибути PAC, отримані через LDAP.
- **Ключі служб** (лише якщо плануєте повторно створювати квитки служб): ключ AES цільового SPN служби, від імені якої виконуватиметься імперсонація.

1. Отримайте TGT для будь-якого контрольованого користувача через AS-REQ (Rubeus `/tgtdeleg` зручний, бо змушує клієнт виконати обмін Kerberos GSS-API без облікових даних).
2. Розшифруйте отриманий TGT ключем krbtgt і змініть атрибути PAC (користувача, групи, дані входу, SID, твердження пристрою тощо).
3. Повторно зашифруйте/підпишіть квиток тим самим ключем krbtgt і впровадьте його в поточний сеанс входу (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. За бажанням повторіть процес із квитком служби, передавши дійсний blob TGT і ключ цільової служби, щоб залишатися непомітними в мережі.

### Оновлені прийоми роботи з Rubeus (2024+)

Нещодавні напрацювання Huntress модернізували дію `diamond` у Rubeus, перенісши до неї покращення `/ldap` і `/opsec`, які раніше були доступні лише для golden/silver tickets. Тепер `/ldap` отримує реальний контекст PAC, надсилаючи запити до LDAP **і** підключаючи SYSVOL, щоб витягти атрибути облікових записів/груп і політики Kerberos/паролів (наприклад, `GptTmpl.inf`), а `/opsec` забезпечує відповідність потоку AS-REQ/AS-REP поведінці Windows: виконує двоетапний обмін попередньої автентифікації та вимагає лише AES і реалістичні KDCOptions. Це значно зменшує кількість очевидних індикаторів, як-от відсутні поля PAC або терміни дії, що не відповідають політиці.<sup>[[3]](#references)</sup>

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

- `/ldap` (з необов’язковими `/ldapuser` і `/ldappassword`) надсилає запити до AD і SYSVOL, щоб скопіювати дані політики PAC цільового користувача.
- `/opsec` примусово виконує повторну спробу AS-REQ, подібну до Windows: обнуляє шумні прапорці та використовує лише AES256.
- `/tgtdeleg` дає змогу не торкатися відкритого пароля або ключа NTLM/AES жертви й водночас отримати TGT, який можна розшифрувати.

### Перекроювання service ticket

У тому самому оновленні Rubeus з’явилася можливість застосовувати техніку diamond до TGS-блобів. Передавши `diamond` **TGT у форматі base64** (отриманий через `asktgt`, `/tgtdeleg` або раніше підроблений TGT), **service SPN** і **ключ AES служби**, можна створювати реалістичні service ticket без звернення до KDC — фактично, це непомітніший silver ticket.<sup>[[3]](#references)</sup>

```powershell
./Rubeus.exe diamond \
  /ticket:<BASE64_TGT_OR_KRB-CRED> \
  /service:cifs/dc01.lab.local \
  /servicekey:<AES256_SERVICE_KEY> \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /ldap /opsec /nowrap
```

Цей workflow ідеальний, якщо ви вже контролюєте ключ service account (наприклад, отриманий за допомогою `lsadump::lsa /inject` або `secretsdump.py`) і хочете створити одноразовий TGS, який точно відповідає політикам AD, часовим межам і даним PAC, не надсилаючи нового трафіку AS/TGS.<sup>[[3]](#references)</sup>

### Заміна PAC у стилі Sapphire (2025)

Новіший варіант, який іноді називають **sapphire ticket**, поєднує основу з «реального TGT» Diamond із **S4U2self+U2U**, щоб викрасти привілейований PAC і вставити його у власний TGT. Замість вигадування додаткових SID ви запитуєте U2U S4U2self ticket для користувача з високими привілеями, де `sname` вказує на користувача з низькими привілеями, який надсилає запит; KRB_TGS_REQ містить TGT користувача, що надсилає запит, у `additional-tickets` і встановлює `ENC-TKT-IN-SKEY`, що дає змогу розшифрувати service ticket за допомогою ключа цього користувача. Потім ви витягуєте привілейований PAC і вставляєте його у свій легітимний TGT, після чого повторно підписуєте його ключем krbtgt.<sup>[[2]](#references)[[5]](#references)</sup>

Тепер Impacket постачається з підтримкою sapphire у `ticketer.py` через `-impersonate` + `-request` (обмін із KDC у реальному часі):<sup>[[2]](#references)[[5]](#references)</sup>

```bash
python3 ticketer.py -request -impersonate 'DAuser' \
  -domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
  -aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```

- `-impersonate` приймає ім’я користувача або SID; `-request` вимагає чинних облікових даних користувача та ключового матеріалу krbtgt (AES/NTLM) для розшифрування/зміни квитків.

Ключові OPSEC-ознаки під час використання цього варіанта:<sup>[[5]](#references)</sup>

- TGS-REQ міститиме `ENC-TKT-IN-SKEY` і `additional-tickets` (TGT жертви) — рідкісне явище у звичайному трафіку.
- `sname` часто збігається з користувачем, який надсилає запит (доступ для власного використання), а Event ID 4769 показує того самого caller і target — SPN/користувача.
- Очікуйте парні записи 4768/4769 з однаковим клієнтським комп’ютером, але різними CNAMES (запитувач із низькими привілеями та власник привілейованого PAC).

### OPSEC і виявлення

- Традиційні евристики пошуку (TGS без AS, термін дії на десятиліття) усе ще застосовні до golden tickets, але diamond tickets переважно виявляють, коли **вміст PAC або зіставлення груп виглядає неправдоподібно**. Заповнюйте кожне поле PAC (години входу, шляхи до профілів користувачів, ідентифікатори пристроїв), щоб автоматизовані порівняння не виявляли підробку одразу.<sup>[[3]](#references)</sup>
- **Не додавайте надмірну кількість груп/RID**. Якщо потрібні лише `512` (Domain Admins) і `519` (Enterprise Admins), зупиніться на них і переконайтеся, що цільовий обліковий запис правдоподібно належить до цих груп деінде в AD. Надмірна кількість `ExtraSids` видає підробку.
- Заміни в стилі Sapphire залишають U2U-сліди: `ENC-TKT-IN-SKEY` + `additional-tickets`, а також `sname`, що вказує на користувача (часто на того, хто надіслав запит) у 4769, і наступний вхід 4624, отриманий із підробленого квитка. Співвідносьте ці поля, а не лише шукайте проміжки без AS-REQ.<sup>[[5]](#references)</sup>
- Microsoft почала поступово відмовлятися від **видачі сервісних квитків RC4** через CVE-2026-20833; примусове використання лише AES etypes на KDC одночасно посилює захист домену та узгоджується з інструментами diamond/sapphire (режим /opsec уже примусово використовує AES). Включення RC4 у підроблені PAC дедалі помітніше вирізнятиметься.<sup>[[6]](#references)</sup>
- Проєкт Splunk Security Content поширює телеметрію attack-range для diamond tickets, а також правила виявлення, як-от *Windows Domain Admin Impersonation Indicator*, що зіставляє незвичні послідовності Event ID 4768/4769/4624 і зміни груп PAC. Повторне відтворення цього набору даних (або створення власного за допомогою наведених вище команд) допомагає перевірити покриття SOC для T1558.001 і водночас надає конкретну логіку сповіщень, яку можна обійти.<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – Дорогоцінні камені: нове покоління атак Kerberos (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: ми любимо гратися з квитками (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Переосмислення Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Дані про атаки Diamond Ticket і правила виявлення (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – Примусове використання RC4 для сервісних квитків у зв’язку з CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)
{{#include ../../banners/hacktricks-training.md}}
