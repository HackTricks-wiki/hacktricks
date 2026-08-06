# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Як і golden ticket**, diamond ticket є TGT, який можна використовувати для **доступу до будь-якого сервісу від імені будь-якого користувача**. Golden ticket повністю підробляється офлайн, шифрується за допомогою хешу krbtgt цього домену, а потім передається в logon session для використання. Оскільки контролери домену не відстежують TGT, які вони легітимно видали, вони охоче приймають TGT, зашифровані власним хешем krbtgt.<sup>[[1]](#references)</sup>

Існує дві поширені техніки виявлення використання golden tickets:

- Шукати TGS-REQ, для яких немає відповідного AS-REQ.
- Шукати TGT із безглуздими значеннями, наприклад стандартним 10-річним терміном дії Mimikatz.

**Diamond ticket** створюється шляхом **модифікації полів легітимного TGT, виданого DC**. Для цього потрібно **запросити** **TGT**, **розшифрувати** його за допомогою хешу krbtgt домену, **змінити** потрібні поля квитка, а потім **повторно зашифрувати його**. Це **усуває два вищезгадані недоліки** golden ticket, оскільки:<sup>[[1]](#references)</sup>

- TGS-REQ матимуть попередній AS-REQ.
- TGT був виданий DC, а отже, міститиме всі правильні дані відповідно до Kerberos policy домену. Хоча їх можна точно підробити в golden ticket, це складніше й створює більше можливостей для помилок.

### Вимоги та workflow

- **Cryptographic material**: AES256 key krbtgt (бажано) або NTLM hash для розшифрування та повторного підпису TGT.
- **Legitimate TGT blob**: отримується за допомогою `/tgtdeleg`, `asktgt`, `s4u` або шляхом експорту tickets із пам'яті.
- **Context data**: RID цільового користувача, group RIDs/SIDs і (необов'язково) PAC attributes, отримані через LDAP.
- **Service keys** (лише якщо ви плануєте повторно створювати service tickets): AES key service SPN, від імені якого потрібно здійснити impersonation.

1. Отримайте TGT для будь-якого контрольованого користувача через AS-REQ (`/tgtdeleg` у Rubeus зручний, оскільки змушує client виконати Kerberos GSS-API dance без credentials).
2. Розшифруйте отриманий TGT за допомогою ключа krbtgt, змініть PAC attributes (user, groups, logon info, SIDs, device claims тощо).
3. Повторно зашифруйте та підпишіть ticket тим самим ключем krbtgt і введіть його в поточну logon session (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. За потреби повторіть процес для service ticket, передавши дійсний TGT blob разом із ключем цільового service, щоб залишатися stealthy у мережі.

### Оновлена практика Rubeus (2024+)

Нещодавні дослідження Huntress модернізували action `diamond` у Rubeus, перенісши вдосконалення `/ldap` і `/opsec`, які раніше існували лише для golden/silver tickets. Тепер `/ldap` отримує реальний PAC context, виконуючи запити до LDAP і підключаючи SYSVOL для вилучення account/group attributes, а також Kerberos/password policy (наприклад, `GptTmpl.inf`), тоді як `/opsec` робить flow AS-REQ/AS-REP схожим на Windows, виконуючи двоетапний preauth exchange і примусово використовуючи AES-only та реалістичні KDCOptions. Це суттєво зменшує очевидні indicators, такі як відсутні PAC fields або lifetimes, що не відповідають policy.<sup>[[3]](#references)</sup>
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
- `/ldap` (з опційними `/ldapuser` і `/ldappassword`) запитує AD і SYSVOL, щоб відтворити дані політики PAC цільового користувача.
- `/opsec` імітує Windows-подібний повторний AS-REQ, обнуляючи шумні flags і використовуючи лише AES256.
- `/tgtdeleg` не розкриває пароль у відкритому вигляді або NTLM/AES key жертви, водночас повертаючи TGT, який можна розшифрувати.

### Перекроювання service-ticket

Те саме оновлення Rubeus додало можливість застосовувати diamond technique до TGS blobs. Передавши `diamond` **base64-encoded TGT** (отриманий через `asktgt`, `/tgtdeleg` або раніше forged TGT), **service SPN** і **service AES key**, можна створювати реалістичні service tickets без взаємодії з KDC — фактично stealthier silver ticket.<sup>[[3]](#references)</sup>
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Цей workflow ідеальний, коли ви вже контролюєте ключ service account (наприклад, отриманий за допомогою `lsadump::lsa /inject` або `secretsdump.py`) і хочете створити одноразовий TGS, який точно відповідає політиці AD, часовим параметрам і даним PAC, не створюючи жодного нового AS/TGS-трафіку.<sup>[[3]](#references)</sup>

### Sapphire-style PAC swaps (2025)

Новий варіант, який іноді називають **sapphire ticket**, поєднує базу «справжнього TGT» від **Diamond** із **S4U2self+U2U**, щоб викрасти привілейований PAC і вставити його у власний TGT. Замість створення додаткових SID ви запитуєте U2U S4U2self ticket для користувача з високими привілеями, де `sname` вказує на requester із низькими привілеями; KRB_TGS_REQ містить TGT requester у `additional-tickets` і встановлює `ENC-TKT-IN-SKEY`, що дає змогу розшифрувати service ticket за допомогою ключа цього користувача. Потім ви видобуваєте привілейований PAC і вставляєте його у свій легітимний TGT, після чого повторно підписуєте його ключем krbtgt.<sup>[[2]](#references)[[5]](#references)</sup>

Тепер Impacket підтримує sapphire через `-impersonate` + `-request` (обмін із KDC у реальному часі):<sup>[[2]](#references)[[5]](#references)</sup>
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` приймає username або SID; `-request` вимагає live user creds, а також key material krbtgt (AES/NTLM) для розшифрування та patch квитків.

Ключові OPSEC-ознаки під час використання цього варіанта:<sup>[[5]](#references)</sup>

- TGS-REQ міститиме `ENC-TKT-IN-SKEY` і `additional-tickets` (TGT жертви) — рідкісна ознака для нормального трафіку.
- `sname` часто дорівнює користувачу, який виконує запит (self-service access), а Event ID 4769 показує caller і target як один і той самий SPN/user.
- Очікуйте парні записи 4768/4769 з одним і тим самим client computer, але різними CNAMES (low-priv requester проти privileged PAC owner).

### OPSEC і зауваження щодо виявлення

- Традиційні hunter heuristics (TGS без AS, lifetimes тривалістю в десятиліття) усе ще застосовні до golden tickets, але diamond tickets переважно виявляються, коли **вміст PAC або mapping груп виглядає неможливим**. Заповнюйте кожне поле PAC (logon hours, user profile paths, device IDs), щоб automated comparisons не позначали forgery одразу.<sup>[[3]](#references)</sup>
- **Не додавайте надмірну кількість груп/RID**. Якщо вам потрібні лише `512` (Domain Admins) і `519` (Enterprise Admins), зупиніться на цьому та переконайтеся, що target account правдоподібно належить до цих груп в інших місцях AD. Надмірна кількість `ExtraSids` одразу викликає підозри.
- Swaps у стилі Sapphire залишають U2U fingerprints: `ENC-TKT-IN-SKEY` + `additional-tickets`, а також `sname`, що вказує на користувача (часто requester) у 4769, і наступний 4624 logon, отриманий із forged ticket. Корелюйте ці поля, а не лише шукайте прогалини без AS-REQ.<sup>[[5]](#references)</sup>
- Microsoft почала поетапно відмовлятися від **видачі RC4 service tickets** через CVE-2026-20833; примусове використання AES-only etypes на KDC одночасно зміцнює domain і узгоджується з diamond/sapphire tooling (/opsec уже примусово використовує AES). Додавання RC4 до forged PACs дедалі більше виділятиметься.<sup>[[6]](#references)</sup>
- Проєкт Splunk Security Content поширює attack-range telemetry для diamond tickets, а також detections, як-от *Windows Domain Admin Impersonation Indicator*, який корелює незвичні послідовності Event ID 4768/4769/4624 і зміни груп у PAC. Відтворення цього dataset (або створення власного за допомогою наведених вище команд) допомагає перевірити SOC coverage для T1558.001 і водночас надає конкретну alert logic для обходу.<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
