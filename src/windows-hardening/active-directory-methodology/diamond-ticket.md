# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Як і golden ticket**, diamond ticket — це TGT, який можна використовувати для доступу до будь-якої служби від імені будь-якого користувача. Golden ticket підробляється повністю офлайн, шифрується за допомогою krbtgt hash цього домену і потім вставляється в сесію входу для використання. Оскільки контролери домену не відстежують TGTs, які вони легітимно видали, вони охоче приймають TGTs, зашифровані своїм власним krbtgt hash.

Існує два поширені методи виявлення використання golden tickets:

- Шукати TGS-REQs, для яких немає відповідного AS-REQ.
- Шукати TGTs з дивними значеннями, наприклад Mimikatz's default 10-year lifetime.

A **diamond ticket** створюється шляхом модифікації полів легітимного TGT, що був виданий DC. Це досягається шляхом отримання TGT, розшифрування його за допомогою krbtgt hash домену, модифікації потрібних полів квитка, а потім повторного його шифрування. Це усуває дві вищезгадані недоліки golden ticket, тому що:

- TGS-REQs будуть мати попередній AS-REQ.
- TGT був виданий DC, отже він матиме всі коректні деталі згідно з Kerberos політикою домену. Хоча ці дані можна точно підробити в golden ticket, це складніше і відкрито для помилок.

### Вимоги та робочий процес

- **Криптографічні матеріали**: ключ krbtgt AES256 (переважний) або NTLM hash для розшифрування та повторного підпису TGT.
- **Легітимний TGT blob**: отримується за допомогою `/tgtdeleg`, `asktgt`, `s4u` або експортом квитків з пам'яті.
- **Контекстні дані**: RID цільового користувача, групові RIDs/SIDs та (опційно) атрибути PAC, отримані через LDAP.
- **Сервісні ключі** (тільки якщо плануєте повторно виписувати service tickets): AES ключ сервісного SPN, від імені якого відбувається імітація.

1. Отримайте TGT для будь-якого контрольованого користувача через AS-REQ (Rubeus `/tgtdeleg` зручний, бо змушує клієнта виконати Kerberos GSS-API обмін без облікових даних).
2. Розшифруйте повернений TGT за допомогою krbtgt ключа, виправте атрибути PAC (user, groups, logon info, SIDs, device claims тощо).
3. Повторно зашифруйте/підпишіть квиток тим самим krbtgt ключем та інжектуйте його в поточну сесію входу (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Опційно, повторіть процес для service ticket, надавши валідний TGT blob плюс цільовий service key, щоб залишатися тихими в мережі.

### Updated Rubeus tradecraft (2024+)

Остання робота Huntress модернізувала дію `diamond` всередині Rubeus, перенісши покращення `/ldap` та `/opsec`, що раніше існували лише для golden/silver tickets. `/ldap` тепер автоматично заповнює точні атрибути PAC безпосередньо з AD (user profile, logon hours, sidHistory, domain policies), тоді як `/opsec` робить AS-REQ/AS-REP потік невідрізним від Windows клієнта шляхом виконання двокрокової pre-auth послідовності та примусового використання тільки AES-шифрування. Це суттєво зменшує очевидні індикатори, такі як порожні device IDs або нереалістичні вікна дії.
```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
.\Rubeus.exe diamond /tgtdeleg \
/ticketuser:svc_sql /ticketuserid:1109 \
/groups:512,519 \
/krbkey:<KRBTGT_AES256_KEY> \
/ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
/opsec /nowrap
```
- `/ldap` (with optional `/ldapuser` & `/ldappassword`) виконує запити до AD і SYSVOL, щоб віддзеркалити дані політики PAC цільового користувача.
- `/opsec` примушує Windows-подібний повторний AS-REQ, обнуляє шумні прапори й використовує AES256.
- `/tgtdeleg` дозволяє уникнути доступу до пароля у відкритому вигляді або NTLM/AES ключа жертви, при цьому повертаючи розшифровуваний TGT.

### Перекроювання service-ticket

Те саме оновлення Rubeus додало можливість застосувати the diamond technique до TGS blobs. Передаючи `diamond` **base64-encoded TGT** (з `asktgt`, `/tgtdeleg` або раніше підробленого TGT), **service SPN**, та **service AES key**, ви можете створювати реалістичні service tickets без звертання до KDC — фактично більш прихований silver ticket.
```powershell
.\Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Цей робочий процес ідеальний, коли ви вже контролюєте ключ облікового запису сервісу (наприклад, витягнутий за допомогою `lsadump::lsa /inject` або `secretsdump.py`) і хочете створити одноразовий TGS, який точно відповідає політиці AD, часовим рамкам і даним PAC без генерації будь-якого нового трафіку AS/TGS.

### OPSEC & примітки щодо виявлення

- Традиційні евристики hunter (TGS without AS, decade-long lifetimes) досі застосовуються до golden tickets, але diamond tickets переважно виявляються, коли **вміст PAC або відображення груп виглядає неможливим**. Заповнюйте всі поля PAC (logon hours, user profile paths, device IDs), щоб автоматизовані порівняння не миттєво помітили підробку.
- **Не додавати зайвих груп/RIDs**. Якщо вам потрібні лише `512` (Domain Admins) і `519` (Enterprise Admins), зупиніться на цьому і переконайтеся, що цільовий акаунт правдоподібно належить до цих груп в AD. Надмірні `ExtraSids` видають підробку.
- Проект Splunk Security Content поширює телеметрію attack-range для diamond tickets та детекції, такі як *Windows Domain Admin Impersonation Indicator*, яка корелює незвичні послідовності Event ID 4768/4769/4624 та зміни груп у PAC. Відтворення цього набору даних (або генерація власного за допомогою команд вище) допомагає перевірити покриття SOC для T1558.001 та дає вам конкретну логіку сповіщень, яку можна використати для обходу.

## References

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)

{{#include ../../banners/hacktricks-training.md}}
