# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Як golden ticket**, diamond ticket — це TGT, який можна використовувати для **доступу до будь-якої служби від імені будь-якого користувача**. Golden ticket підробляється повністю офлайн, шифрується за допомогою krbtgt hash цього домену, а потім впроваджується в сесію входу для використання. Оскільки доменні контролери не відстежують TGT, які вони легітимно видали, вони охоче приймають TGT, зашифровані власним krbtgt hash.

Існує два поширені методи виявлення використання golden tickets:

- Шукати TGS-REQs, для яких немає відповідного AS-REQ.
- Шукати TGTs з дивними значеннями, наприклад стандартний 10-річний термін дії, який став дефолтним у Mimikatz.

A **diamond ticket** створюється шляхом **зміни полів легітимного TGT, який був виданий DC**. Це досягається шляхом **запиту** **TGT**, **розшифровки** його за допомогою krbtgt hash домену, **зміни** необхідних полів тікета і повторної **перешифровки**. Це **усуває два згадані вище недоліки** golden ticket, тому що:

- TGS-REQs матимуть попередній AS-REQ.
- TGT було видано DC, отже він міститиме всі правильні деталі з політики Kerberos домену. Хоча ці атрибути можна точно зімітувати в golden ticket, це складніше і більш схильне до помилок.

### Вимоги та робочий процес

- **Криптографічні матеріали**: AES256 key krbtgt (бажано) або NTLM hash для розшифровки та повторного підпису TGT.
- **Легітимний TGT blob**: отримується за допомогою `/tgtdeleg`, `asktgt`, `s4u`, або експортом ticket'ів з пам'яті.
- **Контекстні дані**: RID цільового користувача, RIDs/SIDs груп та (опціонально) LDAP-derived PAC attributes.
- **Service keys** (тільки якщо плануєте повторно вирізати service tickets): AES key сервісного SPN, від імені якого плануєте імперсонувати.

1. Отримайте TGT для будь-якого контрольованого користувача через AS-REQ (Rubeus `/tgtdeleg` зручний, бо примушує клієнта виконати Kerberos GSS-API dance без облікових даних).
2. Розшифруйте отриманий TGT за допомогою krbtgt key, підправте PAC attributes (user, groups, logon info, SIDs, device claims тощо).
3. Повторно зашифруйте/підпишіть тікет тим самим krbtgt key і інжектніть його в поточну сесію входу (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Опціонально, повторіть процес для service ticket, передавши валідний TGT blob плюс ключ цільового сервісу, щоб залишатися менш помітним "на дроті".

### Updated Rubeus tradecraft (2024+)

Остання робота Huntress модернізувала дію `diamond` всередині Rubeus, портуючи покращення `/ldap` та `/opsec`, які раніше існували тільки для golden/silver tickets. `/ldap` тепер автоматично заповнює точні PAC attributes безпосередньо з AD (user profile, logon hours, sidHistory, domain policies), тоді як `/opsec` робить AS-REQ/AS-REP потік невідрізним від клієнта Windows, виконуючи двокрокову pre-auth послідовність та примушуючи AES-only crypto. Це суттєво зменшує очевидні індикатори, такі як порожні device IDs або нереалістичні validity windows.
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
- `/ldap` (with optional `/ldapuser` & `/ldappassword`) запитує AD і SYSVOL, щоб відобразити дані політики PAC цільового користувача.
- `/opsec` примушує виконати повторну AS-REQ у стилі Windows, обнуляючи шумні прапори і використовуючи AES256.
- `/tgtdeleg` не потребує доступу до пароля у відкритому вигляді або NTLM/AES ключа жертви, але все одно повертає дешифруємий TGT.

### Перероблення service-ticket

Те ж саме оновлення Rubeus додало можливість застосувати diamond technique до TGS blobs. Подаючи в `diamond` **base64-encoded TGT** (from `asktgt`, `/tgtdeleg`, or a previously forged TGT), the **service SPN**, and the **service AES key**, ви можете створювати реалістичні service tickets без звертання до KDC — фактично більш непомітний silver ticket.
```powershell
.\Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Цей робочий процес ідеальний, коли ви вже контролюєте ключ сервісного облікового запису (наприклад, злитий за допомогою `lsadump::lsa /inject` або `secretsdump.py`) і бажаєте створити одноразовий TGS, який точно відповідає політикам AD, часовим обмеженням та даним PAC без надсилання будь-якого нового AS/TGS-трафіку.

### OPSEC & detection notes

- Традиційні евристики (TGS without AS, десятирічна тривалість дії) все ще застосовуються до golden tickets, але diamond tickets зазвичай виявляються тоді, коли **вміст PAC або відображення груп виглядають неможливими**. Заповніть кожне поле PAC (години входу, шляхи профілів користувачів, ідентифікатори пристроїв), щоб автоматизовані порівняння не відразу позначали підробку.
- **Не призначайте надто багато груп/RID**. Якщо вам потрібні лише `512` (Domain Admins) та `519` (Enterprise Admins), зупиніться на них і переконайтеся, що цільовий акаунт правдоподібно належить до цих груп в іншому місці AD. Надмірні `ExtraSids` видають підробку.
- Splunk's Security Content project розповсюджує attack-range телеметрію для diamond tickets, а також сигнатури виявлення, такі як *Windows Domain Admin Impersonation Indicator*, яка корелює незвичні послідовності Event ID 4768/4769/4624 і зміни груп у PAC. Відтворення цього набору даних (або генерація власного за допомогою наведених вище команд) допомагає перевірити покриття SOC для T1558.001 і надає конкретну логіку оповіщень для уникнення виявлення.

## References

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)

{{#include ../../banners/hacktricks-training.md}}
