# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket is a TGT which can be used to **access any service as any user**. A golden ticket is forged completely offline, encrypted with the krbtgt hash of that domain, and then passed into a logon session for use. Because domain controllers don't track TGTs it (or they) have legitimately issued, they will happily accept TGTs that are encrypted with its own krbtgt hash.

There are two common techniques to detect the use of golden tickets:

- Шукайте TGS-REQs, які не мають відповідного AS-REQ.
- Шукайте TGTs з дивними значеннями, наприклад стандартним 10-річним терміном дії у Mimikatz.

A **diamond ticket** is made by **modifying the fields of a legitimate TGT that was issued by a DC**. This is achieved by **requesting** a **TGT**, **decrypting** it with the domain's krbtgt hash, **modifying** the desired fields of the ticket, then **re-encrypting it**. This **overcomes the two aforementioned shortcomings** of a golden ticket because:

- TGS-REQs will have a preceding AS-REQ.
- The TGT was issued by a DC which means it will have all the correct details from the domain's Kerberos policy. Even though these can be accurately forged in a golden ticket, it's more complex and open to mistakes.

### Requirements & workflow

- **Cryptographic material**: the krbtgt AES256 key (preferred) or NTLM hash in order to decrypt and re-sign the TGT.
- **Legitimate TGT blob**: obtained with `/tgtdeleg`, `asktgt`, `s4u`, or by exporting tickets from memory.
- **Context data**: the target user RID, group RIDs/SIDs, and (optionally) LDAP-derived PAC attributes.
- **Service keys** (only if you plan to re-cut service tickets): AES key of the service SPN to be impersonated.

1. Отримайте TGT для будь-якого контрольованого користувача через AS-REQ (Rubeus `/tgtdeleg` зручний, оскільки змушує клієнта виконати Kerberos GSS-API dance без облікових даних).
2. Розшифруйте повернений TGT за допомогою krbtgt key, змініть PAC attributes (user, groups, logon info, SIDs, device claims тощо).
3. Повторно зашифруйте/підпишіть квиток тим самим krbtgt key і інжектуйте його в поточний сеанс входу (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. За бажанням, повторіть процес для service ticket, подавши дійсний TGT blob разом із ключем цільового сервісу, щоб залишатися прихованим у мережевому трафіку.

### Updated Rubeus tradecraft (2024+)

Recent work by Huntress modernized the `diamond` action inside Rubeus by porting the `/ldap` and `/opsec` improvements that previously only existed for golden/silver tickets. `/ldap` now pulls real PAC context by querying LDAP **and** mounting SYSVOL to extract account/group attributes plus Kerberos/password policy (e.g., `GptTmpl.inf`), while `/opsec` makes the AS-REQ/AS-REP flow match Windows by doing the two-step preauth exchange and enforcing AES-only + realistic KDCOptions. This dramatically reduces obvious indicators such as missing PAC fields or policy-mismatched lifetimes.
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
- `/ldap` (з опціональними `/ldapuser` та `/ldappassword`) запитує AD і SYSVOL, щоб відтворити PAC policy data цільового користувача.
- `/opsec` змушує Windows-подібну повторну спробу AS-REQ, обнуляючи шумні прапорці і використовуючи AES256.
- `/tgtdeleg` дозволяє не торкатися пароля у відкритому вигляді або NTLM/AES key жертви, але при цьому повертає розшифровуваний TGT.

### Перекроювання service-ticket

Те саме оновлення Rubeus додало можливість застосовувати diamond technique до TGS blobs. Надавши `diamond` **base64-encoded TGT** (з `asktgt`, `/tgtdeleg` або раніше підробленого TGT), **service SPN** і **service AES key**, ви можете створити реалістичні service tickets без звернення до KDC — фактично більш прихований silver ticket.
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Цей робочий процес ідеально підходить, коли ви вже контролюєте ключ облікового запису сервісу (наприклад, вивантажений за допомогою `lsadump::lsa /inject` або `secretsdump.py`) і хочете згенерувати одноразовий TGS, який ідеально відповідає політиці AD, часовим рамкам і даним PAC, не ініціюючи жодного нового AS/TGS трафіку.

### Sapphire-подібні заміни PAC (2025)

Новіший варіант, який іноді називають **sapphire ticket**, поєднує базу Diamond "real TGT" з **S4U2self+U2U**, щоб вкрасти привілейований PAC і вставити його у власний TGT. Замість вигадування додаткових SIDs, ви запитуєте U2U S4U2self ticket для користувача з високими привілеями, де `sname` спрямований на запитувача з низькими привілеями; KRB_TGS_REQ несе TGT запитувача в `additional-tickets` і встановлює `ENC-TKT-IN-SKEY`, що дозволяє розшифрувати service ticket за допомогою ключа цього користувача. Потім ви витягуєте привілейований PAC і впроваджуєте його у свій легітимний TGT перед повторним підписанням ключем krbtgt.

Impacket's `ticketer.py` тепер має підтримку sapphire через `-impersonate` + `-request` (обмін з KDC у реальному часі):
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` приймає ім'я користувача або SID; `-request` вимагає дійсні облікові дані користувача плюс krbtgt key material (AES/NTLM) для розшифровки/запатчення квитків.

Key OPSEC tells when using this variant:

- TGS-REQ will carry `ENC-TKT-IN-SKEY` and `additional-tickets` (the victim TGT) — рідко зустрічається в нормальному трафіку.
- `sname` часто дорівнює користувачу, що робить запит (self-service access), а Event ID 4769 показує викликача і ціль як той самий SPN/user.
- Очікуйте парні записи 4768/4769 з тим самим клієнтським комп'ютером, але різними CNAMES (заявник з низьким рівнем привілеїв vs. привілейований PAC власник).

### OPSEC & detection notes

- Традиційні hunter евристики (TGS without AS, decade-long lifetimes) все ще застосовні до golden tickets, але diamond tickets переважно виявляються тоді, коли **вміст PAC або відображення груп виглядає неможливим**. Заповнюйте всі поля PAC (logon hours, user profile paths, device IDs), щоб автоматичні порівняння не одразу позначили підробку.
- **Do not oversubscribe groups/RIDs**. Якщо вам потрібні лише `512` (Domain Admins) та `519` (Enterprise Admins), зупиніться на цьому й переконайтеся, що цільовий акаунт правдоподібно належить до цих груп в інших місцях AD. Надмірні `ExtraSids` видають підробку.
- Sapphire-style swaps залишають U2U відбитки: `ENC-TKT-IN-SKEY` + `additional-tickets` плюс `sname`, що вказує на користувача (часто того, хто робив запит) у 4769, і подальший логон 4624, ініційований з підробленого квитка. Корелюйте ці поля замість фокусування лише на відсутності AS-REQ.
- Microsoft почав поступово відмовлятися від **RC4 service ticket issuance** через CVE-2026-20833; застосування лише AES-etype на KDC одночасно зміцнює домен і узгоджується з diamond/sapphire tooling (/opsec вже змушує AES). Змішування RC4 у підроблені PAC буде дедалі помітнішим.
- Splunk's Security Content project поширює телеметрію attack-range для diamond tickets, а також виявлення такі як *Windows Domain Admin Impersonation Indicator*, яке корелює незвичні послідовності Event ID 4768/4769/4624 та зміни груп PAC. Повторний прогін цього набору даних (або генерування власного за наведеними командами) допомагає валідувати покриття SOC для T1558.001 і дає конкретну логіку оповіщень, яку треба обійти.

## References

- [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
