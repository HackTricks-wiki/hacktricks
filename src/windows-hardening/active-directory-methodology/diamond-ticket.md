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

1. Obtain a TGT for any controlled user via AS-REQ (Rubeus `/tgtdeleg` is convenient because it coerces the client to perform the Kerberos GSS-API dance without credentials).
2. Decrypt the returned TGT with the krbtgt key, patch PAC attributes (user, groups, logon info, SIDs, device claims, etc.).
3. Re-encrypt/sign the ticket with the same krbtgt key and inject it into the current logon session (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Optionally, repeat the process over a service ticket by supplying a valid TGT blob plus the target service key to stay stealthy on the wire.

### Оновлений Rubeus tradecraft (2024+)

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
- `/ldap` (with optional `/ldapuser` & `/ldappassword`) запитує AD і SYSVOL, щоб відтворити дані політики PAC цільового користувача.
- `/opsec` примушує повторний AS-REQ у стилі Windows, обнуляє шумні флаги та використовує AES256.
- `/tgtdeleg` не вимагає пароля у відкритому вигляді або NTLM/AES ключа жертви, але все одно повертає розшифровуваний TGT.

### Service-ticket recutting

Те саме оновлення Rubeus додало можливість застосувати diamond technique до TGS blobs. Надавши `diamond` **base64-encoded TGT** (from `asktgt`, `/tgtdeleg`, or a previously forged TGT), the **service SPN**, and the **service AES key**, ви можете створювати реалістичні service tickets без звернення до KDC — по суті більш непомітний silver ticket.
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Цей робочий процес ідеально підходить, коли ви вже контролюєте ключ облікового запису служби (наприклад, отриманий за допомогою `lsadump::lsa /inject` або `secretsdump.py`) і хочете згенерувати одноразовий TGS, який ідеально відповідає політиці AD, часовим рамкам і даним PAC без відправлення нових AS/TGS-запитів.

### Sapphire-style PAC swaps (2025)

Нова варіація, іноді називана **sapphire ticket**, поєднує основу Diamond з «real TGT» та **S4U2self+U2U**, щоб викрасти привілейований PAC і вставити його у власний TGT. Замість вигадування додаткових SIDs ви запитуєте U2U S4U2self ticket для користувача з високими привілеями, де `sname` спрямований на запитувача з низькими привілеями; KRB_TGS_REQ несе TGT запитувача в `additional-tickets` і встановлює `ENC-TKT-IN-SKEY`, що дозволяє розшифрувати service ticket за допомогою ключа цього користувача. Потім ви витягуєте привілейований PAC і вшиваєте його в свій легітимний TGT перед перепідписанням ключем krbtgt.

Impacket's `ticketer.py` тепер підтримує sapphire через `-impersonate` + `-request` (обмін з KDC у реальному часі):
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` приймає ім'я користувача або SID; `-request` вимагає живі облікові дані користувача плюс матеріал ключа krbtgt (AES/NTLM) для розшифровки/правки квитків.

Ключові OPSEC-показники при використанні цього варіанту:

- TGS-REQ буде містити `ENC-TKT-IN-SKEY` та `additional-tickets` (TGT жертви) — рідкісне явище в нормальному трафіку.
- `sname` часто дорівнює користувачу, що робить запит (доступ самообслуговування), а Event ID 4769 показує викликача й ціль як той самий SPN/користувач.
- Очікуйте парні записи 4768/4769 з тим самим клієнтським комп'ютером, але різними CNAMES (запитувач з низькими привілеями проти власника PAC з підвищеними привілеями).

### OPSEC & нотатки щодо виявлення

- Традиційні евристики хантерів (TGS without AS, decade-long lifetimes) все ще застосовуються до golden tickets, але diamond tickets найчастіше спливають, коли **вміст PAC або відображення груп виглядає неможливим**. Заповнюйте всі поля PAC (logon hours, user profile paths, device IDs), щоб автоматичні порівняння не помітили підробку одразу.
- **Не додавати зайві групи/RIDs**. Якщо вам потрібні тільки `512` (Domain Admins) і `519` (Enterprise Admins), зупиніться на них і переконайтеся, що цільовий обліковий запис правдоподібно належить до цих груп в інших місцях AD. Зайве `ExtraSids` видає підробку.
- Sapphire-style swaps залишають U2U відбитки: `ENC-TKT-IN-SKEY` + `additional-tickets` плюс `sname`, що вказує на користувача (часто запитувача) у 4769, і подальший логон 4624, джерелом якого є підроблений квиток. Корелюйте ці поля замість того, щоб шукати лише пропуски no-AS-REQ.
- Microsoft почала відмовлятися від **RC4 service ticket issuance** через CVE-2026-20833; примусове використання лише AES etypes на KDC одночасно підвищує безпеку домену і відповідає інструментарію diamond/sapphire (/opsec вже примушує AES). Змішування RC4 у підроблені PAC дедалі більше виділятиметься.
- Проект Splunk Security Content розповсюджує телеметрію attack-range для diamond tickets разом із детекціями, такими як *Windows Domain Admin Impersonation Indicator*, який корелює незвичні послідовності Event ID 4768/4769/4624 і зміни груп у PAC. Відтворення цього набору даних (або генерація власного за командами вище) допомагає перевірити покриття SOC для T1558.001 і дає конкретну логіку тривог, яку можна використати для обходу виявлення.

## References

- [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
