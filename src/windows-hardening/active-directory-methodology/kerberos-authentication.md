# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

**Перевірте цей чудовий допис:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)<sup>[[3]](#references)</sup>

## TL;DR для атакерів
- Kerberos є протоколом auth за замовчуванням в AD; більшість ланцюжків lateral movement взаємодіятиме з ним.
- Думайте про **три фази оператора**:<sup>[[3]](#references)</sup>
- **AS-REQ / AS-REP** → пароль/hash/certificate для отримання **TGT**. Саме тут працюють **AS-REP roasting**, **over-pass-the-hash / pass-the-key** і **PKINIT**.
- **TGS-REQ / TGS-REP** → використання TGT для отримання **service tickets**. Саме тут актуальні **Kerberoasting**, **S4U abuse**, **delegation abuse** і більшість **ticket-forging tradecraft**.
- **AP-REQ / AP-REP** → передача ticket сервісу. Саме тут відбуваються **pass-the-ticket** і специфічний для сервісу lateral movement.
- Практичні cheatsheets (AS-REP/Kerberoasting, ticket forgery, delegation abuse тощо) див.:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Використовуйте цю сторінку як **оглядовий індекс / індекс “що змінилося останнім часом”**, а потім переходьте до спеціалізованих сторінок [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md) або [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Актуальні нотатки щодо атак (2024-2026)
- **RC4 hardening змінив значення за замовчуванням, а не сам Kerberos** – сучасне hardening DC зосереджене на **типах шифрування, які передбачаються за замовчуванням**, для облікових записів, що **явно не встановлюють** `msDS-SupportedEncryptionTypes`. Після rollout 2026 року такі облікові записи на пропатчених DC дедалі частіше використовують **лише AES** за замовчуванням, тому сліпі припущення про Kerberoast із `/rc4` частіше виявляються хибними. Однак **явно увімкнені для RC4 service accounts залишаються чудовими цілями для offline crack**.<sup>[[1]](#references)</sup>
- **Примусова перевірка PAC важлива для forged tickets** – hardening підписів PAC у 2024 році означає, що **golden/diamond/sapphire/extraSID-style abuses** потребують реалістичніших даних PAC і правильного контексту підпису. Непропатчені домени або домени, у яких залишено compatibility/audit-style deployments, залишаються більш уразливими цілями.<sup>[[2]](#references)</sup>
- **Certificate-based Kerberos змінювався двічі**:<sup>[[2]](#references)</sup>
- **Strong certificate binding** (таймлайн KB5014754) робить недбалі certificate-to-account mappings менш надійними в повністю примусових середовищах.
- **CVE-2025-26647** додала ще один рівень hardening навколо **altSecID / SKI certificate mappings**. Якщо DC не пропатчені, усе ще працюють у режимі auditing або явно обходять перевірку NTAuth, подальше зловживання pass-the-certificate / shadow-credential залишається практичнішим.
- **Зловживання cross-domain / cross-forest delegation усе ще дуже актуальне** – Windows підтримує сучасні cross-realm потоки **S4U2Self/S4U2Proxy**, тому атрибути delegation, доступні для запису в іншому домені, усе ще цінні. Перешкодою зазвичай є точність роботи tooling і деталі trust/policy, а не підтримка протоколу.
- **Рекурсивний multi-domain RBCD має операційне значення** – у лісах із 3+ доменами **S4U2Self/S4U2Proxy** може рекурсивно проходити через trust referrals, а **SPN-less** abuse може вимагати фінального переходу **`S4U2Self+U2U`** разом із ticket handling, залежним від RC4. Див. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[4]](#references)</sup>
- **Windows Server 2025 додала нову Kerberos-adjacent attack surface** через логіку міграції **dMSA**. Якщо ви бачите delegated rights над OU або об’єктами service accounts у домені 2025 року, перевірте спеціальну [BadSuccessor page](acl-persistence-abuse/BadSuccessor.md), а не вважайте це “ще однією gMSA”.

## Швидкі перевірки оператора в сучасних доменах

Перед вибором шляху Kerberos attack швидко дайте відповідь на чотири запитання:

1. **Які облікові записи все ще дружні до RC4?**
2. **Які користувачі не вимагають pre-auth?**
3. **Які об’єкти відкривають можливості delegation abuse?**
4. **Які частини домену достатньо нові, щоб забезпечувати актуальний hardening?**
```powershell
# 1) Service accounts explicitly pinned to RC4 / legacy etypes
Get-ADObject -LDAPFilter '(|(msDS-SupportedEncryptionTypes=4)(msDS-SupportedEncryptionTypes=12))' \
-Properties samAccountName,servicePrincipalName,msDS-SupportedEncryptionTypes

# 2) Service accounts with no explicit etype config
#    (these increasingly inherit AES-only defaults on patched 2026 DCs)
Get-ADObject -LDAPFilter '(&(servicePrincipalName=*)(!(msDS-SupportedEncryptionTypes=*)))' \
-Properties samAccountName,servicePrincipalName

# 3) AS-REP roastable users
Get-ADUser -LDAPFilter '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' \
-Properties userAccountControl

# 4) Delegation hot spots
Get-ADComputer -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' \
-Properties msDS-AllowedToActOnBehalfOfOtherIdentity
Get-ADObject -LDAPFilter '(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216))' \
-Properties samAccountName,servicePrincipalName,userAccountControl

# 5) DC-side RC4 hardening / compatibility clues
Get-WinEvent -LogName System | Where-Object {
$_.ProviderName -eq 'Microsoft-Windows-Kerberos-Key-Distribution-Center' -and $_.Id -in 201..209
}
```
Практична інтерпретація:
- Якщо **цікаві облікові записи SPN явно підтримують RC4**, Kerberoasting залишається дешевим і швидким.
- Якщо більшість сервісних облікових записів **не мають явної конфігурації etype**, очікуйте поведінку **лише AES** на оновлених DC 2026 року та плануйте повільніший offline cracking або інший шлях.
- Якщо присутні **RBCD / KCD / unconstrained delegation**, S4U часто ефективніший за brute-force.
- Якщо використовується **certificate auth**, пам’ятайте: невдалий шлях PKINIT **не завжди** означає, що сертифікат марний; у багатьох середовищах той самий сертифікат усе ще працює для зловживань **Schannel/LDAPS** (див. [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Поширені помилки Kerberos, які змінюють план атаки
- **`KDC_ERR_ETYPE_NOTSUPP`** → Цільовий обліковий запис / DC не використовуватиме запитаний вами тип шифрування. Припиніть повторні спроби лише з RC4; надайте **AES keys** або запитайте roast material для **AES**.
- **`KRB_AP_ERR_MODIFIED`** → Імовірно, у вас **неправильний service key**, **неправильний SPN** або forged ticket, який не відповідає сервісному обліковому запису, що фактично його розшифровує.
- **`KRB_AP_ERR_SKEW`** → Ваш час неправильний. Синхронізуйтеся з DC, перш ніж налагоджувати щось інше.
- **`KDC_ERR_BADOPTION`** під час потоків S4U / delegation → часто означає **sensitive/not-delegable users**, неправильну модель delegation або спробу виконати **classic KCD**, тоді як лише **RBCD** прийняв би non-forwardable S4U2Self ticket.

## Посилання
- [1] [Microsoft Learn - Виявлення та усунення використання RC4 у Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [2] [Microsoft Support - Актуальні рекомендації щодо hardening Windows і ключові дати](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
- [3] [Kerberos (I): Як працює Kerberos? – Теорія](https://www.tarlogic.com/en/blog/how-kerberos-works/)
- [4] [Synacktiv - Експлуатація RBCD у Cross-Domain і Cross-Forest середовищах: частина 2](https://www.synacktiv.com/publications/exploiter-la-rbcd-en-environnements-cross-domain-cross-forest-partie-2)

{{#include ../../banners/hacktricks-training.md}}
