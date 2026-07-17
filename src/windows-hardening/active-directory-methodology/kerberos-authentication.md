# Автентифікація Kerberos

{{#include ../../banners/hacktricks-training.md}}

**Перегляньте чудовий допис:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR для атакерів
- Kerberos — стандартний протокол автентифікації AD; більшість ланцюжків lateral movement так чи інакше його використовують.
- Мисліть у **трьох операторських фазах**:
- **AS-REQ / AS-REP** → пароль/hash/certificate для отримання **TGT**. Саме тут застосовуються **AS-REP roasting**, **over-pass-the-hash / pass-the-key** і **PKINIT**.
- **TGS-REQ / TGS-REP** → використання TGT для отримання **service tickets**. Саме тут актуальні **Kerberoasting**, **S4U abuse**, **delegation abuse** і більшість **ticket-forging tradecraft**.
- **AP-REQ / AP-REP** → передача ticket сервісу. Саме тут відбуваються **pass-the-ticket** і lateral movement, специфічний для сервісу.
- Практичні cheatsheets (AS-REP/Kerberoasting, ticket forgery, delegation abuse тощо) дивіться тут:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Використовуйте цю сторінку як **оглядовий індекс / індекс «що змінилося нещодавно»**, а потім переходьте до окремих сторінок про [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [сертифікати AD / зловживання PKINIT](ad-certificates.md) або [BadSuccessor / зловживання dMSA](acl-persistence-abuse/BadSuccessor.md).

## Актуальні нотатки щодо атак (2024-2026)
- **RC4 hardening змінив defaults, але не сам Kerberos** — сучасне hardening DC зосереджене на **default assumed encryption types** для облікових записів, які **явно не задають `msDS-SupportedEncryptionTypes`**. Після rollout 2026 року такі облікові записи на patched DC дедалі частіше використовують **AES-only**, тому сліпі припущення щодо `/rc4` під час Kerberoast частіше виявляються хибними. Однак **явно RC4-enabled service accounts залишаються чудовими цілями для offline-crack**.
- **Примусова перевірка PAC важлива для forged tickets** — hardening підписів PAC у 2024 році означає, що **golden/diamond/sapphire/extraSID-style abuses** потребують реалістичніших даних PAC і правильного signing context. Unpatched domains або domains, у яких залишено compatibility/audit-style deployments, залишаються слабшими цілями.
- **Certificate-based Kerberos змінювався двічі**:
- **Strong certificate binding** (timeline KB5014754) робить недбалі certificate-to-account mappings менш надійними в повністю enforced environments.
- **CVE-2025-26647** додала ще один шар hardening для **altSecID / SKI certificate mappings**. Якщо DC не patched, усе ще працюють у режимі auditing або явно обходять NTAuth validation, подальше **pass-the-certificate / shadow-credential abuse** залишається практичнішим.
- **Cross-domain / cross-forest delegation abuse усе ще дуже актуальний** — Windows підтримує сучасні cross-realm **S4U2Self/S4U2Proxy** flows, тому writable delegation attributes в іншому домені залишаються цінними. Зазвичай перешкодою є fidelity інструментів і деталі trust/policy, а не підтримка протоколом.
- **Recursive multi-domain RBCD має операційне значення** — у forests із 3+ доменами **S4U2Self/S4U2Proxy** може рекурсивно проходити через trust referrals, а **SPN-less** abuse може потребувати фінального переходу **`S4U2Self+U2U`** і ticket handling, залежного від RC4. Дивіться [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).
- **Windows Server 2025 додав нову attack surface, пов’язану з Kerberos**, через логіку міграції **dMSA**. Якщо ви бачите delegated rights над OU або service-account objects у домені 2025 року, перевірте окрему [сторінку BadSuccessor](acl-persistence-abuse/BadSuccessor.md), а не сприймайте це як «ще один gMSA».

## Швидкі operator checks у сучасних доменах

Перед вибором шляху Kerberos attack швидко дайте відповідь на чотири запитання:

1. **Які облікові записи все ще RC4-friendly?**
2. **Для яких користувачів не потрібна pre-auth?**
3. **Які об’єкти відкривають можливості для delegation abuse?**
4. **Які частини домену достатньо нові, щоб застосовувати recent hardening?**
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
- Якщо **цікаві SPN-акаунти явно підтримують RC4**, Kerberoasting залишається дешевим і швидким.
- Якщо більшість service accounts **не мають явно заданої конфігурації etype**, на оновлених DC у 2026 році очікуйте поведінку **лише AES** і плануйте повільніший offline cracking або інший шлях.
- Якщо присутні **RBCD / KCD / unconstrained delegation**, S4U часто ефективніший за brute-force.
- Якщо використовується **certificate auth**, пам’ятайте: невдалий шлях PKINIT **не завжди означає**, що сертифікат марний; у багатьох середовищах той самий сертифікат усе ще працює для зловживань **Schannel/LDAPS** (див. [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Поширені помилки Kerberos, які змінюють план атаки
- **`KDC_ERR_ETYPE_NOTSUPP`** → Цільовий акаунт / DC не використовує запитаний вами тип шифрування. Припиніть повторні спроби лише з RC4; надайте **AES keys** або запитайте roast material для **AES**.
- **`KRB_AP_ERR_MODIFIED`** → Імовірно, у вас **неправильний service key**, **неправильний SPN** або forged ticket, який не відповідає service account, що фактично його розшифровує.
- **`KRB_AP_ERR_SKEW`** → Ваш час неправильний. Синхронізуйте його з DC, перш ніж налагоджувати щось інше.
- **`KDC_ERR_BADOPTION`** під час S4U / delegation flows → часто означає **sensitive/not-delegable users**, неправильну модель delegation або спробу виконати **classic KCD**, коли лише **RBCD** прийняв би non-forwardable S4U2Self ticket.

## References
- [Microsoft Learn - Виявлення та усунення використання RC4 у Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft Support - Актуальні рекомендації щодо hardening Windows і ключові дати](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
{{#include ../../banners/hacktricks-training.md}}
