# Автентифікація Kerberos

{{#include ../../banners/hacktricks-training.md}}

Для покрокового перегляду обмінів на рівні протоколу, узагальнених нижче, див. статтю Tarlogic про Kerberos.<sup>[[3]](#references)</sup>

## TL;DR для атакувальників
- Kerberos є стандартним протоколом автентифікації AD; більшість ланцюжків lateral movement взаємодіятимуть із ним.
- Думайте про **три фази оператора**:<sup>[[3]](#references)</sup>
- **AS-REQ / AS-REP** → пароль/hash/сертифікат для отримання **TGT**. Саме тут застосовуються **AS-REP roasting**, **over-pass-the-hash / pass-the-key** і **PKINIT**.
- **TGS-REQ / TGS-REP** → використання TGT для отримання **service tickets**. Саме тут стають актуальними **Kerberoasting**, **S4U abuse**, **delegation abuse** і більшість практик **ticket-forging**.
- **AP-REQ / AP-REP** → передавання ticket службі. Саме тут відбуваються **pass-the-ticket** і lateral movement, специфічний для служби.
- Практичні cheatsheets (AS-REP/Kerberoasting, ticket forgery, delegation abuse тощо) див. тут:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Використовуйте цю сторінку як індекс **огляду / «що нещодавно змінилося»**, а потім переходьте до спеціалізованих сторінок [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md) або [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Нові нотатки щодо атак (2024-2026)
- **Посилення захисту RC4 змінило стандартні налаштування, а не сам Kerberos** — сучасне посилення захисту DC зосереджене на **типах шифрування, що використовуються за замовчуванням**, для облікових записів, які явно не встановлюють `msDS-SupportedEncryptionTypes`. Після розгортання змін у 2026 році такі облікові записи на patched DC дедалі частіше використовують **лише AES**, тому припущення про blind `/rc4` Kerberoast частіше виявляються хибними. Однак облікові записи служб із **явно ввімкненим RC4 залишаються чудовими цілями для offline-crack**.<sup>[[1]](#references)</sup>
- **Застосування перевірки PAC має значення для forged tickets** — посилення підписів PAC у 2024 році означає, що **golden/diamond/sapphire/extraSID-style abuses** потребують реалістичніших даних PAC і правильного контексту підписування. Непропатчені домени або домени, залишені в режимах сумісності чи аудиту, залишаються слабшими цілями.<sup>[[2]](#references)</sup>
- **Certificate-based Kerberos змінювався двічі**:
- **Strong certificate binding** (хронологія KB5014754) робить ненадійними недбалі certificate-to-account mappings у середовищах із повністю застосованими політиками.
- **CVE-2025-26647** додала ще один рівень захисту для mappings `altSecurityIdentities`, що використовують Subject Key Identifier сертифіката. Тому під час оцінювання pass-the-certificate та пов’язаних certificate-based шляхів важливі рівень patching, стан enforcement або audit, а також явна конфігурація mapping.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup> Для PKINIT KDC також перевіряє certificate path і те, що issuer є довіреним через NTAuth store.<sup>[[8]](#references)</sup>
- **Зловживання cross-domain / cross-forest delegation усе ще дуже актуальне** — Windows підтримує сучасні cross-realm потоки **S4U2Self/S4U2Proxy**, тому доступні для запису delegation attributes в іншому домені все ще мають високу цінність. Зазвичай перешкодою є точність tooling та деталі trust/policy, а не підтримка протоколом.
- **Recursive multi-domain RBCD має операційне значення** — у лісах із 3+ доменами **S4U2Self/S4U2Proxy** може рекурсивно проходити через trust referrals, а **SPN-less** abuse може вимагати фінального переходу **`S4U2Self+U2U`** і ticket handling, залежного від RC4. Див. [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[4]](#references)</sup>
- **Windows Server 2025 представив delegated Managed Service Accounts (dMSAs)** та логіку їхньої міграції. Якщо в домені 2025 року ви бачите delegated rights для OU або об’єктів service accounts, перевірте спеціальну [сторінку BadSuccessor](acl-persistence-abuse/BadSuccessor.md), а не сприймайте це як «ще один gMSA».<sup>[[7]](#references)</sup>

## Швидкі перевірки оператора в сучасних доменах

Перш ніж обирати шлях атаки Kerberos, швидко дайте відповідь на чотири запитання:

1. **Які облікові записи все ще сумісні з RC4?**
2. **Які користувачі не вимагають pre-auth?**
3. **Які об’єкти відкривають можливості для delegation abuse?**
4. **Які частини домену достатньо нові, щоб застосовувати нещодавні посилення захисту?**
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
- Якщо більшість сервісних облікових записів **не мають явної конфігурації etype**, на оновлених DC 2026 року очікуйте поведінку **лише AES** і плануйте повільніший offline cracking або інший шлях.
- Якщо присутні **RBCD / KCD / unconstrained delegation**, S4U часто ефективніший за brute-force.
- Якщо використовується **certificate auth**, пам’ятайте: невдалий шлях PKINIT **не завжди** означає, що сертифікат непридатний; у багатьох середовищах той самий сертифікат усе ще працює для зловживань **Schannel/LDAPS** (див. [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Common Kerberos errors that change the attack plan
- **`KDC_ERR_ETYPE_NOTSUPP`** → Цільовий обліковий запис / DC не використовуватиме запитаний вами тип шифрування. Припиніть повторні спроби лише з RC4; надайте **AES keys** або запитайте матеріал для roast з **AES**.
- **`KRB_AP_ERR_MODIFIED`** → Імовірно, у вас **неправильний service key**, **неправильний SPN** або forged ticket, який не відповідає сервісному обліковому запису, що фактично його розшифровує.
- **`KRB_AP_ERR_SKEW`** → Ваш час неправильний. Синхронізуйте його з DC, перш ніж налагоджувати щось інше.
- **`KDC_ERR_BADOPTION`** під час потоків S4U / delegation → часто означає **sensitive/not-delegable users**, неправильну delegation model або спробу виконати **classic KCD**, коли лише **RBCD** прийняв би non-forwardable S4U2Self ticket.

## References
- [1] [Microsoft Learn - Виявлення та усунення використання RC4 у Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [2] [Microsoft Support - Актуальні рекомендації щодо hardening Windows і ключові дати](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
- [3] [Kerberos (I): Як працює Kerberos? – Теорія](https://www.tarlogic.com/en/blog/how-kerberos-works/)
- [4] [Synacktiv - Експлуатація RBCD у Cross-Domain і Cross-Forest середовищах: частина 2](https://www.synacktiv.com/publications/exploiter-la-rbcd-en-environnements-cross-domain-cross-forest-partie-2)
- [5] [Microsoft Support - Зміни certificate-based authentication у KB5014754](https://support.microsoft.com/help/5014754)
- [6] [Microsoft - Вразливість зіставлення сертифікатів Kerberos CVE-2025-26647](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-26647)
- [7] [Microsoft Learn - Огляд Delegated Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [8] [Microsoft Learn - Вимоги до сертифікатів Smart Card і перевірка KDC](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration)
{{#include ../../banners/hacktricks-training.md}}
