# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

**Перегляньте чудовий пост від:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR for attackers
- Kerberos is the default AD auth protocol; most lateral-movement chains will touch it.
- Think in **three operator phases**:
- **AS-REQ / AS-REP** → пароль/hash/сертифікат для отримання **TGT**. Тут живуть **AS-REP roasting**, **over-pass-the-hash / pass-the-key** і **PKINIT**.
- **TGS-REQ / TGS-REP** → використайте TGT для отримання **service tickets**. Тут стають актуальними **Kerberoasting**, **S4U abuse**, **delegation abuse** і більшість **ticket-forging tradecraft**.
- **AP-REQ / AP-REP** → пред’явіть ticket сервісу. Тут відбуваються **pass-the-ticket** і service-specific lateral movement.
- Для практичних cheatsheets (AS-REP/Kerberoasting, ticket forgery, delegation abuse, тощо) дивіться:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Використовуйте цю сторінку як **overview / “what changed recently”** index, а потім переходьте на окремі сторінки для [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md), або [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Fresh attack notes (2024-2026)
- **RC4 hardening changed the defaults, not Kerberos itself** – modern DC hardening focuses on the **default assumed encryption types** for accounts that do **not** explicitly set `msDS-SupportedEncryptionTypes`. After the 2026 rollout, those accounts increasingly default to **AES-only** on patched DCs, so blind `/rc4` Kerberoast assumptions fail more often. However, **explicitly RC4-enabled service accounts remain excellent offline-crack targets**.
- **PAC validation enforcement matters for forged tickets** – 2024 PAC-signature hardening means that **golden/diamond/sapphire/extraSID-style abuses** need more realistic PAC data and the correct signing context. Unpatched domains or domains left in compatibility/audit-style deployments stay softer targets.
- **Certificate-based Kerberos changed twice**:
- **Strong certificate binding** (KB5014754 timeline) makes sloppy certificate-to-account mappings less reliable in fully enforced environments.
- **CVE-2025-26647** added another hardening layer around **altSecID / SKI certificate mappings**. If DCs are unpatched, still auditing, or explicitly bypassing NTAuth validation, pass-the-certificate / shadow-credential follow-on abuse stays more practical.
- **Cross-domain / cross-forest delegation abuse is still very alive** – Windows supports modern cross-realm **S4U2Self/S4U2Proxy** flows, so writable delegation attributes in another domain are still valuable. The blocker is usually tooling fidelity and trust/policy details, not protocol support.
- **Windows Server 2025 introduced new Kerberos-adjacent attack surface** through **dMSA** migration logic. If you see delegated rights over OUs or service-account objects in a 2025 domain, check the dedicated [BadSuccessor page](acl-persistence-abuse/BadSuccessor.md) instead of treating it like “just another gMSA”.

## Fast operator checks in modern domains

Before choosing a Kerberos attack path, quickly answer four questions:

1. **Which accounts are still RC4-friendly?**
2. **Which users do not require pre-auth?**
3. **Which objects expose delegation abuse?**
4. **Which parts of the domain are new enough to enforce recent hardening?**
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
- Якщо **interesting SPN accounts явно підтримують RC4**, Kerberoasting лишається дешевим і швидким.
- Якщо більшість service accounts **не мають явної etype configuration**, очікуйте **AES-only** поведінку на оновлених 2026 DCs і плануйте повільніше offline cracking або інший шлях.
- Якщо присутні **RBCD / KCD / unconstrained delegation**, S4U часто ефективніший за brute-force.
- Якщо використовується **certificate auth**, пам’ятайте, що невдалий PKINIT path не завжди означає, що cert марний; у багатьох середовищах той самий cert і далі працює для **Schannel/LDAPS** abuse (див. [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Common Kerberos errors that change the attack plan
- **`KDC_ERR_ETYPE_NOTSUPP`** → Цільовий account / DC не використовуватиме encryption type, який ви запросили. Припиніть повтори лише з RC4; надайте **AES keys** або запитайте **AES** roast material замість цього.
- **`KRB_AP_ERR_MODIFIED`** → Ймовірно, у вас **не той service key**, **не той SPN**, або forged ticket, який не відповідає service account, що фактично його decrypting.
- **`KRB_AP_ERR_SKEW`** → У вас збитий час. Синхронізуйтеся з DC перед тим, як дебажити щось інше.
- **`KDC_ERR_BADOPTION`** під час S4U / delegation flows → часто означає **sensitive/not-delegable users**, неправильну delegation model, або що ви намагаєтеся використати **classic KCD**, тоді як лише **RBCD** прийняв би non-forwardable S4U2Self ticket.

## References
- [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft Support - Latest Windows hardening guidance and key dates](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
{{#include ../../banners/hacktricks-training.md}}
