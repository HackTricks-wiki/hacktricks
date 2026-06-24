# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

**Pogledajte sjajan post od:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR for attackers
- Kerberos je podrazumevani AD auth protokol; većina lateral-movement lanaca će ga dodirnuti.
- Razmišljajte u **tri operator faze**:
- **AS-REQ / AS-REP** → password/hash/certificate za dobijanje **TGT**. Ovde se nalaze **AS-REP roasting**, **over-pass-the-hash / pass-the-key**, i **PKINIT**.
- **TGS-REQ / TGS-REP** → koristite TGT za dobijanje **service tickets**. Ovde su relevantni **Kerberoasting**, **S4U abuse**, **delegation abuse**, i većina **ticket-forging tradecraft**.
- **AP-REQ / AP-REP** → predstavite ticket servisu. Ovde se dešava **pass-the-ticket** i service-specific lateral movement.
- Za praktične cheatsheets (AS-REP/Kerberoasting, ticket forgery, delegation abuse, itd.) pogledajte:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Koristite ovu stranicu kao **pregled / indeks “šta se nedavno promenilo”**, a zatim pređite na posebne stranice za [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md), ili [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

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
Praktično tumačenje:
- Ako su **zanimljivi SPN nalozi eksplicitno RC4-capable**, Kerberoasting ostaje jeftin i brz.
- Ako većina service naloga nema **eksplicitnu etype konfiguraciju**, očekuj **AES-only** ponašanje na ažuriranim 2026 DCs i planiraj sporije offline cracking ili drugi put.
- Ako je prisutan **RBCD / KCD / unconstrained delegation**, S4U često pobeđuje brute-force.
- Ako je **certificate auth** u igri, imaj na umu da neuspešan PKINIT path ne znači **uvek** da je cert beskoristan; u mnogim okruženjima isti cert i dalje radi za **Schannel/LDAPS** abuse (vidi [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Common Kerberos errors that change the attack plan
- **`KDC_ERR_ETYPE_NOTSUPP`** → Ciljni nalog / DC neće koristiti encryption type koji si tražio. Prestani da ponavljaš samo sa RC4; umesto toga obezbedi **AES keys** ili zatraži **AES** roast material.
- **`KRB_AP_ERR_MODIFIED`** → Verovatno imaš **pogrešan service key**, **pogrešan SPN**, ili forged ticket koji se ne poklapa sa service nalogom koji ga zapravo decryptuje.
- **`KRB_AP_ERR_SKEW`** → Tvoje vreme nije sinhronizovano. Sinkronizuj se sa DC pre nego što bilo šta drugo debaguješ.
- **`KDC_ERR_BADOPTION`** tokom S4U / delegation flow-ova → često znači **sensitive/not-delegable users**, pogrešan model delegacije, ili da pokušavaš da radiš **classic KCD** tamo gde bi samo **RBCD** prihvatio non-forwardable S4U2Self ticket.

## References
- [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft Support - Latest Windows hardening guidance and key dates](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
{{#include ../../banners/hacktricks-training.md}}
