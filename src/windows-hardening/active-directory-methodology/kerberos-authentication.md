# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

**Check the amazing post from:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR for attackers
- Kerberos is die verstek AD auth protocol; meeste lateral-movement kettings sal dit raak.
- Dink in **drie operatorfases**:
- **AS-REQ / AS-REP** → password/hash/certificate om 'n **TGT** te verkry. Dit is waar **AS-REP roasting**, **over-pass-the-hash / pass-the-key**, en **PKINIT** voorkom.
- **TGS-REQ / TGS-REP** → gebruik 'n TGT om **service tickets** te verkry. Dit is waar **Kerberoasting**, **S4U abuse**, **delegation abuse**, en die meeste **ticket-forging tradecraft** relevant word.
- **AP-REQ / AP-REP** → bied die ticket aan die diens. Dit is waar **pass-the-ticket** en diens-spesifieke lateral movement plaasvind.
- Vir praktiese cheatsheets (AS-REP/Kerberoasting, ticket forgery, delegation abuse, ens.) sien:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Gebruik hierdie bladsy as die **oorsig / “wat het onlangs verander”** indeks, en spring dan na die toegewyde bladsye vir [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md), of [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Fresh attack notes (2024-2026)
- **RC4 hardening het die verstekwaardes verander, nie Kerberos self nie** – moderne DC hardening fokus op die **default assumed encryption types** vir accounts wat nie `msDS-SupportedEncryptionTypes` uitdruklik stel nie. Ná die 2026-uitrol, val daardie accounts toenemend terug na **AES-only** op gepatchte DCs, so blinde `/rc4` Kerberoast-aannames mis meer dikwels. Maar **uitdruklik RC4-enabled service accounts bly uitstekende offline-crack teikens**.
- **PAC validation enforcement maak saak vir forged tickets** – 2024 PAC-signature hardening beteken dat **golden/diamond/sapphire/extraSID-style abuses** meer realistiese PAC-data en die korrekte signing context nodig het. Ongepatchte domains of domains wat in compatibility/audit-style deployments gelaat is, bly sagter teikens.
- **Certificate-based Kerberos het twee keer verander**:
- **Strong certificate binding** (KB5014754 tydlyn) maak slordige certificate-to-account mappings minder betroubaar in ten volle afgedwonge omgewings.
- **CVE-2025-26647** het nog 'n hardening layer rondom **altSecID / SKI certificate mappings** bygevoeg. As DCs ongepatch is, nog in auditing is, of NTAuth validation eksplisiet omseil, bly pass-the-certificate / shadow-credential follow-on abuse meer prakties.
- **Cross-domain / cross-forest delegation abuse is steeds baie lewendig** – Windows ondersteun moderne cross-realm **S4U2Self/S4U2Proxy** flows, so writable delegation attributes in 'n ander domain is steeds waardevol. Die blokkasie is gewoonlik tooling fidelity en trust/policy besonderhede, nie protocol support nie.
- **Windows Server 2025 het nuwe Kerberos-adjacent attack surface ingestel** deur **dMSA** migration logic. As jy delegated rights oor OUs of service-account objects in 'n 2025 domain sien, kyk na die toegewyde [BadSuccessor page](acl-persistence-abuse/BadSuccessor.md) eerder as om dit soos “net nog 'n gMSA” te behandel.

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
Praktiese interpretasie:
- As **interesting SPN accounts uitdruklik RC4-capable** is, bly Kerberoasting goedkoop en vinnig.
- As die meeste service accounts **geen eksplisiete etype configuration** het nie, verwag **AES-only** gedrag op opgedateerde 2026 DCs en beplan vir stadiger offline cracking of ’n ander roete.
- As **RBCD / KCD / unconstrained delegation** teenwoordig is, klop S4U dikwels brute-force.
- As **certificate auth** in spel is, onthou dat ’n mislukte PKINIT-pad nie **altyd** beteken die cert is nutteloos nie; in baie omgewings werk dieselfde cert steeds vir **Schannel/LDAPS** abuse (sien [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Common Kerberos errors that change the attack plan
- **`KDC_ERR_ETYPE_NOTSUPP`** → The target account / DC sal nie die encryption type gebruik wat jy gevra het nie. Hou op om net met RC4 te herprobeer; voorsien **AES keys** of versoek **AES** roast material in plaas daarvan.
- **`KRB_AP_ERR_MODIFIED`** → Jy het waarskynlik die **verkeerde service key**, die **verkeerde SPN**, of ’n forged ticket wat nie ooreenstem met die service account wat dit werklik dekripteer nie.
- **`KRB_AP_ERR_SKEW`** → Jou tyd is verkeerd. Sinkroniseer met die DC voordat jy enigiets anders debug.
- **`KDC_ERR_BADOPTION`** tydens S4U / delegation flows → beteken dikwels **sensitive/not-delegable users**, die verkeerde delegation model, of dat jy probeer om **classic KCD** te doen waar slegs **RBCD** ’n non-forwardable S4U2Self ticket sou aanvaar.

## References
- [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft Support - Latest Windows hardening guidance and key dates](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
{{#include ../../banners/hacktricks-training.md}}
