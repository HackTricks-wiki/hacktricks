# Kerberos-verifikasie

{{#include ../../banners/hacktricks-training.md}}

Vir 'n protokolvlak-deurloop van die uitruilings wat hieronder opgesom word, sien Tarlogic se Kerberos-artikel.<sup>[[3]](#references)</sup>

## TL;DR vir aanvallers
- Kerberos is die verstek AD-verifikasieprotokol; die meeste lateral-movement-kettings sal daarmee te doen kry.
- Dink in **drie operatorfases**:<sup>[[3]](#references)</sup>
- **AS-REQ / AS-REP** → gebruik 'n wagwoord/hash/certificate om 'n **TGT** te verkry. Dit is waar **AS-REP roasting**, **over-pass-the-hash / pass-the-key**, en **PKINIT** voorkom.
- **TGS-REQ / TGS-REP** → gebruik 'n TGT om **service tickets** te verkry. Dit is waar **Kerberoasting**, **S4U abuse**, **delegation abuse**, en die meeste **ticket-forging tradecraft** relevant word.
- **AP-REQ / AP-REP** → bied die ticket aan die diens. Dit is waar **pass-the-ticket** en diensspesifieke lateral movement plaasvind.
- Vir praktiese cheatsheets (AS-REP/Kerberoasting, ticket forgery, delegation abuse, ens.) sien:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Gebruik hierdie bladsy as die **oorsig / “wat het onlangs verander”**-indeks, en gaan dan na die toegewyde bladsye vir [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md), of [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Nuwe aanvalnotas (2024-2026)
- **RC4-hardening het die verstekke verander, nie Kerberos self nie** – moderne DC-hardening fokus op die **verstek-aanvaarde encryption types** vir rekeninge wat nie eksplisiet `msDS-SupportedEncryptionTypes` stel nie. Ná die 2026-uitrol gebruik daardie rekeninge toenemend by verstek **AES-only** op gepatchte DC's, dus misluk blinde `/rc4` Kerberoast-aannames meer dikwels. Eksplisiet RC4-geaktiveerde diensrekeninge bly egter uitstekende teikens vir offline-cracking.<sup>[[1]](#references)</sup>
- **PAC-validasie-enforcement is belangrik vir forged tickets** – 2024 se PAC-signature-hardening beteken dat **golden/diamond/sapphire/extraSID-style abuses** meer realistiese PAC-data en die korrekte signing context benodig. Unpatched domains of domains wat in compatibility/audit-style deployments gelaat is, bly sagter teikens.<sup>[[2]](#references)</sup>
- **Certificate-based Kerberos het twee keer verander**:
- **Strong certificate binding** (KB5014754-tydlyn) maak slordige certificate-to-account mappings minder betroubaar in omgewings waar dit volledig afgedwing word.
- **CVE-2025-26647** het nog 'n hardening-laag bygevoeg rondom `altSecurityIdentities`-mappings wat 'n certificate se Subject Key Identifier gebruik. Patch level, enforcement- of audit-state, en eksplisiete mapping configuration is dus belangrik wanneer pass-the-certificate en verwante certificate-based paths geëvalueer word.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup> Vir PKINIT valideer die KDC ook die certificate path en kontroleer dit dat die issuer deur die NTAuth-store vertrou word.<sup>[[8]](#references)</sup>
- **Cross-domain / cross-forest delegation abuse is steeds baie aktueel** – Windows ondersteun moderne cross-realm **S4U2Self/S4U2Proxy**-flows, dus is skryfbare delegation attributes in 'n ander domain steeds waardevol. Die struikelblok is gewoonlik tooling fidelity en trust/policy details, nie protokolondersteuning nie.
- **Recursive multi-domain RBCD is operasioneel belangrik** – in forests met 3+ domains kan **S4U2Self/S4U2Proxy** deur trust referrals recurseer, en **SPN-less** abuse kan 'n finale **`S4U2Self+U2U`**-hop plus RC4-afhanklike ticket handling vereis. Sien [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[4]](#references)</sup>
- **Windows Server 2025 het delegated Managed Service Accounts (dMSAs)** en hul migration logic bekendgestel. As jy delegated rights oor OUs of service-account objects in 'n 2025-domain sien, kyk na die toegewyde [BadSuccessor-bladsy](acl-persistence-abuse/BadSuccessor.md) eerder as om dit soos “net nog 'n gMSA” te behandel.<sup>[[7]](#references)</sup>

## Vinnige operator-kontroles in moderne domains

Voordat jy 'n Kerberos-aanvalspad kies, beantwoord vinnig vier vrae:

1. **Watter rekeninge is steeds RC4-vriendelik?**
2. **Watter gebruikers vereis nie pre-auth nie?**
3. **Watter objects stel delegation abuse bloot?**
4. **Watter dele van die domain is nuut genoeg om onlangse hardening af te dwing?**
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
- As **interessante SPN-rekeninge uitdruklik RC4-capable is**, bly Kerberoasting goedkoop en vinnig.
- As die meeste diensrekeninge **geen uitdruklike etype-konfigurasie** het nie, verwag **AES-only**-gedrag op opgedateerde 2026 DCs en beplan vir stadiger offline cracking of ’n ander pad.
- As **RBCD / KCD / unconstrained delegation** teenwoordig is, oortref S4U dikwels brute-force.
- As **certificate auth** gebruik word, onthou dat ’n mislukte PKINIT-pad **nie altyd beteken dat die sertifikaat nutteloos is nie**; in baie omgewings werk dieselfde sertifikaat steeds vir **Schannel/LDAPS**-abuse (sien [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Algemene Kerberos-foute wat die aanvalplan verander
- **`KDC_ERR_ETYPE_NOTSUPP`** → Die teikenrekening / DC sal nie die encryption type gebruik waarvoor jy gevra het nie. Hou op om net met RC4 te herprobeer; verskaf **AES keys** of versoek eerder **AES** roast-materiaal.
- **`KRB_AP_ERR_MODIFIED`** → Jy het waarskynlik die **verkeerde service key**, die **verkeerde SPN**, of ’n vervalste ticket wat nie ooreenstem met die diensrekening wat dit werklik decrypt nie.
- **`KRB_AP_ERR_SKEW`** → Jou tyd is verkeerd. Sinkroniseer met die DC voordat jy enigiets anders debug.
- **`KDC_ERR_BADOPTION`** tydens S4U / delegation-flows → beteken dikwels **sensitive/not-delegable users**, die verkeerde delegation-model, of dat jy **classic KCD** probeer gebruik waar slegs **RBCD** ’n non-forwardable S4U2Self-ticket sal aanvaar.

## References
- [1] [Microsoft Learn - Bespeur en herstel RC4-gebruik in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [2] [Microsoft Support - Jongste Windows-hardeningriglyne en belangrike datums](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
- [3] [Kerberos (I): Hoe werk Kerberos? – Teorie](https://www.tarlogic.com/en/blog/how-kerberos-works/)
- [4] [Synacktiv - Uitbuiting van RBCD in Cross-Domain- en Cross-Forest-omgewings: Deel 2](https://www.synacktiv.com/publications/exploiter-la-rbcd-en-environnements-cross-domain-cross-forest-partie-2)
- [5] [Microsoft Support - KB5014754-veranderinge aan sertifikaatgebaseerde verifikasie](https://support.microsoft.com/help/5014754)
- [6] [Microsoft - CVE-2025-26647 Kerberos-sertifikaatkarteringskwesbaarheid](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-26647)
- [7] [Microsoft Learn - Oorsig van Delegated Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [8] [Microsoft Learn - Smart-card-sertifikaatvereistes en KDC-validasie](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration)
{{#include ../../banners/hacktricks-training.md}}
