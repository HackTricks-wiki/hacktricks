# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

Kwa maelezo ya kiwango cha protocol kuhusu mabadilishano yaliyoainishwa hapa chini, tazama makala ya Kerberos ya Tarlogic.<sup>[[3]](#references)</sup>

## TL;DR for attackers
- Kerberos ni protocol chaguo-msingi ya AD auth; minyororo mingi ya lateral-movement itaigusa.
- Fikiria katika **awamu tatu za operator**:<sup>[[3]](#references)</sup>
- **AS-REQ / AS-REP** → tumia password/hash/certificate kupata **TGT**. Hapa ndipo **AS-REP roasting**, **over-pass-the-hash / pass-the-key**, na **PKINIT** hutumika.
- **TGS-REQ / TGS-REP** → tumia TGT kupata **service tickets**. Hapa ndipo **Kerberoasting**, **S4U abuse**, **delegation abuse**, na mbinu nyingi za **ticket-forging** zinapohusika.
- **AP-REQ / AP-REP** → wasilisha ticket kwa service. Hapa ndipo **pass-the-ticket** na lateral movement maalum kwa service hufanyika.
- Kwa cheatsheets za vitendo (AS-REP/Kerberoasting, ticket forgery, delegation abuse, n.k.) tazama:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Tumia ukurasa huu kama index ya **muhtasari / “kilichobadilika hivi karibuni”**, kisha nenda kwenye kurasa maalum za [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md), au [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Maelezo mapya ya attacks (2024-2026)
- **RC4 hardening ilibadilisha defaults, si Kerberos yenyewe** – hardening ya kisasa ya DC inalenga **default assumed encryption types** za accounts ambazo **hazijaweka wazi** `msDS-SupportedEncryptionTypes`. Baada ya rollout ya 2026, accounts hizo zinazidi kutumia **AES-only** kwa default kwenye DCs zilizofanyiwa patch, hivyo makadirio ya kutumia `/rc4` kwa blind Kerberoast hushindwa mara nyingi zaidi. Hata hivyo, **service accounts zilizowezeshwa wazi kwa RC4 bado ni targets bora za offline-crack**.<sup>[[1]](#references)</sup>
- **PAC validation enforcement ni muhimu kwa forged tickets** – hardening ya PAC-signature ya 2024 inamaanisha kuwa **golden/diamond/sapphire/extraSID-style abuses** zinahitaji PAC data halisi zaidi na signing context sahihi. Domains ambazo hazijafanyiwa patch au zilizoachwa katika deployments za compatibility/audit-style hubaki targets dhaifu zaidi.<sup>[[2]](#references)</sup>
- **Certificate-based Kerberos ilibadilika mara mbili**:
- **Strong certificate binding** (ratiba ya KB5014754) hufanya certificate-to-account mappings zisizo makini zisiwe za kuaminika sana katika environments zilizowezeshwa enforcement kikamilifu.
- **CVE-2025-26647** iliongeza layer nyingine ya hardening kuhusu mappings za `altSecurityIdentities` zinazotumia Subject Key Identifier ya certificate. Kwa hiyo, patch level, enforcement au audit state, na explicit mapping configuration ni muhimu wakati wa kutathmini pass-the-certificate na paths nyingine zinazotegemea certificates.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup> Kwa PKINIT, KDC pia huthibitisha certificate path na hukagua kwamba issuer inaaminika kupitia NTAuth store.<sup>[[8]](#references)</sup>
- **Cross-domain / cross-forest delegation abuse bado iko hai sana** – Windows inasaidia flows za kisasa za cross-realm **S4U2Self/S4U2Proxy**, hivyo delegation attributes zinazoweza kuandikwa katika domain nyingine bado zina thamani. Kikwazo kwa kawaida huwa tooling fidelity na trust/policy details, si msaada wa protocol.
- **Recursive multi-domain RBCD ni muhimu kiutendaji** – katika forests zenye domains 3 au zaidi, **S4U2Self/S4U2Proxy** inaweza kujirudia kupitia trust referrals, na **SPN-less** abuse inaweza kuhitaji hop ya mwisho ya **`S4U2Self+U2U`** pamoja na ticket handling inayotegemea RC4. Tazama [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[4]](#references)</sup>
- **Windows Server 2025 ilianzisha delegated Managed Service Accounts (dMSAs)** na logic yake ya migration. Ukiona delegated rights juu ya OUs au service-account objects katika domain ya 2025, angalia [BadSuccessor page](acl-persistence-abuse/BadSuccessor.md) maalum badala ya kuichukulia kama “gMSA nyingine tu”.<sup>[[7]](#references)</sup>

## Ukaguzi wa haraka wa operator katika domains za kisasa

Kabla ya kuchagua path ya Kerberos attack, jibu haraka maswali manne:

1. **Ni accounts zipi bado zinaendana na RC4?**
2. **Ni users gani hawahitaji pre-auth?**
3. **Ni objects zipi zinaonyesha uwezekano wa delegation abuse?**
4. **Ni sehemu zipi za domain ni mpya vya kutosha kutekeleza hardening ya hivi karibuni?**
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
Tafsiri ya kiutendaji:
- Ikiwa **akaunti za SPN zinazovutia zimeruhusiwa wazi kutumia RC4**, Kerberoasting hubaki rahisi na ya haraka.
- Ikiwa akaunti nyingi za service **hazina usanidi wa etype uliowekwa wazi**, tarajia tabia ya **AES-only** kwenye DC zilizosasishwa za 2026 na jiandae kwa offline cracking ya polepole au njia nyingine.
- Ikiwa **RBCD / KCD / unconstrained delegation** ipo, S4U mara nyingi huwa bora kuliko brute-force.
- Ikiwa **certificate auth** inatumika, kumbuka kuwa kushindwa kwa njia ya PKINIT **hakumaanishi kila mara** kuwa cert haina manufaa; katika mazingira mengi cert hiyo hiyo bado hufanya kazi kwa matumizi mabaya ya **Schannel/LDAPS** (tazama [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Common Kerberos errors that change the attack plan
- **`KDC_ERR_ETYPE_NOTSUPP`** → Akaunti lengwa / DC haitatumia encryption type uliyoomba. Acha kujaribu tena kwa RC4 pekee; toa **AES keys** au omba roast material ya **AES**.
- **`KRB_AP_ERR_MODIFIED`** → Huenda una **service key isiyo sahihi**, **SPN isiyo sahihi**, au ticket iliyoghushiwa ambayo hailingani na service account inayoi-decrypt kwa kweli.
- **`KRB_AP_ERR_SKEW`** → Muda wa mfumo wako si sahihi. Synchronize na DC kabla ya kuchunguza jambo lingine.
- **`KDC_ERR_BADOPTION`** wakati wa mtiririko wa S4U / delegation → mara nyingi humaanisha **watumiaji nyeti/wasioruhusiwa delegation**, delegation model isiyo sahihi, au kwamba unajaribu kufanya **classic KCD** ambapo ni **RBCD** pekee inayoweza kukubali ticket ya S4U2Self isiyo-forwardable.

## References
- [1] [Microsoft Learn - Kugundua na kurekebisha matumizi ya RC4 katika Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [2] [Microsoft Support - Mwongozo wa hivi karibuni wa Windows hardening na tarehe muhimu](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
- [3] [Kerberos (I): Kerberos hufanyaje kazi? – Nadharia](https://www.tarlogic.com/en/blog/how-kerberos-works/)
- [4] [Synacktiv - Kutumia vibaya RBCD katika mazingira ya Cross-Domain na Cross-Forest: Sehemu ya 2](https://www.synacktiv.com/publications/exploiter-la-rbcd-en-environnements-cross-domain-cross-forest-partie-2)
- [5] [Microsoft Support - Mabadiliko ya certificate-based authentication ya KB5014754](https://support.microsoft.com/help/5014754)
- [6] [Microsoft - Udhaifu wa Kerberos certificate mapping wa CVE-2025-26647](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-26647)
- [7] [Microsoft Learn - Muhtasari wa Delegated Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [8] [Microsoft Learn - Mahitaji ya smart-card certificate na uthibitishaji wa KDC](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration)
{{#include ../../banners/hacktricks-training.md}}
