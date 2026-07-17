# Uthibitishaji wa Kerberos

{{#include ../../banners/hacktricks-training.md}}

**Angalia post hii nzuri kutoka:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR kwa attackers
- Kerberos ni default AD auth protocol; chains nyingi za lateral-movement zitahusisha Kerberos.
- Fikiria katika **awamu tatu za operator**:
- **AS-REQ / AS-REP** → tumia password/hash/certificate kupata **TGT**. Hapa ndipo **AS-REP roasting**, **over-pass-the-hash / pass-the-key**, na **PKINIT** hutumika.
- **TGS-REQ / TGS-REP** → tumia TGT kupata **service tickets**. Hapa ndipo **Kerberoasting**, **S4U abuse**, **delegation abuse**, na sehemu kubwa ya **ticket-forging tradecraft** huwa muhimu.
- **AP-REQ / AP-REP** → wasilisha ticket kwa service. Hapa ndipo **pass-the-ticket** na lateral movement inayolenga service hutokea.
- Kwa cheatsheets za vitendo (AS-REP/Kerberoasting, ticket forgery, delegation abuse, n.k.) angalia:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Tumia ukurasa huu kama index ya **muhtasari / “nini kimebadilika hivi karibuni”**, kisha nenda kwenye kurasa maalum za [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md), au [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Maelezo mapya ya mashambulizi (2024-2026)
- **RC4 hardening ilibadilisha defaults, si Kerberos yenyewe** – DC hardening ya kisasa inalenga **default assumed encryption types** za accounts ambazo **hazijaweka** `msDS-SupportedEncryptionTypes` waziwazi. Baada ya rollout ya 2026, accounts hizo zinazidi kuwa **AES-only** kwa patched DCs, hivyo assumptions za blind `/rc4` Kerberoast hushindwa mara nyingi zaidi. Hata hivyo, **service accounts zilizo-enable RC4 waziwazi bado ni targets bora za offline-crack**.
- **PAC validation enforcement ni muhimu kwa forged tickets** – PAC-signature hardening ya 2024 inamaanisha kuwa **golden/diamond/sapphire/extraSID-style abuses** zinahitaji PAC data yenye uhalisia zaidi na signing context sahihi. Domains ambazo hazijapatchiwa au zilizoachwa katika deployments za compatibility/audit-style hubaki targets laini zaidi.
- **Certificate-based Kerberos ilibadilika mara mbili**:
- **Strong certificate binding** (timeline ya KB5014754) hufanya certificate-to-account mappings zisizo sahihi zisiwe za kuaminika sana katika environments zilizo fully enforced.
- **CVE-2025-26647** iliongeza layer nyingine ya hardening inayohusu **altSecID / SKI certificate mappings**. Ikiwa DCs hazijapatchiwa, bado zina-audit, au zinapita NTAuth validation waziwazi, pass-the-certificate / shadow-credential follow-on abuse hubaki kuwa practical zaidi.
- **Cross-domain / cross-forest delegation abuse bado ipo sana** – Windows inasaidia flows za kisasa za cross-realm **S4U2Self/S4U2Proxy**, hivyo delegation attributes zinazoweza kuandikwa katika domain nyingine bado zina thamani. Kizuizi huwa tooling fidelity na trust/policy details, si support ya protocol.
- **Recursive multi-domain RBCD ni muhimu kiutendaji** – katika forests zenye domains 3 au zaidi, **S4U2Self/S4U2Proxy** inaweza kujirudia kupitia trust referrals, na **SPN-less** abuse inaweza kuhitaji hop ya mwisho ya **`S4U2Self+U2U`** pamoja na ticket handling inayotegemea RC4. Angalia [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).
- **Windows Server 2025 ilianzisha attack surface mpya iliyo karibu na Kerberos** kupitia logic ya dMSA migration. Ukiona delegated rights juu ya OUs au service-account objects katika domain ya 2025, angalia [BadSuccessor page](acl-persistence-abuse/BadSuccessor.md) maalum badala ya kuichukulia kama “gMSA nyingine tu”.

## Ukaguzi wa haraka wa operator katika domains za kisasa

Kabla ya kuchagua Kerberos attack path, jibu haraka maswali manne:

1. **Ni accounts zipi bado zinafaa kwa RC4?**
2. **Ni users gani hawahitaji pre-auth?**
3. **Ni objects zipi zinaonyesha delegation abuse?**
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
- Ikiwa **akaunti za SPN zinazovutia zina uwezo wa RC4 uliobainishwa wazi**, Kerberoasting hubaki nafuu na ya haraka.
- Ikiwa akaunti nyingi za huduma **hazina usanidi wa etype uliobainishwa wazi**, tarajia tabia ya **AES-only** kwenye DC zilizosasishwa za 2026 na panga kutumia offline cracking ya polepole zaidi au njia tofauti.
- Ikiwa **RBCD / KCD / unconstrained delegation** ipo, mara nyingi S4U huwa bora kuliko brute-force.
- Ikiwa **certificate auth** inatumika, kumbuka kuwa njia ya PKINIT iliyoshindwa **haimaanishi kila mara kuwa certificate haina manufaa**; katika mazingira mengi certificate hiyo hiyo bado hufanya kazi kwa matumizi mabaya ya **Schannel/LDAPS** (tazama [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Makosa ya kawaida ya Kerberos yanayobadilisha mpango wa shambulio
- **`KDC_ERR_ETYPE_NOTSUPP`** → Akaunti lengwa / DC haitatumia aina ya encryption uliyoomba. Acha kujaribu tena kwa RC4 pekee; toa **AES keys** au omba nyenzo ya roast ya **AES**.
- **`KRB_AP_ERR_MODIFIED`** → Huenda una **service key isiyo sahihi**, **SPN isiyo sahihi**, au ticket iliyoghushiwa ambayo hailingani na akaunti ya huduma inayoi-decrypt kwa kweli.
- **`KRB_AP_ERR_SKEW`** → Muda wa kifaa chako si sahihi. Synchronize na DC kabla ya kutatua tatizo lingine lolote.
- **`KDC_ERR_BADOPTION`** wakati wa mtiririko wa S4U / delegation → mara nyingi humaanisha **watumiaji nyeti/wasioruhusiwa kwa delegation**, modeli isiyo sahihi ya delegation, au kwamba unajaribu kutumia **classic KCD** ambapo ni **RBCD** pekee inayokubali ticket ya S4U2Self isiyo-forwardable.

## Marejeleo
- [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft Support - Latest Windows hardening guidance and key dates](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
{{#include ../../banners/hacktricks-training.md}}
