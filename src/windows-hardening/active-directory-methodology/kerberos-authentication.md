# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

**Angalia chapisho la ajabu kutoka:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR kwa attackers
- Kerberos ni itifaki chaguo-msingi ya AD auth; chains nyingi za lateral-movement zitaigusa.
- Fikiria katika **hatua tatu za operator**:
- **AS-REQ / AS-REP** → password/hash/certificate kupata **TGT**. Hapa ndipo **AS-REP roasting**, **over-pass-the-hash / pass-the-key**, na **PKINIT** zipo.
- **TGS-REQ / TGS-REP** → tumia TGT kupata **service tickets**. Hapa ndipo **Kerberoasting**, **S4U abuse**, **delegation abuse**, na sehemu kubwa ya **ticket-forging tradecraft** huwa muhimu.
- **AP-REQ / AP-REP** → wasilisha ticket kwa service. Hapa ndipo **pass-the-ticket** na lateral movement maalum kwa service hutokea.
- Kwa cheatsheets za vitendo (AS-REP/Kerberoasting, ticket forgery, delegation abuse, n.k.) tazama:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Tumia ukurasa huu kama **muhtasari / faharasa ya “nini imebadilika hivi karibuni”**, kisha ruka kwenda kwa kurasa maalum za [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md), au [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Fresh attack notes (2024-2026)
- **RC4 hardening ilibadilisha defaults, si Kerberos yenyewe** – modern DC hardening inalenga **default assumed encryption types** kwa accounts ambazo **hazijaweka wazi** `msDS-SupportedEncryptionTypes`. Baada ya rollout ya 2026, accounts hizo zinazidi kuwa **AES-only** kwenye patched DCs, hivyo mawazo ya `/rc4` Kerberoast kwa upofu hufeli mara nyingi zaidi. Hata hivyo, **service accounts zilizowezeshwa wazi kwa RC4 bado ni targets bora sana za offline-crack**.
- **PAC validation enforcement ni muhimu kwa forged tickets** – 2024 PAC-signature hardening inamaanisha kwamba **golden/diamond/sapphire/extraSID-style abuses** zinahitaji PAC data halisi zaidi na signing context sahihi. Domains zisizopatchiwa au zile zilizoachwa kwenye compatibility/audit-style deployments hubaki targets laini zaidi.
- **Certificate-based Kerberos imebadilika mara mbili**:
- **Strong certificate binding** (KB5014754 timeline) inafanya sloppy certificate-to-account mappings kutegemewa kidogo zaidi katika mazingira yenye enforcement kamili.
- **CVE-2025-26647** iliongeza tabaka jingine la hardening karibu na **altSecID / SKI certificate mappings**. Ikiwa DCs hazijapatchiwa, bado ziko kwenye auditing, au zinapita wazi NTAuth validation, pass-the-certificate / shadow-credential follow-on abuse hubaki practical zaidi.
- **Cross-domain / cross-forest delegation abuse bado iko hai sana** – Windows inasaidia modern cross-realm **S4U2Self/S4U2Proxy** flows, hivyo writable delegation attributes kwenye domain nyingine bado ni valuable. Kikwazo kawaida ni tooling fidelity na trust/policy details, si support ya protocol.
- **Windows Server 2025 ilianzisha new Kerberos-adjacent attack surface** kupitia **dMSA** migration logic. Ukiona delegated rights juu ya OUs au service-account objects kwenye domain ya 2025, angalia ukurasa maalum wa [BadSuccessor page](acl-persistence-abuse/BadSuccessor.md) badala ya kuichukulia kama “just another gMSA”.

## Fast operator checks in modern domains

Kabla ya kuchagua Kerberos attack path, jibu haraka maswali manne:

1. **Ni accounts gani bado ni RC4-friendly?**
2. **Ni users gani hawahitaji pre-auth?**
3. **Ni objects gani zinaonyesha delegation abuse?**
4. **Ni sehemu gani za domain mpya vya kutosha kutekeleza hardening za hivi karibuni?**
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
Ufasiri wa vitendo:
- Ikiwa **interesting SPN accounts are explicitly RC4-capable**, Kerberoasting hubaki ya bei nafuu na ya haraka.
- Ikiwa akaunti nyingi za huduma hazina **explicit etype configuration**, tarajia tabia ya **AES-only** kwenye updated 2026 DCs na panga kwa ajili ya offline cracking ya polepole zaidi au njia tofauti.
- Ikiwa **RBCD / KCD / unconstrained delegation** ipo, S4U mara nyingi hushinda brute-force.
- Ikiwa **certificate auth** iko katika matumizi, kumbuka kuwa njia iliyoshindwa ya PKINIT haimaanishi **mara zote** kuwa cert haifai; katika mazingira mengi cert hiyo hiyo bado hufanya kazi kwa **Schannel/LDAPS** abuse (tazama [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Common Kerberos errors that change the attack plan
- **`KDC_ERR_ETYPE_NOTSUPP`** → Akaunti lengwa / DC haitatumia encryption type uliyoomba. Acha kujaribu tena kwa RC4 pekee; toa **AES keys** au omba roast material ya **AES** badala yake.
- **`KRB_AP_ERR_MODIFIED`** → Huenda una **wrong service key**, **wrong SPN**, au forged ticket ambayo haifanani na service account inayoi-decrypt kweli.
- **`KRB_AP_ERR_SKEW`** → Muda wako si sahihi. Sync na DC kabla ya kutatua chochote kingine.
- **`KDC_ERR_BADOPTION`** wakati wa S4U / delegation flows → mara nyingi humaanisha **sensitive/not-delegable users**, delegation model isiyo sahihi, au kuwa unajaribu kufanya **classic KCD** ambapo ni **RBCD** pekee ingeaccept non-forwardable S4U2Self ticket.

## References
- [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft Support - Latest Windows hardening guidance and key dates](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
{{#include ../../banners/hacktricks-training.md}}
