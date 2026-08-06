# Uendelevu wa Domain wa AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Huu ni muhtasari wa mbinu za uendelevu wa Domain zilizoshirikiwa katika [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Isome kwa maelezo zaidi.<sup>[[5]](#references)</sup>

## Kutengeneza Certificates kwa kutumia CA Certificates Zilizoibwa (Golden Certificate) - DPERSIST1

Unawezaje kutambua kwamba certificate ni CA certificate?

Inaweza kubainishwa kwamba certificate ni CA certificate ikiwa masharti kadhaa yametimizwa:<sup>[[5]](#references)</sup>

- Certificate imehifadhiwa kwenye CA server, huku private key yake ikilindwa na DPAPI ya mashine, au na hardware kama TPM/HSM ikiwa operating system inaunga mkono.
- Sehemu za Issuer na Subject za certificate zinafanana na distinguished name ya CA.
- Kiendelezi cha "CA Version" kinapatikana kwenye CA certificates pekee.
- Certificate haina sehemu za Extended Key Usage (EKU).

Ili kutoa private key ya certificate hii, kutumia zana ya `certsrv.msc` kwenye CA server ndiyo njia inayoungwa mkono kupitia GUI iliyojengewa ndani. Hata hivyo, certificate hii haitofautiani na nyingine zilizohifadhiwa ndani ya system; kwa hivyo, mbinu kama [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) zinaweza kutumika kwa ajili ya kuitoa.

Certificate na private key pia zinaweza kupatikana kwa kutumia Certipy kwa command ifuatayo:<sup>[[2]](#references)</sup>
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Baada ya kupata cheti cha CA na private key yake katika umbizo la `.pfx`, tools kama [ForgeCert](https://github.com/GhostPack/ForgeCert) zinaweza kutumika kutengeneza certificates halali:
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
> Mtumiaji anayelengwa kwa certificate forgery lazima awe active na aweze kufanya authentication katika Active Directory ili mchakato ufanikiwe. Kuforge certificate kwa accounts maalum kama krbtgt hakufai.

Hii forged certificate itakuwa **valid** hadi tarehe ya mwisho iliyoainishwa na **mradi tu root CA certificate iwe valid** (kwa kawaida kutoka **miaka 5 hadi 10+**). Pia ni valid kwa **machines**, hivyo ikiunganishwa na **S4U2Self**, mshambulizi anaweza **kudumisha persistence kwenye mashine yoyote ya domain** kwa muda wote ambao CA certificate ni valid.\
Zaidi ya hayo, **certificates zinazozalishwa** kwa kutumia njia hii **haziwezi kurevokiwa**, kwa kuwa CA haizijui.

### Operating under Strong Certificate Mapping Enforcement (2025+)

Tangu Februari 11, 2025 (baada ya kusambazwa kwa KB5014754), domain controllers hutumia **Full Enforcement** kwa certificate mappings kwa default. Kwa vitendo, hii inamaanisha forged certificates zako lazima ziwe na mojawapo ya yafuatayo:

- Ziwe na strong binding kwa target account (kwa mfano, SID security extension), au
- Ziambatane na strong, explicit mapping kwenye attribute ya `altSecurityIdentities` ya target object.<sup>[[1]](#references)</sup>

Njia ya kuaminika ya persistence ni kutengeneza forged certificate iliyounganishwa na Enterprise CA iliyoibwa, kisha kuongeza strong explicit mapping kwenye victim principal:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Vidokezo
- Ikiwa unaweza kutengeneza forged certificates zinazojumuisha SID security extension, zitaunganishwa implicitly hata chini ya Full Enforcement. Vinginevyo, pendelea strong mappings zilizo wazi. Angalia [account-persistence](account-persistence.md) kwa maelezo zaidi kuhusu mappings zilizo wazi.
- Revocation haiwasaidii defenders hapa: forged certificates hazijulikani kwenye CA database na hivyo haziwezi kurevokewa.

#### Forging inayoendana na Full-Enforcement (inayotambua SID)

Tooling iliyosasishwa hukuwezesha kuweka SID moja kwa moja, hivyo golden certificates zinaendelea kutumika hata wakati DCs zinakataa weak mappings:<sup>[[3]](#references)</sup>
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
Kwa kupachika SID unaepuka kulazimika kugusa `altSecurityIdentities`, ambayo inaweza kufuatiliwa, huku bado ukikidhi ukaguzi wa strong mapping.

## Kuamini Rogue CA Certificates - DPERSIST2

Object ya `NTAuthCertificates` imefafanuliwa kuwa na **CA certificates** moja au zaidi ndani ya attribute yake ya `cacertificate`, ambayo hutumiwa na Active Directory (AD). Mchakato wa uthibitishaji unaofanywa na **domain controller** unahusisha kukagua object ya `NTAuthCertificates` ili kupata ingizo linalolingana na **CA iliyobainishwa** kwenye sehemu ya Issuer ya **certificate** inayotumika kuthibitisha. Authentication inaendelea ikiwa ulinganifu utapatikana.<sup>[[5]](#references)</sup>

Certificate ya CA iliyojisaini yenyewe inaweza kuongezwa kwenye object ya `NTAuthCertificates` na attacker, iwapo ana udhibiti wa object hii ya AD. Kwa kawaida, ni washiriki wa kundi la **Enterprise Admin**, pamoja na **Domain Admins** au **Administrators** katika **forest root’s domain**, wanaopewa ruhusa ya kurekebisha object hii. Wanaweza kuhariri object ya `NTAuthCertificates` kwa kutumia `certutil.exe` na command `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, au kwa kutumia [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Commands nyingine muhimu kwa technique hii:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
Uwezo huu ni muhimu hasa unapotumiwa pamoja na method iliyoelezwa awali inayohusisha ForgeCert kwa kutengeneza certificates dynamically.

> Mazingatio ya mapping baada ya 2025: kuweka rogue CA katika NTAuth huanzisha tu trust katika issuing CA. Ili kutumia leaf certificates kwa logon wakati DCs ziko katika **Full Enforcement**, leaf lazima iwe na SID security extension au kuwe na strong explicit mapping kwenye target object (kwa mfano, Issuer+Serial katika `altSecurityIdentities`). Tazama {{#ref}}account-persistence.md{{#endref}}.

## Malicious Misconfiguration - DPERSIST3

Fursa za **persistence** kupitia **security descriptor modifications** za components za AD CS ni nyingi. Modifications zilizoelezwa katika sehemu ya "[Domain Escalation](domain-escalation.md)" zinaweza kutekelezwa kwa nia mbaya na attacker mwenye elevated access. Hii inajumuisha kuongeza "control rights" (kwa mfano, WriteOwner/WriteDACL/etc.) kwenye components nyeti kama vile:<sup>[[5]](#references)</sup>

- Object ya **AD computer** ya **CA server**
- **RPC/DCOM server** ya **CA server**
- **AD object au container** yoyote ya **descendant** katika **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (kwa mfano, Certificate Templates container, Certification Authorities container, NTAuthCertificates object, n.k.)
- **AD groups** zilizopewa rights za kudhibiti AD CS kwa default au na organization (kama vile built-in Cert Publishers group na wanachama wake wowote)

Mfano wa implementation yenye nia mbaya ungehusisha attacker, mwenye **elevated permissions** katika domain, akiongeza permission ya **`WriteOwner`** kwenye default **`User`** certificate template, huku attacker akiwa principal wa right hiyo. Ili kutumia hii, attacker angebadilisha kwanza ownership ya **`User`** template iwe yake. Baada ya hapo, **`mspki-certificate-name-flag`** ingewekwa kuwa **1** kwenye template ili kuwezesha **`ENROLLEE_SUPPLIES_SUBJECT`**, na kumruhusu user kutoa Subject Alternative Name katika request. Kisha attacker angeweza **enroll** kwa kutumia **template**, akichagua jina la **domain administrator** kama alternative name, na kutumia certificate iliyopatikana kwa authentication kama DA.

Practical knobs ambazo attackers wanaweza kuweka kwa ajili ya long-term domain persistence (tazama {{#ref}}domain-escalation.md{{#endref}} kwa maelezo kamili na detection):

- CA policy flags zinazoruhusu SAN kutoka kwa requesters (kwa mfano, kuwezesha `EDITF_ATTRIBUTESUBJECTALTNAME2`). Hii huacha paths zinazofanana na ESC1 zikiwa exploitable.
- Template DACL au settings zinazoruhusu issuance yenye uwezo wa authentication (kwa mfano, kuongeza Client Authentication EKU, kuwezesha `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Kudhibiti `NTAuthCertificates` object au CA containers ili kuendelea kuingiza tena rogue issuers ikiwa defenders watajaribu cleanup.

> [!TIP]
> Katika environments zilizo-harden baada ya KB5014754, kuunganisha misconfigurations hizi na explicit strong mappings (`altSecurityIdentities`) huhakikisha certificates zako ulizo-issue au ulizo-forge zinaendelea kutumika hata wakati DCs zinatekeleza strong mapping.

### Certificate renewal abuse (ESC14) kwa persistence

Ukicompromise certificate yenye uwezo wa authentication (au ya Enrollment Agent), unaweza **renew** hiyo certificate **indefinitely** mradi tu issuing template iendelee kuwa published na CA yako bado i-trust issuer chain. Renewal huhifadhi original identity bindings lakini huongeza validity, hivyo kufanya eviction kuwa ngumu isipokuwa template irekebishwe au CA ipublishwe tena.<sup>[[4]](#references)</sup>
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
Ikiwa domain controllers ziko katika **Full Enforcement**, ongeza `-sid <victim SID>` (au tumia template ambayo bado inajumuisha SID security extension) ili renewed leaf certificate iendelee kufanya mapping kwa nguvu bila kugusa `altSecurityIdentities`. Attackers walio na CA admin rights wanaweza pia kurekebisha `policy\RenewalValidityPeriodUnits` ili kuongeza muda wa validity wa certificates zinazorenew kabla ya kujitengenezea certificate.<sup>[[2]](#references)[[4]](#references)</sup>


## Marejeleo

- [1] [Microsoft KB5014754 – Mabadiliko ya certificate-based authentication kwenye Windows domain controllers (ratiba ya enforcement na strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [Certipy – Command Reference na matumizi ya forge/auth](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [3] [SpecterOps – Certify 2.0 (forge iliyounganishwa yenye SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [Muhtasari wa matumizi mabaya ya ESC14 renewal](https://www.adcs-security.com/attacks/esc14)
- [5] [SpecterOps – Certified Pre-Owned: Kutumia vibaya Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
