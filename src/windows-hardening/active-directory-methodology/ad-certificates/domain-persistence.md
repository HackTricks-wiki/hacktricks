# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Hii ni muhtasari wa mbinu za uendelevu wa domain zilizoshirikiwa katika [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Angalia kwa maelezo zaidi.

## Forging Certificates with Stolen CA Certificates (Golden Certificate) - DPERSIST1

Je, unaweza kutambua kuwa cheti ni cheti cha CA vipi?

Inaweza kubainika kuwa cheti ni cheti cha CA ikiwa masharti kadhaa yanakutana:

- Cheti kimehifadhiwa kwenye server ya CA, na ufunguo wake wa kibinafsi umehifadhiwa kwa DPAPI ya mashine, au kwa vifaa kama TPM/HSM ikiwa mfumo wa uendeshaji unaunga mkono.
- Sehemu za Issuer na Subject za cheti zinafanana na distinguished name ya CA.
- Upanuzi wa "CA Version" upo tu kwenye vyeti vya CA.
- Cheti hakina sehemu za Extended Key Usage (EKU).

Ili kutoa ufunguo wa kibinafsi wa cheti hiki, zana certsrv.msc kwenye server ya CA ndiyo njia inayotumika kupitia GUI iliyojengwa. Hata hivyo, cheti hiki hakitofautiani na vyeti vingine vilivyohifadhiwa ndani ya mfumo; kwa hivyo, mbinu kama [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) zinaweza kutumika kwa uchukuzi.

Cheti na ufunguo wa kibinafsi pia yanaweza kupatikana kwa kutumia Certipy na amri ifuatayo:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Baada ya kupata CA certificate na private key yake katika muundo wa `.pfx`, zana kama [ForgeCert](https://github.com/GhostPack/ForgeCert) zinaweza kutumika kuunda certificates halali:
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
> Mtumiaji aliyelengwa kwa certificate forgery lazima awe hai na aweze ku-authenticate katika Active Directory ili mchakato ufae. Forging a certificate kwa akaunti maalum kama krbtgt haina ufanisi.

This forged certificate itakuwa **valid** hadi tarehe ya mwisho iliyotajwa na kwa muda wote ambalo root CA certificate itakuwa **valid** (kwa kawaida kutoka miaka 5 hadi **10+ miaka**). Pia ni **valid** kwa **machines**, hivyo ikichanganywa na **S4U2Self**, mshambuliaji anaweza **maintain persistence on any domain machine** kwa muda wote ambao CA certificate ni valid.\
Zaidi ya hayo, the **certificates generated** kwa njia hii **cannot be revoked** kwa sababu CA haijui kuhusu hizo.

### Kuendesha chini ya Strong Certificate Mapping Enforcement (2025+)

Tangu Februari 11, 2025 (baada ya rollout ya KB5014754), domain controllers kwa default wanaset kwa **Full Enforcement** kwa certificate mappings. Kivitendo hili linamaanisha certificates zako za uongo lazima ziwe ama:

- Ziwe na binding imara kwa akaunti lengwa (kwa mfano, the SID security extension), au
- Ziwe zimeambatana na mapping thabiti, wazi kwenye attribute ya object lengwa `altSecurityIdentities`.

Njia ya kuaminika kwa persistence ni kutengeneza forged certificate iliyounganishwa kwa mnyororo na Enterprise CA iliyoporwa kisha kuongeza mapping thabiti, wazi kwa victim principal:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Vidokezo
- Ikiwa unaweza kutengeneza vyeti vya ubandia vinavyojumuisha SID security extension, vitatafsiriwa kwa njia ya kimfumo hata chini ya Full Enforcement. Vinginevyo, pendelea uwekaji wazi na wa nguvu (explicit strong mappings). Tazama [account-persistence](account-persistence.md) kwa zaidi kuhusu mappings wazi.
- Kufutwa (revocation) hakumsaidi walinzi hapa: vyeti vya ubandia havijulikani kwenye hifadhidata ya CA na kwa hivyo haviwezi kufutwa.

## Kuamini Vyeti haramu za CA - DPERSIST2

Object ya `NTAuthCertificates` imewekwa ili iambatanishe cheti moja au zaidi za **CA certificates** katika sifa yake ya `cacertificate`, ambazo Active Directory (AD) inazitumia. Mchakato wa uthibitisho unaofanywa na **domain controller** unajumuisha kukagua object ya `NTAuthCertificates` kwa kipengee kinacholingana na **CA specified** katika sehemu ya Issuer ya **certificate** inayothibitisha. Uthibitisho unaendelea kama mechi inapopatikana.

Cheti cha CA kilichojisaini mwenyewe kinaweza kuongezwa kwenye object ya `NTAuthCertificates` na mshambuliaji, mradi awe na udhibiti wa object hii ya AD. Kawaida, ni wanachama wa kikundi cha **Enterprise Admin**, pamoja na **Domain Admins** au **Administrators** katika **forest root’s domain**, ndio wanapewa ruhusa ya kubadilisha object hii. Wanaweza kuhariri object ya `NTAuthCertificates` kwa kutumia `certutil.exe` na amri `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, au kwa kutumia [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Amri za ziada zinazosaidia kwa tekniki hii:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
Uwezo huu unahusiana sana inapotumika pamoja na mbinu iliyotajwa awali inayohusisha ForgeCert kutengeneza vyeti kiotomatiki.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Malicious Misconfiguration - DPERSIST3

Fursa za **persistence** kupitia **security descriptor modifications of AD CS** kwenye vipengele ni nyingi. Marekebisho yaliyoelezewa katika sehemu ya "[Domain Escalation](domain-escalation.md)" yanaweza kutekelezwa kwa madhumuni mabaya na mshambuliaji mwenye ruhusa za juu katika domain. Hii inajumuisha kuongeza "control rights" (kwa mfano, `WriteOwner`/`WriteDACL`/n.k.) kwa vipengele nyeti kama:

- Kituo (object) cha **CA server’s AD computer**
- Kituo cha **CA server’s RPC/DCOM server**
- Kituo chochote cha **descendant AD object or container** ndani ya **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (kwa mfano, Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, n.k.)
- Vikundi vya AD ambavyo vimepewa haki za udhibiti wa **AD CS** kwa default au na shirika (kama vile built-in Cert Publishers group na wanachama wake wote)

Mfano wa utekelezaji wa uharifu utajumuisha mshambuliaji, ambaye ana **elevated permissions** katika domain, kuongeza ruhusa ya **`WriteOwner`** kwa template ya cheti ya default **`User`**, na mshambuliaji akiwa ndiye mtendaji wa haki hiyo. Ili kuitumia, mshambuliaji atabadilisha umiliki wa template ya **`User`** kuwa kwake mwenyewe. Baada ya hapo, **`mspki-certificate-name-flag`** itawekwa **1** kwenye template ili kuwezesha **`ENROLLEE_SUPPLIES_SUBJECT`**, ikiruhusu mtumiaji kutoa Subject Alternative Name katika ombi. Baadaye, mshambuliaji anaweza **enroll** akitumia **template**, kuchagua jina la **domain administrator** kama jina mbadala, na kutumia cheti kilichopatikana kwa uthibitishaji kama DA.

Vigezo vitendavyo ambavyo mashambulizi wanaweza kuweka kwa ajili ya long-term domain persistence (tazama {{#ref}}domain-escalation.md{{#endref}} kwa maelezo kamili na utambuzi):

- CA policy flags that allow SAN from requesters (e.g., enabling `EDITF_ATTRIBUTESUBJECTALTNAME2`). Hii inabaki kuruhusu njia kama ESC1 kutumiwa.
- Template DACL or settings that allow authentication-capable issuance (e.g., adding Client Authentication EKU, enabling `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Controlling the `NTAuthCertificates` object or the CA containers to continuously re-introduce rogue issuers if defenders attempt cleanup.

> [!TIP]
> Katika mazingira yaliyoteswa kwa uthabiti baada ya KB5014754, kuoanisha misconfiguration hizi na ramani thabiti za wazi (`altSecurityIdentities`) hakikisha vyeti ulivyotoa au vilivyoforgea vinabaki kutumika hata DCs zitakapotekeleza strong mapping.

## References

- Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
