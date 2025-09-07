# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Hii ni muhtasari wa mbinu za domain persistence zilizosambazwa katika [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Angalia kwa maelezo zaidi.

## Forging Certificates with Stolen CA Certificates - DPERSIST1

How can you tell that a certificate is a CA certificate?

Inaweza kubainika kuwa certificate ni CA certificate ikiwa masharti kadhaa yanatimiza:

- Certificate imehifadhiwa kwenye CA server, na private key yake imehifadhiwa kwa DPAPI ya mashine, au kwa hardware kama TPM/HSM ikiwa sistema ya uendeshaji inaunga mkono.
- Sehemu za Issuer na Subject za certificate zinaendana na distinguished name ya CA.
- Extension ya "CA Version" ipo tu katika CA certificates.
- Certificate haijumuishi Extended Key Usage (EKU) fields.

Ili kutoa private key ya certificate hii, zana certsrv.msc kwenye CA server ndiyo njia inayotambulika kupitia GUI iliyojengwa ndani. Hata hivyo, certificate hii haijatofautiana na nyingine zilizohifadhiwa ndani ya mfumo; kwa hivyo, mbinu kama [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) zinaweza kutumika kwa uondoaji.

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
> Mtumiaji aliyechaguliwa kwa udanganyifu wa vyeti lazima awe hai na aweze kujiuthibitisha katika Active Directory ili mchakato ufanikiwe. Kudanganya cheti kwa akaunti maalum kama krbtgt hakuwezi kufanya kazi.

Cheti hiki cha udanganyifu kitaendelea kuwa **halali** hadi tarehe ya mwisho iliyobainishwa na kwa muda **cheti cha root CA** kitakapoendelea kuwa halali (kwa kawaida kutoka miaka 5 hadi **miaka 10+**). Pia ni halali kwa ajili ya **mashine**, hivyo likiunganishwa na **S4U2Self**, mshambuliaji anaweza **kuendeleza persistence kwenye mashine yoyote ya domain** kwa muda wote cheti cha CA kitakapoendelea kuwa halali.\
Zaidi ya hayo, **vyeti vilivyotengenezwa** kwa njia hii **haiwezi kufutwa** kwa kuwa CA haijui kuhusu vyeti hivyo.

### Kufanya kazi chini ya Utekelezaji Mkali wa Ulinganifu wa Vyeti (2025+)

Tangu Februari 11, 2025 (baada ya rollout ya KB5014754), domain controllers kwa chaguo-msingi ziko kwenye **Full Enforcement** kwa certificate mappings. Kwa vitendo, hili lina maana vyeti vyako vilivyoofdanganywa vinapaswa ama:

- Kuwa na uunganisho thabiti na akaunti lengwa (kwa mfano, upanuzaji wa usalama wa SID), au
- Kuambatanishwa na ulinganifu thabiti, wazi kwenye attribute `altSecurityIdentities` ya objekti lengwa.

Njia ya kuaminika kwa ajili ya persistence ni kutengeneza cheti cha udanganyifu kilichounganishwa na Enterprise CA iliyotekwa kisha kuongeza ulinganifu thabiti, wazi kwa principal wa mwathirika:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Notes
- Ikiwa unaweza kutengeneza vyeti bandia vinavyojumuisha nyongeza ya usalama ya SID, vitafuatana kwa njia ya moja kwa moja hata chini ya Full Enforcement. Vinginevyo, pendelea mapangilio wazi na yenye nguvu. Angalia [account-persistence](account-persistence.md) kwa maelezo zaidi juu ya mapangilio ya wazi.
- Kufutwa hakusaidii watetezi hapa: vyeti bandia havijulikani katika hifadhidata ya CA na kwa hivyo haviwezi kufutwa.

## Kuamini Vyeti vya CA Visivyo Rasmi - DPERSIST2

Kiobjekti cha `NTAuthCertificates` kimefafanuliwa kuhusisha cheti kimoja au zaidi za **CA certificates** ndani ya sifa yake ya `cacertificate`, ambazo Active Directory (AD) hutumia. Mchakato wa uhakiki unaofanywa na **domain controller** unahusisha kuangalia kiobjekti cha `NTAuthCertificates` kwa kipengele kinacholingana na **CA specified** katika uwanja wa Issuer wa **certificate** inayothibitisha. Uthibitishaji utaendelea ikiwa mechi itapatikana.

Cheti cha CA chenye saini ya mwenyewe kinaweza kuongezwa kwenye kiobjekti cha `NTAuthCertificates` na mshambulizi, mradi awe na udhibiti wa kiobjekti hiki cha AD. Kwa kawaida, ni wanachama wa kikundi cha **Enterprise Admin**, pamoja na **Domain Admins** au **Administrators** katika **forest root’s domain**, wanaoruhusiwa kurekebisha kiobjekti hiki. Wanaweza kuhariri kiobjekti cha `NTAuthCertificates` kwa kutumia `certutil.exe` na amri `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, au kwa kutumia [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Additional helpful commands for this technique:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
Uwezo huu una umuhimu maalum unapotumika pamoja na mbinu iliyotajwa hapo awali inayohusisha ForgeCert kutengeneza vyeti kwa njia ya dinamiki.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Usanidi Mbaya - DPERSIST3

Fursa za **persistence** kupitia **urekebishaji wa security descriptor wa vipengele vya AD CS** ni nyingi. Marekebisho yaliyotajwa katika sehemu ya "[Domain Escalation](domain-escalation.md)" yanaweza kutekelezwa kwa nia mbaya na mdhambi mwenye upatikanaji uliopandishwa cheo. Hii inajumuisha kuongeza "control rights" (mfano, WriteOwner/WriteDACL/etc.) kwa vipengele nyeti kama:

- The **CA server’s AD computer** object
- The **CA server’s RPC/DCOM server**
- Any **descendant AD object or container** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (for instance, the Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, etc.)
- **AD groups delegated rights to control AD CS** by default or by the organization (such as the built-in Cert Publishers group and any of its members)

Mfano wa utekelezwaji wa uharifu ungehusisha mdhambi, aliye na **idhini za juu** ndani ya domain, kuongeza ruhusa ya **`WriteOwner`** kwenye template ya kawaida ya cheti ya **`User`**, akiwa yeye ndiye mhusika wa haki hiyo. Ili kuutumia huu, mdhambi atabadilisha kwanza umiliki wa template ya **`User`** kuwa yeye mwenyewe. Baadaye, **`mspki-certificate-name-flag`** itawekwa kuwa **1** kwenye template ili kuwezesha **`ENROLLEE_SUPPLIES_SUBJECT`**, ikimruhusu mtumiaji kutoa Subject Alternative Name katika ombi. Baadaye, mdhambi anaweza **kujisajili** kwa kutumia **template**, akichagua jina la **domain administrator** kama jina mbadala, na kutumia cheti kilichopatikana kwa uthibitisho kama DA.

Mipangilio ya vitendo wadukuzi wanaweza kuweka kwa kudumu ndani ya domain (angalia {{#ref}}domain-escalation.md{{#endref}} kwa maelezo kamili na utambuzi):

- CA policy flags that allow SAN from requesters (e.g., enabling `EDITF_ATTRIBUTESUBJECTALTNAME2`). This keeps ESC1-like paths exploitable.
- Template DACL or settings that allow authentication-capable issuance (e.g., adding Client Authentication EKU, enabling `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Controlling the `NTAuthCertificates` object or the CA containers to continuously re-introduce rogue issuers if defenders attempt cleanup.

> [!TIP]
> In hardened environments after KB5014754, pairing these misconfigurations with explicit strong mappings (`altSecurityIdentities`) ensures your issued or forged certificates remain usable even when DCs enforce strong mapping.

## References

- Microsoft KB5014754 – Mabadiliko ya certificate-based authentication kwenye Windows domain controllers (ratiba ya utekelezaji na strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
{{#include ../../../banners/hacktricks-training.md}}
