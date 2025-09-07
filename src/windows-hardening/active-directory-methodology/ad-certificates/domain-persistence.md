# AD CS Domein-persistensie

{{#include ../../../banners/hacktricks-training.md}}

**Hierdie is 'n samevatting van die domein-persistensie-tegnieke gedeel in [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Raadpleeg dit vir verdere besonderhede.

## Forging Certificates with Stolen CA Certificates - DPERSIST1

How can you tell that a certificate is a CA certificate?

Dit kan bepaal word dat 'n sertifikaat 'n CA-sertifikaat is indien verskeie voorwaardes nagekom word:

- Die sertifikaat is op die CA-server gestoor, met sy privaat sleutel beveilig deur die masjien se DPAPI, of deur hardeware soos 'n TPM/HSM indien die bedryfstelsel dit ondersteun.
- Beide die Issuer en Subject velde van die sertifikaat stem ooreen met die distinguished name van die CA.
- 'n "CA Version" uitbreiding kom slegs in die CA-sertifikate voor.
- Die sertifikaat het nie Extended Key Usage (EKU)-velde nie.

Om die privaat sleutel van hierdie sertifikaat te onttrek, is die certsrv.msc-instrument op die CA-server die ondersteunde metode via die ingeboude GUI. Nietemin verskil hierdie sertifikaat nie van ander wat in die stelsel gestoor is nie; dus kan metodes soos die THEFT2 technique toegepas word vir onttrekking.

Die sertifikaat en privaat sleutel kan ook verkry word met Certipy met die volgende opdrag:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Sodra jy die CA-sertifikaat en sy privaat sleutel in `.pfx`-formaat bekom het, kan gereedskap soos [ForgeCert](https://github.com/GhostPack/ForgeCert) gebruik word om geldige sertifikate te genereer:
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
> Die gebruiker wat geteiken word vir sertifikaatvervalsing moet aktief wees en in staat wees om in Active Directory te autentiseer sodat die proses kan slaag. Om 'n sertifikaat te vervals vir spesiale rekeninge soos krbtgt is ondoeltreffend.

Hierdie vervalste sertifikaat sal **geldig** wees tot die gespesifiseerde einddatum en so **lank as wat die root CA sertifikaat geldig is** (gewoonlik 5 tot **10+ jaar**). Dit is ook geldig vir **masjiene**, dus gekombineer met **S4U2Self**, kan 'n aanvaller **persistentie op enige domeinmasjien handhaaf** so lank as wat die CA-sertifikaat geldig is.\
Boonop kan die **sertifikate wat met hierdie metode gegenereer word** **nie ingetrek word nie**, aangesien die CA nie daarvan bewus is nie.

### Werking onder sterk afdwinging van sertifikaatmappings (2025+)

Sinds 11 Februarie 2025 (na die uitrol van KB5014754), stel domeinkontroleerders standaard in op **Full Enforcement** vir sertifikaatmappings. In praktyk beteken dit jou vervalste sertifikate moet óf:

- Insluit 'n sterk binding aan die geteikende rekening (byvoorbeeld die SID security extension), of
- Gepaard wees met 'n sterk, eksplisiete mapping op die teikenvoorwerp se `altSecurityIdentities` attribuut.

'n Betroubare benadering vir persistentie is om 'n vervalste sertifikaat uit te reik wat gekoppel is aan die gesteelde Enterprise CA en dan 'n sterk, eksplisiete mapping by die slagoffer principal te voeg:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Aantekeninge
- If you can craft forged certificates that include the SID security extension, those will map implicitly even under Full Enforcement. Otherwise, prefer explicit strong mappings. See
[account-persistence](account-persistence.md) for more on explicit mappings.
- Herroeping help verdedigers hier nie: vervalste sertifikate is onbekend aan die CA-database en kan dus nie herroep word nie.

## Vertrou Rogue CA Certificates - DPERSIST2

Die `NTAuthCertificates` object is gedefinieer om een of meer **CA certificates** te bevat in sy `cacertificate`-attribuut, wat Active Directory (AD) gebruik. Die verifikasiëproses deur die **domain controller** behels die kontrole van die `NTAuthCertificates` object vir 'n inskrywing wat ooreenstem met die **CA specified** in die Issuer-veld van die autentiserende **certificate**. Autentisering gaan voort as 'n ooreenstemming gevind word.

'N self-ondertekende CA-sertifikaat kan by die `NTAuthCertificates`-object gevoeg word deur 'n aanvaller, mits hulle beheer oor hierdie AD-voorwerp het. Gewoonlik is dit slegs lede van die **Enterprise Admin** groep, tesame met **Domain Admins** of **Administrators** in die **forest root’s domain**, wat toestemming het om hierdie voorwerp te wysig. Hulle kan die `NTAuthCertificates` object wysig met `certutil.exe` deur die opdrag `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` te gebruik, of deur die [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) te gebruik.

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
Hierdie vermoë is veral relevant wanneer dit saam met 'n vooraf uiteengesette metode gebruik word wat ForgeCert insluit om sertifikate dinamies te genereer.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Malicious Misconfiguration - DPERSIST3

Geleenthede vir **persistence** deur **security descriptor**-wysigings van AD CS-komponente is volop. Wysigings wat in die "[Domain Escalation](domain-escalation.md)" afdeling beskryf word, kan kwaadwillig deur 'n aanvaller met verhoogde toegang geïmplementeer word. Dit sluit die toevoeging van "control rights" (bv. WriteOwner/WriteDACL/etc.) by sensitiewe komponente in, soos:

- Die **CA server’s AD computer** object
- Die **CA server’s RPC/DCOM server**
- Enige **descendant AD object or container** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (byvoorbeeld, die Certificate Templates container, Certification Authorities container, die NTAuthCertificates object, ens.)
- **AD groups delegated rights to control AD CS** standaard of deur die organisasie (soos die ingeboude Cert Publishers group en enige van sy lede)

'n Voorbeeld van 'n kwaadwillige implementering sou behels dat 'n aanvaller, wat **elevated permissions** in die domein het, die **`WriteOwner`**-permit by die verstek **`User`**-sertifikaatsjabloon voeg, met die aanvaller as die principal vir daardie reg. Om dit uit te buit, sou die aanvaller eers die eienaarskap van die **`User`**-sjabloon na homself verander. Daarna sou die **`mspki-certificate-name-flag`** op **1** op die sjabloon gestel word om **`ENROLLEE_SUPPLIES_SUBJECT`** te aktiveer, wat 'n gebruiker toelaat om 'n Subject Alternative Name in die versoek te voorsien. Vervolgens kan die aanvaller die **template** **enroll** deur 'n **domain administrator**-naam as 'n alternatiewe naam te kies, en die verkrygde sertifikaat gebruik vir authenticatie as die DA.

Praktiese instellings wat aanvallers mag stel vir langdurige domein persistence (sien {{#ref}}domain-escalation.md{{#endref}} vir volle besonderhede en opsporing):

- CA policy flags that allow SAN from requesters (e.g., enabling `EDITF_ATTRIBUTESUBJECTALTNAME2`). This keeps ESC1-like paths exploitable.
- Template DACL or settings that allow authentication-capable issuance (e.g., adding Client Authentication EKU, enabling `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Controlling the `NTAuthCertificates` object or the CA containers to continuously re-introduce rogue issuers if defenders attempt cleanup.

> [!TIP]
> In hardened environments after KB5014754, pairing these misconfigurations with explicit strong mappings (`altSecurityIdentities`) ensures your issued or forged certificates remain usable even when DCs enforce strong mapping.

## References

- Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
{{#include ../../../banners/hacktricks-training.md}}
