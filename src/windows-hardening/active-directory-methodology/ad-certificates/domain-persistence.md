# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Dit is 'n opsomming van die domain persistence-tegnieke wat in [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) gedeel word**. Raadpleeg dit vir verdere besonderhede.<sup>[[5]](#references)</sup>

## Vervalsing van sertifikate met gesteelde CA-sertifikate (Golden Certificate) - DPERSIST1

Hoe kan jy bepaal dat 'n sertifikaat 'n CA-sertifikaat is?

Daar kan bepaal word dat 'n sertifikaat 'n CA-sertifikaat is indien verskeie voorwaardes nagekom word:<sup>[[5]](#references)</sup>

- Die sertifikaat word op die CA-bediener gestoor, met sy private key wat deur die masjien se DPAPI beveilig word, of deur hardeware soos 'n TPM/HSM indien die bedryfstelsel dit ondersteun.
- Beide die Issuer- en Subject-velde van die sertifikaat stem ooreen met die distinguished name van die CA.
- 'n "CA Version"-uitbreiding is uitsluitlik in die CA-sertifikate teenwoordig.
- Die sertifikaat het geen Extended Key Usage (EKU)-velde nie.

Om die private key van hierdie sertifikaat te onttrek, is die `certsrv.msc`-tool op die CA-bediener die ondersteunde metode via die ingeboude GUI. Nietemin verskil hierdie sertifikaat nie van ander sertifikate wat binne die stelsel gestoor word nie; gevolglik kan metodes soos die [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) vir onttrekking toegepas word.

Die sertifikaat en private key kan ook met Certipy verkry word deur die volgende command te gebruik:<sup>[[2]](#references)</sup>
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Nadat die CA-sertifikaat en sy private sleutel in `.pfx`-formaat bekom is, kan tools soos [ForgeCert](https://github.com/GhostPack/ForgeCert) gebruik word om geldige sertifikate te genereer:
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
> Die gebruiker wat geteiken word vir certificate forgery moet aktief wees en in staat wees om in Active Directory te authenticate sodat die proses kan slaag. Dit is oneffektief om ’n sertifikaat vir spesiale rekeninge soos krbtgt te forge.

Hierdie forged certificate sal **geldig** wees tot die einddatum wat gespesifiseer is en **solank as wat die root CA certificate geldig is** (gewoonlik van 5 tot **10+ jaar**). Dit is ook geldig vir **masjiene**, dus kan ’n aanvaller, gekombineer met **S4U2Self**, **persistence op enige domain machine handhaaf** solank as wat die CA certificate geldig is.\
Verder kan die **certificates wat gegenereer is** met hierdie metode **nie revoked word nie**, aangesien CA nie daarvan bewus is nie.

### Bedryf onder Strong Certificate Mapping Enforcement (2025+)

Sedert 11 Februarie 2025 (na die uitrol van KB5014754) gebruik domain controllers by verstek **Full Enforcement** vir certificate mappings. Prakties beteken dit dat jou forged certificates óf:

- ’n strong binding aan die teikenrekening moet bevat (byvoorbeeld die SID security extension), óf
- Gekombineer moet word met ’n strong, eksplisiete mapping op die teikenobjek se `altSecurityIdentities`-attribute.<sup>[[1]](#references)</sup>

’n Betroubare benadering vir persistence is om ’n forged certificate te mint wat aan die gesteelde Enterprise CA gekoppel is en dan ’n strong eksplisiete mapping by die victim principal te voeg:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Notas
- As jy vervalste sertifikate kan skep wat die SID-sekuriteitsuitbreiding insluit, sal hulle implisiet gekoppel word, selfs onder Full Enforcement. Andersins, verkies eksplisiete sterk mappings. Sien [account-persistence](account-persistence.md) vir meer oor eksplisiete mappings.
- Herroeping help verdedigers nie hier nie: vervalste sertifikate is onbekend aan die CA-databasis en kan dus nie herroep word nie.

#### Full-Enforcement-versoenbare forging (SID-bewus)

Opgedateerde tooling laat jou toe om die SID direk in te sluit, wat golden certificates bruikbaar hou selfs wanneer DCs swak mappings verwerp:<sup>[[3]](#references)</sup>
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
Deur die SID in te bed, vermy jy dat jy aan `altSecurityIdentities` hoef te raak, wat moontlik gemonitor word, terwyl jy steeds aan sterk mapping-kontroles voldoen.

## Vertroue in Rogue CA Certificates - DPERSIST2

Die `NTAuthCertificates`-objek is gedefinieer om een of meer **CA certificates** binne sy `cacertificate`-attribuut te bevat, wat deur Active Directory (AD) gebruik word. Die verifikasieproses deur die **domain controller** behels dat die `NTAuthCertificates`-objek nagegaan word vir ’n inskrywing wat ooreenstem met die **CA** wat in die Issuer-veld van die verifiërende **certificate** gespesifiseer word. Verifikasie gaan voort indien ’n passing gevind word.<sup>[[5]](#references)</sup>

’n Self-getekende CA certificate kan deur ’n aanvaller by die `NTAuthCertificates`-objek gevoeg word, mits hulle beheer oor hierdie AD-objek het. Normaalweg word slegs lede van die **Enterprise Admin**-groep, tesame met **Domain Admins** of **Administrators** in die **forest root’s domain**, toestemming gegee om hierdie objek te wysig. Hulle kan die `NTAuthCertificates`-objek met `certutil.exe` wysig deur die opdrag `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` te gebruik, of deur die [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) te gebruik.

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
Hierdie vermoë is veral relevant wanneer dit saam met ’n voorheen beskryfde metode gebruik word wat ForgeCert behels om sertifikate dinamies te genereer.

> Oorwegings vir kartering ná 2025: om ’n rogue CA in NTAuth te plaas, vestig slegs vertroue in die uitreikende CA. Om leaf-sertifikate vir logon te gebruik wanneer DCs in **Full Enforcement** is, moet die leaf óf die SID security extension bevat, óf daar moet ’n sterk eksplisiete kartering op die teikenobjek wees (byvoorbeeld Issuer+Serial in `altSecurityIdentities`). Sien {{#ref}}account-persistence.md{{#endref}}.

## Malicious Misconfiguration - DPERSIST3

Geleenthede vir **persistence** deur **security descriptor modifications of AD CS**-komponente is volop. Wysigings wat in die "[Domain Escalation](domain-escalation.md)"-afdeling beskryf word, kan kwaadwillig geïmplementeer word deur ’n aanvaller met verhoogde toegang. Dit sluit die toevoeging van "control rights" (bv. WriteOwner/WriteDACL/etc.) tot sensitiewe komponente in, soos:<sup>[[5]](#references)</sup>

- Die **CA server’s AD computer**-objek
- Die **CA server’s RPC/DCOM server**
- Enige **descendant AD object or container** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (byvoorbeeld die Certificate Templates-container, Certification Authorities-container, die NTAuthCertificates-objek, ens.)
- **AD groups delegated rights to control AD CS** by verstek of deur die organisasie (soos die ingeboude Cert Publishers-groep en enige van sy lede)

’n Voorbeeld van kwaadwillige implementering sou ’n aanvaller behels wat **elevated permissions** in die domein het en die **`WriteOwner`**-permission by die verstek **`User`**-sertifikaatsjabloon voeg, met die aanvaller as die principal vir die reg. Om dit te benut, sou die aanvaller eers die eienaarskap van die **`User`**-sjabloon na hulself verander. Daarna sou die **`mspki-certificate-name-flag`** op die sjabloon na **1** gestel word om **`ENROLLEE_SUPPLIES_SUBJECT`** te aktiveer, sodat ’n gebruiker ’n Subject Alternative Name in die versoek kan verskaf. Vervolgens kon die aanvaller **enroll** met die **template**, ’n **domain administrator**-naam as ’n alternatiewe naam kies, en die verkrygde sertifikaat vir authentication as die DA gebruik.

Praktiese knobs wat aanvallers vir langtermyn-domain **persistence** kan stel (sien {{#ref}}domain-escalation.md{{#endref}} vir volledige besonderhede en detection):

- CA policy flags wat SAN vanaf requesters toelaat (bv. deur `EDITF_ATTRIBUTESUBJECTALTNAME2` te aktiveer). Dit hou ESC1-like paths exploit-able.
- Template DACL of settings wat authentication-capable issuance toelaat (bv. deur Client Authentication EKU by te voeg en `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` te aktiveer).
- Beheer oor die `NTAuthCertificates`-objek of die CA-containers om rogue issuers voortdurend weer in te voer indien defenders probeer om dit op te ruim.

> [!TIP]
> In hardened environments ná KB5014754 verseker die kombinasie van hierdie misconfigurations met eksplisiete strong mappings (`altSecurityIdentities`) dat jou uitgereikte of forged certificates bruikbaar bly, selfs wanneer DCs strong mapping afdwing.

### Certificate renewal abuse (ESC14) for persistence

Indien jy ’n authentication-capable certificate (of ’n Enrollment Agent-een) compromise, kan jy dit **indefinitely renew** solank die issuing template gepubliseer bly en jou CA steeds die issuer chain vertrou. Renewal behou die oorspronklike identity bindings, maar verleng die geldigheid, wat eviction moeilik maak tensy die template reggestel of die CA weer gepubliseer word.<sup>[[4]](#references)</sup>
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
Indien domeinbeheerders in **Full Enforcement** is, voeg `-sid <victim SID>` by (of gebruik ’n template wat steeds die SID-sekuriteitsuitbreiding insluit) sodat die hernuwe leaf certificate steeds sterk gemap word sonder om aan `altSecurityIdentities` te raak. Aanvallers met CA-administrateurregte kan ook `policy\RenewalValidityPeriodUnits` wysig om hernuwe geldigheidsperiodes te verleng voordat hulle vir hulself ’n sertifikaat uitreik.<sup>[[2]](#references)[[4]](#references)</sup>


## Verwysings

- [1] [Microsoft KB5014754 – Veranderinge aan certificate-based authentication op Windows-domeinbeheerders (afdwingingstydlyn en sterk mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [Certipy – Command Reference and forge/auth usage](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [3] [SpecterOps – Certify 2.0 (integrated forge with SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [ESC14 renewal abuse overview](https://www.adcs-security.com/attacks/esc14)
- [5] [SpecterOps – Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
