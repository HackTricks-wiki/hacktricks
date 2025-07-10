# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Introduction

### Components of a Certificate

- **Subjekt** sertifikata označava njegovog vlasnika.
- **Javni ključ** je uparen sa privatno držanim ključem kako bi povezao sertifikat sa njegovim pravim vlasnikom.
- **Period važenja**, definisan datumima **NotBefore** i **NotAfter**, označava efektivnu dužinu trajanja sertifikata.
- Jedinstveni **Serijski broj**, koji obezbeđuje Sertifikaciona vlast (CA), identifikuje svaki sertifikat.
- **Izdavac** se odnosi na CA koja je izdala sertifikat.
- **SubjectAlternativeName** omogućava dodatna imena za subjekt, poboljšavajući fleksibilnost identifikacije.
- **Osnovna ograničenja** identifikuju da li je sertifikat za CA ili krajnji entitet i definišu ograničenja korišćenja.
- **Proširene svrhe korišćenja ključeva (EKUs)** razdvajaju specifične svrhe sertifikata, kao što su potpisivanje koda ili enkripcija e-pošte, putem Identifikatora objekta (OIDs).
- **Algoritam potpisa** specificira metodu za potpisivanje sertifikata.
- **Potpis**, kreiran sa privatnim ključem izdavača, garantuje autentičnost sertifikata.

### Special Considerations

- **Alternativna imena subjekta (SANs)** proširuju primenljivost sertifikata na više identiteta, što je ključno za servere sa više domena. Sigurni procesi izdavanja su vitalni kako bi se izbegli rizici od impersonacije od strane napadača koji manipulišu SAN specifikacijom.

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS priznaje CA sertifikate u AD šumi kroz određene kontejnere, od kojih svaki ima jedinstvene uloge:

- Kontejner **Sertifikacione vlasti** sadrži sertifikate pouzdanih root CA.
- Kontejner **Usluge upisa** detaljno opisuje Enterprise CA i njihove šablone sertifikata.
- Objekat **NTAuthCertificates** uključuje CA sertifikate ovlašćene za AD autentifikaciju.
- Kontejner **AIA (Pristup informacijama o vlasti)** olakšava validaciju lanca sertifikata sa međusobnim i cross CA sertifikatima.

### Certificate Acquisition: Client Certificate Request Flow

1. Proces zahteva počinje kada klijenti pronađu Enterprise CA.
2. CSR se kreira, sadrži javni ključ i druge detalje, nakon generisanja para javnog-privatnog ključa.
3. CA procenjuje CSR u odnosu na dostupne šablone sertifikata, izdajući sertifikat na osnovu dozvola šablona.
4. Nakon odobrenja, CA potpisuje sertifikat svojim privatnim ključem i vraća ga klijentu.

### Certificate Templates

Definisani unutar AD, ovi šabloni opisuju podešavanja i dozvole za izdavanje sertifikata, uključujući dozvoljene EKUs i prava na upis ili modifikaciju, što je ključno za upravljanje pristupom uslugama sertifikata.

## Certificate Enrollment

Proces upisa sertifikata pokreće administrator koji **kreira šablon sertifikata**, koji zatim **objavljuje** Enterprise Sertifikaciona vlast (CA). Ovo čini šablon dostupnim za upis klijenata, što se postiže dodavanjem imena šablona u polje `certificatetemplates` objekta Active Directory.

Da bi klijent zatražio sertifikat, **prava na upis** moraju biti dodeljena. Ova prava definišu se sigurnosnim descriptorima na šablonu sertifikata i samoj Enterprise CA. Dozvole moraju biti dodeljene na oba mesta kako bi zahtev bio uspešan.

### Template Enrollment Rights

Ova prava su specificirana kroz Unose kontrole pristupa (ACE), detaljno opisujući dozvole kao što su:

- **Prava na upis sertifikata** i **Automatski upis sertifikata**, svako povezano sa specifičnim GUID-ovima.
- **Proširena prava**, omogućavajući sve proširene dozvole.
- **Potpuna kontrola/GenericAll**, pružajući potpunu kontrolu nad šablonom.

### Enterprise CA Enrollment Rights

Prava CA su opisana u njegovom sigurnosnom descriptoru, dostupnom putem konzole za upravljanje Sertifikacionom vlasti. Neka podešavanja čak omogućavaju korisnicima sa niskim privilegijama daljinski pristup, što može biti bezbednosna zabrinutost.

### Additional Issuance Controls

Određene kontrole mogu se primeniti, kao što su:

- **Odobrenje menadžera**: Postavlja zahteve u stanje čekanja dok ih ne odobri menadžer sertifikata.
- **Agenti za upis i ovlašćeni potpisi**: Specificiraju broj potrebnih potpisa na CSR-u i neophodne OIDs za aplikacione politike.

### Methods to Request Certificates

Sertifikate je moguće zatražiti putem:

1. **Protokola za upis sertifikata Windows klijenta** (MS-WCCE), koristeći DCOM interfejse.
2. **ICertPassage Remote Protocol** (MS-ICPR), putem imenovanih cevi ili TCP/IP.
3. **Web interfejsa za upis sertifikata**, sa instaliranom ulogom Web upisa Sertifikacione vlasti.
4. **Usluge za upis sertifikata** (CES), u kombinaciji sa uslugom politike upisa sertifikata (CEP).
5. **Usluge za upis mrežnih uređaja** (NDES) za mrežne uređaje, koristeći Protokol za jednostavno upisivanje sertifikata (SCEP).

Windows korisnici takođe mogu zatražiti sertifikate putem GUI-a (`certmgr.msc` ili `certlm.msc`) ili alata komandne linije (`certreq.exe` ili PowerShell-ove komande `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Autentifikacija putem sertifikata

Active Directory (AD) podržava autentifikaciju putem sertifikata, prvenstveno koristeći **Kerberos** i **Secure Channel (Schannel)** protokole.

### Proces autentifikacije putem Kerberosa

U procesu autentifikacije putem Kerberosa, zahtev korisnika za Ticket Granting Ticket (TGT) se potpisuje koristeći **privatni ključ** sertifikata korisnika. Ovaj zahtev prolazi kroz nekoliko validacija od strane kontrolera domena, uključujući **validnost** sertifikata, **putanju** i **status opoziva**. Validacije takođe uključuju proveru da li sertifikat dolazi iz pouzdanog izvora i potvrđivanje prisustva izdavaoca u **NTAUTH sertifikat skladištu**. Uspešne validacije rezultiraju izdavanjem TGT-a. **`NTAuthCertificates`** objekat u AD, nalazi se na:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
je centralno za uspostavljanje poverenja za autentifikaciju putem sertifikata.

### Secure Channel (Schannel) Authentication

Schannel olakšava sigurne TLS/SSL veze, gde tokom rukovanja, klijent predstavlja sertifikat koji, ako je uspešno validiran, odobrava pristup. Mapiranje sertifikata na AD nalog može uključivati Kerberosovu **S4U2Self** funkciju ili **Subject Alternative Name (SAN)** sertifikata, među drugim metodama.

### AD Certificate Services Enumeration

AD-ove usluge sertifikata mogu se enumerisati putem LDAP upita, otkrivajući informacije o **Enterprise Certificate Authorities (CAs)** i njihovim konfiguracijama. Ovo je dostupno svakom korisniku koji je autentifikovan u domenu bez posebnih privilegija. Alati kao što su **[Certify](https://github.com/GhostPack/Certify)** i **[Certipy](https://github.com/ly4k/Certipy)** se koriste za enumeraciju i procenu ranjivosti u AD CS okruženjima.

Komande za korišćenje ovih alata uključuju:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy (>=4.0) for enumeration and identifying vulnerable templates
certipy find -vulnerable -dc-only -u john@corp.local -p Passw0rd -target dc.corp.local

# Request a certificate over the web enrollment interface (new in Certipy 4.x)
certipy req -web -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
---

## Nedavne ranjivosti i bezbednosna ažuriranja (2022-2025)

| Godina | ID / Ime | Uticaj | Ključne informacije |
|--------|----------|--------|---------------------|
| 2022   | **CVE-2022-26923** – “Certifried” / ESC6 | *Povećanje privilegija* lažiranjem sertifikata mašinskog naloga tokom PKINIT-a. | Zakrpa je uključena u **bezbednosna ažuriranja od 10. maja 2022**. Uvedene su kontrole revizije i jakog mapiranja putem **KB5014754**; okruženja bi sada trebala biti u *Potpunoj primeni* modu. citeturn2search0 |
| 2023   | **CVE-2023-35350 / 35351** | *Daljinsko izvršavanje koda* u AD CS Web Enrollment (certsrv) i CES rolama. | Javne PoC-ove su ograničene, ali su ranjivi IIS komponenti često izloženi interno. Zakrpa od **jula 2023** Patch Tuesday. citeturn3search0 |
| 2024   | **CVE-2024-49019** – “EKUwu” / ESC15 | Korisnici sa niskim privilegijama koji imaju prava na upis mogli su da prevaziđu **bilo koji** EKU ili SAN tokom generisanja CSR-a, izdajući sertifikate koji se mogu koristiti za autentifikaciju klijenata ili potpisivanje koda, što dovodi do *kompromitacije domena*. | Rešeno u **aprilskim ažuriranjima 2024**. Uklonite “Supply in the request” iz šablona i ograničite prava na upis. citeturn1search3 |

### Microsoftova vremenska linija za učvršćivanje (KB5014754)

Microsoft je uveo trofazno uvođenje (Kompatibilnost → Revizija → Primena) kako bi prešao sa Kerberos sertifikatske autentifikacije sa slabih implicitnih mapiranja. Od **11. februara 2025**, kontroleri domena automatski prelaze na **Potpunu primenu** ako registry vrednost `StrongCertificateBindingEnforcement` nije postavljena. Administratori bi trebali:

1. Zakrpiti sve DC-ove i AD CS servere (maj 2022. ili kasnije).
2. Pratiti Event ID 39/41 za slaba mapiranja tokom *Revizije* faze.
3. Ponovo izdati sertifikate za autentifikaciju klijenata sa novim **SID ekstenzijom** ili konfigurisati jaka ručna mapiranja pre februara 2025. citeturn2search0

---

## Poboljšanja detekcije i učvršćivanja

* **Defender for Identity AD CS senzor (2023-2024)** sada prikazuje procene stanja za ESC1-ESC8/ESC11 i generiše upozorenja u realnom vremenu kao što su *“Izdavanje sertifikata kontrolera domena za ne-DC”* (ESC8) i *“Spriječiti upis sertifikata sa proizvoljnim aplikacionim politikama”* (ESC15). Osigurajte da su senzori raspoređeni na sve AD CS servere kako biste imali koristi od ovih detekcija. citeturn5search0
* Onemogućite ili strogo ograničite opciju **“Supply in the request”** na svim šablonima; preferirajte eksplicitno definisane SAN/EKU vrednosti.
* Uklonite **Any Purpose** ili **No EKU** iz šablona osim ako nije apsolutno neophodno (rešava ESC2 scenarije).
* Zahtevajte **odobrenje menadžera** ili posvećene tokove rada za upis agenata za osetljive šablone (npr. WebServer / CodeSigning).
* Ograničite web upis (`certsrv`) i CES/NDES krajnje tačke na pouzdane mreže ili iza autentifikacije klijent-sertifikata.
* Primorajte enkripciju upisa RPC-a (`certutil –setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQ`) kako biste ublažili ESC11.

---

## Reference

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/](https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
