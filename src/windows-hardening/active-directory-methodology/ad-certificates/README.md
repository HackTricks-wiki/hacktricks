# AD Certificates

{{#include ../../../banners/hacktricks-training.md}}

## Uvod

### Komponente sertifikata

- **Subjekt** sertifikata označava njegovog vlasnika.
- **Javni ključ** je uparen sa privatno držanim ključem kako bi povezao sertifikat sa njegovim pravim vlasnikom.
- **Period važenja**, definisan datumima **NotBefore** i **NotAfter**, označava efektivnu dužinu trajanja sertifikata.
- Jedinstveni **Serijski broj**, koji obezbeđuje Sertifikaciona vlast (CA), identifikuje svaki sertifikat.
- **Izdao** se odnosi na CA koja je izdala sertifikat.
- **SubjectAlternativeName** omogućava dodatna imena za subjekt, poboljšavajući fleksibilnost identifikacije.
- **Osnovna ograničenja** identifikuju da li je sertifikat za CA ili krajnji entitet i definišu ograničenja korišćenja.
- **Proširene namene ključeva (EKUs)** razdvajaju specifične svrhe sertifikata, kao što su potpisivanje koda ili enkripcija e-pošte, putem Identifikatora objekata (OIDs).
- **Algoritam potpisa** specificira metodu za potpisivanje sertifikata.
- **Potpis**, kreiran sa izdavačevim privatnim ključem, garantuje autentičnost sertifikata.

### Posebna razmatranja

- **Alternativna imena subjekta (SANs)** proširuju primenljivost sertifikata na više identiteta, što je ključno za servere sa više domena. Bezbedni procesi izdavanja su od vitalnog značaja kako bi se izbegli rizici od impersonacije od strane napadača koji manipulišu SAN specifikacijom.

### Sertifikacione vlasti (CAs) u Active Directory (AD)

AD CS priznaje CA sertifikate u AD šumi kroz određene kontejnere, od kojih svaki ima jedinstvene uloge:

- Kontejner **Sertifikacione vlasti** sadrži sertifikate pouzdanih root CA.
- Kontejner **Usluge upisa** detaljno opisuje Enterprise CA i njihove šablone sertifikata.
- Objekat **NTAuthCertificates** uključuje CA sertifikate ovlašćene za AD autentifikaciju.
- Kontejner **AIA (Authority Information Access)** olakšava validaciju lanca sertifikata sa međusobnim i cross CA sertifikatima.

### Sticanje sertifikata: Tok zahteva za klijentski sertifikat

1. Proces zahteva počinje kada klijenti pronađu Enterprise CA.
2. CSR se kreira, sadrži javni ključ i druge detalje, nakon generisanja para javnog-privatnog ključa.
3. CA procenjuje CSR u odnosu na dostupne šablone sertifikata, izdajući sertifikat na osnovu dozvola šablona.
4. Nakon odobrenja, CA potpisuje sertifikat svojim privatnim ključem i vraća ga klijentu.

### Šabloni sertifikata

Definisani unutar AD, ovi šabloni opisuju podešavanja i dozvole za izdavanje sertifikata, uključujući dozvoljene EKUs i prava na upis ili modifikaciju, što je ključno za upravljanje pristupom uslugama sertifikata.

## Upis sertifikata

Proces upisa za sertifikate pokreće administrator koji **kreira šablon sertifikata**, koji zatim **objavljuje** Enterprise Sertifikaciona vlast (CA). Ovo čini šablon dostupnim za upis klijenata, što se postiže dodavanjem imena šablona u polje `certificatetemplates` objekta Active Directory.

Da bi klijent zatražio sertifikat, **prava na upis** moraju biti dodeljena. Ova prava definišu se sigurnosnim descriptorima na šablonu sertifikata i samoj Enterprise CA. Dozvole moraju biti dodeljene na obe lokacije kako bi zahtev bio uspešan.

### Prava na upis šablona

Ova prava su specificirana kroz Unose kontrole pristupa (ACEs), detaljno opisujući dozvole kao što su:

- **Certificate-Enrollment** i **Certificate-AutoEnrollment** prava, svaka povezana sa specifičnim GUID-ovima.
- **ExtendedRights**, omogućavajući sve proširene dozvole.
- **FullControl/GenericAll**, pružajući potpunu kontrolu nad šablonom.

### Prava na upis Enterprise CA

Prava CA su opisana u njegovom sigurnosnom descriptoru, dostupnom putem konzole za upravljanje Sertifikacionom vlasti. Neka podešavanja čak omogućavaju korisnicima sa niskim privilegijama daljinski pristup, što može biti bezbednosna briga.

### Dodatne kontrole izdavanja

Određene kontrole mogu se primeniti, kao što su:

- **Odobrenje menadžera**: Postavlja zahteve u stanje čekanja dok ih ne odobri menadžer sertifikata.
- **Agenti za upis i ovlašćeni potpisi**: Specifikuju broj potrebnih potpisa na CSR-u i neophodne OIDs za politiku aplikacije.

### Metode za zahtev za sertifikate

Sertifikati se mogu zahtevati putem:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), koristeći DCOM interfejse.
2. **ICertPassage Remote Protocol** (MS-ICPR), putem imenovanih cevi ili TCP/IP.
3. **web interfejsa za upis sertifikata**, sa instaliranom ulogom Web upisa sertifikata.
4. **Usluge upisa sertifikata** (CES), u kombinaciji sa uslugom politike upisa sertifikata (CEP).
5. **Usluge upisa mrežnih uređaja** (NDES) za mrežne uređaje, koristeći Protokol jednostavnog upisa sertifikata (SCEP).

Windows korisnici takođe mogu zahtevati sertifikate putem GUI (`certmgr.msc` ili `certlm.msc`) ili alata komandne linije (`certreq.exe` ili PowerShell-ove `Get-Certificate` komande).
```powershell
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Autentifikacija putem sertifikata

Active Directory (AD) podržava autentifikaciju putem sertifikata, prvenstveno koristeći **Kerberos** i **Secure Channel (Schannel)** protokole.

### Proces autentifikacije putem Kerberosa

U procesu autentifikacije putem Kerberosa, zahtev korisnika za Ticket Granting Ticket (TGT) se potpisuje koristeći **privatni ključ** korisničkog sertifikata. Ovaj zahtev prolazi kroz nekoliko validacija od strane kontrolera domena, uključujući **validnost** sertifikata, **putanju** i **status opoziva**. Validacije takođe uključuju proveru da li sertifikat dolazi iz pouzdanog izvora i potvrđivanje prisustva izdavaoca u **NTAUTH sertifikat skladištu**. Uspešne validacije rezultiraju izdavanjem TGT-a. **`NTAuthCertificates`** objekat u AD, nalazi se na:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
je centralno za uspostavljanje poverenja za autentifikaciju sertifikata.

### Secure Channel (Schannel) Authentication

Schannel olakšava sigurne TLS/SSL veze, gde tokom rukovanja, klijent predstavlja sertifikat koji, ako je uspešno validiran, odobrava pristup. Mapiranje sertifikata na AD nalog može uključivati Kerberosovu **S4U2Self** funkciju ili **Subject Alternative Name (SAN)** sertifikata, među drugim metodama.

### AD Certificate Services Enumeration

AD-ove usluge sertifikata mogu se enumerisati putem LDAP upita, otkrivajući informacije o **Enterprise Certificate Authorities (CAs)** i njihovim konfiguracijama. Ovo je dostupno bilo kojem korisniku koji je autentifikovan u domenu bez posebnih privilegija. Alati kao što su **[Certify](https://github.com/GhostPack/Certify)** i **[Certipy](https://github.com/ly4k/Certipy)** se koriste za enumeraciju i procenu ranjivosti u AD CS okruženjima.

Komande za korišćenje ovih alata uključuju:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
## Reference

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

{{#include ../../../banners/hacktricks-training.md}}
