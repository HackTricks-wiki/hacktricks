# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Ovo je kratak pregled poglavlja o postojanosti mašine iz sjajnog istraživanja sa [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## **Razumevanje krađe aktivnih korisničkih akreditiva pomoću sertifikata – PERSIST1**

U scenariju gde korisnik može da zatraži sertifikat koji omogućava autentifikaciju domena, napadač ima priliku da **zatraži** i **ukrade** ovaj sertifikat kako bi **održao postojanost** na mreži. Po defaultu, `User` šablon u Active Directory omogućava takve zahteve, iako može ponekad biti onemogućen.

Korišćenjem alata pod nazivom [**Certify**](https://github.com/GhostPack/Certify), može se pretraživati validne sertifikate koji omogućavaju postojan pristup:
```bash
Certify.exe find /clientauth
```
Istaknuto je da moć sertifikata leži u njegovoj sposobnosti da **autentifikuje kao korisnik** kojem pripada, bez obzira na bilo kakve promene lozinke, sve dok sertifikat ostaje **važeći**.

Sertifikati se mogu tražiti putem grafičkog interfejsa koristeći `certmgr.msc` ili putem komandne linije sa `certreq.exe`. Sa **Certify**, proces traženja sertifikata je pojednostavljen na sledeći način:
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
Kada je zahtev uspešan, sertifikat zajedno sa svojim privatnim ključem se generiše u `.pem` formatu. Da bi se ovo konvertovalo u `.pfx` datoteku, koja se može koristiti na Windows sistemima, koristi se sledeća komanda:
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
Datoteka `.pfx` se zatim može otpremiti na ciljni sistem i koristiti sa alatom pod nazivom [**Rubeus**](https://github.com/GhostPack/Rubeus) za zahtev za Ticket Granting Ticket (TGT) za korisnika, produžavajući pristup napadača sve dok je sertifikat **važeći** (obično jednu godinu):
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
Važna upozorenja se dele o tome kako ova tehnika, u kombinaciji sa drugom metodom opisano u sekciji **THEFT5**, omogućava napadaču da trajno dobije **NTLM hash** naloga bez interakcije sa Local Security Authority Subsystem Service (LSASS), i iz neuzvišenog konteksta, pružajući diskretniju metodu za dugotrajno krađu akreditiva.

## **Sticanje mašinske postojanosti sa sertifikatima - PERSIST2**

Druga metoda uključuje registraciju mašinskog naloga kompromitovanog sistema za sertifikat, koristeći podrazumevani `Machine` šablon koji omogućava takve radnje. Ako napadač dobije uzvišene privilegije na sistemu, može koristiti **SYSTEM** nalog za zahtev sertifikata, pružajući oblik **postojanosti**:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
Ovaj pristup omogućava napadaču da se autentifikuje na **Kerberos** kao mašinski nalog i koristi **S4U2Self** da dobije Kerberos servisne karte za bilo koju uslugu na hostu, efektivno dajući napadaču trajni pristup mašini.

## **Produženje Persistencije Kroz Obnovu Sertifikata - PERSIST3**

Poslednja metoda koja se razmatra uključuje korišćenje **važenja** i **perioda obnove** šablona sertifikata. Obnavljanjem sertifikata pre njegovog isteka, napadač može održati autentifikaciju na Active Directory bez potrebe za dodatnim upisima karata, što bi moglo ostaviti tragove na serveru Sertifikacione vlasti (CA).

### Obnova Sertifikata sa Certify 2.0

Počevši od **Certify 2.0**, proces obnove je potpuno automatizovan kroz novu `request-renew` komandu. Dajući prethodno izdat sertifikat (u **base-64 PKCS#12** formatu), napadač može da ga obnovi bez interakcije sa originalnim vlasnikom – savršeno za diskretnu, dugoročnu persistenciju:
```powershell
Certify.exe request-renew --ca SERVER\\CA-NAME \
--cert-pfx MIACAQMwgAYJKoZIhvcNAQcBoIAkgA...   # original PFX
```
Komanda će vratiti novi PFX koji je važeći za još jedan puni period trajanja, omogućavajući vam da nastavite sa autentifikacijom čak i nakon što prvi sertifikat istekne ili bude opozvan.

## References

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)

{{#include ../../../banners/hacktricks-training.md}}
