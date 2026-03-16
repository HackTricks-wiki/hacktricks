# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Uvod

### Komponente sertifikata

- **Subject** sertifikata označava njegovog vlasnika.
- **Public Key** je u paru sa privatnim ključem i povezuje sertifikat sa njegovim pravim vlasnikom.
- **Validity Period**, definisan datumima **NotBefore** i **NotAfter**, označava period važenja sertifikata.
- Jedinstveni **Serial Number**, koji izdaje Certificate Authority (CA), identifikuje svaki sertifikat.
- **Issuer** se odnosi na CA koji je izdao sertifikat.
- **SubjectAlternativeName** omogućava dodatna imena subjekta, povećavajući fleksibilnost identifikacije.
- **Basic Constraints** ukazuju da li je sertifikat za CA ili krajnji entitet i definišu ograničenja upotrebe.
- **Extended Key Usages (EKUs)** preciziraju specifične namene sertifikata (npr. code signing ili email encryption) putem Object Identifiers (OIDs).
- **Signature Algorithm** određuje metodu potpisivanja sertifikata.
- **Signature**, kreiran privatnim ključem izdavaoca, garantuje autentičnost sertifikata.

### Posebna razmatranja

- **Subject Alternative Names (SANs)** proširuju primenljivost sertifikata na više identiteta, što je ključno za servere sa više domena. Bezbedni procesi izdavanja su neophodni kako bi se izbegli rizici impersonacije usled manipulisanja SAN specifikacijom.

### Certificate Authorities (CAs) u Active Directory (AD)

AD CS prepoznaje CA sertifikate u AD forestu kroz određene kontejnere, pri čemu svaki ima posebnu ulogu:

- **Certification Authorities** container sadrži poverene root CA sertifikate.
- **Enrolment Services** container detaljiše Enterprise CA-ove i njihove certificate templates.
- **NTAuthCertificates** objekat uključuje CA sertifikate ovlašćene za AD autentifikaciju.
- **AIA (Authority Information Access)** container olakšava validaciju lanca sertifikata sa intermediate i cross CA sertifikatima.

### Pribavljanje sertifikata: tok zahteva klijenta (Client Certificate Request Flow)

1. Proces započinje tako što klijenti pronalaze Enterprise CA.
2. Kreira se CSR koji sadrži public key i ostale podatke, nakon generisanja para javnog i privatnog ključa.
3. CA procenjuje CSR u odnosu na dostupne certificate templates i izdaje sertifikat bazirano na dozvolama šablona.
4. Nakon odobrenja, CA potpisuje sertifikat svojim privatnim ključem i vraća ga klijentu.

### Certificate Templates

Definisani u AD, ovi templates opisuju podešavanja i dozvole za izdavanje sertifikata, uključujući dozvoljene EKUs i prava za enrollment ili modifikaciju, što je ključno za upravljanje pristupom servisima za sertifikate.

Važna je verzija šablona. Legacy **v1** templates (npr. ugrađeni **WebServer** template) nemaju nekoliko modernih mehanizama za nametanje pravila. ESC15/EKUwu istraživanje je pokazalo da kod **v1 templates** requester može u CSR ubaciti **Application Policies/EKUs** koji imaju prioritet nad EKUs konfigurisanih u šablonu, omogućavajući client-auth, enrollment agent ili code-signing sertifikate samo sa enrollment pravima. Preferirajte **v2/v3 templates**, uklonite ili zamenite v1 podrazumevane vrednosti i strogo definišite EKUs za namenjenu svrhu.

## Certificate Enrollment

Proces izdavanja sertifikata pokreće administrator koji **kreira certificate template**, koji potom Enterprise Certificate Authority (CA) **publikuje**. Time šablon postaje dostupan za enrollment klijenata, što se postiže dodavanjem imena šablona u `certificatetemplates` polje Active Directory objekta.

Da bi klijent mogao da zatraži sertifikat, moraju mu biti dodeljena **enrollment rights**. Ta prava definišu se kroz security descriptor-e na certificate template-u i na samom Enterprise CA-u. Dozvole moraju biti dodeljene na oba mesta da bi zahtev bio uspešan.

### Template Enrollment Rights

Ta prava su navedena kroz Access Control Entries (ACEs) i uključuju dozvole poput:

- **Certificate-Enrollment** i **Certificate-AutoEnrollment** prava, svaki povezan sa specifičnim GUID-ovima.
- **ExtendedRights**, koje dozvoljavaju sve extended permisije.
- **FullControl/GenericAll**, koje pružaju potpunu kontrolu nad šablonom.

### Enterprise CA Enrollment Rights

Prava CA su navedenа u njegovom security descriptor-u, dostupan putem Certificate Authority management konzole. Neka podešavanja čak dozvoljavaju udaljeni pristup niskoprivilegovanim korisnicima, što može predstavljati bezbednosni rizik.

### Dodatne kontrole izdavanja

Mogu važiti određene kontrole, kao što su:

- **Manager Approval**: stavlja zahteve u pending stanje dok ih ne odobri certificate manager.
- **Enrolment Agents and Authorized Signatures**: specificiraju broj potrebnih potpisa na CSR-u i potrebne Application Policy OID-ove.

### Metode za zahtev sertifikata

Sertifikati se mogu zahtevati putem:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), koristeći DCOM interfejse.
2. **ICertPassage Remote Protocol** (MS-ICPR), preko named pipes ili TCP/IP.
3. certificate enrollment web interface, uz instaliranu Certificate Authority Web Enrollment ulogu.
4. **Certificate Enrollment Service** (CES), u kombinaciji sa Certificate Enrollment Policy (CEP) servisom.
5. **Network Device Enrollment Service** (NDES) za mrežne uređaje, koristeći Simple Certificate Enrollment Protocol (SCEP).

Windows korisnici takođe mogu da zatraže sertifikate preko GUI-ja (`certmgr.msc` ili `certlm.msc`) ili komandnih alata (`certreq.exe` ili PowerShell `Get-Certificate` komanda).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Autentifikacija sertifikatom

Active Directory (AD) podržava autentifikaciju putem sertifikata, prvenstveno koristeći **Kerberos** i **Secure Channel (Schannel)** protokole.

### Kerberos proces autentifikacije

U Kerberos procesu autentifikacije, zahtev korisnika za Ticket Granting Ticket (TGT) potpisuje se koristeći **privatnim ključem** korisnikovog sertifikata. Taj zahtev prolazi kroz nekoliko provera od strane kontrolera domena, uključujući **validnost**, **putanju** i **status opoziva** sertifikata. Provere takođe uključuju verifikaciju da sertifikat potiče iz pouzdanog izvora i potvrdu prisustva izdavaoca u **NTAUTH certificate store**. Uspešne provere rezultuju izdavanjem TGT-a. The **`NTAuthCertificates`** object in AD, found at:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
je centralno za uspostavljanje poverenja za autentikaciju pomoću sertifikata.

### Secure Channel (Schannel) Authentication

Schannel olakšava sigurne TLS/SSL veze, gde tokom handshake-a klijent prezentuje sertifikat koji, ako je uspešno verifikovan, ovlašćuje pristup. Mapiranje sertifikata na AD nalog može uključivati Kerberos-ovu funkciju **S4U2Self** ili **Subject Alternative Name (SAN)** sertifikata, između ostalih metoda.

### AD Certificate Services Enumeration

Sertifikacioni servisi AD-a mogu se enumerisati kroz LDAP upite, otkrivajući informacije o **Enterprise Certificate Authorities (CAs)** i njihovim konfiguracijama. Ovo je dostupno bilo kojem korisniku autentifikovanom u domenu bez posebnih privilegija. Alati kao što su **[Certify](https://github.com/GhostPack/Certify)** i **[Certipy](https://github.com/ly4k/Certipy)** koriste se za enumeraciju i procenu ranjivosti u AD CS okruženjima.

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
{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## Nedavne ranjivosti i bezbednosna ažuriranja (2022–2025)

| Godina | ID / Naziv | Uticaj | Ključne napomene |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilege escalation* by spoofing machine account certificates during PKINIT. | Ispravka je uključena u bezbednosna ažuriranja od **10. maja 2022**. Uvedene su kontrole za reviziju i strong-mapping putem **KB5014754**; okruženja bi sada trebalo da budu u režimu *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* in the AD CS Web Enrollment (certsrv) and CES roles. | Javni PoC-ovi su ograničeni, ali ranjivi IIS komponenti često su izložene interno. Ispravka dostupna od **Patch Tuesday, juli 2023**.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | On **v1 templates**, a requester with enrollment rights can embed **Application Policies/EKUs** in the CSR that are preferred over the template EKUs, producing client-auth, enrollment agent, or code-signing certificates. | Ispravljeno od **12. novembra 2024**. Zamenite ili supersedujte v1 šablone (npr. default WebServer), ograničite EKU-ove na namenu i smanjite prava za enrollment. |

### Microsoft hardening timeline (KB5014754)

Microsoft je uveo rollout u tri faze (Compatibility → Audit → Enforcement) da bi premestio Kerberos certificate authentication sa slabih implicitnih mapiranja. Od **11. februara 2025**, domain controller-i se automatski prebacuju u **Full Enforcement** ako registry vrednost `StrongCertificateBindingEnforcement` nije postavljena. Administratori bi trebalo da:

1. Ažurirajte sve DC-ove i AD CS servere (maj 2022 ili kasnije).
2. Pratite Event ID 39/41 za slaba mapiranja tokom faze *Audit*.
3. Ponovo izdajte client-auth sertifikate sa novim **SID extension** ili konfigurišite jaka manuelna mapiranja pre februara 2025.

---

## Detekcija i poboljšanja za jačanje bezbednosti

* **Defender for Identity AD CS sensor (2023-2024)** sada prikazuje procene stanja za ESC1-ESC8/ESC11 i generiše real-time upozorenja kao što su *“Domain-controller certificate issuance for a non-DC”* (ESC8) i *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Osigurajte da su senzori raspoređeni na svim AD CS serverima da biste iskoristili ove detekcije.
* Onemogućite ili striktno ograničite opciju **“Supply in the request”** na svim šablonima; preferirajte eksplicitno definisane SAN/EKU vrednosti.
* Uklonite **Any Purpose** ili **No EKU** iz šablona osim ako nije apsolutno neophodno (odgovara ESC2 scenarijima).
* Zahtevajte **manager approval** ili posvećene Enrollment Agent workflow-e za osetljive šablone (npr. WebServer / CodeSigning).
* Ograničite web enrollment (`certsrv`) i CES/NDES endpoint-e na pouzdane mreže ili iza autentifikacije klijentskim sertifikatima.
* Primena enkripcije RPC enrollment-a (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) da bi se ublažio ESC11 (RPC relay). Zastavica je **podrazumevano uključena**, ali je često onemogućena za legacy klijente, što ponovo otvara rizik releja.
* Zaštitite **IIS-based enrollment endpoints** (CES/Certsrv): onemogućite NTLM gde je moguće ili zahtevajte HTTPS + Extended Protection da blokirate ESC8 relaye.

---



## Reference

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/](https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/)
{{#include ../../banners/hacktricks-training.md}}
