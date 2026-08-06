# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Uvod

### Komponente sertifikata

- **Subjekt** sertifikata označava njegovog vlasnika.
- **Javni ključ** je uparen sa privatno čuvanim ključem kako bi se sertifikat povezao sa njegovim pravim vlasnikom.
- **Period važenja**, definisan datumima **NotBefore** i **NotAfter**, označava period efektivnog važenja sertifikata.
- Jedinstveni **serijski broj**, koji obezbeđuje Certificate Authority (CA), identifikuje svaki sertifikat.
- **Izdavalac** označava CA koji je izdao sertifikat.
- **SubjectAlternativeName** omogućava dodatna imena za subjekt, čime se povećava fleksibilnost identifikacije.
- **Osnovna ograničenja** određuju da li je sertifikat namenjen za CA ili krajnji entitet i definišu ograničenja upotrebe.
- **Extended Key Usages (EKUs)** određuju posebne namene sertifikata, kao što su potpisivanje koda ili šifrovanje e-pošte, putem Object Identifiers (OID-ova).
- **Algoritam potpisa** određuje metod kojim se sertifikat potpisuje.
- **Potpis**, kreiran privatnim ključem izdavaoca, garantuje autentičnost sertifikata.<sup>[[4]](#references)</sup>

### Posebna razmatranja

- **Subject Alternative Names (SANs)** proširuju primenljivost sertifikata na više identiteta, što je ključno za servere sa više domena. Bezbedni procesi izdavanja su od vitalnog značaja kako bi se izbegli rizici od impersonacije koje napadači mogu izazvati manipulacijom SAN specifikacije.<sup>[[4]](#references)</sup>

### Certificate Authorities (CAs) u Active Directory (AD)

AD CS prepoznaje CA sertifikate u AD forest-u putem namenski određenih kontejnera, od kojih svaki ima jedinstvenu ulogu:<sup>[[4]](#references)</sup>

- Kontejner **Certification Authorities** sadrži pouzdane root CA sertifikate.
- Kontejner **Enrolment Services** sadrži podatke o Enterprise CA-ovima i njihovim predlošcima sertifikata.
- Objekat **NTAuthCertificates** uključuje CA sertifikate ovlašćene za AD autentifikaciju.
- Kontejner **AIA (Authority Information Access)** omogućava validaciju lanca sertifikata pomoću intermediate i cross CA sertifikata.

### Nabavka sertifikata: tok zahteva klijentskog sertifikata

1. Proces zahteva počinje tako što klijenti pronalaze Enterprise CA.
2. Nakon generisanja para javnog i privatnog ključa, kreira se CSR koji sadrži javni ključ i druge podatke.
3. CA procenjuje CSR u odnosu na dostupne predloške sertifikata i izdaje sertifikat na osnovu dozvola predloška.
4. Nakon odobrenja, CA potpisuje sertifikat svojim privatnim ključem i vraća ga klijentu.<sup>[[4]](#references)</sup>

### Predlošci sertifikata

Ovi predlošci, definisani u okviru AD-a, određuju postavke i dozvole za izdavanje sertifikata, uključujući dozvoljene EKU-ove i prava za upis ili izmenu, što je ključno za upravljanje pristupom servisima sertifikata.<sup>[[4]](#references)</sup>

**Verzija šeme predloška je važna.** Nasleđeni **v1** predlošci (na primer, ugrađeni predložak **WebServer**) nemaju nekoliko savremenih mehanizama za sprovođenje pravila. Istraživanje **ESC15/EKUwu** pokazalo je da na **v1 predlošcima** podnosilac zahteva može u CSR da ugradi **Application Policies/EKUs**, koji imaju **prednost nad** EKU-ovima konfigurisanima u predlošku, čime se omogućavaju client-auth, enrollment agent ili code-signing sertifikati uz samo prava za upis. Prednost treba dati **v2/v3 predlošcima**, ukloniti ili zameniti podrazumevane v1 predloške i strogo ograničiti EKU-ove na predviđenu namenu.<sup>[[1]](#references)</sup>

## Upis sertifikata

Proces upisa sertifikata pokreće administrator koji **kreira predložak sertifikata**, a zatim ga **objavljuje** Enterprise Certificate Authority (CA). Time predložak postaje dostupan za upis klijenata, što se postiže dodavanjem imena predloška u polje `certificatetemplates` objekta Active Directory-ja.<sup>[[4]](#references)</sup>

Da bi klijent mogao da zatraži sertifikat, moraju mu biti dodeljena **prava za upis**. Ova prava su definisana bezbednosnim deskriptorima na samom predlošku sertifikata i na Enterprise CA-u. Dozvole moraju biti dodeljene na obe lokacije da bi zahtev bio uspešan.

### Prava za upis na predlošku

Ova prava se navode putem Access Control Entries (ACE-ova), koje detaljno definišu dozvole kao što su:

- Prava **Certificate-Enrollment** i **Certificate-AutoEnrollment**, od kojih je svako povezano sa konkretnim GUID-ovima.
- **ExtendedRights**, koji omogućava sve proširene dozvole.
- **FullControl/GenericAll**, koji obezbeđuje potpunu kontrolu nad predloškom.

### Prava za upis na Enterprise CA-u

Prava CA-a navedena su u njegovom bezbednosnom deskriptoru, kome se može pristupiti putem konzole za upravljanje Certificate Authority-jem. Neke postavke čak omogućavaju korisnicima sa malim privilegijama udaljeni pristup, što može predstavljati bezbednosni problem.

### Dodatne kontrole izdavanja

Mogu se primenjivati određene kontrole, kao što su:

- **Manager Approval**: Zahteve postavlja u stanje čekanja dok ih ne odobri certificate manager.
- **Enrolment Agents and Authorized Signatures**: Određuju broj potrebnih potpisa na CSR-u i neophodne Application Policy OID-ove.

### Metode za zahtevanje sertifikata

Sertifikati se mogu zahtevati putem:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), korišćenjem DCOM interfejsa.
2. **ICertPassage Remote Protocol** (MS-ICPR), putem imenovanih cevi ili TCP/IP-a.
3. **Web interfejsa za upis sertifikata**, sa instaliranom ulogom Certificate Authority Web Enrollment.
4. **Certificate Enrollment Service** (CES), u kombinaciji sa servisom Certificate Enrollment Policy (CEP).
5. **Network Device Enrollment Service** (NDES) za mrežne uređaje, korišćenjem Simple Certificate Enrollment Protocol (SCEP).

Windows korisnici takođe mogu zahtevati sertifikate putem GUI-ja (`certmgr.msc` ili `certlm.msc`) ili alata komandne linije (`certreq.exe` ili PowerShell komande `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Autentifikacija pomoću sertifikata

Active Directory (AD) podržava autentifikaciju pomoću sertifikata, prvenstveno koristeći protokole **Kerberos** i **Secure Channel (Schannel)**.

### Proces Kerberos autentifikacije

U procesu Kerberos autentifikacije, korisnikov zahtev za Ticket Granting Ticket (TGT) potpisuje se pomoću **privatnog ključa** korisnikovog sertifikata. Ovaj zahtev prolazi kroz nekoliko validacija na kontroleru domena, uključujući **važenje**, **putanju** i **status opoziva** sertifikata. Validacije takođe uključuju proveru da sertifikat potiče iz pouzdanog izvora i potvrdu prisustva izdavaoca u **NTAUTH certificate store**. Uspešne validacije dovode do izdavanja TGT-a. Objekat **`NTAuthCertificates`** u AD-u, koji se nalazi na:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
je od suštinskog značaja za uspostavljanje poverenja pri autentifikaciji sertifikatom.<sup>[[4]](#references)</sup>

Od uvođenja **KB5014754**, savremena Kerberos autentifikacija sertifikatom uglavnom se zasniva na **snazi mapiranja**, a ne samo na EKU-ovima.<sup>[[2]](#references)</sup> U ojačanim šumama:

- Sertifikat koji sadrži samo **UPN/DNS SAN** možda više neće biti dovoljan za prijavu.
- KDC daje prednost **jakom povezivanju**, obično putem **SID security extension** (`1.3.6.1.4.1.311.25.2`) ili jakog eksplicitnog mapiranja u `altSecurityIdentities`.
- Ako sertifikatu nedostaje jako mapiranje, DC-ovi evidentiraju **Kdcsvc Event ID 39/41** u compatibility mode-u i odbijaju autentifikaciju u enforcement mode-u.
- U kombinovanim attack path-ovima, **ESC9/ESC16** su važni jer uklanjaju SID ekstenziju iz izdatih sertifikata; napadači se tada oslanjaju na eksplicitna mapiranja ili SAN URL SID formate tamo gde ih attack path podržava.

### Autentifikacija putem Secure Channel-a (Schannel)

Schannel omogućava bezbedne TLS/SSL veze, pri čemu klijent tokom rukovanja predstavlja sertifikat koji, ako je uspešno validiran, autorizuje pristup. Mapiranje sertifikata na AD nalog može uključivati Kerberos funkciju **S4U2Self** ili **Subject Alternative Name (SAN)** sertifikata, između ostalih metoda.<sup>[[4]](#references)</sup>

Schannel je takođe praktičan fallback kada **PKINIT** nije dostupan. Na primer, ako domain controller nema odgovarajući **Smart Card Logon** sertifikat, `certipy auth`/PKINIT tooling možda neće uspeti da dobije TGT, ali isti sertifikat i dalje može biti upotrebljiv protiv **LDAPS**-a ili **LDAP StartTLS**-a za autentifikaciju i LDAP operacije.

### Enumeracija AD Certificate Services-a

Servisi sertifikata u AD-u mogu se enumerisati putem LDAP upita, čime se otkrivaju informacije o **Enterprise Certificate Authorities (CA-ovima)** i njihovim konfiguracijama. Ovo je dostupno svakom korisniku autentifikovanom na domenu bez posebnih privilegija. Alati kao što su **[Certify](https://github.com/GhostPack/Certify)** i **[Certipy](https://github.com/ly4k/Certipy)** koriste se za enumeraciju i procenu ranjivosti u AD CS okruženjima.

Komande za korišćenje ovih alata uključuju:
```bash
# Enumerate trusted root CA certificates, Enterprise CAs, and web endpoints
Certify.exe cas

# Identify vulnerable templates and dump relevant permissions
Certify.exe find /vulnerable
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /showAdmins

# Certipy 5.x enumeration focused on enabled/vulnerable templates
certipy find -enabled -vulnerable -hide-admins -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Save JSON/CSV output for offline review or BloodHound correlation
certipy find -json -output corp_adcs -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Request a certificate over the Web Enrollment endpoint or DCOM/RPC
certipy req -web -ca corp-CA -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local
certipy req -ca corp-CA -target ca.corp.local -template User -upn administrator@corp.local -sid S-1-5-21-...-500

# Use the issued certificate either for PKINIT or directly for LDAP Schannel auth
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10 -ldap-shell

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## Nedavne ranjivosti i bezbednosne ispravke (2022-2025)

| Godina | ID / Naziv | Uticaj | Ključni zaključci |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Eskalacija privilegija* lažiranjem sertifikata računa računara tokom PKINIT-a. | Ispravka je uključena u bezbednosne ispravke od **10. maja 2022.** Kontrole za auditing i strong-mapping uvedene su putem **KB5014754**; okruženja bi sada trebalo da budu u režimu *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* u AD CS Web Enrollment (certsrv) i CES ulogama. | Javni PoC-ovi su ograničeni, ali ranjive IIS komponente su često interno izložene. Ispravka je dostupna od Patch Tuesday-a u **julu 2023.**  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Na **v1 template-ima**, requester sa pravima za enrollment može da ugradi **Application Policies/EKU-ove** u CSR, koji imaju prednost nad EKU-ovima template-a, čime se dobijaju sertifikati za client-auth, enrollment agent ili code-signing. | Ispravljeno od **12. novembra 2024.** Zamenite ili nadjačajte v1 template-e (npr. podrazumevani WebServer), ograničite EKU-ove prema nameni i ograničite prava za enrollment. |

### Microsoft-ova vremenska linija hardening-a (KB5014754)

Microsoft je uveo uvođenje u tri faze (Compatibility → Audit → Enforcement) kako bi Kerberos autentifikaciju sertifikatima udaljio od slabih implicitnih mapiranja. Od **11. februara 2025.**, domain controller-i se automatski prebacuju u režim **Full Enforcement** ako vrednost registra `StrongCertificateBindingEnforcement` nije podešena. Microsoft je kasnije ažurirao vremensku liniju tako da fallback na compatibility mode ostane moguć do bezbednosne ispravke od **9. septembra 2025.**<sup>[[2]](#references)</sup> Administratori bi trebalo da:

1. Instaliraju ispravke na svim DC-ovima i AD CS serverima (maj 2022. ili novije).
2. Prate Event ID 39/41 zbog slabih mapiranja tokom faze *Audit*.
3. Ponovo izdaju client-auth sertifikate sa novim **SID extension-om** ili konfigurišu jaka ručna mapiranja pre nego što enforcement blokira slaba mapiranja.

### Napomene za operatere hardened forest-a

- **ESC1/ESC6 sami više nisu cela priča** u okruženjima iz 2025. i novijim. Ako zatražite sertifikat za drugog principal-a, obično vam je potreban i jak mapping artifact, kao što su SID extension ili eksplicitno mapiranje.
- **ESC15 (EKUwu)** je uglavnom vredan u neispravljenim okruženjima jer bezopasne **v1** template-e, kao što je **WebServer**, pretvara u sertifikate sposobne za autentifikaciju ili enrollment agent funkcije ubacivanjem **Application Policies**. Kerberos PKINIT i dalje proverava EKU-ove, ali **LDAP Schannel** takođe poštuje Application Policies, zbog čega abuse zasnovan na LDAP-u ostaje relevantan.<sup>[[1]](#references)</sup>
- **ESC16** je opcija na nivou CA-a: ako CA globalno onemogući SID security extension, svaki izdati sertifikat prelazi na slabije ponašanje mapiranja, osim ako attack chain ne ubaci SID putem drugog podržanog formata.

---

## Unapređenja detekcije i hardening-a

* **Defender for Identity AD CS sensor (2023-2024)** sada prikazuje procene bezbednosnog stanja za ESC1-ESC8/ESC11 i generiše alerts u realnom vremenu, kao što su *„Izdavanje sertifikata za domain controller koji nije DC“* (ESC8) i *„Sprečite Certificate Enrollment sa proizvoljnim Application Policies“* (ESC15). Obezbedite da su senzori deployment-ovani na svim AD CS serverima kako biste koristili ove detekcije.<sup>[[3]](#references)</sup>
* Onemogućite ili strogo ograničite opciju **“Supply in the request”** na svim template-ima; prednost dajte eksplicitno definisanim SAN/EKU vrednostima.
* Uklonite **Any Purpose** ili **No EKU** iz template-a osim ako su apsolutno neophodni (rešava ESC2 scenarije).
* Zahtevajte **odobrenje manager-a** ili namenske Enrollment Agent workflow-e za osetljive template-e (npr. WebServer / CodeSigning).
* Ograničite web enrollment (`certsrv`) i CES/NDES endpoint-e na pouzdane mreže ili ih postavite iza autentifikacije client-certificate-om.
* Uvedite encryption za RPC enrollment (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) kako biste ublažili ESC11 (RPC relay). Ova zastavica je **podrazumevano uključena**, ali se često onemogućava zbog legacy klijenata, čime se rizik od relay-a ponovo otvara.
* Zaštitite **IIS-based enrollment endpoint-e** (CES/Certsrv): gde je moguće, onemogućite NTLM ili zahtevajte HTTPS + Extended Protection kako biste blokirali ESC8 relay-e.

---

## Reference

- [1] [EKUwu: Not just another AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Certificates security posture assessments - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../banners/hacktricks-training.md}}
