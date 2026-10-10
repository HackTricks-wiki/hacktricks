# AD sertifikati

{{#include ../../banners/hacktricks-training.md}}

## Uvod

### Komponente sertifikata

- **Subject** sertifikata označava njegovog vlasnika.
- **Javni ključ** uparen je sa privatnim ključem kako bi se sertifikat povezao sa pravim vlasnikom.
- **Period važenja**, definisan datumima **NotBefore** i **NotAfter**, označava vremenski interval važenja sertifikata.
- Jedinstveni **serijski broj**, koji dodeljuje Certificate Authority (CA), identifikuje svaki sertifikat.
- **Issuer** označava CA koji je izdao sertifikat.
- **SubjectAlternativeName** omogućava navođenje dodatnih imena za subject, čime se povećava fleksibilnost identifikacije.
- **Basic Constraints** određuju da li je sertifikat namenjen za CA ili krajnji entitet i definišu ograničenja upotrebe.
- **Extended Key Usages (EKUs)** definišu specifične namene sertifikata, kao što su potpisivanje koda ili šifrovanje e-pošte, pomoću Object Identifiers (OIDs).
- **Signature Algorithm** navodi metod kojim se sertifikat potpisuje.
- **Signature**, kreiran privatnim ključem izdavaoca, garantuje autentičnost sertifikata.<sup>[[4]](#references)</sup>

### Posebna razmatranja

- **Subject Alternative Names (SANs)** proširuju primenu sertifikata na više identiteta, što je ključno za servere sa više domena. Bezbedni postupci izdavanja su od suštinskog značaja kako bi se izbegao rizik od lažnog predstavljanja koji nastaje kada napadači manipulišu SAN specifikacijom.<sup>[[4]](#references)</sup>

### Certificate Authorities (CAs) u Active Directory (AD)

AD CS prepoznaje CA sertifikate u AD forest-u preko određenih kontejnera, od kojih svaki ima posebnu ulogu:<sup>[[4]](#references)</sup>

- Kontejner **Certification Authorities** sadrži pouzdane root CA sertifikate.
- Kontejner **Enrolment Services** sadrži podatke o Enterprise CAs i njihovim predlošcima sertifikata.
- Objekat **NTAuthCertificates** sadrži CA sertifikate ovlašćene za AD autentifikaciju.
- Kontejner **AIA (Authority Information Access)** omogućava validaciju lanca sertifikata pomoću intermediate i cross CA sertifikata.

### Izdavanje sertifikata: tok zahteva za klijentski sertifikat

1. Proces zahteva počinje tako što klijenti pronalaze Enterprise CA.
2. Nakon generisanja para javnog i privatnog ključa, kreira se CSR koji sadrži javni ključ i druge podatke.
3. CA proverava CSR u odnosu na dostupne predloške sertifikata i izdaje sertifikat u skladu sa dozvolama predloška.
4. Nakon odobrenja, CA potpisuje sertifikat svojim privatnim ključem i vraća ga klijentu.<sup>[[4]](#references)</sup>

### Predlošci sertifikata

Definisani u AD-u, ovi predlošci navode postavke i dozvole za izdavanje sertifikata, uključujući dozvoljene EKUs i prava za prijavljivanje ili izmenu, koja su ključna za upravljanje pristupom uslugama sertifikata.<sup>[[4]](#references)</sup>

**Važna je verzija šeme predloška.** Zastareli predlošci **v1** (na primer, ugrađeni predložak **WebServer**) nemaju nekoliko savremenih opcija za sprovođenje pravila. Istraživanje **ESC15/EKUwu** pokazalo je da kod **v1 predložaka** podnosilac zahteva može u CSR da ugradi **Application Policies/EKUs** koji imaju **prednost u odnosu na** EKUs konfigurisane u predlošku, čime se omogućavaju sertifikati za client-auth, enrollment agent ili code-signing uz samo prava za prijavljivanje. Dajte prednost **v2/v3 predlošcima**, uklonite ili zamenite podrazumevane v1 predloške i strogo ograničite EKUs na predviđenu namenu.<sup>[[1]](#references)</sup>

## Prijavljivanje za sertifikat

Proces prijavljivanja za sertifikate pokreće administrator koji **kreira predložak sertifikata**, a zatim ga **objavljuje** Enterprise Certificate Authority (CA). Tako predložak postaje dostupan klijentima za prijavljivanje; to se postiže dodavanjem imena predloška u polje `certificatetemplates` Active Directory objekta.<sup>[[4]](#references)</sup>

Da bi klijent mogao da zatraži sertifikat, moraju mu biti dodeljena **prava za prijavljivanje**. Ta prava definišu se bezbednosnim deskriptorima na predlošku sertifikata i samom Enterprise CA-u. Dozvole moraju biti dodeljene na obe lokacije da bi zahtev uspeo.

### Prava za prijavljivanje na predložak

Ova prava se navode u Access Control Entries (ACEs), koje definišu dozvole kao što su:

- Prava **Certificate-Enrollment** i **Certificate-AutoEnrollment**, od kojih je svako povezano sa određenim GUID-ovima.
- **ExtendedRights**, koji omogućava sva proširena prava.
- **FullControl/GenericAll**, koji omogućava potpunu kontrolu nad predloškom.

### Prava za prijavljivanje na Enterprise CA

Prava CA-a navedena su u njegovom bezbednosnom deskriptoru, kojem se može pristupiti preko konzole za upravljanje Certificate Authority. Neke postavke čak omogućavaju udaljeni pristup korisnicima sa niskim privilegijama, što može predstavljati bezbednosni rizik.

### Dodatne kontrole izdavanja

Mogu se primenjivati određene kontrole, kao što su:

- **Odobrenje menadžera**: Zahtevi se stavljaju na čekanje dok ih ne odobri menadžer sertifikata.
- **Enrolment Agents i ovlašćeni potpisi**: Određuju broj potrebnih potpisa na CSR-u i neophodne Application Policy OIDs.

### Načini podnošenja zahteva za sertifikate

Sertifikati se mogu zatražiti pomoću:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), preko DCOM interfejsa.
2. **ICertPassage Remote Protocol** (MS-ICPR), preko imenovanih cevi ili TCP/IP-a.
3. **Veb-interfejsa za prijavljivanje za sertifikat**, kada je instalirana uloga Certificate Authority Web Enrollment.
4. **Certificate Enrollment Service** (CES), zajedno sa uslugom Certificate Enrollment Policy (CEP).
5. **Network Device Enrollment Service** (NDES) za mrežne uređaje, pomoću Simple Certificate Enrollment Protocol (SCEP).

Korisnici Windows-a mogu da zatraže sertifikate i preko GUI-ja (`certmgr.msc` ili `certlm.msc`) ili alata komandne linije (`certreq.exe` ili PowerShell komande `Get-Certificate`).

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Autentifikacija pomoću sertifikata

Active Directory (AD) podržava autentifikaciju pomoću sertifikata, prvenstveno koristeći protokole **Kerberos** i **Secure Channel (Schannel)**.

### Proces Kerberos autentifikacije

U procesu Kerberos autentifikacije, korisnikov zahtev za Ticket Granting Ticket (TGT) potpisuje se **privatnim ključem** korisnikovog sertifikata. Ovaj zahtev prolazi kroz nekoliko provera na kontroleru domena, uključujući proveru **važenja**, **putanje** i **statusa opoziva** sertifikata. Provere obuhvataju i potvrdu da sertifikat potiče iz pouzdanog izvora i da je izdavalac prisutan u **NTAUTH certificate store**. Uspešne provere rezultiraju izdavanjem TGT-a. Objekat **`NTAuthCertificates`** u AD-u nalazi se na:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

je ključna za uspostavljanje poverenja pri autentifikaciji sertifikatom.<sup>[[4]](#references)</sup>

Od uvođenja **KB5014754**, moderna Kerberos autentifikacija sertifikatom uglavnom se svodi na **jačinu mapiranja**, a ne samo na EKU-ove.<sup>[[2]](#references)</sup> U ojačanim šumama:

- Sertifikat koji sadrži samo **UPN/DNS SAN** možda više neće biti dovoljan za prijavu.
- KDC daje prednost **jakom povezivanju**, obično putem **SID bezbednosnog proširenja** (`1.3.6.1.4.1.311.25.2`) ili jakog eksplicitnog mapiranja u `altSecurityIdentities`.
- Ako sertifikat nema jako mapiranje, DC-ovi beleže **Kdcsvc Event ID 39/41** u režimu kompatibilnosti, a u režimu sprovođenja odbijaju autentifikaciju.
- U kombinovanim napadnim putanjama bitni su **ESC9/ESC16**, jer uklanjaju SID proširenje iz izdatih sertifikata; operateri se zatim oslanjaju na eksplicitna mapiranja ili SAN URL SID formate, kada ih napadna putanja podržava.

### Autentifikacija Secure Channel (Schannel)

Schannel omogućava bezbedne TLS/SSL veze. Tokom rukovanja, klijent predstavlja sertifikat koji, ako je uspešno validiran, odobrava pristup. Mapiranje sertifikata na AD nalog može, između ostalih metoda, da koristi Kerberosovu funkciju **S4U2Self** ili **Subject Alternative Name (SAN)** sertifikata.<sup>[[4]](#references)</sup>

Schannel je ujedno praktična rezervna opcija kada **PKINIT** nije dostupan. Na primer, ako kontroler domena nema odgovarajući sertifikat **Smart Card Logon**, `certipy auth`/PKINIT alati možda neće uspeti da dobiju TGT, ali isti sertifikat i dalje može da se koristi za autentifikaciju i LDAP operacije preko **LDAPS** ili **LDAP StartTLS**.

### Enumeracija AD Certificate Services

Certificate Services u AD-u mogu da se enumerišu LDAP upitima, čime se otkrivaju informacije o **Enterprise Certificate Authorities (CA)** i njihovim konfiguracijama. Ove informacije su dostupne svakom korisniku autentifikovanom na domenu, bez posebnih privilegija. Alati kao što su **[Certify](https://github.com/GhostPack/Certify)** i **[Certipy](https://github.com/ly4k/Certipy)** koriste se za enumeraciju i procenu ranjivosti u AD CS okruženjima.

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

## Nedavne ranjivosti i bezbednosna ažuriranja (2022-2025)

| Godina | ID / Naziv | Uticaj | Ključne poruke |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – „Certifried” / ESC6 | *Privilege escalation* lažiranjem sertifikata mašinskih naloga tokom PKINIT-a. | Ispravka je uključena u bezbednosna ažuriranja od **10. maja 2022.** Kontrole za reviziju i strong mapping uvedene su preko **KB5014754**; okruženja bi sada trebalo da koriste režim *Full Enforcement*. |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* u ulogama AD CS Web Enrollment (certsrv) i CES. | Javni PoC-ovi su ograničeni, ali su ranjive IIS komponente često izložene unutar mreže. Instalirajte ispravku iz **jula 2023.** Patch Tuesday-a. |
| 2024 | **CVE-2024-49019** – „EKUwu” / ESC15 | Na **v1 šablonima**, podnosilac zahteva sa pravima za upis može da ugradi **Application Policies/EKU-ove** u CSR, koji imaju prednost nad EKU-ovima šablona, čime se dobijaju sertifikati za client-auth, enrollment agent ili code-signing. | Ispravljeno **12. novembra 2024.** Zamenite ili nadjačajte v1 šablone (npr. podrazumevani WebServer), ograničite EKU-ove prema nameni i ograničite prava za upis. |

### Microsoftov plan za hardening (KB5014754)

Microsoft je uveo trofazno uvođenje (Compatibility → Audit → Enforcement) kako bi Kerberos autentifikaciju sertifikatima prebacio sa slabih implicitnih mapiranja. Od **11. februara 2025.**, kontroleri domena automatski prelaze na **Full Enforcement** ako vrednost registra `StrongCertificateBindingEnforcement` nije podešena. Microsoft je kasnije ažurirao plan tako da je povratak na režim kompatibilnosti moguć do bezbednosnog ažuriranja od **9. septembra 2025.**<sup>[[2]](#references)</sup> Administratori treba da:

1. Instaliraju zakrpe na svim DC-ovima i AD CS serverima (iz maja 2022. ili novije).
2. Prate Event ID 39/41 zbog slabih mapiranja tokom faze *Audit*.
3. Ponovo izdaju client-auth sertifikate sa novim **SID extension** ili konfigurišu snažna ručna mapiranja pre nego što enforcement blokira slaba mapiranja.

### Napomene za operatere u zaštićenim šumama domena

- **ESC1/ESC6 sami po sebi više ne opisuju celu sliku** u okruženjima iz 2025. i kasnijih godina. Ako zatražite sertifikat za drugi principal, obično vam je potreban i artefakt snažnog mapiranja, kao što je SID extension ili eksplicitno mapiranje.
- **ESC15 (EKUwu)** je najkorisniji u okruženjima na kojima nisu instalirane zakrpe, jer bezopasne **v1** šablone, kao što je **WebServer**, pretvara u sertifikate za autentifikaciju ili enrollment agent dodavanjem **Application Policies**. Kerberos PKINIT i dalje proverava EKU-ove, ali **LDAP Schannel** uvažava i Application Policies, zbog čega zloupotreba zasnovana na LDAP-u ostaje relevantna.<sup>[[1]](#references)</sup>
- **ESC16** je podešavanje koje važi za ceo CA: ako CA globalno onemogući SID security extension, svaki izdati sertifikat vraća se ka slabijem ponašanju mapiranja, osim ako napadački lanac ne ugradi SID u nekom drugom podržanom formatu.
- **Prava ESC7 su različita:** dodela `ManageCA` na CA može da omogući izmene podešavanja kao što je `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6), dok `ManageCertificates` kontroliše odobravanje zahteva. Eksplicitan Deny за prava certificate-manager може да блокира тај начин одобравања чак и ако постоји и Allow; процените ефективну CA ACL пре комбиновања подешавања и шаблона. Погледајте [Microsoft's CA ACL assessment](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Побољшања детекције и hardening-а

* **Defender for Identity AD CS sensor (2023-2024)** сада приказује процене безбедносног стања за ESC1-ESC8/ESC11 и генерише упозорења у реалном времену, као што су *„Издавање сертификата контролера домена за уређај који није DC”* (ESC8) и *„Спречите упис сертификата са произвољним Application Policies”* (ESC15). Да бисте користили ове детекције, инсталирајте сензоре на све AD CS сервере.<sup>[[3]](#references)</sup>
* Онемогућите опцију **“Supply in the request”** на свим шаблонима или строго ограничите њен опсег; предност дајте експлицитно дефинисаним SAN/EKU вредностима.
* Уклоните **Any Purpose** или **No EKU** из шаблона, осим ако су апсолутно неопходни (решава ESC2 сценарије).
* За осетљиве шаблоне (нпр. WebServer / CodeSigning) захтевајте **manager approval** или користите наменске радне токове Enrollment Agent-а.
* Ограничите web enrollment (`certsrv`) и CES/NDES крајње тачке на поуздане мреже или их поставите иза аутентификације клијентским сертификатом.
* Захтевајте RPC encryption за упис (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) да бисте ублажили ESC11 (RPC relay). Ова заставица је **подразумевано укључена**, али се често онемогућава због legacy клијената, чиме се поново отвара ризик од relay напада.
* Заштитите **IIS-based enrollment крајње тачке** (CES/Certsrv): где је могуће, онемогућите NTLM или захтевајте HTTPS + Extended Protection да бисте блокирали ESC8 relay нападе.

Процените ESC11 на хосту на коме ради CA, а то може бити сервер члан домена, а не контролер домена. Прочитајте `InterfaceFlags` активног CA-а у `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`; вредност која недостаје или се не може прочитати даје непознат резултат, а не доказ да је RPC encryption онемогућен. Ако је бит `IF_ENFORCEENCRYPTICERTREQUEST` искључен, то је индикација за конфигурацију коју тек треба проверити у погледу доступне RPC крајње тачке за упис, могућности принудног добијања акредитива и употребљивог шаблона сертификата. За ESC8, сам HTTP NTLM изазов није довољан: потврдите да постоји функционална крајња тачка за упис.

---

## References

- [1] [EKUwu: Није само још један AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Промене у аутентификацији заснованој на сертификатима на Windows контролерима домена](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Процене безбедносног стања сертификата - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Злоупотреба Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
