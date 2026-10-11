# AD sertifikati

{{#include ../../banners/hacktricks-training.md}}

## Uvod

### Komponente sertifikata

- **Subject** sertifikata označava njegovog vlasnika.
- **Public Key** je uparen sa privatno čuvanim ključem kako bi se sertifikat povezao sa njegovim pravim vlasnikom.
- **Validity Period**, definisan datumima **NotBefore** i **NotAfter**, označava period važenja sertifikata.
- Jedinstveni **Serial Number**, koji dodeljuje Certificate Authority (CA), identifikuje svaki sertifikat.
- **Issuer** označava CA koji je izdao sertifikat.
- **SubjectAlternativeName** omogućava dodavanje imena za subject, čime se povećava fleksibilnost identifikacije.
- **Basic Constraints** označava da li je sertifikat namenjen za CA ili krajnji entitet i definiše ograničenja upotrebe.
- **Extended Key Usages (EKUs)** određuju specifične namene sertifikata, kao što su potpisivanje koda ili šifrovanje e-pošte, pomoću Object Identifiers (OIDs).
- **Signature Algorithm** određuje metod potpisivanja sertifikata.
- **Signature**, kreiran privatnim ključem izdavaoca, garantuje autentičnost sertifikata.<sup>[[4]](#references)</sup>

### Posebna razmatranja

- **Subject Alternative Names (SANs)** proširuju primenu sertifikata na više identiteta, što je ključno za servere sa više domena. Bezbedni procesi izdavanja su neophodni za sprečavanje rizika od lažnog predstavljanja koje napadači mogu omogućiti izmenom SAN specifikacije.<sup>[[4]](#references)</sup>

### Certificate Authorities (CAs) u Active Directory (AD)

AD CS prepoznaje CA sertifikate u AD forestu putem namenski određenih kontejnera, od kojih svaki ima jedinstvenu ulogu:<sup>[[4]](#references)</sup>

- Kontejner **Certification Authorities** sadrži pouzdane root CA sertifikate.
- Kontejner **Enrolment Services** sadrži podatke o Enterprise CAs i njihovim šablonima sertifikata.
- Objekat **NTAuthCertificates** sadrži CA sertifikate ovlašćene za AD autentifikaciju.
- Kontejner **AIA (Authority Information Access)** omogućava validaciju lanca sertifikata pomoću intermediate i cross CA sertifikata.

### Dobijanje sertifikata: tok zahteva za klijentski sertifikat

1. Proces zahteva počinje tako što klijenti pronalaze Enterprise CA.
2. Nakon generisanja para javnog i privatnog ključa, kreira se CSR koji sadrži javni ključ i druge detalje.
3. CA proverava CSR u odnosu na dostupne šablone sertifikata i izdaje sertifikat na osnovu dozvola šablona.
4. Nakon odobrenja, CA potpisuje sertifikat svojim privatnim ključem i vraća ga klijentu.<sup>[[4]](#references)</sup>

### Šabloni sertifikata

Ovi šabloni, definisani u AD-u, navode podešavanja i dozvole za izdavanje sertifikata, uključujući dozvoljene EKUs i prava za upisivanje ili izmenu. Oni su ključni za upravljanje pristupom servisima za sertifikate.<sup>[[4]](#references)</sup>

**Važna je verzija šeme šablona.** Nasleđeni šabloni **v1** (na primer, ugrađeni šablon **WebServer**) nemaju nekoliko savremenih mehanizama za sprovođenje pravila. Istraživanje **ESC15/EKUwu** pokazalo je da kod **v1 šablona** podnosilac zahteva može da ugradi **Application Policies/EKUs** u CSR, koje imaju **prednost u odnosu na** EKUs podešene u šablonu, čime se omogućavaju client-auth, enrollment agent ili code-signing sertifikati uz samo prava za upisivanje. Dajte prednost **v2/v3 šablonima**, uklonite ili zamenite podrazumevane v1 šablone i strogo ograničite EKUs na predviđenu namenu.<sup>[[1]](#references)</sup>

## Upisivanje sertifikata

Proces upisivanja sertifikata pokreće administrator koji **kreira šablon sertifikata**, a zatim ga **objavljuje** Enterprise Certificate Authority (CA). Tako šablon postaje dostupan klijentima za upisivanje. To se postiže dodavanjem imena šablona u polje `certificatetemplates` Active Directory objekta.<sup>[[4]](#references)</sup>

Da bi klijent mogao da zatraži sertifikat, moraju mu biti dodeljena **prava za upisivanje**. Ta prava definišu bezbednosni deskriptori na šablonu sertifikata i samom Enterprise CA. Dozvole moraju biti dodeljene na obe lokacije da bi zahtev uspeo.

### Prava za upisivanje u šablon

Ova prava se navode pomoću Access Control Entries (ACEs), koje obuhvataju dozvole kao što su:

- Prava **Certificate-Enrollment** i **Certificate-AutoEnrollment**, od kojih je svako povezano sa određenim GUID-ovima.
- **ExtendedRights**, koja omogućavaju sve proširene dozvole.
- **FullControl/GenericAll**, koja pružaju potpunu kontrolu nad šablonom.

### Prava za upisivanje u Enterprise CA

Prava CA navedena su u njegovom bezbednosnom deskriptoru, kojem se može pristupiti putem konzole za upravljanje Certificate Authority. Neka podešavanja čak omogućavaju udaljeni pristup korisnicima sa niskim privilegijama, što može predstavljati bezbednosni rizik.

### Dodatne kontrole izdavanja

Mogu se primenjivati određene kontrole, kao što su:

- **Odobrenje menadžera**: Zahtevi ostaju na čekanju dok ih ne odobri menadžer sertifikata.
- **Enrolment Agents and Authorized Signatures**: Određuju potreban broj potpisa na CSR-u i neophodne OIDs za Application Policy.

### Metode zahtevanja sertifikata

Sertifikate je moguće zatražiti putem:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), koristeći DCOM interfejse.
2. **ICertPassage Remote Protocol** (MS-ICPR), putem imenovanih cevi ili TCP/IP-a.
3. **Veb-interfejsa za upisivanje sertifikata**, uz instaliranu ulogu Certificate Authority Web Enrollment.
4. **Certificate Enrollment Service** (CES), zajedno sa servisom Certificate Enrollment Policy (CEP).
5. **Network Device Enrollment Service** (NDES) za mrežne uređaje, koristeći Simple Certificate Enrollment Protocol (SCEP).

Korisnici Windowsa mogu zatražiti sertifikate i putem GUI-ja (`certmgr.msc` ili `certlm.msc`) ili alata komandne linije (`certreq.exe` ili PowerShell komande `Get-Certificate`).

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Autentifikacija sertifikatom

Active Directory (AD) podržava autentifikaciju sertifikatom, prvenstveno koristeći protokole **Kerberos** i **Secure Channel (Schannel)**.

### Proces Kerberos autentifikacije

U procesu Kerberos autentifikacije, korisnikov zahtev za Ticket Granting Ticket (TGT) potpisuje se **privatnim ključem** korisnikovog sertifikata. Kontroler domena obavlja nekoliko provera ovog zahteva, uključujući **validnost**, **putanju** i **status opoziva** sertifikata. Provere obuhvataju i potvrdu da sertifikat potiče iz pouzdanog izvora, kao i proveru da li je izdavalac prisutan u **NTAUTH skladištu sertifikata**. Uspešne provere rezultuju izdavanjem TGT-a. Objekat **`NTAuthCertificates`** u AD-u nalazi se na:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

je ključno za uspostavljanje poverenja pri autentifikaciji pomoću sertifikata.<sup>[[4]](#references)</sup>

Od uvođenja **KB5014754**, savremena Kerberos autentifikacija pomoću sertifikata uglavnom zavisi od **snage mapiranja**, a ne samo od EKU-ova.<sup>[[2]](#references)</sup> U ojačanim šumama:

- Sertifikat koji sadrži samo **UPN/DNS SAN** možda više nije dovoljan za prijavu.
- KDC preferira **jako povezivanje**, obično pomoću **SID security extension** (`1.3.6.1.4.1.311.25.2`) ili jakog eksplicitnog mapiranja u `altSecurityIdentities`.
- Ako sertifikatu nedostaje jako mapiranje, DC-ovi beleže **Kdcsvc Event ID 39/41** u režimu kompatibilnosti, a u režimu sprovođenja odbijaju autentifikaciju.
- U kombinovanim attack path-ovima, **ESC9/ESC16** su važni zato što uklanjaju SID extension iz izdatih sertifikata; operateri se zatim oslanjaju na eksplicitna mapiranja ili SAN URL SID formate, kada ih attack path podržava.

### Autentifikacija putem Secure Channel-a (Schannel)

Schannel omogućava bezbedne TLS/SSL veze. Tokom rukovanja, klijent predstavlja sertifikat koji, ako je uspešno validiran, odobrava pristup. Mapiranje sertifikata na AD nalog može da koristi Kerberos funkciju **S4U2Self** ili **Subject Alternative Name (SAN)** sertifikata, između ostalih metoda.<sup>[[4]](#references)</sup>

Schannel je takođe praktična rezervna opcija kada **PKINIT** nije dostupan. Na primer, ako kontroler domena nema odgovarajući sertifikat **Smart Card Logon**, `certipy auth`/PKINIT alati možda neće uspeti da pribave TGT, ali isti sertifikat i dalje može da se koristi za autentifikaciju i LDAP operacije preko **LDAPS**-a ili **LDAP StartTLS**-a.

### Enumeracija AD Certificate Services-a

Certificate services u AD-u mogu se enumerisati putem LDAP upita, koji otkrivaju informacije o **Enterprise Certificate Authorities (CA-ovima)** i njihovim konfiguracijama. Dostupni su svakom korisniku autentifikovanom na domenu, bez posebnih privilegija. Alati kao što su **[Certify](https://github.com/GhostPack/Certify)** i **[Certipy](https://github.com/ly4k/Certipy)** koriste se za enumeraciju i procenu ranjivosti u AD CS okruženjima.

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

## Nedavne ranjivosti i bezbednosna ažuriranja (2022–2025)

| Godina | ID / naziv | Uticaj | Ključne pouke |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – „Certifried” / ESC6 | *Eskalacija privilegija* lažiranjem sertifikata računara tokom PKINIT-a. | Zakrpa je uključena u bezbednosna ažuriranja od **10. maja 2022.** Kontrole za reviziju i snažno mapiranje uvedene su putem **KB5014754**; okruženja bi sada trebalo da budu u režimu *Full Enforcement*. |
| 2023 | **CVE-2023-35350 / 35351** | *Daljinsko izvršavanje koda* u ulogama AD CS Web Enrollment (certsrv) i CES. | Javno dostupni PoC-ovi su ograničeni, ali su ranjive IIS komponente često izložene unutar mreže. Instalirajte zakrpu iz **jula 2023.** Patch Tuesday. |
| 2024 | **CVE-2024-49019** – „EKUwu” / ESC15 | Na **v1 šablonima**, podnosilac zahteva sa pravima za upis može da ugradi **Application Policies/EKU-ove** u CSR, koji imaju prednost nad EKU-ovima šablona, čime se dobijaju sertifikati za klijentsku autentifikaciju, enrollment agenta ili potpisivanje koda. | Zakrpljeno **12. novembra 2024.** Zamenite ili nadjačajte v1 šablone (npr. podrazumevani WebServer), ograničite EKU-ove prema nameni i ograničite prava za upis. |

### Microsoft-ov vremenski plan za ojačavanje zaštite (KB5014754)

Microsoft je uveo uvođenje u tri faze (Compatibility → Audit → Enforcement) kako bi Kerberos autentifikaciju sertifikatima udaljio od slabih implicitnih mapiranja. Od **11. februara 2025.**, kontroleri domena automatski prelaze na **Full Enforcement** ako vrednost registra `StrongCertificateBindingEnforcement` nije podešena. Microsoft je kasnije ažurirao vremenski plan tako da povratak u režim kompatibilnosti ostane moguć do bezbednosnog ažuriranja od **9. septembra 2025.**<sup>[[2]](#references)</sup> Administratori bi trebalo da:

1. Instaliraju zakrpe na svim DC-ovima i AD CS serverima (iz maja 2022. ili novije).
2. Prate događaje Event ID 39/41 zbog slabih mapiranja tokom faze *Audit*.
3. Ponovo izdaju sertifikate za klijentsku autentifikaciju sa novim **SID extension** ili podese snažna ručna mapiranja pre nego što Enforcement blokira slaba mapiranja.

### Napomene za operatere u ojačanim šumama

- **ESC1/ESC6 sami po sebi više nisu cela priča** u okruženjima iz 2025. i kasnijih godina. Ako zatražite sertifikat za drugog principal-a, obično vam je potreban i artefakt snažnog mapiranja, kao što je SID extension ili eksplicitno mapiranje.
- **ESC15 (EKUwu)** je uglavnom koristan u nezakrpljenim okruženjima jer bezazlene **v1** šablone, kao što je **WebServer**, pretvara u sertifikate sposobne za autentifikaciju ili enrollment agenta ubacivanjem **Application Policies**. Kerberos PKINIT i dalje proverava EKU-ove, ali **LDAP Schannel** uvažava i Application Policies, pa zloupotreba zasnovana na LDAP-u ostaje relevantna.<sup>[[1]](#references)</sup>
- **ESC16** je podešavanje na nivou CA: ako CA globalno isključi SID security extension, svaki izdati sertifikat se vraća ka slabijem ponašanju mapiranja, osim ako lanac napada ne ubaci SID u nekom drugom podržanom formatu.
- **Prava ESC7 su zasebna:** dodela `ManageCA` na CA može da omogući promene podešavanja kao što je `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6), dok `ManageCertificates` upravlja odobravanjem zahteva. Eksplicitno Deny за права certificate-manager-а може да блокира тај пут одобравања чак и ако постоји и Allow; процените ефективни CA ACL пре повезивања подешавања и шаблона. Погледајте [Microsoft-ову процену CA ACL-а](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Унапређења детекције и ојачавања заштите

* **Defender for Identity AD CS sensor (2023–2024)** сада приказује процене стања за ESC1–ESC8/ESC11 и генерише упозорења у реалном времену, као што су *„Издавање сертификата за контролер домена који није DC”* (ESC8) и *„Спречите упис сертификата са произвољним Application Policies”* (ESC15). Да бисте искористили ове детекције, обезбедите да су сензори инсталирани на свим AD CS серверима.<sup>[[3]](#references)</sup>
* Онемогућите или строго ограничите опцију **„Supply in the request”** на свим шаблонима; дајте предност експлицитно дефинисаним SAN/EKU вредностима.
* Уклоните **Any Purpose** или **No EKU** из шаблона, осим ако је то апсолутно неопходно (решава сценарије ESC2).
* За осетљиве шаблоне (нпр. WebServer / CodeSigning) захтевајте **одобрење менаџера** или наменске Enrollment Agent токове рада.
* Ограничите web enrollment (`certsrv`) и CES/NDES крајње тачке на поуздане мреже или их поставите иза аутентификације сертификатом клијента.
* Обавезно користите шифровање RPC уписа (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) да бисте ублажили ESC11 (RPC relay). Ова заставица је **подразумевано укључена**, али се често онемогућава за старије клијенте, чиме се поново отвара ризик од relay напада.
* Заштитите **крајње тачке за упис засноване на IIS-у** (CES/Certsrv): где је могуће, онемогућите NTLM или захтевајте HTTPS + Extended Protection да бисте блокирали ESC8 relay нападе.

Процените ESC11 на хосту који покреће CA, а који може бити сервер-члан домена, а не контролер домена. Прочитајте активни CA `InterfaceFlags` у `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`; вредност која се не може прочитати или недостаје значи да резултат није познат, а не да је шифровање RPC-а онемогућено. Одсутан бит `IF_ENFORCEENCRYPTICERTREQUEST` указује на конфигурацију коју треба додатно проверити; и даље су потребни доступна RPC крајња тачка за упис, креденцијали које је могуће изнудити и употребљив шаблон сертификата. За ESC8, HTTP NTLM изазов сам по себи није довољан: потврдите да постоји функционална крајња тачка за упис.

---

## References

- [1] [EKUwu: Није само још један AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Промене у аутентификацији заснованој на сертификатима на Windows контролерима домена](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Процене безбедносног стања сертификата - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Злоупотреба Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
