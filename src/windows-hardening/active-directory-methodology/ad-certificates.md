# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Uvod

### Komponente certifikata

- **Subject** certifikata označava njegovog vlasnika.
- **Public Key** je uparen sa privatno čuvanim ključem kako bi se certifikat povezao sa pravim vlasnikom.
- **Validity Period**, definisan datumima **NotBefore** i **NotAfter**, označava efektivni period trajanja certifikata.
- Jedinstveni **Serial Number**, koji dodeljuje Certificate Authority (CA), identifikuje svaki certifikat.
- **Issuer** se odnosi na CA koji je izdao certifikat.
- **SubjectAlternativeName** omogućava dodatna imena za subject, što poboljšava fleksibilnost identifikacije.
- **Basic Constraints** identifikuju da li je certifikat za CA ili za krajnji entitet i definišu ograničenja upotrebe.
- **Extended Key Usages (EKUs)** određuju specifične namene certifikata, kao što su code signing ili email encryption, kroz Object Identifiers (OIDs).
- **Signature Algorithm** određuje metodu za potpisivanje certifikata.
- **Signature**, kreiran privatnim ključem izdavaoca, garantuje autentičnost certifikata.

### Posebna razmatranja

- **Subject Alternative Names (SANs)** proširuju primenljivost certifikata na više identiteta, što je ključno za servere sa više domena. Bezbedni procesi izdavanja su od suštinskog značaja kako bi se izbegli rizici od impersonation koje napadači mogu izazvati manipulacijom SAN specifikacijom.

### Certificate Authorities (CAs) u Active Directory (AD)

AD CS prepoznaje CA certifikate u AD forest kroz namenski definisane kontejnere, od kojih svaki ima posebnu ulogu:

- **Certification Authorities** kontejner sadrži trusted root CA certifikate.
- **Enrolment Services** kontejner sadrži Enterprise CAs i njihove certificate templates.
- **NTAuthCertificates** objekat uključuje CA certifikate autorizovane za AD authentication.
- **AIA (Authority Information Access)** kontejner olakšava validaciju certificate chain sa intermediate i cross CA certifikatima.

### Dobavljanje certifikata: tok zahteva za client certificate

1. Proces zahteva počinje tako što client pronalazi Enterprise CA.
2. Nakon generisanja para javni-privatni ključ, kreira se CSR koji sadrži public key i druge detalje.
3. CA procenjuje CSR u odnosu na dostupne certificate templates i izdaje certifikat na osnovu dozvola template-a.
4. Nakon odobrenja, CA potpisuje certifikat svojim privatnim ključem i vraća ga clientu.

### Certificate Templates

Definisani unutar AD, ovi template-i opisuju settings i permissions za izdavanje certifikata, uključujući dozvoljene EKUs i prava za enrollment ili modifikaciju, što je ključno za upravljanje pristupom certificate services.

**Schema verzija template-a je važna.** Legacy **v1** template-i (na primer, ugrađeni **WebServer** template) nemaju nekoliko modernih enforcement opcija. Istraživanje **ESC15/EKUwu** je pokazalo da na **v1 template-ima** zahtevnik može ubaciti **Application Policies/EKUs** u CSR koji imaju **prednost nad** EKUs konfigurisanih u template-u, što omogućava client-auth, enrollment agent ili code-signing certifikate sa samo enrollment pravima. Preferirajte **v2/v3 template-e**, uklonite ili zamenite v1 podrazumevane vrednosti i striktno ograničite EKUs na predviđenu namenu.

## Certificate Enrollment

Proces enrollment-a za certifikate inicira administrator koji **kreira certificate template**, koji zatim **publikuje** Enterprise Certificate Authority (CA). Time se template čini dostupnim za client enrollment, korakom koji se postiže dodavanjem naziva template-a u `certificatetemplates` polje Active Directory objekta.

Da bi client mogao da zatraži certifikat, moraju biti dodeljena **enrollment rights**. Ova prava su definisana security descriptor-ima na certificate template-u i samom Enterprise CA. Dozvole moraju biti dodeljene na obe lokacije da bi zahtev bio uspešan.

### Template Enrollment Rights

Ova prava su navedena kroz Access Control Entries (ACEs), uz detalje o dozvolama kao što su:

- **Certificate-Enrollment** i **Certificate-AutoEnrollment** prava, svako povezano sa određenim GUID-ovima.
- **ExtendedRights**, koje omogućavaju sve proširene dozvole.
- **FullControl/GenericAll**, koje pružaju potpunu kontrolu nad template-om.

### Enterprise CA Enrollment Rights

CA prava su opisana u njegovom security descriptor-u, dostupnom preko Certificate Authority management konzole. Neka podešavanja čak omogućavaju low-privileged korisnicima remote pristup, što može predstavljati sigurnosni problem.

### Dodatne kontrole izdavanja

Mogu se primeniti određene kontrole, kao što su:

- **Manager Approval**: Postavlja zahteve u pending stanje dok ih certificate manager ne odobri.
- **Enrolment Agents and Authorized Signatures**: Određuju broj potrebnih potpisa na CSR-u i potrebne Application Policy OID-ove.

### Metode za traženje certifikata

Certifikati se mogu tražiti preko:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), koristeći DCOM interfejse.
2. **ICertPassage Remote Protocol** (MS-ICPR), preko named pipes ili TCP/IP.
3. **certificate enrollment web interface**, uz instaliranu Certificate Authority Web Enrollment rolu.
4. **Certificate Enrollment Service** (CES), u kombinaciji sa Certificate Enrollment Policy (CEP) servisom.
5. **Network Device Enrollment Service** (NDES) za network devices, koristeći Simple Certificate Enrollment Protocol (SCEP).

Windows korisnici takođe mogu tražiti certifikate preko GUI-ja (`certmgr.msc` ili `certlm.msc`) ili komandno-linijskih alata (`certreq.exe` ili PowerShell-ove `Get-Certificate` komande).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Autentikacija sertifikatom

Active Directory (AD) podržava autentikaciju sertifikatom, prvenstveno koristeći **Kerberos** i **Secure Channel (Schannel)** protokole.

### Kerberos proces autentikacije

U Kerberos procesu autentikacije, korisnikov zahtev za Ticket Granting Ticket (TGT) se potpisuje pomoću **private key** korisnikovog sertifikata. Ovaj zahtev prolazi kroz nekoliko validacija od strane domain controllera, uključujući **validity** sertifikata, **path** i status **revocation**. Validacije takođe uključuju proveru da sertifikat dolazi iz trusted izvora i potvrdu prisustva izdavaoca u **NTAUTH certificate store**. Uspešne validacije rezultuju izdavanjem TGT-a. Objekat **`NTAuthCertificates`** u AD, pronađen na:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
je centralna za uspostavljanje poverenja za autentifikaciju pomoću sertifikata.

Od rollout-a **KB5014754**, moderno Kerberos certificate auth se uglavnom svodi na **mapping strength**, a ne samo na EKU-ove. U hardened forestovima:

- Sertifikat koji sadrži samo **UPN/DNS SAN** možda više nije dovoljan za logon.
- KDC preferira **strong binding**, obično **SID security extension** (`1.3.6.1.4.1.311.25.2`) ili jak eksplicitni mapping u `altSecurityIdentities`.
- Ako cert nema strong mapping, DC-ovi beleže **Kdcsvc Event ID 39/41** u compatibility modu i odbijaju auth u enforcement modu.
- U mixed attack paths, **ESC9/ESC16** su bitni jer uklanjaju SID extension iz izdatih certova; operateri onda zavise od eksplicitnih mappinga ili SAN URL SID formata tamo gde attack path to podržava.

### Secure Channel (Schannel) Authentication

Schannel omogućava bezbedne TLS/SSL konekcije, gde tokom handshake-a klijent predstavlja sertifikat koji, ako je uspešno validiran, autorizuje pristup. Mapping sertifikata na AD nalog može uključivati Kerberos-ovu funkciju **S4U2Self** ili **Subject Alternative Name (SAN)** sertifikata, između ostalih metoda.

Schannel je takođe praktični fallback kada **PKINIT** nije dostupan. Na primer, ako domain controller nema odgovarajući **Smart Card Logon** sertifikat, `certipy auth`/PKINIT tooling možda neće moći da dobije TGT, ali isti sertifikat i dalje može biti upotrebljiv protiv **LDAPS** ili **LDAP StartTLS** za autentifikaciju i LDAP operacije.

### AD Certificate Services Enumeration

AD certificate services mogu da se enumerišu kroz LDAP upite, otkrivajući informacije o **Enterprise Certificate Authorities (CAs)** i njihovim konfiguracijama. To je dostupno svakom domain-authenticated korisniku bez posebnih privilegija. Alati kao što su **[Certify](https://github.com/GhostPack/Certify)** i **[Certipy](https://github.com/ly4k/Certipy)** koriste se za enumeration i procenu ranjivosti u AD CS okruženjima.

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
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilege escalation* putem spoofing-a machine account certificates tokom PKINIT. | Patch je uključen u bezbednosna ažuriranja od **10. maja 2022**. Auditing i strong-mapping kontrole su uvedene preko **KB5014754**; okruženja bi sada trebalo da budu u *Full Enforcement* modu.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* u AD CS Web Enrollment (certsrv) i CES rolama. | Javni PoC-ovi su ograničeni, ali su ranjive IIS komponente često izložene interno. Patch od **jula 2023** Patch Tuesday.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Na **v1 templates**, requester sa enrollment rights može da ugradi **Application Policies/EKUs** u CSR koji imaju prednost nad template EKU-ovima, što proizvodi client-auth, enrollment agent, ili code-signing certificate. | Zakrpljeno od **12. novembra 2024**. Zamenite ili prevaziđite v1 templates (npr. default WebServer), ograničite EKU-ove na namenu i limitirajte enrollment rights. |

### Microsoft timeline za hardening (KB5014754)

Microsoft je uveo trofazno uvođenje (Compatibility → Audit → Enforcement) kako bi Kerberos certificate authentication prešao sa slabih implicit mappings. Od **11. februara 2025**, domain controllers automatski prelaze u **Full Enforcement** ako `StrongCertificateBindingEnforcement` registry vrednost nije postavljena. Microsoft je kasnije ažurirao timeline tako da je povratak u compatibility mode i dalje moguć do bezbednosnog ažuriranja od **9. septembra 2025**. Administratori treba da:

1. Zakrpe sve DC-ove i AD CS servere (maj 2022 ili novije).
2. Prate Event ID 39/41 za slabe mappings tokom *Audit* faze.
3. Ponovo izdaju client-auth certificates sa novom **SID ekstenzijom** ili konfigurišu jake manual mappings pre nego što enforcement blokira slabe mappings.

### Napomene za operatere u hardened forests

- **ESC1/ESC6 sami po sebi više nisu cela priča** u okruženjima 2025+. Ako tražite cert za drugi principal, obično vam je potreban i strong mapping artifact kao što je SID ekstenzija ili eksplicitno mapping.
- **ESC15 (EKUwu)** je uglavnom koristan u unpatched okruženjima jer pretvara bezopasne **v1** templates kao što je **WebServer** u certs sa sposobnošću za authentication- ili enrollment-agent, tako što ubacuje **Application Policies**. Kerberos PKINIT i dalje evaluira EKU-ove, ali **LDAP Schannel** takođe poštuje Application Policies, što održava relevantnim LDAP-based abuse.
- **ESC16** je CA-wide podešavanje: ako CA globalno isključi SID security extension, svaki izdat certificate se vraća ka slabijem mapping ponašanju osim ako attack chain ne ubaci SID u nekom drugom podržanom formatu.

---

## Poboljšanja za detekciju i hardening

* **Defender for Identity AD CS sensor (2023-2024)** sada prikazuje posture assessments za ESC1-ESC8/ESC11 i generiše real-time alerts kao što su *“Domain-controller certificate issuance for a non-DC”* (ESC8) i *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Osigurajte da su senzori raspoređeni na svim AD CS serverima kako biste imali korist od ovih detekcija.
* Onemogućite ili strogo ograničite opciju **“Supply in the request”** na svim templates; preferirajte eksplicitno definisane SAN/EKU vrednosti.
* Uklonite **Any Purpose** ili **No EKU** sa templates osim ako je apsolutno neophodno (adresira ESC2 scenarije).
* Zahtevajte **manager approval** ili namenski Enrollment Agent workflow za osetljive templates (npr. WebServer / CodeSigning).
* Ograničite web enrollment (`certsrv`) i CES/NDES endpoint-e na trusted networks ili iza client-certificate authentication.
* Enforce RPC enrollment encryption (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) da ublažite ESC11 (RPC relay). Flag je **uključen podrazumevano**, ali je često isključen zbog legacy klijenata, što ponovo otvara relay rizik.
* Zaštitite **IIS-based enrollment endpoints** (CES/Certsrv): onemogućite NTLM gde je moguće ili zahtevajte HTTPS + Extended Protection da blokirate ESC8 relays.

---



## References

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
