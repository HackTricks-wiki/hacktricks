# AD Certificates

{{#include ../../../banners/hacktricks-training.md}}

## Uvod

### Komponente sertifikata

- **Subject** sertifikata označava njegovog vlasnika.
- **Public Key** je uparen sa privatno čuvanim ključem kako bi se sertifikat povezao sa njegovim legitimnim vlasnikom.
- **Validity Period**, definisan datumima **NotBefore** i **NotAfter**, označava period važenja sertifikata.
- Jedinstveni **Serial Number**, koji obezbeđuje Certificate Authority (CA), identifikuje svaki sertifikat.
- **Issuer** označava CA koji je izdao sertifikat.
- **SubjectAlternativeName** omogućava dodatna imena za subject, čime se povećava fleksibilnost identifikacije.
- **Basic Constraints** određuju da li je sertifikat namenjen za CA ili krajnji entitet i definišu ograničenja upotrebe.
- **Extended Key Usages (EKUs)** određuju posebne namene sertifikata, kao što su potpisivanje koda ili šifrovanje e-pošte, putem Object Identifiers (OIDs).
- **Signature Algorithm** određuje metod potpisivanja sertifikata.
- **Signature**, kreiran privatnim ključem izdavaoca, garantuje autentičnost sertifikata.<sup>[[1]](#references)</sup>

### Posebna razmatranja

- **Subject Alternative Names (SANs)** proširuju primenu sertifikata na više identiteta, što je ključno za servere sa više domena. Bezbedni procesi izdavanja su od vitalnog značaja za sprečavanje rizika od impersonacije koju napadači mogu izvršiti manipulisanjem SAN specifikacijom.<sup>[[1]](#references)</sup>

### Certificate Authorities (CAs) u Active Directory (AD)

AD CS prepoznaje CA sertifikate u AD forest-u putem određenih kontejnera, od kojih svaki ima posebnu ulogu:<sup>[[1]](#references)</sup>

- Kontejner **Certification Authorities** sadrži pouzdane root CA sertifikate.
- Kontejner **Enrolment Services** sadrži podatke o Enterprise CA-ovima i njihovim certificate template-ovima.
- Objekat **NTAuthCertificates** sadrži CA sertifikate ovlašćene za AD authentication.
- Kontejner **AIA (Authority Information Access)** omogućava validaciju lanca sertifikata pomoću intermediate i cross CA sertifikata.

### Preuzimanje sertifikata: tok zahteva za client sertifikat

1. Proces zahteva počinje tako što klijenti pronalaze Enterprise CA.
2. Nakon generisanja para javnog i privatnog ključa, kreira se CSR koji sadrži javni ključ i druge podatke.
3. CA proverava CSR u odnosu na dostupne certificate template-ove i izdaje sertifikat na osnovu dozvola template-a.
4. Nakon odobrenja, CA potpisuje sertifikat svojim privatnim ključem i vraća ga klijentu.<sup>[[1]](#references)</sup>

### Certificate Templates

Definisani unutar AD-a, ovi template-ovi određuju postavke i dozvole za izdavanje sertifikata, uključujući dozvoljene EKU-ove i prava za enrollment ili izmenu, što je ključno za upravljanje pristupom certificate servisima.<sup>[[1]](#references)</sup>

## Enrollment sertifikata

Proces enrollment-a sertifikata pokreće administrator koji **kreira certificate template**, a zatim ga **objavljuje** Enterprise Certificate Authority (CA). Time template postaje dostupan za enrollment klijenata, što se postiže dodavanjem imena template-a u polje `certificatetemplates` Active Directory objekta.<sup>[[1]](#references)</sup>

Da bi klijent mogao da zatraži sertifikat, moraju mu biti dodeljena **prava za enrollment**. Ova prava su definisana security descriptor-ima na certificate template-u i samom Enterprise CA-u. Dozvole moraju biti dodeljene na obe lokacije da bi zahtev bio uspešan.<sup>[[1]](#references)</sup>

### Prava za enrollment template-a

Ova prava se navode putem Access Control Entries (ACEs) i obuhvataju dozvole kao što su:<sup>[[1]](#references)</sup>

- Prava **Certificate-Enrollment** i **Certificate-AutoEnrollment**, od kojih je svako povezano sa određenim GUID-ovima.
- **ExtendedRights**, koja omogućavaju sve proširene dozvole.
- **FullControl/GenericAll**, koja pružaju potpunu kontrolu nad template-om.

### Prava za enrollment Enterprise CA-a

Prava CA-a navedena su u njegovom security descriptor-u, kojem se može pristupiti putem konzole za upravljanje Certificate Authority-om. Neke postavke čak omogućavaju korisnicima sa niskim privilegijama udaljeni pristup, što može predstavljati bezbednosni problem.<sup>[[1]](#references)</sup>

### Dodatne kontrole izdavanja

Mogu se primenjivati određene kontrole, kao što su:<sup>[[1]](#references)</sup>

- **Manager Approval**: Zahteve postavlja u stanje čekanja dok ih certificate manager ne odobri.
- **Enrolment Agents and Authorized Signatures**: Određuju broj potpisa potrebnih na CSR-u i neophodne Application Policy OIDs.

### Metode za zahtevanje sertifikata

Sertifikati se mogu zahtevati putem:<sup>[[1]](#references)</sup>

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), uz korišćenje DCOM interfejsa.
2. **ICertPassage Remote Protocol** (MS-ICPR), putem named pipe-ova ili TCP/IP-a.
3. **certificate enrollment web interfejsa**, uz instaliranu Certificate Authority Web Enrollment ulogu.
4. **Certificate Enrollment Service** (CES), u kombinaciji sa servisom Certificate Enrollment Policy (CEP).
5. **Network Device Enrollment Service** (NDES) za mrežne uređaje, uz korišćenje Simple Certificate Enrollment Protocol-a (SCEP).

Windows korisnici takođe mogu da zahtevaju sertifikate putem GUI-ja (`certmgr.msc` ili `certlm.msc`) ili alata komandne linije (`certreq.exe` ili PowerShell komande `Get-Certificate`).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Autentifikacija sertifikatom

Active Directory (AD) podržava autentifikaciju sertifikatom, prvenstveno koristeći protokole **Kerberos** i **Secure Channel (Schannel)**.<sup>[[1]](#references)</sup>

### Proces Kerberos autentifikacije

U procesu Kerberos autentifikacije, korisnikov zahtev za Ticket Granting Ticket (TGT) potpisuje se pomoću **privatnog ključa** korisnikovog sertifikata. Ovaj zahtev prolazi kroz nekoliko validacija koje sprovodi domain controller, uključujući **validnost**, **putanju** i status **opoziva** sertifikata. Validacije takođe obuhvataju proveru da sertifikat potiče iz pouzdanog izvora i potvrdu prisustva izdavaoca u **NTAUTH certificate store**. Uspešne validacije rezultuju izdavanjem TGT-a. Objekat **`NTAuthCertificates`** u AD-u, koji se nalazi na:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
je od ključnog značaja za uspostavljanje poverenja za autentifikaciju sertifikatom.<sup>[[1]](#references)</sup>

### Secure Channel (Schannel) autentifikacija

Schannel omogućava bezbedne TLS/SSL veze, pri čemu tokom rukovanja klijent predstavlja sertifikat koji, ako je uspešno validiran, autorizuje pristup.<sup>[[2]](#references)</sup> Mapiranje sertifikata na AD nalog može uključivati Kerberos funkciju **S4U2Self** ili **Subject Alternative Name (SAN)** sertifikata, između ostalih metoda.<sup>[[1]](#references)</sup>

### Enumeracija AD Certificate Services

Certificate services u AD-u mogu se enumerisati putem LDAP upita, čime se otkrivaju informacije o **Enterprise Certificate Authorities (CA)** i njihovim konfiguracijama. Ovo je dostupno svakom korisniku autentifikovanom na domenu, bez posebnih privilegija.<sup>[[1]](#references)</sup> Alati kao što su **[Certify](https://github.com/GhostPack/Certify)** i **[Certipy](https://github.com/ly4k/Certipy)** koriste se za enumeraciju i procenu ranjivosti u AD CS okruženjima.<sup>[[3]](#references)</sup>

Komande za korišćenje ovih alata uključuju:
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
## Reference

- [1] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [2] [Šta je SSL/TLS Client Authentication i kako funkcioniše?](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [3] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
