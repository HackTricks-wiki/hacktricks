# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Ovo je sažetak tehnika postojanosti domena podeljenih u [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Proverite za dodatne detalje.

## Forging Certificates with Stolen CA Certificates - DPERSIST1

Kako možete da prepoznate da je sertifikat CA sertifikat?

Može se utvrditi da je sertifikat CA sertifikat ako su ispunjeni određeni uslovi:

- Sertifikat je smešten na CA serveru, sa svojim privatnim ključem zaštićenim DPAPI-jem mašine, ili hardverom kao što je TPM/HSM ako operativni sistem to podržava.
- Polja Izdavača i Subjekta sertifikata se poklapaju sa istaknutim imenom CA.
- Ekstenzija "CA Version" je prisutna isključivo u CA sertifikatima.
- Sertifikat nema polja Proširena upotreba ključeva (EKU).

Da biste izvukli privatni ključ ovog sertifikata, alat `certsrv.msc` na CA serveru je podržana metoda putem ugrađenog GUI-a. Ipak, ovaj sertifikat se ne razlikuje od drugih smeštenih unutar sistema; stoga se mogu primeniti metode kao što je [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) za ekstrakciju.

Sertifikat i privatni ključ se takođe mogu dobiti koristeći Certipy sa sledećom komandom:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Nakon sticanja CA sertifikata i njegovog privatnog ključa u `.pfx` formatu, alati poput [ForgeCert](https://github.com/GhostPack/ForgeCert) mogu se koristiti za generisanje validnih sertifikata:
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
> [!WARNING]
> Korisnik koji je meta falsifikovanja sertifikata mora biti aktivan i sposoban za autentifikaciju u Active Directory-ju kako bi proces uspeo. Falsifikovanje sertifikata za posebne naloge kao što je krbtgt je neefikasno.

Ovaj falsifikovani sertifikat će biti **važeći** do datuma isteka koji je naveden i **dok je korenski CA sertifikat važeći** (obično od 5 do **10+ godina**). Takođe je važeći za **mašine**, tako da u kombinaciji sa **S4U2Self**, napadač može **održavati postojanost na bilo kojoj domen mašini** sve dok je CA sertifikat važeći.\
Štaviše, **sertifikati generisani** ovom metodom **ne mogu biti opozvani** jer CA nije svesna njih.

## Verovanje u Rogue CA Sertifikate - DPERSIST2

Objekat `NTAuthCertificates` je definisan da sadrži jedan ili više **CA sertifikata** unutar svog atributa `cacertificate`, koji Active Directory (AD) koristi. Proces verifikacije od strane **domen kontrolera** uključuje proveru objekta `NTAuthCertificates` za unos koji odgovara **CA specificiranom** u polju Izdavača autentifikovanog **sertifikata**. Autentifikacija se nastavlja ako se pronađe podudaranje.

Sertifikat samopotpisanog CA može biti dodat u objekat `NTAuthCertificates` od strane napadača, pod uslovom da imaju kontrolu nad ovim AD objektom. Obično, samo članovi grupe **Enterprise Admin**, zajedno sa **Domain Admins** ili **Administrators** u **domeni korena šume**, imaju dozvolu da modifikuju ovaj objekat. Mogu urediti objekat `NTAuthCertificates` koristeći `certutil.exe` sa komandom `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126`, ili koristeći [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Ova sposobnost je posebno relevantna kada se koristi u kombinaciji sa prethodno opisanim metodom koja uključuje ForgeCert za dinamičko generisanje sertifikata.

## Zloćudna Konfiguracija - DPERSIST3

Mogućnosti za **postojanost** kroz **modifikacije bezbednosnog deskriptora AD CS** komponenti su brojne. Modifikacije opisane u odeljku "[Domain Escalation](domain-escalation.md)" mogu biti zloćudno implementirane od strane napadača sa povišenim pristupom. Ovo uključuje dodavanje "kontrolnih prava" (npr., WriteOwner/WriteDACL/etc.) osetljivim komponentama kao što su:

- **AD računar** objekat **CA servera**
- **RPC/DCOM server** **CA servera**
- Bilo koji **potomak AD objekat ili kontejner** u **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (na primer, kontejner za šablone sertifikata, kontejner za sertifikacione autoritete, objekat NTAuthCertificates, itd.)
- **AD grupe kojima su dodeljena prava za kontrolu AD CS** po defaultu ili od strane organizacije (kao što je ugrađena grupa Cert Publishers i bilo koji od njenih članova)

Primer zloćudne implementacije bi uključivao napadača, koji ima **povišene dozvole** u domenu, koji dodaje **`WriteOwner`** dozvolu na podrazumevani **`User`** šablon sertifikata, pri čemu je napadač glavni za to pravo. Da bi to iskoristio, napadač bi prvo promenio vlasništvo nad **`User`** šablonom na sebe. Nakon toga, **`mspki-certificate-name-flag`** bi bio postavljen na **1** na šablonu kako bi omogućio **`ENROLLEE_SUPPLIES_SUBJECT`**, omogućavajući korisniku da pruži Subject Alternative Name u zahtevu. Nakon toga, napadač bi mogao **da se upiše** koristeći **šablon**, birajući ime **domen administratora** kao alternativno ime, i koristiti stečeni sertifikat za autentifikaciju kao DA.

{{#include ../../../banners/hacktricks-training.md}}
