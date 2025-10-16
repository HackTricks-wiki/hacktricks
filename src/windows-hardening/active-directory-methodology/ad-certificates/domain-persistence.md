# AD CS Perzistencija u domenu

{{#include ../../../banners/hacktricks-training.md}}

**Ovo je sažetak tehnika perzistencije u domenu prikazanih u [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Proverite ga za dodatne detalje.

## Falsifikovanje sertifikata pomoću ukradenih CA sertifikata (Golden Certificate) - DPERSIST1

Kako možete utvrditi da je sertifikat CA sertifikat?

Može se utvrditi da je sertifikat CA sertifikat ako su ispunjeni sledeći uslovi:

- Sertifikat je uskladišten na CA serveru, a njegov privatni ključ je zaštićen DPAPI-jem mašine, ili hardverom poput TPM/HSM ako operativni sistem to podržava.
- Polja Issuer i Subject sertifikata se podudaraju sa distinguished name-om CA.
- Ekstenzija "CA Version" postoji isključivo u CA sertifikatima.
- Sertifikat nema polja Extended Key Usage (EKU).

Za izvlačenje privatnog ključa ovog sertifikata, `certsrv.msc` alat na CA serveru je podržana metoda putem ugrađenog GUI-ja. Ipak, ovaj sertifikat se ne razlikuje od ostalih koji su uskladišteni u sistemu; stoga se za ekstrakciju mogu primeniti metode kao što je [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2).

Sertifikat i privatni ključ se takođe mogu dobiti koristeći Certipy sa sledećom komandom:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Kada se pribavi CA sertifikat i njegov privatni ključ u `.pfx` formatu, alati poput [ForgeCert](https://github.com/GhostPack/ForgeCert) mogu se koristiti za generisanje važećih sertifikata:
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
> Korisnik koji je meta za falsifikovanje sertifikata mora biti aktivan i sposoban za autentifikaciju u Active Directory da bi proces uspeo. Falsifikovanje sertifikata za specijalne naloge poput krbtgt je neefikasno.

Ovaj falsifikovani sertifikat će biti **važeći** do navedenog datuma isteka i sve dok je **root CA certificate važeći** (obično od 5 do **10+ godina**). Takođe važi za **mašine**, pa u kombinaciji sa **S4U2Self**, napadač može **održavati persistentnost na bilo kojoj mašini domena** sve dok je CA certificate važeći.\  
Pored toga, **sertifikati generisani** ovom metodom **ne mogu biti opozvani**, jer CA za njih nije svestan njihovog postojanja.

### Rad pod režimom stroge primene mapiranja sertifikata (2025+)

Od 11. februara 2025. (posle rollout-a KB5014754), domain controlleri podrazumevano koriste **Full Enforcement** za mapiranja sertifikata. Praktično to znači da vaši falsifikovani sertifikati moraju ili:

- Sadržati snažnu vezu sa ciljnim nalogom (na primer, SID security extension), ili
- Biti upareni sa snažnim, eksplicitnim mapiranjem na atributu ciljnog objekta `altSecurityIdentities`.

Pouzdan pristup za persistenciju je izraditi falsifikovani sertifikat povezan sa ukradenim Enterprise CA i zatim dodati snažno eksplicitno mapiranje žrtvinom principalu:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Napomene
- Ako možete izraditi forged certificates koji uključuju SID security extension, oni će se implicitno mapirati čak i pod Full Enforcement. U suprotnom, preferirajte explicit strong mappings. Vidi [account-persistence](account-persistence.md) za više o eksplicitnim mapiranjima.
- Revocation ovde ne pomaže defenderima: forged certificates nisu poznati CA database-u i stoga ne mogu biti revoked.

## Poverenje Rogue CA Certificates - DPERSIST2

Objekat `NTAuthCertificates` je definisan da sadrži jedan ili više **CA certificates** unutar svog `cacertificate` atributa, koje koristi Active Directory (AD). Proces verifikacije od strane **domain controller** uključuje proveru `NTAuthCertificates` objekta za unos koji odgovara **CA specified** u Issuer polju autentifikacione **certificate**. Autentikacija se nastavlja ako se pronađe poklapanje.

Samopotpisani CA certificate može biti dodat u `NTAuthCertificates` objekat od strane napadača, pod uslovom da imaju kontrolu nad ovim AD objektom. Obično samo članovi grupe **Enterprise Admin**, zajedno sa **Domain Admins** ili **Administrators** u **forest root’s domain**, imaju dozvolu da modifikuju ovaj objekat. Mogu izmeniti `NTAuthCertificates` objekat koristeći `certutil.exe` komandom `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, ili koristeći [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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
Ova sposobnost je posebno relevantna kada se koristi u kombinaciji sa prethodno opisanim metodom koja uključuje ForgeCert za dinamičko generisanje sertifikata.

> Post-2025 razmatranja mapiranja: dodavanje rogue CA u NTAuth uspostavlja poverenje samo u issuing CA. Da bi se koristili leaf sertifikati za logon kada su DC-ovi u **Full Enforcement**, leaf mora ili sadržavati **SID security extension** ili mora postojati jaka eksplicitna mapa na ciljnom objektu (na primer, Issuer+Serial u `altSecurityIdentities`). Pogledajte {{#ref}}account-persistence.md{{#endref}}.

## Malicious Misconfiguration - DPERSIST3

Mogućnosti za **persistence** kroz izmene security descriptor-a komponenti AD CS su mnogobrojne. Izmene opisane u sekciji "[Domain Escalation](domain-escalation.md)" mogu biti maliciozno implementirane od strane napadača sa povišenim pristupom. Ovo uključuje dodavanje "control rights" (npr. `WriteOwner/WriteDACL/etc.`) osetljivim komponentama kao što su:

- AD objekat računara CA servera (the **CA server’s AD computer** object)
- RPC/DCOM server CA servera (the **CA server’s RPC/DCOM server**)
- Bilo koji **descendant AD object or container** u **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (na primer, Certificate Templates container, Certification Authorities container, NTAuthCertificates object, itd.)
- **AD groups delegated rights to control AD CS** podrazumevano ili od strane organizacije (kao što je ugrađena Cert Publishers grupa i bilo koji od njenih članova)

Primer maliciozne implementacije bi bio kada napadač koji ima **elevated permissions** u domenu doda permisiju **`WriteOwner`** na podrazumevani `User` certificate template, pri čemu je napadač principal za to pravo. Da bi ovo iskoristio, napadač bi prvo promenio ownership `User` template-a na sebe. Nakon toga, `mspki-certificate-name-flag` bi bio postavljen na **1** na template-u kako bi se omogućio `ENROLLEE_SUPPLIES_SUBJECT`, dozvoljavajući korisniku da navede Subject Alternative Name u zahtevu. Zatim bi napadač mogao da se **enroll** pomoću template-a, izabere ime **domain administrator** kao alternativno ime, i iskoristi pribavljeni sertifikat za autentifikaciju kao DA.

Praktične opcije (knobs) koje napadači mogu podesiti za dugoročnu persistence u domenu (pogledajte {{#ref}}domain-escalation.md{{#endref}} za potpune detalje i detekciju):

- CA policy flags koji dozvoljavaju SAN iz zahteva (npr. omogućavanje `EDITF_ATTRIBUTESUBJECTALTNAME2`). Ovo održava ESC1-slične puteve iskoristivim.
- Template DACL ili podešavanja koja dozvoljavaju izdavanje koje je pogodno za autentifikaciju (npr. dodavanje Client Authentication EKU, omogućavanje `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Kontrola `NTAuthCertificates` objekta ili CA containera da kontinuirano ponovo uvedu rogue issuers ako branitelji pokušaju čišćenje.

> [!TIP]
> U ojačanim okruženjima nakon KB5014754, uparivanje ovih malicioznih konfiguracija sa eksplicitnim jakim mapiranjima (`altSecurityIdentities`) osigurava da izdati ili forged sertifikati ostanu upotrebljivi čak i kada DC-ovi primenjuju strong mapping.



## References

- Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
